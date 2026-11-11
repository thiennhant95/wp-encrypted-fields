<?php

namespace Koyo\EncryptedFields\Migration;

use Koyo\EncryptedFields\Config\Field;
use Koyo\EncryptedFields\Plugin;

/**
 * Classifies the installation as fresh/plaintext/legacy/mixed/configured.
 */
final class StateDetector
{
    private Plugin $plugin;
    private ?object $db;

    public function __construct(Plugin $plugin, ?object $db = null)
    {
        $this->plugin = $plugin;
        $this->db = $db;
    }

    /**
     * @return array<string, mixed>
     */
    public function detect(int $sampleLimit = 20): array
    {
        $targets = Env::targets($this->plugin, $this->db);

        if (!$this->plugin->registry()->isEnabled()) {
            $targets = $this->legacyFallbackTargets();
        }

        $counts = array('plaintext' => 0, 'legacy' => 0, 'v2' => 0, 'token' => 0, 'empty' => 0);
        $fields = array();
        $errors = array();

        foreach ($targets as $target) {
            $row = $this->inspectTarget($target, max(1, $sampleLimit));
            $counts['plaintext'] += $row['plaintext'];
            $counts['legacy'] += $row['legacy'];
            $counts['v2'] += $row['v2'];
            $counts['token'] += $row['token'];
            $counts['empty'] += $row['empty'];
            $fields[] = $row;

            if (!empty($row['error'])) {
                $errors[] = array(
                    'entity' => $row['entity'],
                    'field' => $row['field'],
                    'error' => $row['error'],
                );
            }
        }

        $registryEnabled = $this->plugin->registry()->isEnabled();

        if ($counts['legacy'] > 0 && $counts['plaintext'] > 0) {
            $state = 'mixed';
        } elseif ($counts['legacy'] > 0) {
            $state = 'existing_legacy';
        } elseif ($counts['plaintext'] > 0) {
            $state = 'existing_plaintext';
        } elseif ($registryEnabled && Env::keyConfigured($this->plugin)) {
            $state = 'configured';
        } else {
            $state = 'fresh';
        }

        $warnings = array();
        if (Env::hposEnabled()) {
            $warnings[] = array(
                'code' => 'hpos_enabled',
                'message' => 'WooCommerce HPOS is enabled. Order fields must not be encrypted in v1.',
            );
        }

        if ($registryEnabled && !Env::keyConfigured($this->plugin)) {
            $warnings[] = array(
                'code' => 'missing_key',
                'message' => 'A field registry exists but no encryption key is configured.',
            );
        }

        $keySource = Env::keySource($this->plugin);
        if (0 === stripos($keySource, 'option:')) {
            $warnings[] = array(
                'code' => 'db_key',
                'message' => 'The master key is stored in the database. A database dump also exposes the key; use KEC_KEY/KEC_KEY_FILE instead.',
            );
        }

        return array(
            'state' => $state,
            'registry_enabled' => $registryEnabled,
            'key_configured' => Env::keyConfigured($this->plugin),
            'key_source' => $keySource,
            'key_id' => Env::keyId($this->plugin),
            'hpos' => Env::hposEnabled(),
            'backup_ack' => $this->backupAck(),
            'counts' => $counts,
            'fields' => $fields,
            'errors' => $errors,
            'warnings' => $warnings,
        );
    }

    public function hposEnabled(): bool
    {
        return Env::hposEnabled();
    }

    /**
     * @return array<string, mixed>|null
     */
    public function backupAck(): ?array
    {
        $ack = $this->plugin->option('kec_backup_ack');
        if (!is_array($ack) || empty($ack['timestamp'])) {
            return null;
        }

        return array(
            'timestamp' => (int) $ack['timestamp'],
            'user_id' => isset($ack['user_id']) ? (int) $ack['user_id'] : 0,
            'reference' => isset($ack['reference']) ? (string) $ack['reference'] : '',
        );
    }

    /**
     * @param array<string, mixed> $target
     * @return array<string, mixed>
     */
    private function inspectTarget(array $target, int $limit): array
    {
        $result = array(
            'entity' => $target['entity'],
            'field' => $target['field'],
            'kind' => $target['kind'],
            'table' => $target['kind'] === 'adapter' ? (isset($target['adapter_name']) ? $target['adapter_name'] : $target['table']) : $target['table'],
            'plaintext' => 0,
            'legacy' => 0,
            'v2' => 0,
            'token' => 0,
            'empty' => 0,
            'scanned' => 0,
            'error' => null,
        );

        if (null === Env::db($this->db)) {
            $result['error'] = 'database_unavailable';
            return $result;
        }

        $where = Env::targetWhereSql(Env::db($this->db), $target, $target['value_col'] . " <> ''");
        $sql = 'SELECT ' . $target['id_col'] . ' AS row_id, '
            . $target['entity_id_col'] . ' AS entity_id, '
            . $target['value_col'] . ' AS value'
            . ' FROM ' . $target['table']
            . ($where !== '' ? ' WHERE ' . $where : '')
            . ' ORDER BY ' . $target['id_col'] . ' ASC LIMIT ' . (int) $limit;

        $rows = Env::getResults($this->db, $sql);
        if (array() === $rows && method_exists(Env::db($this->db), 'last_error') && Env::db($this->db)->last_error) {
            $result['error'] = 'query_failed';
        }

        foreach ($rows as $row) {
            $value = isset($row->value) ? (string) $row->value : '';
            $result['scanned']++;
            $class = Env::classify($this->plugin, $value, $target['field_obj']);
            if ('empty' === $class) {
                $result['empty']++;
            } elseif (!empty($target['legacy_only']) && 'plaintext' === $class) {
                continue;
            } else {
                $result[$class]++;
            }
        }

        return $result;
    }

    /**
     * When no registry is configured, user columns are still inspected for legacy ciphertext.
     *
     * @return array<int, array<string, mixed>>
     */
    private function legacyFallbackTargets(): array
    {
        $db = Env::db($this->db);
        if (null === $db) {
            return array();
        }

        $targets = array();

        foreach (array('user_login' => 'login', 'user_email' => 'email') as $column => $type) {
            $targets[] = array(
                'entity' => 'user',
                'field' => $column,
                'kind' => 'column',
                'table' => Env::table($db, 'users'),
                'id_col' => 'ID',
                'entity_id_col' => 'ID',
                'value_col' => $column,
                'where' => '',
                'post_types' => array(),
                'field_obj' => new Field('user', $column, $type),
                'adapter' => null,
                'legacy_only' => true,
            );
        }

        return $targets;
    }
}
