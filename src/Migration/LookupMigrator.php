<?php

namespace EncryptedFields\Migration;

use EncryptedFields\Config\Field;
use EncryptedFields\Integrations\WooCommerce\CustomerLookupSchema;
use EncryptedFields\Plugin;
use EncryptedFields\User\ColumnStore;

/**
 * Migration for auxiliary lookup tables that are not part of the registry.
 */
final class LookupMigrator
{
    private const STATE_OPTION = 'kec_lookup_migration_state';

    private Plugin $plugin;
    private ?object $db;
    private ?Migrator $locker = null;
    private ?ColumnStore $columns = null;

    public function __construct(Plugin $plugin, ?object $db = null)
    {
        $this->plugin = $plugin;
        $this->db = $db;
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function scan(string $type, array $options = array()): array
    {
        $definition = $this->definition($type);
        if (null === $definition) {
            return $this->errorResult('invalid_table', 'Unknown lookup table: ' . $type);
        }

        if (!$this->tableExists($definition)) {
            return $this->emptyScan($definition, $options);
        }

        $sample = isset($options['sample_limit']) ? max(1, (int) $options['sample_limit']) : 100;
        $full = !empty($options['full']);
        $limit = $full ? 500 : $sample;
        $columns = array();
        $totals = array('plaintext' => 0, 'legacy' => 0, 'v2' => 0, 'token' => 0, 'empty' => 0, 'rows' => 0, 'pending' => 0);

        foreach ($definition['columns'] as $column => $spec) {
            $field = $this->fieldFor($spec);
            $stats = array(
                'column' => $column,
                'type' => $spec['type'],
                'plaintext' => 0,
                'legacy' => 0,
                'v2' => 0,
                'token' => 0,
                'empty' => 0,
                'rows' => 0,
                'total' => 0,
                'pending' => 0,
            );

            $cursor = 0;

            while (true) {
                $rows = $this->fetchBatch($definition, $column, $cursor, $limit);
                if (array() === $rows) {
                    break;
                }

                foreach ($rows as $row) {
                    $cursor = isset($row->row_id) ? (int) $row->row_id : $cursor;
                    $value = isset($row->value) ? (string) $row->value : '';
                    $class = Env::classify($this->plugin, $value, $field);

                    if ('empty' === $class) {
                        $stats['empty']++;
                        continue;
                    }

                    $stats[$class]++;
                    $stats['rows']++;
                }

                if (!$full || count($rows) < $limit) {
                    break;
                }
            }

            $stats['total'] = $stats['rows'];
            $stats['pending'] = $this->pendingCount($definition, $stats, !empty($options['rotate']));
            $columns[] = $stats;

            foreach (array('plaintext', 'legacy', 'v2', 'token', 'empty', 'rows', 'pending') as $key) {
                $totals[$key] += $stats[$key];
            }
        }

        return array(
            'ok' => true,
            'table' => $definition['table'],
            'type' => $definition['type'],
            'mode' => $definition['mode'],
            'columns' => $columns,
            'totals' => $totals,
            'backup_satisfied' => $this->backupSatisfied($options),
            'backup_ack' => $this->plugin->option('kec_backup_ack'),
        );
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function dryRun(string $type, array $options = array()): array
    {
        $options['full'] = true;
        $result = $this->scan($type, $options);

        if (!empty($result['ok'])) {
            $result['mode'] = 'dry_run';
            $result['requires_backup'] = (int) $result['totals']['pending'] > 0 && empty($result['backup_satisfied']);
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function migrateTable(string $type, array $options = array()): array
    {
        if (!empty($options['dry_run'])) {
            return $this->dryRun($type, $options);
        }

        $definition = $this->definition($type);
        if (null === $definition) {
            return $this->errorResult('invalid_table', 'Unknown lookup table: ' . $type);
        }

        if (!$this->tableExists($definition)) {
            return array(
                'ok' => true,
                'table' => $definition['table'],
                'type' => $definition['type'],
                'operation' => $definition['mode'],
                'migrated' => 0,
                'skipped' => 0,
                'errors' => array(),
                'stopped' => false,
                'table_missing' => true,
            );
        }

        $batch = isset($options['batch']) ? max(1, min(5000, (int) $options['batch'])) : 500;
        $rotate = !empty($options['rotate']);
        $resume = !empty($options['resume']);
        $stopOnError = !isset($options['stop_on_error']) || (bool) $options['stop_on_error'];

        if ('customer_lookup' === $definition['type']
            && (null === $this->db || !empty($options['widen_columns']))
        ) {
            $widened = CustomerLookupSchema::ensure();

            if ($widened) {
                foreach (array('username', 'email', 'city') as $wideColumn) {
                    if (isset($definition['columns'][$wideColumn])) {
                        $definition['columns'][$wideColumn]['max_length'] = 255;
                    }
                }
            }
        }

        $preview = $this->scan($definition['type'], array('full' => true, 'rotate' => $rotate));
        $pending = (int) $preview['totals']['pending'];

        if ($pending > 0 && !$this->backupSatisfied($options)) {
            return array(
                'ok' => false,
                'error' => 'backup_required',
                'message' => 'Migration of existing data requires a confirmed backup (kec_backup_ack).',
                'table' => $definition['table'],
                'migrated' => 0,
                'skipped' => 0,
                'errors' => array(),
            );
        }

        $useLock = !isset($options['lock']) || (bool) $options['lock'];
        $lock = '';
        if ($useLock) {
            $lock = $this->locker()->acquireLock();
            if ('' === $lock) {
                return array(
                    'ok' => false,
                    'error' => 'locked',
                    'message' => 'Another migration or rotation is running.',
                    'table' => $definition['table'],
                    'migrated' => 0,
                    'skipped' => 0,
                    'errors' => array(),
                );
            }
        }

        $state = $resume ? $this->loadState() : $this->resetState();
        $summary = array(
            'ok' => true,
            'table' => $definition['table'],
            'type' => $definition['type'],
            'operation' => $definition['mode'],
            'migrated' => 0,
            'skipped' => 0,
            'errors' => array(),
            'stopped' => false,
            'batch' => $batch,
            'resumed' => $resume,
        );

        $safety = array('ok' => true, 'path' => null, 'skipped' => true);

        if ($pending > 0) {
            $enabled = array_key_exists('safety_dump', $options)
                ? (bool) $options['safety_dump']
                : (null === $this->db);

            if ($enabled) {
                $db = Env::db($this->db);
                $tables = array($definition['table']);

                if (null !== $db) {
                    $tables[] = Env::table($db, 'kec_search_index');
                }

                $safety = SafetyDump::create($this->plugin, $this->db, $tables, $options);
            }
        }

        if (empty($safety['ok'])) {
            if ($useLock) {
                $this->locker()->releaseLock($lock);
            }

            return array(
                'ok' => false,
                'error' => 'safety_dump_failed',
                'message' => isset($safety['message']) ? (string) $safety['message'] : 'Safety dump failed.',
                'table' => $definition['table'],
                'migrated' => 0,
                'skipped' => 0,
                'errors' => array(),
            );
        }

        $summary['safety_dump'] = isset($safety['path']) ? $safety['path'] : null;

        try {
            foreach ($definition['columns'] as $column => $spec) {
                $field = $this->fieldFor($spec);
                $stateKey = $definition['type'] . ':' . $column;
                $cursor = $resume && isset($state['cursors'][$stateKey]) ? (int) $state['cursors'][$stateKey] : 0;

                while (true) {
                    $previousCursor = $cursor;
                    $rows = $this->fetchBatch($definition, $column, $cursor, $batch);
                    if (array() === $rows) {
                        break;
                    }

                    foreach ($rows as $row) {
                        $cursor = isset($row->row_id) ? (int) $row->row_id : $cursor;
                        $state['cursors'][$stateKey] = $cursor;
                        $result = $this->processRow($definition, $column, $spec, $field, $row, $rotate);

                        if ('migrated' === $result) {
                            $summary['migrated']++;
                        } elseif ('skipped' === $result) {
                            $summary['skipped']++;
                        } else {
                            $summary['errors'][] = $result;
                            if ($stopOnError) {
                                $summary['stopped'] = true;
                            }
                        }

                        if ($summary['stopped']) {
                            break;
                        }
                    }

                    $this->saveState($state);

                    if ($summary['stopped'] || count($rows) < $batch) {
                        break;
                    }

                    if ($cursor <= $previousCursor) {
                        $summary['errors'][] = array(
                            'column' => $column,
                            'id' => $cursor,
                            'error' => 'cursor_stalled',
                        );
                        $summary['stopped'] = true;
                        break;
                    }
                }

                if ($summary['stopped']) {
                    break;
                }
            }
        } catch (\Throwable $exception) {
            $summary['ok'] = false;
            $summary['error'] = 'migration_failed';
        } finally {
            if ($useLock) {
                $this->locker()->releaseLock($lock);
            }
        }

        if (!empty($summary['errors'])) {
            $summary['ok'] = false;
        }

        $this->plugin->logger()->info('lookup_migration_finished', array(
            'table' => $definition['type'],
            'migrated' => $summary['migrated'],
            'skipped' => $summary['skipped'],
            'errors' => count($summary['errors']),
        ));

        return $summary;
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function rotate(string $type, array $options = array()): array
    {
        $options['rotate'] = true;

        return $this->migrateTable($type, $options);
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function verify(string $type, array $options = array()): array
    {
        $definition = $this->definition($type);
        if (null === $definition) {
            return $this->errorResult('invalid_table', 'Unknown lookup table: ' . $type);
        }

        $scan = $this->scan($definition['type'], array('full' => true));
        $errors = array();
        $decryptOk = 0;
        $decryptFailed = 0;
        $columns = array();

        foreach ($scan['columns'] as $stats) {
            $column = $stats['column'];
            $spec = $definition['columns'][$column];
            $field = $this->fieldFor($spec);
            $remaining = 'encrypt' === $definition['mode']
                ? (int) $stats['plaintext'] + (int) $stats['legacy'] + (int) $stats['token']
                : (int) $stats['legacy'] + (int) $stats['v2'];

            if ('encrypt' === $definition['mode']) {
                $sample = $this->fetchBatch($definition, $column, 0, 10);
                foreach ($sample as $row) {
                    $value = isset($row->value) ? (string) $row->value : '';
                    if (!Env::isEncrypted($this->plugin, $value, $field)) {
                        continue;
                    }

                    try {
                        $plain = $this->plugin->crypto()->decrypt($value, $field);
                        if (!Env::isEncrypted($this->plugin, $plain, $field)) {
                            $decryptOk++;
                        } else {
                            $decryptFailed++;
                            $errors[] = array('column' => $column, 'id' => isset($row->row_id) ? (int) $row->row_id : 0, 'error' => 'decrypt_failed');
                        }
                    } catch (\Throwable $exception) {
                        $decryptFailed++;
                        $errors[] = array('column' => $column, 'id' => isset($row->row_id) ? (int) $row->row_id : 0, 'error' => 'decrypt_failed');
                    }
                }
            }

            $columns[] = array(
                'column' => $column,
                'plaintext' => (int) $stats['plaintext'],
                'legacy' => (int) $stats['legacy'],
                'v2' => (int) $stats['v2'],
                'token' => (int) $stats['token'],
                'ok' => 0 === $remaining,
            );

            if ($remaining > 0) {
                $errors[] = array('column' => $column, 'error' => 'not_migrated', 'remaining' => $remaining);
            }
        }

        return array(
            'ok' => 0 === $decryptFailed && array() === $errors,
            'table' => $definition['table'],
            'type' => $definition['type'],
            'plaintext' => (int) $scan['totals']['plaintext'],
            'legacy' => (int) $scan['totals']['legacy'],
            'v2' => (int) $scan['totals']['v2'],
            'token' => (int) $scan['totals']['token'],
            'decrypt_ok' => $decryptOk,
            'decrypt_failed' => $decryptFailed,
            'columns' => $columns,
            'errors' => $errors,
        );
    }

    /**
     * @param array<string, mixed> $definition
     * @param array<string, mixed> $spec
     * @param array<string, mixed> $stats
     */
    private function pendingCount(array $definition, array $stats, bool $rotate): int
    {
        if ('decrypt' === $definition['mode']) {
            return (int) $stats['legacy'] + (int) $stats['v2'];
        }

        if ($rotate) {
            return (int) $stats['rows'];
        }

        return (int) $stats['plaintext'] + (int) $stats['legacy'] + (int) $stats['token'];
    }

    /**
     * @param array<string, mixed> $definition
     * @param array<string, mixed> $spec
     * @return array<string, mixed>|string
     */
    private function processRow(array $definition, string $column, array $spec, Field $field, object $row, bool $rotate)
    {
        $value = isset($row->value) ? (string) $row->value : '';
        $class = Env::classify($this->plugin, $value, $field);
        $id = isset($row->row_id) ? (int) $row->row_id : 0;
        $error = array('column' => $column, 'id' => $id, 'error' => 'failed');

        if ('empty' === $class) {
            return 'skipped';
        }

        if ('decrypt' === $definition['mode']) {
            if ('plaintext' === $class) {
                return 'skipped';
            }

            if ('token' === $class) {
                $error['error'] = 'token_not_supported';
                return $error;
            }

            try {
                $plain = $this->plugin->crypto()->decrypt($value, $field);
            } catch (\Throwable $exception) {
                $plain = '';
            }

            if ('' === $plain || Env::isEncrypted($this->plugin, $plain, $field)) {
                $error['error'] = 'decrypt_failed';
                return $error;
            }

            if (!$this->writeValue($definition, $column, $id, $plain)) {
                $error['error'] = 'write_failed';
                return $error;
            }

            return 'migrated';
        }

        if ('v2' === $class && !$rotate) {
            return 'skipped';
        }

        $plain = $value;

        if ('token' === $class) {
            $name = isset($spec['token']) ? (string) $spec['token'] : '';
            $plain = '' !== $name ? $this->resolveToken($value, $name, $row) : '';
            if (null === $plain || '' === $plain) {
                $error['error'] = 'token_unresolved';
                return $error;
            }
        } elseif ('legacy' === $class || 'v2' === $class) {
            try {
                $plain = $this->plugin->crypto()->decrypt($value, $field);
            } catch (\Throwable $exception) {
                $plain = '';
            }

            if ('' === $plain || Env::isEncrypted($this->plugin, $plain, $field)) {
                $error['error'] = 'decrypt_failed';
                return $error;
            }
        }

        if (in_array($spec['type'], array('email', 'login'), true)) {
            $plain = trim($plain);
            $plain = function_exists('mb_strtolower') ? mb_strtolower($plain, 'UTF-8') : strtolower($plain);
        }

        try {
            $cipher = $this->plugin->crypto()->encrypt($plain, $field);
        } catch (\Throwable $exception) {
            $error['error'] = false !== stripos($exception->getMessage(), 'max length')
                ? 'length_exceeded'
                : 'encrypt_failed';

            return $error;
        }

        if (!Env::isEncrypted($this->plugin, $cipher, $field)) {
            $error['error'] = 'encrypt_failed';
            return $error;
        }

        $max = isset($spec['max_length']) ? (int) $spec['max_length'] : 0;
        if ($max > 0 && strlen($cipher) > $max) {
            $error['error'] = 'length_exceeded';
            return $error;
        }

        if ($cipher === $value) {
            return 'skipped';
        }

        if (!$this->writeValue($definition, $column, $id, $cipher)) {
            $error['error'] = 'write_failed';
            return $error;
        }

        return 'migrated';
    }

    private function resolveToken(string $value, string $name, object $row): ?string
    {
        $userId = isset($row->entity_id) ? (int) $row->entity_id : 0;
        $plain = $this->columnStore()->plainFromStored($value, $name, $userId > 0 ? $userId : null);

        if ('' === $plain || $this->columnStore()->isToken($plain, $name)) {
            return null;
        }

        return $plain;
    }

    /**
     * @param array<string, mixed> $definition
     * @return object[]
     */
    private function fetchBatch(array $definition, string $column, int $cursor, int $batch): array
    {
        $db = Env::db($this->db);
        if (null === $db) {
            return array();
        }

        $idColumn = $definition['id_col'];
        $entityColumn = isset($definition['user_col']) ? (string) $definition['user_col'] : $idColumn;

        $sql = 'SELECT ' . $idColumn . ' AS row_id, '
            . $entityColumn . ' AS entity_id, '
            . $column . ' AS value'
            . ' FROM ' . $definition['table']
            . " WHERE {$column} <> '' AND {$idColumn} > " . (int) $cursor
            . ' ORDER BY ' . $idColumn . ' ASC LIMIT ' . (int) $batch;

        return Env::getResults($db, $sql);
    }

    /**
     * @param array<string, mixed> $definition
     */
    private function writeValue(array $definition, string $column, int $id, string $value): bool
    {
        $db = Env::db($this->db);
        if (null === $db || !method_exists($db, 'update') || $id <= 0) {
            return false;
        }

        return false !== $db->update(
            $definition['table'],
            array($column => $value),
            array($definition['id_col'] => $id)
        );
    }

    /**
     * @param array<string, mixed> $spec
     */
    private function fieldFor(array $spec): Field
    {
        $entity = isset($spec['entity']) ? (string) $spec['entity'] : 'user';
        $key = (string) $spec['key'];
        $type = isset($spec['type']) ? (string) $spec['type'] : 'text';

        try {
            $field = $this->plugin->registry()->get($entity, $key);
            if ($field instanceof Field) {
                return $field;
            }
        } catch (\Throwable $exception) {
            // Fall back to a synthetic field.
        }

        $options = array();
        if (isset($spec['max_length'])) {
            $options['max_length'] = (int) $spec['max_length'];
        }

        return new Field($entity, $key, $type, false, null, $options);
    }

    /**
     * @return array<string, mixed>|null
     */
    private function definition(string $type): ?array
    {
        $db = Env::db($this->db);
        if (null === $db) {
            return null;
        }

        $type = strtolower(trim($type));

        if (in_array($type, array('customer_lookup', 'wc_customer_lookup', 'customer'), true)) {
            return array(
                'type' => 'customer_lookup',
                'mode' => 'encrypt',
                'table' => Env::table($db, 'wc_customer_lookup'),
                'id_col' => 'customer_id',
                'user_col' => 'user_id',
                'columns' => array(
                    'first_name' => array('key' => 'first_name', 'type' => 'text', 'entity' => 'user', 'max_length' => 255),
                    'last_name' => array('key' => 'last_name', 'type' => 'text', 'entity' => 'user', 'max_length' => 255),
                    'city' => array('key' => 'city', 'type' => 'text', 'entity' => 'user', 'max_length' => 100),
                    'email' => array('key' => 'email', 'type' => 'email', 'entity' => 'user', 'max_length' => 100, 'token' => ColumnStore::EMAIL),
                    'username' => array('key' => 'username', 'type' => 'login', 'entity' => 'user', 'max_length' => 60, 'token' => ColumnStore::LOGIN),
                ),
            );
        }

        if (in_array($type, array('siteguard_history', 'siteguard', 'history'), true)) {
            return array(
                'type' => 'siteguard_history',
                'mode' => 'decrypt',
                'table' => Env::table($db, 'siteguard_history'),
                'id_col' => 'id',
                'user_col' => null,
                'columns' => array(
                    'login_name' => array('key' => 'login_name', 'type' => 'login', 'entity' => 'user'),
                ),
            );
        }

        return null;
    }

    private function columnStore(): ColumnStore
    {
        if (null === $this->columns) {
            $this->columns = new ColumnStore($this->plugin);
        }

        return $this->columns;
    }

    private function locker(): Migrator
    {
        if (null === $this->locker) {
            $this->locker = new Migrator($this->plugin, $this->db);
        }

        return $this->locker;
    }

    /**
     * @param array<string, mixed> $options
     */
    private function backupSatisfied(array $options): bool
    {
        return $this->locker()->backupSatisfied($options);
    }

    /**
     * @return array<string, mixed>
     */
    private function loadState(): array
    {
        $state = $this->plugin->option(self::STATE_OPTION);
        if (!is_array($state) || !isset($state['cursors']) || !is_array($state['cursors'])) {
            return array('cursors' => array(), 'started' => time());
        }

        return $state;
    }

    /**
     * @return array<string, mixed>
     */
    private function resetState(): array
    {
        $state = array('cursors' => array(), 'started' => time());
        $this->plugin->updateOption(self::STATE_OPTION, $state);

        return $state;
    }

    /**
     * @param array<string, mixed> $state
     */
    private function saveState(array $state): void
    {
        $state['updated'] = time();
        $this->plugin->updateOption(self::STATE_OPTION, $state);
    }

    /**
     * @return array<string, mixed>
     */
    /**
     * Injected/fake DB objects are treated as already present; only the real
     * global $wpdb is probed, so callers can skip optional tables cleanly.
     *
     * @param array<string, mixed> $definition
     */
    private function tableExists(array $definition): bool
    {
        if (null !== $this->db) {
            return true;
        }

        $db = Env::db(null);
        if (!is_object($db) || !method_exists($db, 'get_var')) {
            return true;
        }

        $table = isset($definition['table']) ? (string) $definition['table'] : '';
        if ('' === $table) {
            return false;
        }

        try {
            $sql = method_exists($db, 'prepare')
                ? $db->prepare('SHOW TABLES LIKE %s', $table)
                : "SHOW TABLES LIKE '" . $table . "'";
            $found = $db->get_var($sql);
        } catch (\Throwable $exception) {
            return false;
        }

        return !empty($found);
    }

    /**
     * @param array<string, mixed> $definition
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    private function emptyScan(array $definition, array $options): array
    {
        $columns = array();

        foreach ($definition['columns'] as $column => $spec) {
            $columns[] = array(
                'column' => $column,
                'type' => isset($spec['type']) ? (string) $spec['type'] : 'text',
                'plaintext' => 0,
                'legacy' => 0,
                'v2' => 0,
                'token' => 0,
                'empty' => 0,
                'rows' => 0,
                'total' => 0,
                'pending' => 0,
            );
        }

        return array(
            'ok' => true,
            'table' => $definition['table'],
            'type' => $definition['type'],
            'mode' => $definition['mode'],
            'columns' => $columns,
            'totals' => array(
                'plaintext' => 0,
                'legacy' => 0,
                'v2' => 0,
                'token' => 0,
                'empty' => 0,
                'rows' => 0,
                'pending' => 0,
            ),
            'backup_satisfied' => $this->backupSatisfied($options),
            'backup_ack' => $this->plugin->option('kec_backup_ack'),
            'table_missing' => true,
        );
    }

    private function errorResult(string $code, string $message): array
    {
        return array(
            'ok' => false,
            'error' => $code,
            'message' => $message,
            'migrated' => 0,
            'skipped' => 0,
            'errors' => array(),
        );
    }
}
