<?php

namespace EncryptedFields\Migration;

use EncryptedFields\Config\Field;
use EncryptedFields\Plugin;
use EncryptedFields\User\ColumnStore;

/**
 * Scans, migrates, verifies and rolls back encrypted fields.
 */
final class Migrator
{
    private const LOCK_OPTION = 'kec_migration_lock';
    private const STATE_OPTION = 'kec_migration_state';

    private Plugin $plugin;
    private ?object $db;
    private ?ColumnStore $columns = null;
    private string $lockToken = '';

    public function __construct(Plugin $plugin, ?object $db = null)
    {
        $this->plugin = $plugin;
        $this->db = $db;
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function scan(array $options = array()): array
    {
        $entity = isset($options['entity']) ? (string) $options['entity'] : '';
        $field = isset($options['field']) ? (string) $options['field'] : '';
        $table = isset($options['table']) ? (string) $options['table'] : '';
        $sample = isset($options['sample_limit']) ? max(1, (int) $options['sample_limit']) : 5;
        $checkLength = !empty($options['check_length']);
        $full = !empty($options['full']);

        if ($checkLength) {
            $sample = max($sample, 100);
        }

        $targets = Env::targets($this->plugin, $this->db, $entity, $field, $table);
        $fields = array();
        $totals = array('plaintext' => 0, 'legacy' => 0, 'v2' => 0, 'token' => 0, 'empty' => 0, 'rows' => 0);
        $warnings = array();
        $scanFailed = false;

        foreach ($targets as $target) {
            $row = $this->scanTarget($target, $sample, $checkLength, $full);
            $fields[] = $row;

            if (!empty($row['error'])) {
                $scanFailed = true;
            }

            foreach (array('plaintext', 'legacy', 'v2', 'token', 'empty', 'rows') as $key) {
                $totals[$key] += $row[$key];
            }

            if (!empty($row['length']['risk'])) {
                $warnings[] = array(
                    'code' => 'length_risk',
                    'entity' => $row['entity'],
                    'field' => $row['field'],
                    'message' => 'Ciphertext may exceed the column length. Use a longer column or avoid encrypting this column.',
                );
            }
        }

        if (Env::hposEnabled() && ('post' === $entity || '' === $entity)) {
            $warnings[] = array(
                'code' => 'hpos_enabled',
                'message' => 'WooCommerce HPOS is enabled; order fields are blocked in v1.',
            );
        }

        return array(
            'ok' => !$scanFailed,
            'error' => $scanFailed ? 'scan_failed' : '',
            'fields' => $fields,
            'totals' => $totals,
            'targets' => count($targets),
            'hpos' => Env::hposEnabled(),
            'warnings' => $warnings,
            'backup_satisfied' => $this->backupSatisfied($options),
            'backup_ack' => $this->plugin->option('kec_backup_ack'),
        );
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function dryRun(array $options = array()): array
    {
        $options['check_length'] = true;
        $options['full'] = true;
        $scan = $this->scan($options);
        $scan['mode'] = 'dry_run';
        $scan['requires_backup'] = ($scan['totals']['plaintext'] + $scan['totals']['legacy']) > 0
            && !$scan['backup_satisfied'];
        $scan['pending'] = $scan['totals']['plaintext'] + $scan['totals']['legacy'];

        return $scan;
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function migrate(array $options = array()): array
    {
        $from = isset($options['from']) ? (string) $options['from'] : 'both';

        if (!in_array($from, array('both', 'plaintext', 'legacy'), true)) {
            return array(
                'ok' => false,
                'error' => 'invalid_from',
                'message' => 'The --from option must be one of: both, plaintext, legacy.',
                'migrated' => 0,
                'errors' => array(),
            );
        }

        if (!empty($options['dry_run'])) {
            return $this->dryRun($options);
        }

        $filters = array(
            'entity' => isset($options['entity']) ? (string) $options['entity'] : '',
            'field' => isset($options['field']) ? (string) $options['field'] : '',
            'table' => isset($options['table']) ? (string) $options['table'] : '',
        );

        $from = isset($options['from']) ? (string) $options['from'] : 'both';
        $batch = isset($options['batch']) ? max(1, min(5000, (int) $options['batch'])) : 500;
        $resume = !empty($options['resume']);
        $stopOnError = !isset($options['stop_on_error']) || (bool) $options['stop_on_error'];

        $preview = $this->scan($filters + array('sample_limit' => 5, 'full' => true));

        if (empty($preview['ok'])) {
            return array(
                'ok' => false,
                'error' => 'scan_failed',
                'message' => 'The pre-migration scan failed; refusing to migrate without a reliable backup decision.',
                'migrated' => 0,
                'errors' => array(),
            );
        }

        $pending = $preview['totals']['plaintext'] + $preview['totals']['legacy'];

        if ($pending > 0 && !$this->backupSatisfied($options)) {
            return array(
                'ok' => false,
                'error' => 'backup_required',
                'message' => 'Migration of existing data requires a confirmed backup (kec_backup_ack).',
                'pending' => $pending,
                'migrated' => 0,
                'errors' => array(),
            );
        }

        if (Env::hposEnabled() && ('post' === $filters['entity'] || '' === $filters['entity'])) {
            return array(
                'ok' => false,
                'error' => 'hpos_enabled',
                'message' => 'HPOS is enabled; order meta migration is blocked in v1.',
                'migrated' => 0,
                'errors' => array(),
            );
        }

        $token = $this->acquireLock();
        if ('' === $token) {
            return array(
                'ok' => false,
                'error' => 'locked',
                'message' => 'Another migration appears to be running.',
                'migrated' => 0,
                'errors' => array(),
            );
        }

        $state = $resume ? $this->loadState() : $this->resetState();
        $summary = array(
            'ok' => true,
            'migrated' => 0,
            'skipped' => 0,
            'errors' => array(),
            'error_count' => 0,
            'stopped' => false,
            'batch' => $batch,
            'from' => $from,
            'resumed' => $resume,
        );

        $targets = Env::targets($this->plugin, $this->db, $filters['entity'], $filters['field'], $filters['table']);

        $safety = $pending > 0
            ? $this->maybeSafetyDump($targets, $options)
            : array('ok' => true, 'path' => null, 'skipped' => true);

        if (empty($safety['ok'])) {
            $this->releaseLock($token);

            return array(
                'ok' => false,
                'error' => 'safety_dump_failed',
                'message' => isset($safety['message']) ? (string) $safety['message'] : 'Safety dump failed.',
                'migrated' => 0,
                'errors' => array(),
            );
        }

        $summary['safety_dump'] = isset($safety['path']) ? $safety['path'] : null;

        try {
            foreach ($targets as $target) {
                $targetKey = Env::targetKey($target);
                $cursor = $resume && isset($state['cursors'][$targetKey]) ? (int) $state['cursors'][$targetKey] : 0;

                while (true) {
                    $rows = $this->fetchBatch($target, $cursor, $batch);
                    if (array() === $rows) {
                        break;
                    }

                    $previousCursor = $cursor;

                    foreach ($rows as $row) {
                        $rowId = isset($row->row_id) ? (int) $row->row_id : $cursor;
                        $result = $this->processRow($target, $row, $from, true);

                        if ('migrated' === $result['status']) {
                            $summary['migrated']++;
                        } elseif ('skipped' === $result['status']) {
                            $summary['skipped']++;
                        } elseif ('error' === $result['status']) {
                            $summary['error_count'] = (int) $summary['error_count'] + 1;

                            if (count($summary['errors']) < 100) {
                                $summary['errors'][] = $result['error'];
                            }

                            if ($stopOnError) {
                                $summary['stopped'] = true;
                            }
                        }

                        if ('error' === $result['status'] && $stopOnError) {
                            break;
                        }

                        if ($rowId > $cursor) {
                            $cursor = $rowId;
                        }
                        $state['cursors'][$targetKey] = $cursor;

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
                            'entity' => $target['entity'],
                            'field' => $target['field'],
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
            $summary['errors'][] = array(
                'entity' => '',
                'field' => '',
                'id' => 0,
                'error' => 'exception',
            );
        } finally {
            $this->releaseLock($token);
        }

        if (!empty($summary['errors'])) {
            $summary['ok'] = false;
        }

        $this->plugin->logger()->info('migration_finished', array(
            'migrated' => $summary['migrated'],
            'skipped' => $summary['skipped'],
            'errors' => count($summary['errors']),
            'stopped' => (bool) $summary['stopped'],
        ));

        return $summary;
    }

    /**
     * Decrypt selected fields back to plaintext.
     *
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function rollback(array $options = array()): array
    {
        if (!empty($options['dry_run'])) {
            return $this->dryRun($options);
        }

        $batch = isset($options['batch']) ? max(1, min(5000, (int) $options['batch'])) : 500;
        $entityFilter = isset($options['entity']) ? (string) $options['entity'] : '';
        $fieldFilter = isset($options['field']) ? (string) $options['field'] : '';
        $tableFilter = isset($options['table']) ? (string) $options['table'] : '';

        if ('' === $fieldFilter) {
            $preview = $this->scan(array(
                'entity' => $entityFilter,
                'field' => $fieldFilter,
                'table' => $tableFilter,
                'sample_limit' => 5,
                'full' => true,
            ));

            if (empty($preview['ok'])) {
                return array(
                    'ok' => false,
                    'error' => 'scan_failed',
                    'message' => 'The rollback scan failed; no data was changed.',
                    'decrypted' => 0,
                    'errors' => array(),
                );
            }

            $pending = (int) $preview['totals']['v2'] + (int) $preview['totals']['legacy'];

            if ($pending > 0 && !$this->backupSatisfied($options)) {
                return array(
                    'ok' => false,
                    'error' => 'backup_required',
                    'message' => 'Rollback decrypts data and requires a confirmed backup.',
                    'decrypted' => 0,
                    'errors' => array(),
                );
            }
        }

        $targets = Env::targets($this->plugin, $this->db, $entityFilter, $fieldFilter, $tableFilter);

        $token = $this->acquireLock();
        if ('' === $token) {
            return array('ok' => false, 'error' => 'locked', 'decrypted' => 0, 'errors' => array());
        }

        $summary = array('ok' => true, 'decrypted' => 0, 'skipped' => 0, 'errors' => array());

        $safety = $this->maybeSafetyDump($targets, $options);

        if (empty($safety['ok'])) {
            $this->releaseLock($token);

            return array(
                'ok' => false,
                'error' => 'safety_dump_failed',
                'message' => isset($safety['message']) ? (string) $safety['message'] : 'Safety dump failed.',
                'decrypted' => 0,
                'errors' => array(),
            );
        }

        $summary['safety_dump'] = isset($safety['path']) ? $safety['path'] : null;

        try {
            foreach ($targets as $target) {
                $cursor = 0;

                while (true) {
                    $rows = $this->fetchBatch($target, $cursor, $batch);
                    if (array() === $rows) {
                        break;
                    }

                    foreach ($rows as $row) {
                        $cursor = isset($row->row_id) ? (int) $row->row_id : $cursor;
                        $result = $this->processRow($target, $row, 'encrypted', false);

                        if ('migrated' === $result['status']) {
                            $summary['decrypted']++;
                        } elseif ('skipped' === $result['status']) {
                            $summary['skipped']++;
                        } elseif ('error' === $result['status']) {
                            $summary['errors'][] = $result['error'];
                        }
                    }

                    if (count($rows) < $batch) {
                        break;
                    }
                }
            }
        } catch (\Throwable $exception) {
            $summary['ok'] = false;
            $summary['error'] = 'rollback_failed';
        } finally {
            $this->releaseLock($token);
        }

        if (!empty($summary['errors'])) {
            $summary['ok'] = false;
        }

        $this->plugin->logger()->info('rollback_finished', array(
            'decrypted' => $summary['decrypted'],
            'skipped' => $summary['skipped'],
            'errors' => count($summary['errors']),
        ));

        return $summary;
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function decrypt(array $options = array()): array
    {
        return $this->rollback($options);
    }

    /**
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function verify(array $options = array()): array
    {
        $scan = $this->scan(array_merge($options, array('sample_limit' => 50, 'full' => true)));
        $full = !empty($options['full']);
        $decryptOk = 0;
        $decryptFailed = 0;
        $tokenErrors = 0;
        $errors = array();
        $fields = array();

        foreach ($scan['fields'] as $fieldRow) {
            $tokenField = $this->isUserTokenFieldRow($fieldRow);
            $remaining = (int) $fieldRow['plaintext'] + (int) $fieldRow['legacy'];
            $ok = 0 === $remaining;

            if ($tokenField) {
                $remaining += (int) $fieldRow['v2'];
                $ok = 0 === $remaining;
            }

            $fields[] = array(
                'entity' => $fieldRow['entity'],
                'field' => $fieldRow['field'],
                'mode' => $tokenField ? 'token' : 'encrypted',
                'plaintext' => (int) $fieldRow['plaintext'],
                'legacy' => (int) $fieldRow['legacy'],
                'v2' => (int) $fieldRow['v2'],
                'token' => isset($fieldRow['token']) ? (int) $fieldRow['token'] : 0,
                'ok' => $ok,
            );

            if (!$ok) {
                if ($tokenField) {
                    $tokenErrors++;
                }

                $errors[] = array(
                    'entity' => $fieldRow['entity'],
                    'field' => $fieldRow['field'],
                    'error' => $tokenField ? 'not_tokenized' : 'not_fully_encrypted',
                    'remaining' => $remaining,
                );
            }
        }

        $targets = Env::targets(
            $this->plugin,
            $this->db,
            isset($options['entity']) ? (string) $options['entity'] : '',
            isset($options['field']) ? (string) $options['field'] : '',
            isset($options['table']) ? (string) $options['table'] : ''
        );

        foreach ($targets as $target) {
            if ($this->isUserTokenTarget($target)) {
                $this->verifyTokenTarget($target, $decryptOk, $decryptFailed, $errors, $full);
                continue;
            }

            $this->verifyEncryptedTarget($target, $decryptOk, $decryptFailed, $errors, $full);
        }

        $indexRows = null;
        $indexOk = true;
        $db = Env::db($this->db);
        if (null !== $db && method_exists($db, 'get_var')) {
            $indexRows = (int) Env::getVar($db, 'SELECT COUNT(*) FROM ' . Env::table($db, 'kec_search_index'));

            $searchable = 0;
            try {
                foreach ($this->plugin->registry()->all() as $entityFields) {
                    foreach ($entityFields as $field) {
                        if ($field instanceof Field && $field->isSearchable()) {
                            $searchable++;
                        }
                    }
                }
            } catch (\Throwable $exception) {
                $searchable = 0;
            }

            if ($full && $searchable > 0 && 0 === $indexRows && (int) $scan['totals']['rows'] > 0) {
                $indexOk = false;
                $errors[] = array(
                    'entity' => '',
                    'field' => '',
                    'error' => 'search_index_empty',
                );
            }
        }

        return array(
            'ok' => 0 === (int) $scan['totals']['plaintext']
                && 0 === (int) $scan['totals']['legacy']
                && 0 === $decryptFailed
                && 0 === $tokenErrors
                && $indexOk,
            'index_ok' => $indexOk,
            'plaintext' => (int) $scan['totals']['plaintext'],
            'legacy' => (int) $scan['totals']['legacy'],
            'v2' => (int) $scan['totals']['v2'],
            'token' => (int) $scan['totals']['token'],
            'decrypt_ok' => $decryptOk,
            'decrypt_failed' => $decryptFailed,
            'index_rows' => $indexRows,
            'fields' => $fields,
            'warnings' => $scan['warnings'],
            'errors' => $errors,
            'hpos' => $scan['hpos'],
        );
    }

    /**
     * Re-encrypt all registered fields with the current key.
     *
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public function rotate(array $options = array()): array
    {
        if (!empty($options['dry_run'])) {
            $result = $this->dryRun($options);
            $result['mode'] = 'rotate_dry_run';
            $result['rotation_rows'] = (int) $result['totals']['rows'];
            return $result;
        }

        if (!$this->backupSatisfied($options)) {
            return array(
                'ok' => false,
                'error' => 'backup_required',
                'message' => 'Key rotation re-encrypts data and requires a confirmed backup.',
                'rotated' => 0,
                'errors' => array(),
            );
        }

        $useLock = !isset($options['lock']) || (bool) $options['lock'];
        $token = '';
        if ($useLock) {
            $token = $this->acquireLock();
            if ('' === $token) {
                return array('ok' => false, 'error' => 'locked', 'rotated' => 0, 'errors' => array());
            }
        }

        $batch = isset($options['batch']) ? max(1, min(5000, (int) $options['batch'])) : 500;
        $stateOption = isset($options['state_option']) ? (string) $options['state_option'] : self::STATE_OPTION;
        $resume = !empty($options['resume']);
        $state = $resume ? $this->loadState($stateOption) : $this->resetState($stateOption);
        $targets = Env::targets(
            $this->plugin,
            $this->db,
            isset($options['entity']) ? (string) $options['entity'] : '',
            isset($options['field']) ? (string) $options['field'] : '',
            isset($options['table']) ? (string) $options['table'] : ''
        );

        $summary = array('ok' => true, 'rotated' => 0, 'skipped' => 0, 'errors' => array(), 'resumed' => $resume);

        $safety = $this->maybeSafetyDump($targets, $options);

        if (empty($safety['ok'])) {
            if ($useLock) {
                $this->releaseLock($token);
            }

            return array(
                'ok' => false,
                'error' => 'safety_dump_failed',
                'message' => isset($safety['message']) ? (string) $safety['message'] : 'Safety dump failed.',
                'rotated' => 0,
                'errors' => array(),
            );
        }

        $summary['safety_dump'] = isset($safety['path']) ? $safety['path'] : null;

        try {
            foreach ($targets as $target) {
                $targetKey = Env::targetKey($target);
                $cursor = $resume && isset($state['cursors'][$targetKey]) ? (int) $state['cursors'][$targetKey] : 0;

                while (true) {
                    $rows = $this->fetchBatch($target, $cursor, $batch);
                    if (array() === $rows) {
                        break;
                    }

                    foreach ($rows as $row) {
                        $cursor = isset($row->row_id) ? (int) $row->row_id : $cursor;
                        $state['cursors'][$targetKey] = $cursor;
                        $result = $this->processRow($target, $row, 'both', true, true);

                        if ('migrated' === $result['status']) {
                            $summary['rotated']++;
                        } elseif ('skipped' === $result['status']) {
                            $summary['skipped']++;
                        } elseif ('error' === $result['status']) {
                            $summary['errors'][] = $result['error'];
                        }
                    }

                    $this->saveState($state, $stateOption);

                    if (count($rows) < $batch) {
                        break;
                    }
                }
            }
        } catch (\Throwable $exception) {
            $summary['ok'] = false;
            $summary['error'] = 'rotation_failed';
        } finally {
            if ($useLock) {
                $this->releaseLock($token);
            }
        }

        if (!empty($summary['errors'])) {
            $summary['ok'] = false;
        }

        $this->plugin->logger()->info('key_rotation_finished', array(
            'rotated' => $summary['rotated'],
            'skipped' => $summary['skipped'],
            'errors' => count($summary['errors']),
        ));

        return $summary;
    }

    /**
     * @param array<int, array<string, mixed>> $targets
     * @param array<string, mixed> $options
     * @param array<int, string> $extraTables
     * @return array<string, mixed>
     */
    private function maybeSafetyDump(array $targets, array $options, array $extraTables = array()): array
    {
        $enabled = array_key_exists('safety_dump', $options)
            ? (bool) $options['safety_dump']
            : (null === $this->db);

        if (!$enabled) {
            return array('ok' => true, 'path' => null, 'skipped' => true);
        }

        $tables = array();

        foreach ($targets as $target) {
            if (isset($target['table'])) {
                $tables[] = (string) $target['table'];
            }
        }

        foreach ($extraTables as $table) {
            $tables[] = (string) $table;
        }

        $db = Env::db($this->db);
        if (null !== $db) {
            $tables[] = Env::table($db, 'kec_search_index');
        }

        return SafetyDump::create($this->plugin, $this->db, $tables, $options);
    }

    public function backupSatisfied(array $options = array()): bool
    {
        if (!empty($options['backup_confirmed'])) {
            return true;
        }

        $ack = $this->plugin->option('kec_backup_ack');
        $timestamp = is_array($ack) && isset($ack['timestamp']) ? (int) $ack['timestamp'] : 0;

        return $timestamp > 0
            && $timestamp <= time() + 300
            && (time() - $timestamp) <= 86400;
    }

    public function acquireLock(): string
    {
        $existing = $this->plugin->option(self::LOCK_OPTION);
        if (is_array($existing) && !empty($existing['token'])) {
            $expires = isset($existing['expires']) ? (int) $existing['expires'] : 0;
            if ($expires > time()) {
                return '';
            }

            $this->plugin->deleteOption(self::LOCK_OPTION);
        }

        try {
            $token = bin2hex(random_bytes(16));
        } catch (\Throwable $exception) {
            $token = uniqid('kec', true);
        }

        $lock = array(
            'token' => $token,
            'time' => time(),
            'expires' => time() + 3600,
            'user_id' => function_exists('get_current_user_id') ? (int) get_current_user_id() : 0,
        );

        if (function_exists('add_option')) {
            if (!add_option(self::LOCK_OPTION, $lock, '', false)) {
                $existing = $this->plugin->option(self::LOCK_OPTION);
                if (is_array($existing) && !empty($existing['token'])) {
                    $expires = isset($existing['expires']) ? (int) $existing['expires'] : 0;
                    if ($expires > time()) {
                        return '';
                    }
                }

                $this->plugin->updateOption(self::LOCK_OPTION, $lock);
            }
        } else {
            $this->plugin->updateOption(self::LOCK_OPTION, $lock);
        }

        $this->lockToken = $token;

        return $token;
    }

    public function releaseLock(?string $token = null): void
    {
        if (null !== $token) {
            $existing = $this->plugin->option(self::LOCK_OPTION);
            if (is_array($existing) && isset($existing['token']) && $existing['token'] !== $token) {
                return;
            }
        }

        $this->plugin->deleteOption(self::LOCK_OPTION);
        $this->lockToken = '';
    }

    public function isLocked(): bool
    {
        $lock = $this->plugin->option(self::LOCK_OPTION);
        if (!is_array($lock) || empty($lock['token'])) {
            return false;
        }

        return isset($lock['expires']) && (int) $lock['expires'] > time();
    }

    /**
     * @return array<string, mixed>
     */
    private function scanTarget(array $target, int $sample, bool $checkLength, bool $full = false): array
    {
        $result = array(
            'entity' => $target['entity'],
            'field' => $target['field'],
            'kind' => $target['kind'],
            'table' => $target['kind'] === 'adapter'
                ? (isset($target['adapter_name']) ? $target['adapter_name'] : $target['table'])
                : $target['table'],
            'mode' => $this->isUserTokenTarget($target) ? 'token' : 'encrypted',
            'plaintext' => 0,
            'legacy' => 0,
            'v2' => 0,
            'token' => 0,
            'empty' => 0,
            'rows' => 0,
            'total' => 0,
            'length' => array('max' => Env::fieldMaxLength($target['field_obj']), 'risk' => false, 'observed' => 0),
            'error' => '',
        );

        $db = Env::db($this->db);
        if (null === $db) {
            $result['error'] = 'scan_failed';

            return $result;
        }

        $where = Env::targetWhereSql($db, $target, $target['value_col'] . " <> ''");
        $result['total'] = (int) Env::getVar($db, 'SELECT COUNT(*) FROM ' . $target['table'] . ($where !== '' ? ' WHERE ' . $where : ''));

        if ('' !== Env::lastError($db)) {
            $result['error'] = 'scan_failed';

            return $result;
        }

        if (!$full) {
            $sql = 'SELECT ' . $target['id_col'] . ' AS row_id, '
                . $target['entity_id_col'] . ' AS entity_id, '
                . $target['value_col'] . ' AS value'
                . ' FROM ' . $target['table']
                . ($where !== '' ? ' WHERE ' . $where : '')
                . ' ORDER BY ' . $target['id_col'] . ' ASC LIMIT ' . (int) $sample;

            $rows = Env::getResults($db, $sql);

            if ('' !== Env::lastError($db)) {
                $result['error'] = 'scan_failed';

                return $result;
            }

            $this->accumulateRows($result, $rows, $target, $checkLength);

            return $result;
        }

        $cursor = 0;
        $batch = 500;

        while (true) {
            $batchWhere = Env::targetWhereSql(
                $db,
                $target,
                $target['value_col'] . " <> '' AND " . $target['id_col'] . ' > ' . (int) $cursor
            );

            $sql = 'SELECT ' . $target['id_col'] . ' AS row_id, '
                . $target['entity_id_col'] . ' AS entity_id, '
                . $target['value_col'] . ' AS value'
                . ' FROM ' . $target['table']
                . ($batchWhere !== '' ? ' WHERE ' . $batchWhere : '')
                . ' ORDER BY ' . $target['id_col'] . ' ASC LIMIT ' . (int) $batch;

            $rows = Env::getResults($db, $sql);

            if ('' !== Env::lastError($db)) {
                $result['error'] = 'scan_failed';

                return $result;
            }

            if (array() === $rows) {
                break;
            }

            $this->accumulateRows($result, $rows, $target, $checkLength);

            $last = end($rows);
            $cursor = isset($last->row_id) ? (int) $last->row_id : $cursor;

            if (count($rows) < $batch) {
                break;
            }
        }

        return $result;
    }

    /**
     * @param array<string, mixed> $result
     * @param object[] $rows
     * @param array<string, mixed> $target
     */
    private function accumulateRows(array &$result, array $rows, array $target, bool $checkLength): void
    {
        $max = $result['length']['max'];
        $tokenTarget = $this->isUserTokenTarget($target);
        $tokenName = $tokenTarget ? $this->tokenName($target) : '';

        foreach ($rows as $row) {
            $value = isset($row->value) ? (string) $row->value : '';
            $class = Env::classify($this->plugin, $value, $target['field_obj']);

            if ('empty' === $class) {
                $result['empty']++;
                continue;
            }

            if ($tokenTarget && $this->columnStore()->isToken($value, $tokenName)) {
                $class = 'token';
            }

            $result[$class]++;
            $result['rows']++;

            if ($checkLength) {
                if ($tokenTarget) {
                    $observed = 'token' === $class ? strlen($value) : 55;
                    $result['length']['observed'] = max($result['length']['observed'], $observed);
                    if ('token' === $class && null !== $max && $max > 0 && $observed > $max) {
                        $result['length']['risk'] = true;
                    }
                } elseif ('plaintext' === $class) {
                    $estimated = (int) ceil((strlen($value) + 48) * 1.34);
                    $result['length']['observed'] = max($result['length']['observed'], $estimated);
                    if (null !== $max && $max > 0 && $estimated > $max) {
                        $result['length']['risk'] = true;
                    }
                } elseif (null !== $max && $max > 0 && strlen($value) > $max) {
                    $result['length']['observed'] = max($result['length']['observed'], strlen($value));
                    $result['length']['risk'] = true;
                }
            }
        }
    }

    /**
     * @param array<string, mixed> $target
     */
    private function isUserTokenTarget(array $target): bool
    {
        return 'user' === $target['entity']
            && 'column' === $target['kind']
            && in_array($target['field'], array('user_login', 'user_email'), true);
    }

    /**
     * @param array<string, mixed> $fieldRow
     */
    private function isUserTokenFieldRow(array $fieldRow): bool
    {
        return 'user' === $fieldRow['entity']
            && 'column' === $fieldRow['kind']
            && in_array($fieldRow['field'], array('user_login', 'user_email'), true);
    }

    /**
     * @param array<string, mixed> $target
     */
    private function tokenName(array $target): string
    {
        return 'user_login' === $target['field'] ? ColumnStore::LOGIN : ColumnStore::EMAIL;
    }

    /**
     * @param array<string, mixed> $target
     * @param array<int, array<string, mixed>> $errors
     */
    private function verifyTokenTarget(array $target, int &$ok, int &$failed, array &$errors, bool $full = false): void
    {
        $columns = $this->columnStore();
        $name = $this->tokenName($target);
        $checked = 0;
        $cursor = 0;
        $batch = $full ? 500 : 50;

        while (true) {
            $rows = $this->fetchBatch($target, $cursor, $batch);
            if (array() === $rows) {
                break;
            }

            foreach ($rows as $row) {
                $cursor = isset($row->row_id) ? (int) $row->row_id : $cursor;
                $value = isset($row->value) ? (string) $row->value : '';

                if (!$columns->isToken($value, $name)) {
                    continue;
                }

                $userId = isset($row->entity_id) ? (int) $row->entity_id : 0;
                $plain = $this->readMetaPlain($userId, $name);

                if (null === $plain) {
                    $failed++;
                    $errors[] = array(
                        'entity' => $target['entity'],
                        'field' => $target['field'],
                        'id' => isset($row->row_id) ? (int) $row->row_id : 0,
                        'error' => 'meta_decrypt_failed',
                    );
                } else {
                    $ok++;
                }

                $checked++;

                if (!$full && $checked >= 10) {
                    return;
                }
            }

            if (!$full || count($rows) < $batch) {
                break;
            }
        }
    }

    private function verifyEncryptedTarget(array $target, int &$ok, int &$failed, array &$errors, bool $full): void
    {
        $cursor = 0;
        $batch = $full ? 500 : 50;
        $checked = 0;

        while (true) {
            $rows = $this->fetchEncryptedSample($target, $batch, $cursor);
            if (array() === $rows) {
                break;
            }

            foreach ($rows as $row) {
                $cursor = isset($row->row_id) ? (int) $row->row_id : $cursor;
                $value = isset($row->value) ? (string) $row->value : '';

                if (!Env::isEncrypted($this->plugin, $value, $target['field_obj'])) {
                    continue;
                }

                try {
                    $plain = $this->plugin->crypto()->decrypt($value, $target['field_obj']);
                    if (!Env::isEncrypted($this->plugin, $plain, $target['field_obj'])) {
                        $ok++;
                    } else {
                        $failed++;
                        $errors[] = array(
                            'entity' => $target['entity'],
                            'field' => $target['field'],
                            'id' => isset($row->row_id) ? (int) $row->row_id : 0,
                            'error' => 'decrypt_failed',
                        );
                    }
                } catch (\Throwable $exception) {
                    $failed++;
                    $errors[] = array(
                        'entity' => $target['entity'],
                        'field' => $target['field'],
                        'id' => isset($row->row_id) ? (int) $row->row_id : 0,
                        'error' => 'decrypt_failed',
                    );
                }

                $checked++;

                if (!$full && $checked >= 50) {
                    return;
                }
            }

            if (!$full || count($rows) < $batch) {
                break;
            }
        }
    }

    private function columnStore(): ColumnStore
    {
        if (null === $this->columns) {
            $this->columns = new ColumnStore($this->plugin);
        }

        return $this->columns;
    }

    /**
     * @param array<string, mixed> $target
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    private function processRow(array $target, object $row, string $from, bool $encrypt, bool $reencryptV2 = false): array
    {
        $value = isset($row->value) ? (string) $row->value : '';
        $field = $target['field_obj'];
        $class = Env::classify($this->plugin, $value, $field);

        if ('empty' === $class) {
            return array('status' => 'skipped');
        }

        if (!$encrypt && $field->isInternal()) {
            return array('status' => 'skipped');
        }

        if ('plaintext' === $class
            && 'plaintext' !== $from
            && $this->looksLikeLegacyIdentifier($value, $field)
        ) {
            return $this->error($target, $row, 'legacy_key_missing');
        }

        if ($this->isUserTokenTarget($target)) {
            return $this->processUserColumnRow($target, $row, $from, $encrypt, $reencryptV2);
        }

        if ($encrypt) {
            if ('v2' === $class && !$reencryptV2) {
                return array('status' => 'skipped');
            }

            if ('both' !== $from) {
                if ('plaintext' === $from && 'plaintext' !== $class) {
                    return array('status' => 'skipped');
                }
                if ('legacy' === $from && 'legacy' !== $class) {
                    return array('status' => 'skipped');
                }
            }

            $plain = $value;
            if ('legacy' === $class || 'v2' === $class) {
                try {
                    $plain = $this->plugin->crypto()->decrypt($value, $field);
                } catch (\Throwable $exception) {
                    $plain = '';
                }

                if ('' === $plain || Env::isEncrypted($this->plugin, $plain, $field)) {
                    return $this->error($target, $row, 'decrypt_failed');
                }
            }

            $plain = $this->normalizeForField($plain, $field);

            try {
                $cipher = $this->plugin->crypto()->encrypt($plain, $field);
            } catch (\Throwable $exception) {
                $message = $exception->getMessage();
                return $this->error(
                    $target,
                    $row,
                    false !== stripos($message, 'max length') ? 'length_exceeded' : 'encrypt_failed'
                );
            }

            if (!Env::isEncrypted($this->plugin, $cipher, $field)) {
                return $this->error($target, $row, 'encrypt_failed');
            }

            $max = Env::fieldMaxLength($field);
            if (null !== $max && $max > 0 && strlen($cipher) > $max) {
                return $this->error($target, $row, 'length_exceeded');
            }

            $written = $this->writeValue($target, $row, $cipher);
            if (!$written) {
                return $this->error($target, $row, 'write_failed');
            }

            $this->indexRow($target, $row);

            return array('status' => 'migrated');
        }

        if ('plaintext' === $class) {
            return array('status' => 'skipped');
        }

        try {
            $plain = $this->plugin->crypto()->decrypt($value, $field);
        } catch (\Throwable $exception) {
            $plain = '';
        }

        if ('' === $plain || Env::isEncrypted($this->plugin, $plain, $field)) {
            return $this->error($target, $row, 'decrypt_failed');
        }

        $max = Env::fieldMaxLength($field);
        if (null !== $max && $max > 0 && strlen($plain) > $max) {
            return $this->error($target, $row, 'length_exceeded');
        }

        $written = $this->writePlainValue($target, $row, $plain);
        if (!$written) {
            return $this->error($target, $row, 'write_failed');
        }

        return array('status' => 'migrated');
    }

    /**
     * @param array<string, mixed> $target
     * @return array<string, mixed>
     */
    private function processUserColumnRow(array $target, object $row, string $from, bool $encrypt, bool $rotate): array
    {
        $columns = $this->columnStore();
        $name = $this->tokenName($target);
        $field = $target['field_obj'];
        $value = isset($row->value) ? (string) $row->value : '';
        $userId = isset($row->entity_id) ? (int) $row->entity_id : (isset($row->row_id) ? (int) $row->row_id : 0);
        $isToken = $columns->isToken($value, $name);

        if (!$encrypt) {
            if (!$isToken) {
                return array('status' => 'skipped');
            }

            $plain = $columns->plainFromStored($value, $name, $userId);
            if ('' === $plain || $columns->isToken($plain, $name)) {
                return $this->error($target, $row, 'decrypt_failed');
            }

            $written = $this->writePlainValue($target, $row, $plain);
            if (!$written) {
                return $this->error($target, $row, 'write_failed');
            }

            return array('status' => 'migrated');
        }

        if ($isToken) {
            $plain = $this->readMetaPlain($userId, $name);

            if (null === $plain) {
                return $this->error($target, $row, 'meta_missing');
            }

            if (!$rotate) {
                return array('status' => 'skipped');
            }
        } else {
            $class = Env::classify($this->plugin, $value, $field);

            if ('both' !== $from) {
                if ('plaintext' === $from && 'plaintext' !== $class) {
                    return array('status' => 'skipped');
                }
                if ('legacy' === $from && 'legacy' !== $class) {
                    return array('status' => 'skipped');
                }
            }

            $plain = $columns->plainFromStored($value, $name, $userId);

            if ('' === $plain) {
                return array('status' => 'skipped');
            }

            if (Env::isEncrypted($this->plugin, $value, $field) && $plain === $value) {
                return $this->error($target, $row, 'decrypt_failed');
            }
        }

        $plain = $this->normalizeForField($plain, $field);

        if ($isToken && !$rotate) {
            $token = $value;
        } elseif ($isToken) {
            $token = $columns->tokenFor($plain, $name);
        } else {
            $token = $columns->lookupToken($plain, $name);
        }

        if (!is_string($token) || '' === $token) {
            return $this->error($target, $row, 'token_failed');
        }

        $max = Env::fieldMaxLength($field);
        if (null !== $max && $max > 0 && strlen($token) > $max) {
            return $this->error($target, $row, 'length_exceeded');
        }

        if (!$columns->storePlain($userId, $plain, $name)) {
            return $this->error($target, $row, 'plaintext_not_stored');
        }

        if ($columns->readPlain($userId, $name) !== $plain) {
            return $this->error($target, $row, 'plaintext_not_stored');
        }

        $written = $this->writeValue($target, $row, $token);
        if (!$written) {
            return $this->error($target, $row, 'write_failed');
        }

        $this->indexRow($target, $row);

        return array('status' => 'migrated');
    }

    private function readMetaPlain(int $userId, string $name): ?string
    {
        if ($userId <= 0) {
            return null;
        }

        $columns = $this->columnStore();
        $value = $columns->readPlain($userId, $name);
        if (!is_string($value) || '' === $value) {
            return null;
        }

        $metaKey = $columns->metaKey($name);
        $field = null;

        try {
            $field = $this->plugin->registry()->get('user', $metaKey);
        } catch (\Throwable $exception) {
            $field = null;
        }

        if (!$field instanceof Field) {
            $field = new Field('user', $metaKey, 'text', false, null, array('internal' => true));
        }

        if (Env::isEncrypted($this->plugin, $value, $field)) {
            try {
                $plain = $this->plugin->crypto()->decrypt($value, $field);
                if (is_string($plain) && '' !== $plain) {
                    return $plain;
                }
            } catch (\Throwable $exception) {
                return null;
            }

            return null;
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $target
     * @return array<string, mixed>
     */
    private function error(array $target, object $row, string $code): array
    {
        $id = isset($row->row_id) ? (int) $row->row_id : 0;

        $this->plugin->logger()->warning('migration_row_error', array(
            'entity' => $target['entity'],
            'field' => $target['field'],
            'row_id' => $id,
            'error' => $code,
        ));

        return array(
            'status' => 'error',
            'error' => array(
                'entity' => $target['entity'],
                'field' => $target['field'],
                'id' => $id,
                'error' => $code,
            ),
        );
    }

    /**
     * Write plaintext without letting MetaWriteGuard re-encrypt it.
     *
     * @param array<string, mixed> $target
     */
    private function writePlainValue(array $target, object $row, string $value): bool
    {
        \EncryptedFields\Meta\MetaWriteGuard::suspend();
        \EncryptedFields\Query\QueryRewriter::suspend();

        try {
            return $this->writeValue($target, $row, $value);
        } finally {
            \EncryptedFields\Query\QueryRewriter::resume();
            \EncryptedFields\Meta\MetaWriteGuard::resume();
        }
    }

    /**
     * @param array<string, mixed> $target
     */
    private function writeValue(array $target, object $row, string $value): bool
    {
        if ('adapter' === $target['kind']) {
            $adapter = isset($target['adapter']) ? $target['adapter'] : null;
            if (!is_object($adapter) || !method_exists($adapter, 'write')) {
                return false;
            }

            $id = isset($row->entity_id) ? (int) $row->entity_id : 0;
            try {
                return (bool) $adapter->write($id, array($target['field'] => $value));
            } catch (\Throwable $exception) {
                return false;
            }
        }

        $db = Env::db($this->db);
        if (null === $db || !method_exists($db, 'update')) {
            return false;
        }

        $id = isset($row->row_id) ? (int) $row->row_id : 0;
        $updated = $db->update(
            $target['table'],
            array($target['value_col'] => $value),
            array($target['id_col'] => $id)
        );

        return false !== $updated;
    }

    /**
     * @param array<string, mixed> $target
     */
    private function indexRow(array $target, object $row): void
    {
        $search = $this->plugin->search();
        if (null === $search || !$target['field_obj']->isSearchable()) {
            return;
        }

        $id = isset($row->entity_id) ? (int) $row->entity_id : 0;
        if ($id <= 0) {
            return;
        }

        try {
            $search->index($target['entity'], $id);
        } catch (\Throwable $exception) {
            $this->plugin->logger()->warning('search_index_failed', array(
                'entity' => $target['entity'],
                'field' => $target['field'],
                'id' => $id,
            ));
        }
    }

    /**
     * @param array<string, mixed> $target
     */
    private function removeIndexRow(array $target, object $row): void
    {
        $search = $this->plugin->search();
        if (null === $search || !$target['field_obj']->isSearchable()) {
            return;
        }

        $id = isset($row->entity_id) ? (int) $row->entity_id : 0;
        if ($id <= 0) {
            return;
        }

        try {
            $search->remove($target['entity'], $id);
        } catch (\Throwable $exception) {
            $this->plugin->logger()->warning('search_index_remove_failed', array(
                'entity' => $target['entity'],
                'field' => $target['field'],
                'id' => $id,
            ));
        }
    }

    /**
     * @param array<string, mixed> $target
     * @return object[]
     */
    private function fetchBatch(array $target, int $cursor, int $batch): array
    {
        $db = Env::db($this->db);
        if (null === $db) {
            return array();
        }

        $where = Env::targetWhereSql(
            $db,
            $target,
            $target['value_col'] . " <> '' AND " . $target['id_col'] . ' > ' . (int) $cursor
        );

        $sql = 'SELECT ' . $target['id_col'] . ' AS row_id, '
            . $target['entity_id_col'] . ' AS entity_id, '
            . $target['value_col'] . ' AS value'
            . ' FROM ' . $target['table']
            . ($where !== '' ? ' WHERE ' . $where : '')
            . ' ORDER BY ' . $target['id_col'] . ' ASC LIMIT ' . (int) $batch;

        return Env::getResults($db, $sql);
    }

    /**
     * @param array<string, mixed> $target
     * @return object[]
     */
    private function fetchEncryptedSample(array $target, int $limit, int $cursor = 0): array
    {
        $db = Env::db($this->db);
        if (null === $db) {
            return array();
        }

        $where = Env::targetWhereSql(
            $db,
            $target,
            $target['value_col'] . " LIKE 'enc:v2%'"
            . ($cursor > 0 ? ' AND ' . $target['id_col'] . ' > ' . (int) $cursor : '')
        );

        $sql = 'SELECT ' . $target['id_col'] . ' AS row_id, '
            . $target['entity_id_col'] . ' AS entity_id, '
            . $target['value_col'] . ' AS value'
            . ' FROM ' . $target['table']
            . ($where !== '' ? ' WHERE ' . $where : '')
            . ' ORDER BY ' . $target['id_col'] . ' ASC'
            . ($limit > 0 ? ' LIMIT ' . (int) $limit : '');

        return Env::getResults($db, $sql);
    }

    /**
     * Strong-ish legacy detector. Avoids treating ordinary emails/logins as
     * legacy ciphertext while still catching base64-shaped values.
     */
    private function looksLikeLegacyIdentifier(string $value, Field $field): bool
    {
        $type = $field->type();

        if ('login' === $type) {
            if (1 === preg_match('/^[A-Za-z0-9_.@ -]+$/', $value)) {
                return false;
            }

            if (1 !== preg_match('/^[A-Za-z0-9+\/=]{16,}={0,2}$/', $value)) {
                return false;
            }

            $decoded = base64_decode($value, true);

            return false !== $decoded && strlen($decoded) >= 16;
        }

        if ('email' === $type) {
            $parts = explode('@', $value);

            if (2 !== count($parts) || 1 !== preg_match('/[+\/=]/', $parts[0])) {
                return false;
            }

            $decoded = base64_decode($parts[0], true);

            return false !== $decoded && strlen($decoded) > 16;
        }

        return false;
    }

    private function normalizeForField(string $value, Field $field): string
    {
        if (!in_array($field->type(), array('email', 'login'), true)) {
            return $value;
        }

        $value = trim($value);

        return function_exists('mb_strtolower') ? mb_strtolower($value, 'UTF-8') : strtolower($value);
    }

    /**
     * @return array<string, mixed>
     */
    private function loadState(string $option = self::STATE_OPTION): array
    {
        $state = $this->plugin->option($option);
        if (!is_array($state) || !isset($state['cursors']) || !is_array($state['cursors'])) {
            return array('cursors' => array(), 'started' => time());
        }

        return $state;
    }

    /**
     * @return array<string, mixed>
     */
    private function resetState(string $option = self::STATE_OPTION): array
    {
        $state = array('cursors' => array(), 'started' => time());
        $this->plugin->updateOption($option, $state);

        return $state;
    }

    /**
     * @param array<string, mixed> $state
     */
    private function saveState(array $state, string $option = self::STATE_OPTION): void
    {
        $state['updated'] = time();
        $this->plugin->updateOption($option, $state);

        if ('' === $this->lockToken) {
            return;
        }

        $lock = $this->plugin->option(self::LOCK_OPTION);
        if (is_array($lock) && isset($lock['token']) && $lock['token'] === $this->lockToken) {
            $lock['expires'] = time() + 3600;
            $this->plugin->updateOption(self::LOCK_OPTION, $lock);
        }
    }
}
