<?php

namespace EncryptedFields\Cli;

use EncryptedFields\Crypto\RotationService;
use EncryptedFields\Migration\Env;
use EncryptedFields\Migration\LookupMigrator;
use EncryptedFields\Migration\Migrator;
use EncryptedFields\Migration\StateDetector;
use EncryptedFields\Plugin;

/**
 * WP-CLI commands for Encrypted Fields.
 */
final class Commands
{
    private Plugin $plugin;

    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    public function register(): void
    {
        if (!class_exists('WP_CLI')) {
            return;
        }

        \WP_CLI::add_command('kec', $this);
    }

    /**
     * Show installation status.
     */
    public function status($args = array(), $assoc = array()): void
    {
        $state = (new StateDetector($this->plugin))->detect();
        $userColumns = $this->plugin->registry()->columns('user');
        $userColumnMode = (isset($userColumns['user_login']) || isset($userColumns['user_email'])) ? 'token' : 'none';
        $rows = array(
            array('key' => 'state', 'value' => $state['state']),
            array('key' => 'registry_enabled', 'value' => $state['registry_enabled'] ? 'yes' : 'no'),
            array('key' => 'user_column_mode', 'value' => $userColumnMode),
            array('key' => 'key_configured', 'value' => $state['key_configured'] ? 'yes' : 'no'),
            array('key' => 'key_source', 'value' => $state['key_source']),
            array('key' => 'key_id', 'value' => $state['key_id'] ?: 'n/a'),
            array('key' => 'hpos', 'value' => $state['hpos'] ? 'enabled' : 'disabled'),
            array('key' => 'backup_ack', 'value' => !empty($state['backup_ack']['timestamp']) ? gmdate('Y-m-d H:i:s', (int) $state['backup_ack']['timestamp']) : 'none'),
            array('key' => 'plaintext_samples', 'value' => (string) $state['counts']['plaintext']),
            array('key' => 'legacy_samples', 'value' => (string) $state['counts']['legacy']),
            array('key' => 'v2_samples', 'value' => (string) $state['counts']['v2']),
            array('key' => 'migration_locked', 'value' => (new Migrator($this->plugin))->isLocked() ? 'yes' : 'no'),
        );

        $this->output($rows, $assoc);

        foreach ($state['warnings'] as $warning) {
            if (isset($warning['message'])) {
                \WP_CLI::warning((string) $warning['message']);
            }
        }
    }

    /**
     * List registered fields.
     */
    public function fields($args = array(), $assoc = array()): void
    {
        $rows = array();
        foreach ($this->plugin->registry()->all() as $entity => $fields) {
            foreach ($fields as $key => $field) {
                $rows[] = array(
                    'entity' => $entity,
                    'field' => $key,
                    'kind' => $field->isColumn() ? 'column' : 'meta',
                    'type' => $field->type(),
                    'cipher' => $field->cipherName(),
                    'search' => $field->isSearchable() ? 'yes' : 'no',
                    'readonly' => $this->plugin->registry()->isReadonly($entity, $key) ? 'yes' : 'no',
                );
            }
        }

        $this->output($rows, $assoc);
    }

    /**
     * Configure registry/preset.
     *
     * ## OPTIONS
     *
     * [--mode=<mode>]
     * : fresh or existing.
     *
     * [--preset=<preset>]
     * : minimal, full or custom.
     *
     * [--fields=<file>]
     * : JSON registry file.
     */
    public function setup($args = array(), $assoc = array()): void
    {
        $preset = isset($assoc['preset']) ? (string) $assoc['preset'] : 'minimal';
        $registry = null;

        if (!empty($assoc['fields'])) {
            $file = (string) $assoc['fields'];
            if (!is_file($file)) {
                \WP_CLI::error('Fields file not found: ' . $file);
                return;
            }
            $decoded = json_decode((string) file_get_contents($file), true);
            if (!is_array($decoded)) {
                \WP_CLI::error('Fields file is not a valid JSON registry.');
                return;
            }
            $registry = $decoded;
        } else {
            $registry = $this->preset($preset);
        }

        if (!is_array($registry)) {
            \WP_CLI::error('Unknown preset or invalid registry.');
            return;
        }

        if (Env::hposEnabled() && isset($registry['post'])) {
            unset($registry['post']);
            \WP_CLI::warning('HPOS is enabled; post/order fields were removed.');
        }

        $this->plugin->updateOption('kec_field_registry', $registry);
        $this->plugin->logger()->info('cli_setup_saved', array(
            'mode' => isset($assoc['mode']) ? (string) $assoc['mode'] : 'fresh',
            'preset' => $preset,
        ));

        \WP_CLI::success('Registry saved. Run `wp kec migrate --backup-confirmed` for existing data.');
    }

    /**
     * Scan fields and rows.
     *
     * ## OPTIONS
     *
     * [--entity=<entity>]
     * [--field=<field>]
     * [--table=<table>]
     * [--check-length]
     * [--format=<format>]
     */
    public function scan($args = array(), $assoc = array()): void
    {
        $result = (new Migrator($this->plugin))->scan(array(
            'entity' => isset($assoc['entity']) ? (string) $assoc['entity'] : '',
            'field' => isset($assoc['field']) ? (string) $assoc['field'] : '',
            'table' => isset($assoc['table']) ? (string) $assoc['table'] : '',
            'check_length' => !empty($assoc['check-length']),
            'sample_limit' => 100,
        ));

        $rows = array();
        foreach ($result['fields'] as $field) {
            $rows[] = array(
                'entity' => $field['entity'],
                'field' => $field['field'],
                'kind' => $field['kind'],
                'mode' => isset($field['mode']) ? $field['mode'] : 'encrypted',
                'total' => $field['total'],
                'plaintext' => $field['plaintext'],
                'legacy' => $field['legacy'],
                'v2' => $field['v2'],
                'token' => isset($field['token']) ? $field['token'] : 0,
                'length_risk' => !empty($field['length']['risk']) ? 'yes' : 'no',
            );
        }

        if (empty($rows)) {
            \WP_CLI::warning('No matching fields.');
            return;
        }

        $this->output($rows, $assoc);
        $totals = $result['totals'];
        \WP_CLI::log(sprintf(
            'Totals: %d plaintext, %d legacy, %d v2, %d token, %d rows.',
            (int) $totals['plaintext'],
            (int) $totals['legacy'],
            (int) $totals['v2'],
            (int) ($totals['token'] ?? 0),
            (int) $totals['rows']
        ));
    }

    /**
     * Migrate plaintext/legacy values to v2; user columns become blind-index tokens.
     *
     * ## OPTIONS
     *
     * [--from=<source>]
     * [--entity=<entity>]
     * [--field=<field>]
     * [--table=<table>]
     * [--dry-run]
     * [--batch=<batch>]
     * [--backup-confirmed]
     * [--resume]
     * [--no-safety-dump]
     */
    public function migrate($args = array(), $assoc = array()): void
    {
        $entity = isset($assoc['entity']) ? (string) $assoc['entity'] : '';
        $field = isset($assoc['field']) ? (string) $assoc['field'] : '';

        if ('' !== $field && false !== strpos($field, ':')) {
            list($fieldEntity, $fieldKey) = explode(':', $field, 2);

            if ('' === $entity) {
                $entity = $fieldEntity;
            }

            $field = $fieldKey;
        }

        $options = array(
            'from' => isset($assoc['from']) ? (string) $assoc['from'] : 'both',
            'entity' => $entity,
            'field' => $field,
            'table' => isset($assoc['table']) ? (string) $assoc['table'] : '',
            'dry_run' => !empty($assoc['dry-run']),
            'batch' => isset($assoc['batch']) ? max(1, (int) $assoc['batch']) : 500,
            'backup_confirmed' => !empty($assoc['backup-confirmed']),
            'resume' => !empty($assoc['resume']),
            'safety_dump' => $this->safetyDumpEnabled($assoc),
        );

        $migrator = new Migrator($this->plugin);
        $result = $migrator->migrate($options);

        $error = isset($result['error']) ? (string) $result['error'] : '';

        if ('' !== $error) {
            if ('backup_required' === $error) {
                \WP_CLI::warning('Backup confirmation required. Pass --backup-confirmed after creating a backup.');
                \WP_CLI::halt(2);
            }
            if ('locked' === $error) {
                \WP_CLI::warning('Another migration is running.');
                \WP_CLI::halt(2);
            }
            \WP_CLI::error(isset($result['message']) ? (string) $result['message'] : $error);
            return;
        }

        if (!empty($options['dry_run'])) {
            $this->printDryRun($result, $assoc);
            return;
        }

        if (empty($result['ok'])) {
            \WP_CLI::error('Migration failed.');
            return;
        }

        \WP_CLI::success(sprintf(
            'Migration complete: %d migrated, %d skipped, %d errors%s.',
            (int) $result['migrated'],
            (int) $result['skipped'],
            count($result['errors']),
            !empty($result['stopped']) ? ' (stopped on error)' : ''
        ));

        if (!empty($result['safety_dump'])) {
            \WP_CLI::log('Safety dump: ' . (string) $result['safety_dump']);
        }

        if (!empty($result['stopped'])) {
            \WP_CLI::halt(2);
        }
    }

    /**
     * Decrypt selected fields back to plaintext.
     *
     * ## OPTIONS
     *
     * --field=<entity:key>
     * : Field to decrypt.
     *
     * [--batch=<batch>]
     * : Rows per batch.
     *
     * [--dry-run]
     * : Print what would change.
     *
     * [--no-safety-dump]
     * : Skip the automatic safety dump.
     */
    public function decrypt($args = array(), $assoc = array()): void
    {
        $target = isset($assoc['field']) ? (string) $assoc['field'] : '';
        if (false === strpos($target, ':')) {
            \WP_CLI::error('Use --field=<entity:key>.');
            return;
        }

        list($entity, $field) = explode(':', $target, 2);

        $result = (new Migrator($this->plugin))->decrypt(array(
            'entity' => $entity,
            'field' => $field,
            'batch' => isset($assoc['batch']) ? max(1, (int) $assoc['batch']) : 500,
            'dry_run' => !empty($assoc['dry-run']),
            'safety_dump' => $this->safetyDumpEnabled($assoc),
        ));

        if (!empty($assoc['dry-run'])) {
            $this->printDryRun($result, $assoc);
            return;
        }

        if (empty($result['ok'])) {
            \WP_CLI::warning(sprintf('Decrypt finished with %d errors.', count($result['errors'])));
            \WP_CLI::halt(2);
        }

        \WP_CLI::success(sprintf('Decrypted %d rows, skipped %d.', (int) $result['decrypted'], (int) $result['skipped']));

        if (!empty($result['safety_dump'])) {
            \WP_CLI::log('Safety dump: ' . (string) $result['safety_dump']);
        }
    }

    /**
     * Roll back to plaintext or print backup restore instructions.
     *
     * ## OPTIONS
     *
     * [--to=<target>]
     * : plaintext (default) or backup.
     *
     * [--backup-confirmed]
     * : Acknowledge that a database backup exists.
     *
     * [--dry-run]
     * : Print what would change.
     *
     * [--no-safety-dump]
     * : Skip the automatic safety dump.
     */
    public function rollback($args = array(), $assoc = array()): void
    {
        $to = isset($assoc['to']) ? (string) $assoc['to'] : 'plaintext';

        if ('backup' === $to) {
            \WP_CLI::log('Restore the confirmed database backup, then keep the original KEC_KEY. Re-run `wp kec verify` after restore.');
            \WP_CLI::halt(2);
        }

        $result = (new Migrator($this->plugin))->rollback(array(
            'dry_run' => !empty($assoc['dry-run']),
            'batch' => isset($assoc['batch']) ? max(1, (int) $assoc['batch']) : 500,
            'backup_confirmed' => !empty($assoc['backup-confirmed']),
            'safety_dump' => $this->safetyDumpEnabled($assoc),
        ));

        $error = isset($result['error']) ? (string) $result['error'] : '';

        if ('' !== $error) {
            if ('backup_required' === $error) {
                \WP_CLI::warning('Backup confirmation required. Pass --backup-confirmed after creating a backup.');
                \WP_CLI::halt(2);
            }

            if ('locked' === $error) {
                \WP_CLI::warning('Another migration is running.');
                \WP_CLI::halt(2);
            }

            \WP_CLI::error(isset($result['message']) ? (string) $result['message'] : $error);
            return;
        }

        if (!empty($assoc['dry-run'])) {
            $this->printDryRun($result, $assoc);
            return;
        }

        if (empty($result['ok'])) {
            \WP_CLI::warning(sprintf('Rollback finished with %d errors.', count($result['errors'])));
            \WP_CLI::halt(2);
        }

        \WP_CLI::success(sprintf('Rollback complete: %d decrypted, %d skipped.', (int) $result['decrypted'], (int) $result['skipped']));

        if (!empty($result['safety_dump'])) {
            \WP_CLI::log('Safety dump: ' . (string) $result['safety_dump']);
        }
    }

    /**
     * Rebuild the blind search index.
     *
     * ## OPTIONS
     *
     * [--entity=<entity>]
     * [--batch=<batch>]
     */
    public function reindex($args = array(), $assoc = array()): void
    {
        $search = $this->plugin->search();
        if (null === $search) {
            \WP_CLI::error('Search service is not available.');
            return;
        }

        $entity = isset($assoc['entity']) ? (string) $assoc['entity'] : 'all';
        $batch = isset($assoc['batch']) ? max(1, (int) $assoc['batch']) : 500;

        $count = $search->reindex($entity, $batch, function ($done, $total) {
            if (class_exists('WP_CLI')) {
                \WP_CLI::log(sprintf('Indexed %d/%d', (int) $done, (int) $total));
            }
        });

        \WP_CLI::success(sprintf('Indexed %d rows for %s.', (int) $count, $entity));
    }

    /**
     * Verify migrated data.
     *
     * ## OPTIONS
     *
     * [--fix]
     * : Rebuild the search index when verification fails.
     *
     * [--entity=<entity>]
     * : Limit verification to one entity.
     *
     * [--field=<field>]
     * : Limit verification to one field.
     *
     * [--full]
     * : Decrypt every row instead of a sample (slower, recommended before go-live).
     */
    public function verify($args = array(), $assoc = array()): void
    {
        $options = array(
            'entity' => isset($assoc['entity']) ? (string) $assoc['entity'] : '',
            'field' => isset($assoc['field']) ? (string) $assoc['field'] : '',
            'full' => !empty($assoc['full']),
        );

        $migrator = new Migrator($this->plugin);
        $result = $migrator->verify($options);

        if (!empty($assoc['fix']) && empty($result['ok'])) {
            $search = $this->plugin->search();
            if (null !== $search) {
                $search->reindex(isset($assoc['entity']) ? (string) $assoc['entity'] : 'all', 500);
                \WP_CLI::log('Search index rebuilt.');
            }
            $result = $migrator->verify($options);
        }

        if (empty($result['ok'])) {
            \WP_CLI::warning(sprintf(
                'Verification failed: %d plaintext, %d legacy, %d decrypt failures, %d errors.',
                (int) $result['plaintext'],
                (int) $result['legacy'],
                (int) $result['decrypt_failed'],
                count($result['errors'])
            ));
            \WP_CLI::halt(2);
        }

        \WP_CLI::success(sprintf(
            'Verification passed: %d v2 rows decrypted, %d %s checked.',
            (int) $result['v2'],
            (int) $result['decrypt_ok'],
            !empty($assoc['full']) ? 'rows' : 'samples'
        ));
    }

    /**
     * Search the blind index.
     *
     * ## OPTIONS
     *
     * <term>
     * : Search term.
     *
     * [--entity=<entity>]
     * : Entity type: user, post, term or comment.
     *
     * [--limit=<limit>]
     * : Maximum number of matches.
     */
    public function search($args = array(), $assoc = array()): void
    {
        $term = isset($args[0]) ? (string) $args[0] : '';
        if ('' === $term) {
            \WP_CLI::error('A search term is required.');
            return;
        }

        $search = $this->plugin->search();
        if (null === $search) {
            \WP_CLI::error('Search service is not available.');
            return;
        }

        $entity = isset($assoc['entity']) ? (string) $assoc['entity'] : 'user';
        $limit = isset($assoc['limit']) ? max(1, (int) $assoc['limit']) : 50;
        $ids = $search->ids($entity, $term, $limit);

        if (empty($ids)) {
            \WP_CLI::log('No matches.');
            return;
        }

        $rows = array();
        foreach ($ids as $id) {
            $rows[] = array('entity' => $entity, 'id' => (int) $id);
        }

        $this->output($rows, $assoc);
    }

    /**
     * Key utilities. Use `wp kec key generate`.
     *
     * ## OPTIONS
     *
     * <action>
     * : generate
     */
    public function key($args = array(), $assoc = array()): void
    {
        $action = isset($args[0]) ? (string) $args[0] : '';

        if ('generate' !== $action) {
            \WP_CLI::error('Usage: wp kec key generate');
            return;
        }

        $key = $this->generateKey();
        if ('' === $key) {
            \WP_CLI::error('Unable to generate a key.');
            return;
        }

        \WP_CLI::log("define('KEC_KEY', '" . $key . "');");
        \WP_CLI::success('Key generated. It is displayed once and was not stored or logged.');
    }

    /**
     * Migrate auxiliary lookup tables.
     *
     * ## OPTIONS
     *
     * <table>
     * : customer_lookup or siteguard_history.
     *
     * [--dry-run]
     * : Print what would change without writing.
     *
     * [--batch=<batch>]
     * : Rows per batch.
     *
     * [--backup-confirmed]
     * : Acknowledge that a database backup exists.
     *
     * [--resume]
     * : Continue a previous run.
     *
     * [--no-safety-dump]
     * : Skip the automatic safety dump.
     *
     * @alias migrate-table
     */
    public function migrate_table($args = array(), $assoc = array()): void
    {
        $type = isset($args[0]) ? (string) $args[0] : '';
        if ('' === $type) {
            \WP_CLI::error('Usage: wp kec migrate-table <customer_lookup|siteguard_history> [--dry-run] [--batch=500] [--backup-confirmed]');
            return;
        }

        $options = array(
            'dry_run' => !empty($assoc['dry-run']),
            'batch' => isset($assoc['batch']) ? max(1, (int) $assoc['batch']) : 500,
            'backup_confirmed' => !empty($assoc['backup-confirmed']),
            'resume' => !empty($assoc['resume']),
            'safety_dump' => $this->safetyDumpEnabled($assoc),
        );

        $result = (new LookupMigrator($this->plugin))->migrateTable($type, $options);

        if (!empty($options['dry_run'])) {
            if (empty($result['ok'])) {
                \WP_CLI::error(isset($result['message']) ? (string) $result['message'] : 'Scan failed.');
                return;
            }

            $rows = array();
            foreach ($result['columns'] as $column) {
                $rows[] = array(
                    'column' => $column['column'],
                    'plaintext' => $column['plaintext'],
                    'legacy' => $column['legacy'],
                    'v2' => $column['v2'],
                    'token' => $column['token'],
                    'pending' => $column['pending'],
                    'rows' => $column['rows'],
                );
            }

            $this->output($rows, $assoc);
            \WP_CLI::log(sprintf(
                'Dry run: %d pending rows. Backup gate: %s.',
                (int) $result['totals']['pending'],
                !empty($result['backup_satisfied']) ? 'satisfied' : 'required'
            ));

            if (!empty($result['requires_backup'])) {
                \WP_CLI::warning('Backup confirmation is required before running the real migration.');
                \WP_CLI::halt(2);
            }

            return;
        }

        if (empty($result['ok'])) {
            $error = isset($result['error']) ? (string) $result['error'] : 'migration_failed';

            if (!empty($result['errors']) && is_array($result['errors'])) {
                foreach (array_slice($result['errors'], 0, 10) as $rowError) {
                    \WP_CLI::log('Row error: ' . json_encode($rowError));
                }
            }

            if ('backup_required' === $error) {
                \WP_CLI::warning('Backup confirmation required. Pass --backup-confirmed after creating a backup.');
                \WP_CLI::halt(2);
            }
            if ('locked' === $error) {
                \WP_CLI::warning('Another migration or rotation is running.');
                \WP_CLI::halt(2);
            }
            \WP_CLI::error(isset($result['message']) ? (string) $result['message'] : $error);
            return;
        }

        \WP_CLI::success(sprintf(
            'Migrated %d rows, skipped %d, %d errors in %s.',
            (int) $result['migrated'],
            (int) $result['skipped'],
            count($result['errors']),
            (string) $result['type']
        ));

        if (!empty($result['safety_dump'])) {
            \WP_CLI::log('Safety dump: ' . (string) $result['safety_dump']);
        }
    }

    /**
     * Rotate the encryption key.
     *
     * Set KEC_KEY_NEXT to the new key and keep the old key in KEC_KEY, then
     * run this command. After it succeeds, promote KEC_KEY_NEXT to KEC_KEY.
     *
     * ## OPTIONS
     *
     * [--dry-run]
     * : Print the rotation plan without re-encrypting.
     *
     * [--batch=<batch>]
     * : Rows per batch.
     *
     * [--backup-confirmed]
     * : Acknowledge that a database backup exists.
     *
     * [--no-safety-dump]
     * : Skip the automatic safety dump.
     *
     * @alias rotate-key
     */
    public function rotate_key($args = array(), $assoc = array()): void
    {
        $keys = $this->plugin->keys();

        if (!method_exists($keys, 'isRotationPending') || !$keys->isRotationPending()) {
            \WP_CLI::error('KEC_KEY_NEXT is required. Set KEC_KEY_NEXT to the new key and keep the old key in KEC_KEY.');
            return;
        }

        $tokenStable = method_exists($keys, 'tokenSecretIsStable') && $keys->tokenSecretIsStable();

        if ($tokenStable) {
            \WP_CLI::log('KEC_TOKEN_SECRET is defined: user_login/user_email tokens stay stable. Encrypted user meta will be re-encrypted.');
        } else {
            \WP_CLI::warning('KEC_TOKEN_SECRET is not defined: key rotation changes user_login/user_email tokens and requires re-tokenizing all users.');
        }

        $dryRun = !empty($assoc['dry-run']);
        $batch = isset($assoc['batch']) ? max(1, (int) $assoc['batch']) : 500;
        $service = new RotationService($this->plugin);
        $result = $service->rotate($dryRun, $batch, function ($done, $total) {
            \WP_CLI::log(sprintf('Rotation phase %d/%d completed.', (int) $done, (int) $total));
        }, !empty($assoc['backup-confirmed']), $this->safetyDumpEnabled($assoc));

        if (!empty($dryRun)) {
            if (empty($result['ok'])) {
                \WP_CLI::error(isset($result['message']) ? (string) $result['message'] : 'Rotation dry run failed.');
                return;
            }

            \WP_CLI::log(sprintf(
                'Rotation dry run: %d rows would be re-encrypted. Tokens: %s. Backup gate: %s.',
                (int) $result['rows'],
                !empty($result['tokens_reissued']) ? 'reissued' : 'stable',
                !empty($result['backup_satisfied']) ? 'satisfied' : 'required'
            ));
            return;
        }

        if (empty($result['ok'])) {
            $error = isset($result['error']) ? (string) $result['error'] : 'rotation_failed';
            if ('backup_required' === $error) {
                \WP_CLI::warning('Backup confirmation required. Pass --backup-confirmed after creating a backup.');
                \WP_CLI::halt(2);
            }
            if ('locked' === $error) {
                \WP_CLI::warning('Another migration or rotation is running.');
                \WP_CLI::halt(2);
            }
            \WP_CLI::error(isset($result['message']) ? (string) $result['message'] : $error);
            return;
        }

        \WP_CLI::success(sprintf(
            'Rotated %d rows, skipped %d, %d errors. Verification %s.',
            (int) $result['rotated'],
            (int) $result['skipped'],
            count($result['errors']),
            empty($result['errors']) ? 'passed' : 'needs attention'
        ));

        foreach (isset($result['safety_dumps']) && is_array($result['safety_dumps']) ? $result['safety_dumps'] : array() as $safetyDump) {
            \WP_CLI::log('Safety dump: ' . (string) $safetyDump);
        }

        \WP_CLI::warning('After confirming success, set KEC_KEY to the value of KEC_KEY_NEXT and remove KEC_KEY_NEXT.');
    }

    /**
     * @param array<string, mixed> $result
     * @param array<string, mixed> $assoc
     */
    private function printDryRun(array $result, array $assoc): void
    {
        $rows = array();
        foreach (isset($result['fields']) && is_array($result['fields']) ? $result['fields'] : array() as $field) {
            $rows[] = array(
                'entity' => $field['entity'],
                'field' => $field['field'],
                'plaintext' => $field['plaintext'],
                'legacy' => $field['legacy'],
                'v2' => $field['v2'],
                'total' => $field['total'],
                'length_risk' => !empty($field['length']['risk']) ? 'yes' : 'no',
            );
        }

        if ($rows) {
            $this->output($rows, $assoc);
        }

        if (isset($result['totals'])) {
            \WP_CLI::log(sprintf(
                'Dry run: %d plaintext, %d legacy, %d v2, %d rows. Backup gate: %s.',
                (int) $result['totals']['plaintext'],
                (int) $result['totals']['legacy'],
                (int) $result['totals']['v2'],
                (int) $result['totals']['rows'],
                !empty($result['backup_satisfied']) ? 'satisfied' : 'required'
            ));
        }

        if (!empty($result['requires_backup'])) {
            \WP_CLI::warning('Backup confirmation is required before running the real migration.');
            \WP_CLI::halt(2);
        }
    }

    /**
     * @param array<string, mixed> $assoc
     */
    private function safetyDumpEnabled(array $assoc): bool
    {
        if (!empty($assoc['no-safety-dump'])) {
            return false;
        }

        if (isset($assoc['safety-dump'])) {
            return (bool) $assoc['safety-dump'];
        }

        return true;
    }

    /**
     * @param array<int, array<string, mixed>> $rows
     * @param array<string, mixed> $assoc
     */
    private function output(array $rows, array $assoc): void
    {
        $format = isset($assoc['format']) ? (string) $assoc['format'] : 'table';

        if ('json' === $format) {
            \WP_CLI::line(function_exists('wp_json_encode') ? wp_json_encode($rows) : json_encode($rows));
            return;
        }

        if (empty($rows)) {
            return;
        }

        if (class_exists('WP_CLI\\Utils')) {
            \WP_CLI\Utils\format_items($format, $rows, array_keys($rows[0]));
            return;
        }

        foreach ($rows as $row) {
            \WP_CLI::line(implode("\t", array_map('strval', $row)));
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    private function preset(string $preset): ?array
    {
        $minimal = array(
            'user' => array(
                'meta' => array(
                    'first_name' => array('type' => 'text'),
                    'last_name' => array('type' => 'text'),
                    'billing_phone' => array('type' => 'text', 'search' => true),
                ),
            ),
            'post' => array(
                'post_types' => array('shop_order'),
                'meta' => array(
                    '_billing_first_name' => array('type' => 'text', 'search' => true),
                    '_billing_email' => array('type' => 'email', 'search' => true),
                    '_billing_phone' => array('type' => 'text', 'search' => true),
                ),
            ),
        );

        if ('minimal' === $preset) {
            return $minimal;
        }

        if ('full' === $preset) {
            $file = dirname(__DIR__, 2) . '/config/fields.example.php';
            if (is_file($file)) {
                $loaded = include $file;
                if (is_array($loaded)) {
                    return $loaded;
                }
            }
            return $minimal;
        }

        return null;
    }

    private function generateKey(): string
    {
        $keys = $this->plugin->keys();

        foreach (array('generate', 'generateKey') as $method) {
            if (method_exists($keys, $method)) {
                try {
                    $generated = $keys->{$method}();
                    if (is_string($generated) && '' !== $generated) {
                        return $generated;
                    }
                    if (is_array($generated)) {
                        foreach (array('key', 'value', 'secret') as $field) {
                            if (isset($generated[$field]) && is_string($generated[$field]) && '' !== $generated[$field]) {
                                return $generated[$field];
                            }
                        }
                    }
                } catch (\Throwable $exception) {
                    // Fall through.
                }
            }
        }

        if (function_exists('sodium_crypto_secretbox_keygen')) {
            try {
                return base64_encode(sodium_crypto_secretbox_keygen());
            } catch (\Throwable $exception) {
                // Fall through.
            }
        }

        try {
            return base64_encode(random_bytes(32));
        } catch (\Throwable $exception) {
            return '';
        }
    }
}
