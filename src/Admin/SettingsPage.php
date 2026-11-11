<?php

namespace Koyo\EncryptedFields\Admin;

use Koyo\EncryptedFields\Migration\Env;
use Koyo\EncryptedFields\Migration\Migrator;
use Koyo\EncryptedFields\Migration\StateDetector;
use Koyo\EncryptedFields\Plugin;

/**
 * Settings -> Encrypted Fields admin screen.
 */
final class SettingsPage
{
    private const CAPABILITY = 'manage_options';
    private const SLUG = 'kec-settings';

    private Plugin $plugin;

    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    public function register(): void
    {
        add_action('admin_menu', array($this, 'registerMenu'));
        add_action('admin_post_kec_settings', array($this, 'handleAction'));
    }

    public function registerMenu(): void
    {
        add_options_page(
            'Encrypted Fields',
            'Encrypted Fields',
            self::CAPABILITY,
            self::SLUG,
            array($this, 'render')
        );
    }

    public function render(): void
    {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die('You do not have permission to access this page.');
        }

        $tabs = array(
            'status' => 'Status',
            'registry' => 'Registry',
            'migration' => 'Migration',
            'index' => 'Search Index',
            'health' => 'Health',
            'logs' => 'Logs',
        );

        $tab = isset($_GET['tab']) ? sanitize_key((string) $_GET['tab']) : 'status';
        if (!isset($tabs[$tab])) {
            $tab = 'status';
        }

        $plugin = $this->plugin;
        $state = (new StateDetector($plugin))->detect();
        $result = $this->getResult();
        $view = __DIR__ . '/views/' . $tab . '.php';

        echo '<div class="wrap">';
        echo '<h1>Encrypted Fields</h1>';

        if (is_array($result) && !empty($result['message'])) {
            $class = !empty($result['ok']) ? 'notice-success' : 'notice-error';
            echo '<div class="notice ' . esc_attr($class) . ' is-dismissible"><p>' . esc_html((string) $result['message']) . '</p></div>';
        }

        echo '<nav class="nav-tab-wrapper">';
        foreach ($tabs as $slug => $label) {
            $url = add_query_arg(array('page' => self::SLUG, 'tab' => $slug), admin_url('options-general.php'));
            $class = 'nav-tab' . ($slug === $tab ? ' nav-tab-active' : '');
            echo '<a class="' . esc_attr($class) . '" href="' . esc_url($url) . '">' . esc_html($label) . '</a>';
        }
        echo '</nav>';

        if (is_file($view)) {
            include $view;
        }

        echo '</div>';
    }

    public function handleAction(): void
    {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die('You do not have permission to perform this action.');
        }

        check_admin_referer('kec_admin', 'kec_nonce');

        $action = isset($_POST['kec_action']) ? sanitize_key((string) $_POST['kec_action']) : '';
        $message = '';
        $ok = true;

        switch ($action) {
            case 'save_registry':
                $ok = $this->saveRegistry();
                $message = $ok ? 'Registry saved.' : 'Registry JSON is invalid.';
                break;

            case 'save_backup_ack':
                $reference = isset($_POST['kec_backup_reference']) ? sanitize_text_field((string) $_POST['kec_backup_reference']) : '';
                $confirmed = !empty($_POST['kec_backup_confirm']);
                if (!$confirmed || '' === $reference) {
                    $ok = false;
                    $message = 'Backup confirmation and a backup reference are required.';
                } else {
                    $this->plugin->updateOption('kec_backup_ack', array(
                        'timestamp' => time(),
                        'user_id' => function_exists('get_current_user_id') ? (int) get_current_user_id() : 0,
                        'reference' => $reference,
                    ));
                    $message = 'Backup acknowledgement saved.';
                }
                break;

            case 'dry_run':
                $migrator = new Migrator($this->plugin);
                $result = $migrator->dryRun($this->filterOptions());
                $ok = !empty($result['backup_satisfied']) || 0 === (int) ($result['pending'] ?? 0);
                $message = sprintf(
                    'Dry run: %d plaintext, %d legacy, %d v2, %d pending. %s',
                    (int) $result['totals']['plaintext'],
                    (int) $result['totals']['legacy'],
                    (int) $result['totals']['v2'],
                    (int) $result['pending'],
                    $ok ? 'Backup gate satisfied.' : 'Backup confirmation is still required.'
                );
                $this->setResult(array('ok' => $ok, 'message' => $message, 'data' => $result));
                $this->redirect('migration');
                return;

            case 'migrate':
                $migrator = new Migrator($this->plugin);
                $result = $migrator->migrate($this->filterOptions());
                $ok = !empty($result['ok']);
                $message = $ok
                    ? sprintf('Migration finished: %d migrated, %d skipped, %d errors.', (int) $result['migrated'], (int) $result['skipped'], count($result['errors']))
                    : (isset($result['message']) ? (string) $result['message'] : 'Migration failed.');
                $this->setResult(array('ok' => $ok, 'message' => $message, 'data' => $result));
                $this->redirect('migration');
                return;

            case 'verify':
                $result = (new Migrator($this->plugin))->verify($this->filterOptions());
                $ok = !empty($result['ok']);
                $message = sprintf(
                    'Verify: %d plaintext, %d legacy, %d decrypt failures.',
                    (int) $result['plaintext'],
                    (int) $result['legacy'],
                    (int) $result['decrypt_failed']
                );
                $this->setResult(array('ok' => $ok, 'message' => $message, 'data' => $result));
                $this->redirect('migration');
                return;

            case 'rollback':
                if (empty($_POST['kec_rollback_confirm'])) {
                    $ok = false;
                    $message = 'Confirm rollback before continuing.';
                    break;
                }
                $result = (new Migrator($this->plugin))->rollback($this->filterOptions());
                $ok = !empty($result['ok']);
                $message = sprintf('Rollback: %d decrypted, %d skipped, %d errors.', (int) $result['decrypted'], (int) $result['skipped'], count($result['errors']));
                $this->setResult(array('ok' => $ok, 'message' => $message, 'data' => $result));
                $this->redirect('migration');
                return;

            case 'reindex':
                $search = $this->plugin->search();
                if (null === $search) {
                    $ok = false;
                    $message = 'Search service is not available.';
                } else {
                    $entity = isset($_POST['kec_entity']) ? sanitize_key((string) $_POST['kec_entity']) : 'all';
                    $batch = isset($_POST['kec_batch']) ? max(1, (int) $_POST['kec_batch']) : 500;
                    $count = $search->reindex($entity, $batch);
                    $message = sprintf('Reindexed %d rows.', (int) $count);
                    $this->plugin->logger()->info('reindex_finished', array('entity' => $entity, 'rows' => (int) $count));
                }
                break;

            case 'clear_logs':
                $this->plugin->logger()->clear();
                $message = 'Logs cleared.';
                break;

            default:
                $ok = false;
                $message = 'Unknown action.';
                break;
        }

        $this->setResult(array('ok' => $ok, 'message' => $message));
        $this->redirect(isset($_POST['kec_tab']) ? sanitize_key((string) $_POST['kec_tab']) : 'status');
    }

    private function saveRegistry(): bool
    {
        $raw = isset($_POST['kec_registry_json']) ? (string) wp_unslash($_POST['kec_registry_json']) : '';
        $decoded = json_decode($raw, true);
        if (!is_array($decoded)) {
            return false;
        }

        $validated = $this->validateRegistry($decoded);
        if (null === $validated) {
            return false;
        }

        $this->plugin->updateOption('kec_field_registry', $validated);
        $this->plugin->logger()->info('registry_saved', array('entities' => array_keys($validated)));

        return true;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function validateRegistry(array $raw): ?array
    {
        $result = array();

        foreach ($raw as $entity => $definition) {
            if (!is_string($entity) || !is_array($definition)) {
                return null;
            }

            if (Env::hposEnabled() && 'post' === $entity && !empty($definition['meta'])) {
                return null;
            }

            $out = array();

            if (isset($definition['post_types'])) {
                if (!is_array($definition['post_types'])) {
                    return null;
                }
                $out['post_types'] = array_values(array_map('strval', $definition['post_types']));
            }

            foreach (array('columns', 'meta') as $group) {
                if (!isset($definition[$group])) {
                    continue;
                }
                if (!is_array($definition[$group])) {
                    return null;
                }

                $out[$group] = array();
                foreach ($definition[$group] as $key => $config) {
                    if (!is_string($key)) {
                        return null;
                    }
                    if ('columns' === $group
                        && ('user' !== $entity || !in_array($key, array('user_login', 'user_email'), true))
                    ) {
                        return null;
                    }
                    if (!is_array($config)) {
                        return null;
                    }
                    $field = array();
                    if (isset($config['type'])) {
                        $type = (string) $config['type'];
                        if (!in_array($type, array('text', 'email', 'login'), true)) {
                            return null;
                        }
                        $field['type'] = $type;
                    }
                    if (isset($config['search'])) {
                        $field['search'] = (bool) $config['search'];
                    }
                    if (isset($config['cipher'])) {
                        $cipher = strtolower(trim((string) $config['cipher']));

                        if (!in_array($cipher, array('sb', 'det', 'deterministic', 'siv', 'secretbox', 'random', 'randomized'), true)) {
                            return null;
                        }

                        $field['cipher'] = $cipher;
                    }
                    if (isset($config['max_length'])) {
                        $field['max_length'] = (int) $config['max_length'];
                    }
                    if (isset($config['post_types']) && is_array($config['post_types'])) {
                        $field['post_types'] = array_values(array_map('strval', $config['post_types']));
                    }
                    $out[$group][$key] = $field;
                }
            }

            $result[$entity] = $out;
        }

        return $result;
    }

    /**
     * @return array<string, mixed>
     */
    private function filterOptions(): array
    {
        return array(
            'entity' => isset($_POST['kec_entity']) ? sanitize_key((string) $_POST['kec_entity']) : '',
            'field' => isset($_POST['kec_field']) ? sanitize_text_field((string) $_POST['kec_field']) : '',
            'batch' => isset($_POST['kec_batch']) ? max(1, (int) $_POST['kec_batch']) : 500,
            'from' => isset($_POST['kec_from']) ? sanitize_key((string) $_POST['kec_from']) : 'both',
            'resume' => !empty($_POST['kec_resume']),
        );
    }

    private function setResult(array $result): void
    {
        if (function_exists('set_transient') && function_exists('get_current_user_id')) {
            set_transient('kec_admin_result_' . (int) get_current_user_id(), $result, 300);
        }
    }

    /**
     * @return array<string, mixed>|null
     */
    private function getResult(): ?array
    {
        if (!function_exists('get_transient') || !function_exists('get_current_user_id')) {
            return null;
        }

        $key = 'kec_admin_result_' . (int) get_current_user_id();
        $result = get_transient($key);
        if (!is_array($result)) {
            return null;
        }

        if (function_exists('delete_transient')) {
            delete_transient($key);
        }

        return $result;
    }

    private function redirect(string $tab): void
    {
        $url = add_query_arg(
            array('page' => self::SLUG, 'tab' => $tab),
            admin_url('options-general.php')
        );
        wp_safe_redirect($url);
        exit;
    }
}
