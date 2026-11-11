<?php

namespace Koyo\EncryptedFields\Admin;

use Koyo\EncryptedFields\Migration\Env;
use Koyo\EncryptedFields\Migration\Migrator;
use Koyo\EncryptedFields\Migration\StateDetector;
use Koyo\EncryptedFields\Plugin;

/**
 * Multi-step setup and migration wizard.
 */
final class SetupWizard
{
    private const CAPABILITY = 'manage_options';
    private const SLUG = 'kec-setup';
    private const STATE_OPTION = 'kec_setup_state';

    private Plugin $plugin;

    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    public function register(): void
    {
        add_action('admin_menu', array($this, 'registerMenu'));
        add_action('admin_notices', array($this, 'maybeNotice'));
        add_action('admin_post_kec_wizard', array($this, 'handleAction'));
    }

    public function registerMenu(): void
    {
        add_submenu_page(
            null,
            'Encrypted Fields Setup',
            'Encrypted Fields Setup',
            self::CAPABILITY,
            self::SLUG,
            array($this, 'render')
        );
    }

    public function maybeNotice(): void
    {
        if (!current_user_can(self::CAPABILITY)) {
            return;
        }

        if (isset($_GET['page']) && self::SLUG === $_GET['page']) {
            return;
        }

        if ($this->plugin->option('kec_setup_complete')) {
            return;
        }

        $state = (new StateDetector($this->plugin))->detect();
        $url = admin_url('admin.php?page=' . self::SLUG);
        $existing = in_array($state['state'], array('existing_plaintext', 'existing_legacy', 'mixed'), true);

        echo '<div class="notice notice-warning">';
        echo '<p><strong>Encrypted Fields:</strong> ';
        if ($existing) {
            echo 'Existing data was detected. A confirmed backup is required before migration. ';
        } else {
            echo 'The encryption setup wizard has not been completed. ';
        }
        echo '<a href="' . esc_url($url) . '">Open the setup wizard</a>.</p>';
        echo '</div>';
    }

    public function render(): void
    {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die('You do not have permission to access this page.');
        }

        $state = (new StateDetector($this->plugin))->detect();
        $setup = $this->setupState();
        $step = $this->currentStep($setup, $state);

        if (isset($_GET['step']) && 'finalize' === sanitize_key((string) $_GET['step']) && $this->plugin->option('kec_setup_complete')) {
            $step = 'finalize';
        }

        $generatedKey = $this->pullGeneratedKey();
        $result = $this->pullResult();

        $plugin = $this->plugin;
        $ack = isset($state['backup_ack']) ? $state['backup_ack'] : null;
        $needsBackup = in_array($state['state'], array('existing_plaintext', 'existing_legacy', 'mixed'), true);
        $presets = $this->presets();
        $preset = isset($setup['preset']) ? (string) $setup['preset'] : 'minimal';

        include __DIR__ . '/views/wizard.php';
    }

    public function handleAction(): void
    {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die('You do not have permission to perform this action.');
        }

        check_admin_referer('kec_wizard', 'kec_nonce');

        $action = isset($_POST['kec_action']) ? sanitize_key((string) $_POST['kec_action']) : '';
        $setup = $this->setupState();
        $state = (new StateDetector($this->plugin))->detect();
        $needsBackup = in_array($state['state'], array('existing_plaintext', 'existing_legacy', 'mixed'), true);

        switch ($action) {
            case 'start':
                $mode = isset($_POST['kec_mode']) ? sanitize_key((string) $_POST['kec_mode']) : 'fresh';
                $setup = array('mode' => $mode, 'step' => 'environment', 'preset' => 'minimal');
                $this->saveSetupState($setup);
                $this->result(true, 'Wizard started.', 'environment');
                return;

            case 'environment':
                $ok = version_compare(PHP_VERSION, '8.0', '>=') && (extension_loaded('openssl') || extension_loaded('sodium'));
                if (!$ok) {
                    $this->result(false, 'PHP 8.0+ and OpenSSL or Sodium are required.', 'environment');
                    return;
                }
                $this->saveSetupState(array_merge($setup, array('step' => 'key')));
                $this->redirect('key');
                return;

            case 'key_generate':
                $key = $this->generateKey();
                if ('' === $key) {
                    $this->result(false, 'Unable to generate a key on this server.', 'key');
                    return;
                }
                $this->storeGeneratedKey($key);
                $this->result(true, 'Key generated. Add it to wp-config.php or the environment, then continue. The key is shown once on this page.', 'key');
                return;

            case 'key':
                if (!Env::keyConfigured($this->plugin)) {
                    $this->result(false, 'No key is configured yet. Add KEC_KEY to wp-config.php, use a key file, or enable the database option explicitly.', 'key');
                    return;
                }
                $this->saveSetupState(array_merge($setup, array('step' => 'fields')));
                $this->redirect('fields');
                return;

            case 'fields':
                $preset = isset($_POST['kec_preset']) ? sanitize_key((string) $_POST['kec_preset']) : 'minimal';
                $custom = isset($_POST['kec_custom_fields']) ? (string) wp_unslash($_POST['kec_custom_fields']) : '';
                $registry = $this->presetRegistry($preset, $custom);
                if (null === $registry) {
                    $this->result(false, 'The custom field registry JSON is invalid.', 'fields');
                    return;
                }

                if (Env::hposEnabled()) {
                    unset($registry['post']);
                }

                $this->plugin->updateOption('kec_field_registry', $registry);
                $setup['preset'] = $preset;
                $setup['step'] = 'backup';
                $this->saveSetupState($setup);
                $this->redirect('backup');
                return;

            case 'backup':
                $reference = isset($_POST['kec_backup_reference']) ? sanitize_text_field((string) $_POST['kec_backup_reference']) : '';
                $confirmed = !empty($_POST['kec_backup_confirm']);
                if (!$confirmed || '' === $reference) {
                    $this->result(false, 'You must confirm the backup and provide a reference before continuing.', 'backup');
                    return;
                }

                $this->plugin->updateOption('kec_backup_ack', array(
                    'timestamp' => time(),
                    'user_id' => function_exists('get_current_user_id') ? (int) get_current_user_id() : 0,
                    'reference' => $reference,
                ));
                $setup['step'] = 'dryrun';
                $this->saveSetupState($setup);
                $this->redirect('dryrun');
                return;

            case 'dryrun':
                $migrator = new Migrator($this->plugin);
                $result = $migrator->dryRun(array('check_length' => true, 'batch' => 500));
                $setup['step'] = 'migrate';
                $this->saveSetupState($setup);
                $this->result(!empty($result['backup_satisfied']) || 0 === (int) $result['pending'], sprintf(
                    'Dry run: %d plaintext, %d legacy, %d v2. Length risks: %d.',
                    (int) $result['totals']['plaintext'],
                    (int) $result['totals']['legacy'],
                    (int) $result['totals']['v2'],
                    count(array_filter($result['warnings'], function ($warning) {
                        return isset($warning['code']) && 'length_risk' === $warning['code'];
                    }))
                ), 'migrate', $result);
                return;

            case 'migrate':
                if ($needsBackup && !$this->plugin->option('kec_backup_ack')) {
                    $this->result(false, 'Backup confirmation is required before migration.', 'backup');
                    return;
                }

                $batch = isset($_POST['kec_batch']) ? max(1, min(5000, (int) $_POST['kec_batch'])) : 500;
                $result = (new Migrator($this->plugin))->migrate(array(
                    'batch' => $batch,
                    'backup_confirmed' => true,
                    'resume' => false,
                ));

                if (empty($result['ok'])) {
                    $this->result(false, isset($result['message']) ? (string) $result['message'] : 'Migration failed.', 'migrate', $result);
                    return;
                }

                $setup['step'] = 'verify';
                $this->saveSetupState($setup);
                $this->result(true, sprintf('Migration completed: %d migrated, %d skipped, %d errors.', (int) $result['migrated'], (int) $result['skipped'], count($result['errors'])), 'verify', $result);
                return;

            case 'verify':
                $result = (new Migrator($this->plugin))->verify();
                if (empty($result['ok'])) {
                    $this->result(false, sprintf('Verification found %d plaintext, %d legacy and %d decrypt failures.', (int) $result['plaintext'], (int) $result['legacy'], (int) $result['decrypt_failed']), 'verify', $result);
                    return;
                }

                $setup['step'] = 'finalize';
                $this->saveSetupState($setup);
                $this->result(true, 'Verification passed.', 'finalize', $result);
                return;

            case 'finalize':
                if (empty($setup['step'])) {
                    $this->result(false, 'Start the wizard before finalizing.', 'start');
                    return;
                }
                (new Migrator($this->plugin))->releaseLock();
                $this->plugin->updateOption('kec_setup_complete', true);
                $this->plugin->deleteOption(self::STATE_OPTION);
                $this->plugin->logger()->info('setup_finalized', array('mode' => isset($setup['mode']) ? $setup['mode'] : ''));
                $this->redirect('finalize');
                return;

            default:
                $this->result(false, 'Unknown wizard action.', 'start');
                return;
        }
    }

    /**
     * @param array<string, mixed> $setup
     * @param array<string, mixed> $state
     */
    private function currentStep(array $setup, array $state): string
    {
        $allowed = array('start', 'environment', 'key', 'fields', 'backup', 'dryrun', 'migrate', 'verify', 'finalize');

        if (empty($setup['step'])) {
            return 'start';
        }

        $step = (string) $setup['step'];
        if (!in_array($step, $allowed, true)) {
            return 'start';
        }

        if ('backup' === $step && !in_array($state['state'], array('existing_plaintext', 'existing_legacy', 'mixed'), true)) {
            return (isset($setup['mode']) && 'fresh' === $setup['mode']) ? 'finalize' : 'dryrun';
        }

        return $step;
    }

    /**
     * @return array<string, mixed>
     */
    private function setupState(): array
    {
        $setup = $this->plugin->option(self::STATE_OPTION);
        return is_array($setup) ? $setup : array();
    }

    /**
     * @param array<string, mixed> $setup
     */
    private function saveSetupState(array $setup): void
    {
        $this->plugin->updateOption(self::STATE_OPTION, $setup);
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function presets(): array
    {
        $full = array(
            'user' => array(
                'columns' => array(
                    'user_login' => array('type' => 'login', 'max_length' => 60),
                    'user_email' => array('type' => 'email', 'max_length' => 100),
                ),
                'meta' => array(
                    'first_name' => array('type' => 'text'),
                    'last_name' => array('type' => 'text'),
                    'billing_first_name' => array('type' => 'text', 'search' => true),
                    'billing_last_name' => array('type' => 'text', 'search' => true),
                    'billing_company' => array('type' => 'text'),
                    'billing_postcode' => array('type' => 'text', 'search' => true),
                    'billing_city' => array('type' => 'text', 'search' => true),
                    'billing_address_1' => array('type' => 'text'),
                    'billing_address_2' => array('type' => 'text'),
                    'billing_phone' => array('type' => 'text', 'search' => true),
                    'billing_email' => array('type' => 'email', 'search' => true),
                    'shipping_first_name' => array('type' => 'text'),
                    'shipping_last_name' => array('type' => 'text'),
                    'shipping_company' => array('type' => 'text'),
                    'shipping_postcode' => array('type' => 'text'),
                    'shipping_city' => array('type' => 'text'),
                    'shipping_address_1' => array('type' => 'text'),
                    'shipping_address_2' => array('type' => 'text'),
                    'shipping_phone' => array('type' => 'text'),
                    'dateofbirth' => array('type' => 'text'),
                    'billing_first_name_kana' => array('type' => 'text'),
                    'billing_last_name_kana' => array('type' => 'text'),
                ),
            ),
            'post' => array(
                'post_types' => array('shop_order'),
                'meta' => array(
                    '_billing_first_name' => array('type' => 'text', 'search' => true),
                    '_billing_last_name' => array('type' => 'text', 'search' => true),
                    '_billing_company' => array('type' => 'text'),
                    '_billing_postcode' => array('type' => 'text', 'search' => true),
                    '_billing_city' => array('type' => 'text', 'search' => true),
                    '_billing_address_1' => array('type' => 'text'),
                    '_billing_address_2' => array('type' => 'text'),
                    '_billing_phone' => array('type' => 'text', 'search' => true),
                    '_billing_email' => array('type' => 'email', 'search' => true),
                    '_shipping_first_name' => array('type' => 'text'),
                    '_shipping_last_name' => array('type' => 'text'),
                    '_shipping_company' => array('type' => 'text'),
                    '_shipping_postcode' => array('type' => 'text'),
                    '_shipping_city' => array('type' => 'text'),
                    '_shipping_address_1' => array('type' => 'text'),
                    '_shipping_address_2' => array('type' => 'text'),
                    '_shipping_phone' => array('type' => 'text'),
                    '_customer_ip_address' => array('type' => 'text'),
                    '_customer_user_agent' => array('type' => 'text'),
                    '_billing_address_index' => array('type' => 'text', 'search' => true),
                    '_shipping_address_index' => array('type' => 'text', 'search' => true),
                ),
            ),
        );

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

        return array(
            'minimal' => array('label' => 'Minimal', 'registry' => $minimal),
            'full-ec-koyo' => array('label' => 'Full EC-KOYO', 'registry' => $full),
            'custom' => array('label' => 'Custom JSON', 'registry' => array()),
        );
    }

    /**
     * @return array<string, mixed>|null
     */
    private function presetRegistry(string $preset, string $custom): ?array
    {
        $presets = $this->presets();

        if ('custom' === $preset) {
            $decoded = json_decode($custom, true);
            return is_array($decoded) ? $decoded : null;
        }

        if (!isset($presets[$preset])) {
            return null;
        }

        $registry = $presets[$preset]['registry'];
        if (!is_array($registry)) {
            return null;
        }

        return $registry;
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
                    // Fall back to local generation.
                }
            }
        }

        if (function_exists('sodium_crypto_secretbox_keygen')) {
            try {
                return base64_encode(sodium_crypto_secretbox_keygen());
            } catch (\Throwable $exception) {
                // Fall back to random bytes.
            }
        }

        try {
            return base64_encode(random_bytes(32));
        } catch (\Throwable $exception) {
            return '';
        }
    }

    private function storeGeneratedKey(string $key): void
    {
        if (!function_exists('set_transient') || !function_exists('get_current_user_id')) {
            return;
        }

        set_transient($this->keyTransientName(), $key, 600);
    }

    private function pullGeneratedKey(): ?string
    {
        if (!function_exists('get_transient') || !function_exists('get_current_user_id')) {
            return null;
        }

        $key = get_transient($this->keyTransientName());
        if (!is_string($key) || '' === $key) {
            return null;
        }

        delete_transient($this->keyTransientName());

        return $key;
    }

    private function keyTransientName(): string
    {
        return 'kec_setup_key_' . (int) get_current_user_id();
    }

    private function result(bool $ok, string $message, string $step, $data = null): void
    {
        if (function_exists('set_transient') && function_exists('get_current_user_id')) {
            set_transient('kec_wizard_result_' . (int) get_current_user_id(), array(
                'ok' => $ok,
                'message' => $message,
                'step' => $step,
                'data' => $data,
            ), 600);
        }

        $this->redirect($step);
    }

    /**
     * @return array<string, mixed>|null
     */
    private function pullResult(): ?array
    {
        if (!function_exists('get_transient') || !function_exists('get_current_user_id')) {
            return null;
        }

        $name = 'kec_wizard_result_' . (int) get_current_user_id();
        $result = get_transient($name);
        if (!is_array($result)) {
            return null;
        }

        delete_transient($name);

        return $result;
    }

    private function redirect(string $step): void
    {
        $url = add_query_arg(
            array('page' => self::SLUG, 'step' => $step),
            admin_url('admin.php')
        );
        wp_safe_redirect($url);
        exit;
    }
}
