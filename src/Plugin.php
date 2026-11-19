<?php

namespace EncryptedFields;

use EncryptedFields\Config\Registry;
use EncryptedFields\Contracts\EncryptorInterface;
use EncryptedFields\Contracts\SearchInterface;
use EncryptedFields\Contracts\TableAdapterInterface;
use EncryptedFields\Crypto\Encryptor;
use EncryptedFields\Crypto\KeyManager;
use EncryptedFields\Support\Logger;

final class Plugin
{
    private static ?Plugin $instance = null;

    private Registry $registry;
    private KeyManager $keys;
    private ?EncryptorInterface $crypto = null;
    private Logger $logger;
    private ?SearchInterface $search = null;
    private array $tableAdapters = array();
    private bool $booted = false;
    private bool $refreshing = false;

    public static function instance(): self
    {
        if (null === self::$instance) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public static function boot(): void
    {
        self::instance()->init();
    }

    public function init(): void
    {
        if ($this->booted) {
            return;
        }

        $this->booted = true;
        $this->refreshing = true;

        try {
            require_once __DIR__ . '/Support/Functions.php';
            $this->logger = new Logger();
            $this->registry = new Registry(array());
            $this->registry = Registry::fromSources();

            if (!class_exists(KeyManager::class) || !class_exists(Encryptor::class)) {
                return;
            }

            $this->keys = new KeyManager();
            $this->crypto = new Encryptor($this->keys);

            if (class_exists(\EncryptedFields\Search\SearchService::class)) {
                $this->search = new \EncryptedFields\Search\SearchService($this);
            }

            $this->tableAdapters = (array) apply_filters('kec_table_adapters', array());
            $this->registerModules();
        } finally {
            $this->refreshing = false;
        }

        if (function_exists('add_action')) {
            add_action('after_setup_theme', array($this, 'refreshExtensions'), 99);
        }
    }

    /**
     * Rebuild registry and table adapters after the theme has loaded.
     *
     * Plugins boot on plugins_loaded, which runs before the active theme's
     * functions.php. This late refresh lets themes and mu-plugins register
     * fields and adapters with normal add_filter() calls.
     */
    public function refreshExtensions(): void
    {
        if (!$this->booted) {
            $this->init();

            return;
        }

        if ($this->refreshing) {
            return;
        }

        $this->refreshing = true;

        try {
            $this->registry = Registry::fromSources();
            $this->tableAdapters = (array) apply_filters('kec_table_adapters', array());
        } finally {
            $this->refreshing = false;
        }
    }

    private function registerModules(): void
    {
        $modules = array(
            \EncryptedFields\Meta\MetaHooks::class,
            \EncryptedFields\User\UserHooks::class,
            \EncryptedFields\User\UserLookup::class,
            \EncryptedFields\User\PasswordReset::class,
            \EncryptedFields\Query\QueryRewriter::class,
            \EncryptedFields\Search\Hooks::class,
            \EncryptedFields\Mail\MailHooks::class,
            \EncryptedFields\Admin\SettingsPage::class,
            \EncryptedFields\Admin\SetupWizard::class,
        );

        if (class_exists('WooCommerce')) {
            $modules[] = \EncryptedFields\Integrations\WooCommerce\Integration::class;
        }

        if (defined('SITEGUARD_VERSION')) {
            $modules[] = \EncryptedFields\Integrations\SiteGuard\Integration::class;
        }

        if (defined('WP_CLI') && WP_CLI) {
            $modules[] = \EncryptedFields\Cli\Commands::class;
        }

        foreach ($modules as $class) {
            if (!class_exists($class)) {
                continue;
            }

            $module = new $class($this);
            if (method_exists($module, 'register')) {
                $module->register();
            }
        }
    }

    public function registry(): Registry
    {
        return $this->registry;
    }

    public function keys(): KeyManager
    {
        return $this->keys;
    }

    public function crypto(): EncryptorInterface
    {
        if (null === $this->crypto) {
            throw new \RuntimeException('Encryptor is not available.');
        }

        return $this->crypto;
    }

    public function logger(): Logger
    {
        return $this->logger;
    }

    public function search(): ?SearchInterface
    {
        return $this->search;
    }

    /**
     * @return array<string, TableAdapterInterface>
     */
    public function tableAdapters(): array
    {
        return $this->tableAdapters;
    }

    public function option(string $name, $default = null)
    {
        return get_option($name, $default);
    }

    public function updateOption(string $name, $value, bool $autoload = false): void
    {
        update_option($name, $value, $autoload);
    }

    public function deleteOption(string $name): void
    {
        delete_option($name);
    }
}
