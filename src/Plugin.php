<?php

namespace Koyo\EncryptedFields;

use Koyo\EncryptedFields\Config\Registry;
use Koyo\EncryptedFields\Contracts\EncryptorInterface;
use Koyo\EncryptedFields\Contracts\SearchInterface;
use Koyo\EncryptedFields\Contracts\TableAdapterInterface;
use Koyo\EncryptedFields\Crypto\Encryptor;
use Koyo\EncryptedFields\Crypto\KeyManager;
use Koyo\EncryptedFields\Support\Logger;

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
        require_once __DIR__ . '/Support/Functions.php';
        $this->logger = new Logger();
        $this->registry = Registry::fromSources();

        if (!class_exists(KeyManager::class) || !class_exists(Encryptor::class)) {
            return;
        }

        $this->keys = new KeyManager();
        $this->crypto = new Encryptor($this->keys);

        if (class_exists(\Koyo\EncryptedFields\Search\SearchService::class)) {
            $this->search = new \Koyo\EncryptedFields\Search\SearchService($this);
        }

        $this->tableAdapters = (array) apply_filters('kec_table_adapters', array());
        $this->registerModules();
    }

    private function registerModules(): void
    {
        $modules = array(
            \Koyo\EncryptedFields\Meta\MetaHooks::class,
            \Koyo\EncryptedFields\User\UserHooks::class,
            \Koyo\EncryptedFields\User\PasswordReset::class,
            \Koyo\EncryptedFields\Query\QueryRewriter::class,
            \Koyo\EncryptedFields\Search\Hooks::class,
            \Koyo\EncryptedFields\Mail\MailHooks::class,
            \Koyo\EncryptedFields\Admin\SettingsPage::class,
            \Koyo\EncryptedFields\Admin\SetupWizard::class,
        );

        if (class_exists('WooCommerce')) {
            $modules[] = \Koyo\EncryptedFields\Integrations\WooCommerce\Integration::class;
        }

        if (defined('SITEGUARD_VERSION')) {
            $modules[] = \Koyo\EncryptedFields\Integrations\SiteGuard\Integration::class;
        }

        if (defined('WP_CLI') && WP_CLI) {
            $modules[] = \Koyo\EncryptedFields\Cli\Commands::class;
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
