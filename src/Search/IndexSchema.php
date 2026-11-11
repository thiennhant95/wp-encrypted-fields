<?php

namespace Koyo\EncryptedFields\Search;

/**
 * Owns the {prefix}kec_search_index table definition and upgrades.
 */
final class IndexSchema
{
    public const VERSION = '1';
    public const OPTION = 'kec_search_db_version';

    /** @var object|null */
    private $wpdb;

    /**
     * @param object|null $wpdb Optional injected wpdb-compatible object.
     */
    public function __construct($wpdb = null)
    {
        if (null === $wpdb) {
            global $wpdb;
        }

        $this->wpdb = $wpdb;
    }

    public function table(): string
    {
        $prefix = is_object($this->wpdb) && isset($this->wpdb->prefix)
            ? (string) $this->wpdb->prefix
            : '';

        return $prefix . 'kec_search_index';
    }

    public function sql(): string
    {
        $charset = '';

        if (is_object($this->wpdb) && method_exists($this->wpdb, 'get_charset_collate')) {
            $charset = (string) $this->wpdb->get_charset_collate();
        }

        if ('' !== $charset) {
            $charset = ' ' . trim($charset);
        }

        return 'CREATE TABLE ' . $this->table() . " (
            entity_type varchar(20) NOT NULL,
            entity_id bigint(20) unsigned NOT NULL,
            field varchar(64) NOT NULL,
            token char(64) NOT NULL,
            PRIMARY KEY  (entity_type,entity_id,field,token),
            KEY token (token)
        )" . $charset . ';';
    }

    /**
     * Run dbDelta when the stored schema version differs.
     */
    public function maybeUpgrade(): bool
    {
        $installed = function_exists('get_option')
            ? get_option(self::OPTION, null)
            : null;

        if (self::VERSION === (string) $installed) {
            return false;
        }

        return $this->create();
    }

    /**
     * Create/upgrade the index table. dbDelta is optional (guarded).
     */
    public function create(): bool
    {
        if (!function_exists('dbDelta')) {
            $upgrade = defined('ABSPATH') ? ABSPATH . 'wp-admin/includes/upgrade.php' : '';
            if ('' !== $upgrade && is_file($upgrade)) {
                require_once $upgrade;
            }
        }

        if (!function_exists('dbDelta')) {
            return false;
        }

        try {
            dbDelta($this->sql());
        } catch (\Throwable $e) {
            return false;
        }

        if (function_exists('update_option')) {
            update_option(self::OPTION, self::VERSION, false);
        }

        return true;
    }

    public function install(): bool
    {
        return $this->create();
    }

    public function upgrade(): bool
    {
        return $this->create();
    }

    public function exists(): bool
    {
        if (!is_object($this->wpdb) || !method_exists($this->wpdb, 'get_var')) {
            return false;
        }

        try {
            $found = $this->wpdb->get_var(
                $this->wpdb->prepare('SHOW TABLES LIKE %s', $this->table())
            );
        } catch (\Throwable $e) {
            return false;
        }

        return !empty($found);
    }
}
