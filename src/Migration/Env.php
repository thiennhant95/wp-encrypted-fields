<?php

namespace Koyo\EncryptedFields\Migration;

use Koyo\EncryptedFields\Config\Field;
use Koyo\EncryptedFields\Plugin;

/**
 * Shared environment helpers for admin/CLI/migration.
 */
final class Env
{
    public static function db(?object $db = null): ?object
    {
        if (null !== $db) {
            return $db;
        }

        if (isset($GLOBALS['wpdb']) && is_object($GLOBALS['wpdb'])) {
            return $GLOBALS['wpdb'];
        }

        return null;
    }

    public static function table(object $db, string $name): string
    {
        if (isset($db->{$name}) && is_string($db->{$name}) && '' !== $db->{$name}) {
            return $db->{$name};
        }

        if (method_exists($db, 'prefix')) {
            return $db->prefix() . $name;
        }

        if (isset($db->prefix) && is_string($db->prefix)) {
            return $db->prefix . $name;
        }

        return $name;
    }

    /**
     * @return object[]
     */
    public static function getResults(?object $db, string $sql): array
    {
        $db = self::db($db);
        if (null === $db || !method_exists($db, 'get_results')) {
            return array();
        }

        $rows = $db->get_results($sql);

        return is_array($rows) ? $rows : array();
    }

    public static function getVar(?object $db, string $sql)
    {
        $db = self::db($db);
        if (null === $db || !method_exists($db, 'get_var')) {
            return null;
        }

        return $db->get_var($sql);
    }

    public static function lastError(?object $db): string
    {
        $db = self::db($db);

        if (!is_object($db) || !isset($db->last_error)) {
            return '';
        }

        return is_string($db->last_error) ? trim($db->last_error) : '';
    }

    public static function isV2(string $value): bool
    {
        return (bool) preg_match('/^enc:v2c?:/', $value);
    }

    public static function isToken(string $value): bool
    {
        return (bool) preg_match('/^k1[te][a-z2-7]{52}$/', $value);
    }

    public static function isEncrypted(Plugin $plugin, string $value, Field $field): bool
    {
        if ('' === $value) {
            return false;
        }

        try {
            return $plugin->crypto()->isEncrypted($value);
        } catch (\Throwable $exception) {
            return false;
        }
    }

    public static function classify(Plugin $plugin, string $value, Field $field): string
    {
        if ('' === $value) {
            return 'empty';
        }

        if (self::isToken($value)) {
            return 'token';
        }

        if (self::isEncrypted($plugin, $value, $field)) {
            return self::isV2($value) ? 'v2' : 'legacy';
        }

        return 'plaintext';
    }

    public static function keyConfigured(Plugin $plugin): bool
    {
        $keys = $plugin->keys();

        foreach (array('isConfigured', 'configured', 'hasKey', 'hasKeys') as $method) {
            if (method_exists($keys, $method)) {
                try {
                    return (bool) $keys->{$method}();
                } catch (\Throwable $exception) {
                    return false;
                }
            }
        }

        if (defined('KEC_KEY') && '' !== (string) KEC_KEY) {
            return true;
        }

        if (defined('KEC_KEY_FILE') && '' !== (string) KEC_KEY_FILE && is_file((string) KEC_KEY_FILE)) {
            return true;
        }

        if (defined('KEC_ALLOW_DB_KEY') && KEC_ALLOW_DB_KEY && $plugin->option('kec_key')) {
            return true;
        }

        return false;
    }

    public static function keyId(Plugin $plugin): ?string
    {
        $keys = $plugin->keys();

        foreach (array('keyId', 'currentKeyId', 'currentId') as $method) {
            if (method_exists($keys, $method)) {
                try {
                    $value = $keys->{$method}();
                    return is_string($value) && '' !== $value ? $value : null;
                } catch (\Throwable $exception) {
                    return null;
                }
            }
        }

        return null;
    }

    public static function keySource(Plugin $plugin): string
    {
        $keys = $plugin->keys();

        foreach (array('source', 'keySource') as $method) {
            if (method_exists($keys, $method)) {
                try {
                    $value = $keys->{$method}();
                    if (is_string($value) && '' !== $value) {
                        return $value;
                    }
                } catch (\Throwable $exception) {
                    // Fall through to constants/options.
                }
            }
        }

        if (defined('KEC_KEY') && '' !== (string) KEC_KEY) {
            return 'wp-config:KEC_KEY';
        }

        if (defined('KEC_KEY_FILE') && '' !== (string) KEC_KEY_FILE) {
            return 'file:KEC_KEY_FILE';
        }

        if (defined('KEC_ALLOW_DB_KEY') && KEC_ALLOW_DB_KEY && $plugin->option('kec_key')) {
            return 'option:kec_key';
        }

        return 'none';
    }

    public static function hposEnabled(): bool
    {
        $option = function_exists('get_option') ? get_option('woocommerce_custom_orders_table_enabled') : null;
        if (in_array($option, array('yes', '1', 1, true), true)) {
            return true;
        }

        $class = 'Automattic\\WooCommerce\\Utilities\\OrderUtil';
        if (class_exists($class) && method_exists($class, 'custom_orders_table_usage_is_enabled')) {
            try {
                return (bool) $class::custom_orders_table_usage_is_enabled();
            } catch (\Throwable $exception) {
                return false;
            }
        }

        return false;
    }

    public static function fieldMaxLength(Field $field): ?int
    {
        $max = $field->maxLength();
        if (null !== $max && $max > 0) {
            return $max;
        }

        if ('user' === $field->entity() && 'user_login' === $field->key()) {
            return 60;
        }

        if ('user' === $field->entity() && 'user_email' === $field->key()) {
            return 100;
        }

        return null;
    }

    public static function escaped(string $value): string
    {
        if (function_exists('esc_sql')) {
            return esc_sql($value);
        }

        if (isset($GLOBALS['wpdb']) && is_object($GLOBALS['wpdb']) && method_exists($GLOBALS['wpdb'], 'esc_sql')) {
            return (string) $GLOBALS['wpdb']->esc_sql($value);
        }

        return str_replace(array('\\', "'"), array('\\\\', "\\'"), $value);
    }

    /**
     * Build migration targets for the current registry and adapters.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function targets(
        Plugin $plugin,
        ?object $db = null,
        string $entityFilter = '',
        string $fieldFilter = '',
        string $tableFilter = ''
    ): array {
        $db = self::db($db);
        if (null === $db) {
            return array();
        }

        $targets = array();
        if (isset($db->prefix) && is_string($db->prefix)) {
            $prefix = $db->prefix;
        } else {
            $prefix = method_exists($db, 'prefix') ? $db->prefix() : '';
        }

        foreach ($plugin->registry()->all() as $entity => $fields) {
            if ('' !== $entityFilter && $entity !== $entityFilter) {
                continue;
            }

            foreach ($fields as $key => $field) {
                if ('' !== $fieldFilter && $key !== $fieldFilter) {
                    continue;
                }

                if ($field->isColumn()) {
                    if ('user' !== $entity) {
                        continue;
                    }

                    if (!in_array($key, array('user_login', 'user_email'), true)) {
                        continue;
                    }

                    $targets[] = array(
                        'entity' => $entity,
                        'field' => $key,
                        'kind' => 'column',
                        'table' => self::table($db, 'users'),
                        'id_col' => 'ID',
                        'entity_id_col' => 'ID',
                        'value_col' => $key,
                        'where' => '',
                        'post_types' => array(),
                        'field_obj' => $field,
                        'adapter' => null,
                    );
                    continue;
                }

                $meta = self::metaTable($db, $entity);
                if (null === $meta) {
                    continue;
                }

                $where = "meta_key = '" . self::escaped((string) $key) . "'";
                $targets[] = array(
                    'entity' => $entity,
                    'field' => $key,
                    'kind' => 'meta',
                    'table' => $meta['table'],
                    'id_col' => $meta['id_col'],
                    'entity_id_col' => $meta['entity_id_col'],
                    'value_col' => 'meta_value',
                    'where' => $where,
                    'post_types' => $field->postTypes(),
                    'field_obj' => $field,
                    'adapter' => null,
                );
            }
        }

        foreach ($plugin->tableAdapters() as $name => $adapter) {
            if (!is_object($adapter)
                || !method_exists($adapter, 'columns')
                || !method_exists($adapter, 'read')
                || !method_exists($adapter, 'write')
                || !method_exists($adapter, 'table')
                || !method_exists($adapter, 'primaryKey')
            ) {
                continue;
            }

            $adapterName = method_exists($adapter, 'name') ? (string) $adapter->name() : (string) $name;
            if ('' !== $tableFilter && $adapterName !== $tableFilter) {
                continue;
            }

            $table = (string) $adapter->table();
            if ('' === $table || !preg_match('/^[A-Za-z0-9_]+$/', $table)) {
                continue;
            }

            $idCol = (string) $adapter->primaryKey();
            if (!preg_match('/^[A-Za-z0-9_]+$/', $idCol)) {
                continue;
            }

            $columns = $adapter->columns();
            if (!is_array($columns)) {
                continue;
            }

            foreach ($columns as $column => $type) {
                $column = (string) $column;

                if ('' !== $fieldFilter && $column !== $fieldFilter) {
                    continue;
                }

                if (!preg_match('/^[A-Za-z0-9_]+$/', $column)) {
                    continue;
                }

                $type = is_string($type) ? $type : 'text';
                $field = new Field('custom', $column, $type, false, null, array('table' => $adapterName));

                $targets[] = array(
                    'entity' => 'custom',
                    'field' => $column,
                    'kind' => 'adapter',
                    'table' => $table,
                    'id_col' => $idCol,
                    'entity_id_col' => $idCol,
                    'value_col' => $column,
                    'where' => '',
                    'post_types' => array(),
                    'field_obj' => $field,
                    'adapter' => $adapter,
                    'adapter_name' => $adapterName,
                );
            }
        }

        return $targets;
    }

    /**
     * @return array<string, string>|null
     */
    private static function metaTable(object $db, string $entity): ?array
    {
        switch ($entity) {
            case 'post':
                return array('table' => self::table($db, 'postmeta'), 'id_col' => 'meta_id', 'entity_id_col' => 'post_id');
            case 'user':
                return array('table' => self::table($db, 'usermeta'), 'id_col' => 'umeta_id', 'entity_id_col' => 'user_id');
            case 'term':
                return array('table' => self::table($db, 'termmeta'), 'id_col' => 'meta_id', 'entity_id_col' => 'term_id');
            case 'comment':
                return array('table' => self::table($db, 'commentmeta'), 'id_col' => 'meta_id', 'entity_id_col' => 'comment_id');
        }

        return null;
    }

    public static function targetKey(array $target): string
    {
        return $target['kind'] . ':' . $target['entity'] . ':' . $target['field'] . ':' . $target['table'];
    }

    /**
     * @param array<string, mixed> $target
     */
    public static function targetWhereSql(object $db, array $target, string $extra = ''): string
    {
        $where = array();

        if (isset($target['where']) && '' !== $target['where']) {
            $where[] = $target['where'];
        }

        if (!empty($target['post_types']) && is_array($target['post_types'])) {
            $types = array();
            foreach ($target['post_types'] as $type) {
                $types[] = "'" . self::escaped((string) $type) . "'";
            }
            if ($types) {
                $where[] = $target['entity_id_col'] . ' IN (SELECT ID FROM ' . self::table($db, 'posts') . ' WHERE post_type IN (' . implode(', ', $types) . '))';
            }
        }

        if ('' !== $extra) {
            $where[] = $extra;
        }

        return implode(' AND ', $where);
    }
}
