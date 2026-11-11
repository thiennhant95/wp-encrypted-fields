<?php

namespace Koyo\EncryptedFields\Integrations\WooCommerce;

/**
 * WooCommerce Analytics customer lookup table helper.
 *
 * The stock schema uses short varchar columns (username 60, email 100,
 * city 100). Ciphertext is longer than plaintext, so a long username can no
 * longer fit. Widen the encrypted columns before migration or before the
 * analytics integration writes a row.
 */
final class CustomerLookupSchema
{
    private const MIN_LENGTH = 255;
    private const COLUMNS = array('username', 'email', 'city', 'billing_phone', 'shipping_phone');

    private static ?bool $ensured = null;

    public static function ensure($wpdb = null): bool
    {
        if (null !== self::$ensured) {
            return self::$ensured;
        }

        if (null === $wpdb) {
            global $wpdb;
        }

        if (!is_object($wpdb)
            || !isset($wpdb->prefix)
            || !method_exists($wpdb, 'get_results')
            || !method_exists($wpdb, 'query')
        ) {
            return false;
        }

        $table = (string) $wpdb->prefix . 'wc_customer_lookup';

        try {
            if (method_exists($wpdb, 'prepare')) {
                $exists = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table));
            } else {
                $exists = $wpdb->get_var("SHOW TABLES LIKE '" . $table . "'");
            }
        } catch (\Throwable $exception) {
            return false;
        }

        if (empty($exists)) {
            return false;
        }

        $format = defined('ARRAY_A') ? ARRAY_A : 'ARRAY_A';

        try {
            $columns = $wpdb->get_results('SHOW COLUMNS FROM `' . $table . '`', $format);
        } catch (\Throwable $exception) {
            return false;
        }

        if (!is_array($columns)) {
            return false;
        }

        $changes = array();

        foreach ($columns as $column) {
            if (!is_array($column) || !isset($column['Field']) || !isset($column['Type'])) {
                continue;
            }

            $name = (string) $column['Field'];

            if (!in_array($name, self::COLUMNS, true)) {
                continue;
            }

            if (1 !== preg_match('/^varchar\((\d+)\)$/i', (string) $column['Type'], $matches)) {
                continue;
            }

            if ((int) $matches[1] >= self::MIN_LENGTH) {
                continue;
            }

            $null = isset($column['Null']) && 'NO' === strtoupper((string) $column['Null']) ? 'NOT NULL' : 'NULL';
            $changes[] = 'MODIFY `' . $name . '` varchar(' . self::MIN_LENGTH . ') ' . $null;
        }

        if (array() === $changes) {
            self::$ensured = true;

            return true;
        }

        try {
            $result = $wpdb->query('ALTER TABLE `' . $table . '` ' . implode(', ', $changes));
        } catch (\Throwable $exception) {
            return false;
        }

        if (false === $result) {
            return false;
        }

        self::$ensured = true;

        return true;
    }
}
