<?php

/**
 * Public plaintext helpers for user login/email values.
 */

if (!function_exists('kec_user_login')) {
    function kec_user_login($value, $userId = 0)
    {
        return kec_resolve_user_value($value, $userId, \Koyo\EncryptedFields\User\ColumnStore::LOGIN);
    }
}

if (!function_exists('kec_user_email')) {
    function kec_user_email($value, $userId = 0)
    {
        return kec_resolve_user_value($value, $userId, \Koyo\EncryptedFields\User\ColumnStore::EMAIL);
    }
}

if (!function_exists('kec_resolve_user_value')) {
    function kec_resolve_user_value($value, $userId, string $name)
    {
        if (!is_string($value) || '' === $value) {
            return $value;
        }

        if (!class_exists('Koyo\\EncryptedFields\\Plugin')) {
            return $value;
        }

        try {
            $plugin = \Koyo\EncryptedFields\Plugin::instance();
            $plugin->init();

            $columns = new \Koyo\EncryptedFields\User\ColumnStore($plugin);

            return $columns->plainFromStored($value, $name, (int) $userId > 0 ? (int) $userId : null);
        } catch (\Throwable $exception) {
            return $value;
        }
    }
}
