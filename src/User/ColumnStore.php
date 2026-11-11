<?php

namespace EncryptedFields\User;

use EncryptedFields\Config\Field;
use EncryptedFields\Plugin;

/**
 * Blind-index storage for wp_users.user_login and user_email.
 *
 * The column keeps a short deterministic token (fits varchar(60)/varchar(100));
 * the reversible plaintext is encrypted in user meta (_kec_user_login / _kec_user_email).
 */
final class ColumnStore
{
    public const LOGIN = 'login';
    public const EMAIL = 'email';

    public const META_LOGIN = '_kec_user_login';
    public const META_EMAIL = '_kec_user_email';

    private const PREFIX_LOGIN = 'k1t';
    private const PREFIX_EMAIL = 'k1e';
    private const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';

    private Plugin $plugin;

    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    public function field(string $name): ?Field
    {
        $registry = $this->plugin->registry();
        $column = self::LOGIN === $name ? 'user_login' : 'user_email';
        $columns = $registry->columns('user');

        return isset($columns[$column]) ? $columns[$column] : null;
    }

    public function metaKey(string $name): string
    {
        return self::LOGIN === $name ? self::META_LOGIN : self::META_EMAIL;
    }

    public function normalize(string $value): string
    {
        return strtolower(trim($value));
    }

    public function isToken(string $value, ?string $name = null): bool
    {
        $prefix = null === $name
            ? '(?:' . self::PREFIX_LOGIN . '|' . self::PREFIX_EMAIL . ')'
            : preg_quote(self::LOGIN === $name ? self::PREFIX_LOGIN : self::PREFIX_EMAIL, '/');

        return (bool) preg_match('/^' . $prefix . '[a-z2-7]{52}$/', $value);
    }

    public function tokenFor(string $plaintext, string $name): ?string
    {
        $field = $this->field($name);
        if (null === $field) {
            return null;
        }

        try {
            $keys = $this->plugin->keys();
            if (method_exists($keys, 'isConfigured') && !$keys->isConfigured()) {
                return null;
            }
            $secret = $keys->tokenSecret();
        } catch (\Throwable $e) {
            return null;
        }

        $prefix = self::LOGIN === $name ? self::PREFIX_LOGIN : self::PREFIX_EMAIL;
        $mac = hash_hmac('sha256', $name . '|' . $this->normalize($plaintext), $secret, true);

        return $prefix . $this->base32Lower($mac);
    }

    /**
     * Convert any stored/legacy/plaintext lookup value into the current token.
     */
    public function lookupToken(string $value, string $name): ?string
    {
        if ('' === trim($value)) {
            return null;
        }

        if ($this->isToken($value, $name)) {
            return $value;
        }

        $plain = $value;
        $field = $this->field($name);

        if (null !== $field) {
            try {
                $crypto = $this->plugin->crypto();
                if ($crypto->isEncrypted($value)) {
                    $decrypted = $crypto->decrypt($value, $field);
                    if (is_string($decrypted) && '' !== $decrypted) {
                        $plain = $decrypted;
                    }
                }
            } catch (\Throwable $e) {
                $plain = $value;
            }
        }

        return $this->tokenFor($plain, $name);
    }

    /**
     * Resolve a stored column value to plaintext (token -> meta, cipher -> decrypt).
     */
    public function plainFromStored(string $value, string $name, ?int $userId = null): string
    {
        if ('' === $value) {
            return $value;
        }

        if ($this->isToken($value, $name)) {
            if (null === $userId || $userId <= 0) {
                $userId = $this->userIdByToken($value, $name);
            }

            if (null !== $userId && $userId > 0) {
                $plain = $this->readPlain($userId, $name);
                if (is_string($plain) && '' !== $plain) {
                    return $plain;
                }
            }

            return $value;
        }

        $field = $this->field($name);
        if (null === $field) {
            return $value;
        }

        try {
            $crypto = $this->plugin->crypto();
            if ($crypto->isEncrypted($value)) {
                $plain = $crypto->decrypt($value, $field);
                if (is_string($plain) && '' !== $plain) {
                    return $plain;
                }
            }
        } catch (\Throwable $e) {
            return $value;
        }

        return $value;
    }

    public function storePlain(int $userId, string $plaintext, string $name): bool
    {
        if ($userId <= 0 || '' === $plaintext) {
            return false;
        }

        return (bool) update_user_meta($userId, $this->metaKey($name), $plaintext);
    }

    public function readPlain(int $userId, string $name): ?string
    {
        if ($userId <= 0) {
            return null;
        }

        $value = get_user_meta($userId, $this->metaKey($name), true);

        return is_string($value) && '' !== $value ? $value : null;
    }

    public function userIdByToken(string $token, string $name): ?int
    {
        global $wpdb;

        if (!is_object($wpdb) || !isset($wpdb->users)) {
            return null;
        }

        $column = self::LOGIN === $name ? 'user_login' : 'user_email';
        $id = $wpdb->get_var($wpdb->prepare(
            "SELECT ID FROM {$wpdb->users} WHERE {$column} = %s LIMIT 1",
            $token
        ));

        return null === $id ? null : (int) $id;
    }

    public function secret(): string
    {
        return $this->plugin->keys()->tokenSecret();
    }

    private function base32Lower(string $binary): string
    {
        $bits = '';
        $length = strlen($binary);

        for ($i = 0; $i < $length; $i++) {
            $bits .= str_pad(decbin(ord($binary[$i])), 8, '0', STR_PAD_LEFT);
        }

        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            $out .= self::BASE32[bindec($chunk)];
        }

        return $out;
    }
}
