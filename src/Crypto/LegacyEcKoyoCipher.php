<?php

namespace Koyo\EncryptedFields\Crypto;

/**
 * Read-only adapter for the legacy EC-KOYO cipher formats.
 *
 * Supported:
 *  - CTR:   base64(16-byte nonce . AES-256-CTR ciphertext)
 *  - login: base64(AES-256-CBC ciphertext), empty IV
 *  - email: base64(base64(AES-256-CBC ciphertext)) . '@' . domain
 *
 * Nothing in this class writes legacy ciphertext; new data always uses v2.
 */
final class LegacyEcKoyoCipher
{
    private ?string $ctrKey;
    private ?string $loginKey;
    private ?string $emailKey;
    private ?string $emailIv;

    /**
     * @param array<string,mixed> $config
     */
    public function __construct(array $config = array())
    {
        if (array() === $config && defined('KEC_LEGACY') && is_array(constant('KEC_LEGACY'))) {
            $config = (array) constant('KEC_LEGACY');
        }

        $this->ctrKey = self::stringOrNull($config['ctr_key'] ?? null);
        $this->loginKey = self::stringOrNull($config['login_key'] ?? null);
        $this->emailKey = self::stringOrNull($config['email_key'] ?? null);
        $this->emailIv = self::stringOrNull($config['email_iv'] ?? null);
    }

    public function isAvailable(): bool
    {
        return null !== $this->ctrKey
            || null !== $this->loginKey
            || (null !== $this->emailKey && null !== $this->emailIv);
    }

    public function isEncrypted(string $value): bool
    {
        return null !== $this->detect($value);
    }

    /**
     * @return string|null "email", "ctr", "login" or null.
     */
    public function detect(string $value): ?string
    {
        if (self::isEmailEncrypted($value)) {
            return 'email';
        }

        if (self::isCtrEncrypted($value)) {
            return 'ctr';
        }

        if (self::isLoginEncrypted($value)) {
            return 'login';
        }

        return null;
    }

    /**
     * Generic decryptor. Callers that know the field type should prefer
     * decryptEmail()/decryptLogin()/decryptCtr() to avoid ambiguity.
     */
    public function decrypt(string $value): ?string
    {
        $format = $this->detect($value);

        if ('email' === $format) {
            return $this->decryptEmail($value);
        }

        if ('ctr' === $format) {
            return $this->decryptCtr($value);
        }

        if ('login' === $format) {
            return $this->decryptLogin($value);
        }

        return null;
    }

    public function decryptCtr(string $value): ?string
    {
        if (null === $this->ctrKey || !self::isCtrEncrypted($value)) {
            return null;
        }

        $key = self::parseLegacyKey($this->ctrKey);
        if (null === $key) {
            return null;
        }

        $raw = base64_decode($value, true);
        if (false === $raw || strlen($raw) <= 16) {
            return null;
        }

        $nonce = substr($raw, 0, 16);
        $ciphertext = substr($raw, 16);
        $plain = @openssl_decrypt($ciphertext, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $nonce);

        return self::validPlaintext($plain);
    }

    public function decryptLogin(string $value): ?string
    {
        if (null === $this->loginKey || !self::isLoginEncrypted($value)) {
            return null;
        }

        $key = self::parseLegacyKey($this->loginKey);
        if (null === $key) {
            return null;
        }

        $raw = base64_decode($value, true);
        if (false === $raw || strlen($raw) < 16) {
            return null;
        }

        $plain = @openssl_decrypt($raw, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, '');

        return self::validPlaintext($plain);
    }

    public function decryptEmail(string $value): ?string
    {
        if (null === $this->emailKey || null === $this->emailIv || !self::isEmailEncrypted($value)) {
            return null;
        }

        $parts = explode('@', $value);
        if (2 !== count($parts)) {
            return null;
        }

        $inner = base64_decode($parts[0], true);
        if (false === $inner || '' === $inner) {
            return null;
        }

        $key = hash('sha256', $this->emailKey);
        $iv = substr(hash('sha256', $this->emailIv), 0, 16);
        $plain = @openssl_decrypt($inner, 'aes-256-cbc', $key, 0, $iv);

        // encrypt_decrypt() encrypts the complete email address, then appends
        // the original domain as a plain-text suffix. The decrypted value is
        // therefore the full address already.
        return self::validPlaintext($plain);
    }

    public static function isCtrEncrypted(string $value): bool
    {
        if (strlen($value) < 24) {
            return false;
        }

        $decoded = base64_decode($value, true);

        return false !== $decoded && strlen($decoded) > 16;
    }

    public static function isLoginEncrypted(string $value): bool
    {
        if (strlen($value) < 16) {
            return false;
        }

        $decoded = base64_decode($value, true);
        if (false === $decoded || strlen($decoded) < 16) {
            return false;
        }

        if (0 !== strlen($decoded) % 16) {
            return false;
        }

        return base64_encode($decoded) === $value;
    }

    public static function isEmailEncrypted(string $value): bool
    {
        $parts = explode('@', $value);
        if (2 !== count($parts)) {
            return false;
        }

        $base64 = $parts[0];
        if (1 !== preg_match('/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', $base64)) {
            return false;
        }

        if (strlen($base64) < 24) {
            return false;
        }

        $decoded = base64_decode($base64, true);

        return false !== $decoded && strlen($decoded) > 16;
    }

    private static function parseLegacyKey(string $raw): ?string
    {
        $raw = trim($raw);
        if ('' === $raw) {
            return null;
        }

        if (0 === stripos($raw, 'hex:')) {
            $raw = substr($raw, 4);
        }

        if (0 === strlen($raw) % 2 && 1 === preg_match('/^[0-9a-fA-F]+$/', $raw)) {
            $binary = @hex2bin($raw);
            if (false !== $binary) {
                return self::normalizeAes256Key($binary);
            }
        }

        $decoded = base64_decode($raw, true);
        if (false !== $decoded && '' !== $decoded) {
            return self::normalizeAes256Key($decoded);
        }

        return self::normalizeAes256Key($raw);
    }

    /**
     * OpenSSL zero-pads short keys for AES-256. Do it explicitly so behaviour
     * is stable across OpenSSL versions.
     */
    private static function normalizeAes256Key(string $key): string
    {
        return substr(str_pad($key, 32, "\0"), 0, 32);
    }

    private static function validPlaintext($plain): ?string
    {
        if (!is_string($plain) || '' === $plain) {
            return null;
        }

        if (1 !== preg_match('//u', $plain)) {
            return null;
        }

        return $plain;
    }

    private static function stringOrNull($value): ?string
    {
        return is_string($value) && '' !== $value ? $value : null;
    }
}
