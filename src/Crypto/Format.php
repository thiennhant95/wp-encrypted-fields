<?php

namespace EncryptedFields\Crypto;

/**
 * Storage format helpers for the v2 cipher envelope.
 *
 *   enc:v2:<cipher>:<key_id>:<base64url(payload)>
 *   enc:v2c:<cipher>:<key_id>:<base64url(payload)>
 */
final class Format
{
    public const PREFIX = 'enc:';
    public const VERSION = 'v2';
    public const COMPACT_VERSION = 'v2c';

    /**
     * @param string $payload Raw binary payload (nonce/ciphertext/tag).
     */
    public static function encode(string $cipher, string $keyId, string $payload, bool $compact = false): string
    {
        $version = $compact ? self::COMPACT_VERSION : self::VERSION;

        return self::PREFIX . $version . ':' . $cipher . ':' . $keyId . ':' . self::base64UrlEncode($payload);
    }

    /**
     * @return array{version:string,cipher:string,key_id:string,payload:string,compact:bool}|null
     */
    public static function decode(string $value): ?array
    {
        $parts = self::split($value);
        if (null === $parts) {
            return null;
        }

        $payload = self::base64UrlDecode($parts['payload']);
        if (null === $payload || '' === $payload) {
            return null;
        }

        return array(
            'version' => $parts['version'],
            'cipher' => $parts['cipher'],
            'key_id' => $parts['key_id'],
            'payload' => $payload,
            'compact' => self::COMPACT_VERSION === $parts['version'],
        );
    }

    /**
     * Returns the detected envelope version ("v2"/"v2c") without decoding
     * the payload. Used for cheap idempotency checks.
     */
    public static function detect(string $value): ?string
    {
        $parts = self::split($value);

        return null === $parts ? null : $parts['version'];
    }

    public static function isEncrypted(string $value): bool
    {
        return null !== self::detect($value);
    }

    public static function base64UrlEncode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $value): ?string
    {
        if ('' === $value) {
            return null;
        }

        $normalized = strtr($value, '-_', '+/');
        $remainder = strlen($normalized) % 4;
        if (0 !== $remainder) {
            $normalized .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode($normalized, true);

        return false === $decoded ? null : $decoded;
    }

    /**
     * @return array{version:string,cipher:string,key_id:string,payload:string}|null
     */
    private static function split(string $value): ?array
    {
        if (0 !== strncmp($value, self::PREFIX, strlen(self::PREFIX))) {
            return null;
        }

        $parts = explode(':', $value);
        if (5 !== count($parts)) {
            return null;
        }

        if (self::PREFIX !== $parts[0] . ':') {
            return null;
        }

        $version = $parts[1];
        if (self::VERSION !== $version && self::COMPACT_VERSION !== $version) {
            return null;
        }

        if ('' === $parts[2] || '' === $parts[3] || '' === $parts[4]) {
            return null;
        }

        return array(
            'version' => $version,
            'cipher' => $parts[2],
            'key_id' => $parts[3],
            'payload' => $parts[4],
        );
    }
}
