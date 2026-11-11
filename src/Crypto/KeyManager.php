<?php

namespace EncryptedFields\Crypto;

/**
 * Resolves master keys, old (rotation) keys and derives purpose-bound
 * sub-keys. Keys are never persisted by this class.
 */
final class KeyManager
{
    private const HKDF_SALT = 'kec-hkdf-v2';
    private const HKDF_INFO_PREFIX = 'kec|v2|';

    /** @var array<string,string> key_id => binary key */
    private array $keys = array();

    /** @var string|null */
    private ?string $currentKey = null;

    /** @var string */
    private string $currentId = '';

    /** @var string|null */
    private ?string $nextKey = null;

    /** @var string */
    private string $nextId = '';

    /** @var bool */
    private bool $rotationPending = false;

    /** @var string */
    private string $source = 'none';

    /** @var array<string,mixed> */
    private array $legacy;

    /** @var string|null */
    private ?string $searchSecretOverride = null;

    public function __construct(array $config = array())
    {
        $this->legacy = $this->resolveLegacy($config);

        $rawKey = null;
        $rawNext = null;
        $nextSource = '';

        if (isset($config['next_key']) && is_string($config['next_key']) && '' !== trim($config['next_key'])) {
            $rawNext = $config['next_key'];
            $nextSource = 'config';
        } elseif (defined('KEC_KEY_NEXT') && is_string(constant('KEC_KEY_NEXT')) && '' !== trim((string) constant('KEC_KEY_NEXT'))) {
            $rawNext = (string) constant('KEC_KEY_NEXT');
            $nextSource = 'constant';
        }

        if (isset($config['key']) && is_string($config['key']) && '' !== trim($config['key'])) {
            $rawKey = $config['key'];
            $this->source = 'config';
        } elseif (defined('KEC_KEY') && is_string(constant('KEC_KEY')) && '' !== trim((string) constant('KEC_KEY'))) {
            $rawKey = (string) constant('KEC_KEY');
            $this->source = 'constant';
        } else {
            $file = null;

            if (isset($config['key_file']) && is_string($config['key_file']) && '' !== $config['key_file']) {
                $file = $config['key_file'];
            } elseif (defined('KEC_KEY_FILE') && is_string(constant('KEC_KEY_FILE'))) {
                $file = (string) constant('KEC_KEY_FILE');
            }

            if (null !== $file && is_file($file) && is_readable($file)) {
                $contents = file_get_contents($file);
                if (is_string($contents) && '' !== trim($contents)) {
                    $rawKey = trim($contents);
                    $this->source = 'file';
                }
            }
        }

        if (null === $rawKey && $this->allowDbKey($config) && function_exists('get_option')) {
            $option = get_option('kec_key');
            if (is_string($option) && '' !== trim($option)) {
                $rawKey = $option;
                $this->source = 'option';
            }
        }

        $primaryKey = null;
        $primaryId = '';

        if (null !== $rawKey) {
            $primaryKey = self::parseKey($rawKey);
            if (null !== $primaryKey) {
                $primaryId = self::keyIdFor($primaryKey);
            }
        }

        if (null !== $rawNext) {
            $parsedNext = self::parseKey($rawNext);
            if (null !== $parsedNext) {
                $this->nextKey = $parsedNext;
                $this->nextId = self::keyIdFor($parsedNext);

                if ('constant' === $nextSource) {
                    $this->source = 'constant';
                } elseif ('config' === $nextSource && 'none' === $this->source) {
                    $this->source = 'config';
                }
            }
        }

        if (null !== $this->nextKey) {
            $this->currentKey = $this->nextKey;
            $this->currentId = $this->nextId;
            $this->keys[$this->currentId] = $this->currentKey;

            if (null !== $primaryKey && $primaryId !== $this->currentId) {
                $this->keys[$primaryId] = $primaryKey;
                $this->rotationPending = true;
            }
        } elseif (null !== $primaryKey) {
            $this->currentKey = $primaryKey;
            $this->currentId = $primaryId;
            $this->keys[$this->currentId] = $primaryKey;
        }

        $oldKeys = array();

        if (isset($config['old_keys']) && is_array($config['old_keys'])) {
            $oldKeys = $config['old_keys'];
        } elseif (defined('KEC_OLD_KEYS') && is_array(constant('KEC_OLD_KEYS'))) {
            $oldKeys = (array) constant('KEC_OLD_KEYS');
        }

        foreach ($oldKeys as $keyId => $raw) {
            if (!is_string($raw)) {
                continue;
            }

            $binary = self::parseKey($raw);
            if (null === $binary) {
                continue;
            }

            $id = (string) $keyId;
            if (null !== $this->currentKey && $id === $this->currentId) {
                continue;
            }

            $this->keys[$id] = $binary;

            $computed = self::keyIdFor($binary);
            if (null !== $this->currentKey && $computed === $this->currentId) {
                continue;
            }

            if (!isset($this->keys[$computed])) {
                $this->keys[$computed] = $binary;
            }
        }

        $secret = null;

        if (isset($config['search_secret']) && is_string($config['search_secret']) && '' !== $config['search_secret']) {
            $secret = $config['search_secret'];
        } elseif (defined('KEC_SEARCH_SECRET') && is_string(constant('KEC_SEARCH_SECRET')) && '' !== (string) constant('KEC_SEARCH_SECRET')) {
            $secret = (string) constant('KEC_SEARCH_SECRET');
        }

        if (null !== $secret) {
            $this->searchSecretOverride = self::normalizeSecret($secret);
        }
    }

    public function currentKeyId(): string
    {
        if (null === $this->currentKey) {
            throw new \RuntimeException('Encryption key is not configured.');
        }

        return $this->currentId;
    }

    /**
     * @return string|null Binary 32-byte key, or null when the id is unknown.
     */
    public function keyFor(string $keyId): ?string
    {
        if ('' !== $keyId && isset($this->keys[$keyId])) {
            return $this->keys[$keyId];
        }

        return null;
    }

    /**
     * Derive a 32-byte sub-key with HKDF-SHA256.
     *
     * @param string $purpose "enc", "mac", "search", ...
     * @param string $domain  Field domain, usually "entity:key".
     */
    public function derive(string $purpose, string $domain, ?string $keyId = null): string
    {
        if (null === $keyId) {
            $master = $this->currentKey;
        } else {
            $master = $this->keyFor($keyId);
        }

        if (null === $master) {
            throw new \RuntimeException('Encryption key is not available for derivation.');
        }

        $info = self::HKDF_INFO_PREFIX . $purpose . '|' . $domain;

        return self::hkdf($master, $info, 32, self::HKDF_SALT);
    }

    /**
     * Search secret is derived from the master key (or an explicit override)
     * and must never be written to the database.
     */
    public function searchSecret(): string
    {
        if (null !== $this->searchSecretOverride) {
            return $this->searchSecretOverride;
        }

        return $this->derive('search', 'search');
    }

    /**
     * Stable secret for blind-index tokens (user_login / user_email).
     * Prefer KEC_TOKEN_SECRET so token values survive master-key rotation.
     */
    public function tokenSecret(): string
    {
        if (defined('KEC_TOKEN_SECRET') && is_string(constant('KEC_TOKEN_SECRET')) && '' !== (string) constant('KEC_TOKEN_SECRET')) {
            return self::normalizeSecret((string) constant('KEC_TOKEN_SECRET'));
        }

        return $this->derive('token', 'token');
    }

    public function tokenSecretIsStable(): bool
    {
        return defined('KEC_TOKEN_SECRET')
            && is_string(constant('KEC_TOKEN_SECRET'))
            && '' !== (string) constant('KEC_TOKEN_SECRET');
    }

    /**
     * Generate a new master key encoded as standard base64 (32 bytes).
     */
    public function generateKey(): string
    {
        return base64_encode(random_bytes(32));
    }

    public function keySource(): string
    {
        return $this->source;
    }

    public function isConfigured(): bool
    {
        return null !== $this->currentKey;
    }

    /**
     * True when KEC_KEY_NEXT is the active key while KEC_KEY remains readable.
     */
    public function isRotationPending(): bool
    {
        return $this->rotationPending;
    }

    public function nextKeyId(): ?string
    {
        return '' !== $this->nextId ? $this->nextId : null;
    }

    /**
     * Legacy cipher configuration, passed through to LegacyCipher.
     *
     * @return array<string,mixed>
     */
    public function legacyConfig(): array
    {
        return $this->legacy;
    }

    /**
     * @param array<string,mixed> $config
     * @return array<string,mixed>
     */
    private function resolveLegacy(array $config): array
    {
        if (isset($config['legacy']) && is_array($config['legacy']) && array() !== $config['legacy']) {
            return $config['legacy'];
        }

        if (defined('KEC_LEGACY') && is_array(constant('KEC_LEGACY'))) {
            return (array) constant('KEC_LEGACY');
        }

        return array();
    }

    /**
     * @param array<string,mixed> $config
     */
    private function allowDbKey(array $config): bool
    {
        if (isset($config['allow_db_key'])) {
            return (bool) $config['allow_db_key'];
        }

        if (defined('KEC_ALLOW_DB_KEY')) {
            return (bool) constant('KEC_ALLOW_DB_KEY');
        }

        return false;
    }

    private static function keyIdFor(string $binary): string
    {
        return substr(hash('sha256', $binary), 0, 8);
    }

    /**
     * Accepts base64, base64:, hex, hex: or raw 32-byte keys.
     */
    private static function parseKey(string $raw): ?string
    {
        $raw = trim($raw);
        if ('' === $raw) {
            return null;
        }

        if (0 === stripos($raw, 'base64:')) {
            return self::decodeBase64(substr($raw, 7));
        }

        if (0 === stripos($raw, 'hex:')) {
            $hex = substr($raw, 4);
            if (self::isHex($hex)) {
                $binary = @hex2bin($hex);
                if (false !== $binary && 32 === strlen($binary)) {
                    return $binary;
                }
            }

            return null;
        }

        if (self::isHex($raw) && 64 === strlen($raw)) {
            $binary = @hex2bin($raw);

            return false === $binary ? null : $binary;
        }

        $decoded = self::decodeBase64($raw);
        if (null !== $decoded) {
            return $decoded;
        }

        if (32 === strlen($raw)) {
            return $raw;
        }

        return null;
    }

    private static function decodeBase64(string $raw): ?string
    {
        $raw = trim($raw);
        if ('' === $raw) {
            return null;
        }

        $normalized = $raw;
        $remainder = strlen($normalized) % 4;
        if (0 !== $remainder) {
            $normalized .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode($normalized, true);

        return false !== $decoded && 32 === strlen($decoded) ? $decoded : null;
    }

    private static function isHex(string $value): bool
    {
        return '' !== $value && 0 === (strlen($value) % 2) && 1 === preg_match('/^[0-9a-fA-F]+$/', $value);
    }

    private static function normalizeSecret(string $secret): string
    {
        $parsed = self::parseKey($secret);
        if (null !== $parsed) {
            return $parsed;
        }

        return hash('sha256', $secret, true);
    }

    private static function hkdf(string $ikm, string $info, int $length, string $salt): string
    {
        if ('' === $salt) {
            $salt = str_repeat("\0", 32);
        }

        $prk = hash_hmac('sha256', $ikm, $salt, true);
        $output = '';
        $previous = '';
        $counter = 1;

        while (strlen($output) < $length) {
            $previous = hash_hmac('sha256', $previous . $info . chr($counter), $prk, true);
            $output .= $previous;
            ++$counter;
        }

        return substr($output, 0, $length);
    }
}
