<?php

namespace EncryptedFields\Crypto;

use EncryptedFields\Config\Field;
use EncryptedFields\Contracts\EncryptorInterface;

/**
 * AES-256-GCM based encryptor.
 *
 * Randomized fields ("sb") store nonce . ciphertext . tag.
 * Deterministic fields ("det") use a SIV-style construction: a keyed hash of
 * the normalized plaintext provides both the GCM nonce and the authentication
 * tag stored with the ciphertext. This keeps equality lookups working without
 * storing the nonce separately.
 */
final class Encryptor implements EncryptorInterface
{
    private KeyManager $keys;
    private LegacyCipher $legacy;

    public function __construct(KeyManager $keys)
    {
        $this->keys = $keys;
        $this->legacy = new LegacyCipher($keys->legacyConfig());
    }

    public function encrypt(string $plaintext, Field $field): string
    {
        if ('' === $plaintext) {
            return $plaintext;
        }

        if ($this->isEncrypted($plaintext)) {
            return $plaintext;
        }

        $cipher = $this->resolveCipher($field);
        $keyId = $this->keys->currentKeyId();
        $domain = $this->domain($field);

        if ('det' === $cipher) {
            $payload = $this->encryptDeterministic($plaintext, $field, $domain, $keyId);
        } else {
            $payload = $this->encryptRandomized($plaintext, $domain, $keyId);
        }

        $compact = (bool) $field->option('compact', false);
        $encoded = Format::encode($cipher, $keyId, $payload, $compact);

        $maxLength = $field->maxLength();
        if (null !== $maxLength && strlen($encoded) > $maxLength) {
            throw new \RuntimeException(sprintf(
                'Ciphertext for %s:%s exceeds max length %d (got %d bytes).',
                $field->entity(),
                $field->key(),
                $maxLength,
                strlen($encoded)
            ));
        }

        return $encoded;
    }

    public function decrypt(string $value, Field $field): string
    {
        if ('' === $value) {
            return $value;
        }

        $decoded = Format::decode($value);
        if (null !== $decoded) {
            $plain = $this->decryptV2($decoded, $field);

            return null === $plain ? $value : $plain;
        }

        if ($this->legacy->isAvailable()) {
            $plain = $this->decryptLegacy($value, $field);
            if (null !== $plain) {
                return $plain;
            }
        }

        return $value;
    }

    public function isEncrypted(string $value): bool
    {
        if (Format::isEncrypted($value)) {
            return true;
        }

        return $this->legacy->isAvailable() && $this->legacy->isEncrypted($value);
    }

    /**
     * @param array{version:string,cipher:string,key_id:string,payload:string,compact:bool} $decoded
     */
    private function decryptV2(array $decoded, Field $field): ?string
    {
        $keyId = $decoded['key_id'];
        $key = $this->keys->keyFor($keyId);

        if (null === $key) {
            return null;
        }

        $domain = $this->domain($field);
        $payload = $decoded['payload'];

        if ('sb' === $decoded['cipher']) {
            return $this->decryptRandomized($payload, $domain, $keyId);
        }

        if ('det' === $decoded['cipher']) {
            return $this->decryptDeterministic($payload, $domain, $keyId);
        }

        return null;
    }

    private function encryptRandomized(string $plaintext, string $domain, string $keyId): string
    {
        $key = $this->keys->derive('enc', $domain, $keyId);
        $nonce = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            '',
            16
        );

        if (false === $ciphertext) {
            throw new \RuntimeException('Encryption failed.');
        }

        return $nonce . $ciphertext . $tag;
    }

    private function decryptRandomized(string $payload, string $domain, string $keyId): ?string
    {
        if (strlen($payload) < 28) {
            return null;
        }

        $nonce = substr($payload, 0, 12);
        $tag = substr($payload, -16);
        $ciphertext = substr($payload, 12, -16);
        $key = $this->keys->derive('enc', $domain, $keyId);
        $plain = @openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);

        return false === $plain ? null : $plain;
    }

    private function encryptDeterministic(string $plaintext, Field $field, string $domain, string $keyId): string
    {
        $normalized = $this->normalize($plaintext, $field);
        $keyEnc = $this->keys->derive('enc', $domain, $keyId);
        $keyMac = $this->keys->derive('mac', $domain, $keyId);

        $siv = substr(hash_hmac('sha256', $domain . '|' . $normalized, $keyMac, true), 0, 16);
        $nonce = substr($siv, 0, 12);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $normalized,
            'aes-256-gcm',
            $keyEnc,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            '',
            16
        );

        if (false === $ciphertext) {
            throw new \RuntimeException('Encryption failed.');
        }

        return $ciphertext . $siv;
    }

    private function decryptDeterministic(string $payload, string $domain, string $keyId): ?string
    {
        if (strlen($payload) < 16) {
            return null;
        }

        $siv = substr($payload, -16);
        $ciphertext = substr($payload, 0, -16);
        $nonce = substr($siv, 0, 12);
        $keyEnc = $this->keys->derive('enc', $domain, $keyId);
        $keyMac = $this->keys->derive('mac', $domain, $keyId);

        // GCM with a 12-byte nonce encrypts using the counter block
        // nonce||0x00000002. The GCM tag is intentionally not stored; the SIV
        // is the authentication tag, so decrypt with the equivalent CTR
        // keystream and verify the SIV afterwards.
        $counter = $nonce . "\x00\x00\x00\x02";
        $plain = @openssl_decrypt($ciphertext, 'aes-256-ctr', $keyEnc, OPENSSL_RAW_DATA, $counter);

        if (false === $plain) {
            return null;
        }

        $expected = substr(hash_hmac('sha256', $domain . '|' . $plain, $keyMac, true), 0, 16);
        if (!hash_equals($expected, $siv)) {
            return null;
        }

        return $plain;
    }

    private function decryptLegacy(string $value, Field $field): ?string
    {
        $type = $field->type();

        if ('email' === $type) {
            $plain = $this->legacy->decryptEmail($value);
            if (null !== $plain) {
                return $plain;
            }
        } elseif ('login' === $type) {
            $plain = $this->legacy->decryptLogin($value);
            if (null !== $plain) {
                return $plain;
            }
        } else {
            $plain = $this->legacy->decryptCtr($value);
            if (null !== $plain) {
                return $plain;
            }
        }

        if (null === $this->legacy->detect($value)) {
            return null;
        }

        return $this->legacy->decrypt($value);
    }

    private function normalize(string $plaintext, Field $field): string
    {
        if ('email' === $field->type() || 'login' === $field->type()) {
            return strtolower(trim($plaintext));
        }

        return $plaintext;
    }

    private function resolveCipher(Field $field): string
    {
        $cipher = strtolower($field->cipherName());

        if (in_array($cipher, array('det', 'deterministic', 'siv'), true)) {
            return 'det';
        }

        if (in_array($cipher, array('sb', 'secretbox', 'random', 'randomized'), true)) {
            return 'sb';
        }

        return in_array($field->type(), array('email', 'login'), true) ? 'det' : 'sb';
    }

    private function domain(Field $field): string
    {
        return $field->entity() . ':' . $field->key();
    }
}
