<?php

/**
 * Standalone crypto tests (no PHPUnit, no WordPress).
 *
 * Run: php tests/run-crypto.php
 */

declare(strict_types=1);

require_once __DIR__ . '/../src/Config/Field.php';
require_once __DIR__ . '/../src/Contracts/EncryptorInterface.php';
require_once __DIR__ . '/../src/Crypto/Format.php';
require_once __DIR__ . '/../src/Crypto/KeyManager.php';
require_once __DIR__ . '/../src/Crypto/LegacyEcKoyoCipher.php';
require_once __DIR__ . '/../src/Crypto/Encryptor.php';

use Koyo\EncryptedFields\Config\Field;
use Koyo\EncryptedFields\Crypto\Encryptor;
use Koyo\EncryptedFields\Crypto\Format;
use Koyo\EncryptedFields\Crypto\KeyManager;
use Koyo\EncryptedFields\Crypto\LegacyEcKoyoCipher;

$GLOBALS['kec_crypto_pass'] = 0;
$GLOBALS['kec_crypto_fail'] = 0;

function check($condition, string $message): void
{
    if ($condition) {
        ++$GLOBALS['kec_crypto_pass'];
        echo "PASS: {$message}\n";

        return;
    }

    ++$GLOBALS['kec_crypto_fail'];
    echo "FAIL: {$message}\n";
}

function legacy_ctr_encrypt(string $plaintext, string $hexKey): string
{
    $key = hex2bin($hexKey);
    $nonce = random_bytes(16);
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $nonce);

    return base64_encode($nonce . $ciphertext);
}

function legacy_login_encrypt(string $plaintext, string $hexKey): string
{
    $key = hex2bin($hexKey);
    $ciphertext = @openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, '');

    return base64_encode($ciphertext);
}

function legacy_email_encrypt(string $email, string $emailKey, string $emailIv): string
{
    $parts = explode('@', $email);
    if (2 !== count($parts)) {
        return $email;
    }

    $key = hash('sha256', $emailKey);
    $iv = substr(hash('sha256', $emailIv), 0, 16);
    $inner = openssl_encrypt($email, 'aes-256-cbc', $key, 0, $iv);

    return base64_encode($inner) . '@' . $parts[1];
}

$legacyConfig = array(
    'ctr_key' => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    'login_key' => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    'email_key' => 'test-email-secret-key-not-for-production',
    'email_iv' => 'test-email-iv-not-for-production',
);

$keyA = base64_encode(random_bytes(32));
$keyB = base64_encode(random_bytes(32));

$keys = new KeyManager(array(
    'key' => $keyA,
    'legacy' => $legacyConfig,
));

$encryptor = new Encryptor($keys);

$textField = new Field('post', '_billing_first_name', 'text');
$emailField = new Field('user', 'user_email', 'email');
$loginField = new Field('user', 'user_login', 'login');

// Key manager basics.
check('config' === $keys->keySource(), 'key source is config');
check(8 === strlen($keys->currentKeyId()), 'key_id is 8 characters');
check(32 === strlen((string) $keys->keyFor($keys->currentKeyId())), 'current key is 32 bytes');
check(32 === strlen($keys->derive('enc', 'user:user_email')), 'derived key is 32 bytes');
check($keys->derive('enc', 'user:user_email') !== $keys->derive('mac', 'user:user_email'), 'purpose separation');
check($keys->derive('enc', 'user:user_email') !== $keys->derive('enc', 'post:_billing_email'), 'domain separation');

$generated = $keys->generateKey();
check(32 === strlen((string) base64_decode($generated, true)), 'generateKey returns base64 of 32 bytes');

// Randomized text roundtrip, including unicode.
$text = 'こんにちは世界 🌏 <>&" NUL:' . "\0" . ' end';
$encryptedText = $encryptor->encrypt($text, $textField);
check(Format::detect($encryptedText) === 'v2', 'text uses v2 envelope');
check(Format::decode($encryptedText)['cipher'] === 'sb', 'text uses randomized cipher');
check($encryptor->decrypt($encryptedText, $textField) === $text, 'text roundtrip (unicode + NUL)');

$encryptedAgain = $encryptor->encrypt($text, $textField);
check($encryptedAgain !== $encryptedText, 'randomized ciphertext differs per call');
check($encryptor->decrypt($encryptedAgain, $textField) === $text, 'second randomized ciphertext decrypts');

// Idempotency.
check($encryptor->encrypt($encryptedText, $textField) === $encryptedText, 'encrypt is idempotent');
check($encryptor->decrypt($text, $textField) === $text, 'decrypt returns plaintext unchanged');

// Deterministic email/login.
$email = 'User.Name@Example.COM';
$encryptedEmail = $encryptor->encrypt($email, $emailField);
$decodedEmail = Format::decode($encryptedEmail);
check($decodedEmail['cipher'] === 'det', 'email uses deterministic cipher');
check($encryptor->encrypt($email, $emailField) === $encryptedEmail, 'deterministic equality for email');
check($encryptor->encrypt('USER.NAME@EXAMPLE.COM ', $emailField) === $encryptedEmail, 'email normalization is case/space insensitive');
check($encryptor->decrypt($encryptedEmail, $emailField) === 'user.name@example.com', 'email roundtrip normalized');

$encryptedEmailOtherField = $encryptor->encrypt($email, new Field('user', 'billing_email', 'email'));
check($encryptedEmailOtherField !== $encryptedEmail, 'email domain separation changes ciphertext');

$login = 'User.Name';
$encryptedLogin = $encryptor->encrypt($login, $loginField);
check(Format::decode($encryptedLogin)['cipher'] === 'det', 'login uses deterministic cipher');
check($encryptor->encrypt(' USER.NAME ', $loginField) === $encryptedLogin, 'login normalization is case/space insensitive');
check($encryptor->decrypt($encryptedLogin, $loginField) === 'user.name', 'login roundtrip normalized');

// key_id in envelope matches manager.
check($decodedEmail['key_id'] === $keys->currentKeyId(), 'envelope key_id matches current key id');

// Rotation with old key.
$oldKeyId = $keys->currentKeyId();
$rotatedKeys = new KeyManager(array(
    'key' => $keyB,
    'old_keys' => array($oldKeyId => $keyA),
    'legacy' => $legacyConfig,
));
$rotated = new Encryptor($rotatedKeys);
check($rotatedKeys->currentKeyId() !== $oldKeyId, 'rotated key id differs');
check($rotated->decrypt($encryptedText, $textField) === $text, 'old key decrypts after rotation');
$newEncryption = $rotated->encrypt('after rotation', $textField);
check(Format::decode($newEncryption)['key_id'] === $rotatedKeys->currentKeyId(), 'new writes use current key id');

$withoutOldKey = new KeyManager(array('key' => $keyB, 'legacy' => $legacyConfig));
check((new Encryptor($withoutOldKey))->decrypt($encryptedText, $textField) === $encryptedText, 'unknown key id returns ciphertext');

// maxLength.
$shortField = new Field('user', 'user_login', 'login', false, null, array('max_length' => 10));
$threw = false;
try {
    $encryptor->encrypt('averylongloginname', $shortField);
} catch (\RuntimeException $exception) {
    $threw = true;
}
check($threw, 'maxLength overflow throws RuntimeException');

// Legacy CTR.
$legacyCtr = legacy_ctr_encrypt('Legacy CTR text 日本語', $legacyConfig['ctr_key']);
check((new LegacyEcKoyoCipher($legacyConfig))->detect($legacyCtr) === 'ctr', 'legacy CTR detected');
check($encryptor->isEncrypted($legacyCtr), 'legacy CTR recognized as encrypted');
check($encryptor->decrypt($legacyCtr, $textField) === 'Legacy CTR text 日本語', 'legacy CTR decrypts');

// Legacy login.
$legacyLogin = legacy_login_encrypt('legacyuser', $legacyConfig['login_key']);
check((new LegacyEcKoyoCipher($legacyConfig))->detect($legacyLogin) === 'login', 'legacy login detected');
check($encryptor->decrypt($legacyLogin, $loginField) === 'legacyuser', 'legacy login decrypts');

// Legacy email.
$legacyEmail = legacy_email_encrypt('Legacy.User@Example.com', $legacyConfig['email_key'], $legacyConfig['email_iv']);
check((new LegacyEcKoyoCipher($legacyConfig))->detect($legacyEmail) === 'email', 'legacy email detected');
check($encryptor->decrypt($legacyEmail, $emailField) === 'Legacy.User@Example.com', 'legacy email decrypts');

// Tamper detection returns the original input.
$tamperedPayload = $decodedEmail['payload'];
$tamperedPayload[0] = chr(ord($tamperedPayload[0]) ^ 0x01);
$tamperedEmail = Format::encode($decodedEmail['cipher'], $decodedEmail['key_id'], $tamperedPayload, false);
check($encryptor->decrypt($tamperedEmail, $emailField) === $tamperedEmail, 'tampered deterministic value returns input');

$textDecoded = Format::decode($encryptedText);
$tamperedTextPayload = $textDecoded['payload'];
$last = strlen($tamperedTextPayload) - 1;
$tamperedTextPayload[$last] = chr(ord($tamperedTextPayload[$last]) ^ 0x01);
$tamperedText = Format::encode($textDecoded['cipher'], $textDecoded['key_id'], $tamperedTextPayload, false);
check($encryptor->decrypt($tamperedText, $textField) === $tamperedText, 'tampered randomized value returns input');

$unknownKeyEnvelope = Format::encode($decodedEmail['cipher'], '00000000', $decodedEmail['payload'], false);
check($encryptor->decrypt($unknownKeyEnvelope, $emailField) === $unknownKeyEnvelope, 'missing key returns input');

// Format helpers, including compact variant.
$payload = random_bytes(30);
$compact = Format::encode('sb', 'abcdef12', $payload, true);
check(Format::detect($compact) === 'v2c', 'compact format detected');
check(Format::decode($compact)['payload'] === $payload, 'compact payload roundtrips');
check(Format::isEncrypted($compact), 'compact format is encrypted');
check(Format::detect('plain text') === null, 'plain text is not an envelope');

$compactField = new Field('user', 'user_email', 'email', false, null, array('compact' => true));
$compactEmail = $encryptor->encrypt('compact@example.com', $compactField);
check(Format::detect($compactEmail) === 'v2c', 'compact field writes v2c');
check($encryptor->decrypt($compactEmail, $compactField) === 'compact@example.com', 'compact field decrypts');

// Empty / sentinel values.
check($encryptor->encrypt('', $textField) === '', 'empty string is not encrypted');
check($encryptor->decrypt('', $textField) === '', 'empty string decrypts to itself');
check($encryptor->decrypt('0', $textField) === '0', 'plaintext "0" is returned unchanged');
check($encryptor->decrypt('0.0', $textField) === '0.0', 'plaintext "0.0" is returned unchanged');
$whitespace = '   ';
$encryptedWhitespace = $encryptor->encrypt($whitespace, $textField);
check($encryptor->decrypt($encryptedWhitespace, $textField) === $whitespace, 'whitespace-only text roundtrips');

// Search secret is derived, stable and never persisted.
$searchSecret = $keys->searchSecret();
check(32 === strlen($searchSecret), 'searchSecret is 32 bytes');
check($searchSecret === $keys->searchSecret(), 'searchSecret is stable');
$override = new KeyManager(array('key' => $keyA, 'search_secret' => 'explicit-search-secret'));
check(32 === strlen($override->searchSecret()), 'searchSecret override is normalized to 32 bytes');
check($override->searchSecret() !== $searchSecret, 'searchSecret override differs from derived secret');

// KEC_KEY_NEXT is the active key while KEC_KEY stays readable.
check(!$keys->isRotationPending(), 'rotation is not pending without a next key');
if (!defined('KEC_KEY')) {
    define('KEC_KEY', $keyA);
}
if (!defined('KEC_KEY_NEXT')) {
    define('KEC_KEY_NEXT', $keyB);
}

$nextKeys = new KeyManager(array('legacy' => $legacyConfig));
check($nextKeys->isRotationPending(), 'KEC_KEY_NEXT marks rotation pending');
check($nextKeys->currentKeyId() !== $oldKeyId, 'KEC_KEY_NEXT is the active current key');
check(null !== $nextKeys->keyFor($oldKeyId), 'KEC_KEY remains readable as the old key');
check(null !== $nextKeys->keyFor($nextKeys->currentKeyId()), 'current key is available by id');
check((new Encryptor($nextKeys))->decrypt($encryptedText, $textField) === $text, 'old ciphertext decrypts with KEC_KEY_NEXT active');
$nextCipher = (new Encryptor($nextKeys))->encrypt('after next rotation', $textField);
check(Format::decode($nextCipher)['key_id'] === $nextKeys->currentKeyId(), 'new writes use the KEC_KEY_NEXT id');
check($nextKeys->tokenSecret() !== $keys->tokenSecret(), 'token secret follows the current key without KEC_TOKEN_SECRET');

echo "\n{$GLOBALS['kec_crypto_pass']} passed, {$GLOBALS['kec_crypto_fail']} failed\n";
exit($GLOBALS['kec_crypto_fail'] > 0 ? 1 : 0);
