<?php

/**
 * Standalone mail hook tests with inline WordPress stubs.
 *
 * Run: php tests/run-mail.php
 */

declare(strict_types=1);

$GLOBALS['kec_mail_filters'] = array();
$GLOBALS['kec_mail_options'] = array();
$GLOBALS['kec_user_meta'] = array();
$GLOBALS['kec_pass'] = 0;
$GLOBALS['kec_fail'] = 0;

function add_filter($hook, $callback, $priority = 10, $accepted_args = 1)
{
    $GLOBALS['kec_mail_filters'][$hook][$priority][] = array($callback, (int) $accepted_args);

    return true;
}

function add_action($hook, $callback, $priority = 10, $accepted_args = 1)
{
    return add_filter($hook, $callback, $priority, $accepted_args);
}

function apply_filters($hook, $value, ...$args)
{
    if (empty($GLOBALS['kec_mail_filters'][$hook])) {
        return $value;
    }

    $priorities = $GLOBALS['kec_mail_filters'][$hook];
    ksort($priorities);
    $all = array_merge(array($value), $args);

    foreach ($priorities as $callbacks) {
        foreach ($callbacks as $entry) {
            $callback = $entry[0];
            $accepted = $entry[1];
            $slice = array_slice($all, 0, $accepted);
            $result = call_user_func_array($callback, $slice);
            $all[0] = $result;
            $value = $result;
        }
    }

    return $value;
}

function do_action($hook, ...$args)
{
    if (empty($GLOBALS['kec_mail_filters'][$hook])) {
        return;
    }

    $priorities = $GLOBALS['kec_mail_filters'][$hook];
    ksort($priorities);

    foreach ($priorities as $callbacks) {
        foreach ($callbacks as $entry) {
            call_user_func_array($entry[0], array_slice($args, 0, $entry[1]));
        }
    }
}

function get_option($name, $default = false)
{
    return array_key_exists($name, $GLOBALS['kec_mail_options'])
        ? $GLOBALS['kec_mail_options'][$name]
        : $default;
}

function update_option($name, $value, $autoload = null)
{
    $GLOBALS['kec_mail_options'][$name] = $value;

    return true;
}

function delete_option($name)
{
    unset($GLOBALS['kec_mail_options'][$name]);

    return true;
}

function wp_json_encode($value)
{
    return json_encode($value);
}

function current_time($type, $gmt = 0)
{
    return gmdate('Y-m-d H:i:s');
}

function get_user_meta($userId, $key = '', $single = false)
{
    $all = $GLOBALS['kec_user_meta'][(int) $userId] ?? array();

    if ($single) {
        return array_key_exists($key, $all) ? $all[$key] : '';
    }

    return $all;
}

final class MailWpdbStub
{
    public string $users = 'wp_users';

    public function prepare($query, ...$args)
    {
        if (1 === count($args) && is_array($args[0])) {
            $args = $args[0];
        }

        $index = 0;

        return preg_replace_callback('/%[sdf]/', function ($match) use (&$index, $args) {
            $value = $args[$index] ?? '';
            $index++;
            return '%s' === $match[0] ? "'" . (string) $value . "'" : (string) (int) $value;
        }, $query);
    }

    public function get_var($sql)
    {
        foreach (isset($GLOBALS['kec_token_user_map']) ? $GLOBALS['kec_token_user_map'] : array() as $token => $userId) {
            if (false !== strpos($sql, $token)) {
                return $userId;
            }
        }

        return null;
    }
}

$GLOBALS['wpdb'] = new MailWpdbStub();

require_once __DIR__ . '/../src/Config/Field.php';
require_once __DIR__ . '/../src/Config/Registry.php';
require_once __DIR__ . '/../src/Contracts/EncryptorInterface.php';
require_once __DIR__ . '/../src/Support/Logger.php';
require_once __DIR__ . '/../src/Crypto/Format.php';
require_once __DIR__ . '/../src/Crypto/KeyManager.php';
require_once __DIR__ . '/../src/Crypto/LegacyCipher.php';
require_once __DIR__ . '/../src/Crypto/Encryptor.php';
require_once __DIR__ . '/../src/Plugin.php';
require_once __DIR__ . '/../src/User/ColumnStore.php';
require_once __DIR__ . '/../src/Mail/MailHooks.php';

use EncryptedFields\Config\Field;
use EncryptedFields\Config\Registry;
use EncryptedFields\Contracts\EncryptorInterface;
use EncryptedFields\Crypto\Encryptor;
use EncryptedFields\Crypto\KeyManager;
use EncryptedFields\Mail\MailHooks;
use EncryptedFields\Plugin;
use EncryptedFields\Support\Logger;

final class TestEncryptor implements EncryptorInterface
{
    public function encrypt(string $plaintext, Field $field): string
    {
        return 'enc:' . $field->type() . ':' . base64_encode($plaintext);
    }

    public function decrypt(string $value, Field $field): string
    {
        if (!$this->isEncrypted($value)) {
            return $value;
        }

        $parts = explode(':', $value, 3);

        return isset($parts[2]) ? (string) base64_decode($parts[2], true) : $value;
    }

    public function isEncrypted(string $value): bool
    {
        return 0 === strncmp($value, 'enc:', 4);
    }
}

function check($condition, string $message): void
{
    if ($condition) {
        ++$GLOBALS['kec_pass'];
        echo "PASS: {$message}\n";

        return;
    }

    ++$GLOBALS['kec_fail'];
    echo "FAIL: {$message}\n";
}

function set_private(object $object, string $property, $value): void
{
    $reflection = new ReflectionProperty($object, $property);
    $reflection->setAccessible(true);
    $reflection->setValue($object, $value);
}

function make_plugin(?EncryptorInterface $crypto): Plugin
{
    $plugin = new Plugin();
    set_private($plugin, 'registry', new Registry(array()));
    set_private($plugin, 'logger', new Logger());
    set_private($plugin, 'crypto', $crypto);

    return $plugin;
}

function enc_email(EncryptorInterface $crypto, string $email): string
{
    return $crypto->encrypt($email, new Field('user', 'user_email', 'email'));
}

function enc_login(EncryptorInterface $crypto, string $login): string
{
    return $crypto->encrypt($login, new Field('user', 'user_login', 'login'));
}

$realCrypto = null;

if (class_exists(Encryptor::class) && function_exists('openssl_encrypt')) {
    try {
        $realCrypto = new Encryptor(new KeyManager(array('key' => base64_encode(random_bytes(32)))));
    } catch (Throwable $exception) {
        $realCrypto = null;
    }
}

$crypto = $realCrypto instanceof EncryptorInterface ? $realCrypto : new TestEncryptor();
$plugin = make_plugin($crypto);
$hooks = new MailHooks($plugin);
$hooks->register();

echo "== recipient strings ==\n";
$to = enc_email($crypto, 'alice@example.com');
$cc = enc_email($crypto, 'bob@example.com');
$bcc = enc_email($crypto, 'carol@example.com');

$mail = apply_filters('wp_mail', array(
    'to' => $to,
    'cc' => $cc,
    'bcc' => $bcc,
    'subject' => 'Order update',
    'message' => 'Body text',
));

check('alice@example.com' === $mail['to'], 'to string decrypts');
check('bob@example.com' === $mail['cc'], 'cc string decrypts');
check('carol@example.com' === $mail['bcc'], 'bcc string decrypts');
check('Order update' === $mail['subject'], 'subject unchanged when body decryption is off');
check('Body text' === $mail['message'], 'body unchanged when body decryption is off');

echo "\n== comma separated lists ==\n";
$list = enc_email($crypto, 'one@example.com') . ', ' . enc_email($crypto, 'two@example.com');
$mail = apply_filters('wp_mail', array(
    'to' => $list,
    'cc' => enc_login($crypto, 'loginuser'),
));
check('one@example.com, two@example.com' === $mail['to'], 'comma separated recipient list decrypts');
check('loginuser' === $mail['cc'], 'bare login-like recipient decrypts');

echo "\n== Name <email> ==\n";
$mail = apply_filters('wp_mail', array(
    'to' => 'Alice <' . enc_email($crypto, 'alice@example.com') . '>',
    'cc' => '"Doe, John" <' . enc_email($crypto, 'john@example.com') . '>',
));
check('Alice <alice@example.com>' === $mail['to'], 'Name <email> decrypts and keeps formatting');
check('"Doe, John" <john@example.com>' === $mail['cc'], 'quoted display name with comma is not split');

echo "\n== recipient arrays ==\n";
$mail = apply_filters('wp_mail', array(
    'to' => array(
        enc_email($crypto, 'first@example.com'),
        'Plain Person <plain@example.com>',
        enc_login($crypto, 'second'),
    ),
    'cc' => array(enc_email($crypto, 'ccone@example.com'), enc_email($crypto, 'cctwo@example.com')),
    'bcc' => array('Bcc Name <' . enc_email($crypto, 'bcc@example.com') . '>'),
));

check(
    array('first@example.com', 'Plain Person <plain@example.com>', 'second') === array_values($mail['to']),
    'array of addresses decrypts each item'
);
check(
    array('ccone@example.com', 'cctwo@example.com') === array_values($mail['cc']),
    'cc array decrypts each item'
);
check(
    array('Bcc Name <bcc@example.com>') === array_values($mail['bcc']),
    'bcc array with display name decrypts'
);

echo "\n== plaintext unchanged ==\n";
$mail = apply_filters('wp_mail', array(
    'to' => 'Plain <plain@example.com>',
    'cc' => 'plaincc@example.com, another@example.com',
    'bcc' => array('plainbcc@example.com'),
));
check('Plain <plain@example.com>' === $mail['to'], 'plaintext Name <email> unchanged');
check('plaincc@example.com, another@example.com' === $mail['cc'], 'plaintext comma list unchanged');
check(array('plainbcc@example.com') === array_values($mail['bcc']), 'plaintext array unchanged');

echo "\n== token recipients ==\n";
$emailToken = 'k1e' . str_repeat('a', 52);
$loginToken = 'k1t' . str_repeat('b', 52);
$GLOBALS['kec_token_user_map'] = array($emailToken => 42, $loginToken => 43);
$GLOBALS['kec_user_meta'][42] = array('_kec_user_email' => 'token@example.com');
$GLOBALS['kec_user_meta'][43] = array('_kec_user_login' => 'tokenuser');

$mail = apply_filters('wp_mail', array(
    'to' => 'Token User <' . $emailToken . '>',
    'cc' => $loginToken,
    'bcc' => array($emailToken),
));
check('Token User <token@example.com>' === $mail['to'], 'email token resolves from user meta and keeps display name');
check('tokenuser' === $mail['cc'], 'login token resolves from user meta');
check(array('token@example.com') === array_values($mail['bcc']), 'email token inside array resolves');
check(false === strpos($mail['to'], $emailToken), 'no token is sent as recipient');

echo "\n== body decryption opt-in ==\n";
$bodyEmail = 'body@example.com';
$bodyToken = enc_email($crypto, $bodyEmail);

$mail = apply_filters('wp_mail', array(
    'to' => 'plain@example.com',
    'subject' => 'Token ' . $bodyToken,
    'message' => 'Contact ' . $bodyToken . ' for details.',
));
check(false !== strpos($mail['subject'], $bodyToken), 'subject token is left intact by default');
check(false !== strpos($mail['message'], $bodyToken), 'body token is left intact by default');

if (!$realCrypto instanceof Encryptor) {
    echo "SKIP: body-on test requires the real Encryptor and openssl\n";
} else {
    add_filter('kec_mail_decrypt_body', function () {
        return true;
    }, 10, 1);

    $mail = apply_filters('wp_mail', array(
        'to' => 'plain@example.com',
        'subject' => 'Token ' . $bodyToken,
        'message' => 'Contact ' . $bodyToken . ' for details.',
    ));

    check(false === strpos($mail['subject'], $bodyToken), 'subject v2 token is replaced when enabled');
    check(false !== strpos($mail['subject'], $bodyEmail), 'decrypted email appears in subject when enabled');
    check(false === strpos($mail['message'], $bodyToken), 'body v2 token is replaced when enabled');
    check('Contact ' . $bodyEmail . ' for details.' === $mail['message'], 'body text around token is preserved');

    $plainBody = 'Contact someone@example.com and abcdefghijklmnopqrstuvwx for details.';
    $mail = apply_filters('wp_mail', array(
        'to' => 'plain@example.com',
        'subject' => 'No tokens',
        'message' => $plainBody,
    ));
    check($plainBody === $mail['message'], 'plaintext body is not false-positive replaced');
}

echo "\n== crypto unavailable ==\n";
$noCryptoHooks = new MailHooks(make_plugin(null));
$mail = $noCryptoHooks->filterMail(array(
    'to' => $to,
    'cc' => $cc,
    'bcc' => $bcc,
));

check($to === $mail['to'], 'to stays ciphertext without fatal when crypto is unavailable');
check($cc === $mail['cc'], 'cc stays ciphertext without fatal when crypto is unavailable');
check($bcc === $mail['bcc'], 'bcc stays ciphertext without fatal when crypto is unavailable');

echo "\n{$GLOBALS['kec_pass']} passed, {$GLOBALS['kec_fail']} failed\n";
exit($GLOBALS['kec_fail'] > 0 ? 1 : 0);
