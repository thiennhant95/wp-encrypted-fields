<?php

/**
 * Standalone tests for late extension hooks, public helpers and runtime
 * table adapters.
 *
 * Run: php tests/run-extensions.php
 */

define('KEC_KEY', 'base64:' . base64_encode(str_repeat('k', 32)));
define('KEC_TOKEN_SECRET', 'base64:' . base64_encode(str_repeat('s', 32)));

spl_autoload_register(function ($class) {
    $prefix = 'EncryptedFields\\';

    if (0 !== strncmp($class, $prefix, strlen($prefix))) {
        return;
    }

    $file = __DIR__ . '/../src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require_once $file;
    }
});

require_once __DIR__ . '/../src/Support/Functions.php';

use EncryptedFields\Config\Field;
use EncryptedFields\Contracts\TableAdapterInterface;
use EncryptedFields\Plugin;

$GLOBALS['kec_ext_filters'] = array();
$GLOBALS['kec_ext_options'] = array();
$GLOBALS['kec_pass'] = 0;
$GLOBALS['kec_fail'] = 0;
$GLOBALS['wpdb'] = new stdClass();

function add_filter($hook, $callback, $priority = 10, $accepted_args = 1)
{
    $GLOBALS['kec_ext_filters'][$hook][(int) $priority][] = array($callback, (int) $accepted_args);

    return true;
}

function add_action($hook, $callback, $priority = 10, $accepted_args = 1)
{
    return add_filter($hook, $callback, $priority, $accepted_args);
}

function apply_filters($hook, $value, ...$args)
{
    if (empty($GLOBALS['kec_ext_filters'][$hook])) {
        return $value;
    }

    $priorities = $GLOBALS['kec_ext_filters'][$hook];
    ksort($priorities);
    $all = array_merge(array($value), $args);

    foreach ($priorities as $callbacks) {
        foreach ($callbacks as $entry) {
            $result = call_user_func_array($entry[0], array_slice($all, 0, $entry[1]));
            $all[0] = $result;
            $value = $result;
        }
    }

    return $value;
}

function do_action($hook, ...$args)
{
    if (empty($GLOBALS['kec_ext_filters'][$hook])) {
        return;
    }

    $priorities = $GLOBALS['kec_ext_filters'][$hook];
    ksort($priorities);

    foreach ($priorities as $callbacks) {
        foreach ($callbacks as $entry) {
            call_user_func_array($entry[0], array_slice($args, 0, $entry[1]));
        }
    }
}

function get_option($name, $default = false)
{
    return array_key_exists($name, $GLOBALS['kec_ext_options'])
        ? $GLOBALS['kec_ext_options'][$name]
        : $default;
}

function update_option($name, $value, $autoload = null)
{
    $GLOBALS['kec_ext_options'][$name] = $value;

    return true;
}

function delete_option($name)
{
    unset($GLOBALS['kec_ext_options'][$name]);

    return true;
}

function check($condition, string $message): void
{
    if ($condition) {
        ++$GLOBALS['kec_pass'];
        echo "ok - {$message}\n";

        return;
    }

    ++$GLOBALS['kec_fail'];
    echo "not ok - {$message}\n";
}

final class ExtensionTestAdapter implements TableAdapterInterface
{
    public array $rows = array();

    public function name(): string
    {
        return 'leads';
    }

    public function table(): string
    {
        return 'acme_leads';
    }

    public function primaryKey(): string
    {
        return 'id';
    }

    public function columns(): array
    {
        return array('email' => 'email', 'name' => 'text');
    }

    public function read(int $id): ?array
    {
        return $this->rows[$id] ?? null;
    }

    public function write(int $id, array $data): bool
    {
        $this->rows[$id] = array_merge($this->rows[$id] ?? array(), $data);

        return true;
    }

    public function searchableColumns(): array
    {
        return array('email');
    }
}

$GLOBALS['kec_ext_adapter'] = new ExtensionTestAdapter();
$GLOBALS['kec_ext_late_adapter'] = new ExtensionTestAdapter();

$GLOBALS['kec_ext_init_lookup'] = array('called' => false, 'table' => 'not-set');

add_filter('kec_field_registry', function ($fields) {
    if (!$GLOBALS['kec_ext_init_lookup']['called']) {
        $GLOBALS['kec_ext_init_lookup']['called'] = true;
        $GLOBALS['kec_ext_init_lookup']['table'] = kec_custom_table('missing-during-init');
    }

    $fields['lead']['meta']['email'] = array('type' => 'email', 'search' => true);

    return $fields;
});

add_filter('kec_table_adapters', function ($adapters) {
    $adapters['leads'] = $GLOBALS['kec_ext_adapter'];

    return $adapters;
});

$plugin = kec_plugin();

check($GLOBALS['kec_ext_init_lookup']['called'], 'registry filter can run during plugin init');
check(null === $GLOBALS['kec_ext_init_lookup']['table'], 'plugin init survives re-entrant table lookup');

echo "== late registration ==\n";
add_filter('kec_field_registry', function ($fields) {
    $fields['lead']['meta']['phone'] = array('type' => 'text');

    return $fields;
}, 20);
add_filter('kec_table_adapters', function ($adapters) {
    $adapters['late'] = $GLOBALS['kec_ext_late_adapter'];

    return $adapters;
}, 20);
add_filter('kec_field_registry', function ($fields) {
    static $entered = false;

    if (!$entered) {
        $entered = true;
        kec_custom_table('missing-during-refresh');
    }

    return $fields;
}, 30);

$callback = $GLOBALS['kec_ext_filters']['after_setup_theme'][99][0][0] ?? null;
check(is_array($callback) && $callback[1] === 'refreshExtensions', 'after_setup_theme refresh hook is registered');

$lazy = kec_custom_table('late');
check(null !== $lazy, 'kec_custom_table resolves a newly filtered adapter before after_setup_theme');

do_action('after_setup_theme');
check(true, 'refresh guard survives re-entrant adapter lookup');
check($plugin->registry()->has('lead', 'phone'), 'registry filter added after plugins_loaded is applied');
check(isset($plugin->tableAdapters()['leads']), 'initial table adapter is available');
check(isset($plugin->tableAdapters()['late']), 'table adapter filter added after plugins_loaded is applied');

echo "\n== public helpers ==\n";
$plain = 'User@Example.com';
$first = kec_encrypt_value($plain, 'lead', 'email');
$second = kec_encrypt_value($plain, 'lead', 'email');
check(kec_is_encrypted($first), 'kec_encrypt_value returns ciphertext');
check(false === strpos($first, $plain), 'ciphertext does not contain plaintext');
check($first === $second, 'registered email field uses deterministic encryption');
check('user@example.com' === kec_decrypt_value($first, 'lead', 'email'), 'kec_decrypt_value returns normalized plaintext');
$unregistered = kec_encrypt_value('secret note', 'unregistered', 'note', array('type' => 'text'));
check(kec_is_encrypted($unregistered), 'unregistered field can be encrypted with explicit options');
check('secret note' === kec_decrypt_value($unregistered, 'unregistered', 'note', array('type' => 'text')), 'unregistered field decrypts with the same options');
check(false === kec_is_encrypted('plain text'), 'kec_is_encrypted rejects plaintext');
check('plain text' === kec_decrypt_value('plain text', 'lead', 'phone'), 'kec_decrypt_value leaves plaintext unchanged');
check('' === kec_encrypt_value('', 'lead', 'phone'), 'empty value is not encrypted');
check(null === kec_encrypt_value(null, 'lead', 'phone'), 'null value is not encrypted');
$numeric = kec_encrypt_value(12345, 'lead', 'phone');
check(kec_is_encrypted($numeric), 'numeric scalar is encrypted as a string');
check('12345' === kec_decrypt_value($numeric, 'lead', 'phone'), 'numeric scalar round-trips as a string');
$threw = false;
try {
    kec_encrypt_value(array('not', 'scalar'), 'lead', 'phone');
} catch (InvalidArgumentException $exception) {
    $threw = true;
}
check($threw, 'kec_encrypt_value rejects arrays');

echo "\n== blind index ==\n";
$indexA = kec_blind_index('User@Example.com', 'lead', 'email');
$indexB = kec_blind_index('user@example.com', 'lead', 'email');
$indexPhone = kec_blind_index('User@Example.com', 'lead', 'phone');
check($indexA === $indexB, 'blind index is case-insensitive');
check($indexA !== $indexPhone, 'blind index is field-bound');
check(64 === strlen($indexA), 'blind index is a 64-char HMAC token');
check('' === kec_blind_index(null, 'lead', 'email'), 'null blind index is empty');
check('' === kec_blind_index('', 'lead', 'email'), 'empty blind index is empty');

echo "\n== runtime table adapter ==\n";
$table = kec_custom_table('leads');
check(null !== $table, 'kec_custom_table resolves a registered adapter');
check(null === kec_custom_table('missing'), 'unknown adapter returns null');
check(array('email', 'name') === $table->encryptedColumns(), 'adapter columns are exposed as encrypted fields');

$table->write(7, array(
    'email' => 'Alice@Example.com',
    'name' => 'Alice',
    'other' => 'keep',
));
$raw = $GLOBALS['kec_ext_adapter']->rows[7];
check(false === strpos((string) $raw['email'], 'Alice'), 'write encrypts declared email column');
check(false === strpos((string) $raw['name'], 'Alice'), 'write encrypts declared text column');
check('keep' === $raw['other'], 'write leaves undeclared columns untouched');

$migrated = $plugin->crypto()->encrypt('Alice@Example.com', new Field('custom', 'email', 'email'));
check($migrated === $raw['email'], 'runtime writes use the same domain as migration');
$table->write(8, array('email' => $migrated));
check($migrated === $GLOBALS['kec_ext_adapter']->rows[8]['email'], 'runtime write does not double-encrypt migration ciphertext');

$single = $table->encryptValue('alice@example.com', 'email');
check(kec_is_encrypted($single), 'encryptValue encrypts a declared column');
check('alice@example.com' === $table->decryptValue($single, 'email'), 'decryptValue decrypts a declared column');
$threw = false;
try {
    $table->encryptRow(array('email' => array('not', 'scalar')));
} catch (InvalidArgumentException $exception) {
    $threw = true;
}
check($threw, 'encryptRow rejects non-scalar declared values');

$decrypted = $table->read(7);
check('alice@example.com' === $decrypted['email'], 'read decrypts email column');
check('Alice' === $decrypted['name'], 'read decrypts text column');
check('keep' === $decrypted['other'], 'read leaves undeclared columns untouched');
check($table->blindIndex('email', 'Alice@Example.com') === kec_blind_index('Alice@Example.com', 'lead', 'email'), 'adapter blind index matches public helper');
$threw = false;
try {
    $table->blindIndex('unknown_column', 'value');
} catch (InvalidArgumentException $exception) {
    $threw = true;
}
check($threw, 'adapter blind index rejects undeclared columns');

echo "\n{$GLOBALS['kec_pass']} passed, {$GLOBALS['kec_fail']} failed\n";
exit($GLOBALS['kec_fail'] > 0 ? 1 : 0);
