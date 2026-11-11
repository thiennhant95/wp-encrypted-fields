<?php

/**
 * Standalone meta hook tests with inline WordPress stubs.
 *
 * Run: php tests/run-meta.php
 */

require_once __DIR__ . '/../src/Contracts/EncryptorInterface.php';
require_once __DIR__ . '/../src/Config/Field.php';
require_once __DIR__ . '/../src/Config/Registry.php';
require_once __DIR__ . '/../src/Support/Logger.php';
require_once __DIR__ . '/../src/Plugin.php';
require_once __DIR__ . '/../src/Meta/MetaCache.php';
require_once __DIR__ . '/../src/Meta/MetaWriteGuard.php';
require_once __DIR__ . '/../src/Meta/MetaHooks.php';

use Koyo\EncryptedFields\Config\Field;
use Koyo\EncryptedFields\Config\Registry;
use Koyo\EncryptedFields\Contracts\EncryptorInterface;
use Koyo\EncryptedFields\Meta\MetaCache;
use Koyo\EncryptedFields\Meta\MetaHooks;
use Koyo\EncryptedFields\Plugin;
use Koyo\EncryptedFields\Support\Logger;

final class TestEncryptor implements EncryptorInterface
{
    public int $encryptCalls = 0;
    public int $decryptCalls = 0;
    public bool $failEncrypt = false;
    public ?string $cipherOverride = null;

    public function encrypt(string $plaintext, Field $field): string
    {
        if ($this->failEncrypt) {
            throw new \RuntimeException('Forced encryption failure.');
        }

        if ($this->isEncrypted($plaintext)) {
            return $plaintext;
        }

        if (null !== $this->cipherOverride) {
            ++$this->encryptCalls;

            return $this->cipherOverride;
        }

        $encoded = 'enc:' . $field->type() . ':' . base64_encode($plaintext);
        $maxLength = $field->maxLength();

        if (null !== $maxLength && strlen($encoded) > $maxLength) {
            throw new \RuntimeException('Ciphertext exceeds max length.');
        }

        ++$this->encryptCalls;

        return $encoded;
    }

    public function decrypt(string $value, Field $field): string
    {
        if (!$this->isEncrypted($value)) {
            return $value;
        }

        ++$this->decryptCalls;
        $parts = explode(':', $value, 3);

        return isset($parts[2]) ? (string) base64_decode($parts[2], true) : '';
    }

    public function isEncrypted(string $value): bool
    {
        return 0 === strncmp($value, 'enc:', 4);
    }
}

final class TestWpdb
{
    public array $queries = array();

    public function prepare($query, ...$args)
    {
        if (1 === count($args) && is_array($args[0])) {
            $args = $args[0];
        }

        $index = 0;

        return preg_replace_callback('/%[ds]/', function ($match) use (&$index, $args) {
            $value = array_key_exists($index, $args) ? $args[$index] : '';
            ++$index;

            if ('%d' === $match[0]) {
                return (string) (int) $value;
            }

            return "'" . esc_sql((string) $value) . "'";
        }, $query);
    }

    public function get_var($query)
    {
        $query = apply_filters('query', $query);
        $this->queries[] = $query;

        if (!preg_match('/SELECT\s+meta_key\s+FROM\s+`?([A-Za-z0-9_$]+)`?\s+WHERE\s+`?(meta_id|umeta_id)`?\s*=\s*(\d+)/i', $query, $matches)) {
            return null;
        }

        $type = table_meta_type($matches[1]);
        $metaId = (int) $matches[3];
        $record = $GLOBALS['kec_test_meta_ids'][$type][$metaId] ?? null;

        return is_array($record) ? $record['key'] : null;
    }
}

$GLOBALS['kec_test_filters'] = array();
$GLOBALS['kec_test_meta'] = array();
$GLOBALS['kec_test_meta_ids'] = array();
$GLOBALS['kec_test_cache'] = array();
$GLOBALS['kec_test_post_types'] = array();
$GLOBALS['kec_test_options'] = array();
$GLOBALS['kec_test_next_id'] = 1;
$GLOBALS['kec_pass'] = 0;
$GLOBALS['kec_fail'] = 0;
$GLOBALS['wpdb'] = new TestWpdb();

function add_filter($hook, $callback, $priority = 10, $accepted_args = 1)
{
    $GLOBALS['kec_test_filters'][$hook][$priority][] = array($callback, (int) $accepted_args);

    return true;
}

function add_action($hook, $callback, $priority = 10, $accepted_args = 1)
{
    return add_filter($hook, $callback, $priority, $accepted_args);
}

function apply_filters($hook, $value, ...$args)
{
    if (empty($GLOBALS['kec_test_filters'][$hook])) {
        return $value;
    }

    $priorities = $GLOBALS['kec_test_filters'][$hook];
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
    if (empty($GLOBALS['kec_test_filters'][$hook])) {
        return;
    }

    $priorities = $GLOBALS['kec_test_filters'][$hook];
    ksort($priorities);

    foreach ($priorities as $callbacks) {
        foreach ($callbacks as $entry) {
            $callback = $entry[0];
            $accepted = $entry[1];
            call_user_func_array($callback, array_slice($args, 0, $accepted));
        }
    }
}

function esc_sql($value)
{
    return addslashes((string) $value);
}

function table_meta_type(string $table)
{
    $table = strtolower($table);

    foreach (array('postmeta' => 'post', 'usermeta' => 'user', 'termmeta' => 'term', 'commentmeta' => 'comment') as $suffix => $type) {
        if ($table === $suffix || substr($table, -strlen($suffix)) === $suffix) {
            return $type;
        }
    }

    return '';
}

function table_for_meta_type(string $type)
{
    $map = array('post' => 'wp_postmeta', 'user' => 'wp_usermeta', 'term' => 'wp_termmeta', 'comment' => 'wp_commentmeta');

    return $map[$type] ?? null;
}

function sql_extract_literal(string $sql): ?string
{
    if (!preg_match('/SET\s+`?meta_value`?\s*=\s*\'((?:[^\'\\\\]|\\\\.|\'\')*)\'/is', $sql, $matches)) {
        return null;
    }

    $literal = str_replace("''", "'", $matches[1]);

    return stripcslashes($literal);
}

function wp_cache_get($key, $group = '', $force = false)
{
    return $GLOBALS['kec_test_cache'][$group][$key] ?? false;
}

function wp_cache_set($key, $value, $group = '', $expire = 0)
{
    $GLOBALS['kec_test_cache'][$group][$key] = $value;

    return true;
}

function wp_cache_delete($key, $group = '')
{
    unset($GLOBALS['kec_test_cache'][$group][$key]);

    return true;
}

function update_meta_cache($meta_type, $object_ids)
{
    $ids = is_array($object_ids) ? $object_ids : array($object_ids);
    $result = array();

    foreach ($ids as $id) {
        $id = (int) $id;
        $existing = wp_cache_get($id, $meta_type . '_meta');

        if (false !== $existing) {
            $result[$id] = $existing;
            continue;
        }

        $data = array();
        foreach (($GLOBALS['kec_test_meta'][$meta_type][$id] ?? array()) as $key => $values) {
            $data[$key] = array_values($values);
        }

        wp_cache_set($id, $data, $meta_type . '_meta');
        $result[$id] = $data;
    }

    return $result;
}

function maybe_unserialize($data)
{
    if (!is_string($data) || '' === $data) {
        return $data;
    }

    if ('b:0;' === $data) {
        return false;
    }

    if (preg_match('/^(a|O|s|i|d|b|N):/', $data)) {
        $unserialized = @unserialize($data);
        if (false !== $unserialized) {
            return $unserialized;
        }
    }

    return $data;
}

function get_post_type($post_id)
{
    return $GLOBALS['kec_test_post_types'][(int) $post_id] ?? false;
}

function get_option($name, $default = false)
{
    return array_key_exists($name, $GLOBALS['kec_test_options'])
        ? $GLOBALS['kec_test_options'][$name]
        : $default;
}

function update_option($name, $value, $autoload = null)
{
    $GLOBALS['kec_test_options'][$name] = $value;

    return true;
}

function wp_json_encode($value)
{
    return json_encode($value);
}

function add_metadata($meta_type, $object_id, $meta_key, $meta_value, $unique = false)
{
    $check = apply_filters("add_{$meta_type}_metadata", null, $object_id, $meta_key, $meta_value, $unique);

    if (null !== $check) {
        return $check;
    }

    $object_id = (int) $object_id;

    if ($unique && !empty($GLOBALS['kec_test_meta'][$meta_type][$object_id][$meta_key])) {
        return false;
    }

    $GLOBALS['kec_test_meta'][$meta_type][$object_id][$meta_key][] = $meta_value;
    $mid = $GLOBALS['kec_test_next_id']++;
    $GLOBALS['kec_test_meta_ids'][$meta_type][$mid] = array('key' => $meta_key, 'object_id' => $object_id);
    wp_cache_delete($object_id, $meta_type . '_meta');

    return $mid;
}

function update_metadata($meta_type, $object_id, $meta_key, $meta_value, $prev_value = '')
{
    $check = apply_filters("update_{$meta_type}_metadata", null, $object_id, $meta_key, $meta_value, $prev_value);

    if (null !== $check) {
        return (bool) $check;
    }

    $object_id = (int) $object_id;

    if (!isset($GLOBALS['kec_test_meta'][$meta_type][$object_id][$meta_key])) {
        return add_metadata($meta_type, $object_id, $meta_key, $meta_value);
    }

    $GLOBALS['kec_test_meta'][$meta_type][$object_id][$meta_key] = array($meta_value);
    wp_cache_delete($object_id, $meta_type . '_meta');

    return true;
}

function update_metadata_by_mid($meta_type, $meta_id, $meta_value, $meta_key = false)
{
    $table = table_for_meta_type($meta_type);
    if (null === $table) {
        return false;
    }

    $idColumn = 'user' === $meta_type ? 'umeta_id' : 'meta_id';
    $sql = 'UPDATE `' . $table . '` SET `meta_value` = \'' . esc_sql((string) $meta_value) . '\''
        . ' WHERE `' . $idColumn . '` = ' . (int) $meta_id;
    $sql = apply_filters('query', $sql);
    $literal = sql_extract_literal($sql);
    $record = $GLOBALS['kec_test_meta_ids'][$meta_type][(int) $meta_id] ?? null;

    if (null === $literal || !is_array($record)) {
        return false;
    }

    $GLOBALS['kec_test_meta'][$meta_type][$record['object_id']][$record['key']] = array($literal);
    wp_cache_delete($record['object_id'], $meta_type . '_meta');

    return true;
}

function get_metadata($meta_type, $object_id, $meta_key = '', $single = false)
{
    $check = apply_filters("get_{$meta_type}_metadata", null, $object_id, $meta_key, $single, $meta_type);

    if (null !== $check) {
        if ($single && is_array($check)) {
            return $check[0] ?? '';
        }

        return $check;
    }

    $cache = wp_cache_get($object_id, $meta_type . '_meta');

    if (false === $cache) {
        $all = update_meta_cache($meta_type, array($object_id));
        $cache = $all[$object_id] ?? array();
    }

    if ('' === $meta_key) {
        return $cache;
    }

    if (isset($cache[$meta_key])) {
        if ($single) {
            return maybe_unserialize($cache[$meta_key][0]);
        }

        return array_map('maybe_unserialize', $cache[$meta_key]);
    }

    return null;
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

function reset_store(): void
{
    $GLOBALS['kec_test_meta'] = array();
    $GLOBALS['kec_test_meta_ids'] = array();
    $GLOBALS['kec_test_cache'] = array();
    $GLOBALS['kec_test_post_types'] = array();
    $GLOBALS['kec_test_options'] = array();
    $GLOBALS['kec_test_next_id'] = 1;
    $GLOBALS['wpdb']->queries = array();
    MetaCache::clear();
}

function seed_meta(string $type, int $id, string $key, array $values): void
{
    $GLOBALS['kec_test_meta'][$type][$id][$key] = $values;
    wp_cache_delete($id, $type . '_meta');
}

function seed_meta_with_id(string $type, int $id, string $key, array $values, int $metaId): void
{
    seed_meta($type, $id, $key, $values);
    $GLOBALS['kec_test_meta_ids'][$type][$metaId] = array('key' => $key, 'object_id' => $id);
}

function stored_value(string $type, int $id, string $key)
{
    return $GLOBALS['kec_test_meta'][$type][$id][$key][0] ?? null;
}

function enc(string $type, string $plaintext): string
{
    return 'enc:' . $type . ':' . base64_encode($plaintext);
}

function set_private(object $object, string $property, $value): void
{
    $reflection = new ReflectionProperty($object, $property);
    $reflection->setAccessible(true);
    $reflection->setValue($object, $value);
}

function use_registry(array $raw, array $readonly = array()): void
{
    set_private($GLOBALS['kec_plugin'], 'registry', new Registry($raw, $readonly));
}

$plugin = new Plugin();
$crypto = new TestEncryptor();

$originalRaw = array(
    'post' => array(
        'post_types' => array('shop_order'),
        'meta' => array(
            '_billing_email' => array('type' => 'email'),
            '_billing_phone' => array('type' => 'text'),
        ),
    ),
    'user' => array(
        'meta' => array(
            'first_name' => array('type' => 'text'),
            'billing_phone' => array('type' => 'text'),
        ),
    ),
    'term' => array(
        'meta' => array(
            'term_secret' => array('type' => 'text'),
        ),
    ),
    'comment' => array(
        'meta' => array(
            'comment_secret' => array('type' => 'text'),
        ),
    ),
);
$originalReadonly = array('user' => array('billing_phone'));

set_private($plugin, 'registry', new Registry($originalRaw, $originalReadonly));
set_private($plugin, 'crypto', $crypto);
set_private($plugin, 'logger', new Logger());

$GLOBALS['kec_plugin'] = $plugin;

$hooks = new MetaHooks($plugin);
$hooks->register();

add_filter('kec_should_encrypt', function ($bool, $entity, $key, $context) {
    if (!empty($GLOBALS['kec_block_first_name']) && 'user' === $entity && 'first_name' === $key) {
        return false;
    }

    return $bool;
}, 10, 4);

echo "== write encrypt ==\n";
reset_store();
use_registry($originalRaw, $originalReadonly);
$GLOBALS['kec_test_post_types'][100] = 'shop_order';
$crypto->encryptCalls = 0;
$result = update_metadata('post', 100, '_billing_email', 'john@example.com');
$stored = stored_value('post', 100, '_billing_email');
check(true === $result, 'update_metadata returns true after encryption');
check(is_string($stored) && str_starts_with($stored, 'enc:email:'), 'write encrypts registered post meta');
check(base64_decode(substr($stored, strlen('enc:email:'))) === 'john@example.com', 'stored ciphertext round-trips');
check(!str_contains($stored, 'john@example.com'), 'stored value contains no plaintext');
check(1 === $crypto->encryptCalls, 'encrypt called exactly once');

echo "\n== read single / multi ==\n";
reset_store();
seed_meta('post', 100, '_billing_email', array(enc('email', 'john@example.com')));
$GLOBALS['kec_test_post_types'][100] = 'shop_order';
$crypto->decryptCalls = 0;
check(get_metadata('post', 100, '_billing_email', true) === 'john@example.com', 'single read decrypts');
check(1 === $crypto->decryptCalls, 'single read decrypts once');
seed_meta('post', 100, '_billing_phone', array(enc('text', '090'), enc('text', '091')));
check(get_metadata('post', 100, '_billing_phone', false) === array('090', '091'), 'multi-value read decrypts all values');

echo "\n== read bulk ==\n";
reset_store();
seed_meta('post', 100, '_billing_email', array(enc('email', 'a@b.c')));
seed_meta('post', 100, '_billing_phone', array(enc('text', '123')));
seed_meta('post', 100, '_not_registered', array('plainvalue'));
$GLOBALS['kec_test_post_types'][100] = 'shop_order';
$bulk = get_metadata('post', 100, '', false);
check(isset($bulk['_billing_email']) && $bulk['_billing_email'] === array('a@b.c'), 'bulk decrypts registered email');
check(isset($bulk['_billing_phone']) && $bulk['_billing_phone'] === array('123'), 'bulk decrypts registered phone');
check(isset($bulk['_not_registered']) && $bulk['_not_registered'] === array('plainvalue'), 'bulk leaves unregistered key untouched');

echo "\n== term / comment / user hooks ==\n";
reset_store();
seed_meta('term', 5, 'term_secret', array(enc('text', 'term')));
seed_meta('comment', 6, 'comment_secret', array(enc('text', 'comment')));
seed_meta('user', 7, 'first_name', array(enc('text', 'Alice')));
check(get_metadata('term', 5, 'term_secret', true) === 'term', 'term meta decrypts');
check(get_metadata('comment', 6, 'comment_secret', true) === 'comment', 'comment meta decrypts');
check(get_metadata('user', 7, 'first_name', true) === 'Alice', 'user meta decrypts');

echo "\n== readonly ==\n";
reset_store();
seed_meta('user', 7, 'billing_phone', array(enc('text', '090')));
check(get_metadata('user', 7, 'billing_phone', true) === '090', 'readonly field still decrypts on read');
update_metadata('user', 7, 'billing_phone', '0987');
check(stored_value('user', 7, 'billing_phone') === '0987', 'readonly field is not encrypted on write');

echo "\n== post type filter ==\n";
reset_store();
$GLOBALS['kec_test_post_types'][200] = 'page';
seed_meta('post', 200, '_billing_email', array(enc('email', 'page@example.com')));
check(
    get_metadata('post', 200, '_billing_email', true) === enc('email', 'page@example.com'),
    'post type mismatch leaves ciphertext on read'
);
update_metadata('post', 200, '_billing_email', 'page@example.com');
check(
    stored_value('post', 200, '_billing_email') === 'page@example.com',
    'post type mismatch skips encryption on write'
);

echo "\n== non-string / empty ==\n";
reset_store();
update_metadata('user', 8, 'first_name', array('x'));
check(
    stored_value('user', 8, 'first_name') === 'enc:text:' . base64_encode(serialize(array('x'))),
    'array value is serialized and encrypted'
);
check(get_metadata('user', 8, 'first_name', true) === array('x'), 'array value decrypts back to an array');
update_metadata('user', 8, 'first_name', '');
check(stored_value('user', 8, 'first_name') === '', 'empty string is not encrypted');
add_metadata('user', 9, 'first_name', 123);
check(stored_value('user', 9, 'first_name') === 123, 'integer value is not encrypted on add');

echo "\n== idempotency / memo ==\n";
reset_store();
$already = enc('text', 'already');
update_metadata('user', 10, 'first_name', $already);
check(stored_value('user', 10, 'first_name') === $already, 'already encrypted value is not double-encrypted');
seed_meta('user', 11, 'first_name', array(enc('text', 'memo')));
$crypto->decryptCalls = 0;
get_metadata('user', 11, 'first_name', true);
get_metadata('user', 11, 'first_name', true);
check(1 === $crypto->decryptCalls, 'memo avoids repeat decryption');
update_metadata('user', 11, 'first_name', 'changed');
check(get_metadata('user', 11, 'first_name', true) === 'changed', 'memo invalidated after write');

echo "\n== recursion guard ==\n";
reset_store();
seed_meta('user', 12, 'first_name', array('plain'));
$crypto->encryptCalls = 0;
update_metadata('user', 12, 'first_name', 'recursion');
$stored = stored_value('user', 12, 'first_name');
$field = $plugin->registry()->get('user', 'first_name');
check(1 === $crypto->encryptCalls, 'encrypt called once despite nested update');
check(is_string($stored) && str_starts_with($stored, 'enc:text:'), 'recursion value is encrypted once');
check($crypto->decrypt($stored, $field) === 'recursion', 'recursion value round-trips');

echo "\n== update_metadata_by_mid query guard ==\n";
reset_store();
use_registry($originalRaw, $originalReadonly);
$GLOBALS['kec_test_post_types'][100] = 'shop_order';
seed_meta_with_id('post', 100, '_billing_email', array('secret@example.com'), 501);
check(update_metadata_by_mid('post', 501, 'secret@example.com') === true, 'update_metadata_by_mid writes through query filter');
$stored = stored_value('post', 100, '_billing_email');
check(is_string($stored) && str_starts_with($stored, 'enc:email:'), 'update_metadata_by_mid stores ciphertext');
check(!str_contains($stored, 'secret@example.com'), 'update_metadata_by_mid stores no plaintext');
check(get_metadata('post', 100, '_billing_email', true) === 'secret@example.com', 'update_metadata_by_mid round-trips');

$already = enc('email', 'already@example.com');
seed_meta_with_id('post', 100, '_billing_email', array($already), 502);
update_metadata_by_mid('post', 502, $already);
check(stored_value('post', 100, '_billing_email') === $already, 'update_metadata_by_mid leaves already encrypted value untouched');

seed_meta_with_id('post', 100, '_not_registered', array('plain'), 503);
$unregisteredSql = 'UPDATE `wp_postmeta` SET `meta_value` = \'plain\' WHERE `meta_id` = 503';
check(apply_filters('query', $unregisteredSql) === $unregisteredSql, 'update_metadata_by_mid leaves non-registry key untouched');
$otherTableSql = 'UPDATE `wp_options` SET `meta_value` = \'plain\' WHERE `meta_id` = 503';
check(apply_filters('query', $otherTableSql) === $otherTableSql, 'query guard ignores non-meta tables');
$otherColumnSql = 'UPDATE `wp_postmeta` SET `meta_key` = \'plain\' WHERE `meta_id` = 503';
check(apply_filters('query', $otherColumnSql) === $otherColumnSql, 'query guard ignores non meta_value columns');

seed_meta_with_id('term', 5, 'term_secret', array('term'), 601);
check(update_metadata_by_mid('term', 601, 'term') === true, 'update_metadata_by_mid handles termmeta');
check(stored_value('term', 5, 'term_secret') === enc('text', 'term'), 'termmeta value is encrypted');
seed_meta_with_id('comment', 6, 'comment_secret', array('comment'), 602);
check(update_metadata_by_mid('comment', 602, 'comment') === true, 'update_metadata_by_mid handles commentmeta');
check(stored_value('comment', 6, 'comment_secret') === enc('text', 'comment'), 'commentmeta value is encrypted');
seed_meta_with_id('user', 7, 'first_name', array('Alice'), 603);
check(update_metadata_by_mid('user', 603, 'Alice') === true, 'update_metadata_by_mid handles usermeta');
check(stored_value('user', 7, 'first_name') === enc('text', 'Alice'), 'usermeta value is encrypted');
seed_meta_with_id('user', 7, 'billing_phone', array('090'), 604);
update_metadata_by_mid('user', 604, '090');
check(stored_value('user', 7, 'billing_phone') === '090', 'readonly usermeta is left untouched by query guard');

seed_meta_with_id('post', 100, '_billing_phone', array('one'), 701);
seed_meta_with_id('post', 100, '_billing_phone', array('two'), 702);
$inSql = 'UPDATE `wp_postmeta` SET `meta_value` = \'shared\' WHERE `meta_id` IN (701, 702)';
$inRewritten = apply_filters('query', $inSql);
check(sql_extract_literal($inRewritten) === enc('text', 'shared'), 'update_metadata_by_mid rewrites meta_id IN lists');

$quoted = "O'Brien \\\\ path";
seed_meta_with_id('post', 100, '_billing_phone', array($quoted), 703);
$quotedSql = 'UPDATE `wp_postmeta` SET `meta_value` = \'' . esc_sql($quoted) . '\' WHERE `meta_id` = 703';
$quotedRewritten = apply_filters('query', $quotedSql);
$quotedLiteral = sql_extract_literal($quotedRewritten);
check($quotedLiteral !== null && $crypto->decrypt($quotedLiteral, $plugin->registry()->get('post', '_billing_phone')) === $quoted, 'query guard decodes quotes and backslashes');
check(!str_contains($quotedRewritten, "O'Brien"), 'quoted plaintext is absent from rewritten SQL');

$crypto->cipherOverride = "enc:text:quote'\\slash";
seed_meta_with_id('post', 100, '_billing_email', array('value'), 704);
$escapeSql = 'UPDATE `wp_postmeta` SET `meta_value` = \'value\' WHERE `meta_id` = 704';
$escapeRewritten = apply_filters('query', $escapeSql);
check(sql_extract_literal($escapeRewritten) === $crypto->cipherOverride, 'query guard escapes quotes and backslashes in ciphertext');
$crypto->cipherOverride = null;

$crypto->failEncrypt = true;
seed_meta_with_id('post', 100, '_billing_email', array('keep@example.com'), 705);
$failureSql = 'UPDATE `wp_postmeta` SET `meta_value` = \'keep@example.com\' WHERE `meta_id` = 705';
check(apply_filters('query', $failureSql) === $failureSql, 'query guard leaves SQL unchanged when encryption fails');
$logs = get_option('kec_logs', array());
check(is_array($logs) && count($logs) > 0, 'query guard logs encryption failures');
check(!str_contains(json_encode($logs), 'keep@example.com'), 'query guard failure log contains no plaintext');
$crypto->failEncrypt = false;

echo "\n== fail closed: max length ==\n";
$originalRegistry = $plugin->registry();
reset_store();
use_registry(array(
    'user' => array(
        'meta' => array(
            'short' => array('type' => 'text', 'max_length' => 5),
        ),
    ),
));
$GLOBALS['kec_test_meta']['user'][13]['short'] = array('x');
wp_cache_delete(13, 'user_meta');
$result = update_metadata('user', 13, 'short', 'longvalue');
check(false === $result, 'maxLength exception makes update_metadata return false');
check(stored_value('user', 13, 'short') === 'x', 'maxLength exception does not overwrite existing value');
$addResult = add_metadata('user', 15, 'short', 'longvalue');
check(false === $addResult, 'maxLength exception makes add_metadata return false');
check(stored_value('user', 15, 'short') === null, 'maxLength exception does not write new plaintext');
$logs = get_option('kec_logs', array());
check(is_array($logs) && count($logs) > 0, 'maxLength exception is logged');
check(!str_contains(json_encode($logs), 'longvalue'), 'maxLength failure log contains no plaintext');
set_private($plugin, 'registry', $originalRegistry);

echo "\n== fail closed: encryption failure ==\n";
reset_store();
use_registry($originalRaw, $originalReadonly);
$GLOBALS['kec_test_post_types'][100] = 'shop_order';
$crypto->failEncrypt = true;
$updateResult = update_metadata('post', 100, '_billing_email', 'secret@example.com');
check(false === $updateResult, 'encryption failure makes update_metadata return false');
check(stored_value('post', 100, '_billing_email') === null, 'encryption failure does not write plaintext on update');
$addResult = add_metadata('post', 100, '_billing_email', 'secret@example.com');
check(false === $addResult, 'encryption failure makes add_metadata return false');
check(stored_value('post', 100, '_billing_email') === null, 'encryption failure does not write plaintext on add');
$logs = get_option('kec_logs', array());
check(is_array($logs) && count($logs) > 0, 'encryption failure is logged as a warning');
check(!str_contains(json_encode($logs), 'secret@example.com'), 'encryption failure log contains no plaintext');
$crypto->failEncrypt = false;

echo "\n== kec_should_encrypt filter ==\n";
reset_store();
$GLOBALS['kec_block_first_name'] = true;
update_metadata('user', 14, 'first_name', 'blocked');
check(stored_value('user', 14, 'first_name') === 'blocked', 'kec_should_encrypt false skips encryption');
$GLOBALS['kec_block_first_name'] = false;

echo "\n{$GLOBALS['kec_pass']} passed, {$GLOBALS['kec_fail']} failed\n";
exit($GLOBALS['kec_fail'] > 0 ? 1 : 0);
