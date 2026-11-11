<?php

/**
 * Standalone integration smoke tests (no WordPress / PHPUnit required).
 *
 * Run: php tests/run-integrations.php
 */

$GLOBALS['kec_test_actions'] = array();
$GLOBALS['kec_test_filters'] = array();
$GLOBALS['kec_test_options'] = array();
$GLOBALS['kec_test_user_meta'] = array();
$GLOBALS['kec_test_token_users'] = array();
$GLOBALS['kec_test_customer_rows'] = array();
$GLOBALS['kec_test_customer_updates'] = array();

if (!defined('ARRAY_A')) {
    define('ARRAY_A', 'ARRAY_A');
}

function add_action($tag, $callback, $priority = 10, $accepted_args = 1)
{
    $GLOBALS['kec_test_actions'][$tag][$priority][] = array(
        'callback' => $callback,
        'accepted' => $accepted_args,
    );
}

function add_filter($tag, $callback, $priority = 10, $accepted_args = 1)
{
    $GLOBALS['kec_test_filters'][$tag][$priority][] = array(
        'callback' => $callback,
        'accepted' => $accepted_args,
    );
}

function kec_test_apply_filters($tag, $value, ...$args)
{
    if (empty($GLOBALS['kec_test_filters'][$tag])) {
        return $value;
    }

    $byPriority = $GLOBALS['kec_test_filters'][$tag];
    ksort($byPriority);

    foreach ($byPriority as $callbacks) {
        foreach ($callbacks as $entry) {
            $callArgs = array_merge(array($value), $args);
            if ($entry['accepted'] > 0) {
                $callArgs = array_slice($callArgs, 0, $entry['accepted']);
            }
            $value = call_user_func_array($entry['callback'], $callArgs);
        }
    }

    return $value;
}

function kec_test_has_filter($tag)
{
    return !empty($GLOBALS['kec_test_filters'][$tag]);
}

function kec_test_has_action($tag)
{
    return !empty($GLOBALS['kec_test_actions'][$tag]);
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

function delete_option($name)
{
    unset($GLOBALS['kec_test_options'][$name]);

    return true;
}

function get_user_meta($userId, $key = '', $single = false)
{
    $all = $GLOBALS['kec_test_user_meta'][(int) $userId] ?? array();

    if ($single) {
        return array_key_exists($key, $all) ? $all[$key] : '';
    }

    return $all;
}

final class KecIntegrationWpdb
{
    public string $prefix = 'wp_';
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
        foreach ($GLOBALS['kec_test_token_users'] as $token => $userId) {
            if (false !== strpos($sql, $token)) {
                return $userId;
            }
        }

        return null;
    }

    public function get_row($sql, $format = null)
    {
        if (preg_match('/customer_id\s*=\s*(\d+)/i', $sql, $match)) {
            $id = (int) $match[1];
            return $GLOBALS['kec_test_customer_rows'][$id] ?? null;
        }

        return null;
    }

    public function update($table, $data, $where)
    {
        $GLOBALS['kec_test_customer_updates'][] = array($table, $data, $where);

        return 1;
    }
}

$GLOBALS['wpdb'] = new KecIntegrationWpdb();

function current_user_can($capability)
{
    return true;
}

function current_time($type, $gmt = 0)
{
    return gmdate('Y-m-d H:i:s');
}

function esc_html($text)
{
    return $text;
}

function esc_html__($text, $domain = null)
{
    return $text;
}

function wp_json_encode($value)
{
    return json_encode($value);
}

function get_post_type($post_id)
{
    return 'shop_order';
}

require_once dirname(__DIR__) . '/src/Config/Field.php';
require_once dirname(__DIR__) . '/src/Config/Registry.php';
require_once dirname(__DIR__) . '/src/Contracts/EncryptorInterface.php';
require_once dirname(__DIR__) . '/src/Contracts/SearchInterface.php';
require_once dirname(__DIR__) . '/src/Support/Logger.php';
require_once dirname(__DIR__) . '/src/Plugin.php';
require_once dirname(__DIR__) . '/src/User/ColumnStore.php';
require_once dirname(__DIR__) . '/src/Integrations/WooCommerce/CustomerLookupSchema.php';
require_once dirname(__DIR__) . '/src/Integrations/WooCommerce/Integration.php';
require_once dirname(__DIR__) . '/src/Integrations/SiteGuard/Integration.php';
require_once dirname(__DIR__) . '/src/Integrations/Legacy/Preset.php';

use EncryptedFields\Config\Field;
use EncryptedFields\Config\Registry;
use EncryptedFields\Contracts\EncryptorInterface;
use EncryptedFields\Contracts\SearchInterface;
use EncryptedFields\Integrations\Legacy\Preset;
use EncryptedFields\Integrations\SiteGuard\Integration as SiteGuardIntegration;
use EncryptedFields\Integrations\WooCommerce\Integration as WooIntegration;
use EncryptedFields\Plugin;
use EncryptedFields\Support\Logger;
use EncryptedFields\User\ColumnStore;

final class FakeCrypto implements EncryptorInterface
{
    public function encrypt(string $plaintext, Field $field): string
    {
        return 'enc:' . $plaintext;
    }

    public function decrypt(string $value, Field $field): string
    {
        return 0 === strpos($value, 'enc:') ? substr($value, 4) : $value;
    }

    public function isEncrypted(string $value): bool
    {
        return 0 === strpos($value, 'enc:');
    }
}

final class FakeSearch implements SearchInterface
{
    public function index(string $entity, int $id): void
    {
    }

    public function remove(string $entity, int $id): void
    {
    }

    public function ids(string $entity, string $term, int $limit = 50): array
    {
        return 'post' === $entity ? array(101, 102) : array();
    }

    public function reindex(string $entity = 'all', int $batch = 500, ?callable $progress = null): int
    {
        return 0;
    }
}

function kec_test_reset_hooks(): void
{
    $GLOBALS['kec_test_actions'] = array();
    $GLOBALS['kec_test_filters'] = array();
}

function kec_test_reset_options(): void
{
    $GLOBALS['kec_test_options'] = array();
}

function kec_test_plugin(?Registry $registry = null, $crypto = null, $search = null): Plugin
{
    $plugin = Plugin::instance();
    $reflection = new ReflectionClass(Plugin::class);

    $values = array(
        'registry' => $registry ?: new Registry(array()),
        'crypto' => $crypto,
        'search' => $search,
        'logger' => new Logger(),
        'tableAdapters' => array(),
    );

    foreach ($values as $name => $value) {
        $property = $reflection->getProperty($name);
        $property->setAccessible(true);
        $property->setValue($plugin, $value);
    }

    return $plugin;
}

function kec_test_assert_true($condition, string $message = ''): void
{
    if (!$condition) {
        throw new RuntimeException($message ?: 'Expected true.');
    }
}

function kec_test_assert_same($expected, $actual, string $message = ''): void
{
    if ($expected !== $actual) {
        throw new RuntimeException(
            ($message ?: 'Values differ.') . ' expected=' . var_export($expected, true) . ' actual=' . var_export($actual, true)
        );
    }
}

$GLOBALS['kec_test_passed'] = 0;
$GLOBALS['kec_test_failed'] = 0;

function kec_test_run(string $name, callable $test): void
{
    try {
        $test();
        $GLOBALS['kec_test_passed']++;
        echo "PASS  {$name}\n";
    } catch (Throwable $e) {
        $GLOBALS['kec_test_failed']++;
        echo "FAIL  {$name}\n";
        echo '      ' . $e->getMessage() . "\n";
    }
}

kec_test_run('HPOS detection: option fallback off/on', function () {
    kec_test_reset_options();
    $plugin = kec_test_plugin();
    $integration = new WooIntegration($plugin);

    $GLOBALS['kec_test_options']['woocommerce_custom_orders_table_enabled'] = 'no';
    kec_test_assert_same(false, $integration->isHposEnabled(), 'HPOS should be off.');

    $GLOBALS['kec_test_options']['woocommerce_custom_orders_table_enabled'] = 'yes';
    kec_test_assert_same(true, $integration->isHposEnabled(), 'HPOS should be on.');
});

kec_test_run('HPOS enabled: notice + should_encrypt guard, user fields untouched', function () {
    kec_test_reset_options();
    kec_test_reset_hooks();
    $GLOBALS['kec_test_options']['woocommerce_custom_orders_table_enabled'] = 'yes';

    $plugin = kec_test_plugin();
    $integration = new WooIntegration($plugin);
    $integration->register();

    kec_test_assert_true(kec_test_has_action('admin_notices'), 'Admin notice is not registered.');
    kec_test_assert_true(kec_test_has_filter('kec_should_encrypt'), 'kec_should_encrypt filter is not registered.');

    $blocked = kec_test_apply_filters('kec_should_encrypt', true, 'post', '_billing_email', array('post_type' => 'shop_order'));
    kec_test_assert_same(false, $blocked, 'Post underscore key must be blocked.');

    $blockedOrder = kec_test_apply_filters('kec_should_encrypt', true, 'post', 'billing_email', array('post_type' => 'shop_order'));
    kec_test_assert_same(false, $blockedOrder, 'shop_order post context must be blocked.');

    $user = kec_test_apply_filters('kec_should_encrypt', true, 'user', 'billing_email', array());
    kec_test_assert_same(true, $user, 'User fields must not be blocked by HPOS.');

    $otherPost = kec_test_apply_filters('kec_should_encrypt', true, 'post', 'public_field', array('post_type' => 'post'));
    kec_test_assert_same(true, $otherPost, 'Non-order post fields must not be blocked.');

    $logs = isset($GLOBALS['kec_test_options']['kec_logs']) ? $GLOBALS['kec_test_options']['kec_logs'] : array();
    kec_test_assert_true(is_array($logs) && count($logs) > 0, 'HPOS warning was not logged.');
});

kec_test_run('HPOS off: order search filters use fake search service', function () {
    kec_test_reset_options();
    kec_test_reset_hooks();
    $GLOBALS['kec_test_options']['woocommerce_custom_orders_table_enabled'] = 'no';

    $registry = new Registry(array(
        'post' => array(
            'post_types' => array('shop_order'),
            'meta' => array(
                '_billing_email' => array('type' => 'email'),
                '_billing_first_name' => array('type' => 'text'),
            ),
        ),
    ));

    $plugin = kec_test_plugin($registry, new FakeCrypto(), new FakeSearch());
    $integration = new WooIntegration($plugin);
    $integration->register();

    kec_test_assert_same(false, $integration->isHposEnabled(), 'HPOS should be off.');
    kec_test_assert_true(kec_test_has_filter('woocommerce_shop_order_search_fields'), 'Search fields filter missing.');
    kec_test_assert_true(kec_test_has_filter('woocommerce_shop_order_search_results'), 'Search results filter missing.');

    $fields = kec_test_apply_filters(
        'woocommerce_shop_order_search_fields',
        array('_billing_email', '_billing_first_name', '_billing_address_index', '_order_total')
    );
    kec_test_assert_same(
        array('_billing_address_index', '_order_total'),
        array_values($fields),
        'Encrypted fields must be removed, plaintext fields kept.'
    );

    $results = kec_test_apply_filters('woocommerce_shop_order_search_results', array(10, 11), 'john', array());
    kec_test_assert_same(array(10, 11, 101, 102), array_values($results), 'Search index IDs were not merged.');
});

kec_test_run('Analytics row decrypts customer fields + name idempotently', function () {
    kec_test_reset_options();
    $plugin = kec_test_plugin(new Registry(array(
        'user' => array(
            'columns' => array(
                'user_email' => array('type' => 'email'),
                'user_login' => array('type' => 'login'),
            ),
            'meta' => array(
                'first_name' => array('type' => 'text'),
                'last_name' => array('type' => 'text'),
                'city' => array('type' => 'text'),
            ),
        ),
    )), new FakeCrypto());
    $integration = new WooIntegration($plugin);

    $row = array(
        'first_name' => 'enc:John',
        'last_name' => 'enc:Doe',
        'email' => 'enc:john@example.com',
        'username' => 'enc:john',
        'city' => 'enc:Tokyo',
        'name' => 'enc:John enc:Doe',
    );

    $out = $integration->decryptAnalyticsRow($row);
    kec_test_assert_same('John', $out['first_name']);
    kec_test_assert_same('Doe', $out['last_name']);
    kec_test_assert_same('john@example.com', $out['email']);
    kec_test_assert_same('john', $out['username']);
    kec_test_assert_same('Tokyo', $out['city']);
    kec_test_assert_same('John Doe', $out['name']);

    $plain = $integration->decryptAnalyticsRow(array('first_name' => 'John', 'email' => 'john@example.com'));
    kec_test_assert_same('John', $plain['first_name'], 'Plaintext must stay unchanged.');
    kec_test_assert_same('john@example.com', $plain['email'], 'Plaintext email must stay unchanged.');
});

kec_test_run('Woo customer token email/username resolves with user id', function () {
    kec_test_reset_options();
    $emailToken = 'k1e' . str_repeat('a', 52);
    $loginToken = 'k1t' . str_repeat('b', 52);
    $GLOBALS['kec_test_user_meta'][21] = array(
        '_kec_user_email' => 'john@example.com',
        '_kec_user_login' => 'john',
    );

    $plugin = kec_test_plugin(new Registry(array()), new FakeCrypto());
    $integration = new WooIntegration($plugin);

    $customer = new class($emailToken, $loginToken) {
        public int $id = 21;
        public string $email;
        public string $username;
        public bool $applied = false;

        public function __construct(string $email, string $username)
        {
            $this->email = $email;
            $this->username = $username;
        }

        public function get_id(): int
        {
            return $this->id;
        }

        public function get_email(): string
        {
            return $this->email;
        }

        public function set_email($email): void
        {
            $this->email = (string) $email;
        }

        public function get_username(): string
        {
            return $this->username;
        }

        public function set_username($username): void
        {
            $this->username = (string) $username;
        }

        public function apply_changes(): void
        {
            $this->applied = true;
        }
    };

    $integration->onCustomerLoaded($customer);
    kec_test_assert_same('john@example.com', $customer->email, 'Customer email token should resolve to plaintext.');
    kec_test_assert_same('john', $customer->username, 'Customer username token should resolve to plaintext.');
    kec_test_assert_true($customer->applied, 'Decrypted customer changes should be applied.');
});

kec_test_run('Woo analytics lookup resolves tokens before encrypting lookup row', function () {
    kec_test_reset_options();
    $emailToken = 'k1e' . str_repeat('a', 52);
    $loginToken = 'k1t' . str_repeat('b', 52);
    $GLOBALS['kec_test_user_meta'][21] = array(
        '_kec_user_email' => 'john@example.com',
        '_kec_user_login' => 'john',
    );
    $GLOBALS['kec_test_customer_rows'][21] = array(
        'customer_id' => 21,
        'first_name' => 'John',
        'last_name' => 'Doe',
        'city' => 'Tokyo',
        'email' => $emailToken,
        'username' => $loginToken,
    );
    $GLOBALS['kec_test_customer_updates'] = array();

    $plugin = kec_test_plugin(new Registry(array(
        'user' => array(
            'columns' => array(
                'user_email' => array('type' => 'email'),
                'user_login' => array('type' => 'login'),
            ),
            'meta' => array(
                'first_name' => array('type' => 'text'),
                'last_name' => array('type' => 'text'),
                'city' => array('type' => 'text'),
            ),
        ),
    )), new FakeCrypto());
    $integration = new WooIntegration($plugin);
    $integration->onAnalyticsCustomer(21);

    $update = $GLOBALS['kec_test_customer_updates'][0] ?? array();
    $data = $update[1] ?? array();
    kec_test_assert_same('enc:john@example.com', $data['email'] ?? null, 'Lookup email must be encrypted plaintext, not the token.');
    kec_test_assert_same('enc:john', $data['username'] ?? null, 'Lookup username must be encrypted plaintext, not the token.');
    kec_test_assert_true(false === strpos((string) ($data['email'] ?? ''), $emailToken), 'Token must not be stored in wc_customer_lookup.');

    $row = $integration->decryptAnalyticsRow(array(
        'customer_id' => 21,
        'email' => $emailToken,
        'username' => $loginToken,
    ));
    kec_test_assert_same('john@example.com', $row['email'], 'Analytics email token should resolve.');
    kec_test_assert_same('john', $row['username'], 'Analytics username token should resolve.');
});

kec_test_run('SiteGuard resolves user tokens and token mail recipients', function () {
    kec_test_reset_options();
    $emailToken = 'k1e' . str_repeat('a', 52);
    $loginToken = 'k1t' . str_repeat('b', 52);
    $GLOBALS['kec_test_token_users'] = array($emailToken => 22, $loginToken => 22);
    $GLOBALS['kec_test_user_meta'][22] = array(
        '_kec_user_email' => 'admin@example.com',
        '_kec_user_login' => 'admin',
    );

    $plugin = kec_test_plugin(new Registry(array()), new FakeCrypto());
    $integration = new SiteGuardIntegration($plugin);

    $user = (object) array(
        'ID' => 22,
        'user_email' => $emailToken,
        'user_login' => $loginToken,
        'data' => (object) array('ID' => 22),
    );

    $integration->decryptLoginUser('admin', $user);
    kec_test_assert_same('admin@example.com', $user->user_email, 'User email token should resolve.');
    kec_test_assert_same('admin', $user->user_login, 'User login token should resolve.');

    $mail = $integration->filterMail(array(
        'to' => 'Admin <' . $emailToken . '>',
        'cc' => $loginToken,
    ));
    kec_test_assert_same('Admin <admin@example.com>', $mail['to'], 'Mail token recipient should resolve.');
    kec_test_assert_same('admin', $mail['cc'], 'Mail login token recipient should resolve.');
});

kec_test_run('legacy preset contains expected columns, meta and legacy keys', function () {
    $registry = Preset::registry();

    kec_test_assert_same('login', $registry['user']['columns']['user_login']['type']);
    kec_test_assert_same('email', $registry['user']['columns']['user_email']['type']);
    kec_test_assert_same('email', $registry['user']['meta']['billing_email']['type']);
    kec_test_assert_same('email', $registry['user']['meta']['shipping_email']['type']);
    kec_test_assert_same('email', $registry['post']['meta']['_billing_email']['type']);

    $userKeys = array(
        'first_name', 'last_name',
        'billing_first_name', 'billing_last_name', 'billing_yomigana_first_name',
        'billing_yomigana_last_name', 'billing_company', 'billing_postcode',
        'billing_city', 'billing_address_1', 'billing_address_2', 'billing_phone',
        'billing_email',
        'shipping_first_name', 'shipping_last_name', 'shipping_yomigana_first_name',
        'shipping_yomigana_last_name', 'shipping_company', 'shipping_postcode',
        'shipping_city', 'shipping_address_1', 'shipping_address_2', 'shipping_phone',
        'shipping_email', 'city', 'building_name', 'dateofbirth', 'zipcode', 'phone',
        'billing_first_name_kana', 'billing_last_name_kana',
        'shipping_first_name_kana', 'shipping_last_name_kana',
    );

    foreach ($userKeys as $key) {
        kec_test_assert_true(isset($registry['user']['meta'][$key]), 'Missing user meta: ' . $key);
    }

    $postKeys = array(
        '_billing_first_name', '_billing_last_name', '_billing_yomigana_first_name',
        '_billing_yomigana_last_name', '_billing_company', '_billing_postcode',
        '_billing_city', '_billing_address_1', '_billing_address_2', '_billing_phone',
        '_billing_email',
        '_shipping_first_name', '_shipping_last_name', '_shipping_yomigana_first_name',
        '_shipping_yomigana_last_name', '_shipping_company', '_shipping_postcode',
        '_shipping_city', '_shipping_address_1', '_shipping_address_2', '_shipping_phone',
        '_customer_ip_address', '_customer_user_agent',
        '_billing_address_index', '_shipping_address_index',
    );

    foreach ($postKeys as $key) {
        kec_test_assert_true(isset($registry['post']['meta'][$key]), 'Missing post meta: ' . $key);
    }

    $legacy = Preset::legacyConfig();
    foreach (array('ctr_key', 'login_key', 'email_key', 'email_iv') as $key) {
        kec_test_assert_true(array_key_exists($key, $legacy), 'Missing legacy key: ' . $key);
    }

    $configPreset = require dirname(__DIR__) . '/config/presets/full.php';
    kec_test_assert_same($registry, $configPreset, 'Config preset differs from Preset::registry().');

    $configLegacy = require dirname(__DIR__) . '/config/presets/legacy.php';
    kec_test_assert_same($legacy, $configLegacy, 'Config legacy preset differs from Preset::legacyConfig().');
});

kec_test_run('SiteGuard fallback decrypts user email/login and mail recipients', function () {
    kec_test_reset_options();
    $plugin = kec_test_plugin(new Registry(array()), new FakeCrypto());
    $integration = new SiteGuardIntegration($plugin);

    $user = (object) array(
        'user_email' => 'enc:admin@example.com',
        'user_login' => 'enc:admin',
        'data' => (object) array(),
    );

    $integration->decryptLoginUser('admin', $user);
    kec_test_assert_same('admin@example.com', $user->user_email);
    kec_test_assert_same('admin', $user->user_login);
    kec_test_assert_same('admin@example.com', $user->data->user_email);

    $mail = $integration->filterMail(array(
        'to' => 'Admin <enc:admin@example.com>',
        'cc' => 'enc:cc@example.com',
        'bcc' => 'enc:bcc@example.com',
    ));
    kec_test_assert_same('Admin <admin@example.com>', $mail['to']);
    kec_test_assert_same('cc@example.com', $mail['cc']);
    kec_test_assert_same('bcc@example.com', $mail['bcc']);
});

echo "\n";
echo 'Passed: ' . $GLOBALS['kec_test_passed'] . ', Failed: ' . $GLOBALS['kec_test_failed'] . "\n";

exit($GLOBALS['kec_test_failed'] > 0 ? 1 : 0);
