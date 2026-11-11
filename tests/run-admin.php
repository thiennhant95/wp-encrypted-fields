<?php
/**
 * Standalone tests for admin/migration logic (no WordPress install required).
 */

namespace {
    define('ABSPATH', __DIR__ . '/');

    $GLOBALS['kec_options'] = array();
    $GLOBALS['kec_actions'] = array();
    $GLOBALS['kec_filters'] = array();
    $GLOBALS['kec_usermeta'] = array();

    function get_option($name, $default = false)
    {
        return array_key_exists($name, $GLOBALS['kec_options']) ? $GLOBALS['kec_options'][$name] : $default;
    }

    function update_option($name, $value, $autoload = null)
    {
        $GLOBALS['kec_options'][$name] = $value;
        return true;
    }

    function delete_option($name)
    {
        unset($GLOBALS['kec_options'][$name]);
        return true;
    }

    function add_action($hook, $callback, $priority = 10, $accepted = 1)
    {
        $GLOBALS['kec_actions'][$hook][] = $callback;
    }

    function add_filter($hook, $callback, $priority = 10, $accepted = 3)
    {
        $GLOBALS['kec_filters'][$hook][] = $callback;
    }

    function apply_filters($hook, $value)
    {
        return $value;
    }

    function current_user_can($capability)
    {
        return true;
    }

    function current_user_id()
    {
        return 1;
    }

    function get_current_user_id()
    {
        return 1;
    }

    function wp_die($message)
    {
        throw new \RuntimeException('wp_die: ' . $message);
    }

    function check_admin_referer($action, $field = '_wpnonce')
    {
        return true;
    }

    function current_time($type, $gmt = 0)
    {
        return gmdate('Y-m-d H:i:s');
    }

    function wp_json_encode($value)
    {
        return json_encode($value);
    }

    function esc_sql($value)
    {
        return str_replace(array('\\', "'"), array('\\\\', "\\'"), (string) $value);
    }

    function is_multisite()
    {
        return false;
    }

    function get_user_meta($userId, $key = '', $single = false)
    {
        $all = $GLOBALS['kec_usermeta'][(int) $userId] ?? array();

        if ($single) {
            return array_key_exists($key, $all) ? $all[$key] : '';
        }

        return $all;
    }

    function update_user_meta($userId, $key, $value, $prevValue = null)
    {
        $GLOBALS['kec_usermeta'][(int) $userId][$key] = $value;
        return true;
    }

    spl_autoload_register(function ($class) {
        $prefix = 'Koyo\\EncryptedFields\\';
        if (0 !== strncmp($class, $prefix, strlen($prefix))) {
            return;
        }
        $relative = substr($class, strlen($prefix));
        $file = __DIR__ . '/../src/' . str_replace('\\', '/', $relative) . '.php';
        if (is_file($file)) {
            require $file;
        }
    });

    require_once __DIR__ . '/../src/Contracts/EncryptorInterface.php';
    require_once __DIR__ . '/../src/Contracts/SearchInterface.php';
    require_once __DIR__ . '/../src/Contracts/TableAdapterInterface.php';
}

namespace Koyo\EncryptedFields\Crypto {
    use Koyo\EncryptedFields\Config\Field;
    use Koyo\EncryptedFields\Contracts\EncryptorInterface;

    final class KeyManager
    {
        public function isConfigured(): bool
        {
            return true;
        }

        public function isRotationPending(): bool
        {
            return !empty($GLOBALS['kec_rotation_pending']);
        }

        public function keyId(): string
        {
            return 'testkey01';
        }

        public function currentKeyId(): string
        {
            return 'testkey01';
        }

        public function keyFor(string $keyId): ?string
        {
            return 'testkey01' === $keyId ? str_repeat('k', 32) : null;
        }

        public function source(): string
        {
            return 'wp-config:KEC_KEY';
        }

        public function generate(): string
        {
            return 'generated-test-key';
        }

        public function tokenSecret(): string
        {
            return isset($GLOBALS['kec_token_secret']) ? (string) $GLOBALS['kec_token_secret'] : 'test-token-secret';
        }

        public function tokenSecretIsStable(): bool
        {
            return !empty($GLOBALS['kec_token_secret_stable']);
        }
    }

    final class Encryptor implements EncryptorInterface
    {
        public function __construct(KeyManager $keys)
        {
        }

        public function encrypt(string $plaintext, Field $field): string
        {
            return 'enc:v2:det:testkey01:' . base64_encode($plaintext);
        }

        public function decrypt(string $value, Field $field): string
        {
            if (0 === strpos($value, 'enc:v2:')) {
                $parts = explode(':', $value);
                $payload = end($parts);
                $decoded = base64_decode($payload, true);
                return false === $decoded ? '' : $decoded;
            }

            if (0 === strpos($value, 'LEG:')) {
                return substr($value, 4);
            }

            return $value;
        }

        public function isEncrypted(string $value): bool
        {
            return 0 === strpos($value, 'enc:v2:') || 0 === strpos($value, 'LEG:');
        }
    }
}

namespace {
    final class KecWpdbStub
    {
        public $users = 'wp_users';
        public $usermeta = 'wp_usermeta';
        public $postmeta = 'wp_postmeta';
        public $termmeta = 'wp_termmeta';
        public $commentmeta = 'wp_commentmeta';
        public $posts = 'wp_posts';
        public $prefix = 'wp_';
        public $last_error = '';
        public $writes = 0;
        public $fixtures = array();
        public $updates = array();

        public function setFixtures(array $fixtures): void
        {
            $this->fixtures = $fixtures;
            $this->writes = 0;
        }

        public function get_results($sql)
        {
            $rows = $this->matchingRows($sql);
            $limit = $this->limit($sql);
            if ($limit > 0) {
                $rows = array_slice($rows, 0, $limit);
            }

            $valueCol = $this->valueColumn($sql);
            $idCol = $this->aliasedColumn($sql, 'row_id', 'ID');
            $entityCol = $this->aliasedColumn($sql, 'entity_id', $idCol);

            $result = array();
            foreach ($rows as $row) {
                $value = isset($row[$valueCol]) ? (string) $row[$valueCol] : '';
                if (preg_match("/value_col_never|<> ''/", $sql) && '' === $value) {
                    continue;
                }
                $object = new \stdClass();
                $object->row_id = isset($row[$idCol]) ? $row[$idCol] : 0;
                $object->entity_id = isset($row[$entityCol]) ? $row[$entityCol] : $object->row_id;
                $object->value = $value;
                $result[] = $object;
            }

            return $result;
        }

        public function get_var($sql)
        {
            if (false === stripos($sql, 'COUNT(*)')) {
                return null;
            }

            $rows = $this->matchingRows($sql);
            $valueCol = $this->valueColumn($sql);
            $count = 0;
            foreach ($rows as $row) {
                if (isset($row[$valueCol]) && '' !== (string) $row[$valueCol]) {
                    $count++;
                }
            }

            return $count;
        }

        public function update($table, array $data, array $where)
        {
            $this->writes++;
            $this->updates[] = array($table, $data, $where);

            if (isset($this->fixtures[$table]) && is_array($this->fixtures[$table])) {
                foreach ($this->fixtures[$table] as $index => $row) {
                    $matches = true;
                    foreach ($where as $key => $value) {
                        if (!isset($row[$key]) || (string) $row[$key] !== (string) $value) {
                            $matches = false;
                            break;
                        }
                    }

                    if ($matches) {
                        $this->fixtures[$table][$index] = array_merge($row, $data);
                    }
                }
            }

            return 1;
        }

        public function prefix()
        {
            return $this->prefix;
        }

        private function tableFrom(string $sql): string
        {
            if (preg_match('/FROM\s+([A-Za-z0-9_]+)/i', $sql, $match)) {
                return $match[1];
            }
            return '';
        }

        private function valueColumn(string $sql): string
        {
            if (preg_match('/,\s*`?([A-Za-z0-9_]+)`?\s+AS\s+value/i', $sql, $match)) {
                return $match[1];
            }
            return 'value';
        }

        private function aliasedColumn(string $sql, string $alias, string $fallback): string
        {
            if (preg_match('/`?([A-Za-z0-9_]+)`?\s+AS\s+' . preg_quote($alias, '/') . '/i', $sql, $match)) {
                return $match[1];
            }
            return $fallback;
        }

        private function limit(string $sql): int
        {
            if (preg_match('/LIMIT\s+(\d+)/i', $sql, $match)) {
                return (int) $match[1];
            }
            return 0;
        }

        private function matchingRows(string $sql): array
        {
            $table = $this->tableFrom($sql);
            $rows = isset($this->fixtures[$table]) && is_array($this->fixtures[$table]) ? $this->fixtures[$table] : array();
            $valueCol = $this->valueColumn($sql);

            if (preg_match("/meta_key\s*=\s*'([^']+)'/i", $sql, $match)) {
                $key = $match[1];
                $rows = array_values(array_filter($rows, function ($row) use ($key) {
                    return isset($row['meta_key']) && (string) $row['meta_key'] === $key;
                }));
            }

            if (preg_match("/LIKE\s+'enc:v2%/i", $sql)) {
                $rows = array_values(array_filter($rows, function ($row) use ($valueCol) {
                    return isset($row[$valueCol]) && 0 === strpos((string) $row[$valueCol], 'enc:v2');
                }));
            }

            if (preg_match('/`?([A-Za-z0-9_]+)`?\s*>\s*(\d+)/', $sql, $match)) {
                $cursorCol = $match[1];
                $cursor = (int) $match[2];
                if (in_array($cursorCol, array('ID', 'meta_id', 'umeta_id', 'id', 'customer_id'), true)) {
                    $rows = array_values(array_filter($rows, function ($row) use ($cursorCol, $cursor) {
                        return isset($row[$cursorCol]) && (int) $row[$cursorCol] > $cursor;
                    }));
                }
            }

            return $rows;
        }
    }

    function kec_make_plugin(): \Koyo\EncryptedFields\Plugin
    {
        $plugin = new \Koyo\EncryptedFields\Plugin();
        $plugin->init();
        return $plugin;
    }

    function kec_reset(string $registry = ''): KecWpdbStub
    {
        $GLOBALS['kec_options'] = array();
        $GLOBALS['kec_usermeta'] = array();
        $GLOBALS['kec_rotation_pending'] = false;
        $GLOBALS['kec_token_secret'] = 'test-token-secret';
        $GLOBALS['kec_token_secret_stable'] = false;
        unset($GLOBALS['kec_options']['kec_backup_ack']);
        if ('' !== $registry) {
            $GLOBALS['kec_options']['kec_field_registry'] = json_decode($registry, true);
        }
        $db = new KecWpdbStub();
        $GLOBALS['wpdb'] = $db;
        return $db;
    }

    $tests = array();
    $failures = 0;

    function test(string $name, callable $callback): void
    {
        global $tests;
        $tests[] = array($name, $callback);
    }

    function assert_true($condition, string $message): void
    {
        if (!$condition) {
            throw new \RuntimeException($message);
        }
    }

    function assert_same($expected, $actual, string $message): void
    {
        if ($expected !== $actual) {
            throw new \RuntimeException($message . ' (expected ' . var_export($expected, true) . ', got ' . var_export($actual, true) . ')');
        }
    }

    $registryJson = json_encode(array(
        'user' => array(
            'columns' => array(
                'user_login' => array('type' => 'login', 'max_length' => 60),
                'user_email' => array('type' => 'email', 'max_length' => 100),
            ),
            'meta' => array(
                'billing_phone' => array('type' => 'text', 'search' => true),
            ),
        ),
        'post' => array(
            'post_types' => array('shop_order'),
            'meta' => array(
                '_billing_email' => array('type' => 'email', 'search' => true),
            ),
        ),
    ));

    test('StateDetector reports existing_plaintext', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $db->setFixtures(array(
            'wp_users' => array(
                array('ID' => 1, 'user_login' => 'alice', 'user_email' => 'alice@example.com'),
            ),
            'wp_usermeta' => array(
                array('umeta_id' => 1, 'user_id' => 1, 'meta_key' => 'billing_phone', 'meta_value' => '0901234567'),
            ),
            'wp_postmeta' => array(),
        ));
        $plugin = kec_make_plugin();
        $state = (new \Koyo\EncryptedFields\Migration\StateDetector($plugin, $db))->detect();
        assert_same('existing_plaintext', $state['state'], 'state should be existing_plaintext');
        assert_true($state['counts']['plaintext'] >= 2, 'plaintext samples should be counted');
        assert_true($state['key_configured'], 'key should be configured');
    });

    test('StateDetector reports existing_legacy and mixed', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $db->setFixtures(array(
            'wp_users' => array(
                array('ID' => 1, 'user_login' => 'LEG:alice', 'user_email' => 'LEG:alice@example.com'),
            ),
            'wp_usermeta' => array(),
            'wp_postmeta' => array(),
        ));
        $plugin = kec_make_plugin();
        $state = (new \Koyo\EncryptedFields\Migration\StateDetector($plugin, $db))->detect();
        assert_same('existing_legacy', $state['state'], 'state should be existing_legacy');
        assert_true($state['counts']['legacy'] >= 2, 'legacy samples should be counted');

        $db = kec_reset($registryJson);
        $db->setFixtures(array(
            'wp_users' => array(
                array('ID' => 1, 'user_login' => 'alice', 'user_email' => 'LEG:alice@example.com'),
            ),
            'wp_usermeta' => array(),
            'wp_postmeta' => array(),
        ));
        $plugin = kec_make_plugin();
        $state = (new \Koyo\EncryptedFields\Migration\StateDetector($plugin, $db))->detect();
        assert_same('mixed', $state['state'], 'state should be mixed');
    });

    test('StateDetector reports configured and fresh', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $db->setFixtures(array(
            'wp_users' => array(
                array('ID' => 1, 'user_login' => 'enc:v2:det:testkey01:' . base64_encode('alice'), 'user_email' => 'enc:v2:det:testkey01:' . base64_encode('alice@example.com')),
            ),
            'wp_usermeta' => array(),
            'wp_postmeta' => array(),
        ));
        $plugin = kec_make_plugin();
        $state = (new \Koyo\EncryptedFields\Migration\StateDetector($plugin, $db))->detect();
        assert_same('configured', $state['state'], 'state should be configured');

        $db = kec_reset('');
        $db->setFixtures(array('wp_users' => array()));
        $plugin = kec_make_plugin();
        $state = (new \Koyo\EncryptedFields\Migration\StateDetector($plugin, $db))->detect();
        assert_same('fresh', $state['state'], 'state should be fresh');
    });

    test('StateDetector detects HPOS and legacy without registry', function () {
        $db = kec_reset('');
        $GLOBALS['kec_options']['woocommerce_custom_orders_table_enabled'] = 'yes';
        $db->setFixtures(array(
            'wp_users' => array(
                array('ID' => 1, 'user_login' => 'LEG:alice', 'user_email' => 'alice@example.com'),
            ),
        ));
        $plugin = kec_make_plugin();
        $state = (new \Koyo\EncryptedFields\Migration\StateDetector($plugin, $db))->detect();
        assert_true($state['hpos'], 'HPOS should be detected');
        assert_same('existing_legacy', $state['state'], 'fallback scan should detect legacy data without treating plaintext as configured PII');
    });

    test('StateDetector warns about known plaintext logging/CRM plugins', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $GLOBALS['kec_options']['active_plugins'] = array(
            'wp-mail-logging/wp-mail-logging.php',
            'mailpoet/mailpoet.php',
        );
        $db->setFixtures(array(
            'wp_users' => array(),
            'wp_usermeta' => array(),
            'wp_postmeta' => array(),
        ));
        $plugin = kec_make_plugin();
        $state = (new \Koyo\EncryptedFields\Migration\StateDetector($plugin, $db))->detect();
        $codes = array_column($state['warnings'], 'code');
        assert_true(in_array('plaintext_plugin', $codes, true), 'plaintext plugin warning should be present');
        $plugins = array_column($state['warnings'], 'plugin');
        assert_true(in_array('wp-mail-logging', $plugins, true), 'WP Mail Logging warning should be present');
    });

    test('Migrator dry run builds a plan without plaintext values', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $longEmail = str_repeat('long', 30) . '@example.com';
        $db->setFixtures(array(
            'wp_users' => array(
                array('ID' => 1, 'user_login' => 'alice', 'user_email' => $longEmail),
                array('ID' => 2, 'user_login' => 'LEG:bob', 'user_email' => 'bob@example.com'),
            ),
            'wp_usermeta' => array(
                array('umeta_id' => 10, 'user_id' => 1, 'meta_key' => 'billing_phone', 'meta_value' => '0901234567'),
            ),
            'wp_postmeta' => array(
                array('meta_id' => 20, 'post_id' => 99, 'meta_key' => '_billing_email', 'meta_value' => 'order@example.com'),
            ),
        ));
        $plugin = kec_make_plugin();
        $result = (new \Koyo\EncryptedFields\Migration\Migrator($plugin, $db))->dryRun();
        assert_same('dry_run', $result['mode'], 'mode should be dry_run');
        assert_true($result['totals']['plaintext'] >= 2, 'plaintext should be detected');
        assert_true($result['totals']['legacy'] >= 1, 'legacy should be detected');
        assert_true($result['pending'] >= 3, 'pending count should include plaintext and legacy');
        assert_true($result['requires_backup'], 'backup should be required without ack');
        assert_true(count($result['fields']) >= 3, 'plan should include fields');
        $json = json_encode($result);
        assert_true(false === strpos($json, 'alice@example.com'), 'dry run must not expose plaintext email');
        assert_true(false === strpos($json, '0901234567'), 'dry run must not expose plaintext phone');
        assert_true(false === strpos($json, 'order@example.com'), 'dry run must not expose post meta plaintext');
        $risks = array_filter($result['warnings'], function ($warning) {
            return isset($warning['code']) && 'length_risk' === $warning['code'];
        });
        assert_same(0, count($risks), 'token mode must not report a cipher length risk for user columns');
    });

    test('Migrator hard blocks migration without backup acknowledgement', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $db->setFixtures(array(
            'wp_users' => array(
                array('ID' => 1, 'user_login' => 'alice', 'user_email' => 'alice@example.com'),
            ),
            'wp_usermeta' => array(),
            'wp_postmeta' => array(),
        ));
        $plugin = kec_make_plugin();
        $result = (new \Koyo\EncryptedFields\Migration\Migrator($plugin, $db))->migrate();
        assert_same(false, $result['ok'], 'migration should fail');
        assert_same('backup_required', $result['error'], 'error should be backup_required');
        assert_same(0, $db->writes, 'no writes should happen before backup ack');
    });

    test('Migrator accepts backup ack and migrates rows', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $GLOBALS['kec_options']['kec_backup_ack'] = array(
            'timestamp' => time(),
            'user_id' => 1,
            'reference' => 'test-backup',
        );
        $db->setFixtures(array(
            'wp_users' => array(
                array('ID' => 1, 'user_login' => 'alice', 'user_email' => 'alice@example.com'),
                array('ID' => 2, 'user_login' => 'LEG:bob', 'user_email' => 'bob@example.com'),
            ),
            'wp_usermeta' => array(
                array('umeta_id' => 10, 'user_id' => 1, 'meta_key' => 'billing_phone', 'meta_value' => '0901234567'),
            ),
            'wp_postmeta' => array(),
        ));
        $plugin = kec_make_plugin();
        $migrator = new \Koyo\EncryptedFields\Migration\Migrator($plugin, $db);
        assert_true($migrator->backupSatisfied(), 'backup ack should satisfy gate');
        $result = $migrator->migrate(array('batch' => 2));
        assert_same(true, $result['ok'], 'migration should succeed');
        assert_true($result['migrated'] >= 4, 'all rows should be migrated');
        assert_true($db->writes >= 4, 'rows should be written');
        assert_same(array(), $result['errors'], 'no errors expected');
    });

    test('Migrator tokenizes long user columns and stores plaintext meta', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $GLOBALS['kec_options']['kec_backup_ack'] = array(
            'timestamp' => time(),
            'user_id' => 1,
            'reference' => 'test-backup',
        );
        $longLogin = str_repeat('L', 58);
        $longEmail = str_repeat('E', 80) . '@example.com';
        $db->setFixtures(array(
            'wp_users' => array(
                array('ID' => 1, 'user_login' => $longLogin, 'user_email' => $longEmail),
            ),
            'wp_usermeta' => array(),
            'wp_postmeta' => array(),
        ));
        $plugin = kec_make_plugin();
        $columns = new \Koyo\EncryptedFields\User\ColumnStore($plugin);
        $result = (new \Koyo\EncryptedFields\Migration\Migrator($plugin, $db))->migrate(array('batch' => 10));
        assert_same(true, $result['ok'], 'migration should succeed');
        assert_same(array(), $result['errors'], 'no errors expected');

        $written = array();
        foreach ($db->updates as $update) {
            if ('wp_users' === $update[0] && isset($update[1]['user_login'])) {
                $written['login'] = (string) $update[1]['user_login'];
            }
            if ('wp_users' === $update[0] && isset($update[1]['user_email'])) {
                $written['email'] = (string) $update[1]['user_email'];
            }
        }

        assert_true(isset($written['login']) && $columns->isToken($written['login'], \Koyo\EncryptedFields\User\ColumnStore::LOGIN), 'login column should hold a token');
        assert_true(isset($written['email']) && $columns->isToken($written['email'], \Koyo\EncryptedFields\User\ColumnStore::EMAIL), 'email column should hold a token');
        assert_true(strlen($written['login']) <= 60, 'login token must fit varchar(60)');
        assert_true(strlen($written['email']) <= 100, 'email token must fit varchar(100)');
        assert_same(strtolower($longLogin), $GLOBALS['kec_usermeta'][1]['_kec_user_login'] ?? null, 'login plaintext meta should be normalized');
        assert_same(strtolower($longEmail), $GLOBALS['kec_usermeta'][1]['_kec_user_email'] ?? null, 'email plaintext meta should be normalized');
    });

    test('Migrator rotates v2 rows only after backup ack', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $db->setFixtures(array(
            'wp_users' => array(
                array('ID' => 1, 'user_login' => 'enc:v2:det:testkey01:' . base64_encode('alice'), 'user_email' => 'enc:v2:det:testkey01:' . base64_encode('alice@example.com')),
            ),
            'wp_usermeta' => array(),
            'wp_postmeta' => array(),
        ));
        $plugin = kec_make_plugin();
        $migrator = new \Koyo\EncryptedFields\Migration\Migrator($plugin, $db);
        $blocked = $migrator->rotate();
        assert_same('backup_required', $blocked['error'], 'rotation should require backup ack');

        $GLOBALS['kec_options']['kec_backup_ack'] = array('timestamp' => time(), 'user_id' => 1, 'reference' => 'test');
        $result = $migrator->rotate(array('batch' => 10));
        assert_same(true, $result['ok'], 'rotation should succeed');
        assert_true($result['rotated'] >= 2, 'v2 rows should be re-encrypted');
        assert_true($db->writes >= 2, 'rotated rows should be written');
    });

    test('Migrator verifies tokenized user columns and meta', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $plugin = kec_make_plugin();
        $columns = new \Koyo\EncryptedFields\User\ColumnStore($plugin);
        $loginToken = $columns->tokenFor('alice', \Koyo\EncryptedFields\User\ColumnStore::LOGIN);
        $emailToken = $columns->tokenFor('alice@example.com', \Koyo\EncryptedFields\User\ColumnStore::EMAIL);

        $db->setFixtures(array(
            'wp_users' => array(
                array('ID' => 1, 'user_login' => $loginToken, 'user_email' => $emailToken),
            ),
            'wp_usermeta' => array(
                array('umeta_id' => 12, 'user_id' => 1, 'meta_key' => 'billing_phone', 'meta_value' => 'enc:v2:det:testkey01:' . base64_encode('0901234567')),
            ),
            'wp_postmeta' => array(),
        ));
        $GLOBALS['kec_usermeta'][1] = array(
            '_kec_user_login' => 'alice',
            '_kec_user_email' => 'alice@example.com',
        );

        $result = (new \Koyo\EncryptedFields\Migration\Migrator($plugin, $db))->verify();
        assert_same(true, $result['ok'], 'verification should pass');
        assert_same(2, $result['token'], 'both user columns should be counted as tokens');
        assert_true($result['decrypt_ok'] >= 2, 'token meta should resolve to plaintext');
        assert_same(0, $result['plaintext'], 'no plaintext should remain');
        assert_same(0, $result['legacy'], 'no legacy should remain');
    });

    test('Migrator verify rejects plaintext user columns', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $db->setFixtures(array(
            'wp_users' => array(
                array('ID' => 1, 'user_login' => 'alice', 'user_email' => 'alice@example.com'),
            ),
            'wp_usermeta' => array(),
            'wp_postmeta' => array(),
        ));
        $plugin = kec_make_plugin();
        $result = (new \Koyo\EncryptedFields\Migration\Migrator($plugin, $db))->verify();
        assert_same(false, $result['ok'], 'plaintext user columns must fail verification');
        assert_true($result['plaintext'] >= 2, 'plaintext columns should be reported');
    });

    test('LookupMigrator encrypts wc_customer_lookup with dry run and backup gate', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $db->setFixtures(array(
            'wp_wc_customer_lookup' => array(
                array(
                    'customer_id' => 1,
                    'user_id' => 10,
                    'first_name' => 'Alice',
                    'last_name' => 'Smith',
                    'city' => 'Tokyo',
                    'email' => 'alice@example.com',
                    'username' => 'alice',
                ),
            ),
        ));
        $plugin = kec_make_plugin();
        $migrator = new \Koyo\EncryptedFields\Migration\LookupMigrator($plugin, $db);

        $dry = $migrator->dryRun('customer_lookup');
        assert_same(true, $dry['ok'], 'dry run should succeed');
        assert_same(5, $dry['totals']['pending'], 'dry run should count all customer columns');
        assert_true($dry['requires_backup'], 'dry run should require backup');
        assert_same(0, $db->writes, 'dry run must not write');

        $blocked = $migrator->migrateTable('customer_lookup');
        assert_same('backup_required', $blocked['error'], 'migration should be blocked without backup');
        assert_same(0, $db->writes, 'blocked migration must not write');

        $GLOBALS['kec_options']['kec_backup_ack'] = array('timestamp' => time(), 'user_id' => 1, 'reference' => 'test');
        $result = $migrator->migrateTable('customer_lookup', array('batch' => 2));
        assert_same(true, $result['ok'], 'migration should succeed with backup ack');
        assert_same(5, $result['migrated'], 'all customer columns should be encrypted');
        assert_same(array(), $result['errors'], 'no customer migration errors');

        $verify = $migrator->verify('customer_lookup');
        assert_same(true, $verify['ok'], 'customer lookup verification should pass');
        assert_same(0, $verify['plaintext'], 'no plaintext should remain in customer lookup');
        assert_true($verify['decrypt_ok'] > 0, 'customer lookup ciphertext should decrypt');
    });

    test('LookupMigrator decrypts siteguard_history login_name to plaintext', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $GLOBALS['kec_options']['kec_backup_ack'] = array('timestamp' => time(), 'user_id' => 1, 'reference' => 'test');
        $db->setFixtures(array(
            'wp_siteguard_history' => array(
                array('id' => 1, 'login_name' => 'LEG:alice'),
                array('id' => 2, 'login_name' => 'bob'),
                array('id' => 3, 'login_name' => 'LEG:carol'),
            ),
        ));
        $plugin = kec_make_plugin();
        $migrator = new \Koyo\EncryptedFields\Migration\LookupMigrator($plugin, $db);

        $dry = $migrator->dryRun('siteguard_history');
        assert_same(2, $dry['totals']['pending'], 'dry run should count encrypted logins only');

        $result = $migrator->migrateTable('siteguard_history', array('batch' => 1));
        assert_same(true, $result['ok'], 'siteguard migration should succeed');
        assert_same(2, $result['migrated'], 'legacy logins should be decrypted');
        assert_same(1, $result['skipped'], 'plaintext logins should be skipped');

        $verify = $migrator->verify('siteguard_history');
        assert_same(true, $verify['ok'], 'siteguard verification should pass');
        assert_same(0, $verify['legacy'], 'no legacy logins should remain');
        assert_same(0, $verify['v2'], 'no v2 logins should remain');
    });

    test('RotationService builds a dry-run plan and blocks without backup', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $db->setFixtures(array(
            'wp_users' => array(
                array(
                    'ID' => 1,
                    'user_login' => 'enc:v2:det:testkey01:' . base64_encode('alice'),
                    'user_email' => 'enc:v2:det:testkey01:' . base64_encode('alice@example.com'),
                ),
            ),
            'wp_wc_customer_lookup' => array(
                array(
                    'customer_id' => 1,
                    'user_id' => 0,
                    'first_name' => 'enc:v2:det:testkey01:' . base64_encode('Alice'),
                    'last_name' => 'enc:v2:det:testkey01:' . base64_encode('Smith'),
                    'city' => 'enc:v2:det:testkey01:' . base64_encode('Tokyo'),
                    'email' => 'enc:v2:det:testkey01:' . base64_encode('alice@example.com'),
                    'username' => 'enc:v2:det:testkey01:' . base64_encode('alice'),
                ),
            ),
        ));
        $GLOBALS['kec_rotation_pending'] = true;
        $plugin = kec_make_plugin();
        $service = new \Koyo\EncryptedFields\Crypto\RotationService($plugin, $db);

        $plan = $service->rotate(true, 500);
        assert_same(true, $plan['ok'], 'rotation dry run should succeed');
        assert_same('rotate_dry_run', $plan['mode'], 'rotation dry run mode');
        assert_true($plan['rotation_pending'], 'rotation should be pending');
        assert_true($plan['rows'] > 0, 'rotation plan should include rows');
        assert_same(0, $db->writes, 'rotation dry run must not write');

        $blocked = $service->rotate(false, 500);
        assert_same(false, $blocked['ok'], 'rotation should be blocked without backup');
        assert_same('backup_required', $blocked['error'], 'rotation backup gate');
        assert_same(0, $db->writes, 'blocked rotation must not write');
    });

    test('Rotation re-tokenizes user columns when KEC_TOKEN_SECRET is absent', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $GLOBALS['kec_options']['kec_backup_ack'] = array('timestamp' => time(), 'user_id' => 1, 'reference' => 'test');
        $db->setFixtures(array(
            'wp_users' => array(
                array('ID' => 1, 'user_login' => 'alice', 'user_email' => 'alice@example.com'),
            ),
        ));
        $plugin = kec_make_plugin();
        $columns = new \Koyo\EncryptedFields\User\ColumnStore($plugin);
        $migrator = new \Koyo\EncryptedFields\Migration\Migrator($plugin, $db);

        $migrated = $migrator->migrate(array('batch' => 10));
        assert_same(true, $migrated['ok'], 'initial tokenization should succeed');

        $oldLogin = '';
        foreach ($db->updates as $update) {
            if ('wp_users' === $update[0] && isset($update[1]['user_login'])) {
                $oldLogin = (string) $update[1]['user_login'];
            }
        }
        assert_true($columns->isToken($oldLogin, \Koyo\EncryptedFields\User\ColumnStore::LOGIN), 'initial login should be a token');

        $GLOBALS['kec_token_secret'] = 'rotated-token-secret';
        $rotated = $migrator->rotate(array('batch' => 10));
        assert_same(true, $rotated['ok'], 'rotation should succeed');
        assert_true($rotated['rotated'] >= 2, 'user columns should be re-tokenized');

        $newLogin = '';
        foreach ($db->updates as $update) {
            if ('wp_users' === $update[0] && isset($update[1]['user_login'])) {
                $newLogin = (string) $update[1]['user_login'];
            }
        }

        assert_true($newLogin !== $oldLogin, 'token should change without KEC_TOKEN_SECRET');
        assert_same(
            $columns->tokenFor('alice', \Koyo\EncryptedFields\User\ColumnStore::LOGIN),
            $newLogin,
            'new token should use the rotated token secret'
        );
    });

    test('Password reset and user helpers resolve tokens to plaintext', function () use ($registryJson) {
        $db = kec_reset($registryJson);
        $plugin = kec_make_plugin();
        $columns = new \Koyo\EncryptedFields\User\ColumnStore($plugin);
        $loginToken = $columns->tokenFor('alice', \Koyo\EncryptedFields\User\ColumnStore::LOGIN);
        $emailToken = $columns->tokenFor('alice@example.com', \Koyo\EncryptedFields\User\ColumnStore::EMAIL);

        $GLOBALS['kec_usermeta'][7] = array(
            '_kec_user_login' => 'alice',
            '_kec_user_email' => 'alice@example.com',
        );

        assert_same('alice', kec_user_login($loginToken, 7), 'kec_user_login resolves token');
        assert_same('alice@example.com', kec_user_email($emailToken, 7), 'kec_user_email resolves token');
        assert_same('plain', kec_user_login('plain', 7), 'kec_user_login keeps plaintext');
        assert_same('plain@example.com', kec_user_email('plain@example.com', 7), 'kec_user_email keeps plaintext');

        $user = (object) array('ID' => 7, 'user_email' => $emailToken);
        $message = "Username: {$loginToken}\nEmail: {$emailToken}\nReset: https://example.test/?login=" . rawurlencode($loginToken);
        $reset = new \Koyo\EncryptedFields\User\PasswordReset($plugin);
        $out = $reset->filterMessage($message, 'key', $loginToken, $user);

        assert_true(false === strpos($out, $loginToken), 'password reset message must not contain login token');
        assert_true(false === strpos($out, $emailToken), 'password reset message must not contain email token');
        assert_true(false !== strpos($out, 'alice@example.com'), 'password reset message should contain plaintext email');
        assert_true(false !== strpos($out, rawurlencode('alice')), 'password reset link should be decoded');
        assert_same('Password reset for alice', $reset->filterTitle('Password reset for ' . $loginToken, $loginToken, $user), 'password reset title resolves token');
    });

    foreach ($tests as $test) {
        list($name, $callback) = $test;
        try {
            $callback();
            echo "PASS: {$name}\n";
        } catch (\Throwable $exception) {
            $failures++;
            echo "FAIL: {$name}\n  " . $exception->getMessage() . "\n";
        }
    }

    if ($failures > 0) {
        echo "\n{$failures} test(s) failed.\n";
        exit(1);
    }

    echo "\nAll " . count($tests) . " tests passed.\n";
    exit(0);
}
