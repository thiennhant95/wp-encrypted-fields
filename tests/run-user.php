<?php

declare(strict_types=1);

namespace {
    use Koyo\EncryptedFields\Config\Field;
    use Koyo\EncryptedFields\Config\Registry;
    use Koyo\EncryptedFields\Contracts\EncryptorInterface;
    use Koyo\EncryptedFields\Contracts\SearchInterface;
    use Koyo\EncryptedFields\Crypto\KeyManager;
    use Koyo\EncryptedFields\Plugin;
    use Koyo\EncryptedFields\Query\QueryRewriter;
    use Koyo\EncryptedFields\Support\Logger;
    use Koyo\EncryptedFields\User\ColumnStore;
    use Koyo\EncryptedFields\User\UserHooks;
    use Koyo\EncryptedFields\User\UserLookup;

    $root = dirname(__DIR__);
    require $root . '/src/Config/Field.php';
    require $root . '/src/Config/Registry.php';
    require $root . '/src/Contracts/EncryptorInterface.php';
    require $root . '/src/Contracts/SearchInterface.php';
    require $root . '/src/Support/Logger.php';
    require $root . '/src/Plugin.php';
    require $root . '/src/Crypto/KeyManager.php';
    require $root . '/src/User/ColumnStore.php';
    require $root . '/src/User/UserHooks.php';
    require $root . '/src/User/UserLookup.php';
    require $root . '/src/Query/QueryRewriter.php';

    $GLOBALS['__filters'] = array();
    $GLOBALS['__actions'] = array();
    $GLOBALS['__cache'] = array();
    $GLOBALS['__options'] = array();
    $GLOBALS['__user_meta'] = array();
    $GLOBALS['__column_users'] = array();

    if (!function_exists(__NAMESPACE__ . '\\add_filter')) {
        function add_filter($hook, $callback, $priority = 10, $acceptedArgs = 1)
        {
            $GLOBALS['__filters'][$hook][] = array($callback, (int) $priority, (int) $acceptedArgs);
            return true;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\add_action')) {
        function add_action($hook, $callback, $priority = 10, $acceptedArgs = 1)
        {
            $GLOBALS['__actions'][$hook][] = array($callback, (int) $priority, (int) $acceptedArgs);
            return true;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\apply_filters')) {
        function apply_filters($hook, $value, ...$args)
        {
            $callbacks = $GLOBALS['__filters'][$hook] ?? array();

            foreach ($callbacks as $entry) {
                $accepted = $entry[2];
                $callArgs = array($value);
                if ($accepted > 1) {
                    $callArgs = array_merge($callArgs, array_slice($args, 0, $accepted - 1));
                }
                $value = call_user_func_array($entry[0], $callArgs);
            }

            return $value;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\wp_cache_get')) {
        function wp_cache_get($key, $group = '', $force = false)
        {
            return $GLOBALS['__cache'][$group][$key] ?? false;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\wp_cache_set')) {
        function wp_cache_set($key, $value, $group = '', $expire = 0)
        {
            $GLOBALS['__cache'][$group][$key] = $value;
            return true;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\get_option')) {
        function get_option($name, $default = false)
        {
            return array_key_exists($name, $GLOBALS['__options'])
                ? $GLOBALS['__options'][$name]
                : $default;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\update_option')) {
        function update_option($name, $value, $autoload = null)
        {
            $GLOBALS['__options'][$name] = $value;
            return true;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\get_user_meta')) {
        function get_user_meta($userId, $key = '', $single = false)
        {
            $all = $GLOBALS['__user_meta'][(int) $userId] ?? array();

            if ('' === $key) {
                return $all;
            }

            if (!array_key_exists($key, $all)) {
                return $single ? '' : array();
            }

            $values = is_array($all[$key]) ? $all[$key] : array($all[$key]);

            return $single ? ($values[0] ?? '') : $values;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\update_user_meta')) {
        function update_user_meta($userId, $key, $value, $prevValue = '')
        {
            $GLOBALS['__user_meta'][(int) $userId][(string) $key] = $value;
            return true;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\delete_user_meta')) {
        function delete_user_meta($userId, $key)
        {
            unset($GLOBALS['__user_meta'][(int) $userId][(string) $key]);
            return true;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\sanitize_title')) {
        function sanitize_title($title)
        {
            $value = strtolower(trim((string) $title));
            $value = preg_replace('/[^a-z0-9]+/i', '-', $value);
            return trim((string) $value, '-');
        }
    }

    if (!class_exists('WP_User', false)) {
        class WP_User
        {
            public int $ID;
            public object $data;
            public string $user_login;
            public string $user_email;

            public function __construct(int $id = 0, array $data = array())
            {
                $this->ID = $id;
                $this->data = (object) $data;
                $this->user_login = isset($data['user_login']) ? (string) $data['user_login'] : '';
                $this->user_email = isset($data['user_email']) ? (string) $data['user_email'] : '';
            }
        }
    }

    final class WpdbStub
    {
        public string $prefix = 'wp_';
        public string $users = 'wp_users';
        public string $posts = 'wp_posts';

        public function prepare($query, ...$args)
        {
            $value = isset($args[0]) ? (string) $args[0] : '';
            return preg_replace('/%s/', "'" . addslashes($value) . "'", (string) $query, 1);
        }

        public function get_var($query)
        {
            if (preg_match("/WHERE (user_login|user_email) = '([^']+)'/", (string) $query, $match)) {
                $map = $GLOBALS['__column_users'][$match[1]] ?? array();

                return array_key_exists($match[2], $map) ? $map[$match[2]] : null;
            }

            return null;
        }
    }

    final class FakeCrypto implements EncryptorInterface
    {
        private const PREFIX = 'enc:v2:fake:';

        public function encrypt(string $plaintext, Field $field): string
        {
            if ('' === $plaintext || $this->isEncrypted($plaintext)) {
                return $plaintext;
            }

            $value = $plaintext;
            $key = strtolower($field->key());
            if (in_array($field->type(), array('email', 'login'), true)
                || 'user_email' === $key
                || 'user_login' === $key
            ) {
                $value = strtolower(trim($value));
            }

            return self::PREFIX . base64_encode($value);
        }

        public function decrypt(string $value, Field $field): string
        {
            if (!$this->isEncrypted($value)) {
                return $value;
            }

            $decoded = base64_decode(substr($value, strlen(self::PREFIX)), true);

            return false === $decoded ? $value : $decoded;
        }

        public function isEncrypted(string $value): bool
        {
            return 0 === strncmp($value, self::PREFIX, strlen(self::PREFIX));
        }
    }

    final class FakeSearch implements SearchInterface
    {
        /** @var int[] */
        public array $idsToReturn = array();
        /** @var array<int, array{0:string,1:string}> */
        public array $terms = array();

        public function index(string $entity, int $id): void
        {
        }

        public function remove(string $entity, int $id): void
        {
        }

        public function ids(string $entity, string $term, int $limit = 50): array
        {
            $this->terms[] = array($entity, $term);
            return $this->idsToReturn;
        }

        public function reindex(string $entity = 'all', int $batch = 500, ?callable $progress = null): int
        {
            return 0;
        }
    }

    function set_property(object $object, string $property, $value): void
    {
        $reflection = new \ReflectionClass($object);
        $prop = $reflection->getProperty($property);
        $prop->setAccessible(true);
        $prop->setValue($object, $value);
    }

    function make_plugin(array $registry, ?EncryptorInterface $crypto = null, ?SearchInterface $search = null): Plugin
    {
        $reflection = new \ReflectionClass(Plugin::class);
        /** @var Plugin $plugin */
        $plugin = $reflection->newInstanceWithoutConstructor();

        set_property($plugin, 'registry', new Registry($registry));
        set_property($plugin, 'keys', new KeyManager(array(
            'key' => base64_encode(str_repeat('k', 32)),
        )));
        set_property($plugin, 'crypto', $crypto);
        set_property($plugin, 'search', $search);
        set_property($plugin, 'logger', new Logger());
        set_property($plugin, 'tableAdapters', array());
        set_property($plugin, 'booted', false);

        return $plugin;
    }

    $GLOBALS['__passes'] = 0;
    $GLOBALS['__failures'] = 0;

    function check(bool $condition, string $label, string $detail = ''): void
    {
        if ($condition) {
            $GLOBALS['__passes']++;
            echo "PASS {$label}\n";
            return;
        }

        $GLOBALS['__failures']++;
        echo "FAIL {$label}" . ('' !== $detail ? " ({$detail})" : '') . "\n";
    }

    function same($expected, $actual, string $label): void
    {
        check(
            $expected === $actual,
            $label,
            'expected ' . var_export($expected, true) . ', got ' . var_export($actual, true)
        );
    }

    function contains(string $needle, string $haystack, string $label): void
    {
        check(false !== strpos($haystack, $needle), $label, $haystack);
    }

    function not_contains(string $needle, string $haystack, string $label): void
    {
        check(false === strpos($haystack, $needle), $label, $haystack);
    }

    $GLOBALS['wpdb'] = new WpdbStub();

    $crypto = new FakeCrypto();
    $registry = array(
        'user' => array(
            'columns' => array(
                'user_login' => array('type' => 'login', 'max_length' => 60),
                'user_email' => array('type' => 'email', 'max_length' => 100),
            ),
            'meta' => array(
                'first_name' => array('type' => 'text'),
                'last_name' => array('type' => 'text'),
            ),
        ),
    );

    $plugin = make_plugin($registry, $crypto, null);
    $store = new ColumnStore($plugin);
    $hooks = new UserHooks($plugin);
    $hooks->register();

    $loginField = $plugin->registry()->get('user', 'user_login');
    $emailField = $plugin->registry()->get('user', 'user_email');
    $firstNameField = $plugin->registry()->get('user', 'first_name');
    $lastNameField = $plugin->registry()->get('user', 'last_name');

    $longLogin = str_repeat('L', 60);
    $longEmail = str_repeat('E', 88) . '@example.com';
    $longInsert = $hooks->filterPreInsert(array(
        'user_login' => $longLogin,
        'user_email' => $longEmail,
    ), false, 0);
    $hooks->filterInsertUserMeta(array(), new WP_User(0, array()), false);

    check(strlen($longInsert['user_login']) <= 60, 'long login token fits varchar(60)');
    check(strlen($longInsert['user_email']) <= 100, 'long email token fits varchar(100)');
    check($store->isToken($longInsert['user_login'], ColumnStore::LOGIN), 'long login stored as token');
    check($store->isToken($longInsert['user_email'], ColumnStore::EMAIL), 'long email stored as token');
    not_contains(strtolower($longLogin), $longInsert['user_login'], 'long login plaintext not in column');
    not_contains(strtolower($longEmail), $longInsert['user_email'], 'long email plaintext not in column');

    $data = array(
        'user_login' => 'Alice@Example.COM',
        'user_email' => 'Alice@Example.COM',
        'user_nicename' => 'alice-example-com',
        'display_name' => 'Alice',
        'user_url' => 'https://example.test',
    );

    $inserted = $hooks->filterPreInsert($data, false, 0);
    $loginToken = (string) $inserted['user_login'];
    $emailToken = (string) $inserted['user_email'];

    check($store->isToken($loginToken, ColumnStore::LOGIN), 'declared user_login stored as token');
    check($store->isToken($emailToken, ColumnStore::EMAIL), 'declared user_email stored as token');
    not_contains('Alice@Example.COM', $loginToken, 'user_login plaintext not stored');
    not_contains('Alice@Example.COM', $emailToken, 'user_email plaintext not stored');
    same($store->tokenFor('alice@example.com', ColumnStore::LOGIN), $loginToken, 'user_login token is normalized');
    same($store->tokenFor('alice@example.com', ColumnStore::EMAIL), $emailToken, 'user_email token is normalized');
    same('alice-example-com', $inserted['user_nicename'], 'undeclared user_nicename untouched');
    same('Alice', $inserted['display_name'], 'undeclared display_name untouched');
    same('https://example.test', $inserted['user_url'], 'undeclared user_url untouched');

    $meta = $hooks->filterInsertUserMeta(array('existing' => 'value'), new WP_User(7, array()), false);
    same('Alice@Example.COM', $meta['_kec_user_login'] ?? null, 'pending login plaintext stored in meta');
    same('Alice@Example.COM', $meta['_kec_user_email'] ?? null, 'pending email plaintext stored in meta');
    same('value', $meta['existing'] ?? null, 'insert_user_meta keeps existing meta');

    $cleared = $hooks->filterInsertUserMeta(array(), new WP_User(7, array()), false);
    same(array(), $cleared, 'pending plaintext cleared after insert_user_meta');

    update_user_meta(7, '_kec_user_login', 'Alice@Example.COM');
    update_user_meta(7, '_kec_user_email', 'Alice@Example.COM');

    $again = $hooks->filterPreInsert($inserted, true, 7);
    same($loginToken, $again['user_login'], 'existing login token preserved on update');
    same($emailToken, $again['user_email'], 'existing email token preserved on update');

    $againMeta = $hooks->filterInsertUserMeta(array(), new WP_User(7, array()), true);
    same('Alice@Example.COM', $againMeta['_kec_user_login'] ?? null, 'token resolves plaintext from existing meta');
    same('Alice@Example.COM', $againMeta['_kec_user_email'] ?? null, 'token resolves email from existing meta');

    $emailOnlyPlugin = make_plugin(array(
        'user' => array(
            'columns' => array(
                'user_email' => array('type' => 'email'),
            ),
        ),
    ), $crypto, null);
    $emailOnlyStore = new ColumnStore($emailOnlyPlugin);
    $emailOnlyHooks = new UserHooks($emailOnlyPlugin);
    $emailOnly = $emailOnlyHooks->filterPreInsert(array(
        'user_login' => 'PlainLogin',
        'user_email' => 'Plain@Example.com',
    ), false, 0);
    $emailOnlyHooks->filterInsertUserMeta(array(), new WP_User(8, array()), false);

    same('PlainLogin', $emailOnly['user_login'], 'only declared columns tokenized (login left untouched)');
    check($emailOnlyStore->isToken($emailOnly['user_email'], ColumnStore::EMAIL), 'only declared columns tokenized (email token)');

    same(
        $store->tokenFor('alice@example.com', ColumnStore::LOGIN),
        $store->lookupToken(' Alice@Example.COM ', ColumnStore::LOGIN),
        'lookupToken normalizes plaintext login'
    );

    $legacyLogin = $crypto->encrypt('Alice', $loginField);
    same(
        $store->tokenFor('alice', ColumnStore::LOGIN),
        $store->lookupToken($legacyLogin, ColumnStore::LOGIN),
        'lookupToken converts legacy ciphertext'
    );

    $bobToken = $store->tokenFor('bob', ColumnStore::LOGIN);
    same($bobToken, $store->lookupToken($bobToken, ColumnStore::LOGIN), 'lookupToken leaves tokens unchanged');

    $encryptedDisplay = $crypto->encrypt('Alice Display', $firstNameField);
    same('Alice Display', $hooks->filterDisplayName($encryptedDisplay), 'pre_user_display_name decrypts stored value');
    same('Alice Display', $hooks->filterDisplayName('Alice Display'), 'plain display_name left alone');

    update_user_meta(12, '_kec_user_login', 'Alice');
    $token12 = $store->tokenFor('alice', ColumnStore::LOGIN);
    same('alice', $hooks->filterNicename('whatever', 12, $token12), 'pre_user_nicename derives from token meta');
    same('alice', $hooks->filterNicename('whatever', 7, $legacyLogin), 'pre_user_nicename decrypts legacy login');
    same('alice-example-com', $hooks->filterNicename('whatever', 12, 'Alice@Example.COM'), 'pre_user_nicename derives from plaintext login');

    update_user_meta(7, '_kec_user_login', 'Alice');
    update_user_meta(7, '_kec_user_email', 'Alice@Example.COM');
    $tokenLogin7 = $store->tokenFor('alice', ColumnStore::LOGIN);
    $tokenEmail7 = $store->tokenFor('alice@example.com', ColumnStore::EMAIL);

    new UserHooks($plugin);
    $directUser = new WP_User(7, array(
        'user_login' => $tokenLogin7,
        'user_email' => $tokenEmail7,
    ));
    UserHooks::decryptUser($directUser);

    same('Alice', $directUser->data->user_login, 'decryptUser resolves $user->data login from meta');
    same('Alice@Example.COM', $directUser->data->user_email, 'decryptUser resolves $user->data email from meta');
    same('Alice', $directUser->user_login, 'decryptUser resolves object login from meta');
    same('Alice@Example.COM', $directUser->user_email, 'decryptUser resolves object email from meta');

    $encryptedFirst = $crypto->encrypt('Alice', $firstNameField);
    $encryptedLast = $crypto->encrypt('Nguyen', $lastNameField);

    $restUser = new WP_User(7, array(
        'user_login' => $tokenLogin7,
        'user_email' => $tokenEmail7,
    ));

    $response = new class {
        public array $data;
    };
    $response->data = array(
        'username' => $tokenLogin7,
        'email' => $tokenEmail7,
        'slug' => $tokenLogin7,
        'name' => $tokenLogin7,
        'first_name' => $encryptedFirst,
        'last_name' => $encryptedLast,
        'description' => 'plain text',
        'meta' => array(
            'first_name' => $encryptedFirst,
            'last_name' => $encryptedLast,
        ),
    );

    $prepared = $hooks->filterRestPrepare($response, $restUser, null);

    same('Alice@Example.COM', $prepared->data['email'], 'rest_prepare_user resolves email from meta');
    same('Alice', $prepared->data['username'], 'rest_prepare_user resolves username from meta');
    same('Alice', $prepared->data['slug'], 'rest_prepare_user resolves slug from meta');
    same('Alice', $prepared->data['name'], 'rest_prepare_user resolves name from meta');
    same('Alice', $prepared->data['first_name'], 'rest_prepare_user decrypts first_name');
    same('Nguyen', $prepared->data['last_name'], 'rest_prepare_user decrypts last_name');
    same('plain text', $prepared->data['description'], 'rest_prepare_user leaves plaintext fields');
    same('Alice', $prepared->data['meta']['first_name'], 'rest_prepare_user decrypts meta first_name');

    $rewriter = new QueryRewriter($plugin);
    $rewriter->register();

    $expectedEmailToken = $store->tokenFor('alice@example.com', ColumnStore::EMAIL);
    $expectedLoginToken = $store->tokenFor('alice', ColumnStore::LOGIN);

    $equalsSql = "SELECT ID FROM wp_users WHERE user_email = ' Alice@Example.COM '";
    $equalsOut = $rewriter->rewrite($equalsSql);
    contains($expectedEmailToken, $equalsOut, 'query rewrite converts = value to token');
    not_contains('Alice@Example.COM', $equalsOut, 'query rewrite removes plaintext = value');

    $loginEqualsOut = $rewriter->rewrite("SELECT ID FROM wp_users WHERE user_login = 'Alice'");
    contains($expectedLoginToken, $loginEqualsOut, 'query rewrite normalizes login before tokenizing');

    $legacyEqualsOut = $rewriter->rewrite("SELECT ID FROM wp_users WHERE user_login = '" . $legacyLogin . "'");
    contains($expectedLoginToken, $legacyEqualsOut, 'query rewrite converts legacy ciphertext to token');

    $inSql = "SELECT ID FROM wp_users WHERE user_login IN ('Foo', 'BAR') AND user_email IN (\"Baz@Example.com\")";
    $inOut = $rewriter->rewrite($inSql);
    contains($store->tokenFor('foo', ColumnStore::LOGIN), $inOut, 'query rewrite converts IN first item');
    contains($store->tokenFor('bar', ColumnStore::LOGIN), $inOut, 'query rewrite converts IN second item');
    contains($store->tokenFor('baz@example.com', ColumnStore::EMAIL), $inOut, 'query rewrite converts IN email with double quotes');
    not_contains("'Foo'", $inOut, 'query rewrite removes IN plaintext');

    $updateSql = "UPDATE wp_users SET user_email = 'New@Example.com' WHERE user_login = 'Bob'";
    $updateOut = $rewriter->rewrite($updateSql);
    contains($store->tokenFor('new@example.com', ColumnStore::EMAIL), $updateOut, 'query rewrite handles UPDATE SET');
    contains($store->tokenFor('bob', ColumnStore::LOGIN), $updateOut, 'query rewrite handles UPDATE WHERE');

    $once = $rewriter->rewrite("SELECT ID FROM wp_users WHERE user_login = 'Alice'");
    $twice = $rewriter->rewrite($once);
    same($once, $twice, 'query rewrite is idempotent for tokens');

    $tokenSql = "SELECT ID FROM wp_users WHERE user_login = '" . $expectedLoginToken . "'";
    same($tokenSql, $rewriter->rewrite($tokenSql), 'query rewrite leaves existing tokens unchanged');

    $aliasSql = "SELECT * FROM wp_users u WHERE u.user_email = 'alice@example.com'";
    same($aliasSql, $rewriter->rewrite($aliasSql), 'table-qualified/alias column skipped');

    $aliasedTableSql = "SELECT * FROM wp_users u WHERE user_email = 'alice@example.com'";
    same($aliasedTableSql, $rewriter->rewrite($aliasedTableSql), 'aliased main table skipped');

    $otherTableSql = "SELECT * FROM wp_posts WHERE user_email = 'alice@example.com'";
    same($otherTableSql, $rewriter->rewrite($otherTableSql), 'other table skipped');

    $likeSql = "SELECT * FROM wp_users WHERE user_login LIKE '%ali%'";
    same($likeSql, $rewriter->rewrite($likeSql), 'LIKE is not rewritten by QueryRewriter');

    $selectListSql = "SELECT user_login = 'Alice' AS is_alice FROM wp_users";
    same($selectListSql, $rewriter->rewrite($selectListSql), 'SELECT list is not rewritten');

    $search = new FakeSearch();
    $search->idsToReturn = array(3, 7, 7, 0);

    $lookup = new UserLookup($plugin);
    $lookup->register();

    $lookupQuery = new class {
        public string $query_where = "WHERE user_login LIKE '%Alice%' AND display_name LIKE '%Alice%' AND user_email LIKE '%Alice@Example.com%' AND user_nicename LIKE '%alice%'";
    };

    set_property($plugin, 'search', $search);
    $lookup->filterUserQuery($lookupQuery);

    same(2, substr_count($lookupQuery->query_where, 'ID IN (3, 7)'), 'UserLookup builds ID IN for login/email LIKE');
    contains("display_name LIKE '%Alice%'", $lookupQuery->query_where, 'UserLookup keeps display_name LIKE');
    contains("user_nicename LIKE '%alice%'", $lookupQuery->query_where, 'UserLookup keeps user_nicename LIKE');
    not_contains('user_login LIKE', $lookupQuery->query_where, 'UserLookup removes user_login LIKE');
    not_contains('user_email LIKE', $lookupQuery->query_where, 'UserLookup removes user_email LIKE');
    same('Alice', $search->terms[0][1] ?? null, 'UserLookup strips LIKE wildcards before searching');
    same('user', $search->terms[0][0] ?? null, 'UserLookup searches the user entity');

    $underscoreSearch = new FakeSearch();
    $underscoreSearch->idsToReturn = array(1);
    $underscoreWhere = "WHERE user_email LIKE 'nhan\\\\_tt'";
    $lookup->rewriteLikes($underscoreWhere, $underscoreSearch);
    same('nhan_tt', $underscoreSearch->terms[0][1] ?? null, 'UserLookup unescapes LIKE underscores');

    $cipherRegistry = new Registry(array(
        'user' => array(
            'meta' => array(
                'bad_cipher' => array('type' => 'text', 'cipher' => 'bogus'),
                'det_cipher' => array('type' => 'text', 'cipher' => 'det'),
            ),
        ),
    ));
    same('sb', $cipherRegistry->get('user', 'bad_cipher')->cipherName(), 'invalid cipher falls back to default');
    same('det', $cipherRegistry->get('user', 'det_cipher')->cipherName(), 'valid cipher override is kept');

    $nullSearchPlugin = make_plugin($registry, $crypto, null);
    $nullSearchLookup = new UserLookup($nullSearchPlugin);
    $nullQuery = new class {
        public string $query_where = "WHERE user_login LIKE '%Alice%'";
    };
    $nullSearchLookup->filterUserQuery($nullQuery);
    same("WHERE user_login LIKE '%Alice%'", $nullQuery->query_where, 'UserLookup is a no-op without search service');

    $disabledPlugin = make_plugin(array(), $crypto, $search);
    $disabledRewriter = new QueryRewriter($disabledPlugin);
    $disabledSql = "SELECT ID FROM wp_users WHERE user_email = 'alice@example.com'";
    same($disabledSql, $disabledRewriter->rewrite($disabledSql), 'rewrite no-op without user columns');

    $disabledLookup = new UserLookup($disabledPlugin);
    $disabledWhere = "WHERE user_login LIKE '%Alice%'";
    same($disabledWhere, $disabledLookup->rewriteLikes($disabledWhere, $search), 'UserLookup no-op without user columns');

    echo "\n";
    echo 'Tests: ' . ($GLOBALS['__passes'] + $GLOBALS['__failures'])
        . ', Passed: ' . $GLOBALS['__passes']
        . ', Failed: ' . $GLOBALS['__failures'] . "\n";

    exit($GLOBALS['__failures'] > 0 ? 1 : 0);
}
