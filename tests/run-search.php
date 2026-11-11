<?php

declare(strict_types=1);

namespace Koyo\EncryptedFields\Crypto {
    if (!class_exists(KeyManager::class, false)) {
        final class KeyManager
        {
            public function searchSecret(): string
            {
                return 'unit-test-search-secret';
            }

            public function tokenSecret(): string
            {
                return 'unit-test-token-secret';
            }

            public function tokenSecretIsStable(): bool
            {
                return true;
            }
        }
    }
}

namespace {
    use Koyo\EncryptedFields\Config\Registry;
    use Koyo\EncryptedFields\Plugin;
    use Koyo\EncryptedFields\Search\Hooks;
    use Koyo\EncryptedFields\Search\IndexSchema;
    use Koyo\EncryptedFields\Search\SearchService;
    use Koyo\EncryptedFields\Search\Tokenizer;
    use Koyo\EncryptedFields\Support\Logger;
    use Koyo\EncryptedFields\User\ColumnStore;

    $root = dirname(__DIR__);
    require $root . '/src/Config/Field.php';
    require $root . '/src/Config/Registry.php';
    require $root . '/src/Contracts/SearchInterface.php';
    require $root . '/src/Support/Logger.php';
    require $root . '/src/Plugin.php';
    require $root . '/src/User/ColumnStore.php';
    require $root . '/src/Search/Tokenizer.php';
    require $root . '/src/Search/IndexSchema.php';
    require $root . '/src/Search/SearchService.php';
    require $root . '/src/Search/Hooks.php';

    $GLOBALS['__dbdelta'] = array();
    $GLOBALS['__actions'] = array();
    $GLOBALS['__options'] = array();
    $GLOBALS['__user_meta'] = array();
    $GLOBALS['__post_meta'] = array();
    $GLOBALS['__term_meta'] = array();
    $GLOBALS['__comment_meta'] = array();
    $GLOBALS['__entity_ids'] = array(
        'user' => array(),
        'post' => array(),
        'term' => array(),
        'comment' => array(),
    );

    if (!function_exists(__NAMESPACE__ . '\\dbDelta')) {
        function dbDelta($sql)
        {
            $GLOBALS['__dbdelta'][] = $sql;
            return array();
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

    if (!function_exists(__NAMESPACE__ . '\\add_action')) {
        function add_action($hook, $callback, $priority = 10, $acceptedArgs = 1)
        {
            $GLOBALS['__actions'][$hook][] = array($callback, (int) $priority, (int) $acceptedArgs);
            return true;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\get_user_meta')) {
        function get_user_meta($id, $key = '', $single = false)
        {
            $all = $GLOBALS['__user_meta'][(int) $id] ?? array();
            if ($single) {
                return array_key_exists($key, $all) ? $all[$key] : '';
            }
            return $all;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\get_post_meta')) {
        function get_post_meta($id, $key = '', $single = false)
        {
            $all = $GLOBALS['__post_meta'][(int) $id] ?? array();
            if ($single) {
                return array_key_exists($key, $all) ? $all[$key] : '';
            }
            return $all;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\get_term_meta')) {
        function get_term_meta($id, $key = '', $single = false)
        {
            $all = $GLOBALS['__term_meta'][(int) $id] ?? array();
            if ($single) {
                return array_key_exists($key, $all) ? $all[$key] : '';
            }
            return $all;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\get_comment_meta')) {
        function get_comment_meta($id, $key = '', $single = false)
        {
            $all = $GLOBALS['__comment_meta'][(int) $id] ?? array();
            if ($single) {
                return array_key_exists($key, $all) ? $all[$key] : '';
            }
            return $all;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\get_userdata')) {
        function get_userdata($id)
        {
            return $GLOBALS['__users'][(int) $id] ?? false;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\get_users')) {
        function get_users($args = array())
        {
            $ids = $GLOBALS['__entity_ids']['user'] ?? array();
            return paged_ids($ids, $args);
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\get_posts')) {
        function get_posts($args = array())
        {
            $ids = $GLOBALS['__entity_ids']['post'] ?? array();
            return paged_ids($ids, $args);
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\get_terms')) {
        function get_terms($args = array())
        {
            $ids = $GLOBALS['__entity_ids']['term'] ?? array();
            return paged_ids($ids, $args);
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\get_comments')) {
        function get_comments($args = array())
        {
            $ids = $GLOBALS['__entity_ids']['comment'] ?? array();
            return paged_ids($ids, $args);
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\paged_ids')) {
        function paged_ids(array $ids, array $args): array
        {
            $offset = max(0, (int) ($args['offset'] ?? 0));
            $number = isset($args['number']) ? (int) $args['number'] : (int) ($args['posts_per_page'] ?? -1);
            return array_slice($ids, $offset, $number > 0 ? $number : null);
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\wp_is_post_revision')) {
        function wp_is_post_revision($postId)
        {
            return false;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\wp_is_post_autosave')) {
        function wp_is_post_autosave($postId)
        {
            return false;
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\get_post_type')) {
        function get_post_type($id)
        {
            return 'shop_order';
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\get_taxonomies')) {
        function get_taxonomies()
        {
            return array('category', 'post_tag');
        }
    }

    if (!function_exists(__NAMESPACE__ . '\\is_wp_error')) {
        function is_wp_error($value)
        {
            return false;
        }
    }

    final class WpdbStub
    {
        public string $prefix = 'wp_';
        public string $users = 'wp_users';
        public string $posts = 'wp_posts';
        public string $terms = 'wp_terms';
        public string $comments = 'wp_comments';

        public array $queries = array();
        public array $colResults = array();
        public int $colCalls = 0;
        public array $counts = array('users' => 0, 'posts' => 0, 'terms' => 0, 'comments' => 0);

        public function prepare($query, ...$args)
        {
            if (1 === count($args) && is_array($args[0])) {
                $args = $args[0];
            }

            $index = 0;

            return preg_replace_callback('/%[sdf]/', function ($match) use (&$index, $args) {
                $value = $args[$index] ?? '';
                $index++;

                if ('%s' === $match[0]) {
                    return "'" . str_replace("'", "''", (string) $value) . "'";
                }

                if ('%d' === $match[0]) {
                    return (string) (int) $value;
                }

                return (string) (float) $value;
            }, $query);
        }

        public function query($sql)
        {
            $this->queries[] = $sql;
            return true;
        }

        public function get_col($sql)
        {
            $this->queries[] = $sql;
            $this->colCalls++;
            return $this->colResults;
        }

        public function get_var($sql)
        {
            foreach (array('users', 'posts', 'terms', 'comments') as $key) {
                if (false !== strpos($sql, 'wp_' . $key)) {
                    return $this->counts[$key] ?? 0;
                }
            }

            return null;
        }

        public function get_charset_collate()
        {
            return 'DEFAULT CHARACTER SET utf8mb4';
        }
    }

    function set_property(object $object, string $property, $value): void
    {
        $reflection = new \ReflectionClass($object);
        $prop = $reflection->getProperty($property);
        $prop->setAccessible(true);
        $prop->setValue($object, $value);
    }

    function make_plugin(array $registry): Plugin
    {
        $reflection = new \ReflectionClass(Plugin::class);
        /** @var Plugin $plugin */
        $plugin = $reflection->newInstanceWithoutConstructor();

        set_property($plugin, 'registry', new Registry($registry));
        set_property($plugin, 'keys', new \Koyo\EncryptedFields\Crypto\KeyManager());
        set_property($plugin, 'logger', new Logger());
        set_property($plugin, 'crypto', null);
        set_property($plugin, 'search', null);
        set_property($plugin, 'tableAdapters', array());
        set_property($plugin, 'booted', false);

        return $plugin;
    }

    function fire_action(string $hook, array $args = array()): void
    {
        $callbacks = $GLOBALS['__actions'][$hook] ?? array();
        foreach ($callbacks as $entry) {
            $accepted = $entry[2] > 0 ? array_slice($args, 0, $entry[2]) : array();
            call_user_func_array($entry[0], $accepted);
        }
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

    $secret = 'unit-test-search-secret';
    $tokenizer = new Tokenizer($secret);

    same('mixed value', $tokenizer->normalize("  MiXeD\t\n   Value  "), 'normalize lowercases/collapses/trims');
    same('hello world', $tokenizer->normalize(" Ｈｅｌｌｏ　　World "), 'normalize handles NFKC + ideographic space');
    same('カタカナ', $tokenizer->normalize('ｶﾀｶﾅ'), 'normalize converts half-width katakana');
    same('', $tokenizer->normalize(" \t\n　 "), 'normalize whitespace-only becomes empty');

    $expectedFull = hash_hmac('sha256', 'F:title:hello', $secret);
    same($expectedFull, $tokenizer->fullToken('HELLO', 'title'), 'full token is deterministic + normalized');
    same(64, strlen($expectedFull), 'full token is char(64) hex');

    $tokens = $tokenizer->tokens('Hello', 'title');
    same(4, count($tokens), 'tokens = full + 3 unique trigrams');
    same($expectedFull, $tokens[0], 'tokens starts with full token');
    check(in_array(hash_hmac('sha256', 'G:title:hel', $secret), $tokens, true), 'trigram hel token present');
    check(in_array(hash_hmac('sha256', 'G:title:ell', $secret), $tokens, true), 'trigram ell token present');
    check(in_array(hash_hmac('sha256', 'G:title:llo', $secret), $tokens, true), 'trigram llo token present');

    same(1, count($tokenizer->tokens('ab', 'title')), 'short term gets exact token only');
    same(0, count($tokenizer->trigramTokens('ab', 'title')), 'short term has no trigrams');
    same(2, count($tokenizer->tokens('aaaa', 'title')), 'duplicate trigrams are deduplicated');
    check(
        $tokenizer->fullToken('hello', 'title') !== $tokenizer->fullToken('hello', 'body'),
        'field domain separation changes tokens'
    );

    $wpdb = new WpdbStub();
    $GLOBALS['wpdb'] = $wpdb;

    $schema = new IndexSchema($wpdb);
    $schemaSql = $schema->sql();
    check(false !== strpos($schemaSql, 'CREATE TABLE wp_kec_search_index'), 'schema table name');
    check(false !== strpos($schemaSql, 'entity_type varchar(20) NOT NULL'), 'schema entity_type column');
    check(false !== strpos($schemaSql, 'entity_id bigint(20) unsigned NOT NULL'), 'schema entity_id column');
    check(false !== strpos($schemaSql, 'field varchar(64) NOT NULL'), 'schema field column');
    check(false !== strpos($schemaSql, 'token char(64) NOT NULL'), 'schema token column');
    check(false !== strpos($schemaSql, 'PRIMARY KEY  (entity_type,entity_id,field,token)'), 'schema primary key');
    check(false !== strpos($schemaSql, 'KEY token (token)'), 'schema token key');
    check($schema->create(), 'schema create uses dbDelta stub');
    check(isset($GLOBALS['__dbdelta'][0]) && false !== strpos($GLOBALS['__dbdelta'][0], 'kec_search_index'), 'dbDelta receives schema');

    $registry = array(
        'user' => array(
            'meta' => array(
                'billing_email' => array('type' => 'email', 'search' => true),
                'billing_phone' => array('type' => 'text', 'search' => true),
                'first_name' => array('type' => 'text'),
            ),
        ),
        'post' => array(
            'post_types' => array('shop_order'),
            'meta' => array(
                '_billing_email' => array('type' => 'email', 'search' => true),
            ),
        ),
    );

    $plugin = make_plugin($registry);
    $search = new SearchService($plugin);

    $GLOBALS['__user_meta'][7] = array(
        'billing_email' => 'Alice@Example.com',
        'billing_phone' => '+1 555',
        'first_name' => 'Ignored',
    );

    $wpdb->queries = array();
    $search->index('user', 7);

    $deletes = array_values(array_filter($wpdb->queries, static function ($sql) {
        return 0 === strpos($sql, 'DELETE FROM wp_kec_search_index');
    }));
    $inserts = array_values(array_filter($wpdb->queries, static function ($sql) {
        return 0 === strpos($sql, 'INSERT IGNORE INTO wp_kec_search_index');
    }));

    same(1, count($deletes), 'index issues one delete for entity/id');
    check(false !== strpos($deletes[0] ?? '', "entity_type = 'user'"), 'delete filters entity_type');
    check(false !== strpos($deletes[0] ?? '', 'entity_id = 7'), 'delete filters entity_id');

    same(1, count($inserts), 'index issues INSERT IGNORE');
    $insert = $inserts[0] ?? '';
    check(false !== strpos($insert, '(entity_type, entity_id, field, token) VALUES'), 'insert column shape');
    check(false === strpos($insert, 'first_name'), 'non-searchable registry field not indexed');

    $emailFull = $tokenizer->fullToken('alice@example.com', 'billing_email');
    check(false !== strpos($insert, "'" . $emailFull . "'"), 'insert contains normalized email full token');
    check(false === strpos($insert, 'Alice'), 'insert does not contain plaintext (case)');
    check(false === strpos($insert, 'Example.com'), 'insert does not contain plaintext (domain)');
    check(false === strpos($insert, '+1 555'), 'insert does not contain plaintext (phone)');
    same(21, substr_count($insert, "('user', 7,"), 'email + phone token rows (16 + 5)');

    $wpdb->queries = array();
    $search->remove('user', 7);
    same(1, count($wpdb->queries), 'remove issues one delete');
    check(0 === strpos($wpdb->queries[0] ?? '', 'DELETE FROM wp_kec_search_index'), 'remove does not insert');

    $wpdb->queries = array();
    $wpdb->colCalls = 0;
    $wpdb->colResults = array(9, 7, 7);
    $ids = $search->ids('user', 'Alice@Example.com', 10);

    same(array(7, 9), $ids, 'ids deduplicates + sorts results');
    same(4, $wpdb->colCalls, 'long term builds exact + trigram query per searchable field');

    $selects = $wpdb->queries;
    $having = array_values(array_filter($selects, static function ($sql) {
        return false !== strpos($sql, 'HAVING COUNT(DISTINCT token)');
    }));
    same(2, count($having), 'trigram queries use AND via HAVING count');
    foreach ($selects as $sql) {
        check(false === strpos($sql, 'Alice'), 'ids query never contains plaintext', $sql);
        check(false !== strpos($sql, "entity_type = 'user'"), 'ids query filters entity_type', $sql);
        check(false !== strpos($sql, 'token'), 'ids query filters token', $sql);
    }

    $wpdb->queries = array();
    $wpdb->colCalls = 0;
    $wpdb->colResults = array(5);
    same(array(5), $search->ids('user', 'ab', 10), 'short term returns exact matches');
    same(2, $wpdb->colCalls, 'short term queries each searchable field once');
    same(0, count(array_filter($wpdb->queries, static function ($sql) {
        return false !== strpos($sql, 'HAVING COUNT(DISTINCT token)');
    })), 'short term does not use trigrams');

    $wpdb->queries = array();
    $wpdb->colCalls = 0;
    same(array(), $search->ids('user', '   ', 10), 'empty term returns empty result');
    same(0, $wpdb->colCalls, 'empty term runs no queries');

    $GLOBALS['__entity_ids']['user'] = array(7, 8);
    $GLOBALS['__user_meta'][8] = array(
        'billing_email' => 'bob@example.com',
        'billing_phone' => '+2 444',
    );
    $wpdb->counts = array('users' => 2, 'posts' => 0, 'terms' => 0, 'comments' => 0);
    $progress = array();

    $indexed = $search->reindex('user', 500, static function ($done, $total) use (&$progress) {
        $progress[] = array($done, $total);
    });

    same(2, $indexed, 'reindex returns number of indexed entities');
    same(array(2, 2), end($progress), 'reindex progress reports done/total');

    $GLOBALS['__actions'] = array();
    $hooks = new Hooks($plugin);
    $hooks->register();

    foreach (array('save_post', 'user_register', 'profile_update', 'created_term', 'edited_term', 'deleted_post', 'deleted_user', 'deleted_term') as $hook) {
        check(isset($GLOBALS['__actions'][$hook]), 'hooks registered: ' . $hook);
    }

    $GLOBALS['__post_meta'][7] = array('_billing_email' => 'order@example.com');

    $wpdb->queries = array();
    fire_action('save_post', array(7, null, true));
    check(isset($GLOBALS['__actions']['shutdown']), 'queued write schedules shutdown flush');

    $hooks->flush();
    check(count(array_filter($wpdb->queries, static function ($sql) {
        return 0 === strpos($sql, 'INSERT IGNORE INTO wp_kec_search_index');
    })) > 0, 'shutdown flush indexes queued entity');

    $wpdb->queries = array();
    fire_action('deleted_user', array(7));
    $hooks->flush();
    check(count(array_filter($wpdb->queries, static function ($sql) {
        return 0 === strpos($sql, 'DELETE FROM wp_kec_search_index');
    })) > 0, 'deleted hook removes queued entity tokens');

    $tokenRegistry = array(
        'user' => array(
            'columns' => array(
                'user_login' => array('type' => 'login', 'search' => true),
                'user_email' => array('type' => 'email', 'search' => true),
            ),
        ),
    );

    $tokenPlugin = make_plugin($tokenRegistry);
    $tokenSearch = new SearchService($tokenPlugin);
    $columns = new ColumnStore($tokenPlugin);
    $loginToken = $columns->tokenFor('Alice', ColumnStore::LOGIN);
    $emailToken = $columns->tokenFor('Alice@Example.com', ColumnStore::EMAIL);

    $GLOBALS['__users'][11] = (object) array(
        'ID' => 11,
        'user_login' => $loginToken,
        'user_email' => $emailToken,
    );
    $GLOBALS['__user_meta'][11] = array(
        '_kec_user_login' => 'Alice',
        '_kec_user_email' => 'Alice@Example.com',
    );

    $wpdb->queries = array();
    $tokenSearch->index('user', 11);
    $tokenInsert = '';
    foreach ($wpdb->queries as $sql) {
        if (0 === strpos($sql, 'INSERT IGNORE INTO wp_kec_search_index')) {
            $tokenInsert .= $sql;
        }
    }

    $loginFull = $tokenizer->fullToken('Alice', 'user_login');
    $emailFull = $tokenizer->fullToken('Alice@Example.com', 'user_email');
    check(false !== strpos($tokenInsert, "'" . $loginFull . "'"), 'user login column indexes plaintext, not token');
    check(false !== strpos($tokenInsert, "'" . $emailFull . "'"), 'user email column indexes plaintext, not token');
    check(false === strpos($tokenInsert, $loginToken), 'login token is never written to the search index');
    check(false === strpos($tokenInsert, $emailToken), 'email token is never written to the search index');

    $disabledPlugin = make_plugin(array());
    $disabledSearch = new SearchService($disabledPlugin);
    $wpdb->queries = array();
    $disabledSearch->index('user', 7);
    $disabledSearch->remove('user', 7);
    same(array(), $disabledSearch->ids('user', 'alice', 10), 'disabled registry search returns no ids');
    same(array(), $wpdb->queries, 'disabled registry performs no queries');
    same(0, $disabledSearch->reindex('all'), 'disabled registry reindex is a no-op');

    echo "\n";
    echo 'Tests: ' . ($GLOBALS['__passes'] + $GLOBALS['__failures'])
        . ', Passed: ' . $GLOBALS['__passes']
        . ', Failed: ' . $GLOBALS['__failures'] . "\n";

    exit($GLOBALS['__failures'] > 0 ? 1 : 0);
}
