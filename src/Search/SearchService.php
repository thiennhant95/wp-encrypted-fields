<?php

namespace Koyo\EncryptedFields\Search;

use Koyo\EncryptedFields\Config\Field;
use Koyo\EncryptedFields\Config\Registry;
use Koyo\EncryptedFields\Contracts\SearchInterface;
use Koyo\EncryptedFields\Plugin;
use Koyo\EncryptedFields\User\ColumnStore;

final class SearchService implements SearchInterface
{
    private const ENTITIES = array('user', 'post', 'term', 'comment');
    private const INSERT_CHUNK = 500;

    private Plugin $plugin;

    /** @var object|null */
    private $wpdb;

    private ?Tokenizer $tokenizer = null;
    private ?IndexSchema $schema = null;
    private bool $schemaChecked = false;
    private ?ColumnStore $columns = null;

    public function __construct(Plugin $plugin)
    {
        global $wpdb;

        $this->plugin = $plugin;
        $this->wpdb = $wpdb;
    }

    public function index(string $entity, int $id): void
    {
        $entity = $this->entity($entity);
        if (!$this->enabled() || null === $entity || $id <= 0) {
            return;
        }

        $this->ensureSchema();
        $this->deleteEntity($entity, $id);

        $fields = $this->searchableFields($entity);
        if (array() === $fields) {
            return;
        }

        $rows = array();

        foreach ($fields as $field) {
            if (!$this->isFieldApplicable($entity, $id, $field)) {
                continue;
            }

            $value = $this->readPlaintext($entity, $id, $field);
            if (null === $value || '' === $value) {
                continue;
            }

            foreach ($this->tokenizer()->tokens($value, $field->key()) as $token) {
                $rows[] = array($entity, $id, $field->key(), $token);

                if (count($rows) >= self::INSERT_CHUNK) {
                    $this->insertRows($rows);
                    $rows = array();
                }
            }
        }

        if (array() !== $rows) {
            $this->insertRows($rows);
        }
    }

    public function remove(string $entity, int $id): void
    {
        $entity = $this->entity($entity);
        if (!$this->enabled() || null === $entity || $id <= 0) {
            return;
        }

        $this->ensureSchema();
        $this->deleteEntity($entity, $id);
    }

    /**
     * @return int[]
     */
    public function ids(string $entity, string $term, int $limit = 50): array
    {
        $entity = $this->entity($entity);
        if (!$this->enabled() || null === $entity || $limit <= 0) {
            return array();
        }

        $normalized = $this->tokenizer()->normalize($term);
        if ('' === $normalized) {
            return array();
        }

        $fields = $this->searchableFields($entity);
        if (array() === $fields) {
            return array();
        }

        $this->ensureSchema();

        $length = $this->tokenizer()->normalizedLength($normalized);
        $trigrams = $length >= 3 ? $this->tokenizer()->trigrams($normalized) : array();
        $found = array();

        foreach ($fields as $field) {
            $fieldKey = $field->key();
            $fullToken = $this->tokenizer()->token('F', $normalized, $fieldKey);

            foreach ($this->queryByToken($entity, $fieldKey, $fullToken, $limit) as $id) {
                $found[$id] = true;
            }

            if (array() === $trigrams) {
                continue;
            }

            $tokens = array();
            foreach ($trigrams as $trigram) {
                $tokens[] = $this->tokenizer()->token('G', $trigram, $fieldKey);
            }

            foreach ($this->queryByTokens($entity, $fieldKey, $tokens, $limit) as $id) {
                $found[$id] = true;
            }
        }

        $ids = array_keys($found);
        sort($ids, SORT_NUMERIC);

        return array_slice($ids, 0, $limit);
    }

    public function reindex(string $entity = 'all', int $batch = 500, ?callable $progress = null): int
    {
        if (!$this->enabled()) {
            return 0;
        }

        $entity = strtolower(trim($entity));
        $batch = max(1, $batch);

        if ('all' === $entity) {
            $targets = array();
            foreach (self::ENTITIES as $candidate) {
                if (array() !== $this->searchableFields($candidate)) {
                    $targets[] = $candidate;
                }
            }
        } else {
            $entity = $this->entity($entity);
            if (null === $entity || array() === $this->searchableFields($entity)) {
                return 0;
            }
            $targets = array($entity);
        }

        if (array() === $targets) {
            return 0;
        }

        $this->ensureSchema();

        $total = 0;
        foreach ($targets as $target) {
            $total += $this->countEntities($target);
        }

        $done = 0;
        $indexed = 0;

        foreach ($targets as $target) {
            $offset = 0;

            do {
                $ids = $this->fetchIds($target, $batch, $offset);
                $fetched = count($ids);

                foreach ($ids as $id) {
                    if ($id <= 0) {
                        continue;
                    }

                    $this->index($target, $id);
                    $indexed++;
                    $done++;

                    if (null !== $progress) {
                        $progress($done, $total);
                    }
                }

                $offset += $batch;
            } while ($fetched >= $batch);
        }

        return $indexed;
    }

    public function table(): string
    {
        return $this->schema()->table();
    }

    private function entity(string $entity): ?string
    {
        $entity = strtolower(trim($entity));

        return in_array($entity, self::ENTITIES, true) ? $entity : null;
    }

    private function enabled(): bool
    {
        try {
            $registry = $this->plugin->registry();
        } catch (\Throwable $e) {
            return false;
        }

        return $registry instanceof Registry && $registry->isEnabled();
    }

    /**
     * @return array<string, Field>
     */
    private function searchableFields(string $entity): array
    {
        try {
            $registry = $this->plugin->registry();
        } catch (\Throwable $e) {
            return array();
        }

        if (!$registry instanceof Registry) {
            return array();
        }

        $fields = array();
        foreach ($registry->fields($entity) as $key => $field) {
            if ($field instanceof Field && $field->isSearchable()) {
                $fields[$key] = $field;
            }
        }

        return $fields;
    }

    private function isFieldApplicable(string $entity, int $id, Field $field): bool
    {
        if ('post' !== $entity) {
            return true;
        }

        $postTypes = $field->postTypes();
        if (array() === $postTypes || !function_exists('get_post_type')) {
            return true;
        }

        return in_array((string) get_post_type($id), $postTypes, true);
    }

    private function readPlaintext(string $entity, int $id, Field $field): ?string
    {
        if ($field->isColumn()) {
            $value = $this->readColumn($entity, $id, $field->key());
        } else {
            $value = $this->readMeta($entity, $id, $field->key());
        }

        if (null === $value || is_array($value) || is_object($value)) {
            return null;
        }

        if (!is_scalar($value)) {
            return null;
        }

        $value = (string) $value;

        if ('user' === $entity && $field->isColumn() && $this->isUserColumn($field->key())) {
            return $this->userColumnPlaintext($value, $field->key(), $id);
        }

        return $this->maybeDecrypt($value, $field);
    }

    private function isUserColumn(string $key): bool
    {
        return 'user_login' === $key || 'user_email' === $key;
    }

    private function userColumnPlaintext(string $value, string $key, int $userId): ?string
    {
        $columns = $this->columnStore();
        if (null === $columns) {
            return $this->maybeDecrypt($value, new Field('user', $key, 'user_email' === $key ? 'email' : 'login'));
        }

        $name = 'user_login' === $key ? ColumnStore::LOGIN : ColumnStore::EMAIL;
        $plain = $columns->plainFromStored($value, $name, $userId);

        if ('' === $plain) {
            return null;
        }

        if ($columns->isToken($plain, $name)) {
            return null;
        }

        return $plain;
    }

    private function columnStore(): ?ColumnStore
    {
        if (null !== $this->columns) {
            return $this->columns;
        }

        if (!class_exists(ColumnStore::class)) {
            return null;
        }

        try {
            $this->columns = new ColumnStore($this->plugin);
        } catch (\Throwable $e) {
            return null;
        }

        return $this->columns;
    }

    /**
     * @return mixed
     */
    private function readMeta(string $entity, int $id, string $key)
    {
        $function = '';
        switch ($entity) {
            case 'user':
                $function = 'get_user_meta';
                break;
            case 'post':
                $function = 'get_post_meta';
                break;
            case 'term':
                $function = 'get_term_meta';
                break;
            case 'comment':
                $function = 'get_comment_meta';
                break;
        }

        if ('' === $function || !function_exists($function)) {
            return null;
        }

        return $function($id, $key, true);
    }

    /**
     * @return mixed
     */
    private function readColumn(string $entity, int $id, string $key)
    {
        if ('user' !== $entity || !function_exists('get_userdata')) {
            return null;
        }

        $user = get_userdata($id);
        if (!is_object($user) || !isset($user->{$key})) {
            return null;
        }

        return $user->{$key};
    }

    private function maybeDecrypt(string $value, Field $field): string
    {
        if ('' === $value) {
            return '';
        }

        try {
            $crypto = $this->plugin->crypto();
        } catch (\Throwable $e) {
            return $value;
        }

        if (!is_object($crypto) || !method_exists($crypto, 'isEncrypted') || !method_exists($crypto, 'decrypt')) {
            return $value;
        }

        try {
            if ($crypto->isEncrypted($value)) {
                $decrypted = $crypto->decrypt($value, $field);
                if (is_string($decrypted)) {
                    return $decrypted;
                }
            }
        } catch (\Throwable $e) {
            return $value;
        }

        return $value;
    }

    private function deleteEntity(string $entity, int $id): void
    {
        $sql = $this->prepare(
            'DELETE FROM ' . $this->table() . ' WHERE entity_type = %s AND entity_id = %d',
            array($entity, $id)
        );

        if (null !== $sql) {
            $this->query($sql);
        }
    }

    /**
     * @param array<int, array{0: string, 1: int, 2: string, 3: string}> $rows
     */
    private function insertRows(array $rows): void
    {
        if (array() === $rows) {
            return;
        }

        $values = array();
        $args = array();

        foreach ($rows as $row) {
            $values[] = '(%s, %d, %s, %s)';
            $args[] = $row[0];
            $args[] = $row[1];
            $args[] = $row[2];
            $args[] = $row[3];
        }

        $sql = 'INSERT IGNORE INTO ' . $this->table()
            . ' (entity_type, entity_id, field, token) VALUES '
            . implode(', ', $values);

        $prepared = $this->prepare($sql, $args);
        if (null !== $prepared) {
            $this->query($prepared);
        }
    }

    /**
     * @return int[]
     */
    private function queryByToken(string $entity, string $field, string $token, int $limit): array
    {
        $sql = $this->prepare(
            'SELECT DISTINCT entity_id FROM ' . $this->table()
            . ' WHERE entity_type = %s AND field = %s AND token = %s'
            . ' ORDER BY entity_id ASC LIMIT %d',
            array($entity, $field, $token, $limit)
        );

        return $this->intColumn($sql);
    }

    /**
     * @param string[] $tokens
     *
     * @return int[]
     */
    private function queryByTokens(string $entity, string $field, array $tokens, int $limit): array
    {
        if (array() === $tokens) {
            return array();
        }

        $placeholders = implode(', ', array_fill(0, count($tokens), '%s'));
        $args = array_merge(array($entity, $field), array_values($tokens), array(count($tokens), $limit));

        $sql = $this->prepare(
            'SELECT entity_id FROM ' . $this->table()
            . ' WHERE entity_type = %s AND field = %s AND token IN (' . $placeholders . ')'
            . ' GROUP BY entity_id HAVING COUNT(DISTINCT token) = %d'
            . ' ORDER BY entity_id ASC LIMIT %d',
            $args
        );

        return $this->intColumn($sql);
    }

    /**
     * @return int[]
     */
    private function intColumn(?string $sql): array
    {
        if (null === $sql || !is_object($this->wpdb) || !method_exists($this->wpdb, 'get_col')) {
            return array();
        }

        try {
            $values = $this->wpdb->get_col($sql);
        } catch (\Throwable $e) {
            return array();
        }

        if (!is_array($values)) {
            return array();
        }

        $ids = array();
        foreach ($values as $value) {
            $id = (int) $value;
            if ($id > 0) {
                $ids[] = $id;
            }
        }

        return $ids;
    }

    private function prepare(string $sql, array $args): ?string
    {
        if (!is_object($this->wpdb) || !method_exists($this->wpdb, 'prepare')) {
            return null;
        }

        try {
            $prepared = $this->wpdb->prepare($sql, $args);
        } catch (\Throwable $e) {
            $this->logWarning('Search query prepare failed.', array('error' => get_class($e)));
            return null;
        }

        return is_string($prepared) ? $prepared : null;
    }

    private function query(string $sql): void
    {
        if (!is_object($this->wpdb) || !method_exists($this->wpdb, 'query')) {
            return;
        }

        try {
            $this->wpdb->query($sql);
        } catch (\Throwable $e) {
            $this->logWarning('Search index write failed.', array('error' => get_class($e)));
        }
    }

    private function ensureSchema(): void
    {
        if ($this->schemaChecked) {
            return;
        }

        $this->schemaChecked = true;

        try {
            $this->schema()->maybeUpgrade();
        } catch (\Throwable $e) {
            $this->logWarning('Search index schema upgrade failed.', array('error' => get_class($e)));
        }
    }

    private function schema(): IndexSchema
    {
        if (null === $this->schema) {
            $this->schema = new IndexSchema($this->wpdb);
        }

        return $this->schema;
    }

    private function tokenizer(): Tokenizer
    {
        if (null === $this->tokenizer) {
            $this->tokenizer = new Tokenizer($this->searchSecret());
        }

        return $this->tokenizer;
    }

    private function searchSecret(): string
    {
        try {
            if (method_exists($this->plugin, 'keys')) {
                $keys = $this->plugin->keys();
                if (is_object($keys) && method_exists($keys, 'searchSecret')) {
                    $secret = (string) $keys->searchSecret();
                    if ('' !== $secret) {
                        return $secret;
                    }
                }
            }
        } catch (\Throwable $e) {
            // Fall through to the safest available secret.
        }

        if (defined('KEC_SEARCH_SECRET')) {
            $secret = (string) KEC_SEARCH_SECRET;
            if ('' !== $secret) {
                return $secret;
            }
        }

        if (function_exists('wp_salt')) {
            $secret = (string) wp_salt('auth');
            if ('' !== $secret) {
                return $secret;
            }
        }

        if (defined('AUTH_KEY')) {
            $secret = (string) AUTH_KEY;
            if ('' !== $secret) {
                return $secret;
            }
        }

        return 'kec-search-index';
    }

    private function countEntities(string $entity): int
    {
        if (!is_object($this->wpdb) || !method_exists($this->wpdb, 'get_var')) {
            return 0;
        }

        $property = '';
        switch ($entity) {
            case 'user':
                $property = 'users';
                break;
            case 'post':
                $property = 'posts';
                break;
            case 'term':
                $property = 'terms';
                break;
            case 'comment':
                $property = 'comments';
                break;
        }

        if ('' === $property || !isset($this->wpdb->{$property})) {
            return 0;
        }

        $table = (string) $this->wpdb->{$property};
        if ('' === $table) {
            return 0;
        }

        try {
            return (int) $this->wpdb->get_var('SELECT COUNT(*) FROM ' . $table);
        } catch (\Throwable $e) {
            return 0;
        }
    }

    /**
     * @return int[]
     */
    private function fetchIds(string $entity, int $limit, int $offset): array
    {
        switch ($entity) {
            case 'user':
                if (!function_exists('get_users')) {
                    return array();
                }
                $ids = get_users(array(
                    'fields' => 'ID',
                    'number' => $limit,
                    'offset' => $offset,
                    'orderby' => 'ID',
                    'order' => 'ASC',
                    'count_total' => false,
                ));
                break;

            case 'post':
                if (function_exists('get_posts')) {
                    $ids = get_posts(array(
                        'post_type' => 'any',
                        'post_status' => 'any',
                        'posts_per_page' => $limit,
                        'offset' => $offset,
                        'fields' => 'ids',
                        'orderby' => 'ID',
                        'order' => 'ASC',
                        'no_found_rows' => true,
                        'cache_results' => false,
                    ));
                } elseif (class_exists('\\WP_Query')) {
                    $query = new \WP_Query(array(
                        'post_type' => 'any',
                        'post_status' => 'any',
                        'posts_per_page' => $limit,
                        'offset' => $offset,
                        'fields' => 'ids',
                        'orderby' => 'ID',
                        'order' => 'ASC',
                        'no_found_rows' => true,
                    ));
                    $ids = $query->posts;
                } else {
                    return array();
                }
                break;

            case 'term':
                if (!function_exists('get_terms')) {
                    return array();
                }
                $taxonomies = function_exists('get_taxonomies') ? get_taxonomies() : array('category', 'post_tag');
                if (!is_array($taxonomies) || array() === $taxonomies) {
                    return array();
                }
                $ids = get_terms(array(
                    'taxonomy' => array_values($taxonomies),
                    'hide_empty' => false,
                    'fields' => 'ids',
                    'number' => $limit,
                    'offset' => $offset,
                    'orderby' => 'term_id',
                    'order' => 'ASC',
                ));
                if (function_exists('is_wp_error') && is_wp_error($ids)) {
                    return array();
                }
                break;

            case 'comment':
                if (!function_exists('get_comments')) {
                    return array();
                }
                $ids = get_comments(array(
                    'fields' => 'ids',
                    'number' => $limit,
                    'offset' => $offset,
                    'orderby' => 'comment_ID',
                    'order' => 'ASC',
                    'status' => 'all',
                ));
                break;

            default:
                return array();
        }

        if (!is_array($ids)) {
            return array();
        }

        $result = array();
        foreach ($ids as $id) {
            $id = (int) $id;
            if ($id > 0) {
                $result[] = $id;
            }
        }

        return $result;
    }

    private function logWarning(string $message, array $context = array()): void
    {
        try {
            $logger = $this->plugin->logger();
            if (is_object($logger) && method_exists($logger, 'warning')) {
                $logger->warning($message, $context);
            }
        } catch (\Throwable $e) {
            // Never surface failures from the logger.
        }
    }
}
