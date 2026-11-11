<?php

namespace EncryptedFields\Meta;

use EncryptedFields\Plugin;

final class MetaWriteGuard
{
    private const TABLES = array(
        'postmeta' => array('entity' => 'post', 'id_column' => 'meta_id'),
        'usermeta' => array('entity' => 'user', 'id_column' => 'umeta_id'),
        'termmeta' => array('entity' => 'term', 'id_column' => 'meta_id'),
        'commentmeta' => array('entity' => 'comment', 'id_column' => 'meta_id'),
    );

    private const PATTERN = '/^\s*UPDATE\s+`?([A-Za-z0-9_$]+)`?\s+SET\s+`?meta_value`?\s*=\s*\'((?:[^\'\\\\]|\\\\.|\'\')*)\'\s+WHERE\s+`?(meta_id|umeta_id)`?\s*(?:=\s*(\d+)|IN\s*\(\s*([0-9,\s]+)\s*\))\s*;?\s*$/is';

    private Plugin $plugin;
    private bool $registered = false;

    private static bool $busy = false;

    private static int $suspendDepth = 0;

    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    /**
     * Temporarily stop the guard from re-encrypting raw UPDATE queries.
     *
     * Used by migration/rollback, which intentionally write plaintext.
     */
    public static function suspend(): void
    {
        ++self::$suspendDepth;
    }

    public static function resume(): void
    {
        if (self::$suspendDepth > 0) {
            --self::$suspendDepth;
        }
    }

    public static function isSuspended(): bool
    {
        return self::$suspendDepth > 0;
    }

    public function register(): void
    {
        if ($this->registered || !function_exists('add_filter')) {
            return;
        }

        $this->registered = true;

        add_filter('query', array($this, 'filterQuery'), 10, 1);
    }

    public function filterQuery($query)
    {
        if (!is_string($query) || '' === $query || self::$busy || self::$suspendDepth > 0) {
            return $query;
        }

        try {
            return $this->rewrite($query);
        } catch (\Throwable $e) {
            $this->logWarning('Meta query rewrite failed.', array('error' => get_class($e)));

            return $query;
        }
    }

    public function rewrite(string $sql): string
    {
        $parsed = $this->parse($sql);
        if (null === $parsed) {
            return $sql;
        }

        $target = $this->tableTarget($parsed['table']);
        if (null === $target) {
            return $sql;
        }

        $registry = $this->plugin->registry();
        if (!$registry->isEnabled()) {
            return $sql;
        }

        $metaKey = $this->resolveMetaKey($target, $parsed);
        if (null === $metaKey) {
            return $sql;
        }

        $entity = $target['entity'];
        $field = $registry->get($entity, $metaKey);

        if (null === $field || $registry->isReadonly($entity, $metaKey)) {
            return $sql;
        }

        $context = array(
            'entity' => $entity,
            'key' => $metaKey,
            'operation' => 'write',
        );

        if (!apply_filters('kec_should_encrypt', true, $entity, $metaKey, $context)) {
            return $sql;
        }

        $plaintext = $this->unescapeLiteral($parsed['literal']);

        if ('' === $plaintext) {
            return $sql;
        }

        try {
            $crypto = $this->plugin->crypto();

            if ($crypto->isEncrypted($plaintext)) {
                return $sql;
            }

            $ciphertext = $crypto->encrypt($plaintext, $field);
        } catch (\Throwable $e) {
            $this->logWarning(
                'Meta query encryption failed.',
                array(
                    'entity' => $entity,
                    'key' => $metaKey,
                    'error' => get_class($e) . ' (' . $e->getCode() . ')',
                )
            );

            return $sql;
        }

        if (!is_string($ciphertext) || '' === $ciphertext || $ciphertext === $plaintext) {
            return $sql;
        }

        $escaped = function_exists('esc_sql') ? esc_sql($ciphertext) : addslashes($ciphertext);

        return substr($sql, 0, $parsed['literal_offset'])
            . $escaped
            . substr($sql, $parsed['literal_offset'] + strlen($parsed['literal']));
    }

    private function parse(string $sql): ?array
    {
        if (!preg_match(self::PATTERN, $sql, $matches, PREG_OFFSET_CAPTURE)) {
            return null;
        }

        $ids = array();

        if (isset($matches[4]) && '' !== $matches[4][0]) {
            $ids[] = (int) $matches[4][0];
        } elseif (isset($matches[5]) && '' !== $matches[5][0]) {
            foreach (preg_split('/\s*,\s*/', trim($matches[5][0])) as $id) {
                if ('' !== $id) {
                    $ids[] = (int) $id;
                }
            }
        }

        if (empty($ids)) {
            return null;
        }

        return array(
            'table' => $matches[1][0],
            'literal' => $matches[2][0],
            'literal_offset' => $matches[2][1],
            'id_column' => $matches[3][0],
            'ids' => $ids,
        );
    }

    private function tableTarget(string $table): ?array
    {
        $lower = strtolower($table);

        foreach (self::TABLES as $suffix => $target) {
            if ($lower === $suffix || substr($lower, -strlen($suffix)) === $suffix) {
                return $target;
            }
        }

        return null;
    }

    private function resolveMetaKey(array $target, array $parsed): ?string
    {
        $keys = array();

        foreach ($parsed['ids'] as $metaId) {
            $key = $this->lookupMetaKey($parsed['table'], $parsed['id_column'], $metaId);

            if (null === $key || '' === $key) {
                return null;
            }

            $keys[$key] = true;
        }

        if (1 !== count($keys)) {
            return null;
        }

        return (string) array_key_first($keys);
    }

    private function lookupMetaKey(string $table, string $idColumn, int $metaId): ?string
    {
        global $wpdb;

        if (!is_object($wpdb) || !method_exists($wpdb, 'get_var') || !method_exists($wpdb, 'prepare')) {
            return null;
        }

        self::$busy = true;

        try {
            $sql = $wpdb->prepare(
                'SELECT meta_key FROM `' . $table . '` WHERE `' . $idColumn . '` = %d',
                $metaId
            );
            $key = $wpdb->get_var($sql);
        } finally {
            self::$busy = false;
        }

        return is_string($key) && '' !== $key ? $key : null;
    }

    private function unescapeLiteral(string $literal): string
    {
        if ('' === $literal) {
            return '';
        }

        $result = '';
        $length = strlen($literal);

        for ($i = 0; $i < $length; ++$i) {
            $char = $literal[$i];

            if ("'" === $char && $i + 1 < $length && "'" === $literal[$i + 1]) {
                $result .= "'";
                ++$i;
                continue;
            }

            if ('\\' !== $char || $i + 1 >= $length) {
                $result .= $char;
                continue;
            }

            $next = $literal[++$i];

            switch ($next) {
                case '0':
                    $result .= "\0";
                    break;
                case 'b':
                    $result .= "\x08";
                    break;
                case 'n':
                    $result .= "\n";
                    break;
                case 'r':
                    $result .= "\r";
                    break;
                case 't':
                    $result .= "\t";
                    break;
                case 'Z':
                    $result .= "\x1a";
                    break;
                case '%':
                    $result .= '\\%';
                    break;
                case '_':
                    $result .= '\\_';
                    break;
                default:
                    $result .= $next;
                    break;
            }
        }

        return $result;
    }

    private function logWarning(string $message, array $context = array()): void
    {
        try {
            $this->plugin->logger()->warning($message, $context);
        } catch (\Throwable $ignored) {
        }
    }
}
