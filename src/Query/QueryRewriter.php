<?php

namespace Koyo\EncryptedFields\Query;

use Koyo\EncryptedFields\Config\Field;
use Koyo\EncryptedFields\Config\Registry;
use Koyo\EncryptedFields\Plugin;
use Koyo\EncryptedFields\User\ColumnStore;

/**
 * Rewrites bare wp_users.user_login / user_email equality lookups so core
 * functions such as get_user_by('email') and username_exists() keep working.
 *
 * Only the main table is considered. Table aliases, table-qualified columns,
 * LIKE comparisons, SELECT lists and other tables are never rewritten.
 */
final class QueryRewriter
{
    private Plugin $plugin;
    private bool $registered = false;

    private static int $suspendDepth = 0;

    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

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

    public function register(): void
    {
        if ($this->registered || !function_exists('add_filter')) {
            return;
        }

        $this->registered = true;

        if (!$this->hasUserColumns()) {
            return;
        }

        add_filter('query', array($this, 'filterQuery'), 10, 1);
    }

    /**
     * @param mixed $query
     *
     * @return mixed
     */
    public function filterQuery($query)
    {
        if (!is_string($query) || '' === $query) {
            return $query;
        }

        if (self::$suspendDepth > 0 || !$this->enabled() || !$this->hasUserColumns()) {
            return $query;
        }

        try {
            return $this->rewrite($query);
        } catch (\Throwable $e) {
            $this->logWarning('User query rewrite failed.', array('error' => get_class($e)));

            return $query;
        }
    }

    public function rewrite(string $sql): string
    {
        if ('' === $sql || !$this->mainTableIsUsers($sql)) {
            return $sql;
        }

        $start = $this->rewriteStart($sql);
        if (null === $start) {
            return $sql;
        }

        $segment = substr($sql, $start);
        $rewritten = $this->rewriteEquals($segment);
        $rewritten = $this->rewriteInLists($rewritten);

        if ($rewritten === $segment) {
            return $sql;
        }

        return substr($sql, 0, $start) . $rewritten;
    }

    private function rewriteEquals(string $segment): string
    {
        $pattern = '/(?<![\w$.])(`?(?:user_login|user_email)`?)(?![\w`])\s*=\s*('
            . $this->sqlStringPattern() . ')/i';

        $result = preg_replace_callback($pattern, function (array $match): string {
            $name = $this->columnName($match[1]);
            $store = $this->store();

            if (null === $name || null === $store) {
                return $match[0];
            }

            $plain = $this->parseLiteral($match[2]);
            if (null === $plain) {
                return $match[0];
            }

            $token = $store->lookupToken($plain, $name);
            if (null === $token || '' === $token || $token === $plain) {
                return $match[0];
            }

            return $match[1] . ' = ' . $this->quoteLiteral($token);
        }, $segment);

        return is_string($result) ? $result : $segment;
    }

    private function rewriteInLists(string $segment): string
    {
        $pattern = '/(?<![\w$.])(`?(user_login|user_email)`?)(?![\w`])\s+IN\s*\(/i';
        $offset = 0;

        while (preg_match($pattern, $segment, $match, PREG_OFFSET_CAPTURE, $offset)) {
            $matchStart = (int) $match[0][1];
            $matchText = (string) $match[0][0];
            $openPos = $matchStart + strlen($matchText) - 1;

            $closePos = $this->findMatchingParen($segment, $openPos);
            if (null === $closePos) {
                break;
            }

            $column = (string) $match[1][0];
            $name = $this->columnName((string) $match[2][0]);
            $store = $this->store();

            if (null === $name || null === $store) {
                $offset = $closePos + 1;
                continue;
            }

            $list = substr($segment, $openPos + 1, $closePos - $openPos - 1);
            $items = $this->splitList($list);

            if (null === $items) {
                $offset = $closePos + 1;
                continue;
            }

            $newItems = array();
            $changed = false;

            foreach ($items as $item) {
                $trimmed = trim($item);

                if ('' === $trimmed) {
                    continue;
                }

                $plain = $this->parseLiteral($trimmed);

                if (null === $plain) {
                    $newItems[] = $trimmed;
                    continue;
                }

                $token = $store->lookupToken($plain, $name);
                if (null === $token || '' === $token || $token === $plain) {
                    $newItems[] = $trimmed;
                    continue;
                }

                $newItems[] = $this->quoteLiteral($token);
                $changed = true;
            }

            if (!$changed) {
                $offset = $closePos + 1;
                continue;
            }

            $replacement = $column . ' IN (' . implode(', ', $newItems) . ')';
            $segment = substr($segment, 0, $matchStart)
                . $replacement
                . substr($segment, $closePos + 1);

            $offset = $matchStart + strlen($replacement);
        }

        return $segment;
    }

    private function mainTableIsUsers(string $sql): bool
    {
        $table = $this->usersTable();
        if ('' === $table) {
            return false;
        }

        $keywords = $this->topLevelKeywords($sql);
        $main = null;

        foreach ($keywords as $entry) {
            if (in_array($entry[0], array('FROM', 'UPDATE', 'INTO'), true)) {
                $main = $entry;
                break;
            }
        }

        if (null === $main) {
            return false;
        }

        $rest = substr($sql, $main[1] + strlen($main[0]));
        $pattern = '/^\s+`?' . preg_quote($table, '/') . '`?(?![\w`])/i';

        if (!preg_match($pattern, $rest, $match)) {
            return false;
        }

        return !$this->hasTableAlias(substr($rest, strlen($match[0])));
    }

    /**
     * Comparisons in a SELECT list must not be rewritten. For SELECT queries
     * rewriting starts at the main FROM; UPDATE/INSERT/DELETE are processed
     * from the beginning (which covers SET and ON DUPLICATE KEY UPDATE).
     */
    private function rewriteStart(string $sql): ?int
    {
        $keywords = $this->topLevelKeywords($sql);

        $mainPos = null;
        foreach ($keywords as $entry) {
            if (in_array($entry[0], array('FROM', 'UPDATE', 'INTO'), true)) {
                $mainPos = $entry[1];
                break;
            }
        }

        if (null === $mainPos) {
            return null;
        }

        foreach ($keywords as $entry) {
            if ($entry[1] < $mainPos && 'SELECT' === $entry[0]) {
                return $mainPos;
            }
        }

        return 0;
    }

    /**
     * Returns the SQL keywords found outside strings, identifiers and
     * parentheses. Used to find the main table and the main WHERE clause.
     *
     * @return array<int, array{0:string,1:int}>
     */
    private function topLevelKeywords(string $sql): array
    {
        $keywords = array();
        $length = strlen($sql);
        $depth = 0;
        $quote = null;

        for ($i = 0; $i < $length; $i++) {
            $char = $sql[$i];

            if (null !== $quote) {
                if ('\\' === $char && '`' !== $quote) {
                    $i++;
                    continue;
                }

                if ($char === $quote) {
                    if ($i + 1 < $length && $sql[$i + 1] === $quote) {
                        $i++;
                        continue;
                    }
                    $quote = null;
                }

                continue;
            }

            if ("'" === $char || '"' === $char || '`' === $char) {
                $quote = $char;
                continue;
            }

            if ('(' === $char) {
                $depth++;
                continue;
            }

            if (')' === $char) {
                $depth = max(0, $depth - 1);
                continue;
            }

            if (0 === $depth && (ctype_alpha($char) || '_' === $char)) {
                $start = $i;
                while ($i + 1 < $length && (ctype_alnum($sql[$i + 1]) || '_' === $sql[$i + 1])) {
                    $i++;
                }
                $keywords[] = array(strtoupper(substr($sql, $start, $i - $start + 1)), $start);
            }
        }

        return $keywords;
    }

    private function hasTableAlias(string $rest): bool
    {
        $trimmed = ltrim($rest);
        if ('' === $trimmed) {
            return false;
        }

        $first = $trimmed[0];
        if ('(' === $first || ';' === $first || '/' === $first || '-' === $first) {
            return false;
        }

        if ('`' === $first) {
            return true;
        }

        if (!preg_match('/^([A-Za-z_]+)/', $trimmed, $match)) {
            return false;
        }

        $word = strtoupper($match[1]);

        $keywords = array(
            'WHERE', 'ORDER', 'GROUP', 'LIMIT', 'HAVING', 'JOIN', 'LEFT',
            'RIGHT', 'INNER', 'OUTER', 'CROSS', 'STRAIGHT_JOIN', 'NATURAL',
            'ON', 'USING', 'SET', 'VALUES', 'VALUE', 'FOR', 'LOCK', 'UNION',
            'PROCEDURE', 'INTO', 'RETURNING', 'WINDOW', 'PARTITION', 'USE',
            'IGNORE', 'FORCE',
        );

        if ('AS' === $word) {
            return true;
        }

        return !in_array($word, $keywords, true);
    }

    private function fieldForColumn(string $column): ?Field
    {
        $column = strtolower(trim($column, " \t\n\r\0\x0B`"));

        if ('user_login' !== $column && 'user_email' !== $column) {
            return null;
        }

        $registry = $this->registry();
        if (null === $registry) {
            return null;
        }

        try {
            $columns = $registry->columns('user');
        } catch (\Throwable $e) {
            return null;
        }

        return isset($columns[$column]) ? $columns[$column] : null;
    }

    private function columnName(string $column): ?string
    {
        $column = strtolower(trim($column, " \t\n\r\0\x0B`"));

        if ('user_login' === $column) {
            return ColumnStore::LOGIN;
        }

        if ('user_email' === $column) {
            return ColumnStore::EMAIL;
        }

        return null;
    }

    private function hasUserColumns(): bool
    {
        return null !== $this->fieldForColumn('user_login')
            || null !== $this->fieldForColumn('user_email');
    }

    private function enabled(): bool
    {
        return (bool) apply_filters('kec_enable_query_rewrite', true);
    }

    private function usersTable(): string
    {
        global $wpdb;

        if (!is_object($wpdb) || !isset($wpdb->users) || !is_string($wpdb->users)) {
            return '';
        }

        return $wpdb->users;
    }

    private function parseLiteral(string $literal): ?string
    {
        $literal = trim($literal);
        if ('' === $literal) {
            return null;
        }

        $quote = $literal[0];

        if ("'" !== $quote && '"' !== $quote) {
            if (preg_match('/^(?:NULL|TRUE|FALSE)$/i', $literal)) {
                return null;
            }

            if (!preg_match('/^[A-Za-z0-9_.@+\-]+$/', $literal)) {
                return null;
            }

            return $literal;
        }

        if (substr($literal, -1) !== $quote) {
            return null;
        }

        $inner = substr($literal, 1, -1);
        $length = strlen($inner);
        $result = '';

        for ($i = 0; $i < $length; $i++) {
            $char = $inner[$i];

            if ('\\' === $char && $i + 1 < $length) {
                $next = $inner[++$i];
                $map = array(
                    '0' => "\0",
                    'b' => "\x08",
                    'n' => "\n",
                    'r' => "\r",
                    't' => "\t",
                    'Z' => "\x1a",
                );
                $result .= array_key_exists($next, $map) ? $map[$next] : $next;
                continue;
            }

            if ($char === $quote) {
                if ($i + 1 < $length && $inner[$i + 1] === $quote) {
                    $result .= $quote;
                    $i++;
                    continue;
                }

                return null;
            }

            $result .= $char;
        }

        return $result;
    }

    private function findMatchingParen(string $sql, int $openPos): ?int
    {
        $length = strlen($sql);
        $depth = 0;
        $quote = null;

        for ($i = $openPos; $i < $length; $i++) {
            $char = $sql[$i];

            if (null !== $quote) {
                if ('\\' === $char && '`' !== $quote) {
                    $i++;
                    continue;
                }

                if ($char === $quote) {
                    if ($i + 1 < $length && $sql[$i + 1] === $quote) {
                        $i++;
                        continue;
                    }
                    $quote = null;
                }

                continue;
            }

            if ("'" === $char || '"' === $char || '`' === $char) {
                $quote = $char;
                continue;
            }

            if ('(' === $char) {
                $depth++;
                continue;
            }

            if (')' === $char) {
                $depth--;
                if (0 === $depth) {
                    return $i;
                }
                if ($depth < 0) {
                    return null;
                }
            }
        }

        return null;
    }

    /**
     * @return string[]|null
     */
    private function splitList(string $list): ?array
    {
        $items = array();
        $length = strlen($list);
        $start = 0;
        $depth = 0;
        $quote = null;

        for ($i = 0; $i < $length; $i++) {
            $char = $list[$i];

            if (null !== $quote) {
                if ('\\' === $char && '`' !== $quote) {
                    $i++;
                    continue;
                }

                if ($char === $quote) {
                    if ($i + 1 < $length && $list[$i + 1] === $quote) {
                        $i++;
                        continue;
                    }
                    $quote = null;
                }

                continue;
            }

            if ("'" === $char || '"' === $char || '`' === $char) {
                $quote = $char;
                continue;
            }

            if ('(' === $char) {
                $depth++;
                continue;
            }

            if (')' === $char) {
                $depth--;
                continue;
            }

            if (',' === $char && 0 === $depth) {
                $items[] = substr($list, $start, $i - $start);
                $start = $i + 1;
            }
        }

        if (null !== $quote) {
            return null;
        }

        $items[] = substr($list, $start);

        return $items;
    }

    private function sqlStringPattern(): string
    {
        return "'(?:[^'\\\\]|\\\\.|'')*'|\"(?:[^\"\\\\]|\\\\.|\"\")*\"";
    }

    private function quoteLiteral(string $value): string
    {
        return "'" . str_replace(array('\\', "'"), array('\\\\', "''"), $value) . "'";
    }

    private function store(): ?ColumnStore
    {
        try {
            return new ColumnStore($this->plugin);
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function registry(): ?Registry
    {
        try {
            $registry = $this->plugin->registry();
        } catch (\Throwable $e) {
            return null;
        }

        return $registry instanceof Registry ? $registry : null;
    }

    private function logWarning(string $message, array $context = array()): void
    {
        try {
            $this->plugin->logger()->warning($message, $context);
        } catch (\Throwable $ignored) {
            // Logging must never break a query.
        }
    }
}
