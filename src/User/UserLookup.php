<?php

namespace EncryptedFields\User;

use EncryptedFields\Config\Registry;
use EncryptedFields\Contracts\SearchInterface;
use EncryptedFields\Plugin;

/**
 * Replaces encrypted wp_users LIKE searches with blind-index lookups.
 *
 * WP_User_Query uses user_login LIKE / user_email LIKE for its search
 * argument. Encrypted columns cannot be matched with LIKE, so those clauses
 * are rewritten to ID IN (...) using the search index. display_name and
 * user_nicename stay as LIKE because they are stored in plaintext.
 */
final class UserLookup
{
    private Plugin $plugin;
    private bool $registered = false;

    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    public function register(): void
    {
        if ($this->registered || !function_exists('add_action')) {
            return;
        }

        $this->registered = true;

        if (!$this->hasUserColumns()) {
            return;
        }

        add_action('pre_user_query', array($this, 'filterUserQuery'), 10, 1);
    }

    /**
     * @param mixed $query
     */
    public function filterUserQuery($query): void
    {
        if (!is_object($query) || !isset($query->query_where) || !is_string($query->query_where)) {
            return;
        }

        if (!$this->hasUserColumns() || '' === $query->query_where) {
            return;
        }

        $search = $this->search();
        if (null === $search) {
            return;
        }

        try {
            $query->query_where = $this->rewriteLikes($query->query_where, $search);
        } catch (\Throwable $e) {
            $this->logWarning('User LIKE lookup rewrite failed.', array('error' => get_class($e)));
        }
    }

    public function rewriteLikes(string $where, SearchInterface $search): string
    {
        if (!$this->hasUserColumns()) {
            return $where;
        }

        $pattern = '/(?<![\w$.])(`?(?:user_login|user_email)`?)(?![\w`])\s+LIKE\s+('
            . $this->sqlStringPattern() . ')/i';

        $result = preg_replace_callback($pattern, function (array $match) use ($search): string {
            $value = $this->parseLiteral($match[2]);
            if (null === $value) {
                return $match[0];
            }

            $term = trim($value);
            $term = trim($term, '%');
            $term = $this->unescapeLike($term);
            $term = trim($term);

            if ('' === $term) {
                return $match[0];
            }

            try {
                $ids = $search->ids('user', $term);
            } catch (\Throwable $e) {
                return $match[0];
            }

            if (!is_array($ids)) {
                $ids = array();
            }

            $clean = array();
            foreach ($ids as $id) {
                $id = (int) $id;
                if ($id > 0) {
                    $clean[$id] = true;
                }
            }

            $list = array_keys($clean);
            sort($list, SORT_NUMERIC);

            $sqlList = array() === $list ? '0' : implode(', ', $list);

            return 'ID IN (' . $sqlList . ')';
        }, $where);

        return is_string($result) ? $result : $where;
    }

    private function search(): ?SearchInterface
    {
        try {
            $search = $this->plugin->search();
        } catch (\Throwable $e) {
            return null;
        }

        return $search instanceof SearchInterface ? $search : null;
    }

    private function hasUserColumns(): bool
    {
        $registry = $this->registry();
        if (null === $registry) {
            return false;
        }

        try {
            $columns = $registry->columns('user');
        } catch (\Throwable $e) {
            return false;
        }

        return isset($columns['user_login']) || isset($columns['user_email']);
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

    private function parseLiteral(string $literal): ?string
    {
        $literal = trim($literal);
        if ('' === $literal) {
            return null;
        }

        $quote = $literal[0];

        if ("'" !== $quote && '"' !== $quote) {
            return null;
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

    /**
     * Undo the LIKE escaping added by esc_like()/wpdb::prepare().
     * WP_User_Query escapes "_" and "%" so a literal search such as
     * "nhan_tt" arrives here as "nhan\\_tt"; strip that layer before
     * building the blind-index lookup.
     */
    private function unescapeLike(string $term): string
    {
        return str_replace(array('\\\\', '\\_', '\\%'), array('\\', '_', '%'), $term);
    }

    private function sqlStringPattern(): string
    {
        return "'(?:[^'\\\\]|\\\\.|'')*'|\"(?:[^\"\\\\]|\\\\.|\"\")*\"";
    }

    private function logWarning(string $message, array $context = array()): void
    {
        try {
            $this->plugin->logger()->warning($message, $context);
        } catch (\Throwable $ignored) {
            // Logging must never break user queries.
        }
    }
}
