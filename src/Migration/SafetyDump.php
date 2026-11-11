<?php

namespace Koyo\EncryptedFields\Migration;

use Koyo\EncryptedFields\Plugin;

/**
 * Creates a best-effort SQL snapshot of the tables a migration will touch.
 *
 * This is not a full site backup. The dump can contain plaintext PII, so it is
 * written with 0600 permissions into a 0700 directory with web-server deny
 * rules. Prefer KEC_SAFETY_DUMP_DIR outside the web root on production.
 */
final class SafetyDump
{
    private const KEEP_FILES = 5;
    private const INSERT_ROWS = 100;
    private const SELECT_BATCH = 500;
    private const DEFAULT_MAX_BYTES = 67108864;
    private const DEFAULT_MAX_ROWS = 500000;

    /**
     * @param array<int, string> $tables
     * @param array<string, mixed> $options
     * @return array<string, mixed>
     */
    public static function create(Plugin $plugin, ?object $db, array $tables, array $options = array()): array
    {
        $db = Env::db($db);

        if (!is_object($db)
            || !method_exists($db, 'get_row')
            || !method_exists($db, 'get_results')
            || !method_exists($db, 'get_var')
        ) {
            return self::error('safety_dump_unavailable', 'Database helpers are not available for a safety dump.');
        }

        $tables = self::existingTables($db, $tables);

        if (array() === $tables) {
            return array('ok' => true, 'path' => null, 'tables' => array(), 'skipped' => true);
        }

        $maxBytes = self::maxBytes();
        $maxRows = self::maxRows();
        $counts = array();
        $totalRows = 0;

        foreach ($tables as $table) {
            $count = $db->get_var('SELECT COUNT(*) FROM `' . $table . '`');
            if (null === $count) {
                return self::error('safety_dump_unavailable', 'Could not count rows in ' . $table . '.');
            }

            $counts[$table] = (int) $count;
            $totalRows += (int) $count;
        }

        if ($maxRows > 0 && $totalRows > $maxRows) {
            return array(
                'ok' => false,
                'error' => 'safety_dump_too_large',
                'message' => sprintf(
                    'Safety dump would contain %d rows (limit %d). Run a full database backup manually and use --no-safety-dump.',
                    $totalRows,
                    $maxRows
                ),
                'rows' => $totalRows,
            );
        }

        $dir = self::directory();

        if (!self::ensureDirectory($dir)) {
            return self::error('safety_dump_unwritable', 'Could not create the safety dump directory: ' . $dir);
        }

        $file = $dir . '/kec-safety-' . gmdate('Ymd-His') . '-' . bin2hex(random_bytes(3)) . '.sql';
        $handle = @fopen($file, 'xb');

        if (false === $handle) {
            return self::error('safety_dump_unwritable', 'Could not create the safety dump file.');
        }

        @chmod($file, 0600);
        $bytes = 0;
        $writtenRows = 0;

        try {
            self::write($handle, "-- KEC safety dump\n", $bytes, $maxBytes);
            self::write($handle, '-- Created: ' . gmdate('c') . "\n", $bytes, $maxBytes);
            self::write($handle, '-- Tables: ' . implode(', ', $tables) . "\n", $bytes, $maxBytes);
            self::write($handle, "-- WARNING: may contain plaintext PII. Delete after use.\n\n", $bytes, $maxBytes);
            self::write($handle, "SET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\n\n", $bytes, $maxBytes);

            foreach ($tables as $table) {
                $create = $db->get_row('SHOW CREATE TABLE `' . $table . '`', defined('ARRAY_N') ? ARRAY_N : 'ARRAY_N');

                if (!is_array($create) || !isset($create[1]) || !is_string($create[1])) {
                    throw new \RuntimeException('Could not read schema for ' . $table);
                }

                self::write($handle, '-- Table: ' . $table . "\n", $bytes, $maxBytes);
                self::write($handle, 'DROP TABLE IF EXISTS `' . $table . "`;\n" . $create[1] . ";\n\n", $bytes, $maxBytes);

                $columns = self::columns($db, $table);
                if (array() === $columns) {
                    continue;
                }

                $offset = 0;

                while (true) {
                    $rows = $db->get_results(
                        'SELECT * FROM `' . $table . '` LIMIT ' . (int) $offset . ', ' . self::SELECT_BATCH,
                        defined('ARRAY_A') ? ARRAY_A : 'ARRAY_A'
                    );

                    if (!is_array($rows) || array() === $rows) {
                        break;
                    }

                    $values = array();

                    foreach ($rows as $row) {
                        $parts = array();

                        foreach ($columns as $column) {
                            $parts[] = self::quote($db, isset($row[$column]) ? $row[$column] : null);
                        }

                        $values[] = '(' . implode(',', $parts) . ')';
                        ++$writtenRows;

                        if (count($values) >= self::INSERT_ROWS) {
                            self::writeInsert($handle, $table, $columns, $values, $bytes, $maxBytes);
                            $values = array();
                        }
                    }

                    if (array() !== $values) {
                        self::writeInsert($handle, $table, $columns, $values, $bytes, $maxBytes);
                    }

                    $offset += count($rows);

                    if (count($rows) < self::SELECT_BATCH) {
                        break;
                    }
                }

                self::write($handle, "\n", $bytes, $maxBytes);
            }

            self::write($handle, "SET FOREIGN_KEY_CHECKS=1;\n-- End of KEC safety dump\n", $bytes, $maxBytes);
        } catch (\Throwable $exception) {
            fclose($handle);
            @unlink($file);

            return self::error('safety_dump_failed', 'Safety dump failed: ' . $exception->getMessage());
        }

        fclose($handle);
        @chmod($file, 0600);
        self::cleanup($dir, $file);

        $plugin->logger()->info('safety_dump_created', array(
            'file' => basename($file),
            'tables' => count($tables),
            'rows' => $writtenRows,
            'bytes' => $bytes,
        ));

        return array(
            'ok' => true,
            'path' => $file,
            'tables' => $tables,
            'rows' => $writtenRows,
            'bytes' => $bytes,
        );
    }

    /**
     * @param array<int, string> $tables
     * @return array<int, string>
     */
    private static function existingTables(object $db, array $tables): array
    {
        $result = array();

        foreach ($tables as $table) {
            $table = (string) $table;

            if ('' === $table
                || !preg_match('/^[A-Za-z0-9_]+$/', $table)
                || isset($result[$table])
            ) {
                continue;
            }

            try {
                $exists = method_exists($db, 'prepare')
                    ? $db->get_var($db->prepare('SHOW TABLES LIKE %s', $table))
                    : $db->get_var("SHOW TABLES LIKE '" . $table . "'");
            } catch (\Throwable $exception) {
                $exists = null;
            }

            if (!empty($exists)) {
                $result[$table] = $table;
            }
        }

        return array_values($result);
    }

    /**
     * @return array<int, string>
     */
    private static function columns(object $db, string $table): array
    {
        $rows = $db->get_results('SHOW COLUMNS FROM `' . $table . '`', defined('ARRAY_A') ? ARRAY_A : 'ARRAY_A');

        if (!is_array($rows)) {
            return array();
        }

        $columns = array();

        foreach ($rows as $row) {
            if (!is_array($row) || !isset($row['Field'])) {
                continue;
            }

            $column = (string) $row['Field'];

            if (preg_match('/^[A-Za-z0-9_]+$/', $column)) {
                $columns[] = $column;
            }
        }

        return $columns;
    }

    /**
     * @param array<int, string> $columns
     * @param array<int, string> $values
     */
    private static function writeInsert($handle, string $table, array $columns, array $values, int &$bytes, int $maxBytes): void
    {
        $sql = 'INSERT INTO `' . $table . '` (`' . implode('`,`', $columns) . '`) VALUES '
            . implode(',', $values) . ";\n";

        self::write($handle, $sql, $bytes, $maxBytes);
    }

    private static function write($handle, string $data, int &$bytes, int $maxBytes): void
    {
        if ($maxBytes > 0 && $bytes + strlen($data) > $maxBytes) {
            throw new \RuntimeException('Safety dump exceeds the configured size limit.');
        }

        $length = strlen($data);
        $written = 0;

        while ($written < $length) {
            $chunk = fwrite($handle, substr($data, $written));

            if (false === $chunk || 0 === $chunk) {
                throw new \RuntimeException('Could not write to the safety dump file.');
            }

            $written += $chunk;
        }

        $bytes += $length;
    }

    /**
     * @param mixed $value
     */
    private static function quote(object $db, $value): string
    {
        if (null === $value) {
            return 'NULL';
        }

        $value = (string) $value;

        if (function_exists('esc_sql')) {
            $value = esc_sql($value);
        } else {
            $value = str_replace(array('\\', "'"), array('\\\\', "''"), $value);
        }

        return "'" . $value . "'";
    }

    private static function directory(): string
    {
        if (defined('KEC_SAFETY_DUMP_DIR') && '' !== (string) constant('KEC_SAFETY_DUMP_DIR')) {
            return rtrim((string) constant('KEC_SAFETY_DUMP_DIR'), '/\\');
        }

        $base = defined('WP_CONTENT_DIR')
            ? (string) WP_CONTENT_DIR
            : sys_get_temp_dir();

        $dir = rtrim($base, '/\\') . '/kec-backups';

        if (function_exists('apply_filters')) {
            $filtered = apply_filters('kec_safety_dump_dir', $dir);
            if (is_string($filtered) && '' !== $filtered) {
                $dir = $filtered;
            }
        }

        return rtrim($dir, '/\\');
    }

    private static function ensureDirectory(string $dir): bool
    {
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            return false;
        }

        @chmod($dir, 0700);

        $htaccess = $dir . '/.htaccess';
        if (!is_file($htaccess)) {
            @file_put_contents($htaccess, "Require all denied\nDeny from all\n");
            @chmod($htaccess, 0600);
        }

        $index = $dir . '/index.php';
        if (!is_file($index)) {
            @file_put_contents($index, "<?php\n// Silence is golden.\n");
            @chmod($index, 0600);
        }

        return is_dir($dir) && is_writable($dir);
    }

    private static function cleanup(string $dir, string $current): void
    {
        $files = glob($dir . '/kec-safety-*.sql');

        if (!is_array($files) || count($files) <= self::KEEP_FILES) {
            return;
        }

        usort($files, static function (string $a, string $b): int {
            return (int) @filemtime($a) <=> (int) @filemtime($b);
        });

        foreach (array_slice($files, 0, count($files) - self::KEEP_FILES) as $file) {
            if ($file !== $current) {
                @unlink($file);
            }
        }
    }

    private static function maxBytes(): int
    {
        $value = self::DEFAULT_MAX_BYTES;

        if (function_exists('apply_filters')) {
            $value = (int) apply_filters('kec_safety_dump_max_bytes', $value);
        }

        return max(0, $value);
    }

    private static function maxRows(): int
    {
        $value = self::DEFAULT_MAX_ROWS;

        if (function_exists('apply_filters')) {
            $value = (int) apply_filters('kec_safety_dump_max_rows', $value);
        }

        return max(0, $value);
    }

    /**
     * @return array<string, mixed>
     */
    private static function error(string $code, string $message): array
    {
        return array('ok' => false, 'error' => $code, 'message' => $message);
    }
}
