<?php

namespace Koyo\EncryptedFields\Support;

final class Logger
{
    private const OPTION = 'kec_logs';
    private const MAX_ENTRIES = 200;

    public function info(string $message, array $context = array()): void
    {
        $this->write('info', $message, $context);
    }

    public function warning(string $message, array $context = array()): void
    {
        $this->write('warning', $message, $context);
    }

    public function error(string $message, array $context = array()): void
    {
        $this->write('error', $message, $context);
    }

    public function recent(int $limit = 50): array
    {
        $logs = function_exists('get_option') ? get_option(self::OPTION, array()) : array();
        if (!is_array($logs)) {
            return array();
        }
        return array_slice($logs, -$limit);
    }

    public function clear(): void
    {
        if (function_exists('update_option')) {
            update_option(self::OPTION, array(), false);
        }
    }

    private function write(string $level, string $message, array $context): void
    {
        $entry = array(
            'time' => function_exists('current_time') ? current_time('mysql', true) : gmdate('Y-m-d H:i:s'),
            'level' => $level,
            'message' => $message,
            'context' => $context,
        );

        if (defined('KEC_DEBUG') && KEC_DEBUG) {
            error_log('[encrypted-fields] ' . $level . ': ' . $message . ' ' . wp_json_encode($context));
        }

        if (!function_exists('get_option') || !function_exists('update_option')) {
            return;
        }

        $logs = get_option(self::OPTION, array());
        if (!is_array($logs)) {
            $logs = array();
        }
        $logs[] = $entry;
        if (count($logs) > self::MAX_ENTRIES) {
            $logs = array_slice($logs, -self::MAX_ENTRIES);
        }
        update_option(self::OPTION, $logs, false);
    }
}
