<?php

namespace Koyo\EncryptedFields\Meta;

final class MetaCache
{
    /** @var array<string, array<int, array<string, array<int, mixed>>>> */
    private static array $memo = array();

    public static function get(string $type, int $id, string $key, ?bool &$found = null): array
    {
        $found = isset(self::$memo[$type][$id][$key]);

        return $found ? self::$memo[$type][$id][$key] : array();
    }

    public static function set(string $type, int $id, string $key, array $values): void
    {
        self::$memo[$type][$id][$key] = $values;
    }

    public static function forget(string $type, int $id, ?string $key = null): void
    {
        if (null === $key) {
            unset(self::$memo[$type][$id]);

            if (isset(self::$memo[$type]) && empty(self::$memo[$type])) {
                unset(self::$memo[$type]);
            }

            return;
        }

        unset(self::$memo[$type][$id][$key]);

        if (isset(self::$memo[$type][$id]) && empty(self::$memo[$type][$id])) {
            unset(self::$memo[$type][$id]);
        }

        if (isset(self::$memo[$type]) && empty(self::$memo[$type])) {
            unset(self::$memo[$type]);
        }
    }

    public static function clear(): void
    {
        self::$memo = array();
    }
}
