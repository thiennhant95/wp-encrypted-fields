<?php

namespace EncryptedFields\Meta;

use EncryptedFields\Config\Field;
use EncryptedFields\Plugin;

final class MetaHooks
{
    private const META_TYPES = array('post', 'user', 'term', 'comment');

    private Plugin $plugin;
    private bool $registered = false;

    private static bool $busy = false;
    private static bool $reading = false;

    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    public function register(): void
    {
        if ($this->registered) {
            return;
        }

        $this->registered = true;

        foreach (self::META_TYPES as $type) {
            add_filter(
                'get_' . $type . '_metadata',
                function ($check, $objectId, $metaKey, $single, $metaType) use ($type) {
                    return $this->filterGet($check, (int) $objectId, (string) $metaKey, (bool) $single, $type);
                },
                10,
                5
            );

            add_filter(
                'add_' . $type . '_metadata',
                function ($check, $objectId, $metaKey, $metaValue, $unique) use ($type) {
                    return $this->filterAdd($check, (int) $objectId, (string) $metaKey, $metaValue, (bool) $unique, $type);
                },
                10,
                5
            );

            add_filter(
                'update_' . $type . '_metadata',
                function ($check, $objectId, $metaKey, $metaValue, $prevValue) use ($type) {
                    return $this->filterUpdate($check, (int) $objectId, (string) $metaKey, $metaValue, $prevValue, $type);
                },
                10,
                5
            );
        }

        $guard = new MetaWriteGuard($this->plugin);
        $guard->register();
    }

    /**
     * @param mixed $check
     *
     * @return mixed
     */
    private function filterGet($check, int $objectId, string $metaKey, bool $single, string $metaType)
    {
        if (null !== $check || self::$reading) {
            return $check;
        }

        $registry = $this->plugin->registry();

        if (!$registry->isEnabled()) {
            return $check;
        }

        if ('' !== $metaKey && !$registry->has($metaType, $metaKey)) {
            return $check;
        }

        self::$reading = true;

        try {
            $cache = $this->rawMetaCache($metaType, $objectId);

            if (!is_array($cache)) {
                return $check;
            }

            if ('' === $metaKey) {
                return $this->readBulk($metaType, $objectId, $cache);
            }

            if (!isset($cache[$metaKey]) || !is_array($cache[$metaKey])) {
                return $check;
            }

            $field = $registry->get($metaType, $metaKey);
            if (null === $field) {
                return $check;
            }

            $context = $this->context($metaType, $objectId, $field, 'read');
            if (!$this->shouldHandle($metaType, $field, $context)) {
                return $check;
            }

            $values = $this->decryptValues($cache[$metaKey], $field, true, $metaType, $objectId, $metaKey);

            if ($single) {
                $value = isset($values[0]) ? $values[0] : '';

                // WordPress unwraps an array returned by get_*_metadata with
                // $check[0]; wrap array meta so it survives that unwrapping.
                return is_array($value) ? array($value) : $value;
            }

            return $values;
        } finally {
            self::$reading = false;
        }
    }

    /**
     * @param mixed $check
     * @param mixed $metaValue
     *
     * @return mixed
     */
    private function filterAdd($check, int $objectId, string $metaKey, $metaValue, bool $unique, string $metaType)
    {
        if (null !== $check || self::$busy) {
            return $check;
        }

        $registry = $this->plugin->registry();

        if (!$registry->isEnabled()) {
            return $check;
        }

        $field = $registry->get($metaType, $metaKey);
        if (null === $field || $registry->isReadonly($metaType, $metaKey)) {
            return $check;
        }

        $context = $this->context($metaType, $objectId, $field, 'write');
        if (!$this->shouldHandle($metaType, $field, $context)) {
            return $check;
        }

        $prepared = $this->prepareMetaValue($metaValue, $metaType, $metaKey);

        if (null === $prepared) {
            return $check;
        }

        $encrypted = $this->encrypt($prepared, $field, $metaType, $metaKey);
        if (false === $encrypted) {
            return false;
        }

        self::$busy = true;

        try {
            $result = add_metadata($metaType, $objectId, $metaKey, $encrypted, $unique);
        } finally {
            self::$busy = false;
        }

        MetaCache::forget($metaType, $objectId, $metaKey);

        return $result;
    }

    /**
     * @param mixed $check
     * @param mixed $metaValue
     * @param mixed $prevValue
     *
     * @return mixed
     */
    private function filterUpdate($check, int $objectId, string $metaKey, $metaValue, $prevValue, string $metaType)
    {
        if (null !== $check || self::$busy) {
            return $check;
        }

        $registry = $this->plugin->registry();

        if (!$registry->isEnabled()) {
            return $check;
        }

        $field = $registry->get($metaType, $metaKey);
        if (null === $field || $registry->isReadonly($metaType, $metaKey)) {
            return $check;
        }

        $context = $this->context($metaType, $objectId, $field, 'write');
        if (!$this->shouldHandle($metaType, $field, $context)) {
            return $check;
        }

        $prepared = $this->prepareMetaValue($metaValue, $metaType, $metaKey);

        if (null === $prepared) {
            return $check;
        }

        $encrypted = $this->encrypt($prepared, $field, $metaType, $metaKey);
        if (false === $encrypted) {
            return false;
        }

        self::$busy = true;

        try {
            $result = update_metadata($metaType, $objectId, $metaKey, $encrypted, $prevValue);
        } finally {
            self::$busy = false;
        }

        MetaCache::forget($metaType, $objectId, $metaKey);

        return $result;
    }

    private function rawMetaCache(string $metaType, int $objectId): ?array
    {
        $group = $metaType . '_meta';
        $cache = function_exists('wp_cache_get') ? wp_cache_get($objectId, $group) : false;

        if (!is_array($cache)) {
            if (function_exists('update_meta_cache')) {
                $updated = update_meta_cache($metaType, array($objectId));

                if (is_array($updated) && isset($updated[$objectId]) && is_array($updated[$objectId])) {
                    $cache = $updated[$objectId];
                }
            }

            if (!is_array($cache) && function_exists('wp_cache_get')) {
                $cache = wp_cache_get($objectId, $group);
            }
        }

        return is_array($cache) ? $cache : null;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function readBulk(string $metaType, int $objectId, array $cache): ?array
    {
        $registry = $this->plugin->registry();
        $result = array();
        $handled = false;

        foreach ($cache as $key => $rawValues) {
            $key = (string) $key;
            $field = $registry->get($metaType, $key);

            if (null === $field) {
                $result[$key] = $rawValues;
                continue;
            }

            $context = $this->context($metaType, $objectId, $field, 'read');
            if (!$this->shouldHandle($metaType, $field, $context)) {
                $result[$key] = $rawValues;
                continue;
            }

            $handled = true;
            $result[$key] = $this->decryptValues(
                is_array($rawValues) ? $rawValues : array($rawValues),
                $field,
                false,
                $metaType,
                $objectId,
                $key
            );
        }

        return $handled ? $result : null;
    }

    /**
     * @return array<int, mixed>
     */
    private function decryptValues(
        array $rawValues,
        Field $field,
        bool $unserialize,
        string $metaType,
        int $objectId,
        string $metaKey
    ): array {
        $found = false;
        $memo = MetaCache::get($metaType, $objectId, $metaKey, $found);
        $result = array();
        $newMemo = $memo;
        $memoChanged = false;

        foreach ($rawValues as $index => $raw) {
            $value = ($unserialize && function_exists('maybe_unserialize'))
                ? maybe_unserialize($raw)
                : $raw;

            if (is_string($value) && '' !== $value && $this->isEncrypted($value)) {
                if ($found && array_key_exists($index, $newMemo)) {
                    $result[$index] = $newMemo[$index];
                    continue;
                }

                $decrypted = $this->decrypt($value, $field, $metaType, $metaKey);

                if (function_exists('maybe_unserialize')) {
                    $decrypted = maybe_unserialize($decrypted);
                }

                $result[$index] = $decrypted;

                if ($decrypted !== $value) {
                    $newMemo[$index] = $decrypted;
                    $memoChanged = true;
                }
            } else {
                $result[$index] = $value;
            }
        }

        if ($memoChanged) {
            MetaCache::set($metaType, $objectId, $metaKey, $newMemo);
        }

        return $result;
    }

    private function isEncrypted(string $value): bool
    {
        try {
            return $this->plugin->crypto()->isEncrypted($value);
        } catch (\Throwable $e) {
            return false;
        }
    }

    private function decrypt(string $value, Field $field, string $metaType, string $metaKey): string
    {
        try {
            return $this->plugin->crypto()->decrypt($value, $field);
        } catch (\Throwable $e) {
            $this->log('warning', 'Meta decryption failed', $metaType, $metaKey, $e);

            return $value;
        }
    }

    private function encrypt(string $value, Field $field, string $metaType, string $metaKey)
    {
        try {
            $crypto = $this->plugin->crypto();

            if ($crypto->isEncrypted($value)) {
                return $value;
            }

            return $crypto->encrypt($value, $field);
        } catch (\Throwable $e) {
            $this->log('warning', 'Meta encryption failed', $metaType, $metaKey, $e);

            return false;
        }
    }

    private function context(string $metaType, int $objectId, Field $field, string $operation): array
    {
        $context = array(
            'entity' => $metaType,
            'key' => $field->key(),
            'operation' => $operation,
        );

        if ('post' === $metaType) {
            $context['post_type'] = $this->postType($objectId);
        }

        return $context;
    }

    private function shouldHandle(string $metaType, Field $field, array $context): bool
    {
        if ('post' === $metaType) {
            $postTypes = $field->postTypes();

            if (!empty($postTypes)) {
                $postType = isset($context['post_type']) ? $context['post_type'] : false;

                if (!is_string($postType) || '' === $postType || !in_array($postType, $postTypes, true)) {
                    return false;
                }
            }
        }

        return (bool) apply_filters('kec_should_encrypt', true, $metaType, $field->key(), $context);
    }

    /**
     * @return string|false
     */
    private function postType(int $objectId)
    {
        if (!function_exists('get_post_type')) {
            return false;
        }

        try {
            return get_post_type($objectId);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Turn scalar strings and arrays/objects into a value we can encrypt.
     * Arrays are serialized first; the read path unserializes after decrypt.
     *
     * @param mixed $metaValue
     */
    private function prepareMetaValue($metaValue, string $metaType, string $metaKey): ?string
    {
        if (is_string($metaValue)) {
            if ('' === $metaValue) {
                $this->logWarning('Meta value skipped', $metaType, $metaKey, array('reason' => 'empty'));

                return null;
            }

            return $metaValue;
        }

        if (is_array($metaValue) || is_object($metaValue)) {
            try {
                return serialize($metaValue);
            } catch (\Throwable $exception) {
                $this->logWarning('Meta value skipped', $metaType, $metaKey, array('reason' => 'serialize_failed'));

                return null;
            }
        }

        $this->logWarning('Meta value skipped', $metaType, $metaKey, array(
            'reason' => 'non-string',
            'value_type' => gettype($metaValue),
        ));

        return null;
    }

    private function logWarning(string $message, string $metaType, string $metaKey, array $context = array()): void
    {
        $context = array_merge(array('entity' => $metaType, 'key' => $metaKey), $context);

        try {
            $this->plugin->logger()->warning($message, $context);
        } catch (\Throwable $ignored) {
            // Logging must never break meta operations.
        }
    }

    private function log(string $level, string $message, string $metaType, string $metaKey, \Throwable $error): void
    {
        $context = array(
            'entity' => $metaType,
            'key' => $metaKey,
            'error' => get_class($error) . ' (' . $error->getCode() . ')',
        );

        try {
            $logger = $this->plugin->logger();

            if ('error' === $level) {
                $logger->error($message, $context);
            } else {
                $logger->warning($message, $context);
            }
        } catch (\Throwable $ignored) {
            // Logging must never break meta operations.
        }
    }
}
