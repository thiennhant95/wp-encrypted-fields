<?php

namespace Koyo\EncryptedFields\Integrations\SiteGuard;

use Koyo\EncryptedFields\Config\Field;
use Koyo\EncryptedFields\Config\Registry;
use Koyo\EncryptedFields\Plugin;
use Koyo\EncryptedFields\User\ColumnStore;

/**
 * SiteGuard integration.
 *
 * Core UserHooks already decrypts the user on wp_login (priority 1). This
 * module adds a late idempotent fallback for the SiteGuard login-alert email
 * and a wp_mail safety net for encrypted recipients. SiteGuard is not patched.
 */
final class Integration
{
    private Plugin $plugin;
    private ?ColumnStore $columns = null;

    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    public function register(): void
    {
        if (function_exists('add_action')) {
            add_action('wp_login', array($this, 'decryptLoginUser'), 2, 2);
        }

        if (function_exists('add_filter')) {
            add_filter('wp_mail', array($this, 'filterMail'), 5, 1);
        }
    }

    /**
     * @param mixed $login
     * @param mixed $user
     */
    public function decryptLoginUser($login, $user): void
    {
        if (!is_object($user)) {
            return;
        }

        $userId = $this->userId($user);

        $email = $this->readUserValue($user, 'user_email');
        if (is_string($email) && '' !== $email) {
            $plain = $this->resolveUserValue($email, 'user', 'user_email', 'email', ColumnStore::EMAIL, $userId);
            if (is_string($plain) && '' !== $plain && $plain !== $email) {
                $this->writeUserValue($user, 'user_email', $plain);
            }
        }

        $username = $this->readUserValue($user, 'user_login');
        if (is_string($username) && '' !== $username) {
            $plain = $this->resolveUserValue($username, 'user', 'user_login', 'login', ColumnStore::LOGIN, $userId);
            if (is_string($plain) && '' !== $plain && $plain !== $username) {
                $this->writeUserValue($user, 'user_login', $plain);
            }
        }
    }

    /**
     * @param mixed $atts
     * @return mixed
     */
    public function filterMail($atts)
    {
        if (!is_array($atts)) {
            return $atts;
        }

        foreach (array('to', 'cc', 'bcc') as $key) {
            if (!empty($atts[$key])) {
                $atts[$key] = $this->decryptAddressList($atts[$key]);
            }
        }

        return $atts;
    }

    /**
     * @param mixed $value
     * @return mixed
     */
    private function decryptAddressList($value)
    {
        if (is_array($value)) {
            foreach ($value as $key => $item) {
                $value[$key] = $this->decryptAddressList($item);
            }

            return $value;
        }

        if (!is_string($value) || '' === $value) {
            return $value;
        }

        $parts = explode(',', $value);
        foreach ($parts as $index => $part) {
            $part = trim($part);

            if (preg_match('/^(.*)<([^>]+)>\s*$/', $part, $matches)) {
                $email = trim($matches[2]);
                $plain = $this->resolveAddressValue($email);
                $parts[$index] = trim($matches[1]) . ' <' . $plain . '>';
            } else {
                $parts[$index] = $this->resolveAddressValue($part);
            }
        }

        return implode(',', $parts);
    }

    /**
     * @param object $user
     * @param string $key
     * @return string|null
     */
    private function readUserValue($user, string $key): ?string
    {
        if (isset($user->{$key}) && is_string($user->{$key})) {
            return $user->{$key};
        }

        if (method_exists($user, 'get')) {
            $value = $user->get($key);
            if (is_string($value)) {
                return $value;
            }
        }

        return null;
    }

    /**
     * @param object $user
     * @param string $key
     * @param string $value
     */
    private function writeUserValue($user, string $key, string $value): void
    {
        $user->{$key} = $value;

        if (isset($user->data) && is_object($user->data)) {
            $user->data->{$key} = $value;
        }
    }

    private function resolveAddressValue(string $value): string
    {
        foreach (array(ColumnStore::EMAIL, ColumnStore::LOGIN) as $name) {
            $plain = $this->tokenPlaintext($value, $name);
            if (null !== $plain) {
                return $plain;
            }
        }

        $decrypted = $this->decryptValue($value, 'user', 'user_email', 'email');

        return is_string($decrypted) ? $decrypted : $value;
    }

    private function resolveUserValue(
        string $value,
        string $entity,
        string $key,
        string $type,
        string $name,
        ?int $userId = null
    ): string {
        $plain = $this->tokenPlaintext($value, $name, $userId);
        if (null !== $plain) {
            return $plain;
        }

        $decrypted = $this->decryptValue($value, $entity, $key, $type);

        return is_string($decrypted) ? $decrypted : $value;
    }

    private function tokenPlaintext(string $value, string $name, ?int $userId = null): ?string
    {
        $columns = $this->columnStore();
        if (null === $columns || !$columns->isToken($value, $name)) {
            return null;
        }

        if (null === $userId || $userId <= 0) {
            $userId = $columns->userIdByToken($value, $name);
        }

        if (null === $userId || $userId <= 0) {
            return null;
        }

        $plain = $columns->readPlain($userId, $name);

        return is_string($plain) && '' !== $plain ? $plain : null;
    }

    /**
     * @param object $user
     */
    private function userId($user): int
    {
        foreach (array('ID', 'id') as $property) {
            if (isset($user->{$property}) && is_numeric($user->{$property})) {
                return (int) $user->{$property};
            }
        }

        if (isset($user->data) && is_object($user->data)) {
            foreach (array('ID', 'id') as $property) {
                if (isset($user->data->{$property}) && is_numeric($user->data->{$property})) {
                    return (int) $user->data->{$property};
                }
            }
        }

        return 0;
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
     * @param mixed $value
     * @return mixed
     */
    private function decryptValue($value, string $entity, string $key, string $type)
    {
        if (!is_string($value) || '' === $value) {
            return $value;
        }

        $crypto = $this->crypto();
        if (!$crypto) {
            return $value;
        }

        try {
            $plain = $crypto->decrypt($value, $this->field($entity, $key, $type));
        } catch (\Throwable $e) {
            return $value;
        }

        return is_string($plain) ? $plain : $value;
    }

    private function field(string $entity, string $key, string $type): Field
    {
        $registry = $this->registry();

        if ($registry) {
            $field = $registry->get($entity, $key);
            if ($field instanceof Field) {
                return $field;
            }
        }

        return new Field($entity, $key, $type);
    }

    private function registry(): ?Registry
    {
        try {
            return $this->plugin->registry();
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function crypto(): ?\Koyo\EncryptedFields\Contracts\EncryptorInterface
    {
        try {
            return $this->plugin->crypto();
        } catch (\Throwable $e) {
            return null;
        }
    }
}
