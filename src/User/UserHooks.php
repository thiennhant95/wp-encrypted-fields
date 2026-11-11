<?php

namespace Koyo\EncryptedFields\User;

use Koyo\EncryptedFields\Config\Field;
use Koyo\EncryptedFields\Config\Registry;
use Koyo\EncryptedFields\Plugin;

/**
 * Transparent handling of encrypted wp_users columns.
 *
 * Only user_login / user_email are handled here. The registry must declare
 * them as user columns; otherwise every hook is a no-op.
 *
 * The columns store blind-index tokens; reversible plaintext lives in the
 * internal user meta keys managed by ColumnStore.
 */
final class UserHooks
{
    private Plugin $plugin;
    private bool $registered = false;

    private static ?Plugin $staticPlugin = null;

    /** @var array<string, string> */
    private static array $pending = array();

    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
        self::$staticPlugin = $plugin;
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

        add_filter('wp_pre_insert_user_data', array($this, 'filterPreInsert'), 10, 3);
        add_filter('insert_user_meta', array($this, 'filterInsertUserMeta'), 10, 3);
        add_filter('pre_user_display_name', array($this, 'filterDisplayName'), 10, 4);
        add_filter('pre_user_nicename', array($this, 'filterNicename'), 10, 3);
        add_filter('authenticate', array($this, 'filterAuthenticate'), 25, 3);
        add_action('set_current_user', array($this, 'filterCurrentUser'), 10, 1);
        add_action('wp_login', array($this, 'filterLogin'), 1, 2);
        add_filter('rest_prepare_user', array($this, 'filterRestPrepare'), 10, 3);
    }

    /**
     * Replace declared user columns with blind-index tokens before
     * wp_insert_user() writes them, and remember the plaintext for meta.
     *
     * @param mixed $data
     * @param mixed $update
     * @param mixed $userId
     *
     * @return mixed
     */
    public function filterPreInsert($data, $update = 0, $userId = 0)
    {
        if (!is_array($data)) {
            return $data;
        }

        $columns = $this->userColumns();
        $store = $this->store();

        if (null === $store) {
            return $data;
        }

        $userId = (int) $userId;

        if ($userId <= 0 && isset($data['ID'])) {
            $userId = (int) $data['ID'];
        }

        $targets = array(
            'user_login' => ColumnStore::LOGIN,
            'user_email' => ColumnStore::EMAIL,
        );

        foreach ($targets as $key => $name) {
            if (!isset($columns[$key]) || !array_key_exists($key, $data)) {
                continue;
            }

            $value = $data[$key];

            if (!is_string($value) || '' === trim($value)) {
                // Partial updates (for example a password-only update) can
                // arrive with an empty email/login. Rebuild the token from the
                // encrypted plaintext meta so the column is never blanked.
                if ($userId > 0) {
                    $plain = $store->readPlain($userId, $name);

                    if (is_string($plain) && '' !== $plain && !$store->isToken($plain, $name)) {
                        $token = $store->lookupToken($plain, $name);

                        if (is_string($token) && '' !== $token) {
                            $data[$key] = $token;
                            self::$pending[$name] = $plain;
                        }
                    }
                }

                continue;
            }

            $token = $store->lookupToken($value, $name);
            if (null === $token || '' === $token) {
                continue;
            }

            $plain = $this->plainForMeta($store, $value, $name, (int) $userId);

            if (null !== $plain && '' !== $plain && !$store->isToken($plain, $name)) {
                self::$pending[$name] = $plain;
            }

            $data[$key] = $token;
        }

        return $data;
    }

    /**
     * Store the pending plaintext in the internal user meta keys. MetaHooks
     * encrypts them on the way into the database.
     *
     * @param mixed $meta
     * @param mixed $user
     * @param mixed $update
     *
     * @return mixed
     */
    public function filterInsertUserMeta($meta, $user = null, $update = false)
    {
        if (!is_array($meta) || array() === self::$pending) {
            return $meta;
        }

        $store = $this->store();
        if (null === $store) {
            return $meta;
        }

        foreach (array(ColumnStore::LOGIN, ColumnStore::EMAIL) as $name) {
            if (!array_key_exists($name, self::$pending)) {
                continue;
            }

            $plain = self::$pending[$name];
            if (is_string($plain) && '' !== $plain) {
                $meta[$store->metaKey($name)] = $plain;
            }
        }

        self::$pending = array();

        return $meta;
    }

    /**
     * Decrypt a stored display_name before it is saved again.
     *
     * @param mixed $displayName
     * @param mixed $userLogin
     * @param mixed $userId
     * @param mixed $userData
     *
     * @return mixed
     */
    public function filterDisplayName($displayName, $userLogin = '', $userId = 0, $userData = array())
    {
        if (!is_string($displayName) || '' === $displayName) {
            return $displayName;
        }

        $loginField = $this->loginField();
        $field = $loginField ?? $this->emailField();
        if (null === $field) {
            return $displayName;
        }

        $name = null !== $loginField ? ColumnStore::LOGIN : ColumnStore::EMAIL;

        return $this->decrypt($displayName, $field, $name, (int) $userId);
    }

    /**
     * Derive user_nicename from the plaintext login.
     *
     * @param mixed $userNicename
     * @param mixed $userId
     * @param mixed $userLogin
     *
     * @return mixed
     */
    public function filterNicename($userNicename, $userId = 0, $userLogin = '')
    {
        $field = $this->loginField();
        if (null === $field) {
            return $userNicename;
        }

        $login = $userLogin;
        if (!is_string($login) || '' === $login) {
            if (!is_string($userNicename) || '' === $userNicename) {
                return $userNicename;
            }
            $login = $userNicename;
        }

        $login = $this->decrypt($login, $field, ColumnStore::LOGIN, (int) $userId);
        if ('' === $login) {
            return $userNicename;
        }

        return $this->sanitizeNicename($login);
    }

    /**
     * @param mixed $user
     * @param mixed $username
     * @param mixed $password
     *
     * @return mixed
     */
    public function filterAuthenticate($user, $username = '', $password = '')
    {
        if (is_object($user)) {
            self::decryptUser($user);
        }

        return $user;
    }

    /**
     * @param mixed $user
     * @param mixed $userId
     */
    public function filterCurrentUser($user, $userId = 0): void
    {
        if (is_object($user)) {
            self::decryptUser($user);
        }
    }

    /**
     * @param mixed $userLogin
     * @param mixed $user
     *
     * @return mixed
     */
    public function filterLogin($userLogin, $user = null)
    {
        if (is_object($user)) {
            self::decryptUser($user);
        }

        return $userLogin;
    }

    /**
     * @param mixed $response
     * @param mixed $user
     * @param mixed $request
     *
     * @return mixed
     */
    public function filterRestPrepare($response, $user = null, $request = null)
    {
        if (is_object($user)) {
            self::decryptUser($user);
        }

        if (is_object($response) && isset($response->data) && is_array($response->data)) {
            $response->data = $this->decryptRestData($response->data, self::userIdOf($user, null));

            return $response;
        }

        if (is_array($response)) {
            return $this->decryptRestData($response, self::userIdOf($user, null));
        }

        return $response;
    }

    /**
     * Decrypt the login/email of a WP_User object in place.
     *
     * This is intentionally public and static so callers can use it for users
     * loaded outside of the hooks above:
     *
     *     \Koyo\EncryptedFields\User\UserHooks::decryptUser($user);
     *
     * @param mixed $user
     */
    public static function decryptUser($user): void
    {
        if (!is_object($user)) {
            return;
        }

        $plugin = self::$staticPlugin;
        if (!$plugin instanceof Plugin) {
            try {
                $plugin = Plugin::instance();
            } catch (\Throwable $e) {
                return;
            }
        }

        if (!$plugin instanceof Plugin) {
            return;
        }

        try {
            $registry = $plugin->registry();
            $store = new ColumnStore($plugin);
        } catch (\Throwable $e) {
            return;
        }

        if (!$registry instanceof Registry) {
            return;
        }

        $columns = $registry->columns('user');
        $fields = array(
            'user_login' => array(
                isset($columns['user_login']) ? $columns['user_login'] : null,
                ColumnStore::LOGIN,
            ),
            'user_email' => array(
                isset($columns['user_email']) ? $columns['user_email'] : null,
                ColumnStore::EMAIL,
            ),
        );

        if (null === $fields['user_login'][0] && null === $fields['user_email'][0]) {
            return;
        }

        $data = null;
        if (isset($user->data) && is_object($user->data)) {
            $data = $user->data;
        } elseif (isset($user->data) && is_array($user->data)) {
            $data = $user->data;
        }

        $userId = self::userIdOf($user, $data);

        foreach ($fields as $key => $entry) {
            list($field, $name) = $entry;

            if (null === $field) {
                continue;
            }

            $value = null;

            if (is_object($data) && isset($data->{$key})) {
                $value = $data->{$key};
            } elseif (is_array($data) && array_key_exists($key, $data)) {
                $value = $data[$key];
            } elseif (isset($user->{$key})) {
                $value = $user->{$key};
            }

            if (!is_string($value) || '' === $value) {
                continue;
            }

            $plain = $store->plainFromStored($value, $name, $userId > 0 ? $userId : null);
            if ($plain === $value) {
                continue;
            }

            if (is_object($data)) {
                $data->{$key} = $plain;
            } elseif (is_array($data)) {
                $data[$key] = $plain;
            }

            if (property_exists($user, $key) || isset($user->{$key})) {
                $user->{$key} = $plain;
            }
        }
    }

    private function decryptRestData(array $data, int $userId = 0): array
    {
        if (!$this->hasUserColumns()) {
            return $data;
        }

        $loginField = $this->loginField();
        $emailField = $this->emailField();

        $map = array(
            'email' => array($emailField, ColumnStore::EMAIL),
            'username' => array($loginField, ColumnStore::LOGIN),
            'slug' => array($loginField, ColumnStore::LOGIN),
            'name' => array($loginField, ColumnStore::LOGIN),
            'first_name' => array($this->metaField('first_name'), null),
            'last_name' => array($this->metaField('last_name'), null),
        );

        foreach ($map as $key => $entry) {
            list($field, $name) = $entry;

            if (null === $field || !array_key_exists($key, $data) || !is_string($data[$key]) || '' === $data[$key]) {
                continue;
            }

            $data[$key] = $this->decrypt($data[$key], $field, $name, $userId);
        }

        if (isset($data['meta']) && is_array($data['meta'])) {
            foreach (array('first_name', 'last_name') as $key) {
                $field = $this->metaField($key);
                if (null === $field || !isset($data['meta'][$key]) || !is_string($data['meta'][$key])) {
                    continue;
                }
                $data['meta'][$key] = $this->decrypt($data['meta'][$key], $field);
            }
        }

        return $data;
    }

    private function plainForMeta(ColumnStore $store, string $value, string $name, int $userId): ?string
    {
        if ($store->isToken($value, $name)) {
            if ($userId <= 0) {
                return null;
            }

            $plain = $store->plainFromStored($value, $name, $userId);
        } else {
            $plain = $store->plainFromStored($value, $name, $userId > 0 ? $userId : null);
        }

        if ($store->isToken($plain, $name)) {
            return null;
        }

        return $plain;
    }

    private static function userIdOf($user, $data): int
    {
        if (is_object($user) && isset($user->ID)) {
            return (int) $user->ID;
        }

        if (is_object($data) && isset($data->ID)) {
            return (int) $data->ID;
        }

        if (is_array($data) && isset($data['ID'])) {
            return (int) $data['ID'];
        }

        return 0;
    }

    private function hasUserColumns(): bool
    {
        return null !== $this->loginField() || null !== $this->emailField();
    }

    /**
     * @return array<string, Field>
     */
    private function userColumns(): array
    {
        $registry = $this->registry();
        if (null === $registry) {
            return array();
        }

        try {
            return $registry->columns('user');
        } catch (\Throwable $e) {
            return array();
        }
    }

    private function loginField(): ?Field
    {
        $columns = $this->userColumns();

        return isset($columns['user_login']) ? $columns['user_login'] : null;
    }

    private function emailField(): ?Field
    {
        $columns = $this->userColumns();

        return isset($columns['user_email']) ? $columns['user_email'] : null;
    }

    private function metaField(string $key): ?Field
    {
        $registry = $this->registry();
        if (null === $registry) {
            return null;
        }

        try {
            return $registry->get('user', $key);
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

    private function store(): ?ColumnStore
    {
        try {
            return new ColumnStore($this->plugin);
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function decrypt(string $value, Field $field, ?string $name = null, int $userId = 0): string
    {
        $store = $this->store();

        if (null !== $name && null !== $store) {
            return $store->plainFromStored($value, $name, $userId > 0 ? $userId : null);
        }

        $crypto = $this->crypto();
        if (null === $crypto) {
            return $value;
        }

        try {
            return $crypto->isEncrypted($value) ? $crypto->decrypt($value, $field) : $value;
        } catch (\Throwable $e) {
            $this->logWarning('User column decryption failed.', $field, $e);

            return $value;
        }
    }

    private function crypto()
    {
        try {
            $crypto = $this->plugin->crypto();
        } catch (\Throwable $e) {
            return null;
        }

        return is_object($crypto) ? $crypto : null;
    }

    private function sanitizeNicename(string $login): string
    {
        if (function_exists('sanitize_title')) {
            return (string) sanitize_title($login);
        }

        $value = strtolower(trim($login));
        $value = preg_replace('/[^a-z0-9]+/i', '-', $value);
        $value = trim((string) $value, '-');

        return '' === $value ? strtolower(trim($login)) : $value;
    }

    private function logWarning(string $message, Field $field, \Throwable $error): void
    {
        try {
            $this->plugin->logger()->warning($message, array(
                'entity' => 'user',
                'key' => $field->key(),
                'error' => get_class($error),
            ));
        } catch (\Throwable $ignored) {
            // Logging must never break user writes.
        }
    }
}
