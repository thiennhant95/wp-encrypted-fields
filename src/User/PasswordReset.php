<?php

namespace Koyo\EncryptedFields\User;

use Koyo\EncryptedFields\Plugin;

/**
 * Replaces blind-index tokens in password reset mail with plaintext.
 */
final class PasswordReset
{
    private Plugin $plugin;
    private ?ColumnStore $columns = null;

    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    public function register(): void
    {
        if (!function_exists('add_filter')) {
            return;
        }

        add_filter('retrieve_password_message', array($this, 'filterMessage'), 10, 4);
        add_filter('retrieve_password_title', array($this, 'filterTitle'), 10, 3);
    }

    /**
     * @param mixed $message
     * @param mixed $key
     * @param mixed $userLogin
     * @param mixed $userData
     * @return mixed
     */
    public function filterMessage($message, $key = '', $userLogin = '', $userData = null)
    {
        if (!is_string($message) || '' === $message) {
            return $message;
        }

        $login = is_string($userLogin) ? $userLogin : '';
        $email = $this->userEmail($userData);
        $userId = $this->userId($userData, array($login, $email));

        return $this->replaceTokens($message, $login, $email, $userId);
    }

    /**
     * @param mixed $title
     * @param mixed $userLogin
     * @param mixed $userData
     * @return mixed
     */
    public function filterTitle($title, $userLogin = '', $userData = null)
    {
        if (!is_string($title) || '' === $title) {
            return $title;
        }

        $login = is_string($userLogin) ? $userLogin : '';
        $email = $this->userEmail($userData);
        $userId = $this->userId($userData, array($login, $email));

        return $this->replaceTokens($title, $login, $email, $userId);
    }

    private function replaceTokens(string $text, string $login, string $email, int $userId): string
    {
        $columns = $this->columnStore();
        $search = array();
        $replace = array();

        if ('' !== $login && $columns->isToken($login, ColumnStore::LOGIN)) {
            $plain = $columns->plainFromStored($login, ColumnStore::LOGIN, $userId > 0 ? $userId : null);
            $this->addReplacements($search, $replace, $login, $plain);
        }

        if ('' !== $email && $columns->isToken($email, ColumnStore::EMAIL)) {
            $plain = $columns->plainFromStored($email, ColumnStore::EMAIL, $userId > 0 ? $userId : null);
            $this->addReplacements($search, $replace, $email, $plain);
        }

        if (array() === $search) {
            return $text;
        }

        return str_replace($search, $replace, $text);
    }

    /**
     * @param string[] $search
     * @param string[] $replace
     */
    private function addReplacements(array &$search, array &$replace, string $token, string $plain): void
    {
        if ('' === $plain || $plain === $token) {
            return;
        }

        $search[] = $token;
        $replace[] = $plain;
        $search[] = rawurlencode($token);
        $replace[] = rawurlencode($plain);
        $search[] = urlencode($token);
        $replace[] = urlencode($plain);
    }

    /**
     * @param mixed $userData
     */
    private function userEmail($userData): string
    {
        if (is_object($userData) && isset($userData->user_email) && is_string($userData->user_email)) {
            return $userData->user_email;
        }

        if (is_array($userData) && isset($userData['user_email']) && is_string($userData['user_email'])) {
            return $userData['user_email'];
        }

        return '';
    }

    /**
     * @param mixed $userData
     * @param string[] $values
     */
    private function userId($userData, array $values): int
    {
        if (is_object($userData) && isset($userData->ID) && is_numeric($userData->ID)) {
            return (int) $userData->ID;
        }

        if (is_array($userData) && isset($userData['ID']) && is_numeric($userData['ID'])) {
            return (int) $userData['ID'];
        }

        $columns = $this->columnStore();
        foreach (array(array($values[0] ?? '', ColumnStore::LOGIN), array($values[1] ?? '', ColumnStore::EMAIL)) as $pair) {
            $value = (string) $pair[0];
            if ('' !== $value && $columns->isToken($value, $pair[1])) {
                $id = $columns->userIdByToken($value, $pair[1]);
                if (null !== $id && $id > 0) {
                    return $id;
                }
            }
        }

        return 0;
    }

    private function columnStore(): ColumnStore
    {
        if (null === $this->columns) {
            $this->columns = new ColumnStore($this->plugin);
        }

        return $this->columns;
    }
}
