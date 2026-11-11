<?php

namespace Koyo\EncryptedFields\Mail;

use Koyo\EncryptedFields\Config\Field;
use Koyo\EncryptedFields\Contracts\EncryptorInterface;
use Koyo\EncryptedFields\Plugin;
use Koyo\EncryptedFields\User\ColumnStore;

/**
 * Decrypts encrypted recipients before mail is handed to the mailer.
 *
 * Plaintext values are returned untouched because Encryptor::decrypt() is
 * idempotent. Body/subject token replacement is opt-in and never logs values.
 */
final class MailHooks
{
    private const ADDRESS_KEYS = array('to', 'cc', 'bcc');

    private Plugin $plugin;
    private bool $registered = false;
    private ?ColumnStore $columns = null;

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

        if (function_exists('add_filter')) {
            add_filter('wp_mail', array($this, 'filterMail'), 10, 1);
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

        foreach (self::ADDRESS_KEYS as $key) {
            if (!array_key_exists($key, $atts)) {
                continue;
            }

            if (is_string($atts[$key]) || is_array($atts[$key])) {
                $atts[$key] = $this->decryptAddressList($atts[$key]);
            }
        }

        if ($this->bodyDecryptionEnabled()) {
            foreach (array('subject', 'message') as $key) {
                if (isset($atts[$key]) && is_string($atts[$key]) && '' !== $atts[$key]) {
                    $atts[$key] = $this->decryptBodyText($atts[$key]);
                }
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
            $result = array();

            foreach ($value as $key => $item) {
                $result[$key] = (is_string($item) || is_array($item))
                    ? $this->decryptAddressList($item)
                    : $item;
            }

            return $result;
        }

        if (!is_string($value) || '' === $value) {
            return $value;
        }

        $segments = $this->splitAddressList($value);

        foreach ($segments as $index => $segment) {
            $segments[$index] = $this->decryptAddressSegment($segment);
        }

        return implode(',', $segments);
    }

    /**
     * Splits on commas that are not inside quotes or angle brackets.
     *
     * @return string[]
     */
    private function splitAddressList(string $value): array
    {
        $segments = array();
        $buffer = '';
        $length = strlen($value);
        $inQuotes = false;
        $angleDepth = 0;

        for ($index = 0; $index < $length; ++$index) {
            $char = $value[$index];

            if ('"' === $char) {
                $inQuotes = !$inQuotes;
                $buffer .= $char;
                continue;
            }

            if (!$inQuotes) {
                if ('<' === $char) {
                    ++$angleDepth;
                } elseif ('>' === $char && $angleDepth > 0) {
                    --$angleDepth;
                }
            }

            if (',' === $char && !$inQuotes && 0 === $angleDepth) {
                $segments[] = $buffer;
                $buffer = '';
                continue;
            }

            $buffer .= $char;
        }

        $segments[] = $buffer;

        return $segments;
    }

    private function decryptAddressSegment(string $segment): string
    {
        $core = trim($segment);

        if ('' === $core) {
            return $segment;
        }

        $leading = substr($segment, 0, strlen($segment) - strlen(ltrim($segment)));
        $trailingLength = strlen($segment) - strlen(rtrim($segment));
        $trailing = $trailingLength > 0 ? substr($segment, -$trailingLength) : '';

        if (preg_match('/^(.*)<([^<>]+)>(\s*)$/s', $core, $matches)) {
            $email = trim($matches[2]);
            $plain = $this->decryptAddressValue($email);

            return $leading . $matches[1] . '<' . $plain . '>' . $matches[3] . $trailing;
        }

        return $leading . $this->decryptAddressValue($core) . $trailing;
    }

    private function decryptAddressValue(string $value): string
    {
        if ('' === $value) {
            return $value;
        }

        $plain = $this->resolveTokenRecipient($value);
        if (null !== $plain) {
            return $plain;
        }

        $emailField = new Field('user', 'user_email', 'email');
        $loginField = new Field('user', 'user_login', 'login');

        $candidates = false !== strpos($value, '@')
            ? array($emailField, $loginField)
            : array($loginField, $emailField);

        foreach ($candidates as $field) {
            $plain = $this->tryDecrypt($value, $field);

            if (null !== $plain) {
                return $plain;
            }
        }

        return $value;
    }

    private function resolveTokenRecipient(string $value): ?string
    {
        $columns = $this->columnStore();
        if (null === $columns) {
            return null;
        }

        $names = false !== strpos($value, '@')
            ? array(ColumnStore::EMAIL, ColumnStore::LOGIN)
            : array(ColumnStore::LOGIN, ColumnStore::EMAIL);

        foreach ($names as $name) {
            if (!$columns->isToken($value, $name)) {
                continue;
            }

            $userId = $columns->userIdByToken($value, $name);
            if (null === $userId || $userId <= 0) {
                return null;
            }

            $plain = $columns->readPlain($userId, $name);
            if (is_string($plain) && '' !== $plain) {
                return $plain;
            }

            return null;
        }

        return null;
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
        } catch (\Throwable $exception) {
            return null;
        }

        return $this->columns;
    }

    private function tryDecrypt(string $value, Field $field): ?string
    {
        $crypto = $this->crypto();

        if (null === $crypto) {
            return null;
        }

        try {
            $plain = $crypto->decrypt($value, $field);
        } catch (\Throwable $exception) {
            return null;
        }

        if (!is_string($plain) || '' === $plain || $plain === $value) {
            return null;
        }

        return $plain;
    }

    private function bodyDecryptionEnabled(): bool
    {
        if (!function_exists('apply_filters')) {
            return false;
        }

        return (bool) apply_filters('kec_mail_decrypt_body', false);
    }

    private function decryptBodyText(string $text): string
    {
        $crypto = $this->crypto();

        if (null === $crypto) {
            return $text;
        }

        $pattern = '/'
            . 'enc:v2c?:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+'
            . '|[A-Za-z0-9+\/]{16,}@[A-Za-z0-9._-]+'
            . '|(?<![A-Za-z0-9+\/=])[A-Za-z0-9+\/=]{24,}={0,2}(?![A-Za-z0-9+\/=])'
            . '/';

        $result = preg_replace_callback($pattern, function (array $matches) use ($crypto): string {
            return $this->decryptBodyToken($matches[0], $crypto);
        }, $text);

        return is_string($result) ? $result : $text;
    }

    private function decryptBodyToken(string $token, EncryptorInterface $crypto): string
    {
        try {
            if (!$crypto->isEncrypted($token)) {
                return $token;
            }
        } catch (\Throwable $exception) {
            return $token;
        }

        foreach ($this->tokenFields() as $field) {
            try {
                $plain = $crypto->decrypt($token, $field);
            } catch (\Throwable $exception) {
                continue;
            }

            if (is_string($plain) && $plain !== $token && $this->isPlausiblePlaintext($plain)) {
                return $plain;
            }
        }

        return $token;
    }

    private function isPlausiblePlaintext(string $plain): bool
    {
        if ('' === $plain || false !== strpos($plain, "\0")) {
            return false;
        }

        if (1 !== preg_match('//u', $plain)) {
            return false;
        }

        // Never replace a token with another cipher envelope.
        if (1 === preg_match('/^enc:v2c?:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+$/', $plain)) {
            return false;
        }

        return true;
    }

    /**
     * @return Field[]
     */
    private function tokenFields(): array
    {
        $fields = array();
        $seen = array();

        $add = function (Field $field) use (&$fields, &$seen): void {
            $domain = $field->entity() . ':' . $field->key();

            if (isset($seen[$domain])) {
                return;
            }

            $seen[$domain] = true;
            $fields[] = $field;
        };

        $add(new Field('user', 'user_email', 'email'));
        $add(new Field('user', 'user_login', 'login'));

        try {
            $registry = $this->plugin->registry();

            foreach ($registry->all() as $keys) {
                foreach ($keys as $field) {
                    if ($field instanceof Field) {
                        $add($field);
                    }
                }
            }
        } catch (\Throwable $exception) {
            // Registry is optional for body token replacement.
        }

        return $fields;
    }

    private function crypto(): ?EncryptorInterface
    {
        try {
            return $this->plugin->crypto();
        } catch (\Throwable $exception) {
            return null;
        }
    }
}
