<?php

/**
 * Public helpers for user values, custom fields and table adapters.
 */

if (!function_exists('kec_plugin')) {
    function kec_plugin(): \EncryptedFields\Plugin
    {
        $plugin = \EncryptedFields\Plugin::instance();
        $plugin->init();

        return $plugin;
    }
}

if (!function_exists('kec_field')) {
    function kec_field(string $entity, string $field, array $options = array()): \EncryptedFields\Config\Field
    {
        $registered = kec_plugin()->registry()->get($entity, $field);

        if (null !== $registered) {
            return $registered;
        }

        $fieldOptions = isset($options['options']) && is_array($options['options'])
            ? $options['options']
            : $options;

        unset($fieldOptions['type'], $fieldOptions['search'], $fieldOptions['cipher'], $fieldOptions['options']);

        if (isset($options['max_length'])) {
            $fieldOptions['max_length'] = (int) $options['max_length'];
        }

        if (isset($options['post_types']) && is_array($options['post_types'])) {
            $fieldOptions['post_types'] = array_values($options['post_types']);
        }

        return new \EncryptedFields\Config\Field(
            $entity,
            $field,
            isset($options['type']) && is_string($options['type']) ? $options['type'] : 'text',
            !empty($options['search']),
            isset($options['cipher']) && is_string($options['cipher']) ? $options['cipher'] : null,
            $fieldOptions
        );
    }
}

if (!function_exists('kec_encrypt_value')) {
    function kec_encrypt_value($value, string $entity, string $field, array $options = array())
    {
        if (null === $value) {
            return null;
        }

        if (!is_scalar($value)) {
            throw new \InvalidArgumentException('kec_encrypt_value() accepts scalar values only.');
        }

        $value = (string) $value;
        if ('' === $value) {
            return $value;
        }

        return kec_plugin()->crypto()->encrypt($value, kec_field($entity, $field, $options));
    }
}

if (!function_exists('kec_decrypt_value')) {
    function kec_decrypt_value($value, string $entity, string $field, array $options = array())
    {
        if (null === $value) {
            return null;
        }

        if (!is_scalar($value)) {
            throw new \InvalidArgumentException('kec_decrypt_value() accepts scalar values only.');
        }

        $value = (string) $value;
        if ('' === $value) {
            return $value;
        }

        return kec_plugin()->crypto()->decrypt($value, kec_field($entity, $field, $options));
    }
}

if (!function_exists('kec_is_encrypted')) {
    function kec_is_encrypted($value): bool
    {
        return is_string($value) && '' !== $value && kec_plugin()->crypto()->isEncrypted($value);
    }
}

if (!function_exists('kec_blind_index')) {
    function kec_blind_index($value, string $entity, string $field, array $options = array()): string
    {
        if (null === $value) {
            return '';
        }

        if (!is_scalar($value)) {
            throw new \InvalidArgumentException('kec_blind_index() accepts scalar values only.');
        }

        $value = (string) $value;
        if ('' === $value) {
            return '';
        }

        $field = kec_field($entity, $field, $options);
        $tokenizer = new \EncryptedFields\Search\Tokenizer(kec_plugin()->keys()->searchSecret());

        return $tokenizer->fullToken((string) $value, $field->key());
    }
}

if (!function_exists('kec_custom_table')) {
    function kec_custom_table(string $name): ?\EncryptedFields\Table\EncryptedTable
    {
        $plugin = kec_plugin();
        $table = \EncryptedFields\Table\EncryptedTable::fromName($plugin, $name);

        if (null !== $table) {
            return $table;
        }

        // Theme functions.php runs before the after_setup_theme refresh.
        $plugin->refreshExtensions();

        return \EncryptedFields\Table\EncryptedTable::fromName($plugin, $name);
    }
}

if (!function_exists('kec_user_login')) {
    function kec_user_login($value, $userId = 0)
    {
        return kec_resolve_user_value($value, $userId, \EncryptedFields\User\ColumnStore::LOGIN);
    }
}

if (!function_exists('kec_user_email')) {
    function kec_user_email($value, $userId = 0)
    {
        return kec_resolve_user_value($value, $userId, \EncryptedFields\User\ColumnStore::EMAIL);
    }
}

if (!function_exists('kec_resolve_user_value')) {
    function kec_resolve_user_value($value, $userId, string $name)
    {
        if (!is_string($value) || '' === $value) {
            return $value;
        }

        if (!class_exists('EncryptedFields\\Plugin')) {
            return $value;
        }

        try {
            $plugin = \EncryptedFields\Plugin::instance();
            $plugin->init();

            $columns = new \EncryptedFields\User\ColumnStore($plugin);

            return $columns->plainFromStored($value, $name, (int) $userId > 0 ? (int) $userId : null);
        } catch (\Throwable $exception) {
            return $value;
        }
    }
}
