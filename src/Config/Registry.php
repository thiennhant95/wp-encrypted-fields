<?php

namespace Koyo\EncryptedFields\Config;

final class Registry
{
    /** @var array<string, array<string, Field>> */
    private array $fields = array();

    /** @var array<string, array<string, bool>> */
    private array $readonly = array();

    public static function fromSources(): self
    {
        $raw = null;

        if (defined('KEC_FIELDS')) {
            $raw = KEC_FIELDS;
        }

        if (!is_array($raw)) {
            $file = defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR . '/kec-fields.php' : '';
            if ('' !== $file && is_file($file)) {
                $loaded = include $file;
                if (is_array($loaded)) {
                    $raw = $loaded;
                }
            }
        }

        if (!is_array($raw) && function_exists('get_option')) {
            $option = get_option('kec_field_registry');
            if (is_array($option)) {
                $raw = $option;
            }
        }

        if (!is_array($raw)) {
            $raw = array();
        }

        if (function_exists('apply_filters')) {
            $raw = apply_filters('kec_field_registry', $raw);
        }

        $readonly = array();

        if (defined('KEC_READONLY_FIELDS') && is_array(KEC_READONLY_FIELDS)) {
            $readonly = KEC_READONLY_FIELDS;
        } elseif (function_exists('get_option')) {
            $option = get_option('kec_readonly_fields');
            if (is_array($option)) {
                $readonly = $option;
            }
        }

        if (function_exists('apply_filters')) {
            $readonly = apply_filters('kec_readonly_fields', $readonly);
        }

        return new self($raw, is_array($readonly) ? $readonly : array());
    }

    public function __construct(array $raw, array $readonly = array())
    {
        foreach ($raw as $entity => $definition) {
            if (!is_string($entity) || !is_array($definition)) {
                continue;
            }

            $postTypes = isset($definition['post_types']) && is_array($definition['post_types'])
                ? array_values($definition['post_types'])
                : array();

            if (isset($definition['columns']) && is_array($definition['columns'])) {
                foreach ($definition['columns'] as $column => $config) {
                    $this->addField($entity, (string) $column, $config, array('column' => true));
                }
            }

            if (isset($definition['meta']) && is_array($definition['meta'])) {
                foreach ($definition['meta'] as $key => $config) {
                    $options = array('post_types' => $postTypes);
                    $this->addField($entity, (string) $key, $config, $options);
                }
            }
        }

        if (isset($this->fields['user']['user_login']) || isset($this->fields['user']['user_email'])) {
            foreach (array('_kec_user_login', '_kec_user_email') as $internalKey) {
                if (!isset($this->fields['user'][$internalKey])) {
                    $this->fields['user'][$internalKey] = new Field(
                        'user',
                        $internalKey,
                        'text',
                        false,
                        null,
                        array('internal' => true)
                    );
                }
            }
        }

        foreach ($readonly as $entity => $keys) {
            if (!is_array($keys)) {
                continue;
            }
            foreach ($keys as $key => $flag) {
                if (is_int($key)) {
                    $this->readonly[$entity][(string) $flag] = true;
                } elseif ($flag) {
                    $this->readonly[$entity][(string) $key] = true;
                }
            }
        }
    }

    private function addField(string $entity, string $key, $config, array $extra): void
    {
        if (is_string($config)) {
            $config = array('type' => $config);
        }

        if (!is_array($config)) {
            $config = array();
        }

        $options = array_merge($extra, isset($config['options']) && is_array($config['options']) ? $config['options'] : array());

        if (isset($config['max_length'])) {
            $options['max_length'] = (int) $config['max_length'];
        }

        if (isset($config['post_types']) && is_array($config['post_types'])) {
            $options['post_types'] = array_values($config['post_types']);
        }

        $cipher = isset($config['cipher']) ? strtolower(trim((string) $config['cipher'])) : null;
        $allowedCiphers = array('sb', 'det', 'deterministic', 'siv', 'secretbox', 'random', 'randomized');

        if (null !== $cipher && !in_array($cipher, $allowedCiphers, true)) {
            $cipher = null;
        }

        $field = new Field(
            $entity,
            $key,
            isset($config['type']) ? (string) $config['type'] : 'text',
            !empty($config['search']),
            $cipher,
            $options
        );

        $this->fields[$entity][$key] = $field;
    }

    public function get(string $entity, string $key): ?Field
    {
        return $this->fields[$entity][$key] ?? null;
    }

    public function has(string $entity, string $key): bool
    {
        return isset($this->fields[$entity][$key]);
    }

    public function fields(string $entity): array
    {
        return $this->fields[$entity] ?? array();
    }

    public function columns(string $entity): array
    {
        $result = array();
        foreach ($this->fields($entity) as $key => $field) {
            if ($field->isColumn()) {
                $result[$key] = $field;
            }
        }
        return $result;
    }

    public function entities(): array
    {
        return array_keys($this->fields);
    }

    public function all(): array
    {
        return $this->fields;
    }

    public function isReadonly(string $entity, string $key): bool
    {
        return !empty($this->readonly[$entity][$key]);
    }

    public function isEnabled(): bool
    {
        foreach ($this->fields as $fields) {
            if (!empty($fields)) {
                return true;
            }
        }
        return false;
    }
}
