<?php

namespace EncryptedFields\Config;

final class Field
{
    private string $entity;
    private string $key;
    private string $type;
    private bool $search;
    private ?string $cipher;
    private array $options;

    public function __construct(
        string $entity,
        string $key,
        string $type = 'text',
        bool $search = false,
        ?string $cipher = null,
        array $options = []
    ) {
        $this->entity = $entity;
        $this->key = $key;
        $this->type = in_array($type, array('text', 'email', 'login'), true) ? $type : 'text';
        $this->search = $search;
        $this->cipher = $cipher;
        $this->options = $options;
    }

    public function entity(): string
    {
        return $this->entity;
    }

    public function key(): string
    {
        return $this->key;
    }

    public function type(): string
    {
        return $this->type;
    }

    public function isSearchable(): bool
    {
        return $this->search;
    }

    public function isColumn(): bool
    {
        return !empty($this->options['column']);
    }

    public function isInternal(): bool
    {
        return !empty($this->options['internal']);
    }

    public function cipherName(): string
    {
        if (is_string($this->cipher) && '' !== $this->cipher) {
            return $this->cipher;
        }

        return 'text' === $this->type ? 'sb' : 'det';
    }

    public function maxLength(): ?int
    {
        return isset($this->options['max_length']) ? (int) $this->options['max_length'] : null;
    }

    /**
     * @return string[]
     */
    public function postTypes(): array
    {
        return isset($this->options['post_types']) && is_array($this->options['post_types'])
            ? array_values($this->options['post_types'])
            : array();
    }

    public function option(string $name, $default = null)
    {
        return array_key_exists($name, $this->options) ? $this->options[$name] : $default;
    }
}
