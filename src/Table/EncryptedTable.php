<?php

namespace EncryptedFields\Table;

use EncryptedFields\Config\Field;
use EncryptedFields\Contracts\TableAdapterInterface;
use EncryptedFields\Plugin;
use EncryptedFields\Search\Tokenizer;

/**
 * Runtime wrapper for a registered table adapter.
 *
 * The adapter still owns SQL access. This wrapper encrypts declared columns
 * before write() and decrypts declared columns after read(), so integrations
 * can reuse the same declaration used by migration.
 */
final class EncryptedTable
{
    private Plugin $plugin;
    private TableAdapterInterface $adapter;

    /** @var array<string, Field>|null */
    private ?array $fields = null;

    public function __construct(Plugin $plugin, TableAdapterInterface $adapter)
    {
        $this->plugin = $plugin;
        $this->adapter = $adapter;
    }

    public static function fromName(Plugin $plugin, string $name): ?self
    {
        foreach ($plugin->tableAdapters() as $key => $adapter) {
            if (!$adapter instanceof TableAdapterInterface) {
                continue;
            }

            if ((string) $key === $name || (string) $adapter->name() === $name) {
                return new self($plugin, $adapter);
            }
        }

        return null;
    }

    public function adapter(): TableAdapterInterface
    {
        return $this->adapter;
    }

    public function name(): string
    {
        return $this->adapter->name();
    }

    public function table(): string
    {
        return $this->adapter->table();
    }

    /**
     * @return array<string, Field>
     */
    public function fields(): array
    {
        if (null !== $this->fields) {
            return $this->fields;
        }

        $searchable = $this->adapter->searchableColumns();
        $searchable = is_array($searchable) ? array_map('strval', $searchable) : array();
        $columns = $this->adapter->columns();
        $fields = array();

        if (is_array($columns)) {
            foreach ($columns as $column => $type) {
                $column = (string) $column;
                $fields[$column] = new Field(
                    'custom',
                    $column,
                    is_string($type) ? $type : 'text',
                    in_array($column, $searchable, true),
                    null,
                    array('table' => $this->name())
                );
            }
        }

        $this->fields = $fields;

        return $this->fields;
    }

    public function field(string $column): ?Field
    {
        $fields = $this->fields();

        return $fields[$column] ?? null;
    }

    /**
     * @return string[]
     */
    public function encryptedColumns(): array
    {
        return array_keys($this->fields());
    }

    /**
     * @return array<string, mixed>|null
     */
    public function read(int $id): ?array
    {
        $row = $this->adapter->read($id);

        return is_array($row) ? $this->decryptRow($row) : null;
    }

    /**
     * @param array<string, mixed> $data
     */
    public function write(int $id, array $data): bool
    {
        return $this->adapter->write($id, $this->encryptRow($data));
    }

    /**
     * @param array<string, mixed> $row
     * @return array<string, mixed>
     */
    public function encryptRow(array $row): array
    {
        foreach (array_keys($this->fields()) as $column) {
            if (!array_key_exists($column, $row)) {
                continue;
            }

            $row[$column] = $this->encryptValue($row[$column], $column);
        }

        return $row;
    }

    /**
     * @param array<string, mixed> $row
     * @return array<string, mixed>
     */
    public function decryptRow(array $row): array
    {
        foreach (array_keys($this->fields()) as $column) {
            if (!array_key_exists($column, $row)) {
                continue;
            }

            $row[$column] = $this->decryptValue($row[$column], $column);
        }

        return $row;
    }

    public function encryptValue($value, string $column)
    {
        $field = $this->field($column);

        if (null === $field) {
            throw new \InvalidArgumentException(sprintf('Column "%s" is not declared by adapter "%s".', $column, $this->name()));
        }

        if (null === $value) {
            return null;
        }

        if (!is_scalar($value)) {
            throw new \InvalidArgumentException(sprintf('Column "%s" accepts scalar values only.', $column));
        }

        $value = (string) $value;

        return '' === $value ? $value : $this->plugin->crypto()->encrypt($value, $field);
    }

    public function decryptValue($value, string $column)
    {
        $field = $this->field($column);

        if (null === $field) {
            throw new \InvalidArgumentException(sprintf('Column "%s" is not declared by adapter "%s".', $column, $this->name()));
        }

        if (null === $value) {
            return null;
        }

        if (!is_scalar($value)) {
            throw new \InvalidArgumentException(sprintf('Column "%s" accepts scalar values only.', $column));
        }

        $value = (string) $value;

        return '' === $value ? $value : $this->plugin->crypto()->decrypt($value, $field);
    }

    public function blindIndex(string $column, $value): string
    {
        if (null === $this->field($column)) {
            throw new \InvalidArgumentException(sprintf('Column "%s" is not declared by adapter "%s".', $column, $this->name()));
        }

        if (null === $value) {
            return '';
        }

        if (!is_scalar($value)) {
            throw new \InvalidArgumentException('blindIndex() accepts scalar values only.');
        }

        $value = (string) $value;
        if ('' === $value) {
            return '';
        }

        $tokenizer = new Tokenizer($this->plugin->keys()->searchSecret());

        return $tokenizer->fullToken($value, $column);
    }
}
