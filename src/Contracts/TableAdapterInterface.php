<?php

namespace Koyo\EncryptedFields\Contracts;

interface TableAdapterInterface
{
    public function name(): string;

    /**
     * Physical table name (without backticks). Must be a valid identifier.
     */
    public function table(): string;

    /**
     * Unique integer primary key column.
     */
    public function primaryKey(): string;

    /**
     * @return array<string, string> column => type
     */
    public function columns(): array;

    /**
     * @return array<string, mixed>|null
     */
    public function read(int $id): ?array;

    /**
     * @param array<string, mixed> $data
     * @return bool true when every value was written
     */
    public function write(int $id, array $data): bool;

    /**
     * @return string[]
     */
    public function searchableColumns(): array;
}
