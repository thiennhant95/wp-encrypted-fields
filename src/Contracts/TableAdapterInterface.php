<?php

namespace Koyo\EncryptedFields\Contracts;

interface TableAdapterInterface
{
    public function name(): string;

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
     */
    public function write(int $id, array $data): void;

    /**
     * @return string[]
     */
    public function searchableColumns(): array;
}
