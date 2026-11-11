<?php

namespace Koyo\EncryptedFields\Contracts;

interface SearchInterface
{
    public function index(string $entity, int $id): void;

    public function remove(string $entity, int $id): void;

    /**
     * @return int[]
     */
    public function ids(string $entity, string $term, int $limit = 50): array;

    /**
     * @param callable|null $progress function (int $done, int $total): void
     */
    public function reindex(string $entity = 'all', int $batch = 500, ?callable $progress = null): int;
}
