<?php

namespace EncryptedFields\Contracts;

use EncryptedFields\Config\Field;

interface EncryptorInterface
{
    public function encrypt(string $plaintext, Field $field): string;

    public function decrypt(string $value, Field $field): string;

    public function isEncrypted(string $value): bool;
}
