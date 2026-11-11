<?php

namespace EncryptedFields\Search;

/**
 * Builds deterministic blind-index tokens.
 *
 * Token format (stored as 64 hex chars):
 *   full     = HMAC-SHA256(secret, "F:" . field . ":" . normalized)
 *   trigram  = HMAC-SHA256(secret, "G:" . field . ":" . trigram)
 *
 * The field is part of the HMAC domain so the same plaintext in different
 * fields does not produce the same token.
 */
final class Tokenizer
{
    private const TRIGRAM_LENGTH = 3;

    private string $secret;

    public function __construct(string $secret)
    {
        $this->secret = $secret;
    }

    public function secret(): string
    {
        return $this->secret;
    }

    public function normalize(string $text): string
    {
        if ('' === $text) {
            return '';
        }

        $original = $text;

        if (class_exists('\\Normalizer')) {
            $normalized = \Normalizer::normalize($text, \Normalizer::FORM_KC);
            if (is_string($normalized)) {
                $text = $normalized;
            }
        } elseif (function_exists('mb_convert_kana')) {
            $converted = mb_convert_kana($text, 'asK', 'UTF-8');
            if (is_string($converted)) {
                $text = $converted;
            }
        }

        if (function_exists('mb_strtolower')) {
            $lower = mb_strtolower($text, 'UTF-8');
            if (is_string($lower)) {
                $text = $lower;
            }
        } else {
            $text = strtolower($text);
        }

        $collapsed = preg_replace('/[\s\x{00A0}\x{3000}]+/u', ' ', $text);
        if (null === $collapsed) {
            $collapsed = preg_replace('/[\s\x{00A0}\x{3000}]+/', ' ', $text);
        }

        if (!is_string($collapsed)) {
            $collapsed = $text;
        }

        $trimmed = trim($collapsed);

        return '' === $trimmed ? '' : $trimmed;
    }

    public function fullToken(string $text, string $field = ''): string
    {
        return $this->token('F', $this->normalize($text), $field);
    }

    /**
     * @return string[]
     */
    public function trigramTokens(string $text, string $field = ''): array
    {
        $normalized = $this->normalize($text);
        $tokens = array();

        foreach ($this->trigrams($normalized) as $trigram) {
            $tokens[] = $this->token('G', $trigram, $field);
        }

        return $tokens;
    }

    /**
     * Full token followed by unique trigram tokens.
     *
     * @return string[]
     */
    public function tokens(string $text, string $field = ''): array
    {
        $normalized = $this->normalize($text);
        if ('' === $normalized) {
            return array();
        }

        $tokens = array($this->token('F', $normalized, $field));

        foreach ($this->trigrams($normalized) as $trigram) {
            $tokens[] = $this->token('G', $trigram, $field);
        }

        return $tokens;
    }

    public function normalizedLength(string $text): int
    {
        $normalized = $this->normalize($text);
        if (function_exists('mb_strlen')) {
            return (int) mb_strlen($normalized, 'UTF-8');
        }

        return strlen($normalized);
    }

    /**
     * @return string[]
     */
    public function trigrams(string $normalized): array
    {
        if ('' === $normalized) {
            return array();
        }

        $chars = preg_split('//u', $normalized, -1, PREG_SPLIT_NO_EMPTY);
        if (!is_array($chars)) {
            $chars = str_split($normalized);
        }

        $count = count($chars);
        if ($count < self::TRIGRAM_LENGTH) {
            return array();
        }

        $trigrams = array();
        $limit = $count - self::TRIGRAM_LENGTH;

        for ($i = 0; $i <= $limit; $i++) {
            $trigram = $chars[$i] . $chars[$i + 1] . $chars[$i + 2];
            $trigrams[$trigram] = true;
        }

        return array_keys($trigrams);
    }

    /**
     * Low-level HMAC token builder. $text is expected to be normalized.
     */
    public function token(string $prefix, string $text, string $field): string
    {
        $material = $prefix . ':';

        if ('' !== $field) {
            $material .= $field . ':';
        }

        return hash_hmac('sha256', $material . $text, $this->secret);
    }
}
