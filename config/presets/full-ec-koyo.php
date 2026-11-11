<?php

/**
 * Full EC-KOYO registry preset.
 *
 * Safe to load from wp-config.php: the preset class has no other dependencies.
 */

if (!class_exists('Koyo\\EncryptedFields\\Integrations\\LegacyEcKoyo\\Preset')) {
    require_once dirname(__DIR__, 2) . '/src/Integrations/LegacyEcKoyo/Preset.php';
}

return \Koyo\EncryptedFields\Integrations\LegacyEcKoyo\Preset::registry();
