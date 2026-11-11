<?php

/**
 * EC-KOYO legacy cipher configuration.
 *
 * Values come from KEC_LEGACY_* (or KOYO_LEGACY_*) constants / environment.
 * Never commit the actual secrets.
 */

if (!class_exists('Koyo\\EncryptedFields\\Integrations\\LegacyEcKoyo\\Preset')) {
    require_once dirname(__DIR__, 2) . '/src/Integrations/LegacyEcKoyo/Preset.php';
}

return \Koyo\EncryptedFields\Integrations\LegacyEcKoyo\Preset::legacyConfig();
