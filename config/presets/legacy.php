<?php

/**
 * Legacy cipher configuration.
 *
 * Values come from KEC_LEGACY_* constants / environment.
 * Never commit the actual secrets.
 */

if (!class_exists('EncryptedFields\\Integrations\\Legacy\\Preset')) {
    require_once dirname(__DIR__, 2) . '/src/Integrations/Legacy/Preset.php';
}

return \EncryptedFields\Integrations\Legacy\Preset::legacyConfig();
