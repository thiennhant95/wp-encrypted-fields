<?php

/**
 * Full registry preset.
 *
 * Safe to load from wp-config.php: the preset class has no other dependencies.
 */

if (!class_exists('EncryptedFields\\Integrations\\Legacy\\Preset')) {
    require_once dirname(__DIR__, 2) . '/src/Integrations/Legacy/Preset.php';
}

return \EncryptedFields\Integrations\Legacy\Preset::registry();
