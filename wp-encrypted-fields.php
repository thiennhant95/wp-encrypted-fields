<?php
/**
 * Plugin Name: Encrypted Fields
 * Plugin URI: https://github.com/thiennhant95/wp-encrypted-fields
 * Description: Registry-driven field-level encryption for WordPress and WooCommerce.
 * Version: 0.2.2
 * Requires PHP: 8.0
 * Requires at least: 6.4
 * Author: thiennhant95
 * Author URI: https://github.com/thiennhant95
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: encrypted-fields
 */

if (!defined('ABSPATH')) {
    exit;
}

define('KEC_VERSION', '0.2.2');
define('KEC_DB_VERSION', '1');
define('KEC_FILE', __FILE__);
define('KEC_DIR', plugin_dir_path(__FILE__));
define('KEC_URL', plugin_dir_url(__FILE__));

spl_autoload_register(function ($class) {
    $prefix = 'Koyo\\EncryptedFields\\';

    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }

    $relative = substr($class, strlen($prefix));
    $file = KEC_DIR . 'src/' . str_replace('\\', '/', $relative) . '.php';

    if (is_file($file)) {
        require $file;
    }
});

add_action('plugins_loaded', function () {
    \Koyo\EncryptedFields\Plugin::boot();
}, 5);
