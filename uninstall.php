<?php

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

if (!defined('KEC_DIR')) {
    define('KEC_DIR', plugin_dir_path(__FILE__));
}

if (!function_exists('get_option')) {
    exit;
}

$delete = (bool) get_option('kec_delete_data_on_uninstall', false);

if (!$delete) {
    return;
}

global $wpdb;

$wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}kec_search_index");

foreach (array(
    'kec_field_registry',
    'kec_readonly_fields',
    'kec_backup_ack',
    'kec_setup_complete',
    'kec_logs',
    'kec_db_version',
    'kec_index_version',
    'kec_key',
) as $option) {
    delete_option($option);
}
