<?php

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

if (!function_exists('get_option')) {
    exit;
}

global $wpdb;

$kecRestoreFailed = false;
$kecPluginFile = __DIR__ . '/wp-encrypted-fields.php';

/**
 * Restore tokenized wp_users columns before the plugin code is removed.
 * Without this a user_login/user_email stay as k1t/k1e tokens and the
 * accounts can no longer authenticate.
 */
if (function_exists('get_users') && is_file($kecPluginFile)) {
    try {
        require_once $kecPluginFile;

        $kecPlugin = \Koyo\EncryptedFields\Plugin::instance();
        $kecPlugin->init();
        $kecStore = new \Koyo\EncryptedFields\User\ColumnStore($kecPlugin);

        $kecUsers = $wpdb->get_results("SELECT ID, user_login, user_email FROM {$wpdb->users}");

        if (is_array($kecUsers)) {
            foreach ($kecUsers as $kecUser) {
                $kecId = isset($kecUser->ID) ? (int) $kecUser->ID : 0;
                if ($kecId <= 0) {
                    continue;
                }

                $kecColumns = array(
                    'user_login' => array(\Koyo\EncryptedFields\User\ColumnStore::LOGIN, '_kec_user_login'),
                    'user_email' => array(\Koyo\EncryptedFields\User\ColumnStore::EMAIL, '_kec_user_email'),
                );

                foreach ($kecColumns as $kecColumn => $kecTarget) {
                    $kecValue = isset($kecUser->{$kecColumn}) ? (string) $kecUser->{$kecColumn} : '';

                    if ('' === $kecValue || !$kecStore->isToken($kecValue, $kecTarget[0])) {
                        continue;
                    }

                    $kecPlain = $kecStore->plainFromStored($kecValue, $kecTarget[0], $kecId);

                    if (!is_string($kecPlain)
                        || '' === $kecPlain
                        || $kecPlain === $kecValue
                        || $kecStore->isToken($kecPlain, $kecTarget[0])
                        || 0 === strpos($kecPlain, 'enc:v2')
                    ) {
                        $kecRestoreFailed = true;
                        continue;
                    }

                    \Koyo\EncryptedFields\Query\QueryRewriter::suspend();

                    try {
                        $kecUpdated = $wpdb->update(
                            $wpdb->users,
                            array($kecColumn => $kecPlain),
                            array('ID' => $kecId)
                        );
                    } finally {
                        \Koyo\EncryptedFields\Query\QueryRewriter::resume();
                    }

                    if (false === $kecUpdated) {
                        $kecRestoreFailed = true;
                        continue;
                    }

                    delete_user_meta($kecId, $kecTarget[1]);
                }
            }
        }
    } catch (\Throwable $kecException) {
        $kecRestoreFailed = true;
    }
}

$kecDelete = get_option('kec_delete_data_on_uninstall', false);

if (!in_array($kecDelete, array(true, 1, '1', 'true'), true)) {
    return;
}

$kecMultisite = function_exists('is_multisite') && is_multisite();
$kecSites = array(get_current_blog_id());

if ($kecMultisite && function_exists('get_sites')) {
    $kecFound = get_sites(array('fields' => 'ids', 'number' => 0));

    if (is_array($kecFound) && array() !== $kecFound) {
        $kecSites = $kecFound;
    }
}

foreach ($kecSites as $kecSiteId) {
    if ($kecMultisite && function_exists('switch_to_blog')) {
        switch_to_blog((int) $kecSiteId);
    }

    $kecTable = $wpdb->prefix . 'kec_search_index';
    $wpdb->query("DROP TABLE IF EXISTS `{$kecTable}`");

    foreach (array(
        'kec_field_registry',
        'kec_readonly_fields',
        'kec_backup_ack',
        'kec_setup_complete',
        'kec_setup_state',
        'kec_logs',
        'kec_db_version',
        'kec_search_db_version',
        'kec_migration_state',
        'kec_lookup_migration_state',
        'kec_rotation_state',
        'kec_rotation_targets',
        'kec_migration_lock',
        'kec_delete_data_on_uninstall',
    ) as $kecOption) {
        delete_option($kecOption);
    }

    if (!$kecRestoreFailed) {
        delete_option('kec_key');
    }

    $kecSql = "DELETE FROM {$wpdb->options}"
        . " WHERE (option_name LIKE 'kec\\_%'"
        . " OR option_name LIKE '\\_transient\\_kec\\_%'"
        . " OR option_name LIKE '\\_transient_timeout\\_kec\\_%')";

    if ($kecRestoreFailed) {
        $kecSql .= " AND option_name <> 'kec\\_key'";
    }

    $wpdb->query($kecSql);

    if ($kecMultisite && function_exists('restore_current_blog')) {
        restore_current_blog();
    }
}
