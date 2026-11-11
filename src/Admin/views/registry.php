<?php
/**
 * Registry tab.
 *
 * @var \EncryptedFields\Plugin $plugin
 */

$option = $plugin->option('kec_field_registry', null);
if (is_array($option) && $option) {
    $raw = $option;
} else {
    $raw = array();
    foreach ($plugin->registry()->all() as $entity => $fields) {
        $raw[$entity] = array('post_types' => array(), 'columns' => array(), 'meta' => array());
        foreach ($fields as $key => $field) {
            $config = array('type' => $field->type());
            if ($field->isSearchable()) {
                $config['search'] = true;
            }
            $max = $field->maxLength();
            if (null !== $max) {
                $config['max_length'] = $max;
            }
            if ($field->isColumn()) {
                $raw[$entity]['columns'][$key] = $config;
            } else {
                $raw[$entity]['meta'][$key] = $config;
            }
        }
        if (empty($raw[$entity]['columns'])) {
            unset($raw[$entity]['columns']);
        }
        if (empty($raw[$entity]['post_types'])) {
            unset($raw[$entity]['post_types']);
        }
    }
}

$json = function_exists('wp_json_encode') ? wp_json_encode($raw, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) : json_encode($raw, JSON_PRETTY_PRINT);
$fileMode = (defined('KEC_FIELDS') || (defined('WP_CONTENT_DIR') && is_file(WP_CONTENT_DIR . '/kec-fields.php')));
?>
<?php if ($fileMode) : ?>
    <div class="notice notice-info inline" style="margin-top: 16px;">
        <p>Fields are currently loaded from a constant or file. Saving here writes the option, but the constant/file takes precedence.</p>
    </div>
<?php endif; ?>

<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-top: 16px;">
    <input type="hidden" name="action" value="kec_settings">
    <input type="hidden" name="kec_action" value="save_registry">
    <input type="hidden" name="kec_tab" value="registry">
    <?php wp_nonce_field('kec_admin', 'kec_nonce'); ?>
    <textarea name="kec_registry_json" rows="22" class="large-text code" spellcheck="false"><?php echo esc_textarea((string) $json); ?></textarea>
    <p class="description">Only declared fields are encrypted. Supported types: text, email, login. Registry is validated before saving.</p>
    <p><button type="submit" class="button button-primary">Save Registry</button></p>
</form>
