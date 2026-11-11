<?php
/**
 * Search index tab.
 *
 * @var \Koyo\EncryptedFields\Plugin $plugin
 */

$db = isset($GLOBALS['wpdb']) ? $GLOBALS['wpdb'] : null;
$rows = null;
if (is_object($db) && method_exists($db, 'get_var')) {
    $prefix = method_exists($db, 'prefix') ? $db->prefix : (isset($db->prefix) ? $db->prefix : '');
    $rows = $db->get_var('SELECT COUNT(*) FROM ' . $prefix . 'kec_search_index');
}

$search = $plugin->search();
$searchable = array();
foreach ($plugin->registry()->all() as $entity => $fields) {
    foreach ($fields as $key => $field) {
        if ($field->isSearchable()) {
            $searchable[] = $entity . ':' . $key;
        }
    }
}
?>
<h2>Search Index</h2>

<table class="widefat striped" style="max-width: 900px;">
    <tbody>
        <tr>
            <th scope="row">Search service</th>
            <td><?php echo null === $search ? 'Not available' : 'Available'; ?></td>
        </tr>
        <tr>
            <th scope="row">Index rows</th>
            <td><?php echo null === $rows ? 'Table not available' : esc_html((string) (int) $rows); ?></td>
        </tr>
        <tr>
            <th scope="row">Searchable fields</th>
            <td><?php echo $searchable ? esc_html(implode(', ', $searchable)) : 'None'; ?></td>
        </tr>
    </tbody>
</table>

<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-top: 16px;">
    <input type="hidden" name="action" value="kec_settings">
    <input type="hidden" name="kec_action" value="reindex">
    <input type="hidden" name="kec_tab" value="index">
    <?php wp_nonce_field('kec_admin', 'kec_nonce'); ?>
    <p>
        <label for="kec_entity">Entity</label>
        <select id="kec_entity" name="kec_entity">
            <option value="all">all</option>
            <option value="user">user</option>
            <option value="post">post</option>
            <option value="term">term</option>
            <option value="comment">comment</option>
        </select>
        <label for="kec_batch">Batch</label>
        <input type="number" id="kec_batch" name="kec_batch" value="500" min="1" max="5000">
        <button type="submit" class="button button-primary" <?php echo null === $search ? 'disabled' : ''; ?>>Reindex</button>
    </p>
    <p class="description">Changing the master key or search secret requires a full reindex.</p>
</form>
