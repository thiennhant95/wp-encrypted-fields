<?php
/**
 * Status tab.
 *
 * @var \Koyo\EncryptedFields\Plugin $plugin
 * @var array<string, mixed> $state
 */

$db = isset($GLOBALS['wpdb']) ? $GLOBALS['wpdb'] : null;
$indexRows = null;
if (is_object($db) && method_exists($db, 'get_var')) {
    $prefix = method_exists($db, 'prefix') ? $db->prefix : (isset($db->prefix) ? $db->prefix : '');
    $indexRows = $db->get_var('SELECT COUNT(*) FROM ' . $prefix . 'kec_search_index');
}

$registry = $plugin->registry();
$fieldCount = 0;
foreach ($registry->all() as $fields) {
    $fieldCount += count($fields);
}

$stateLabel = isset($state['state']) ? (string) $state['state'] : 'unknown';
$ack = isset($state['backup_ack']) && is_array($state['backup_ack']) ? $state['backup_ack'] : null;
?>
<table class="widefat striped" style="max-width: 900px; margin-top: 16px;">
    <tbody>
        <tr>
            <th scope="row">Installation state</th>
            <td><strong><?php echo esc_html($stateLabel); ?></strong></td>
        </tr>
        <tr>
            <th scope="row">Key source</th>
            <td><?php echo esc_html(isset($state['key_source']) ? (string) $state['key_source'] : 'none'); ?></td>
        </tr>
        <tr>
            <th scope="row">Key ID</th>
            <td><?php echo esc_html(!empty($state['key_id']) ? (string) $state['key_id'] : 'not available'); ?></td>
        </tr>
        <tr>
            <th scope="row">Key configured</th>
            <td><?php echo !empty($state['key_configured']) ? 'Yes' : 'No'; ?></td>
        </tr>
        <tr>
            <th scope="row">Registry</th>
            <td><?php echo $registry->isEnabled() ? esc_html(sprintf('%d fields across %d entities', $fieldCount, count($registry->entities()))) : 'Empty (plugin inactive)'; ?></td>
        </tr>
        <tr>
            <th scope="row">Search index rows</th>
            <td><?php echo null === $indexRows ? 'Table not available' : esc_html((string) (int) $indexRows); ?></td>
        </tr>
        <tr>
            <th scope="row">Backup acknowledgement</th>
            <td>
                <?php if (null !== $ack) : ?>
                    <?php echo esc_html(gmdate('Y-m-d H:i:s', (int) $ack['timestamp'])); ?>
                    <?php if (!empty($ack['reference'])) : ?>
                        &mdash; <?php echo esc_html((string) $ack['reference']); ?>
                    <?php endif; ?>
                <?php else : ?>
                    Not confirmed
                <?php endif; ?>
            </td>
        </tr>
        <tr>
            <th scope="row">HPOS</th>
            <td><?php echo !empty($state['hpos']) ? 'Enabled (order fields blocked)' : 'Disabled'; ?></td>
        </tr>
        <tr>
            <th scope="row">Data samples</th>
            <td>
                plaintext <?php echo esc_html((string) (int) ($state['counts']['plaintext'] ?? 0)); ?>,
                legacy <?php echo esc_html((string) (int) ($state['counts']['legacy'] ?? 0)); ?>,
                v2 <?php echo esc_html((string) (int) ($state['counts']['v2'] ?? 0)); ?>
            </td>
        </tr>
    </tbody>
</table>

<?php if (!empty($state['warnings'])) : ?>
    <div class="notice notice-warning inline" style="margin-top: 16px;">
        <ul>
            <?php foreach ($state['warnings'] as $warning) : ?>
                <li><?php echo esc_html(isset($warning['message']) ? (string) $warning['message'] : (string) $warning['code']); ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<p style="margin-top: 16px;">
    <a class="button button-primary" href="<?php echo esc_url(admin_url('admin.php?page=kec-setup')); ?>">Open Setup Wizard</a>
</p>
