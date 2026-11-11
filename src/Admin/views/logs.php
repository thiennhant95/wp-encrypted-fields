<?php
/**
 * Logs tab.
 *
 * @var \EncryptedFields\Plugin $plugin
 */

$logs = $plugin->logger()->recent(100);
?>
<h2>Logs</h2>
<p class="description">Logs contain identifiers, fields and error codes only. Plaintext and keys are never logged.</p>

<table class="widefat striped" style="max-width: 1000px;">
    <thead>
        <tr>
            <th>Time (UTC)</th>
            <th>Level</th>
            <th>Message</th>
            <th>Context</th>
        </tr>
    </thead>
    <tbody>
        <?php if (empty($logs)) : ?>
            <tr><td colspan="4">No entries.</td></tr>
        <?php else : ?>
            <?php foreach (array_reverse($logs) as $log) : ?>
                <tr>
                    <td><?php echo esc_html(isset($log['time']) ? (string) $log['time'] : ''); ?></td>
                    <td><?php echo esc_html(isset($log['level']) ? (string) $log['level'] : ''); ?></td>
                    <td><?php echo esc_html(isset($log['message']) ? (string) $log['message'] : ''); ?></td>
                    <td><code><?php echo esc_html(isset($log['context']) ? (string) wp_json_encode($log['context']) : ''); ?></code></td>
                </tr>
            <?php endforeach; ?>
        <?php endif; ?>
    </tbody>
</table>

<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-top: 16px;">
    <input type="hidden" name="action" value="kec_settings">
    <input type="hidden" name="kec_action" value="clear_logs">
    <input type="hidden" name="kec_tab" value="logs">
    <?php wp_nonce_field('kec_admin', 'kec_nonce'); ?>
    <p><button type="submit" class="button">Clear logs</button></p>
</form>
