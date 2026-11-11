<?php
/**
 * Migration tab.
 *
 * @var \EncryptedFields\Plugin $plugin
 * @var array<string, mixed> $state
 * @var array<string, mixed>|null $result
 */

$ack = isset($state['backup_ack']) && is_array($state['backup_ack']) ? $state['backup_ack'] : null;
$stateName = isset($state['state']) ? (string) $state['state'] : 'unknown';
$pending = (int) ($state['counts']['plaintext'] ?? 0) + (int) ($state['counts']['legacy'] ?? 0);
$hpos = !empty($state['hpos']);
$needsBackup = $pending > 0 && null === $ack;
$data = is_array($result) && isset($result['data']) && is_array($result['data']) ? $result['data'] : null;
?>
<h2>Migration</h2>
<p>Detected state: <strong><?php echo esc_html($stateName); ?></strong>.
    Sampled pending rows: <?php echo esc_html((string) $pending); ?>.</p>

<?php if ($hpos) : ?>
    <div class="notice notice-error inline"><p>WooCommerce HPOS is enabled. Order fields are blocked in v1.</p></div>
<?php endif; ?>

<?php if ($needsBackup) : ?>
    <div class="notice notice-error inline">
        <p><strong>Backup gate:</strong> existing data cannot be migrated until a backup is confirmed. Use the Setup Wizard backup step or the form below.</p>
    </div>
<?php else : ?>
    <div class="notice notice-success inline"><p>Backup gate satisfied.</p></div>
<?php endif; ?>

<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin: 20px 0; padding: 12px; border: 1px solid #dcdcde; background: #fff;">
    <input type="hidden" name="action" value="kec_settings">
    <input type="hidden" name="kec_action" value="save_backup_ack">
    <input type="hidden" name="kec_tab" value="migration">
    <?php wp_nonce_field('kec_admin', 'kec_nonce'); ?>
    <h3>Backup acknowledgement</h3>
    <p>
        <label><input type="checkbox" name="kec_backup_confirm" value="1"> I have a full database and files backup.</label><br>
        <input type="text" class="regular-text" name="kec_backup_reference" placeholder="Backup path, snapshot ID or note" value="<?php echo esc_attr($ack['reference'] ?? ''); ?>">
    </p>
    <p class="description">A safety dump of affected tables is created automatically before migration when possible. It can contain plaintext and is not a full backup; restore requires the same encryption key.</p>
    <p><button type="submit" class="button">Save backup acknowledgement</button></p>
</form>

<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
    <input type="hidden" name="action" value="kec_settings">
    <input type="hidden" name="kec_tab" value="migration">
    <?php wp_nonce_field('kec_admin', 'kec_nonce'); ?>

    <table class="form-table">
        <tr>
            <th scope="row"><label for="kec_entity">Entity</label></th>
            <td>
                <select name="kec_entity" id="kec_entity">
                    <option value="">All</option>
                    <option value="user">user</option>
                    <option value="post">post</option>
                    <option value="term">term</option>
                    <option value="comment">comment</option>
                    <option value="custom">custom table</option>
                </select>
            </td>
        </tr>
        <tr>
            <th scope="row"><label for="kec_field">Field</label></th>
            <td><input type="text" class="regular-text" id="kec_field" name="kec_field" placeholder="optional field/key name"></td>
        </tr>
        <tr>
            <th scope="row"><label for="kec_from">Source</label></th>
            <td>
                <select name="kec_from" id="kec_from">
                    <option value="both">plaintext + legacy</option>
                    <option value="plaintext">plaintext only</option>
                    <option value="legacy">legacy only</option>
                </select>
            </td>
        </tr>
        <tr>
            <th scope="row"><label for="kec_batch">Batch size</label></th>
            <td><input type="number" min="1" max="5000" id="kec_batch" name="kec_batch" value="500"></td>
        </tr>
    </table>

    <p>
        <button type="submit" class="button" name="kec_action" value="dry_run">Dry run</button>
        <button type="submit" class="button" name="kec_action" value="verify">Verify</button>
        <button type="submit" class="button button-primary" name="kec_action" value="migrate" <?php echo $needsBackup ? 'disabled' : ''; ?>>Run migration</button>
    </p>
</form>

<form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" onsubmit="return confirm('Rollback will decrypt matching encrypted fields back to plaintext. Continue?');" style="margin-top: 24px;">
    <input type="hidden" name="action" value="kec_settings">
    <input type="hidden" name="kec_action" value="rollback">
    <input type="hidden" name="kec_tab" value="migration">
    <?php wp_nonce_field('kec_admin', 'kec_nonce'); ?>
    <h3>Rollback</h3>
    <p class="description">Rollback to plaintext decrypts encrypted rows. To restore from a backup, restore the database snapshot confirmed above and keep the original key.</p>
    <p><label><input type="checkbox" name="kec_rollback_confirm" value="1"> I understand this decrypts data back to plaintext.</label></p>
    <p><button type="submit" class="button button-secondary">Rollback to plaintext</button></p>
</form>

<?php if (is_array($data)) : ?>
    <h3>Last result</h3>
    <pre style="max-height: 320px; overflow: auto; background: #f6f7f7; padding: 12px;"><?php echo esc_html(wp_json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)); ?></pre>
<?php endif; ?>
