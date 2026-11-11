<?php
/**
 * Setup wizard view.
 *
 * @var \Koyo\EncryptedFields\Plugin $plugin
 * @var array<string, mixed> $state
 * @var array<string, mixed> $setup
 * @var string $step
 * @var string|null $generatedKey
 * @var array<string, mixed>|null $result
 * @var array<string, mixed>|null $ack
 * @var bool $needsBackup
 * @var array<string, array<string, mixed>> $presets
 * @var string $preset
 */

$steps = array(
    'start' => 'Start',
    'environment' => 'Environment',
    'key' => 'Key',
    'fields' => 'Fields',
    'backup' => 'Backup',
    'dryrun' => 'Dry run',
    'migrate' => 'Migrate',
    'verify' => 'Verify',
    'finalize' => 'Finalize',
);

$order = array_keys($steps);
$currentIndex = array_search($step, $order, true);
$stateName = isset($state['state']) ? (string) $state['state'] : 'fresh';
$busy = (bool) ($setup['step'] ?? false);
?>
<div class="wrap">
    <h1>Encrypted Fields Setup</h1>
    <p>Detected state: <strong><?php echo esc_html($stateName); ?></strong>.
        Key source: <strong><?php echo esc_html((string) ($state['key_source'] ?? 'none')); ?></strong>.
        HPOS: <strong><?php echo !empty($state['hpos']) ? 'enabled (order fields blocked)' : 'disabled'; ?></strong>.
    </p>

    <nav class="nav-tab-wrapper" style="margin-bottom: 16px;">
        <?php foreach ($order as $index => $slug) : ?>
            <?php
            if ($slug === 'backup' && !$needsBackup) {
                continue;
            }
            $class = 'nav-tab';
            if ($slug === $step) {
                $class .= ' nav-tab-active';
            } elseif (false !== $currentIndex && $index < $currentIndex) {
                $class .= ' kec-complete';
            }
            ?>
            <span class="<?php echo esc_attr($class); ?>" style="cursor: default;"><?php echo esc_html($steps[$slug]); ?></span>
        <?php endforeach; ?>
    </nav>

    <?php if (is_array($result)) : ?>
        <div class="notice <?php echo !empty($result['ok']) ? 'notice-success' : 'notice-error'; ?>">
            <p><?php echo esc_html(isset($result['message']) ? (string) $result['message'] : ''); ?></p>
        </div>
    <?php endif; ?>

    <?php if (!empty($state['warnings'])) : ?>
        <div class="notice notice-warning">
            <ul>
                <?php foreach ($state['warnings'] as $warning) : ?>
                    <li><?php echo esc_html((string) $warning['message']); ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <?php if ('start' === $step) : ?>
        <h2>Choose setup mode</h2>
        <p>Use <em>fresh</em> for a new project. Existing data requires a confirmed backup before any migration.</p>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <input type="hidden" name="action" value="kec_wizard">
            <input type="hidden" name="kec_action" value="start">
            <?php wp_nonce_field('kec_wizard', 'kec_nonce'); ?>
            <p>
                <label><input type="radio" name="kec_mode" value="fresh" checked> Fresh project</label><br>
                <label><input type="radio" name="kec_mode" value="existing"> Existing data (plaintext/legacy)</label>
            </p>
            <p><button type="submit" class="button button-primary">Continue</button></p>
        </form>

    <?php elseif ('environment' === $step) : ?>
        <h2>Environment</h2>
        <table class="widefat striped" style="max-width: 800px;">
            <tbody>
                <tr><th>PHP &gt;= 8.0</th><td><?php echo version_compare(PHP_VERSION, '8.0', '>=') ? 'OK' : 'FAIL'; ?></td></tr>
                <tr><th>OpenSSL</th><td><?php echo extension_loaded('openssl') ? 'OK' : 'WARN'; ?></td></tr>
                <tr><th>Sodium</th><td><?php echo extension_loaded('sodium') ? 'OK' : 'WARN'; ?></td></tr>
                <tr><th>Normalizer (intl)</th><td><?php echo class_exists('Normalizer') ? 'OK' : 'WARN'; ?></td></tr>
                <tr><th>HPOS</th><td><?php echo !empty($state['hpos']) ? 'BLOCKED for order fields' : 'OK'; ?></td></tr>
                <tr><th>Multisite</th><td><?php echo function_exists('is_multisite') && is_multisite() ? 'Per-site setup required' : 'Single site'; ?></td></tr>
            </tbody>
        </table>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-top: 16px;">
            <input type="hidden" name="action" value="kec_wizard">
            <input type="hidden" name="kec_action" value="environment">
            <?php wp_nonce_field('kec_wizard', 'kec_nonce'); ?>
            <p><button type="submit" class="button button-primary">Continue</button></p>
        </form>

    <?php elseif ('key' === $step) : ?>
        <h2>Encryption key</h2>
        <p>Recommended: define <code>KEC_KEY</code> in <code>wp-config.php</code> or the environment, outside the database and source code.</p>
        <p>Current key source: <strong><?php echo esc_html((string) ($state['key_source'] ?? 'none')); ?></strong>.
            Key configured: <strong><?php echo !empty($state['key_configured']) ? 'yes' : 'no'; ?></strong>.</p>

        <?php if (null !== $generatedKey) : ?>
            <div class="notice notice-warning">
                <p><strong>Copy this key now. It is shown once and is not stored by the wizard.</strong></p>
                <textarea readonly rows="3" class="large-text code" onclick="this.select();"><?php echo esc_textarea("define('KEC_KEY', '" . $generatedKey . "');"); ?></textarea>
            </div>
        <?php endif; ?>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-top: 12px;">
            <input type="hidden" name="action" value="kec_wizard">
            <?php wp_nonce_field('kec_wizard', 'kec_nonce'); ?>
            <p>
                <button type="submit" class="button" name="kec_action" value="key_generate">Generate key (shown once)</button>
                <button type="submit" class="button button-primary" name="kec_action" value="key">I have configured the key</button>
            </p>
        </form>
        <p class="description">Database key storage is disabled by default. It requires <code>KEC_ALLOW_DB_KEY=true</code> and weakens at-rest protection because a database leak exposes the key.</p>

    <?php elseif ('fields' === $step) : ?>
        <h2>Select fields</h2>
        <p>Only declared fields are encrypted. Default deny applies.</p>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <input type="hidden" name="action" value="kec_wizard">
            <input type="hidden" name="kec_action" value="fields">
            <?php wp_nonce_field('kec_wizard', 'kec_nonce'); ?>

            <?php foreach ($presets as $slug => $meta) : ?>
                <p><label>
                    <input type="radio" name="kec_preset" value="<?php echo esc_attr($slug); ?>" <?php echo $slug === $preset ? 'checked' : ''; ?>>
                    <strong><?php echo esc_html((string) $meta['label']); ?></strong>
                    <?php if ('full-ec-koyo' === $slug) : ?>
                        &mdash; EC-KOYO billing/shipping/user fields
                    <?php elseif ('minimal' === $slug) : ?>
                        &mdash; a small set of user and order fields
                    <?php endif; ?>
                </label></p>
            <?php endforeach; ?>

            <?php if (!empty($state['hpos'])) : ?>
                <div class="notice notice-warning inline"><p>HPOS is enabled. Order fields are removed from the selected preset in v1.</p></div>
            <?php endif; ?>

            <p><label for="kec_custom_fields"><strong>Custom registry JSON</strong></label></p>
            <textarea name="kec_custom_fields" id="kec_custom_fields" rows="14" class="large-text code" placeholder='{ "user": { "meta": { "billing_phone": { "type": "text", "search": true } } } }'></textarea>
            <p class="description">Used only when the Custom JSON preset is selected.</p>

            <p><button type="submit" class="button button-primary">Save fields and continue</button></p>
        </form>

    <?php elseif ('backup' === $step) : ?>
        <h2>Backup gate</h2>
        <p>Existing data cannot be migrated without a confirmed backup. Create a full database and files backup first.</p>
        <ul>
            <li>Suggested: <code>wp db export backup-<?php echo esc_html(gmdate('Ymd-His')); ?>.sql</code></li>
            <li>Or use your hosting/backup plugin snapshot.</li>
            <li>A safety dump of affected tables is created automatically before migration when the content directory is writable. It can contain plaintext and is not a full backup.</li>
        </ul>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <input type="hidden" name="action" value="kec_wizard">
            <input type="hidden" name="kec_action" value="backup">
            <?php wp_nonce_field('kec_wizard', 'kec_nonce'); ?>
            <p><label><input type="checkbox" name="kec_backup_confirm" value="1"> I have completed a full database and files backup.</label></p>
            <p><input type="text" class="regular-text" name="kec_backup_reference" placeholder="Backup path, snapshot ID or note" value="<?php echo esc_attr($ack['reference'] ?? ''); ?>"></p>
            <p><button type="submit" class="button button-primary">Confirm backup and continue</button></p>
        </form>

    <?php elseif ('dryrun' === $step) : ?>
        <h2>Dry run</h2>
        <p>No data is changed in this step. The report lists row counts and length risks only.</p>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <input type="hidden" name="action" value="kec_wizard">
            <input type="hidden" name="kec_action" value="dryrun">
            <?php wp_nonce_field('kec_wizard', 'kec_nonce'); ?>
            <p><button type="submit" class="button button-primary">Run dry run</button></p>
        </form>

    <?php elseif ('migrate' === $step) : ?>
        <h2>Run migration</h2>
        <?php if ($needsBackup && null === $ack) : ?>
            <div class="notice notice-error inline"><p>Backup confirmation is required before migration.</p></div>
        <?php else : ?>
            <p>Rows are processed in batches and the run is resumable. Legacy ciphertext is read and re-encrypted as v2.</p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="kec_wizard">
                <input type="hidden" name="kec_action" value="migrate">
                <?php wp_nonce_field('kec_wizard', 'kec_nonce'); ?>
                <p><label for="kec_batch">Batch size</label>
                    <input type="number" id="kec_batch" name="kec_batch" value="500" min="1" max="5000"></p>
                <p><button type="submit" class="button button-primary">Start migration</button></p>
            </form>
        <?php endif; ?>

    <?php elseif ('verify' === $step) : ?>
        <h2>Verify</h2>
        <p>Checks that selected fields no longer contain plaintext or legacy ciphertext and that v2 samples decrypt.</p>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <input type="hidden" name="action" value="kec_wizard">
            <input type="hidden" name="kec_action" value="verify">
            <?php wp_nonce_field('kec_wizard', 'kec_nonce'); ?>
            <p><button type="submit" class="button button-primary">Run verification</button></p>
        </form>

    <?php elseif ('finalize' === $step) : ?>
        <h2>Finalize</h2>
        <p>Finalizing clears the migration lock and turns on normal operation. Keep the confirmed backup and original key.</p>
        <p>Rollback to plaintext is available in Settings &rarr; Encrypted Fields &rarr; Migration. To restore from backup, restore the database snapshot and keep the original key.</p>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <input type="hidden" name="action" value="kec_wizard">
            <input type="hidden" name="kec_action" value="finalize">
            <?php wp_nonce_field('kec_wizard', 'kec_nonce'); ?>
            <p><button type="submit" class="button button-primary">Finish setup</button></p>
        </form>
        <p><a href="<?php echo esc_url(admin_url('options-general.php?page=kec-settings')); ?>">Go to Status</a></p>
    <?php endif; ?>
</div>
