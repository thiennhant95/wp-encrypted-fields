<?php
/**
 * Health check tab.
 *
 * @var \Koyo\EncryptedFields\Plugin $plugin
 * @var array<string, mixed> $state
 */

$phpOk = version_compare(PHP_VERSION, '8.0', '>=');
$sodium = extension_loaded('sodium') || function_exists('sodium_crypto_secretbox');
$openssl = extension_loaded('openssl');
$intl = class_exists('Normalizer');
$writable = defined('WP_CONTENT_DIR') ? is_writable(WP_CONTENT_DIR) : false;
$multisite = function_exists('is_multisite') && is_multisite();
$externalCache = function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache();
$hpos = !empty($state['hpos']);
$plaintextWarnings = array();
foreach (isset($state['warnings']) && is_array($state['warnings']) ? $state['warnings'] : array() as $warning) {
    if (isset($warning['code']) && 'plaintext_plugin' === $warning['code']) {
        $plaintextWarnings[] = isset($warning['message']) ? (string) $warning['message'] : 'Known plaintext plugin';
    }
}
?>
<h2>Health Check</h2>
<table class="widefat striped" style="max-width: 900px;">
    <thead>
        <tr><th>Check</th><th>Status</th><th>Notes</th></tr>
    </thead>
    <tbody>
        <tr>
            <td>PHP version</td>
            <td><?php echo $phpOk ? 'OK' : 'FAIL'; ?></td>
            <td><?php echo esc_html(PHP_VERSION . ' (requires 8.0+)'); ?></td>
        </tr>
        <tr>
            <td>Sodium</td>
            <td><?php echo $sodium ? 'OK' : 'WARN'; ?></td>
            <td>Preferred cipher backend.</td>
        </tr>
        <tr>
            <td>OpenSSL</td>
            <td><?php echo $openssl ? 'OK' : 'WARN'; ?></td>
            <td>Legacy and deterministic cipher support.</td>
        </tr>
        <tr>
            <td>Normalizer (intl)</td>
            <td><?php echo $intl ? 'OK' : 'WARN'; ?></td>
            <td>Search normalization falls back to lowercase when missing.</td>
        </tr>
        <tr>
            <td>Content directory writable</td>
            <td><?php echo $writable ? 'OK' : 'INFO'; ?></td>
            <td>Needed only for optional safety dumps.</td>
        </tr>
        <tr>
            <td>HPOS</td>
            <td><?php echo $hpos ? 'BLOCKED' : 'OK'; ?></td>
            <td>Order fields are disabled when HPOS is enabled.</td>
        </tr>
        <tr>
            <td>Multisite</td>
            <td><?php echo $multisite ? 'INFO' : 'OK'; ?></td>
            <td>Wizard runs per site; key may be network-level.</td>
        </tr>
        <tr>
            <td>External object cache</td>
            <td><?php echo $externalCache ? 'INFO' : 'OK'; ?></td>
            <td>Plaintext is not written to persistent object cache.</td>
        </tr>
        <tr>
            <td>Plaintext logging/CRM plugins</td>
            <td><?php echo array() !== $plaintextWarnings ? 'WARN' : 'OK'; ?></td>
            <td>
                <?php if (array() === $plaintextWarnings) : ?>
                    No known plaintext email/CRM plugin detected.
                <?php else : ?>
                    <ul style="margin: 0;">
                        <?php foreach ($plaintextWarnings as $plaintextWarning) : ?>
                            <li><?php echo esc_html($plaintextWarning); ?></li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </td>
        </tr>
    </tbody>
</table>
