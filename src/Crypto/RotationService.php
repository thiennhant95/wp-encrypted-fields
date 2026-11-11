<?php

namespace Koyo\EncryptedFields\Crypto;

use Koyo\EncryptedFields\Migration\LookupMigrator;
use Koyo\EncryptedFields\Migration\Migrator;
use Koyo\EncryptedFields\Plugin;

/**
 * Two-phase key rotation using KEC_KEY_NEXT as the new current key.
 */
final class RotationService
{
    private const STATE_OPTION = 'kec_rotation_state';
    private const TARGET_STATE_OPTION = 'kec_rotation_targets';

    private Plugin $plugin;
    private ?object $db;

    public function __construct(Plugin $plugin, ?object $db = null)
    {
        $this->plugin = $plugin;
        $this->db = $db;
    }

    /**
     * @return array<string, mixed>
     */
    public function rotate(bool $dryRun = false, int $batch = 500, ?callable $progress = null, bool $backupConfirmed = false, bool $safetyDump = true): array
    {
        $keys = $this->plugin->keys();

        if (!$keys->isConfigured()) {
            return $this->failure('key_missing', 'Encryption key is not configured.');
        }

        if (!method_exists($keys, 'isRotationPending') || !$keys->isRotationPending()) {
            return $this->failure('rotation_not_pending', 'Set KEC_KEY_NEXT to the new key while KEC_KEY keeps the old key.');
        }

        $batch = max(1, min(5000, $batch));
        $migrator = new Migrator($this->plugin, $this->db);
        $lookup = new LookupMigrator($this->plugin, $this->db);

        if ($dryRun) {
            $registry = $migrator->rotate(array('dry_run' => true, 'batch' => $batch));
            $customer = $lookup->dryRun('customer_lookup', array('rotate' => true, 'batch' => $batch));
            $siteguard = $lookup->dryRun('siteguard_history', array('batch' => $batch));
            $rows = (int) ($registry['rotation_rows'] ?? 0)
                + (int) ($customer['totals']['pending'] ?? 0)
                + (int) ($siteguard['totals']['pending'] ?? 0);

            return array(
                'ok' => true,
                'mode' => 'rotate_dry_run',
                'rotation_pending' => true,
                'rows' => $rows,
                'registry' => $registry,
                'tables' => array(
                    'customer_lookup' => $customer,
                    'siteguard_history' => $siteguard,
                ),
                'tokens_reissued' => !$keys->tokenSecretIsStable(),
                'backup_satisfied' => $migrator->backupSatisfied(array('backup_confirmed' => $backupConfirmed)),
            );
        }

        if (!$migrator->backupSatisfied(array('backup_confirmed' => $backupConfirmed))) {
            return $this->failure('backup_required', 'Key rotation re-encrypts data and requires a confirmed backup.');
        }

        $lock = $migrator->acquireLock();
        if ('' === $lock) {
            return $this->failure('locked', 'Another migration or rotation is running.');
        }

        $state = $this->loadState();
        $phases = array('registry', 'customer_lookup', 'siteguard_history', 'verify');
        $start = array_search($state['phase'], $phases, true);
        if (false === $start) {
            $start = 0;
            $state['phase'] = 'registry';
        }

        $summary = array(
            'ok' => true,
            'mode' => 'rotate',
            'rotated' => 0,
            'skipped' => 0,
            'errors' => array(),
            'tokens_reissued' => !$keys->tokenSecretIsStable(),
            'phases' => array(),
            'safety_dumps' => array(),
        );

        try {
            for ($index = $start; $index < count($phases); $index++) {
                $phase = $phases[$index];

                if ('registry' === $phase) {
                    $result = $migrator->rotate(array(
                        'batch' => $batch,
                        'lock' => false,
                        'resume' => true,
                        'state_option' => self::TARGET_STATE_OPTION,
                        'backup_confirmed' => true,
                        'safety_dump' => $safetyDump,
                    ));
                } elseif ('customer_lookup' === $phase) {
                    $result = $lookup->rotate('customer_lookup', array(
                        'batch' => $batch,
                        'lock' => false,
                        'resume' => true,
                        'backup_confirmed' => true,
                        'safety_dump' => $safetyDump,
                    ));
                } elseif ('siteguard_history' === $phase) {
                    $result = $lookup->rotate('siteguard_history', array(
                        'batch' => $batch,
                        'lock' => false,
                        'resume' => true,
                        'backup_confirmed' => true,
                        'safety_dump' => $safetyDump,
                    ));
                } else {
                    $result = $this->verify($migrator, $lookup, $batch);
                }

                $summary['phases'][$phase] = $result;

                if (!empty($result['safety_dump'])) {
                    $summary['safety_dumps'][] = (string) $result['safety_dump'];
                }

                if (empty($result['ok'])) {
                    $summary['ok'] = false;
                    $summary['error'] = isset($result['error']) ? (string) $result['error'] : $phase . '_failed';
                    $summary['errors'][] = $summary['error'];
                    $state['phase'] = $phase;
                    $this->saveState($state);
                    break;
                }

                if (isset($result['rotated'])) {
                    $summary['rotated'] += (int) $result['rotated'];
                }
                if (isset($result['migrated'])) {
                    $summary['rotated'] += (int) $result['migrated'];
                }
                if (isset($result['skipped'])) {
                    $summary['skipped'] += (int) $result['skipped'];
                }

                $state['phase'] = $phase;
                $state['completed'][$phase] = true;
                $this->saveState($state);

                if (null !== $progress) {
                    $progress($index + 1, count($phases));
                }
            }
        } finally {
            $migrator->releaseLock($lock);
        }

        if (!empty($summary['ok'])) {
            $this->plugin->deleteOption(self::STATE_OPTION);
            $this->plugin->deleteOption(self::TARGET_STATE_OPTION);
        }

        $this->plugin->logger()->info('key_rotation_finished', array(
            'rotated' => $summary['rotated'],
            'skipped' => $summary['skipped'],
            'errors' => count($summary['errors']),
            'tokens_reissued' => $summary['tokens_reissued'],
        ));

        return $summary;
    }

    /**
     * @return array<string, mixed>
     */
    private function verify(Migrator $migrator, LookupMigrator $lookup, int $batch): array
    {
        $registry = $migrator->verify(array('sample_limit' => 50, 'full' => true));
        $customer = $lookup->verify('customer_lookup');
        $siteguard = $lookup->verify('siteguard_history');

        $ok = !empty($registry['ok']) && !empty($customer['ok']) && !empty($siteguard['ok']);

        return array(
            'ok' => $ok,
            'registry' => array(
                'ok' => !empty($registry['ok']),
                'plaintext' => (int) ($registry['plaintext'] ?? 0),
                'legacy' => (int) ($registry['legacy'] ?? 0),
                'v2' => (int) ($registry['v2'] ?? 0),
            ),
            'tables' => array(
                'customer_lookup' => $customer,
                'siteguard_history' => $siteguard,
            ),
            'batch' => $batch,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function loadState(): array
    {
        $state = $this->plugin->option(self::STATE_OPTION);
        if (!is_array($state) || !isset($state['phase']) || !is_string($state['phase'])) {
            return array('phase' => 'registry', 'started' => time(), 'completed' => array());
        }

        if (!isset($state['completed']) || !is_array($state['completed'])) {
            $state['completed'] = array();
        }

        return $state;
    }

    /**
     * @param array<string, mixed> $state
     */
    private function saveState(array $state): void
    {
        $state['updated'] = time();
        $this->plugin->updateOption(self::STATE_OPTION, $state);
    }

    /**
     * @return array<string, mixed>
     */
    private function failure(string $code, string $message): array
    {
        return array(
            'ok' => false,
            'error' => $code,
            'message' => $message,
            'rotated' => 0,
            'skipped' => 0,
            'errors' => array(),
        );
    }
}
