<?php

namespace Koyo\EncryptedFields\Search;

use Koyo\EncryptedFields\Plugin;

/**
 * Keeps the blind index in sync with WordPress write/delete hooks.
 *
 * Writes are queued and flushed on shutdown so requests are not blocked.
 */
final class Hooks
{
    private Plugin $plugin;
    private ?SearchService $search = null;
    private bool $registered = false;
    private bool $scheduled = false;

    /** @var array<string, array{entity: string, id: int, op: string}> */
    private array $queue = array();

    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    public function register(): void
    {
        if ($this->registered || !function_exists('add_action')) {
            return;
        }

        $this->registered = true;

        add_action('save_post', array($this, 'onSavePost'), 20, 3);
        add_action('user_register', array($this, 'onUser'), 20, 1);
        add_action('profile_update', array($this, 'onUser'), 20, 2);
        add_action('created_term', array($this, 'onTerm'), 20, 3);
        add_action('edited_term', array($this, 'onTerm'), 20, 3);
        add_action('deleted_post', array($this, 'onDeletedPost'), 20, 1);
        add_action('deleted_user', array($this, 'onDeletedUser'), 20, 1);
        add_action('deleted_term', array($this, 'onDeletedTerm'), 20, 3);

        foreach (array('post', 'user', 'term', 'comment') as $type) {
            foreach (array('added', 'updated', 'deleted') as $event) {
                add_action(
                    $event . '_' . $type . '_meta',
                    function ($metaId, $objectId, $metaKey = '') use ($type): void {
                        $this->onMeta($type, (int) $objectId, $metaKey);
                    },
                    20,
                    3
                );
            }
        }
    }

    public function onSavePost($postId, $post = null, $update = false): void
    {
        $postId = (int) $postId;
        if ($postId <= 0) {
            return;
        }

        if (function_exists('wp_is_post_revision') && wp_is_post_revision($postId)) {
            return;
        }

        if (function_exists('wp_is_post_autosave') && wp_is_post_autosave($postId)) {
            return;
        }

        $this->queue('post', $postId, 'index');
    }

    public function onUser($userId, $oldUserData = null): void
    {
        $this->queue('user', (int) $userId, 'index');
    }

    public function onTerm($termId, $termTaxonomyId = null, $taxonomy = ''): void
    {
        $this->queue('term', (int) $termId, 'index');
    }

    public function onDeletedPost($postId): void
    {
        $this->queue('post', (int) $postId, 'remove');
    }

    public function onDeletedUser($userId): void
    {
        $this->queue('user', (int) $userId, 'remove');
    }

    public function onDeletedTerm($termId, $termTaxonomyId = null, $taxonomy = ''): void
    {
        $this->queue('term', (int) $termId, 'remove');
    }

    /**
     * Keep the blind index in sync when searchable meta is written directly.
     *
     * @param mixed $metaKey
     */
    public function onMeta(string $entity, int $objectId, $metaKey = ''): void
    {
        if ($objectId <= 0) {
            return;
        }

        $keys = is_array($metaKey) ? $metaKey : array($metaKey);

        try {
            $registry = $this->plugin->registry();
        } catch (\Throwable $e) {
            return;
        }

        foreach ($keys as $key) {
            $key = (string) $key;
            if ('' === $key) {
                continue;
            }

            $field = $registry->get($entity, $key);
            if (null !== $field && $field->isSearchable()) {
                $this->queue($entity, $objectId, 'index');

                return;
            }
        }
    }

    public function flush(): void
    {
        $queue = $this->queue;
        $this->queue = array();
        $this->scheduled = false;

        foreach ($queue as $item) {
            try {
                if ('remove' === $item['op']) {
                    $this->search()->remove($item['entity'], $item['id']);
                } else {
                    $this->search()->index($item['entity'], $item['id']);
                }
            } catch (\Throwable $e) {
                $this->logFailure($item['entity'], $item['id'], $e);
            }
        }
    }

    private function queue(string $entity, int $id, string $op): void
    {
        if ($id <= 0) {
            return;
        }

        $key = $entity . ':' . $id;
        $this->queue[$key] = array(
            'entity' => $entity,
            'id' => $id,
            'op' => $op,
        );

        if (!$this->scheduled && function_exists('add_action')) {
            $this->scheduled = true;
            add_action('shutdown', array($this, 'flush'), 20, 0);
        }
    }

    private function search(): SearchService
    {
        try {
            $existing = $this->plugin->search();
            if ($existing instanceof SearchService) {
                return $existing;
            }
        } catch (\Throwable $e) {
            // Fall back to a local instance below.
        }

        if (null === $this->search) {
            $this->search = new SearchService($this->plugin);
        }

        return $this->search;
    }

    private function logFailure(string $entity, int $id, \Throwable $error): void
    {
        try {
            $logger = $this->plugin->logger();
            if (is_object($logger) && method_exists($logger, 'warning')) {
                $logger->warning('Search hook failed.', array(
                    'entity' => $entity,
                    'id' => $id,
                    'error' => get_class($error),
                ));
            }
        } catch (\Throwable $ignored) {
            // Logging must never break shutdown.
        }
    }
}
