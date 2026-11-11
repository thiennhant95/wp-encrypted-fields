<?php

namespace EncryptedFields\Integrations\WooCommerce;

use EncryptedFields\Config\Field;
use EncryptedFields\Config\Registry;
use EncryptedFields\Plugin;
use EncryptedFields\User\ColumnStore;

/**
 * WooCommerce integration.
 *
 * v1 does not support HPOS. When HPOS is enabled, order fields are blocked
 * from encryption while user/customer hooks stay active. When HPOS is off,
 * order search is delegated to the plugin search index for the post entity.
 */
final class Integration
{
    private Plugin $plugin;
    private ?ColumnStore $columns = null;

    public function __construct(Plugin $plugin)
    {
        $this->plugin = $plugin;
    }

    public function register(): void
    {
        if ($this->isHposEnabled()) {
            $this->registerHposGuards();
        } else {
            $this->registerOrderSearch();
        }

        $this->registerCustomerHooks();
    }

    public function isHposEnabled(): bool
    {
        $orderUtil = 'Automattic\\WooCommerce\\Utilities\\OrderUtil';

        if (class_exists($orderUtil) && method_exists($orderUtil, 'custom_orders_table_usage_is_enabled')) {
            return (bool) call_user_func(array($orderUtil, 'custom_orders_table_usage_is_enabled'));
        }

        if (!function_exists('get_option')) {
            return false;
        }

        $option = get_option('woocommerce_custom_orders_table_enabled');

        return in_array($option, array('yes', '1', 1, true), true);
    }

    private function registerHposGuards(): void
    {
        if (function_exists('add_action')) {
            add_action('admin_notices', array($this, 'renderHposNotice'), 10, 0);
        }

        if (function_exists('add_filter')) {
            add_filter('kec_should_encrypt', array($this, 'filterShouldEncrypt'), 10, 4);
        }

        $this->warning('WooCommerce HPOS is enabled; order fields are not encrypted in v1.', array(
            'entity' => 'post',
            'post_type' => 'shop_order',
        ));
    }

    /**
     * Keep order meta plaintext while HPOS is active; never block user fields.
     *
     * @param mixed $should
     * @param mixed $entity
     * @param mixed $key
     * @param mixed $context
     * @return mixed
     */
    public function filterShouldEncrypt($should, $entity = '', $key = '', $context = array())
    {
        if ('post' !== $entity) {
            return $should;
        }

        if (is_string($key) && 0 === strpos($key, '_')) {
            return false;
        }

        if (is_array($context) && isset($context['post_type']) && 'shop_order' === $context['post_type']) {
            return false;
        }

        return $should;
    }

    public function renderHposNotice(): void
    {
        if (function_exists('current_user_can') && !current_user_can('manage_options')) {
            return;
        }

        $message = 'Encrypted Fields: WooCommerce HPOS is enabled. Order fields are not encrypted in v1; customer and user fields remain protected.';
        if (function_exists('esc_html')) {
            $message = esc_html($message);
        }

        echo '<div class="notice notice-warning"><p>' . $message . '</p></div>';
    }

    private function registerOrderSearch(): void
    {
        if (function_exists('add_filter')) {
            add_filter('woocommerce_shop_order_search_fields', array($this, 'filterSearchFields'), 10, 1);
            add_filter('woocommerce_shop_order_search_results', array($this, 'filterSearchResults'), 10, 3);
        }
    }

    /**
     * Remove encrypted fields from WC LIKE search and keep plaintext fields.
     *
     * @param mixed $fields
     * @return array
     */
    public function filterSearchFields($fields): array
    {
        $fields = is_array($fields) ? $fields : array();
        $registry = $this->registry();

        if (!$registry) {
            return $fields;
        }

        $result = array();
        foreach ($fields as $field) {
            if (is_string($field) && $registry->has('post', $field) && !$registry->isReadonly('post', $field)) {
                continue;
            }
            $result[] = $field;
        }

        return $result;
    }

    /**
     * Add blind-index order IDs to WC's plaintext search results.
     *
     * @param mixed $orderIds
     * @param mixed $term
     * @param mixed $searchFields
     * @return array
     */
    public function filterSearchResults($orderIds, $term = '', $searchFields = array()): array
    {
        $ids = is_array($orderIds) ? array_map('intval', $orderIds) : array();
        $search = $this->search();

        if (!$search || !is_string($term) || '' === trim($term)) {
            return $ids;
        }

        try {
            $found = $search->ids('post', $term, 300);
        } catch (\Throwable $e) {
            return $ids;
        }

        if (!is_array($found)) {
            return $ids;
        }

        $found = array_map('intval', $found);

        if (function_exists('get_post_type')) {
            $found = array_values(array_filter($found, function ($id) {
                return 'shop_order' === get_post_type($id);
            }));
        }

        return array_values(array_unique(array_merge($ids, $found)));
    }

    private function registerCustomerHooks(): void
    {
        if (function_exists('add_action')) {
            add_action('woocommerce_customer_loaded', array($this, 'onCustomerLoaded'), 10, 1);
            add_action('woocommerce_analytics_new_customer', array($this, 'onAnalyticsCustomer'), 10, 1);
            add_action('woocommerce_analytics_update_customer', array($this, 'onAnalyticsCustomer'), 10, 1);
        }

        if (function_exists('add_filter')) {
            add_filter('rest_post_dispatch', array($this, 'filterRestResponse'), 10, 3);
        }
    }

    /**
     * Decrypt email/username on a loaded WC_Customer.
     *
     * WC setters mark the customer as changed; apply_changes() commits the
     * plaintext and clears the dirty state so a later save does not write the
     * ciphertext back. Writing directly into WC_Data::$data via reflection is
     * more invasive and is intentionally avoided.
     *
     * @param mixed $customer
     */
    public function onCustomerLoaded($customer): void
    {
        if (!is_object($customer)) {
            return;
        }

        $changed = false;
        $userId = $this->customerId($customer);

        if (method_exists($customer, 'get_email') && method_exists($customer, 'set_email')) {
            $email = $customer->get_email();
            if (is_string($email) && '' !== $email) {
                $plain = $this->resolveUserValue($email, 'user', 'user_email', 'email', ColumnStore::EMAIL, $userId);
                if (is_string($plain) && '' !== $plain && $plain !== $email) {
                    $customer->set_email($plain);
                    $changed = true;
                }
            }
        }

        if (method_exists($customer, 'get_username') && method_exists($customer, 'set_username')) {
            $username = $customer->get_username();
            if (is_string($username) && '' !== $username) {
                $plain = $this->resolveUserValue($username, 'user', 'user_login', 'login', ColumnStore::LOGIN, $userId);
                if (is_string($plain) && '' !== $plain && $plain !== $username) {
                    $customer->set_username($plain);
                    $changed = true;
                }
            }
        }

        if ($changed && method_exists($customer, 'apply_changes')) {
            $customer->apply_changes();
        }
    }

    /**
     * Encrypt the WC customer lookup row after analytics writes it.
     *
     * @param mixed $customerId
     */
    public function onAnalyticsCustomer($customerId): void
    {
        $customerId = (int) $customerId;
        if ($customerId <= 0 || !isset($GLOBALS['wpdb']) || !is_object($GLOBALS['wpdb'])) {
            return;
        }

        $wpdb = $GLOBALS['wpdb'];
        if (!method_exists($wpdb, 'get_row') || !method_exists($wpdb, 'update') || !method_exists($wpdb, 'prepare')) {
            return;
        }

        $table = $wpdb->prefix . 'wc_customer_lookup';

        $widened = CustomerLookupSchema::ensure($wpdb);

        $format = defined('ARRAY_A') ? ARRAY_A : 'ARRAY_A';
        $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE customer_id = %d", $customerId), $format);

        if (!is_array($row)) {
            return;
        }

        $data = array();
        $map = array(
            'first_name' => 'text',
            'last_name' => 'text',
            'city' => 'text',
            'email' => 'email',
            'username' => 'login',
        );
        $maxLengths = $widened
            ? array(
                'first_name' => 255,
                'last_name' => 255,
                'city' => 255,
                'email' => 255,
                'username' => 255,
            )
            : array(
                'first_name' => 255,
                'last_name' => 255,
                'city' => 100,
                'email' => 100,
                'username' => 60,
            );

        foreach ($map as $key => $type) {
            if (!isset($row[$key]) || !is_string($row[$key]) || '' === $row[$key]) {
                continue;
            }

            $value = $row[$key];
            $name = 'email' === $key ? ColumnStore::EMAIL : ('username' === $key ? ColumnStore::LOGIN : '');
            $columns = '' !== $name ? $this->columnStore() : null;

            if (null !== $columns && $columns->isToken($value, $name)) {
                $plain = $this->tokenPlaintext($value, $name, $customerId);
                if (null === $plain) {
                    continue;
                }
                $value = $plain;
            }

            $encrypted = $this->encryptValue($value, 'user', $key, $type);
            if (is_string($encrypted) && $encrypted !== $value) {
                $max = isset($maxLengths[$key]) ? (int) $maxLengths[$key] : 0;

                if ($max > 0 && strlen($encrypted) > $max) {
                    try {
                        $this->plugin->logger()->warning('Woo customer lookup value is too long to encrypt.', array(
                            'column' => $key,
                            'max_length' => $max,
                            'cipher_length' => strlen($encrypted),
                        ));
                    } catch (\Throwable $ignored) {
                        // Logging must never break the lookup update.
                    }

                    continue;
                }

                $data[$key] = $encrypted;
            }
        }

        if (!empty($data)) {
            $wpdb->update($table, $data, array('customer_id' => $customerId));
        }
    }

    /**
     * Decrypt customer rows returned by WooCommerce Analytics REST endpoints.
     *
     * @param mixed $response
     * @param mixed $server
     * @param mixed $request
     * @return mixed
     */
    public function filterRestResponse($response, $server = null, $request = null)
    {
        if (!is_object($response) || !method_exists($response, 'get_data') || !method_exists($response, 'set_data')) {
            return $response;
        }

        $route = (is_object($request) && method_exists($request, 'get_route')) ? (string) $request->get_route() : '';
        if ('' === $route) {
            return $response;
        }

        $isReport = false !== strpos($route, 'reports/customers');
        $isLeader = false !== strpos($route, 'leaderboards/customers');
        $isCustomer = (bool) preg_match('#/wc-analytics/customers(?:/|$)#', $route);

        if (!$isReport && !$isLeader && !$isCustomer) {
            return $response;
        }

        $data = $response->get_data();
        if (!is_array($data)) {
            return $response;
        }

        $response->set_data($this->decryptPayload($data));

        return $response;
    }

    /**
     * Decrypt known customer fields in a single analytics row.
     *
     * @param mixed $row
     * @return mixed
     */
    public function decryptAnalyticsRow($row)
    {
        if (!is_array($row)) {
            return $row;
        }

        $map = array(
            'first_name' => 'text',
            'last_name' => 'text',
            'city' => 'text',
            'email' => 'email',
            'username' => 'login',
        );
        $userId = $this->rowUserId($row);

        foreach ($map as $key => $type) {
            if (isset($row[$key]) && is_string($row[$key]) && '' !== $row[$key]) {
                $name = 'email' === $key ? ColumnStore::EMAIL : ('username' === $key ? ColumnStore::LOGIN : '');
                $row[$key] = '' !== $name
                    ? $this->resolveUserValue($row[$key], 'user', $key, $type, $name, $userId)
                    : $this->decryptValue($row[$key], 'user', $key, $type);
            }
        }

        if (isset($row['name']) && is_string($row['name']) && '' !== $row['name']) {
            $parts = preg_split('/\s+/', trim($row['name']));
            if (is_array($parts)) {
                $decrypted = array();
                foreach ($parts as $part) {
                    $plain = $part;

                    foreach (array('first_name', 'last_name') as $candidate) {
                        $value = $this->decryptValue($part, 'user', $candidate, 'text');

                        if (is_string($value) && '' !== $value && $value !== $part) {
                            $plain = $value;
                            break;
                        }
                    }

                    if (is_string($plain) && '' !== $plain) {
                        $decrypted[] = $plain;
                    }
                }
                $row['name'] = implode(' ', $decrypted);
            }
        }

        return $row;
    }

    /**
     * @param mixed $data
     * @return mixed
     */
    private function decryptPayload($data)
    {
        if (!is_array($data)) {
            return $data;
        }

        if ($this->looksLikeCustomerRow($data)) {
            return $this->decryptAnalyticsRow($data);
        }

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = $this->decryptPayload($value);
            }
        }

        return $data;
    }

    private function looksLikeCustomerRow(array $row): bool
    {
        foreach (array('first_name', 'last_name', 'email', 'username', 'city', 'name') as $key) {
            if (array_key_exists($key, $row)) {
                return true;
            }
        }

        return false;
    }

    private function resolveUserValue(
        string $value,
        string $entity,
        string $key,
        string $type,
        string $name,
        ?int $userId = null
    ): string {
        $plain = $this->tokenPlaintext($value, $name, $userId);
        if (null !== $plain) {
            return $plain;
        }

        $decrypted = $this->decryptValue($value, $entity, $key, $type);

        return is_string($decrypted) ? $decrypted : $value;
    }

    private function tokenPlaintext(string $value, string $name, ?int $userId = null): ?string
    {
        $columns = $this->columnStore();
        if (null === $columns || !$columns->isToken($value, $name)) {
            return null;
        }

        if (null === $userId || $userId <= 0) {
            $userId = $columns->userIdByToken($value, $name);
        }

        if (null === $userId || $userId <= 0) {
            return null;
        }

        $plain = $columns->readPlain($userId, $name);

        return is_string($plain) && '' !== $plain ? $plain : null;
    }

    /**
     * @param mixed $customer
     */
    private function customerId($customer): int
    {
        if (!is_object($customer)) {
            return 0;
        }

        foreach (array('get_id', 'get_user_id', 'get_customer_id') as $method) {
            if (method_exists($customer, $method)) {
                return (int) $customer->{$method}();
            }
        }

        foreach (array('id', 'ID') as $property) {
            if (isset($customer->{$property}) && is_numeric($customer->{$property})) {
                return (int) $customer->{$property};
            }
        }

        return 0;
    }

    /**
     * @param array<string, mixed> $row
     */
    private function rowUserId(array $row): int
    {
        foreach (array('customer_id', 'user_id', 'id') as $key) {
            if (isset($row[$key]) && is_numeric($row[$key])) {
                return (int) $row[$key];
            }
        }

        return 0;
    }

    private function columnStore(): ?ColumnStore
    {
        if (null !== $this->columns) {
            return $this->columns;
        }

        if (!class_exists(ColumnStore::class)) {
            return null;
        }

        try {
            $this->columns = new ColumnStore($this->plugin);
        } catch (\Throwable $e) {
            return null;
        }

        return $this->columns;
    }

    /**
     * Default-deny: only encrypt/decrypt fields explicitly declared in the
     * registry. Analytics columns map email/username back to the user columns.
     */
    private function isDeclared(string $entity, string $key): bool
    {
        $registry = $this->registry();

        if (!$registry instanceof Registry) {
            return false;
        }

        if ($registry->has($entity, $key)) {
            return true;
        }

        if ('email' === $key) {
            return $registry->has($entity, 'user_email');
        }

        if ('username' === $key) {
            return $registry->has($entity, 'user_login');
        }

        return false;
    }

    private function field(string $entity, string $key, string $type): Field
    {
        $registry = $this->registry();

        if ($registry) {
            $field = $registry->get($entity, $key);
            if ($field instanceof Field) {
                return $field;
            }
        }

        return new Field($entity, $key, $type);
    }

    /**
     * @param mixed $value
     * @return mixed
     */
    private function decryptValue($value, string $entity, string $key, string $type)
    {
        if (!is_string($value) || '' === $value) {
            return $value;
        }

        if (!$this->isDeclared($entity, $key)) {
            return $value;
        }

        $crypto = $this->crypto();
        if (!$crypto) {
            return $value;
        }

        try {
            $plain = $crypto->decrypt($value, $this->field($entity, $key, $type));
        } catch (\Throwable $e) {
            return $value;
        }

        return is_string($plain) ? $plain : $value;
    }

    /**
     * @param mixed $value
     * @return mixed
     */
    private function encryptValue($value, string $entity, string $key, string $type)
    {
        if (!is_string($value) || '' === $value) {
            return $value;
        }

        if (!$this->isDeclared($entity, $key)) {
            return $value;
        }

        $crypto = $this->crypto();
        if (!$crypto) {
            return $value;
        }

        try {
            if (method_exists($crypto, 'isEncrypted') && $crypto->isEncrypted($value)) {
                return $value;
            }

            $encrypted = $crypto->encrypt($value, $this->field($entity, $key, $type));
        } catch (\Throwable $e) {
            return $value;
        }

        return (is_string($encrypted) && '' !== $encrypted) ? $encrypted : $value;
    }

    private function registry(): ?Registry
    {
        try {
            return $this->plugin->registry();
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function search(): ?\EncryptedFields\Contracts\SearchInterface
    {
        try {
            return $this->plugin->search();
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function crypto(): ?\EncryptedFields\Contracts\EncryptorInterface
    {
        try {
            return $this->plugin->crypto();
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function warning(string $message, array $context = array()): void
    {
        try {
            $logger = $this->plugin->logger();
            if (is_object($logger) && method_exists($logger, 'warning')) {
                $logger->warning($message, $context);
            }
        } catch (\Throwable $e) {
            return;
        }
    }
}
