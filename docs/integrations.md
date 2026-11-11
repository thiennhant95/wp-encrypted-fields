# Integrations

The core plugin has no WooCommerce dependency. Integrations load only when the
corresponding plugin is active.

## WooCommerce

Enabled automatically when `WooCommerce` is loaded.

- Order meta (`_billing_*`, `_shipping_*`, configured fields) is encrypted
  through the normal meta hooks.
- Order search uses the blind index and `woocommerce_shop_order_search_*`
  filters.
- `wc_customer_lookup` analytics rows are encrypted and decrypted in REST
  responses.
- Customer objects are decrypted after `woocommerce_customer_loaded`.
- Customer email/username tokens are resolved when reading customer data.

### HPOS

HPOS is **not supported in v1**. When HPOS is enabled:

- the integration shows an admin notice;
- order fields are not encrypted (the plugin refuses to avoid corrupting
  expectations);
- user/meta features keep working.

Disable HPOS before using order-field encryption.

### Known limitation

WooCommerce's reset-password email template can render the token login. Core
password-reset messages are handled by the plugin.

## SiteGuard

When SiteGuard is active:

- login history keeps plaintext login names (stock SiteGuard UI);
- token user values are resolved when SiteGuard reads a `WP_User`;
- mail recipients are decrypted by the shared `wp_mail` filter.

## Legacy preset

`Integrations\LegacyEcKoyo\Preset` provides a registry matching the original
Koyo implementation:

```bash
wp kec setup --mode=existing --preset=full-ec-koyo
```

It also maps the legacy cipher configuration:

```php
define('KEC_LEGACY', [
    'ctr_key'   => '...',
    'login_key' => '...',
    'email_key' => '...',
    'email_iv'  => '...',
]);
```

Legacy values are read-only; new writes use v2/token mode.

## Custom tables

Register an adapter for tables that store PII outside WordPress meta:

```php
add_filter('kec_table_adapters', function ($adapters) {
    $adapters['my_table'] = new My_Table_Adapter();
    return $adapters;
});
```

Implement `Koyo\EncryptedFields\Contracts\TableAdapterInterface`:

```php
interface TableAdapterInterface
{
    public function name(): string;
    public function columns(): array;
    public function read(int $id): ?array;
    public function write(int $id, array $data): void;
    public function searchableColumns(): array;
}
```

Adapters are optional and are used by `wp kec migrate --table=...`.

## Popular plugin compatibility

See [compatibility.md](compatibility.md).
