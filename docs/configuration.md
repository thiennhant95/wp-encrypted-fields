# Configuration

## Registry

A registry lists the fields to encrypt. Anything not listed stays plaintext
(default deny).

```php
return [
    'user' => [
        'columns' => [
            'user_login' => ['type' => 'login', 'max_length' => 60],
            'user_email' => ['type' => 'email', 'max_length' => 100],
        ],
        'meta' => [
            'first_name' => ['type' => 'text'],
            'last_name'  => ['type' => 'text'],
            'billing_first_name' => ['type' => 'text', 'search' => true],
            'billing_email'      => ['type' => 'email', 'search' => true],
            'billing_phone'      => ['type' => 'text', 'search' => true],
        ],
    ],
    'post' => [
        'post_types' => ['shop_order'],
        'meta' => [
            '_billing_first_name' => ['type' => 'text', 'search' => true],
            '_billing_email'      => ['type' => 'email', 'search' => true],
            '_billing_address_index'  => ['type' => 'text', 'search' => true],
            '_shipping_address_index' => ['type' => 'text', 'search' => true],
            '_customer_ip_address'=> ['type' => 'text'],
        ],
    ],
    'term'    => ['meta' => []],
    'comment' => ['meta' => []],
];
```

### Field options

| Option | Meaning |
|---|---|
| `type` | `text`, `email`, `login` |
| `search` | Build blind-index tokens for exact/partial search |
| `cipher` | Override the cipher name |
| `max_length` | Refuse values whose ciphertext exceeds this length (meta only) |
| `compact` | Use the `v2c` envelope (legacy compatibility) |
| `post_types` | Restrict a post meta field to these post types |

### Cipher types

- `text`: randomized AES-256-GCM.
- `email` / `login`: deterministic SIV-style encryption, used for meta values
  that need equality lookups (for example `billing_email`).
- `wp_users.user_login` / `user_email`: **token mode**. The column stores a
  55-character blind-index token; the reversible plaintext is encrypted in
  `_kec_user_login` / `_kec_user_email`.

## Constants

| Constant | Purpose |
|---|---|
| `KEC_KEY` | Current master key (base64 or hex, 32 bytes) |
| `KEC_KEY_NEXT` | New key during two-phase rotation |
| `KEC_OLD_KEYS` | Map of `key_id => key` for reading old data |
| `KEC_TOKEN_SECRET` | Stable secret for login/email tokens |
| `KEC_SEARCH_SECRET` | Optional override for search tokens |
| `KEC_FIELDS` | Registry array |
| `KEC_READONLY_FIELDS` | Fields to decrypt but never encrypt |
| `KEC_LEGACY` | Legacy cipher keys for migration reads |
| `KEC_ALLOW_DB_KEY` | Allow `kec_key` option (not recommended) |
| `KEC_DEBUG` | Write plugin errors to `error_log` |

Legacy configuration:

```php
define('KEC_LEGACY', [
    'ctr_key'   => '...hex...',
    'login_key' => '...hex...',
    'email_key' => '...',
    'email_iv'  => '...',
]);
```

Never commit real keys. Use environment variables or `wp-config.php`.

## Read-only fields

```php
define('KEC_READONLY_FIELDS', [
    'user' => ['billing_phone'],
]);
```

Read-only fields are decrypted on read but not encrypted on write. Use them
while migrating a field away from encryption:

1. Add the field to `kec_readonly_fields`.
2. Run `wp kec decrypt --field=user:billing_phone`.
3. Remove it from the registry.

## Remote/CI configuration

For staging or CI, point to a different key file:

```php
define('KEC_KEY_FILE', '/etc/kec/staging.key');
```

Never reuse production keys in staging dumps you share.
