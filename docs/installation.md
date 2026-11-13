# Installation

## Requirements

| Component | Version |
|---|---|
| PHP | 8.0+ (8.3 recommended) |
| WordPress | 6.4+ |
| OpenSSL | required |
| Sodium | optional |
| WooCommerce | optional |
| WP-CLI | optional, 2.7+ |

## Install the plugin

1. Copy `wp-encrypted-fields/` into `wp-content/plugins/`.
2. Activate **Encrypted Fields**.
3. Define a key and a registry (see [configuration](configuration.md)).
4. Run the setup wizard at **Settings → Encrypted Fields**.

### Via Composer

Once the package is published on [Packagist](https://packagist.org/packages/thiennhant95/wp-encrypted-fields), projects managed with Composer (Bedrock, Roots) can require it directly:

```bash
composer require thiennhant95/wp-encrypted-fields
```

If you need it before the Packagist listing is live, use the VCS repository:

```json
{
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/thiennhant95/wp-encrypted-fields"
        }
    ]
}
```

```bash
composer require thiennhant95/wp-encrypted-fields
```

## Key setup

Recommended: `wp-config.php` or environment.

```php
define('KEC_KEY', 'base64:...');          // 32 bytes, base64
define('KEC_TOKEN_SECRET', 'base64:...'); // stable token secret
```

Alternatives:

- `KEC_KEY_FILE`: path to a file outside the web root.
- Database option `kec_key`: only when `KEC_ALLOW_DB_KEY` is true. This weakens
  the threat model (a database leak also leaks the key) and is not recommended.

Generate keys:

```bash
wp kec key generate
```

The generated value is shown once. Store it outside the repository.

## Registry setup

Choose one source:

1. `KEC_FIELDS` constant in `wp-config.php`.
2. `wp-content/kec-fields.php` returning an array.
3. Option `kec_field_registry` (saved from the admin UI).
4. `kec_field_registry` filter for final adjustments.

If the registry is empty the plugin does nothing.

## Fresh site

1. Key setup.
2. Choose fields.
3. Finish the wizard.
4. New writes are encrypted immediately; no migration is needed.

## Existing site

1. Back up the database **and** files.
2. Key setup.
3. Scan and dry-run.
4. Confirm the backup in the wizard or pass `--backup-confirmed`.
5. Migrate in batches.
6. Verify, then finalize.

The wizard blocks migration until the backup is acknowledged.

After upgrading the plugin, run `wp kec verify --full` and
`wp kec scan` to confirm the registry still matches the stored data. HPOS must
remain disabled for WooCommerce order encryption in v1.

## Deactivation and uninstall

Deactivation keeps data. Uninstall keeps data by default. To remove index and
option data on uninstall, set `kec_delete_data_on_uninstall` to true. Keys in
`wp-config.php` are never removed automatically.
