# Migration

## Before you start

1. Back up the database and files.
2. Verify the backup can be restored.
3. Keep the site in maintenance mode if appropriate.
4. Never run migration without `--backup-confirmed` (CLI) or the wizard's backup
   gate (admin).

The plugin is idempotent: already-migrated rows are skipped.

## Data states

| State | Meaning |
|---|---|
| `fresh` | No encrypted/plaintext PII detected |
| `existing_plaintext` | PII exists in plaintext |
| `existing_legacy` | Legacy ciphertext detected |
| `mixed` | Plaintext and legacy mixed |
| `configured` | Registry and key configured |

## Plaintext to encrypted

```bash
wp kec scan
wp kec migrate --backup-confirmed --dry-run
wp kec migrate --backup-confirmed --batch=500
wp kec verify
```

Writes go through WordPress meta APIs, so the normal meta hooks encrypt each
field. Rows are processed in batches and can be resumed.

## Legacy ciphertext

Set `KEC_LEGACY` (or constants/env `KEC_LEGACY_*`) so the legacy adapter can
read old values. Then run the same commands. New writes always use the v2
format or token mode.

Legacy formats supported for reading:

- `base64(nonce + ciphertext)` — AES-256-CTR.
- `base64@domain` — AES-256-CBC email format.
- `base64` 16-byte blocks — AES-256-CBC login format.

## User columns

`wp_users.user_login` and `user_email` are migrated to token mode:

1. Resolve plaintext from plaintext, legacy or v2 data, or from user meta when
   the column already contains a token.
2. Store a 55-character token in the column.
3. Store encrypted plaintext in `_kec_user_login` / `_kec_user_email`.
4. Verify that columns contain only tokens and that meta decrypts.

Rows with a token but missing meta are reported as `meta_missing`; restore the
missing meta or re-run from a backup. The tool never re-tokenizes a token.

## Auxiliary tables

```bash
wp kec migrate-table customer_lookup --backup-confirmed
wp kec migrate-table siteguard_history --backup-confirmed
```

- `wc_customer_lookup` values are encrypted/decrypted field by field.
- `siteguard_history.login_name` is converted to plaintext so the stock
  SiteGuard UI can display it.

## Adding a field later

1. Add the field to the registry.
2. New writes are encrypted.
3. Existing plaintext rows remain readable; run `wp kec migrate` to encrypt
   them if required.
4. For `user_login` / `user_email`, migrate all users before or together with
   enabling the column.

## Removing a field

1. Add the field to `KEC_READONLY_FIELDS` so reads still decrypt.
2. Run `wp kec decrypt --field=entity:key`.
3. Remove it from the registry and read-only list.

## Rollback

- `wp kec rollback --to=plaintext` decrypts registry fields.
- `wp kec rollback --to=backup` prints restore instructions.
- Always keep a database backup before rollback.

## Rotation

See [CLI rotation](cli.md#two-phase-rotation).
