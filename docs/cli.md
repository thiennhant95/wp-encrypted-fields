# WP-CLI

All commands are registered under `wp kec`. Commands are available only when
WP-CLI is active.

## Diagnostics

```bash
wp kec status
wp kec fields
wp kec scan [--entity=user|post|term|comment] [--format=table|json] [--check-length]
wp kec verify [--fix] [--full]
wp kec search <term> [--entity=user|post]
```

`scan` reports plaintext, legacy, v2, token and empty counts per field.
`verify` checks that no selected field still contains plaintext/legacy data and
that encrypted values decrypt. Use `--full` before go-live to decrypt every
row instead of a sample, and to require a non-empty search index when
searchable fields exist.

## Setup

```bash
wp kec setup --mode=fresh --preset=full-ec-koyo
wp kec setup --mode=existing --preset=custom --fields=fields.json
```

Presets:

- `minimal`
- `full-ec-koyo`
- `custom` (requires a fields file)

## Migration

```bash
wp kec migrate --backup-confirmed --dry-run
wp kec migrate --backup-confirmed --batch=500
wp kec migrate --from=plaintext --entity=user --field=user:billing_phone
wp kec migrate --resume
```

Options:

| Option | Meaning |
|---|---|
| `--dry-run` | Build a plan and print counts, change nothing |
| `--backup-confirmed` | Acknowledge that a backup exists |
| `--batch=500` | Rows per batch |
| `--resume` | Continue a previous run |
| `--entity=...` | Limit to an entity |
| `--field=entity:key` | Limit to one field |
| `--from=plaintext|legacy` | Source format |
| `--no-safety-dump` | Skip the automatic safety dump of affected tables |

Existing data migration is blocked without backup acknowledgement. A safety
dump is created by default before real migration/rollback/rotation; the path is
printed and it may contain plaintext, so protect or delete it after use.

## Auxiliary tables

```bash
wp kec migrate-table customer_lookup --dry-run
wp kec migrate-table customer_lookup --backup-confirmed
wp kec migrate-table siteguard_history --backup-confirmed
```

- `customer_lookup`: encrypt/decrypt WooCommerce Analytics customer rows.
- `siteguard_history`: decrypt legacy/v2 login names to plaintext.

## Decrypt / rollback

```bash
wp kec decrypt --field=user:billing_phone --dry-run
wp kec decrypt --field=user:billing_phone
wp kec rollback --to=plaintext
wp kec rollback --to=backup
```

`decrypt` turns stored ciphertext back into plaintext for one field.
`rollback --to=plaintext` does this for the whole registry.
`rollback --to=backup` prints restore instructions; it does not touch the DB.

## Search index

```bash
wp kec reindex --entity=user
wp kec reindex --entity=all --batch=500
```

Run after changing `KEC_SEARCH_SECRET`, rotating the master key when the search
secret is derived from it, or importing data outside WordPress APIs.

## Keys

```bash
wp kec key generate
wp kec rotate-key --dry-run
wp kec rotate-key --backup-confirmed
```

### Two-phase rotation

1. Generate a new key.
2. Set `KEC_KEY_NEXT` to the new key; keep `KEC_KEY` as the old key.
3. Run `wp kec rotate-key --backup-confirmed`.
4. Run `wp kec verify --full`.
5. Set `KEC_KEY` to the new key and remove `KEC_KEY_NEXT`.
6. Run `wp kec verify --full` again.
7. Keep the old key in `KEC_OLD_KEYS` until you have verified all data.

If `KEC_TOKEN_SECRET` is not defined, login/email tokens are derived from the
master key. Rotation then re-tokenizes every user and updates `_kec_user_login`
and `_kec_user_email`. Define `KEC_TOKEN_SECRET` for stable tokens.

## Exit codes

- `0`: success
- `1`: error
- `2`: action required (missing backup acknowledgement, key, etc.)
