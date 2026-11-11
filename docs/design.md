# Design

## Goals

- Encrypt declared fields at rest without patching core or third-party plugins.
- Keep normal WordPress/WooCommerce APIs returning plaintext.
- Keep lookup/search working for encrypted identifiers.
- Make key ownership explicit and rotation possible.

## Modules

| Module | Responsibility |
|---|---|
| `Config` | Registry, field definitions |
| `Crypto` | Keys, ciphers, format, legacy adapter, rotation |
| `Meta` | Read/write filters for post/user/term/comment meta |
| `User` | `wp_users` token mode, auth hooks, password reset, helpers |
| `Query` | `wp_users` `=`/`IN` query rewriting |
| `Search` | HMAC token index, indexer, searcher, hooks |
| `Mail` | Recipient decryption and optional body replacement |
| `Admin` | Settings, setup wizard, health/status |
| `Cli` | WP-CLI commands |
| `Migration` | Scan, migrate, verify, rollback, auxiliary tables |
| `Integrations` | WooCommerce, SiteGuard, legacy preset |

## Read path

1. `get_*_metadata` filter receives the request.
2. The registry is checked; unlisted keys pass through.
3. Raw values come from the object meta cache (no recursion).
4. Tokens/ciphertext are decrypted; plaintext passes through.
5. Results are memoized per request only.

## Write path

1. `add_*_metadata` / `update_*_metadata` filter receives the value.
2. Registry and read-only lists are checked.
3. Value is encrypted with the current key.
4. The real meta API is called with a static recursion guard.
5. On failure the write is blocked and logged (fail-closed).

## User columns

- `user_login` / `user_email` store 55-character blind-index tokens.
- Reversible plaintext is encrypted in `_kec_user_login` / `_kec_user_email`.
- `get_user_by()` and raw equality/`IN` queries are rewritten to tokens.
- Supported hooks decrypt `WP_User` objects for auth, current user, `wp_login`,
  REST and password reset.

## Storage

| Data | Storage |
|---|---|
| Meta fields | `enc:v2` ciphertext |
| User columns | `k1t`/`k1e` tokens |
| User plaintext | Encrypted user meta |
| Search | HMAC tokens in `kec_search_index` |
| Keys | `wp-config.php`/env/file (not DB by default) |

## Search

Full token + trigrams, field-scoped, HMAC-SHA256. Exact and partial search are
supported without plaintext at rest. Search secret is separate from the
encryption key.

## Rotation

Two-phase: `KEC_KEY_NEXT` is current, `KEC_KEY` remains readable. The rotation
service re-encrypts registry fields, user columns and auxiliary tables, reindexes
search, and verifies. Promote the new key afterwards.

## Migration

- State detector classifies data as fresh/plaintext/legacy/mixed/configured.
- Migrator plans batches, enforces the backup gate, supports resume and verify.
- Legacy ciphertext is read through the legacy adapter.
- Auxiliary tables are migrated with dedicated commands.

## Design constraints

- No core patches.
- No plaintext in persistent object cache.
- Do not silently store plaintext if encryption fails.
- HPOS is out of scope for v1.
- Only scalar string meta values are encrypted.
