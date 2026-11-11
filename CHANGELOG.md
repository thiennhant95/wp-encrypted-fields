# Changelog

All notable changes to this project are documented here.

## [0.2.1] - 2026-11-11

### Fixed

- Password-only or partial `wp_update_user()` calls no longer blank the
  tokenized `user_email` / `user_login` columns; the token is rebuilt from the
  encrypted user meta.
- Admin/email lookups keep working after a password-only update.

### Tests

- Added a regression test for blank-email partial updates.

## [0.2.0] - 2026-11-11

### Added

- Serialized array/object meta encryption for declared fields; values decrypt
  back to arrays.
- `wp kec verify --full`: decrypt every row in batches and require a non-empty
  search index when searchable fields exist.
- Registered `UserLookup`; `WP_User_Query` login/email `LIKE` searches now use
  the blind index.
- Search index hooks for added/updated/deleted post, user, term and comment
  meta.
- WooCommerce: automatic widening of short `wc_customer_lookup` columns,
  length checks in migration and analytics writes, and address-index fields in
  examples/presets.
- `TableAdapterInterface::table()`, `primaryKey()` and `write(): bool`, with
  identifier validation and a cursor-stall guard.
- CLI aliases `migrate-table` and `rotate-key`; `search --entity/--limit`,
  `migrate --field=entity:key`, `--full` verification, and clear errors for
  invalid `--from` values.
- Cipher-name validation and a database-key warning in `wp kec status`.
- Tokenizer fallback when `ext-intl` is not available.
- Go-live/post-import checklist docs, GitHub issue/PR templates and a code of
  conduct.
- Regression tests for serialized meta, LIKE escaping and cipher validation.

### Changed

- Decrypt/rollback bypass the meta write guard, keep the search index, and
  require backup acknowledgement for whole-registry rollback.
- Migration scans fail closed; resume cursors advance only after success;
  stored error lists are capped; the migration lock is atomic and renewed.
- Backup acknowledgement expires after 24 hours.
- Uninstall restores tokenized user columns before removing code and keeps the
  key if restoration fails.
- HPOS detection is aligned; the admin registry refuses post fields when HPOS
  is on; the setup wizard no longer forces backup confirmation.
- WooCommerce analytics respects default-deny and skips too-long ciphertext
  instead of truncating it.
- Missing optional lookup tables are skipped cleanly.
- Rotation verifies all rows and no longer errors when `siteguard_history` is
  absent.
- Full verification is batched to avoid memory spikes on large sites.

### Fixed

- `wp kec decrypt` reported success while the write guard re-encrypted data and
  removed search-index rows.
- `UserLookup` failed for `LIKE` terms containing escaped `_` or `%`.
- Serialized single-value meta triggered a WordPress array-key warning.
- `wc_customer_lookup.username` overflow could fail or truncate.
- WooCommerce `_billing_address_index` / `_shipping_address_index` leaked
  plaintext unless declared.
- Uninstall used wrong option names and could leave tokenized users locked out.
- CLI option parsing/docblock mismatches for search, rollback, `migrate-table`
  and `rotate-key`.
- Invalid `--from` values were silently accepted.

### Security

- Cipher overrides are restricted to known cipher names.
- Warn when `KEC_ALLOW_DB_KEY` stores the master key in the database.
- Documented that `post_content` / `post_title`, `wp_options` and undeclared
  custom tables remain plaintext.

## [0.1.0] - 2026-11-05

### Added

- Registry-driven encryption for post/user/term/comment meta.
- `wp_users.user_login` / `user_email` blind-index token mode.
- Transparent reads/writes through WordPress meta APIs.
- `get_user_by()`, `email_exists()`, `username_exists()` and `=`/`IN` query
  rewriting for user columns.
- HMAC blind-index search (full + trigram tokens).
- Mail recipient decryption and optional body token replacement.
- Password-reset message support and `kec_user_login()` / `kec_user_email()`
  helpers.
- WooCommerce integration (orders, analytics lookup, customer objects), HPOS
  detection.
- SiteGuard integration.
- Legacy cipher adapter and preset for migration.
- Setup wizard with mandatory backup gate.
- WP-CLI: status, fields, setup, scan, migrate, decrypt, rollback, reindex,
  verify, search, key generation, two-phase rotation, auxiliary table
  migration.
- Fail-closed meta writes and `update_metadata_by_mid` guard.
- Uninstall cleanup option (data retained by default).
- GPL-2.0-or-later license.
