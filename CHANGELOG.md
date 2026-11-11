# Changelog

All notable changes to this project are documented here.

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
