=== Encrypted Fields ===
Contributors: thiennhant95
Tags: encryption, security, privacy, gdpr, woocommerce
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 0.3.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Registry-driven, field-level encryption for WordPress with searchable blind indexes.

== Description ==

Encrypt only the fields you declare. Reads through normal WordPress APIs return
plaintext; the database stores ciphertext. User login and email columns use
fixed-length blind-index tokens with encrypted plaintext in user meta.

Features:

* Post, user, term and comment meta encryption.
* User login/email token mode (no column overflow).
* Exact and partial search through HMAC token indexes.
* `get_user_by()`, `email_exists()`, `username_exists()` support.
* Mail recipient decryption; password-reset message support.
* WooCommerce integration (HPOS must be disabled in v1).
* SiteGuard integration and a legacy migration preset.
* Setup wizard with a mandatory backup gate.
* WP-CLI migration, full verification, reindex and two-phase key rotation.
* Serialized array/object meta encryption for declared fields.
* WooCommerce customer-lookup column widening and order address-index guidance.
* No core or third-party plugin patches.

== Installation ==

1. Upload the plugin directory to `/wp-content/plugins/`.
2. Activate the plugin.
3. Define `KEC_KEY` and `KEC_FIELDS` in `wp-config.php`, or use the setup wizard.
4. Open **Settings → Encrypted Fields**.

Existing data must be backed up before migration.

== Frequently Asked Questions ==

= Do I have to encrypt every field? =

No. Only fields listed in the registry are encrypted.

= Does get_user_by() still work? =

Yes. Login and email lookups are rewritten to the stored token.

= Does it work with WooCommerce HPOS? =

Not in v1. Disable HPOS before enabling order encryption.

= Where are keys stored? =

In `wp-config.php`, environment, or a key file outside the web root. Database
storage is disabled by default.

== Changelog ==

= 0.3.0 =
* Automatic safety dump of affected tables before migration, rollback and key
  rotation; 0600 files in a 0700 directory, last five kept,
  `--no-safety-dump` and `KEC_SAFETY_DUMP_DIR` overrides.
* Compatibility matrix expanded to 100 plugins; 99 pass, with only
  `encrypted-blog` failing due to its own activation error.
* Bilingual GitHub Pages landing page.

= 0.2.3 =
* Warn about known plaintext email/CRM plugins in status and Health.
* Admin Settings and Setup Wizard verify all rows.
* Polylang two-language verification.

= 0.2.2 =
* Fixed multisite/WP-CLI user creation reporting duplicate email after the
  account was inserted; email is tokenized before the duplicate check.
* Password-only updates keep tokenized email/login on multisite.
* Documented email logging/CRM plaintext caveats.

= 0.2.1 =
* Fixed password-only/partial user updates blanking tokenized login/email
  columns; the token is rebuilt from encrypted user meta.

= 0.2.0 =
* Added serialized meta encryption, full row verification, search-index checks,
  WooCommerce lookup safeguards, CLI aliases and adapter contract validation.
* Fixed decrypt/index handling, LIKE search escaping, lookup column overflow,
  uninstall lockout and CLI option parsing.
* Security: cipher validation, database-key warning, address-index guidance.

= 0.1.0 =
Initial implementation.

== Upgrade Notice ==

= 0.3.0 =
Adds automatic safety dumps before migration/rotation and expands
compatibility testing to 100 plugins.

= 0.2.3 =
Recommended when using email logging/CRM plugins or Polylang.

= 0.2.2 =
Recommended for multisite and WP-CLI user management.

= 0.2.1 =
Recommended for sites that update users/passwords from CLI or third-party
plugins: partial updates no longer blank tokenized login/email columns.

= 0.2.0 =
Update custom table adapters to implement table(), primaryKey() and
write(): bool. Run `wp kec verify --full` after upgrading.

= 0.1.0 =
First release.
