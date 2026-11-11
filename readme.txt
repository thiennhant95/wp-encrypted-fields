=== Encrypted Fields ===
Contributors: thiennhant95
Tags: encryption, security, privacy, gdpr, woocommerce
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 0.1.0
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
* WP-CLI migration, verification, reindex and two-phase key rotation.
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

= 0.1.0 =
Initial implementation.

== Upgrade Notice ==

= 0.1.0 =
First release.
