# Compatibility

## WordPress / PHP

| Component | Supported |
|---|---|
| PHP | 8.0 – 8.3 |
| WordPress | 6.4+ (tested through 7.x) |
| WooCommerce | optional, HPOS disabled |
| Multisite | supported (per-site key and tables) |
| Object cache | supported; plaintext is never written to persistent cache |

## Plugin families

Most plugins that use standard WordPress/WooCommerce APIs work unchanged.

| Family | Examples | Impact |
|---|---|---|
| Page builders | Elementor, WPBakery, Divi | None for unlisted content fields |
| SEO | Yoast, Rank Math | None |
| Forms | CF7, WPForms, Gravity Forms | Entries in their own tables are not encrypted; current-user email is decrypted |
| Cache | WP Rocket, LiteSpeed, W3TC | None |
| Security | Wordfence | Exact `get_user_by`/SQL lookups work via query rewrite; activity reports/LIKE searches may need testing |
| Backup/migration | UpdraftPlus, Duplicator, All-in-One WP Migration | Dumps contain ciphertext; restore needs the same key; user imports may need the index |
| Membership/LMS | MemberPress, LearnDash | User meta works; test admin lists that read raw columns |
| Email marketing | Mailchimp for WooCommerce, Klaviyo | Customer emails resolve via WC integration; test sync |
| Multilingual | WPML, Polylang | None for encryption; search normalization still applies |
| Woo extensions | Subscriptions, Bookings, YITH | Order meta works when HPOS is off |
| Search engines | Relevanssi, ElasticPress, Algolia | Encrypted fields cannot be indexed automatically |
| Import/export | WP All Import/Export | Export emits ciphertext; importing plaintext requires migration |
| CRM/helpdesk | FluentCRM, Awesome Support | Test custom user search/export |

## Checklist before adding a plugin

1. Does it read/write `wp_users.user_login` or `user_email` with raw SQL or
   `get_user_by()`?
2. Does it search those columns with `LIKE`?
3. Does it export/import users or orders?
4. Does it use an external search engine?
5. Does it read `$user->user_email` / `$user->user_login` outside the supported
   hooks?
6. Does it store PII in its own table?
7. Does it require HPOS?

If 1–3 or 5 is yes, test it and possibly add an adapter. If 6 is yes, register
a `TableAdapterInterface`. If 7 is yes, do not use v1 for orders.

## Not supported in v1

- WooCommerce HPOS.
- Encrypting `wp_options` / API keys.
- Full-text search outside trigram tokens.
- Automatic protection against plugins reading raw `wp_users` columns outside
  the supported hooks.
