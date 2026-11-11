# Search

## Why a blind index

Encrypted values cannot be searched with `LIKE`. The plugin stores HMAC-SHA256
tokens in a separate table so exact and partial search work without storing
plaintext.

Table: `{prefix}kec_search_index`

| Column | Purpose |
|---|---|
| `entity_type` | user, post, term, comment |
| `entity_id` | object ID |
| `field` | meta key or column |
| `token` | HMAC token |

## Token rules

- Secret: `KEC_SEARCH_SECRET` or a key derived from the master key. Never stored
  in the database by default.
- Normalize: lowercase, NFKC when `intl` is available, collapse whitespace.
- Full token for exact matches.
- Trigram tokens for partial matches; terms shorter than three characters use
  exact matching only.
- Tokens are field-scoped: the same value in two fields produces different
  tokens.

## User identifiers

`wp_users.user_login` and `user_email` use a separate token scheme:

```text
k1t<base32(HMAC-SHA256(token_secret, "login|normalized"))>   // 55 chars
k1e<base32(HMAC-SHA256(token_secret, "email|normalized"))>   // 55 chars
```

The reversible plaintext is encrypted in `_kec_user_login` /
`_kec_user_email`. Use `KEC_TOKEN_SECRET` so tokens survive key rotation.
Without it, rotating the master key requires re-tokenizing all users.

## What works

- `get_user_by('login'|'email', $plaintext)`
- `email_exists()`, `username_exists()`
- Raw SQL equality and `IN` on `user_login` / `user_email`
- `WP_User_Query` search through the user index
- WooCommerce order search through the order index
- Exact and partial search for fields marked `search => true`

## What does not work automatically

- `LIKE` directly on encrypted columns (use the index).
- Queries with table aliases on `wp_users` (skipped to avoid false positives).
- External search engines. Index plaintext out of band or exclude encrypted
  fields.
- Search on fields without `search => true`.

## Reindex

```bash
wp kec reindex --entity=user
wp kec reindex --entity=all --batch=500
```

Reindex when:

- `KEC_SEARCH_SECRET` changes;
- the master key changes and the search secret is derived from it;
- data is imported/updated outside WordPress APIs;
- a field is switched to `search => true`.
