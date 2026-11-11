# Security

## Threat model

The plugin protects data at rest when the database or a backup leaks.

| Scenario | Protected |
|---|---|
| Database dump / backup leak | Yes (no key in DB by default) |
| SQL injection reading tables | Yes (ciphertext/tokens) |
| Source code leak | Yes (key outside code) |
| `wp-config.php` or server compromise | No |
| Malicious administrator | No (can read data through WP) |
| Key exposed in logs | Prevented by the plugin |

## Keys

- 32-byte master key (`KEC_KEY`).
- Stored in `wp-config.php`, environment or a file outside the web root.
- The `kec_key` option is disabled by default; enabling it
  (`KEC_ALLOW_DB_KEY`) means a database leak also leaks the key.
- Never commit keys. Never log keys or plaintext.
- `KEC_TOKEN_SECRET` should be stable and separate from `KEC_KEY` so login/email
  tokens survive master-key rotation.

## Encryption

- Randomized fields: AES-256-GCM with a random 12-byte nonce and 16-byte tag.
- Deterministic fields (`email`/`login` meta): SIV-style construction with
  domain separation per field. Deterministic values reveal equality, by design,
  for equality lookups.
- User columns use blind-index tokens; reversible plaintext is encrypted in
  user meta.
- Format: `enc:v2:<cipher>:<key_id>:<base64url(payload)>`.
- Decryption failures return the stored value and log an error code, never a
  fatal error or plaintext.

## Rotation

Two-phase rotation uses `KEC_KEY_NEXT` while `KEC_KEY` stays readable. After
re-encryption, promote the new key and keep the old one in `KEC_OLD_KEYS` until
verification completes.

If the token secret is derived from the master key (no `KEC_TOKEN_SECRET`),
rotation re-tokenizes every user.

## Fail-closed behavior

- Meta writes are blocked (`false`) when encryption fails.
- `update_metadata_by_mid` SQL is rewritten when possible; if encryption fails
  the SQL is left unchanged and logged (cannot be blocked at that layer).
- User columns are tokenized; encryption of the reversible user meta is handled
  by the meta layer.

## Logging

Logs contain entity, field, row IDs and error codes. They never contain
plaintext, ciphertext, keys or email addresses.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md). Do not open a public issue for security
reports.
