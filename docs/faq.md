# FAQ

### Do I have to encrypt everything?

No. The registry is a default-deny list. Encrypt only the fields you choose.

### Can I encrypt fewer fields than the example?

Yes. Remove fields from the registry. If a field was already encrypted, use
`KEC_READONLY_FIELDS` and `wp kec decrypt --field=...` before removing it.

### Can I add fields later?

Yes. Add the key to the registry; new writes are encrypted. Run
`wp kec migrate` to encrypt existing plaintext rows if desired.

### Why are user_login and user_email tokens instead of ciphertext?

`wp_users.user_login` is `varchar(60)` and `user_email` is `varchar(100)`.
Ciphertext can exceed those limits. Tokens are fixed length; the reversible
plaintext is encrypted in user meta.

### Does `get_user_by('email')` still work?

Yes. The query rewriter converts the plaintext value to the stored token.

### Do emails still reach users?

Yes. The `wp_mail` filter resolves token or encrypted recipients to plaintext.

### What happens if the key is lost?

Encrypted data cannot be recovered. There is no key escrow. Keep offline
backups of the key in a secure location.

### Can I use staging and production keys?

Yes, but they are different. Do not restore a production dump into staging
unless you also provide the production key; otherwise encrypted fields cannot
be read.

### Does it work with HPOS?

No, not in v1. Disable HPOS before enabling order-field encryption.

### Does it work with multisite?

Yes. Keys and index tables are per site unless you define a network-level key.

### Is plaintext ever written to the database?

Not for successfully encrypted fields. Writes are fail-closed: if encryption
fails, the meta write is blocked. User columns always store tokens.

### Can I search partial values?

For fields with `search => true`, yes, through trigram tokens. Search terms
shorter than three characters use exact matching only.

### How do I rotate keys?

Two-phase rotation with `KEC_KEY_NEXT`. See the CLI documentation.
