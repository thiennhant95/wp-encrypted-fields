# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's **private security advisory** for this repository:

1. Open the repository on GitHub.
2. Go to **Security → Advisories → Report a vulnerability**.
3. Include reproduction steps, affected version and impact.

We will acknowledge reports as soon as possible and coordinate a fix and
disclosure.

## Scope

In scope:

- Key handling and storage.
- Cipher/format implementation.
- Authentication/session behavior.
- Query rewriting and access control.
- Migration and rotation safety.

Out of scope:

- Compromised hosting, `wp-config.php` or server filesystem.
- Malicious administrators.
- Vulnerabilities in WordPress, WooCommerce or third-party plugins.
- Data recovered from a leaked key.

## Guidance

- Keep keys outside the database and repository.
- Use `KEC_TOKEN_SECRET` as a stable secret.
- Back up before migration and rotation.
- Do not share database dumps without encryption keys.
