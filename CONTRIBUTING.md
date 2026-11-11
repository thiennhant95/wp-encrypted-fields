# Contributing

## Requirements

- PHP 8.0+
- OpenSSL extension
- Git

## Setup

```bash
git clone https://github.com/thiennhant95/wp-encrypted-fields.git
cd wp-encrypted-fields
```

Composer is optional. The plugin ships a PSR-4 autoloader, so no vendor
directory is required to run the test scripts.

## Checks

```bash
find src tests -name '*.php' -print0 | xargs -0 -n1 php -l
for t in tests/run-*.php; do php "$t" || exit 1; done
```

All test scripts are standalone and use inline WordPress stubs; they do not
need a database.

If you have Composer and PHPUnit installed:

```bash
composer install
vendor/bin/phpunit
```

## Coding guidelines

- PHP 8.0-compatible syntax (no readonly properties, enums, or readonly classes).
- PSR-4 namespace `EncryptedFields\`.
- Follow WordPress coding standards where practical.
- Keep public APIs documented with short PHPDoc.
- Never log plaintext, ciphertext, keys or email addresses.
- Never add real keys or secrets to tests or fixtures.

## Documentation and changelog

Every change that affects behavior, configuration, CLI output, storage or
security must update documentation in the same pull request:

- `CHANGELOG.md` — Keep a Changelog format (`Added`, `Changed`, `Deprecated`,
  `Removed`, `Fixed`, `Security`).
- `readme.txt` — WordPress.org changelog and upgrade notice.
- `docs/` and `README.md` — only when the user-facing behavior changes.
- Version bump for releases (`wp-encrypted-fields.php`, `KEC_VERSION`,
  `readme.txt` stable tag).

## Release checklist

1. Update `CHANGELOG.md` and `readme.txt`.
2. Bump the version in the plugin header, `KEC_VERSION` and `Stable tag`.
3. Run lint, all test scripts and `wp kec verify --full` on a staging copy.
4. Confirm no secrets, keys or customer data are staged.
5. Tag the release (`vX.Y.Z`) and publish GitHub release notes from the
   changelog.

## Pull requests

1. Fork the repository.
2. Create a feature branch.
3. Add or update tests for the changed behavior.
4. Update the changelog and documentation.
5. Run the checks above.
6. Describe the security impact of the change.

Security fixes should follow [SECURITY.md](SECURITY.md) and must not be
discussed in public issues before a fix is released.
