## Summary

Describe the change and why it is needed.

## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Security
- [ ] Documentation
- [ ] Refactor / tests

## Checklist

- [ ] `php -l` passes for changed files
- [ ] `for t in tests/run-*.php; do php "$t" || exit 1; done` passes
- [ ] `CHANGELOG.md` updated
- [ ] `readme.txt` changelog/upgrade notice updated for releases
- [ ] `docs/` and/or `README.md` updated for user-facing changes
- [ ] No plaintext, keys, tokens or customer data added to code/tests/logs
- [ ] Security impact described below

## Security impact

Describe storage/format changes, key handling, migration impact and rollback
steps. Write "none" when not applicable.
