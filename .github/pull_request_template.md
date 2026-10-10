## Summary

<!-- What changed, and why? Keep the scope focused. -->

## Safety and behavior

- [ ] Safe mode remains non-state-changing.
- [ ] Any active POST, body mutation, upload, login, time-based, OOB, or browser behavior is explicitly gated.
- [ ] No credentials, tokens, private target URLs, or sensitive response bodies are committed.
- [ ] Findings require evidence; reflection/status alone is not promoted to a vulnerability.
- [ ] Partial/degraded scans cannot be reported as clean.

## Validation

- [ ] Tests added or updated (including a negative control where applicable).
- [ ] `py -m pytest tests/ -q`
- [ ] `py -m ruff check core gash.py tests`
- [ ] `py -m bandit -q -ll -r core gash.py`
- [ ] `go vet ./...` and `go test ./...` (if `go/` changed)

## Release/docs

- [ ] README.md and README.tr.md updated when user-visible behavior changed.
- [ ] CHANGELOG.md updated.
- [ ] Check count and registry names remain accurate.
