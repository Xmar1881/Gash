<!--
Thank you for contributing to Gash!
Please ensure your PR follows our contribution guidelines:
https://github.com/Xmar1881/Gash/blob/main/CONTRIBUTING.md

Before submitting, please run:
- go test ./...
- go vet ./...
- go build -tags deep ./cmd/gash
- go run ./cmd/gash plugins test plugins/<your-plugin> (if adding/updating a plugin)
-->

## Description
<!-- Brief summary of changes -->

## Type of Change
- [ ] Bug fix
- [ ] New plugin
- [ ] Plugin improvement
- [ ] Engine/oracle change
- [ ] Documentation
- [ ] CI/Build
- [ ] Other: _____

## Testing
<!-- How did you verify this change? -->

- [ ] `go test ./...` passes
- [ ] `go vet ./...` passes
- [ ] `go build -tags deep ./cmd/gash` passes
- [ ] Plugin fixture tests pass (`go run ./cmd/gash plugins test plugins/...`)
- [ ] Metrics gate passes (`go test ./tests/plugins -run TestMetricGate`)
- [ ] Manual test: `go run ./cmd/gash scan --target ...` (describe)

## Checklist
- [ ] My code follows the existing style (run `gofmt`)
- [ ] I added/updated tests for new functionality
- [ ] I updated relevant documentation (README, docs/, plugin YAML comments)
- [ ] New plugins include: positive, negative, and ambiguous fixtures
- [ ] New plugins use existing oracles (no new oracle code without discussion)
- [ ] Confidence levels match evidence (confirmed/firm/tentative/blocked/unverified)
- [ ] Safe defaults: `safe: true` unless active payloads required; `active: false` by default
- [ ] Scope discipline: no out-of-scope requests without `--scope`
- [ ] OOB discipline: honest skip when `--oob-server` not provided

## Breaking Changes
<!-- Any breaking changes? Version bump needed? -->

## Related Issues
<!-- Link issues: Fixes #123, Related to #456 -->

## Screenshots/Logs (if applicable)
<!-- Plugin test output, benchmark diff, etc. -->