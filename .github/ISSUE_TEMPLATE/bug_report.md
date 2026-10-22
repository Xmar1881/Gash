---
name: Bug Report
about: Report a reproducible bug in Gash
title: "[BUG] "
labels: ["bug"]
assignees: ""
---

## Environment
- **OS**: (e.g., Windows 11, Ubuntu 22.04, macOS 14)
- **Go version**: (run `go version`)
- **Gash version**: (run `gash version` or commit hash)
- **Build tags**: (standard / `-tags deep`)

## Description
<!-- Clear, concise description of the bug -->

## Steps to Reproduce
1. 
2. 
3. 

## Expected Behavior
<!-- What should happen? -->

## Actual Behavior
<!-- What happens instead? (error messages, logs, findings) -->

## Minimal Reproduction
```bash
# Exact command that triggers the bug
gash scan --target ...
```

## Additional Context
- Plugin(s) involved:
- Oracle(s) involved:
- Fixture lab or real target:
- Any workarounds:

## Checklist
- [ ] I searched existing issues and didn't find a duplicate
- [ ] I can reproduce on the fixture lab (`go run ./cmd/gash bench run --dataset bench/datasets/fixtures.yaml`)
- [ ] I included relevant logs/output (redact sensitive data)