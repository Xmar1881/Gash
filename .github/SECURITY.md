# Security Policy

## Supported Versions

We only support the latest stable release with security updates.

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |

## Reporting a Vulnerability

**Please do NOT open public issues for security vulnerabilities.**

Report security vulnerabilities privately via:

- **GitHub Security Advisories**: https://github.com/Xmar1881/Gash/security/advisories/new
- **Email**: security@xmar1881.dev (PGP key available on GitHub profile)

Include in your report:
1. Affected plugin/oracle/component
2. Steps to reproduce (minimal test case)
3. Impact assessment (CVSS if possible)
4. Suggested fix or mitigation

## Response Timeline

| Severity | Initial Response | Fix Target |
|----------|------------------|------------|
| Critical (CVSS ≥ 9.0) | 24 hours | 7 days |
| High (CVSS ≥ 7.0) | 48 hours | 14 days |
| Medium (CVSS ≥ 4.0) | 72 hours | 30 days |
| Low (CVSS < 4.0) | 1 week | Next release |

## Scope

This policy covers:
- Gash core engine (`internal/engine/`, `internal/plugin/`, `internal/oracle/`)
- All reference plugins (`plugins/*`)
- Benchmark harness (`internal/bench/`)

Out of scope:
- Third-party dependencies (report to upstream)
- Docker/base image vulnerabilities
- Denial-of-service via resource exhaustion (expected for scanners)

## Disclosure Process

1. Acknowledge receipt within SLA
2. Validate and reproduce
3. Develop fix with test case
4. Coordinate disclosure date (typically 7-30 days after fix)
5. Publish GitHub Security Advisory + release
6. Credit reporter (unless anonymity requested)

## Safe Harbor

We authorize good-faith security research on:
- Public GitHub Actions runners
- Local fixture lab (`bench.StartFixtureLab()`)
- Your own authorized targets

**We will NOT pursue legal action** for research that:
- Respects `robots.txt` and `--scope`
- Does not access third-party data
- Reports findings via this policy