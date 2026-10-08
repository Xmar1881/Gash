# Changelog

## v0.4.0

- Detection depth: POST-body fuzzing for SQLi/XSS/SSTI/OS-command
  (deep only, password forms never touched); cross-session IDOR
  confirmation via `--cookie-b`/`--header-b`; UNION ORDER BY
  differential; DBMS fingerprinting; OOB-SQLi DNS exfiltration
- Proof upgrades: php://filter LFI confirmation, Azure + GCP metadata
  SSRF, MSSQL WAITFOR delay, Thymeleaf SSTI bundle, SVG upload
  verification, LDAP wildcard bypass, cache-poisoning surface
- Coverage: crawler POST forms, wider FUZZ params, dir backup mutations
  + extensions, broader JS secret sweep; CSP weakness + HSTS depth
  audit, CORS preflight + null-origin, X-Forwarded-Host fallback,
  reset-poisoning OOB proof, TRACE live confirm; 42 checks total
- Honesty hardening: dispatcher session-binding fix, 401/403 never
  exposure without content proof, PartialResults + INCOMPLETE reporting,
  429 storm caps, report-dir auto-create
- UX: live spinner + 429 countdown, modern 3-step wizard, Xmar1881
  branding in banner/menu/README/reports

## v0.3.0

- 39 security checks: injection (SQLi, OS command, CRLF, SSTI), XSS
  (reflected, stored, DOM), SSRF/IDOR, auth (login bypass, JWT, CSRF),
  modern web (CORS, open redirect, traversal, headers, methods, GraphQL,
  Firebase, Supabase, Next.js, WordPress), recon + BFS crawler
- Safe by default: aggressive checks (time-based, active POST, uploads,
  login tests) require explicit `--deep`
- Findings vs INFO observations (discovery never scores), confidence
  ratings, CWE/OWASP/CVSS enrichment
- Out-of-band verification via interactsh (`--oob`): proven Blind XSS
  and SSRF callbacks
- JSON/HTML/TXT reports with previous-scan diff, bulk scan with resume,
  scope allowlist, CI gate (`--fail-on`)
