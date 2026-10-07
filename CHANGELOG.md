# Changelog

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
