<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/auth.md
What: Authenticated scan contexts (--auth-header/--cookie/--basic-auth).
Why: requires_auth plugins need credentials; credentials must not leak.
-->

# Authenticated Scans

Plugins with `requires_auth: true` are skipped unless the scan carries an
authentication context. Provide one (or more) of:

```sh
gash scan --target https://app.example.com --scope app.example.com \
  --auth-header "Authorization: Bearer <token>" \
  --cookie "session=<id>; theme=dark" \
  --basic-auth "user:password"
```

## Semantics

- `--auth-header "Name: value"` (repeatable): sent as-is on every request.
- `--cookie "a=b[; c=d]"` (repeatable): merged into one `Cookie` header.
- `--basic-auth "user:password"`: sent as `Authorization: Basic ...`.
- Precedence: an explicitly set request header is never overwritten by the
  context (explicit wins).
- Any of the three sets the engine `HasAuth` gate, so `requires_auth`
  plugins become runnable. Scope, budget, and safe/active policy still apply
  unchanged — auth does not widen scope or authorize destructive payloads.

## Validation (fail-closed)

- `Name: value` shape required; empty names/values rejected.
- CR/LF anywhere in names or values is rejected (header-injection guard).
- `--basic-auth` requires the `user:password` shape (password may be empty).

## Redaction

Credential **values never appear** in findings, reports, or logs. The CLI
prints only a redacted summary to stderr:

```text
auth: headers=[Authorization] cookies=[session,theme] basic=yes(user=admin)
```

Store tokens in CI secret storage or environment-fed wrappers; never commit
them, never paste them into issue reports.

---

## Login Flow (`--login-url`)

Instead of pasting a session token you already extracted, you can point Gash at
the login form and let it establish one real session (P2.6):

```sh
gash scan --target https://app.example.com --scope app.example.com \
  --active \
  --login-url https://app.example.com/login \
  --login-user analyst \
  --login-pass-env GASH_LOGIN_PASS \
  --login-verify-url https://app.example.com/dashboard
```

### Flags

- `--login-url <url>`: page carrying the login form (required to enable the flow).
- `--login-user <name>`: the single username set (required).
- `--login-pass <pass>` or `--login-pass-env <VAR>`: the single password set
  (exactly one source; missing/empty env vars fail fast). Prefer the env var:
  `--login-pass` is visible in the process list.
- `--login-user-field` / `--login-pass-field`: field-name overrides for
  unusual forms.
- `--login-verify-url <url>`: page that only logged-in users can see
  (defaults to the form action target, then to `--login-url`).

The flow sends a POST, so it requires `--active` and is subject to the same
scope, rate, and budget policy as every other request (a dedicated per-plugin
budget of 40 requests bounds the whole flow).

### Semantics (honest verification)

1. GET the login page and pick the first form containing a `type=password`
   field. GET-method forms and `text/plain` forms are refused.
2. Username field: your override, else the first text/email field whose name
   matches `user|email|login|account|mail`, else the first text/email field.
   Password field: your override, else the first `type=password` field. Hidden
   fields (CSRF tokens) are preserved with fresh values on every attempt.
3. POST through the policy pipeline. Redirects are followed manually (up to 5);
   cookies set on any hop are kept per host, and an `https → http` downgrade
   aborts the flow.
4. Verify: GET the verify target with the new cookies. Success is declared only
   when the response has **no** password field AND differs from an anonymous
   control fetch of the same URL (token-like `value="..."` contents are
   normalized out, so rotating CSRF nonces cannot fake a difference).
5. On success the session cookies are merged into the scan context and every
   later request (including `requires_auth` plugins) carries them.

### Failure reasons (never silent)

Failures do not stop the scan: one `login` skip record is emitted and the scan
continues unauthenticated. `login-failed: <reason>` uses these reasons:

| Reason | Meaning |
| --- | --- |
| `login-failed` | POST rejected; no session evidence. |
| `2fa-detected` | OTP/MFA/CAPTCHA field seen; the flow **never** retries. |
| `unverified-session` | A session-like cookie was set but verification stayed inconclusive. |
| `no-password-form` | No form with a password field on the page. |
| `no-user-field` | No usable username field (use `--login-user-field`). |
| `login-form-get` | Form submits with GET (password would land in the URL). |
| `unsupported-enctype` | `text/plain` form encoding. |
| `redirect-downgrade-blocked` | Login tried to redirect https → http. |
| `request-failed` | The requests could not be completed. |

Stats: `login_attempted`, `login_succeeded`, `login_cookies`. A scope or
policy violation during login is the one fail-closed case: the scan aborts
before any plugin traffic.

### Attempts and limits

- At most 2 POST attempts by default (hard cap 3): this is a single credential
  set, never password guessing. Once `2fa-detected` fires there is no retry.
- Precedence: explicitly supplied `--auth-header`/`--cookie`/`--basic-auth`
  values win per name; login-derived cookies only fill the gaps, so you can
  mix, e.g., a fixed API token with a form-derived session cookie.
- Credentials never appear in findings, stats, skip reasons, or logs. The CLI
  prints a redacted summary (`user=[redacted] pass=[redacted]`).
- Not covered: OAuth/SSO/OIDC flows, JS-rendered login widgets, JSON token
  endpoints, and re-login after mid-scan session expiry — see
  `docs/known-limits.md`.

---

## Upstream Proxy & TLS / mTLS Verification (`--proxy`)

For manual inspection, workflow validation, and collaborative red teaming, Gash supports routing all HTTP traffic through an upstream interception proxy such as **Burp Suite** or **OWASP ZAP**:

```sh
gash scan --target https://app.example.com --scope app.example.com \
  --proxy http://127.0.0.1:8080
```

### 1. Scope Firewall Integrity
Gash's engine-level `PolicySession` operates as a preflight policy gateway ahead of the network transport. 
Even when `--proxy` is active:
- Every probe request is evaluated against the `--scope` allowlist **before** reaching the proxy transport.
- Requests outside the target allowlist fail immediately with `ErrScopeViolation` and are never dispatched to the proxy.
- HTTP server redirects (including 301/302 redirects returned through the proxy) undergo strict scope revalidation before the next hop is attempted.

### 2. TLS Certificate Verification & Self-Signed Proxy CAs
When intercepting HTTPS traffic, proxies terminate the client TLS connection and generate dynamic host certificates signed by the proxy's internal Root CA (e.g. *PortSwigger CA* for Burp Suite, *OWASP ZAP Root CA*):

- **System Trust Store**: Gash adheres to strict fail-closed certificate validation. For HTTPS inspection, install and trust the proxy's exported Root CA certificate in the operating system certificate store (e.g. Windows Trusted Root Certification Authorities or `/etc/ssl/certs` on Linux).
- **Environment CA Override**: Alternatively, export the proxy CA path using Go's standard environment variable without altering system certificates:
  ```sh
  export SSL_CERT_FILE=/path/to/burp_cacert.pem
  gash scan --target https://app.example.com --proxy http://127.0.0.1:8080
  ```

### 3. Mutual TLS (mTLS) in Proxy Scenarios
When the target application requires client certificate authentication (mTLS):

- **Proxy-Terminated mTLS Handshake**: In an interception topology (`Gash -> Proxy -> Target`), the client certificate authentication is negotiated between the **upstream proxy** and the **target server**.
- **Configuration**: 
  - Install the client certificate (PKCS#12 or PEM keypair) inside Burp Suite under `Settings -> Network -> Connections -> Client TLS Certificates` or OWASP ZAP under `Options -> Network -> Client Certificates`.
  - Gash communicates with the proxy over HTTP (or standard TLS to the proxy), and the proxy presents the client certificate to the target host during the upstream TLS handshake.
- **Fail-Closed Security**: If the proxy fails to present a valid client certificate or the target rejects it (e.g. HTTP 403 / TLS handshake failure), Gash classifies the error as transport failure and isolates the affected probes without leaking credentials.

