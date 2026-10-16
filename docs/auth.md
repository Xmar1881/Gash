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

