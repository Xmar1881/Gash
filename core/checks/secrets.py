"""Secret/identity exposure: JS secrets, JWT, Firebase, Supabase."""
from __future__ import annotations

import base64
import json
import re
from urllib.parse import urlparse

from core.checks._shared import _mask, _same_host
from core.colors import warn
from core.diff import (looks_authenticated, response_fingerprint,
                       same_protected_response)
from core.net import ScanBudgetExceeded, pace
from core.registry import check as register_check
from core.scanner import Finding, _get

SECRET_RES = [
    # (kind, pattern, severity, why-this-level)
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "CRITICAL", "account-level credential"),
    ("Stripe live key", re.compile(r"\bsk-live-[0-9A-Za-z]{16,}\b"),
     "CRITICAL", "live money-moving key"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
     "CRITICAL", "workspace credential"),
    ("GitHub token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
     "CRITICAL", "account/repo credential"),
    # CI/CD supply-chain class (2025–2026 research): Actions + npm tokens
    # in frontend/bundles are as bad as classic ghp_ leaks.
    ("GitHub Actions token", re.compile(r"\bghs_[A-Za-z0-9_]{36,}\b"),
     "CRITICAL", "CI workflow credential (supply-chain)"),
    ("GitHub fine-grained PAT",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
     "CRITICAL", "fine-grained repo credential"),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36,}\b"),
     "CRITICAL", "package-publish credential (supply-chain)"),
    ("OpenAI key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
     "CRITICAL", "billable API credential"),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
     "CRITICAL", "billable API credential"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
     "MEDIUM", "impact depends on Cloud Console API restrictions — verify"),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "CRITICAL", "raw private key material"),
]
PLACEHOLDER_HINT = re.compile(
    r"example|test|xxx+|your[_-]?key|1234|abcd|placeholder|dummy|sample", re.I)
# ---------- 7. JWT alg:none (passive) ----------

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])")


def _jwt_header(token: str) -> dict | None:
    """Decode JWT header JSON without verifying. None on failure."""
    try:
        import base64
        import json as _json
        seg = token.split(".")[0]
        seg += "=" * (-len(seg) % 4)
        hdr = _json.loads(base64.urlsafe_b64decode(seg).decode(
            "utf-8", "ignore"))
        return hdr if isinstance(hdr, dict) else None
    except Exception:
        return None


def _jwt_alg(token: str) -> str | None:
    """Decode a JWT header without verifying. Returns alg or None."""
    hdr = _jwt_header(token)
    if not hdr:
        return None
    alg = hdr.get("alg")
    return str(alg) if alg is not None else None


@register_check("jwt-none", "JWTs using alg:none / dangerous kid (passive)",
                order=11)
def test_jwt_none(pages: dict, verbose: bool = False) -> list[Finding]:
    """Passive JWT header hygiene: alg:none sighting + path-like kid
    (header injection / key confusion surface). Acceptance/replay is NOT
    assumed — titles stay LOW/MEDIUM until confirmed."""
    out: list[Finding] = []
    for html in list((pages or {}).values())[:4]:
        for m in JWT_RE.finditer(html or ""):
            tok = m.group(0)
            hdr = _jwt_header(tok) or {}
            alg = str(hdr.get("alg") or "").lower()
            kid = str(hdr.get("kid") or "")
            if alg == "none" and not any(
                    f.title.startswith("JWT using alg:none") for f in out):
                out.append(Finding(
                    title="JWT using alg:none observed", severity="LOW",
                    url="",
                    detail="A JWT with alg:none was seen in page content. "
                           "It becomes CRITICAL only if the backend accepts "
                           "it (replay a doctored token to confirm)",
                    evidence="alg:none",
                    confidence="Low",
                ))
                if verbose:
                    print(warn("    [!] JWT alg:none in page content"))
            # kid path / URL / file hints → key-confusion surface (no replay).
            kid_bad = bool(re.search(
                r"\.\.|/etc/|file:|https?://|\\\\", kid, re.I))
            if kid_bad and not any("JWT kid" in f.title for f in out):
                out.append(Finding(
                    title="JWT kid path/URL confusion surface",
                    severity="MEDIUM",
                    url="",
                    detail="JWT header kid looks like a path or URL "
                           f"({kid[:60]!r}). If the verifier fetches keys by "
                           "kid, this is a classic confusion/SSRF surface — "
                           "pin keys server-side; never trust client kid paths.",
                    evidence=f"kid={kid[:80]}",
                    confidence="Medium",
                ))
                if verbose:
                    print(warn(f"    [!] JWT kid surface: {kid[:40]}"))
            if len(out) >= 2:
                break
        if len(out) >= 2:
            break
    return out[:2]


# ---------- 7b. JWT acceptance replay (deep-only, GET only) ----------

_JWT_AUTH_MARKERS = re.compile(
    r"logout|sign[ -]?out|dashboard|account|profile|settings|private|welcome",
    re.I)
_JWT_LOGIN_MARKERS = re.compile(
    r"sign[ -]?in|log[ -]?in|login|forgot password|unauthori[sz]ed",
    re.I)


def _jwt_b64_json(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwt_none_variant(token: str) -> str | None:
    """Keep claims unchanged and remove only the signing requirement."""
    try:
        header, payload, _sig = token.split(".", 2)
        def decode(seg: str) -> dict:
            padded = seg + "=" * (-len(seg) % 4)
            value = json.loads(base64.urlsafe_b64decode(padded).decode())
            if not isinstance(value, dict):
                raise ValueError("JWT segment is not an object")
            return value
        hdr = decode(header)
        claims = decode(payload)
        hdr["alg"] = "none"
        return f"{_jwt_b64_json(hdr)}.{_jwt_b64_json(claims)}."
    except Exception:
        return None


def _jwt_auth_candidates(session, pages: dict, base: str) -> list[tuple[str, str, bool]]:
    """Return (token, URL, from-session-auth) without exposing token values."""
    out: list[tuple[str, str, bool]] = []
    seen: set[str] = set()
    preferred_url = next((str(url) for url in (pages or {})
                          if urlparse(str(url)).path not in ("", "/")
                          and (urlparse(str(url)).hostname or "").lower() ==
                          (urlparse(base).hostname or "").lower()),
                         base.rstrip("/") + "/")

    def add(token: str, url: str, from_auth: bool) -> None:
        if not JWT_RE.fullmatch(token or "") or token in seen:
            return
        try:
            same = (urlparse(url).hostname or "").lower() == \
                (urlparse(base).hostname or "").lower()
        except Exception:
            same = False
        if not same:
            url = base.rstrip("/") + "/"
        seen.add(token)
        out.append((token, url, from_auth))

    headers = getattr(session, "headers", {}) or {}
    for key, value in headers.items() if hasattr(headers, "items") else ():
        if str(key).lower() == "authorization":
            match = JWT_RE.search(str(value))
            if match:
                add(match.group(0), preferred_url, True)
    cookies = getattr(session, "cookies", None)
    try:
        cookie_values = [(getattr(c, "name", ""), getattr(c, "value", ""))
                         for c in cookies] if cookies else []
    except Exception:
        cookie_values = []
    for _name, value in cookie_values:
        match = JWT_RE.search(str(value))
        if match:
            add(match.group(0), preferred_url, True)
    for url, html in list((pages or {}).items())[:8]:
        for match in JWT_RE.finditer(html or ""):
            add(match.group(0), str(url), False)
    return out[:8]


def _jwt_replay(session, url: str, token: str, timeout: int):
    """One explicit GET replay; never mutates the caller's session headers."""
    try:
        pace()
        return session.get(url, timeout=timeout, allow_redirects=False,
                           headers={"Authorization": f"Bearer {token}"})
    except ScanBudgetExceeded:
        raise
    except Exception:
        return None


def _jwt_auth_body(response) -> bool:
    return looks_authenticated(response,
                               positive=_JWT_AUTH_MARKERS.pattern,
                               negative=_JWT_LOGIN_MARKERS.pattern)


def _jwt_fp(response) -> str:
    return response_fingerprint(response)


@register_check("jwt-acceptance", "JWT alg:none/kid acceptance replay",
                deep_only=True, order=11, active=True, requires_auth=True,
                max_requests=3)
def test_jwt_acceptance(session, base: str, pages: dict, timeout: int,
                        verbose: bool = False) -> list[Finding]:
    """Controlled GET differential: claims stay unchanged and no elevation
    claim is added. A status code alone never proves acceptance."""
    candidates = _jwt_auth_candidates(session, pages, base)
    if not candidates:
        return []
    out: list[Finding] = []
    # A real session token is preferred as the baseline. Page-only tokens are
    # useful only when they are already an authenticated-looking bearer.
    baseline = next((x for x in candidates
                     if x[2] and (_jwt_alg(x[0]) or "").lower() != "none"), None)
    if baseline:
        original, url, _ = baseline
        forged = _jwt_none_variant(original)
        if forged:
            first = _jwt_replay(session, url, original, timeout)
            second = _jwt_replay(session, url, forged, timeout)
            same, fingerprint = same_protected_response(
                first, second, positive=_JWT_AUTH_MARKERS.pattern,
                negative=_JWT_LOGIN_MARKERS.pattern)
            if same:
                out.append(Finding(
                    title="JWT alg:none accepted (replay confirmed)",
                    severity="CRITICAL", url=url,
                    detail="An authenticated GET returned the same protected "
                           "content for the original token and a claim-identical "
                           "alg:none variant; no privilege claim was added.",
                    evidence="baseline+alg:none protected-response fingerprint "
                             f"{fingerprint}",
                    confidence="High", method="GET", location="header",
                    param="Authorization", auth_context="user",
                    fingerprint=fingerprint, confirm="jwt-replay"))
    # A dangerous kid is reported only when the supplied token itself is
    # accepted by an authenticated session. We do not rewrite a signed token.
    for token, url, from_auth in candidates:
        kid = str((_jwt_header(token) or {}).get("kid") or "")
        if not from_auth or not re.search(r"\.\.|/etc/|file:|https?://|\\\\", kid, re.I):
            continue
        response = _jwt_replay(session, url, token, timeout)
        if _jwt_auth_body(response):
            out.append(Finding(
                title="JWT dangerous kid accepted (replay confirmed)",
                severity="MEDIUM", url=url,
                detail="An authenticated GET accepted a token whose client-"
                       "supplied kid looks like a path or URL. This confirms "
                       "acceptance of the surface, not key disclosure or SSRF.",
                evidence=f"kid={kid[:80]}", confidence="High", method="GET",
                location="header", param="Authorization", auth_context="user",
                fingerprint=_jwt_fp(response), confirm="jwt-replay"))
            break
    if verbose and out:
        print(warn(f"    [!] JWT acceptance replay confirmed: {len(out)}"))
    return out[:2]


# ---------- 6. JS secrets ----------

@register_check("js-secrets", "Hardcoded secrets in JavaScript", order=11)
def test_js_secrets(session, base: str, pages: dict, timeout: int,
                    verbose: bool = False) -> list[Finding]:
    """AI-built frontends love shipping live keys. Scans inline scripts on
    every crawled page plus up to 5 same-host .js files (200KB cap each).
    Placeholders are skipped, real secrets are masked in the report."""
    from urllib.parse import urljoin
    texts: list[str] = []
    for html in list((pages or {}).values()):
        for m in re.finditer(
                r"<script(?![^>]*src=)[^>]*>(.*?)</script>",
                html or "", re.I | re.S):
            chunk = m.group(1) or ""
            if chunk.strip():
                texts.append(chunk[:200_000])
            if len(texts) >= 12:
                break
        if len(texts) >= 12:
            break
    try:
        srcs = []
        for html in list((pages or {}).values()):
            for m in re.findall(r'<script[^>]*src=["\']([^"\']+)["\']',
                                html or "", re.I):
                if m not in srcs:
                    srcs.append(m)
    except Exception:
        srcs = []
    fetched = 0
    for src in srcs:
        if fetched >= 5:
            break
        full = urljoin(base + "/", src)
        if not _same_host(full, base):
            continue
        fetched += 1
        got = _get(session, full, timeout)
        if not got or len(got[1] or "") > 200_000:
            continue
        texts.append(got[1])
    out: list[Finding] = []
    for kind, rx, severity, note in SECRET_RES:
        for m in rx.finditer("\n".join(texts)):
            secret = m.group(0)
            if PLACEHOLDER_HINT.search(secret):
                continue
            out.append(Finding(
                title=f"Exposed secret in JavaScript ({kind})",
                severity=severity,
                url=base + "/",
                detail=f"Hardcoded {kind} found in frontend code "
                       f"(any visitor can read it; {note})",
                evidence=_mask(secret),
                confidence="High",
            ))
            if verbose:
                print(warn(f"    [!] JS secret ({kind}): {base}/"))
            break  # one finding per secret kind is enough
        if len(out) >= 3:
            break
    return out[:3]


# ---------- 14. Firebase open database ----------

FIREBASE_RE = re.compile(r"https?://([a-z0-9-]+)\.firebaseio\.com", re.I)
FIREBASE_PROJ_RE = re.compile(
    r'''(?:projectId|firebase[_-]?project)["']?\s*[:=]\s*["']([a-z0-9-]+)["']''', re.I)


@register_check("firebase-open", "Public Firebase realtime database", order=11)
def test_firebase_open(session, base: str, pages: dict, timeout: int,
                       verbose: bool = False) -> list[Finding]:
    """Firebase project refs leak in JS. One GET to /.json proves the
    database reads without auth."""
    projects: list[str] = []
    for html in list((pages or {}).values())[:4]:
        body = html or ""
        projects += FIREBASE_RE.findall(body)
        projects += FIREBASE_PROJ_RE.findall(body)
    projects = list(dict.fromkeys(p for p in projects if p))[:3]
    out: list[Finding] = []
    for proj in projects:
        got = _get(session, f"https://{proj}.firebaseio.com/.json", timeout)
        if not got or got[0] != 200:
            continue
        try:
            import json as _json
            data = _json.loads(got[1] or "")
        except Exception:
            continue
        if isinstance(data, (dict, list)) and data:
            out.append(Finding(
                title="Open Firebase database", severity="CRITICAL",
                url=f"https://{proj}.firebaseio.com/.json",
                detail=f"Realtime database of '{proj}' reads without "
                       "authentication",
                evidence=f"{len(data)} top-level keys" if isinstance(
                    data, dict) else f"{len(data)} records",
                confidence="High",
            ))
            if verbose:
                print(warn(f"    [!] Firebase open: {proj}"))
            break
    return out


# ---------- 15. Supabase anon table read ----------

SUPABASE_URL_RE = re.compile(r"https?://([a-z0-9-]+\.supabase\.co)", re.I)
SUPABASE_KEY_RE = re.compile(
    r'''(?:anon|public)[_a-z]*(?:key)?["']?\s*[:=]\s*["'](eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*)["']''',
    re.I)
PRIVATE_TABLES = ["profiles", "users", "user_profiles", "customers",
                  "orders", "messages", "payments", "subscriptions",
                  "chats", "api_keys", "secrets", "tokens"]


@register_check("supabase-anon", "Supabase table readable without login", order=11)
def test_supabase_anon(session, base: str, pages: dict, timeout: int,
                       verbose: bool = False) -> list[Finding]:
    """The CVE-2025-48757 pattern: anon key in the bundle, RLS missing on a
    private-smelling table. Only private tables are probed — a public
    products listing is not a finding."""
    hosts: list[str] = []
    keys: list[str] = []
    for html in list((pages or {}).values())[:4]:
        body = html or ""
        hosts += SUPABASE_URL_RE.findall(body)
        keys += SUPABASE_KEY_RE.findall(body)
    hosts = list(dict.fromkeys(hosts))[:2]
    keys = list(dict.fromkeys(keys))[:2]
    if not hosts or not keys:
        return []
    out: list[Finding] = []
    for host in hosts:
        for table in PRIVATE_TABLES:
            got = _get(session,
                       f"https://{host}/rest/v1/{table}?select=*&limit=1",
                       timeout,
                       headers={"apikey": keys[0],
                                "Authorization": f"Bearer {keys[0]}"})
            if not got or got[0] != 200:
                continue
            try:
                import json as _json
                data = _json.loads(got[1] or "")
            except Exception:
                continue
            if isinstance(data, (dict, list)) and data:
                out.append(Finding(
                    title="Exposed Supabase table (no login)", severity="CRITICAL",
                    url=f"https://{host}/rest/v1/{table}",
                    detail=f"Table '{table}' returns rows for an anonymous key; "
                           "row-level security is missing or open",
                    evidence=table,
                    confidence="Medium",
                ))
                if verbose:
                    print(warn(f"    [!] Supabase open: {host}/{table}"))
                return out
    return out

# ---------- Public cloud object storage (S3 / GCS / Azure Blob) ----------

# Only URLs already present in crawled pages are probed — never invents
# bucket names. Listing XML/JSON markers = content proof (status alone no).
S3_URL_RE = re.compile(
    r"https?://([a-z0-9.\-]+)\.s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com"
    r"(?:/([^\s\"'<>]*))?"
    r"|https?://s3(?:[.\-][a-z0-9\-]+)?\.amazonaws\.com/([a-z0-9.\-]+)"
    r"(?:/([^\s\"'<>]*))?",
    re.I)
GCS_URL_RE = re.compile(
    r"https?://storage\.googleapis\.com/([a-z0-9.\-_]+)"
    r"(?:/([^\s\"'<>]*))?"
    r"|https?://([a-z0-9.\-_]+)\.storage\.googleapis\.com",
    re.I)
AZURE_BLOB_RE = re.compile(
    r"https?://([a-z0-9\-]+)\.blob\.core\.windows\.net/([a-z0-9\-]+)",
    re.I)
LIST_MARKERS = (
    "<ListBucketResult", "<ListBucketResult ",
    "<Contents>", "<Key>",
    '"kind": "storage#objects"',
    '"kind":"storage#objects"',
    "<EnumerationResults", "<Blobs>",
)


def _cloud_candidates(pages: dict) -> list[str]:
    """Deduped listing-root URLs mined from page HTML/JS (cap 6)."""
    urls: list[str] = []
    for html in list((pages or {}).values())[:5]:
        body = html or ""
        for m in S3_URL_RE.finditer(body):
            if m.group(1):
                bucket = m.group(1)
                urls.append(f"https://{bucket}.s3.amazonaws.com/")
            elif m.group(3):
                urls.append(f"https://s3.amazonaws.com/{m.group(3)}/")
        for m in GCS_URL_RE.finditer(body):
            bucket = m.group(1) or m.group(3)
            if bucket:
                urls.append(f"https://storage.googleapis.com/{bucket}")
        for m in AZURE_BLOB_RE.finditer(body):
            acct, container = m.group(1), m.group(2)
            urls.append(
                f"https://{acct}.blob.core.windows.net/{container}?restype=container&comp=list")
    return list(dict.fromkeys(urls))[:6]


@register_check("cloud-storage", "Public cloud storage bucket listing", order=11)
def test_cloud_storage(session, base: str, pages: dict, timeout: int,
                       verbose: bool = False) -> list[Finding]:
    """Cloud misconfig class (research 2024–2026): public S3/GCS/Azure
    containers linked from the app. Content listing markers required —
    403/AccessDenied is not a finding."""
    out: list[Finding] = []
    for url in _cloud_candidates(pages):
        got = _get(session, url, timeout)
        if not got or got[0] != 200:
            continue
        body = got[1] or ""
        if len(body) > 500_000:
            continue
        hit = next((m for m in LIST_MARKERS if m in body), None)
        if not hit:
            continue
        # Reject error pages that echo the marker string in docs
        low = body.lower()
        if "accessdenied" in low or "<error>" in low[:500]:
            continue
        out.append(Finding(
            title="Public cloud storage listing",
            severity="CRITICAL",
            url=url[:240],
            detail="Object-storage container linked from the app returns a "
                   "public listing (no auth). Restrict ACL/IAM; rotate any "
                   "objects that may have been exposed.",
            evidence=hit[:60],
            confidence="High",
            method="GET",
            location="url",
            confirm="content-marker",
        ))
        if verbose:
            print(warn(f"    [!] Public bucket listing: {url[:80]}"))
        if len(out) >= 2:
            break
    return out


# ---------- Deserialization surface (passive; no gadget execution) ----------

# Client-controlled serialized blobs are a classic RCE footgun. We only
# sight magic markers — never instantiate or send gadget chains.
JAVA_SER_B64 = re.compile(r"\brO0AB[A-Za-z0-9+/]{8,}={0,2}\b")
JAVA_SER_HEX = re.compile(r"\baced0005[0-9a-fA-F]{8,}\b")
PHP_SER_OBJ = re.compile(r"\bO:\d+:\"[A-Za-z_\\\\]{3,80}\":\d+:\{")
DOTNET_VIEWSTATE = re.compile(r"\b/wE[A-Za-z0-9+/]{40,}={0,2}\b")


def _deser_blobs(pages: dict) -> list[tuple[str, str, str]]:
    """[(kind, evidence_snip, url)] from crawled HTML (cap scan)."""
    hits: list[tuple[str, str, str]] = []
    for url, html in list((pages or {}).items())[:6]:
        body = html or ""
        if len(body) > 300_000:
            body = body[:300_000]
        for kind, rx in (
            ("Java serialized (base64)", JAVA_SER_B64),
            ("Java serialized (hex)", JAVA_SER_HEX),
            ("PHP serialized object", PHP_SER_OBJ),
            (".NET ViewState blob", DOTNET_VIEWSTATE),
        ):
            m = rx.search(body)
            if m:
                hits.append((kind, m.group(0)[:48], url))
        if len(hits) >= 4:
            break
    return hits


@register_check("deserialize-surface",
                "Client-controlled serialization markers (passive)", order=11)
def test_deserialize_surface(pages: dict, verbose: bool = False,
                             base: str = "") -> list[Finding]:
    """Passive sighting of Java/PHP/.NET serialized payloads in pages.
    No deserialization is performed — MEDIUM for Java magic (common RCE
    class), LOW for PHP/.NET without further proof."""
    out: list[Finding] = []
    for kind, ev, url in _deser_blobs(pages):
        sev = "MEDIUM" if kind.startswith("Java") else "LOW"
        out.append(Finding(
            title=f"Serialized payload in client content ({kind})",
            severity=sev,
            url=(url or base or "")[:240],
            detail=f"{kind} marker observed in crawled content. If the "
                   "server deserializes this without an allowlist, RCE / "
                   "object injection follows — never deserialize "
                   "untrusted input; prefer JSON with typed schemas.",
            evidence=_mask(ev) if len(ev) > 20 else ev,
            confidence="Medium" if sev == "MEDIUM" else "Low",
            location="body",
            confirm="passive-marker",
        ))
        if verbose:
            print(warn(f"    [!] Deserialize surface ({kind}): {(url or '')[:60]}"))
        if len(out) >= 2:
            break
    return out


# ---------- CI/CD workflow exposure (supply-chain research 2025–2026) ----------

CI_WORKFLOW_PATHS = [
    "/.github/workflows/ci.yml",
    "/.github/workflows/main.yml",
    "/.github/workflows/build.yml",
    "/.github/workflows/publish.yml",
    "/azure-pipelines.yml",
]
WORKFLOW_SHAPE = re.compile(
    r"(?m)^\s*(?:on|jobs|runs-on|steps)\s*:", re.I)
# Compromised / high-risk action patterns from 2025 supply-chain incidents
# (tj-actions) — unpinned @v* tags on these names are a yellow flag.
BAD_ACTION_RE = re.compile(
    r"(?m)^\s*-\s*uses:\s*(tj-actions/changed-files)@(?!sha256:)[^\s#]+",
    re.I)
SECRET_IN_YAML = re.compile(
    r"(?i)(?:npm_[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|"
    r"ghs_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"AKIA[0-9A-Z]{16})")
SECRETS_CTX = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")


@register_check("ci-workflow",
                "Public CI/CD workflow + supply-chain risk markers", order=11)
def test_ci_workflow(session, base: str, timeout: int,
                     verbose: bool = False,
                     pages: dict | None = None) -> list[Finding]:
    """Research supply-chain class: public workflow YAML on the web root
    (misdeployed .github) or embedded in pages. Flags hardcoded tokens and
    known-risky unpinned actions. Never executes workflows."""
    out: list[Finding] = []
    # Prefer in-page YAML first (no extra hop), then a few path probes.
    blobs: list[tuple[str, str]] = []
    for url, html in list((pages or {}).items())[:4]:
        if WORKFLOW_SHAPE.search(html or "") and (
                "uses:" in (html or "") or "runs-on:" in (html or "")):
            blobs.append((url, html or ""))
    root = (base or "").rstrip("/")
    for path in CI_WORKFLOW_PATHS[:4]:
        if len(blobs) >= 4:
            break
        got = _get(session, root + path, timeout)
        if not got or got[0] != 200:
            continue
        body = got[1] or ""
        if len(body) > 200_000 or not WORKFLOW_SHAPE.search(body):
            continue
        blobs.append((root + path, body))

    for url, body in blobs[:4]:
        tok = SECRET_IN_YAML.search(body)
        if tok:
            out.append(Finding(
                title="CI/CD workflow embeds live credential",
                severity="CRITICAL",
                url=url[:240],
                detail="Public workflow/YAML contains a live token pattern "
                       "(supply-chain credential leakage). Rotate the secret "
                       "immediately; use ${{ secrets.* }} and never commit "
                       "raw tokens.",
                evidence=_mask(tok.group(0)),
                confidence="High",
                method="GET",
                location="body",
                confirm="secret-pattern",
            ))
            if verbose:
                print(warn(f"    [!] CI secret in workflow: {url[:80]}"))
            break
        bad = BAD_ACTION_RE.search(body)
        if bad:
            out.append(Finding(
                title="CI workflow uses high-risk unpinned action",
                severity="MEDIUM",
                url=url[:240],
                detail=f"Workflow references {bad.group(1)} without a "
                       "commit-SHA pin (tj-actions class supply-chain risk "
                       "2025). Pin actions to full SHAs; audit recent runs.",
                evidence=bad.group(0)[:80],
                confidence="Medium",
                method="GET",
                location="body",
                confirm="action-name",
            ))
            if verbose:
                print(warn(f"    [!] Risky CI action: {url[:80]}"))
            break
        if SECRETS_CTX.search(body) and url.rstrip("/").endswith(
                (".yml", ".yaml")):
            # Exposed workflow that *references* secrets — INFO observation.
            if not any(f.severity == "INFO" for f in out):
                out.append(Finding(
                    title="Public CI/CD workflow file exposed",
                    severity="INFO",
                    url=url[:240],
                    detail="Workflow YAML is world-readable on the app host "
                           "(misdeployed .github). Not a vuln by itself, but "
                           "leaks pipeline shape and secret *names*.",
                    evidence="on:/jobs:",
                    confidence="High",
                    method="GET",
                    location="path",
                    confirm="workflow-shape",
                ))
        if len(out) >= 2:
            break
    return out[:2]


__all__ = [
    "SECRET_RES",
    "PLACEHOLDER_HINT",
    "JWT_RE",
    "_jwt_header",
    "_jwt_alg",
    "test_jwt_none",
    "test_js_secrets",
    "FIREBASE_RE",
    "FIREBASE_PROJ_RE",
    "test_firebase_open",
    "SUPABASE_URL_RE",
    "SUPABASE_KEY_RE",
    "PRIVATE_TABLES",
    "test_supabase_anon",
    "S3_URL_RE",
    "GCS_URL_RE",
    "AZURE_BLOB_RE",
    "LIST_MARKERS",
    "_cloud_candidates",
    "test_cloud_storage",
    "JAVA_SER_B64",
    "test_deserialize_surface",
    "CI_WORKFLOW_PATHS",
    "test_ci_workflow",
]
