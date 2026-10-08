"""IDOR/BOLA + authorization-matrix engine — pure, no network.

Object references live in path segments, query values, JSON bodies and
(headers such as X-User-Id), as numeric IDs, UUIDs/GUIDs or slugs. Only
*enumerable* refs (numeric) get a sibling (N+1); unguessable refs
(UUID/GUID/slug) are tested by direct access instead — nobody can
enumerate them, but the server must still refuse the wrong session.

Cross-session proof is canonical-JSON-first (keys, values, ownership
fields, identity) with the legacy length rule as the HTML fallback, so
old numeric outcomes do not drift. Response classification
(denied/login-redirect/ok/...) feeds the authorization matrix.
"""

from __future__ import annotations

import hashlib
import json as _json
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlparse

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
GUID_RE = re.compile(
    r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
INT_RE = re.compile(r"^\d{1,8}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,60}$", re.I)

# Query names that mark an integer value as an object reference.
ID_NAME_RE = re.compile(r"(^id$|_id$|^user_?id$|uuid|guid$)", re.I)
# Slug-ish values are only refs when the name looks identifier-like.
SLUG_NAME_RE = re.compile(r"(id|slug|uuid|guid|user|account|order)$", re.I)

# Segment names that are never object refs (routes, files, actions).
NON_REF_SEGMENTS = frozenset({
    "api", "v1", "v2", "admin", "login", "logout", "search", "static",
    "assets", "graphql", "query", "profile", "settings", "docs",
    "posts", "post", "blog", "files", "pages", "users", "orders",
    "items",
})

OWNER_KEYS = ("userid", "user_id", "owner", "ownerid", "owner_id",
              "accountid", "account_id", "email", "username")
LOGIN_MARKERS = ("password", "sign in", "log in", "giriş", "login")


@dataclass(frozen=True)
class ObjectRef:
    kind: str      # int|uuid|guid|slug
    location: str  # path|query|json|header
    name: str      # segment index / param / field / header name
    value: str


def classify_value(value: str) -> str | None:
    """int|uuid|guid|slug for identifier-looking values, else None."""
    v = (value or "").strip()
    if not v:
        return None
    if INT_RE.match(v):
        return "int"
    if UUID_RE.match(v):
        return "uuid"
    if GUID_RE.match(v):
        return "guid"
    if SLUG_RE.match(v) and re.search(r"[a-z]", v, re.I) \
            and not v.lower().endswith((".html", ".php", ".js", ".png")):
        return "slug"
    return None


def extract_refs_from_url(url: str) -> list[ObjectRef]:
    """Path segments + query values that look like object references."""
    out: list[ObjectRef] = []
    try:
        p = urlparse(url or "")
    except Exception:
        return out
    for i, seg in enumerate([s for s in (p.path or "").split("/") if s]):
        if seg.lower() in NON_REF_SEGMENTS:
            continue
        kind = classify_value(seg)
        if kind in ("int", "uuid", "guid"):
            out.append(ObjectRef(kind, "path", str(i), seg))
        elif kind == "slug" and i > 0:
            out.append(ObjectRef(kind, "path", str(i), seg))
    try:
        qsl = parse_qsl(p.query, keep_blank_values=True)
    except Exception:
        qsl = []
    for k, v in qsl:
        kind = classify_value(v)
        if kind == "int" and ID_NAME_RE.search(k or ""):
            out.append(ObjectRef(kind, "query", k, v))
        elif kind == "uuid":
            # any UUID-typed query value is an object reference
            out.append(ObjectRef(kind, "query", k, v))
        elif kind == "slug" and SLUG_NAME_RE.search(k or ""):
            out.append(ObjectRef(kind, "query", k, v))
    return out


def extract_refs_from_json(obj, url: str = "") -> list[ObjectRef]:
    """Nested identifier fields (user.id, items[0].sku …)."""
    from core.api_params import flatten_json
    out: list[ObjectRef] = []
    try:
        leaves = flatten_json(obj if isinstance(obj, (dict, list)) else {})
    except Exception:
        return out
    for name, val in leaves:
        kind = classify_value(val)
        if kind is None:
            continue
        leaf = name.split(".")[-1].lower().strip("[]0123456789")
        if kind == "int" and not ID_NAME_RE.search(leaf or ""):
            continue
        if kind == "slug" and not SLUG_NAME_RE.search(leaf or ""):
            continue
        out.append(ObjectRef(kind, "json", name, val))
        if len(out) >= 10:
            break
    return out


def sibling_value(ref: ObjectRef) -> str | None:
    """N+1 for numerics. UUID/GUID/slug are unguessable -> None."""
    if ref.kind == "int":
        try:
            return str(int(ref.value) + 1)
        except Exception:
            return None
    return None


def sibling_url(url: str, ref: ObjectRef) -> str | None:
    """Same URL with the ref replaced by its sibling. None if unguessable."""
    sib = sibling_value(ref)
    if sib is None:
        return None
    try:
        from urllib.parse import urlencode, urlunparse
        p = urlparse(url)
        if ref.location == "path":
            segs = [s for s in p.path.split("/") if s]
            idx = int(ref.name)
            if idx >= len(segs):
                return None
            raw = [s for s in p.path.split("/")]
            seen = -1
            for j, s in enumerate(raw):
                if s:
                    seen += 1
                    if seen == idx:
                        raw[j] = sib
                        break
            return urlunparse((p.scheme, p.netloc, "/".join(raw),
                               p.params, p.query, p.fragment))
        qsl = parse_qsl(p.query, keep_blank_values=True)
        hit = False
        out_q = []
        for k, v in qsl:
            if not hit and k == ref.name and v == ref.value:
                out_q.append((k, sib))
                hit = True
            else:
                out_q.append((k, v))
        if not hit:
            return None
        return urlunparse((p.scheme, p.netloc, p.path, p.params,
                           urlencode(out_q), p.fragment))
    except Exception:
        return None


def normalized_hash(body: str | None) -> str:
    """sha256 over whitespace-collapsed body — object identity signal."""
    text = re.sub(r"\s+", " ", body or "").strip()
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:16]


def extract_ownership(body: str | None) -> dict:
    """owner-ish fields from JSON bodies ({userId: …}). {} when absent."""
    try:
        obj = _json.loads(body or "")
    except Exception:
        return {}
    if not isinstance(obj, dict):
        return {}
    from core.api_params import flatten_json
    owners: dict = {}
    for name, val in flatten_json(obj):
        leaf = name.split(".")[-1].lower()
        if leaf in OWNER_KEYS and val:
            owners[name] = val[:80]
    return owners


def canonical_same(a_body: str | None, b_body: str | None) -> bool | None:
    """Canonical-JSON equality, or None when either side is not JSON."""
    from core.diff import canonical_json
    ja, jb = canonical_json(a_body or ""), canonical_json(b_body or "")
    if ja is None or jb is None:
        return None
    return ja == jb


def same_object(a_body: str | None, b_body: str | None) -> bool:
    """Does session B see the same object as session A?

    Canonical JSON first (keys/values/ownership exact); legacy
    length rule as the HTML fallback (keeps numeric outcomes stable).
    """
    eq = canonical_same(a_body, b_body)
    if eq is not None:
        return eq
    la, lb = len(a_body or ""), len(b_body or "")
    if max(la, lb) == 0:
        return False
    return abs(la - lb) <= max(30, lb // 5)


def classify_auth_response(status: int, body: str | None,
                           final_url: str = "") -> str:
    """denied | login-redirect | ok | notfound | error | other."""
    try:
        code = int(status or 0)
    except Exception:
        code = 0
    low = (body or "")[:2000].lower()
    if code in (401, 403):
        return "denied"
    if code in (301, 302, 303, 307, 308) and \
            any(m in (final_url or "").lower() for m in ("login", "signin")):
        return "login-redirect"
    if code == 404:
        return "notfound"
    if code >= 500 or code == 0:
        return "error"
    if code == 200:
        if any(m in low for m in LOGIN_MARKERS):
            return "login-redirect"  # 200 but a login form: not inside
        return "ok"
    return "other"


def matrix_rows(endpoint: str, cells: dict) -> list[dict]:
    """Authorization verdicts for one endpoint from classified cells.

    cells: {"anonymous": cls, "user": cls, "user_b": cls}.
    A second user's *same-content* read is decided by the caller via
    same_object(), not here.
    """
    rows: list[dict] = []
    anon, user = cells.get("anonymous"), cells.get("user")
    sensitive = bool(re.search(r"/(api|admin|dashboard|manage|account|order)",
                              endpoint, re.I))
    if anon == "ok" and sensitive:
        rows.append({"endpoint": endpoint, "issue": "anonymous-access",
                     "detail": "sensitive endpoint answers 200 without a "
                               "session (no login gate)"})
    if anon == "ok" and user == "ok" and sensitive:
        rows.append({"endpoint": endpoint, "issue": "no-auth-gap",
                     "detail": "anonymous and authenticated sessions see "
                               "the same protected surface"})
    return rows
