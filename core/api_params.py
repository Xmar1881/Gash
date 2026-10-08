"""API/body parameter engine — recursive extraction + safe mutation.

URLs are not the only input: JSON bodies (nested), urlencoded forms, XML,
GraphQL variables, headers and path params are each modeled as separate
test targets with dotted names (user.id, user.role, items[0].sku).

Safety contract (madde 2): structure-preserving leaf replacement only —
no key injection, no array growth, no multipart assembly. State-changing
methods (POST/PUT/PATCH/DELETE) and header/path mutations probe ONLY in
deep mode; safe mode may look but never mutates.

Pure functions (no network) — the scanner wires them to HTTP.
"""

from __future__ import annotations

import json as _json
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlparse

MAX_LEAVES = 40
MAX_DEPTH = 5

# Methods that may change server state -> active probing is deep-only.
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

# Locations whose mutation is active probing (deep-only).
ACTIVE_LOCATIONS = {"json", "form", "xml", "graphql", "header", "path"}


@dataclass
class ApiParam:
    """One testable leaf: dotted name, location, sample value."""
    name: str
    location: str  # query|path|json|form|xml|graphql|header
    value: str = ""


@dataclass
class ApiTarget:
    """One endpoint + method + content shape to probe."""
    url: str
    method: str = "POST"
    content_type: str = "application/json"
    params: list[ApiParam] = field(default_factory=list)
    # raw template body (JSON/form/XML) for structure-preserving rebuilds
    template: str = ""


def flatten_json(obj, prefix: str = "", depth: int = 0,
                 out: list | None = None) -> list[tuple[str, str]]:
    """Nested JSON -> [(dotted, scalar)] e.g. user.role. Capped."""
    if out is None:
        out = []
    if depth > MAX_DEPTH or len(out) >= MAX_LEAVES:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            if len(out) >= MAX_LEAVES:
                break
            flatten_json(v, f"{prefix}.{k}" if prefix else str(k),
                         depth + 1, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:5]):
            if len(out) >= MAX_LEAVES:
                break
            flatten_json(v, f"{prefix}[{i}]", depth + 1, out)
    elif obj is None or isinstance(obj, (str, int, float, bool)):
        out.append((prefix, "" if obj is None else str(obj)))
    return out


def _set_path(obj, parts: list, payload: str):
    """Copy-on-write set of one EXISTING leaf. Returns (new_obj, ok).

    Missing keys/indices are never created (no key injection — the shape
    of the request stays byte-identical apart from the one value).
    """
    import copy
    if not parts:
        return payload, True
    try:
        new = copy.deepcopy(obj)
    except Exception:
        return obj, False
    cur = new
    try:
        for p in parts[:-1]:
            if isinstance(cur, dict):
                if p not in cur:
                    return obj, False
                cur = cur[p]
            elif isinstance(cur, list):
                m = re.fullmatch(r"\[(\d+)\]", p)
                if not m or int(m.group(1)) >= len(cur):
                    return obj, False
                cur = cur[int(m.group(1))]
            else:
                return obj, False
        last = parts[-1]
        if isinstance(cur, dict):
            if last not in cur:
                return obj, False
            cur[last] = payload
        elif isinstance(cur, list):
            m = re.fullmatch(r"\[(\d+)\]", last)
            if not m or int(m.group(1)) >= len(cur):
                return obj, False
            cur[int(m.group(1))] = payload
        else:
            return obj, False
    except Exception:
        return obj, False
    return new, True


def split_dotted(name: str) -> list[str]:
    """user.items[0].sku -> [user, items, [0], sku]."""
    parts: list[str] = []
    for chunk in (name or "").split("."):
        m = re.match(r"^([^\[]+)((?:\[\d+\])*)$", chunk)
        if not m:
            parts.append(chunk)
            continue
        if m.group(1):
            parts.append(m.group(1))
        parts += re.findall(r"\[\d+\]", m.group(2))
    return [p for p in parts if p]


def mutate_json_body(template: str, dotted: str, payload: str) -> str | None:
    """Rebuild the JSON template with one leaf replaced. None on failure."""
    try:
        obj = _json.loads(template or "{}")
    except Exception:
        return None
    new, ok = _set_path(obj, split_dotted(dotted), payload)
    if not ok:
        return None
    try:
        return _json.dumps(new)
    except Exception:
        return None


_XML_TAG_RE = re.compile(r"<([a-zA-Z_][\w.-]*)\s*>([^<>]{0,200})</\1\s*>")
_XML_TAG_OPEN = re.compile(r"<([a-zA-Z_][\w.-]*)(\s[^>]*)?>")


def extract_xml_params(body: str) -> list[ApiParam]:
    """Leaf elements <name>value</name> -> params (first occurrence each)."""
    out: list[ApiParam] = []
    seen: set[str] = set()
    for tag, val in _XML_TAG_RE.findall(body or ""):
        if tag.lower() in seen or len(out) >= MAX_LEAVES:
            continue
        seen.add(tag.lower())
        out.append(ApiParam(name=tag, location="xml",
                            value=(val or "").strip()[:100]))
    return out


def mutate_xml_body(template: str, tag: str, payload: str) -> str | None:
    """Replace the first <tag>...</tag> content. None when absent."""
    try:
        rx = re.compile(r"(<" + re.escape(tag) + r"(?:\s[^>]*)?>).*?(</"
                        + re.escape(tag) + r"\s*>)", re.S)
    except Exception:
        return None
    new, n = rx.subn(lambda m: m.group(1) + payload + m.group(2),
                     template or "", count=1)
    return new if n else None


def extract_graphql_params(query: str, variables: str | None = None) -> list[ApiParam]:
    """$variables of a GraphQL operation (+ operation name as context)."""
    out: list[ApiParam] = []
    if variables:
        try:
            obj = _json.loads(variables)
        except Exception:
            obj = None
        if isinstance(obj, dict):
            for name, val in flatten_json(obj):
                out.append(ApiParam(name=name, location="graphql",
                                    value=val[:100]))
                if len(out) >= MAX_LEAVES:
                    return out
    # bare literals inside the query text are second-class targets
    for lit in re.findall(r'"([^"]{1,60})"', query or ""):
        if len(out) >= MAX_LEAVES:
            break
        out.append(ApiParam(name=f"literal:{lit[:30]}", location="graphql",
                            value=lit[:100]))
    return out


def extract_request_params(url: str = "", headers: dict | None = None,
                           content_type: str = "",
                           body: str | None = None) -> list[ApiParam]:
    """All inputs of one request, by location. Pure, capped."""
    out: list[ApiParam] = []
    try:
        qsl = parse_qsl(urlparse(url or "").query, keep_blank_values=True)
        for k, v in qsl[:20]:
            out.append(ApiParam(name=k, location="query", value=v[:100]))
    except Exception:
        pass
    for hk, hv in (headers or {}).items():
        lk = str(hk).lower()
        if lk in ("x-forwarded-host", "referer", "origin", "x-api-key",
                  "authorization", "content-type", "accept"):
            out.append(ApiParam(name=str(hk), location="header",
                                value=str(hv)[:100]))
    ct = (content_type or "").lower()
    if body:
        if "json" in ct:
            try:
                obj = _json.loads(body)
            except Exception:
                obj = None
            if isinstance(obj, dict):
                for name, val in flatten_json(obj):
                    out.append(ApiParam(name=name, location="json",
                                        value=val[:100]))
        elif "urlencoded" in ct or "form-data" in ct:
            try:
                for k, v in parse_qsl(body, keep_blank_values=True)[:20]:
                    out.append(ApiParam(name=k, location="form",
                                        value=v[:100]))
            except Exception:
                pass
        elif "xml" in ct:
            out += extract_xml_params(body)
        elif "graphql" in ct:
            try:
                doc = _json.loads(body)
                out += extract_graphql_params(
                    doc.get("query", "") if isinstance(doc, dict) else "",
                    _json.dumps(doc.get("variables"))
                    if isinstance(doc, dict) and doc.get("variables")
                    else None)
            except Exception:
                out += extract_graphql_params(body)
    return out[:MAX_LEAVES]


def allowed_in_safe_mode(method: str, location: str) -> bool:
    """Safe mode mutates nothing state-changing and no body/header/path."""
    if (method or "GET").upper() in STATE_CHANGING:
        return False
    return location not in ACTIVE_LOCATIONS


def _schema_props(schema: dict | None) -> list[str]:
    """JSON-schema object -> flattened property paths (one level + nested)."""
    if not isinstance(schema, dict):
        return []
    props = schema.get("properties") or {}
    if not isinstance(props, dict):
        return []
    out: list[str] = []
    for name, sub in props.items():
        out.append(str(name))
        if isinstance(sub, dict) and (sub.get("type") == "object"):
            for sub_name in _schema_props(sub):
                out.append(f"{name}.{sub_name}")
                if len(out) >= MAX_LEAVES:
                    break
        if len(out) >= MAX_LEAVES:
            break
    return out


def swagger_api_targets(spec: dict, base: str,
                        limit: int = 20) -> list[ApiTarget]:
    """OpenAPI spec -> probe-able targets (methods + params + bodies).

    Query/path/header parameters plus JSON requestBody properties become
    dotted ApiParams. GET stays GET; POST/PUT/PATCH/DELETE keep their
    method (deep-only at probe time).
    """
    out: list[ApiTarget] = []
    try:
        paths = spec.get("paths", {}) or {}
    except Exception:
        return out
    from core.discovery import concretize_rest_path
    for raw_path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        concrete, _rest = concretize_rest_path(str(raw_path))
        from urllib.parse import urljoin
        url = urljoin(base + "/", concrete.lstrip("/"))
        for method, op in ops.items():
            if method.lower() not in ("get", "post", "put", "patch",
                                      "delete"):
                continue
            if not isinstance(op, dict):
                continue
            params: list[ApiParam] = []
            for p in op.get("parameters", []) or []:
                if not isinstance(p, dict):
                    continue
                name = str(p.get("name", ""))
                pin = str(p.get("in", "query")).lower()
                if not name or pin not in ("query", "path", "header"):
                    continue
                params.append(ApiParam(name=name, location=pin))
                if len(params) >= MAX_LEAVES:
                    break
            body = (op.get("requestBody") or {}).get("content", {}) or {}
            template = ""
            ctype = "application/json"
            for mt in ("application/json", "application/x-www-form-urlencoded",
                       "application/xml", "multipart/form-data"):
                if mt in body and isinstance(body[mt], dict):
                    ctype = mt
                    schema = body[mt].get("schema") or {}
                    loc = ("json" if "json" in mt else
                           "form" if "form" in mt else "xml")
                    props = _schema_props(schema)
                    if loc == "json":
                        # leaves only: "user" is skipped when "user.role"
                        # exists (replacing an object with a string would
                        # change the shape, not just a value).
                        props = [p for p in props
                                 if not any(q != p and q.startswith(p + ".")
                                            for q in props)]
                    for prop in props:
                        params.append(ApiParam(name=prop, location=loc))
                    if loc == "json":
                        empt = {}
                        for prop in props:
                            cur = empt
                            *pre, last = prop.split(".")
                            for part in pre:
                                cur = cur.setdefault(part, {})
                            cur[last] = "1"
                        try:
                            template = _json.dumps(empt)
                        except Exception:
                            template = ""
                    break
            if params:
                out.append(ApiTarget(url=url, method=method.upper(),
                                     content_type=ctype,
                                     params=params[:20], template=template))
            if len(out) >= limit:
                return out
    return out
