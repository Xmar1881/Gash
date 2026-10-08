"""GraphQL deep analysis — schema parsing + safe probing.

Introspection dumps are recon gold; this module turns them into
structure: query vs mutation fields, argument shapes, and minimal
read-only probes. Mutations are NEVER executed (state-changing) — only
their input surface is mapped. Nested object authorization reuses the
cross-session rule: the same canonical object for two users means the
object check is missing.

Pure functions (no network) except the tiny query sender, which stays
read-only (queries only, capped, benign selections).
"""

from __future__ import annotations

import json as _json

SENSITIVE_FIELDS = ("password", "passwd", "hash", "secret", "token",
                    "ssn", "social", "salary", "phone", "email",
                    "address", "credit", "card", "otp", "api_key",
                    "apikey", "private")

ID_ARG_NAMES = ("id", "ids", "uuid", "guid", "key", "slug", "userid",
                "user_id", "accountid", "account_id", "orderid",
                "order_id")


def _unwrap(named: dict | None) -> tuple[str, str]:
    """GraphQL type wrapper -> (kind, name). kind: OBJECT|SCALAR|..."""
    t = named or {}
    while isinstance(t, dict) and t.get("kind") in ("NON_NULL", "LIST"):
        t = t.get("ofType") or {}
    if not isinstance(t, dict):
        return "UNKNOWN", ""
    return str(t.get("kind", "UNKNOWN")), str(t.get("name", "") or "")


def parse_schema(schema: dict) -> dict:
    """Introspection __schema -> {queries, mutations, objects}.

    queries: [{name, args: [{name, required}], returns}].
    mutations: [{name, args: [{name, required}]}].
    objects: {TypeName: [scalar field names]} for selection building.
    Never raises; unknown shapes yield empties.
    """
    out = {"queries": [], "mutations": [], "objects": {}}
    try:
        types = schema.get("__schema", {}).get("types", []) or []
        qname = (schema.get("__schema", {}).get("queryType", {}) or {}
                 ).get("name", "Query")
        mname = (schema.get("__schema", {}).get("mutationType", {}) or {}
                 ).get("name", "Mutation")
    except Exception:
        return out
    by_name: dict = {}
    try:
        for t in types:
            if isinstance(t, dict) and t.get("name"):
                by_name[t["name"]] = t
    except Exception:
        return out

    def _fields(tname: str) -> list[dict]:
        t = by_name.get(tname) or {}
        fields = []
        for f in t.get("fields", []) or []:
            if not isinstance(f, dict) or not f.get("name"):
                continue
            args = []
            for a in f.get("args", []) or []:
                if not isinstance(a, dict) or not a.get("name"):
                    continue
                atype = a.get("type") or {}
                required = isinstance(atype, dict) and \
                    atype.get("kind") == "NON_NULL"
                args.append({"name": a["name"], "required": required})
            kind, ret = _unwrap(f.get("type"))
            fields.append({"name": f["name"], "args": args,
                           "returns": ret, "ret_kind": kind})
        return fields

    out["queries"] = _fields(qname)
    out["mutations"] = _fields(mname)
    for tname, t in by_name.items():
        if not isinstance(t, dict) or t.get("kind") != "OBJECT":
            continue
        if tname.startswith("__") or tname in (qname, mname):
            continue
        scalars = []
        for f in t.get("fields", []) or []:
            if not isinstance(f, dict):
                continue
            kind, _n = _unwrap(f.get("type"))
            if kind in ("SCALAR", "ENUM") and f.get("name"):
                scalars.append(f["name"])
        if scalars:
            out["objects"][tname] = scalars[:12]
    return out


def sensitive_queries(parsed: dict) -> list[dict]:
    """Query fields that smell sensitive — by name or by returned scalars."""
    out = []
    objects = parsed.get("objects", {}) or {}
    for q in parsed.get("queries", []):
        name = (q.get("name") or "").lower()
        if any(s in name for s in SENSITIVE_FIELDS):
            out.append(q)
            continue
        scalars = [s.lower() for s in objects.get(q.get("returns") or "", [])]
        if any(any(s in sc for s in SENSITIVE_FIELDS) for sc in scalars):
            out.append(q)
    return out


def build_selection(parsed: dict, field: dict,
                    max_scalars: int = 3) -> str | None:
    """Minimal read-only selection for a query field. None when unsafe.

    Only fields with NO required args (no guessing), scalar subfields
    only, capped. Returns e.g. '{ users { email name } }'.
    """
    try:
        if any(a.get("required") for a in field.get("args", []) or []):
            return None
        ret = field.get("returns") or ""
        scalars = list((parsed.get("objects", {}) or {}).get(ret, []))[:max_scalars]
        name = field.get("name") or ""
        if not name:
            return None
        if not scalars:
            return "{ %s }" % name
        return "{ %s { %s } }" % (name, " ".join(scalars))
    except Exception:
        return None


def id_arg(field: dict) -> dict | None:
    """First id-ish argument of a query field, if any."""
    for a in field.get("args", []) or []:
        if (a.get("name") or "").lower() in ID_ARG_NAMES:
            return a
    return None


def build_by_id_query(parsed: dict, field: dict,
                      value: str) -> str | None:
    """Selection addressing one object: { user(id: 1) { scalars } }."""
    arg = id_arg(field)
    name = field.get("name") or ""
    if arg is None or not name:
        return None
    try:
        scalars = list((parsed.get("objects", {}) or {}).get(
            field.get("returns") or "", []))[:3]
        if not scalars:
            return None
        safe = str(value)[:40].replace('"', "").replace("\\", "")
        return '{ %s(%s: "%s") { %s } }' % (name, arg.get("name"), safe,
                                           " ".join(scalars))
    except Exception:
        return None


def send_query(session, url: str, timeout: int, query: str,
               variables: dict | None = None):
    """POST one read-only query. Response or None (budget degrades)."""
    try:
        from core.net import pace
        pace()
    except Exception:
        return None
    try:
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        return session.post(url, timeout=timeout, json=payload)
    except Exception:
        return None


def response_data(resp) -> dict | None:
    """The data dict of a GraphQL response, or None (errors/empty)."""
    try:
        doc = _json.loads(getattr(resp, "text", "") or "")
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    data = doc.get("data")
    return data if isinstance(data, dict) else None


def has_sensitive_data(data: dict) -> str | None:
    """First sensitive key with a non-empty value found recursively."""
    from core.api_params import flatten_json
    try:
        leaves = flatten_json(data if isinstance(data, dict) else {})
    except Exception:
        return None
    for name, val in leaves:
        leaf = name.split(".")[-1].lower()
        if any(s in leaf for s in SENSITIVE_FIELDS) and val:
            return name
    return None


SENSITIVE_ARGS = ("role", "roles", "permissions", "admin", "isadmin",
                  "is_admin", "owner", "ownerid", "owner_id",
                  "internalid", "internal_id", "privileged", "root")


def schema_graph(parsed: dict, endpoint: str = "") -> dict:
    """Query/mutation/object graph with sensitive flags. Pure.

    Nodes carry kind+name+args; sensitive marks spread from field names
    and returned scalars. Consumers: verbose reports, IDOR id-args,
    contract review (nullable sensitive inputs).
    """
    sens_q = {q.get("name") for q in sensitive_queries(parsed)}
    queries = []
    for q in parsed.get("queries", []) or []:
        queries.append({
            "kind": "query", "name": q.get("name", ""),
            "args": [a.get("name", "") for a in q.get("args", []) or []],
            "returns": q.get("returns", ""),
            "sensitive": q.get("name") in sens_q,
            "has_id_arg": id_arg(q) is not None,
        })
    mutations = []
    for m in parsed.get("mutations", []) or []:
        args = [a.get("name", "") for a in m.get("args", []) or []]
        mutations.append({
            "kind": "mutation", "name": m.get("name", ""),
            "args": args,
            "sensitive": any(a.lower() in SENSITIVE_ARGS for a in args),
        })
    return {"endpoint": endpoint, "queries": queries,
            "mutations": mutations,
            "objects": {k: list(v)
                        for k, v in (parsed.get("objects", {}) or {}).items()},
            "sensitive": sorted(
                {q["name"] for q in queries if q["sensitive"]} |
                {m["name"] for m in mutations if m["sensitive"]})}


def weak_contracts(parsed: dict) -> list[dict]:
    """Mutations taking nullable sensitive args (static contract review).

    A nullable `role`/`permissions` input invites escalation: no request
    is sent (mutations never execute) — the schema alone is evidence.
    INFO surface for manual review, capped.
    """
    out: list[dict] = []
    for m in parsed.get("mutations", []) or []:
        for a in m.get("args", []) or []:
            name = (a.get("name") or "")
            if name.lower() in SENSITIVE_ARGS and not a.get("required"):
                out.append({"mutation": m.get("name", ""), "arg": name,
                            "issue": "nullable sensitive input"})
                break
        if len(out) >= 4:
            break
    return out
