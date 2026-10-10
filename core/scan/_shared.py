"""Scan shared model: Finding + signatures + regexes (no I/O, no checks)."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Finding:
    title: str
    severity: str  # CRITICAL | MEDIUM | LOW
    detail: str = ""
    url: str = ""
    evidence: str = ""
    confidence: str = ""  # High | Medium | Low — how sure the check is
    cwe: str = ""
    owasp: str = ""
    cvss: str = ""
    remediation: str = ""
    # request/confirmation context (populated by producers when known)
    method: str = ""       # GET|POST|PUT|PATCH|DELETE…
    param: str = ""        # injected parameter / field name
    location: str = ""     # query|path|header|body|fragment
    auth_context: str = ""  # anonymous|user|user-b|…
    fingerprint: str = ""  # normalized response fingerprint (truncated)
    confirm: str = ""      # how it was confirmed: breakout|browser|oob|…
    check: str = ""        # producing check name (stamped by registry)
    triage: dict | None = None  # structured XSS two-pass result
    evidence_meta: dict | None = None  # source/sink/AST evidence metadata
    vulnerability_finding: dict | None = None  # public XSS evidence contract

    def to_dict(self) -> dict:
        # keep reports small: evidence 300, detail 2000 chars.
        # URLs always live in `url`, never inside `detail`.
        # Secrets are never written in full: masked at the source.
        detail = self.detail or ""
        return {"title": self.title, "severity": self.severity,
                "detail": detail[:2000], "url": self.url,
                "evidence": (self.evidence or "")[:300],
                "confidence": self.confidence,
                "cwe": self.cwe, "owasp": self.owasp, "cvss": self.cvss,
                "remediation": self.remediation,
                "method": self.method[:12], "param": self.param[:80],
                "location": self.location[:12],
                "auth_context": self.auth_context[:24],
                "fingerprint": self.fingerprint[:120],
                "confirm": self.confirm[:40], "check": self.check[:40],
                "triage": self.triage or {},
                "evidence_meta": self.evidence_meta or {},
                "vulnerability_finding": self.vulnerability_finding or {}}


# SQL error signatures (matched lowercase)
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql", "mysqli_fetch", "mysql_fetch_array",
    "unclosed quotation mark", "quoted string not properly terminated",
    "ora-01756", "ora-00933", "oracle error",
    "pg_query()", "postgresql", "psql:",
    "sqlite3", "sqlite error",
    "odbc sql", "jdbc", "sqlstate",
    "supplied argument is not a valid mysql",
]

SQLI_PAYLOADS = ["'", '"', "' OR '1'='1"]

# Which database produced this error? First match wins; unknown stays honest.
DBMS_FINGERPRINTS = [
    ("MySQL/MariaDB", ["you have an error in your sql syntax",
                        "warning: mysql", "mysqli_", "mysql_fetch"]),
    ("PostgreSQL", ["pg_query()", "postgresql", "psql:", "pg_exec",
                     "unterminated quoted"]),
    ("MSSQL", ["unclosed quotation mark",
               "quoted string not properly terminated", "sql server",
               "odbc sql server", "80040e"]),
    ("Oracle", ["ora-", "oracle error", "pls-"]),
    ("SQLite", ["sqlite3", "sqlite error"]),
]


def fingerprint_dbms(hit: str) -> str:
    """Map a matched error signature to a backend name, or 'Unknown'."""
    low = (hit or "").lower()
    for name, marks in DBMS_FINGERPRINTS:
        if any(m in low for m in marks):
            return name
    return "Unknown"


XSS_PAYLOAD = 'gashxss"><svg onload=alert(1)>'

# Context-aware probe set: (context, marker, payload). First hit wins.
XSS_PROBES = [
    ("html-attr", "gx1", 'gx1"><svg onload=alert(1)>'),
    ("attr-js", "gx2", 'gx2"autofocus/onfocus=alert(1)>\'-alert(1)-'),
    ("tag-break", "gx3", "gx3</title><svg onload=alert(1)>"),
]

# Marker cevresi bunlari iceriyorsa echo encode'lanmis demektir -> FP'yi ele
ESCAPED_HINTS = ["&lt;", "&gt;", "&quot;", "&#039;", "&#x27;", "&#39;",
                 "\\u003c", "\\u003e", "\\x3c", "\\x3e"]

HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)
FORM_RE = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.S)
ACTION_RE = re.compile(r'action=["\']([^"\']*)["\']', re.I)
METHOD_RE = re.compile(r'method=["\']([^"\']*)["\']', re.I)
INPUT_RE = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.I)

ADMIN_HINT = re.compile(r'admin|dashboard|giriş|login|wp-|panel|phpmyadmin', re.I)
FILE_INPUT_HINT = re.compile(r'type\s*=\s*["\']?file["\']?', re.I)
# Paths that look sensitive (MEDIUM). Ordinary pages (contact/about) stay INFO.
# NOTE: no generic words like test/dev (so innocent paths like /latest
# don't get flagged MEDIUM). api/db are kept narrow (word-boundaried).
SENSITIVE_HINT = re.compile(
    r"config|backup|\bapi\b|\bdb\b|\bsql\b|env|\.git|debug|console|manager|"
    r"actuator|web-inf|swagger|graphql|upload|private|secret|token|\bauth\b|"
    r"wp-|shell|phpinfo|server-status|health|metrics|bak|old",
    re.I)


__all__ = [
    "Finding",
    "SQL_ERRORS", "SQLI_PAYLOADS", "DBMS_FINGERPRINTS", "fingerprint_dbms",
    "XSS_PAYLOAD", "XSS_PROBES", "ESCAPED_HINTS",
    "HREF_RE", "FORM_RE", "ACTION_RE", "METHOD_RE", "INPUT_RE",
    "ADMIN_HINT", "FILE_INPUT_HINT", "SENSITIVE_HINT",
]
