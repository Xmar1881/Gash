"""Vulnerability scanning.

Covers SQLi (query params + form inputs, DB error signatures), reflected
XSS, upload-form hunting, and dir-brute with a built-in wordlist plus
robots.txt. GET-heavy, no destructive payloads. Detection is signature /
reflection / status based, with a soft-404 filter. ThreadPoolExecutor
keeps it fast.

Import hub: implementations live in core/scan/*.py; this module
re-exports every name so existing imports keep working.
"""
from __future__ import annotations

from core.scan._shared import (
    Finding, SQL_ERRORS, SQLI_PAYLOADS, DBMS_FINGERPRINTS, fingerprint_dbms,
    XSS_PAYLOAD, XSS_PROBES, ESCAPED_HINTS,
    HREF_RE, FORM_RE, ACTION_RE, METHOD_RE, INPUT_RE,
    ADMIN_HINT, FILE_INPUT_HINT, SENSITIVE_HINT,
)
from core.scan.http import (
    _session, _tls_session, _TLS_POOL, _calm_down, _mark_dead,
    _get, _post, _request, do_login, _fetch_base,
)
from core.scan.discovery import (
    TEXTAREA_RE, INPUT_TYPE_RE, INPUT_TYPE_RE2, UNFUZZABLE_TYPES,
    _forms, _method_re,
    discover_test_urls, _build_probe_pool, _inject, _post_form_targets,
)
from core.scan.injection import (
    _raw_reflected, _filter_map,
    test_sqli, _post_sqli,
    test_xss, _api_body_xss, _api_ct_retry, _post_xss,
    test_xss_errpage,
)
from core.scan.enumeration import (
    check_upload,
    _baseline_404, _looks_like_baseline, _secret_file_proof, _probe_dir,
    _verdict_dir,
    check_robots, dir_brute, smart_recurse,
)
from core.scan.engine import load_wordlist, run_scan
# Probe params, upload endpoints and dir-brute wordlists live in
# core/wordlists.py; re-exported here so existing imports keep working
# (the `as` form marks intentional re-exports for ruff F401).
from core.wordlists import (
    FUZZ_PARAMS, UPLOAD_PATHS,
    WL_GENERAL as WL_GENERAL, WL_WORDPRESS as WL_WORDPRESS,
    WL_PHP as WL_PHP, WL_NODE as WL_NODE, WL_JAVA as WL_JAVA,
    WL_PYTHON as WL_PYTHON, WL_API as WL_API,
    WL_BACKUP_SECRET as WL_BACKUP_SECRET, WL_TECHMAP as WL_TECHMAP,
    DIR_WORDLIST as DIR_WORDLIST,
    RECURSE_FILE_SUFFIX, RECURSE_DIR_EXTRA, RECURSE_DIR_MUTATIONS,
    RECURSE_DIR_FILE_EXT, wordlist_for_techs,
)

__all__ = [
    "Finding",
    "SQL_ERRORS", "SQLI_PAYLOADS", "DBMS_FINGERPRINTS", "fingerprint_dbms",
    "XSS_PAYLOAD", "XSS_PROBES", "ESCAPED_HINTS",
    "HREF_RE", "FORM_RE", "ACTION_RE", "METHOD_RE", "INPUT_RE",
    "ADMIN_HINT", "FILE_INPUT_HINT", "SENSITIVE_HINT",
    "_session", "_tls_session", "_TLS_POOL", "_calm_down", "_mark_dead",
    "_get", "_post", "_request", "do_login", "_fetch_base",
    "TEXTAREA_RE", "INPUT_TYPE_RE", "INPUT_TYPE_RE2", "UNFUZZABLE_TYPES",
    "_forms", "_method_re",
    "discover_test_urls", "_build_probe_pool", "_inject", "_post_form_targets",
    "_raw_reflected", "_filter_map",
    "test_sqli", "_post_sqli",
    "test_xss", "_api_body_xss", "_api_ct_retry", "_post_xss",
    "test_xss_errpage",
    "check_upload",
    "_baseline_404", "_looks_like_baseline", "_secret_file_proof", "_probe_dir",
    "_verdict_dir",
    "check_robots", "dir_brute", "smart_recurse",
    "load_wordlist", "run_scan",
    "FUZZ_PARAMS", "UPLOAD_PATHS",
    "WL_GENERAL", "WL_WORDPRESS", "WL_PHP", "WL_NODE", "WL_JAVA",
    "WL_PYTHON", "WL_API", "WL_BACKUP_SECRET", "WL_TECHMAP",
    "DIR_WORDLIST",
    "RECURSE_FILE_SUFFIX", "RECURSE_DIR_EXTRA", "RECURSE_DIR_MUTATIONS",
    "RECURSE_DIR_FILE_EXT", "wordlist_for_techs",
]
