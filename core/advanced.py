"""Advanced checks: blind SQLi, SSTI, SSRF, IDOR, stored XSS, upload bypass.

Active POST probes only run with --deep and always use harmless content.
Blind XSS stays silent unless --blind-callback points at your listener.

Import hub: implementations live in core/deep/*.py; this module
re-exports every name so existing imports keep working.
"""
from __future__ import annotations

# Form helpers moved to core.scan.discovery (single owner, breaks the
# scan<->deep import cycle); re-exported here for compatibility
# (core.checks.* does `from core.advanced import _forms`).
from core.scan.discovery import (
    TEXTAREA_RE as TEXTAREA_RE,
    INPUT_TYPE_RE as INPUT_TYPE_RE,
    INPUT_TYPE_RE2 as INPUT_TYPE_RE2,
    UNFUZZABLE_TYPES as UNFUZZABLE_TYPES,
    _forms as _forms,
    _method_re as _method_re,
)
from core.deep._shared import (
    encoded_variants, _bodies_differ, _param_names,
    BOOLEAN_PAIRS, TIME_PAYLOADS, TIME_SLEEP,
    NOSQLI_OP_PAIRS, NOSQLI_JSON_TRUE, NOSQLI_JSON_FALSE, NOSQLI_ERR,
    SSTI_PAIR, SSTI_BUNDLES,
    SSRF_KEYS, SSRF_META_URL, SSRF_MARKERS, AWS_AMI_ID_RE,
    AZURE_META_URL, AZURE_MARKERS, GCP_META_URL,
    IDOR_RE, IDOR_PARAM_RE, PP_PAYLOADS,
    UPLOAD_BYPASS_NAMES, UPLOAD_OK_HINT, UPLOAD_BLOCK_HINT,
    SMART_PATHS, TECH_MARKERS,
    LOGIN_PAYLOADS, LOGIN_OK, LOGIN_INPUT_RE, LOGIN_INPUT_RE2,
    LOGIN_USER_HINTS, LOGIN_PASS_HINTS,
    _login_fields, _scrub_hidden,
    LDAP_BYPASS_USERS, WAF_SIGNS,
    UPLOAD_JSON_FIELDS, _UPLOAD_URL_HINT,
)
from core.deep.sqli import (
    test_sqli_blind, test_sqli_login, test_login_enum, test_ldap_injection,
)
from core.deep.server import (
    test_ssti, test_ssrf, test_idor, _cross_session_confirm,
    test_proto_pollution, test_idor_param, test_authz_matrix,
    _nosqli_morph, test_nosqli,
    test_xxe, XXE_MARKERS, _xxe_payloads, _xxe_targets,
)
from core.deep.stored import (
    test_stored_xss,
    discover_json_uploads, _upload_ok,
    _json_upload_probes, _upload_mismatch_probe, _upload_filename_probe,
    test_upload_rce,
)
from core.deep.surface import (
    detect_waf, test_waf_detect, test_cookie_flags,
    smart_tech_paths, smart_tech,
)

__all__ = [
    "TEXTAREA_RE", "INPUT_TYPE_RE", "INPUT_TYPE_RE2", "UNFUZZABLE_TYPES",
    "_forms", "_method_re",
    "encoded_variants", "_bodies_differ", "_param_names",
    "BOOLEAN_PAIRS", "TIME_PAYLOADS", "TIME_SLEEP",
    "NOSQLI_OP_PAIRS", "NOSQLI_JSON_TRUE", "NOSQLI_JSON_FALSE", "NOSQLI_ERR",
    "SSTI_PAIR", "SSTI_BUNDLES",
    "SSRF_KEYS", "SSRF_META_URL", "SSRF_MARKERS", "AWS_AMI_ID_RE",
    "AZURE_META_URL", "AZURE_MARKERS", "GCP_META_URL",
    "IDOR_RE", "IDOR_PARAM_RE", "PP_PAYLOADS",
    "UPLOAD_BYPASS_NAMES", "UPLOAD_OK_HINT", "UPLOAD_BLOCK_HINT",
    "SMART_PATHS", "TECH_MARKERS",
    "LOGIN_PAYLOADS", "LOGIN_OK", "LOGIN_INPUT_RE", "LOGIN_INPUT_RE2",
    "LOGIN_USER_HINTS", "LOGIN_PASS_HINTS",
    "_login_fields", "_scrub_hidden",
    "LDAP_BYPASS_USERS", "WAF_SIGNS",
    "UPLOAD_JSON_FIELDS", "_UPLOAD_URL_HINT",
    "test_sqli_blind", "test_sqli_login", "test_login_enum", "test_ldap_injection",
    "test_ssti", "test_ssrf", "test_idor", "_cross_session_confirm",
    "test_proto_pollution", "test_idor_param", "test_authz_matrix",
    "_nosqli_morph", "test_nosqli",
    "test_xxe", "XXE_MARKERS", "_xxe_payloads", "_xxe_targets",
    "test_stored_xss",
    "discover_json_uploads", "_upload_ok",
    "_json_upload_probes", "_upload_mismatch_probe", "_upload_filename_probe",
    "test_upload_rce",
    "detect_waf", "test_waf_detect", "test_cookie_flags",
    "smart_tech_paths", "smart_tech",
]
