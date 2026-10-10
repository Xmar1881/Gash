"""Deterministic two-pass XSS triage.

This is intentionally local and evidence-first.  It does not call a model,
store page content, or turn a severity label into proof.  Pass one extracts
context and execution signals; pass two applies the proof policy and emits
the stable JSON contract used by reports and future AI adapters.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any


XSS_TRIAGE_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "XSSVulnerabilityTriageResult",
    "type": "object",
    "properties": {
        "finding_id": {"type": "string"},
        "is_vulnerable": {"type": "boolean"},
        "confidence_score": {"type": "number", "minimum": 0.0,
                              "maximum": 1.0},
        "vulnerability_type": {"type": "string", "enum": [
            "Reflected_XSS", "Stored_XSS", "DOM_XSS", "Mutation_XSS",
            "CSTI", "False_Positive"]},
        "execution_context": {"type": "string", "enum": [
            "HTML_Text", "HTML_Attribute", "JS_Literal", "JS_Block",
            "URL_Attribute", "CSS_Context"]},
        "bypass_reasoning": {"type": "string"},
        "remediation_advice": {"type": "string"},
    },
    "required": ["finding_id", "is_vulnerable", "confidence_score",
                  "vulnerability_type", "execution_context",
                  "bypass_reasoning"],
}

# Public, machine-readable contract for the XSS/DOM evidence layer.  It is
# intentionally separate from the legacy triage object above so existing
# report consumers remain compatible while new consumers get one stable
# finding shape.
VULNERABILITY_FINDING_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "VulnerabilityFinding",
    "type": "object",
    "properties": {
        "finding_id": {"type": "string"},
        "target_url": {"type": "string"},
        "parameter": {"type": "string"},
        "is_vulnerable": {"type": "boolean"},
        "vulnerability_type": {"type": "string", "enum": [
            "Reflected_XSS", "DOM_XSS", "Mutation_XSS", "CSTI",
            "False_Positive"]},
        "execution_context": {"type": "string"},
        "evidence": {"type": "object", "properties": {
            "source_used": {"type": "string"},
            "sink_triggered": {"type": "string"},
            "ast_node_type": {"type": "string"},
            "raw_payload": {"type": "string"},
        }},
        "remediation": {"type": "string"},
    },
    "required": ["finding_id", "target_url", "is_vulnerable",
                  "vulnerability_type", "execution_context", "evidence"],
}

_CONTEXTS = set(XSS_TRIAGE_SCHEMA["properties"]["execution_context"]["enum"])
_TYPES = set(XSS_TRIAGE_SCHEMA["properties"]["vulnerability_type"]["enum"])
_CONTRACT_TYPES = set(
    VULNERABILITY_FINDING_SCHEMA["properties"]["vulnerability_type"]["enum"])

_CONTEXT_RE = re.compile(
    r"(?:context\s*[=:]\s*|in\s+['\"])([a-z][a-z0-9_-]*)",
    re.I,
)


def _context(raw: str, location: str = "") -> str:
    """Map the richer internal context names to the public six-value enum."""
    value = (raw or "").lower().replace(" ", "-")
    if "css" in value or "style" in value:
        return "CSS_Context"
    if "url" in value or value in {"href", "src", "url-attr"}:
        return "URL_Attribute"
    if value.startswith("js-string") or "template-literal" in value \
            or value in {"json-script", "json-string"}:
        return "JS_Literal"
    if value.startswith("js-") or "event-handler" in value:
        return "JS_Block"
    if value.startswith("attr") or "attribute" in value:
        return "HTML_Attribute"
    if location == "fragment" and not value:
        return "HTML_Text"
    return "HTML_Text"


def _finding_id(finding: Any) -> str:
    material = "|".join(str(getattr(finding, k, "") or "")
                         for k in ("check", "title", "url", "param",
                                   "evidence", "confirm"))
    return "xss-" + hashlib.sha256(material.encode("utf-8", "replace"))\
        .hexdigest()[:16]


def _extract_context(finding: Any) -> str:
    title = str(getattr(finding, "title", "") or "").lower()
    detail = str(getattr(finding, "detail", "") or "")
    match = _CONTEXT_RE.search(detail)
    raw = match.group(1) if match else ""
    if not raw and "dom xss" in title:
        return "JS_Block"
    return _context(raw, str(getattr(finding, "location", "") or ""))


def triage_pass_one(finding: Any) -> dict[str, Any]:
    """Extract signals without deciding vulnerability status."""
    title = str(getattr(finding, "title", "") or "")
    detail = str(getattr(finding, "detail", "") or "")
    evidence = str(getattr(finding, "evidence", "") or "")
    confirm = str(getattr(finding, "confirm", "") or "").lower()
    blob = f"{title} {detail} {evidence}".lower()
    explicit_execution = confirm in {"breakout", "browser", "oob",
                                     "execution", "browser-mxss"}
    explicit_execution |= any(x in blob for x in (
        "alert fired", "executable sink", "script execution",
        "confirmed via oob", "mutation xss", "mxss"))
    unconfirmed = any(x in blob for x in (
        "unconfirmed", "suspected", "review manually", "not proven",
        "filtered-or-text", "encoded reflection"))
    if unconfirmed:
        explicit_execution = False
    if "csti" in blob or "client-side template injection" in blob:
        kind = "CSTI"
    elif "mutation xss" in blob or "mxss" in blob:
        kind = "Mutation_XSS"
    elif "dom xss" in blob or "dom-xss" in blob:
        kind = "DOM_XSS"
    elif ("stored xss" in blob or "stored reflection" in blob
          or "blind xss" in blob):
        kind = "Stored_XSS"
    elif "xss" in blob or "reflection" in blob:
        kind = "Reflected_XSS"
    else:
        kind = "False_Positive"
    return {
        "title": title,
        "detail": detail,
        "confirm": confirm,
        "context": _extract_context(finding),
        "candidate_type": kind,
        "execution_proof": bool(explicit_execution),
        "unconfirmed": bool(unconfirmed),
        "confidence": str(getattr(finding, "confidence", "") or "").lower(),
    }


def validate_result(result: dict[str, Any]) -> dict[str, Any]:
    """Validate and return a schema-shaped result; raise on contract drift."""
    if not isinstance(result, dict):
        raise ValueError("XSS triage result must be an object")
    for key in XSS_TRIAGE_SCHEMA["required"]:
        if key not in result:
            raise ValueError(f"XSS triage result missing {key}")
    if not isinstance(result["finding_id"], str):
        raise ValueError("finding_id must be a string")
    if not isinstance(result["is_vulnerable"], bool):
        raise ValueError("is_vulnerable must be boolean")
    score = result["confidence_score"]
    if isinstance(score, bool) or not isinstance(score, (int, float)) \
            or not 0.0 <= float(score) <= 1.0:
        raise ValueError("confidence_score must be between 0 and 1")
    if result["vulnerability_type"] not in _TYPES:
        raise ValueError("invalid vulnerability_type")
    if result["execution_context"] not in _CONTEXTS:
        raise ValueError("invalid execution_context")
    for key in ("bypass_reasoning", "remediation_advice"):
        if not isinstance(result[key], str):
            raise ValueError(f"{key} must be a string")
    return result


def validate_vulnerability_finding(result: dict[str, Any]) -> dict[str, Any]:
    """Validate the public VulnerabilityFinding contract without dependencies."""
    if not isinstance(result, dict):
        raise ValueError("VulnerabilityFinding must be an object")
    for key in VULNERABILITY_FINDING_SCHEMA["required"]:
        if key not in result:
            raise ValueError(f"VulnerabilityFinding missing {key}")
    for key in ("finding_id", "target_url", "parameter", "execution_context"):
        if not isinstance(result.get(key, ""), str):
            raise ValueError(f"{key} must be a string")
    if not isinstance(result["is_vulnerable"], bool):
        raise ValueError("is_vulnerable must be boolean")
    if result["vulnerability_type"] not in _CONTRACT_TYPES:
        raise ValueError("invalid vulnerability_type")
    evidence = result["evidence"]
    if not isinstance(evidence, dict):
        raise ValueError("evidence must be an object")
    for key in ("source_used", "sink_triggered", "ast_node_type", "raw_payload"):
        if key in evidence and not isinstance(evidence[key], str):
            raise ValueError(f"evidence.{key} must be a string")
    return result


def triage_pass_two(finding: Any, signals: dict[str, Any]) -> dict[str, Any]:
    """Apply the proof policy and emit the exact public result contract."""
    vulnerable = bool(signals["execution_proof"] and
                      not signals["unconfirmed"])
    kind = signals["candidate_type"] if vulnerable else "False_Positive"
    if kind not in _TYPES:
        kind = "False_Positive"
    confidence = signals["confidence"]
    if vulnerable:
        score = {"high": 0.95, "medium": 0.82, "low": 0.65}.get(
            confidence, 0.70)
        reason = ("Pass 1 found a context-aware XSS signal; pass 2 found "
                  "an execution proof via "
                  f"{signals['confirm'] or 'evidence'}.")
    else:
        score = 0.92 if signals["unconfirmed"] else 0.78
        reason = ("Pass 1 found reflection or a sink surface, but pass 2 "
                  "found no reliable executable proof; classified as "
                  "False_Positive for triage purposes.")
    remediation = str(getattr(finding, "remediation", "") or "")
    if not remediation:
        remediation = ("Encode output for its actual context, use a safe "
                       "allowlist sanitizer, and enforce CSP/Trusted Types.")
    result = {
        "finding_id": _finding_id(finding),
        "is_vulnerable": vulnerable,
        "confidence_score": round(score, 2),
        "vulnerability_type": kind,
        "execution_context": signals["context"],
        "bypass_reasoning": reason,
        "remediation_advice": remediation[:2000],
    }
    return validate_result(result)


def triage_finding(finding: Any) -> dict[str, Any]:
    """Run both local passes for one Finding."""
    return triage_pass_two(finding, triage_pass_one(finding))


def _ast_node_type(signals: dict[str, Any], sink: str) -> str:
    if sink in {"eval", "Function", "setTimeout", "setInterval"}:
        return "CallExpression"
    if signals.get("context") in {"JS_Literal", "JS_Block"}:
        return "LiteralOrExpression"
    if sink:
        return "HTMLFragment"
    return "Unknown"


def vulnerability_finding(finding: Any,
                          triage: dict[str, Any] | None = None) -> dict[str, Any]:
    """Adapt one local triage result to the requested public contract."""
    signals = triage_pass_one(finding)
    triage = triage or triage_pass_two(finding, signals)
    kind = triage.get("vulnerability_type", "False_Positive")
    # The requested contract intentionally has no Stored_XSS member.  Keep
    # the legacy type in ``triage`` and expose stored callback results as the
    # response-level reflected family in this narrower contract.
    if kind == "Stored_XSS":
        kind = "Reflected_XSS"
    if kind not in _CONTRACT_TYPES:
        kind = "False_Positive"
    meta = getattr(finding, "evidence_meta", None) or {}
    detail = str(getattr(finding, "detail", "") or "")
    chain = re.search(r"(?:flows|marker reaches)\s+([^\s]+)\s*->\s*([^\s]+)",
                      detail, re.I)
    source = str(meta.get("source_used") or (chain.group(1) if chain else "")
                 or getattr(finding, "location", "") or "unknown")
    sink = str(meta.get("sink_triggered") or (chain.group(2) if chain else "")
               or (getattr(finding, "confirm", "") if
                   getattr(finding, "confirm", "") == "browser" else ""))
    evidence = {
        "source_used": source[:120],
        "sink_triggered": sink[:120],
        "ast_node_type": str(meta.get("ast_node_type") or
                              _ast_node_type(signals, sink))[:80],
        "raw_payload": str(meta.get("raw_payload") or
                            getattr(finding, "evidence", "") or "")[:300],
    }
    result = {
        "finding_id": triage["finding_id"],
        "target_url": str(getattr(finding, "url", "") or ""),
        "parameter": str(getattr(finding, "param", "") or ""),
        "is_vulnerable": bool(triage["is_vulnerable"]),
        "vulnerability_type": kind,
        "execution_context": triage["execution_context"],
        "evidence": evidence,
        "remediation": str(getattr(finding, "remediation", "") or
                            triage.get("remediation_advice", ""))[:2000],
    }
    return validate_vulnerability_finding(result)


__all__ = ["XSS_TRIAGE_SCHEMA", "VULNERABILITY_FINDING_SCHEMA",
           "triage_pass_one", "triage_pass_two", "triage_finding",
           "validate_result", "validate_vulnerability_finding",
           "vulnerability_finding"]
