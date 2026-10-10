"""XSS reflection context analysis — evidence ladder P0.

Separates *reflection* (marker echoes somewhere) from *breakout*
(the payload's breaker characters survive raw at the same spot).
Raw marker alone is NOT an XSS proof: filters often keep alphanumerics
while stripping/encoding ``< > " ' ` = ( )``.

Pure functions, no network. Safe for fake-session unit tests.
"""

from __future__ import annotations

import re
from html import escape as _html_escape
from html.parser import HTMLParser
from html import unescape as _html_unescape
from urllib.parse import unquote

# Same hints as scanner._raw_reflected: entity/unicode escapes nearby mean
# the echo went through an encoder.
ESCAPED_HINTS = ["&lt;", "&gt;", "&quot;", "&#039;", "&#x27;", "&#39;",
                 "\\u003c", "\\u003e", "\\x3c", "\\x3e"]

URL_ATTRS = frozenset({
    "href", "src", "action", "formaction", "xlink:href", "data",
    "background", "cite", "poster", "srcset", "icon", "manifest",
    "codebase", "usemap", "longdesc", "profile", "classid", "lowsrc",
})

_TAG_OPEN_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9-]*)[^>]*$", re.S)
_ATTR_ASSIGN_RE = re.compile(r"([a-zA-Z_:][\w:.-]*)\s*=\s*[\"']?$", re.S)


class _TokenParser(HTMLParser):
    """Small, non-executing HTML token collector for parser differentials."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.tokens: list[tuple] = []

    def handle_starttag(self, tag: str, attrs: list[tuple]) -> None:
        self.tokens.append(("start", tag.lower(), tuple(
            (str(k).lower(), "" if v is None else str(v))
            for k, v in attrs)))

    def handle_startendtag(self, tag: str, attrs: list[tuple]) -> None:
        self.tokens.append(("startend", tag.lower(), tuple(
            (str(k).lower(), "" if v is None else str(v))
            for k, v in attrs)))

    def handle_endtag(self, tag: str) -> None:
        self.tokens.append(("end", tag.lower()))

    def handle_data(self, data: str) -> None:
        self.tokens.append(("data", data))

    def handle_entityref(self, name: str) -> None:
        self.tokens.append(("entity", name))

    def handle_charref(self, name: str) -> None:
        self.tokens.append(("charref", name))

    def handle_comment(self, data: str) -> None:
        self.tokens.append(("comment", data))


def _html_tokens(value: str) -> list[tuple]:
    parser = _TokenParser()
    try:
        parser.feed((value or "")[:20000])
        parser.close()
    except Exception:
        # A malformed fragment is still useful as a passive observation; do
        # not turn parser disagreement into a scan failure.
        pass
    return parser.tokens


def _serialize_tokens(tokens: list[tuple]) -> str:
    """Serialize only parser tokens; never execute or evaluate their values."""
    out: list[str] = []
    for token in tokens:
        kind = token[0]
        if kind in {"start", "startend"}:
            tag, attrs = token[1], token[2]
            text = ["<", tag]
            for name, value in attrs:
                text += [" ", name, '="', _html_escape(value, quote=True), '"']
            text.append(" />" if kind == "startend" else ">")
            out.append("".join(text))
        elif kind == "end":
            out.append(f"</{token[1]}>")
        elif kind == "data":
            out.append(token[1])
        elif kind == "entity":
            out.append(f"&{token[1]};")
        elif kind == "charref":
            out.append(f"&#{token[1]};")
        elif kind == "comment":
            out.append(f"<!--{token[1]}-->")
    return "".join(out)


def double_parse_mutation(raw: str, sanitized: str,
                          marker: str = "") -> dict:
    """Compare a sanitized fragment across two passive HTML parses.

    This is a bounded parser-differential signal, not browser execution.  It
    reports a possible mutation only when a marker survives and an executable
    tag/attribute appears *after* the second parse while absent from the first
    token stream.  Callers must still require an explicit browser/OOB proof
    before raising a vulnerability severity.
    """
    first = _html_tokens(sanitized)
    normalized = _serialize_tokens(first)
    second = _html_tokens(normalized)
    dangerous_tags = {"script", "iframe", "object", "embed", "svg", "math"}
    dangerous_attrs = {"onload", "onerror", "onclick", "onfocus", "href",
                       "src", "srcdoc"}

    def dangerous(tokens: list[tuple]) -> bool:
        for token in tokens:
            if token[0] not in {"start", "startend"}:
                continue
            if token[1] in dangerous_tags or any(
                    name in dangerous_attrs for name, _ in token[2]):
                return True
        return False

    first_dangerous = dangerous(first)
    second_dangerous = dangerous(second)
    marker_low = (marker or "").lower()
    second_text = normalized.lower()
    marker_preserved = bool(marker_low and marker_low in second_text)
    structure_changed = first != second
    return {
        "changed": normalized != (sanitized or ""),
        "structure_changed": structure_changed,
        "dangerous_before": first_dangerous,
        "dangerous_after": second_dangerous,
        "marker_preserved": marker_preserved,
        "mutation_suspected": bool(marker_preserved and structure_changed
                                     and second_dangerous
                                     and not first_dangerous),
        "raw_was_dangerous": dangerous(_html_tokens(raw)),
    }


def decode_chain(value: str, max_rounds: int = 3) -> list[str]:
    """Return bounded URL/HTML-decoded variants for review, never execution."""
    out = [str(value or "")[:20000]]
    for _ in range(max(0, min(int(max_rounds), 3))):
        current = out[-1]
        decoded = _html_unescape(unquote(current))
        if decoded == current or decoded in out:
            break
        out.append(decoded[:20000])
    return out


def is_encoded_window(window_lower: str) -> bool:
    """True when the reflection window carries an escape trace."""
    return any(h in window_lower for h in ESCAPED_HINTS)


def _js_quote_state(snippet: str) -> str | None:
    """Which JS string quote is currently open (None = code position)."""
    quote: str | None = None
    escaped = False
    i = 0
    while i < len(snippet):
        ch = snippet[i]
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif quote is None and ch in ("'", '"', "`"):
            quote = ch
        elif quote is not None and ch == quote:
            # crude: count preceding backslashes instead of the flag above
            # (kept simple on purpose — heuristic, not a JS engine).
            bs = 0
            j = i - 1
            while j >= 0 and snippet[j] == "\\":
                bs += 1
                j -= 1
            if bs % 2 == 0:
                quote = None
        i += 1
    return quote


def detect_context(body: str, index: int, marker: str) -> dict:
    """Classify the reflection at ``index`` into a context dict.

    Returns ``{"context": str, "tag": str, "attr": str}``. Never raises.
    """
    try:
        before = body[max(0, index - 600):index]
        after = body[index + len(marker):index + len(marker) + 200]
    except Exception:
        return {"context": "html-text", "tag": "", "attr": ""}
    low_before = before.lower()

    # 1) HTML comment: last <!-- wins over last -->.
    if low_before.rfind("<!--") > low_before.rfind("-->"):
        return {"context": "html-comment", "tag": "", "attr": ""}

    # 2) <script> content vs <style> content.
    open_script = low_before.rfind("<script")
    close_script = low_before.rfind("</script")
    if open_script > close_script:
        tail = before[open_script:]
        if ">" in tail:  # past the opening tag -> JS content
            if re.search(r"<script\b[^>]*type\s*=\s*[\"']?"
                         r"(?:application/(?:json|ld\+json)|importmap)",
                         tail, re.I):
                return {"context": "json-script", "tag": "script", "attr": "type"}
            try:
                script_start = body.find(">", open_script) + 1
                script_end = low_before.find("</script")
                if script_start > 0 and script_end >= script_start:
                    from core.js_ast import context_at
                    ast = context_at(body[script_start:script_end],
                                     max(0, index - script_start))
                    if ast:
                        return {"context": ast["context"], "tag": "script",
                                "attr": "", "ast_node": ast["ast_node"],
                                "ast_backend": ast["backend"]}
            except Exception:
                pass
            q = _js_quote_state(before[-300:])
            if q == "'":
                ctx = "js-string-single"
            elif q == '"':
                ctx = "js-string-double"
            elif q == "`":
                ctx = "js-template-literal"
            else:
                # ${...} inside template vs plain expression
                ctx = ("js-template-expression"
                       if "${" in before[-80:] and "}" in after[:80]
                       else "js-expression")
            return {"context": ctx, "tag": "script", "attr": ""}
        # else: still inside <script src="..."> attributes -> fall through
    open_style = low_before.rfind("<style")
    close_style = low_before.rfind("</style")
    if open_style > close_style and ">" in before[open_style:]:
        return {"context": "style-css", "tag": "style", "attr": ""}

    # 3) Inside a tag (<...> not yet closed)?
    lt = before.rfind("<")
    gt = before.rfind(">")
    if lt != -1 and lt > gt:
        tag_chunk = before[lt:]
        m = _TAG_OPEN_RE.search(tag_chunk)
        tag = (m.group(1).lower() if m else "")
        # Find the attr whose quoted value currently wraps the marker:
        # last `name="...` with no closing quote yet -> double-quoted, etc.
        attr = ""
        ctx = "attr-unquoted"
        last_dq = None
        for mm in re.finditer(r"([a-zA-Z_:][\w:.-]*)\s*=\s*\"", tag_chunk):
            last_dq = mm
        last_sq = None
        for mm in re.finditer(r"([a-zA-Z_:][\w:.-]*)\s*=\s*'", tag_chunk):
            last_sq = mm
        # quotes after the opening decide if we already closed it
        if last_dq is not None:
            opened = tag_chunk[last_dq.end():]
            if '"' not in opened:
                attr, ctx = last_dq.group(1).lower(), "attr-double-quoted"
        if not attr and last_sq is not None:
            opened = tag_chunk[last_sq.end():]
            if "'" not in opened:
                attr, ctx = last_sq.group(1).lower(), "attr-single-quoted"
        if not attr:
            am = _ATTR_ASSIGN_RE.search(tag_chunk.rstrip())
            if am:
                # ends with name= (unquoted value start)
                attr, ctx = am.group(1).lower(), "attr-unquoted"
            else:
                # <div MARKER> / stray text or JS-in-attr like onclick="do(...
                # -> recover the attr name from `name="...` prefix, if any.
                pre = re.search(r"([a-zA-Z_:][\w:.-]*)\s*=\s*[\"'][^\"']*$",
                                tag_chunk)
                if pre:
                    attr = pre.group(1).lower()
                    # quote type from the opening char
                    ctx = ("attr-double-quoted"
                           if '="' in pre.group(0) else "attr-single-quoted")
                else:
                    attr, ctx = "", "attr-unquoted"
        if attr == "style":
            ctx = "style-attribute"
        elif attr.startswith("on"):
            ctx = "event-handler"
        elif attr in URL_ATTRS:
            ctx = "url-attr"
        if tag == "svg" and ctx.startswith("attr"):
            return {"context": "svg-" + ctx, "tag": tag, "attr": attr}
        return {"context": ctx, "tag": tag, "attr": attr}

    # 4) JSON string value (API responses).
    stripped_body = (body or "").lstrip()[:1]
    if stripped_body in ("{", "["):
        pre = before[-1:] if before else ""
        post = after[:1] if after else ""
        if pre == '"' and post == '"':
            return {"context": "json-string", "tag": "", "attr": ""}

    # 5) SVG text content (outside tag attrs but inside <svg>).
    if "<svg" in low_before:
        last_svg = low_before.rfind("<svg")
        if low_before.rfind("</svg") < last_svg:
            return {"context": "svg-text", "tag": "svg", "attr": ""}

    return {"context": "html-text", "tag": "", "attr": ""}


def find_marker_contexts(body: str | None, marker: str) -> list[dict]:
    """Every (case-insensitive) marker hit with context + encoded flag."""
    if not body or not marker or marker.lower() not in (body or "").lower():
        return []
    low = body.lower()
    m = marker.lower()
    out: list[dict] = []
    start = 0
    while True:
        i = low.find(m, start)
        if i == -1:
            break
        window = low[max(0, i - 120):i + len(m) + 120]
        encoded = is_encoded_window(window)
        info = detect_context(body, i, marker)
        info.update({"index": i, "encoded": encoded})
        out.append(info)
        start = i + len(m)
        if len(out) >= 20:  # cap: huge pages, same marker everywhere
            break
    return out


def _breaker_fragments(payload: str, marker: str) -> list[str]:
    """Payload chunks around the marker that prove filter behavior."""
    if not payload or marker not in payload:
        return []
    parts = payload.split(marker)
    frags: list[str] = []
    for p in parts:
        p = p.strip()
        if len(p) >= 2:
            # head/tail slices are enough; full payload compare is brittle
            frags.append(p[:25])
            if len(p) > 25:
                frags.append(p[-25:])
    # most telling chars first (breakers), deduped, longest first
    uniq = list(dict.fromkeys(f for f in frags if f))
    uniq.sort(key=lambda s: (
        0 if any(c in s for c in "<>\"'`") else 1, -len(s)))
    return uniq[:4]


def breaker_present(body: str, index: int, marker: str,
                    payload: str | None) -> bool:
    """Do the payload's breaker chars survive raw next to this hit?"""
    if not payload or marker not in payload:
        return False
    low = (body or "").lower()
    window = low[max(0, index - 40):index + len(marker) + 60]
    for frag in _breaker_fragments(payload, marker):
        if frag.lower() in window:
            return True
    return False


def classify_reflection(body: str | None, marker: str,
                        payload: str | None = None) -> dict:
    """Strongest evidence for this marker across all hits.

    status: none | encoded | raw-unconfirmed | breakout
    """
    hits = find_marker_contexts(body, marker)
    if not hits:
        return {"status": "none", "context": "", "tag": "",
                "attr": "", "encoded": False, "evidence": "",
                "contexts": []}
    contexts = [h["context"] for h in hits]
    raws = [h for h in hits if not h["encoded"]]
    if not raws:
        h = hits[0]
        return {"status": "encoded", "context": h["context"],
                "tag": h["tag"], "attr": h["attr"], "encoded": True,
                "evidence": f"context={h['context']} encoded reflection",
                "contexts": contexts}
    if payload:
        for h in raws:
            if breaker_present(body or "", h["index"], marker, payload):
                after = (body or "")[h["index"] + len(marker):
                                     h["index"] + len(marker) + 40]
                return {"status": "breakout", "context": h["context"],
                        "tag": h["tag"], "attr": h["attr"],
                        "encoded": False,
                        "evidence": (f"context={h['context']} "
                                     f"breaker={after.strip()[:40]!r}"),
                        "contexts": contexts}
    h = raws[0]
    return {"status": "raw-unconfirmed", "context": h["context"],
            "tag": h["tag"], "attr": h["attr"], "encoded": False,
            "evidence": (f"context={h['context']} marker raw, "
                         "breaker not observed"),
            "contexts": contexts}
