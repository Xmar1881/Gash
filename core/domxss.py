"""DOM XSS verification with a headless browser (opt-in --dom).

Sources are probed in stages: page load (query/fragment), postMessage,
storage (plant + reload) and referrer navigation. Each stage attributes
newly-reached sinks to its source, so findings read as source -> sink
chains with a raw/filtered-or-text transform note.

Sinks hooked: innerHTML/outerHTML, insertAdjacentHTML,
createContextualFragment, document.write/writeln, eval/Function/
setTimeout-string, setAttribute event/URL attrs, jQuery html/append,
location.assign/replace, window.open, iframe src/srcdoc, script src,
document.domain. A marker in a sink is NOT auto-confirmed: the sample
must carry executable markup/code (else: suspected, LOW).
alert/confirm/prompt are wrapped into __gash_fired plus dialog/console
listeners, so execution counts even under a CSP that blocks inline
scripts. A marker in the rendered DOM (but not raw HTML) without any
sink is an INFO note. Confirmed stages stop the probe early (budget).

Skipped quietly without Playwright (prints the install hint instead).
Slow (~4-9s/page with all stages), so it only runs with --dom.
"""

from __future__ import annotations

import re

from core.colors import info, warn
from core.registry import check as register_check

DOM_MARKER = "gxdom"
DOM_QUERY_PAYLOAD = DOM_MARKER + '"><img src=x onerror="alert(\'gxdom\')">'
DOM_FRAG_PAYLOAD = DOM_MARKER + '"><svg onload=alert(\'gxdom\')>'

# Tagged into every marker-carrying dispatch we evaluate ourselves, so
# note() can tell our scaffolding apart from genuine page data flow.
DISPATCH_TAG = "/*__gash_dispatch*/"

# Per-source canaries (all carry DOM_MARKER so hooks catch them).
PM_PAYLOAD = DOM_MARKER + '-pm"><svg onload=alert(1)>'
STORAGE_KEY = "gashdom"
STORAGE_PAYLOAD = DOM_MARKER + "-st"
REFERRER_URL = f"https://gash.test/?r={DOM_MARKER}-ref"

SRC_LOAD = "location.search/fragment"
SRC_POSTMESSAGE = "postMessage"
SRC_STORAGE = "localStorage/sessionStorage"
SRC_REFERRER = "document.referrer"


def _snapshot(page):
    """(sinks, samples, fired) — each read degrades to empty, never raises."""
    try:
        sinks = page.evaluate("() => (window.__gash_sinks || []).slice(0, 8)")
    except Exception:
        sinks = []
    try:
        samples = page.evaluate("() => (window.__gash_sink_samples || {})")
    except Exception:
        samples = {}
    try:
        fired = page.evaluate("() => (window.__gash_fired || []).slice(0, 3)")
    except Exception:
        fired = []
    return (sinks or [], samples or {}, fired or [])


def _transform_note(sample: str) -> str:
    """raw = executable characters survived; else filtered-or-text."""
    s = sample or ""
    if EXEC_MARKUP_RE.search(s) or (";" in s and "(" in s):
        return "raw"
    return "filtered-or-text"

# Sink taxonomy (DOM Invader ranking, GASH subset). Code sinks execute
# strings; HTML sinks need executable markup in the sample; attribute
# sinks depend on the attribute (event/js-url vs plain).
CODE_SINKS = {"eval", "Function", "setTimeout", "setInterval"}
HTML_SINKS = {"innerHTML", "outerHTML", "insertAdjacentHTML",
              "createContextualFragment", "document.write",
              "document.writeln", "jQuery.html", "jQuery.append",
              "srcdoc"}
NAV_SINKS = {"location", "location.href", "location.assign",
             "location.replace", "window.open"}
SRC_SINKS = {"src", "iframe.src", "script.src", "script.text"}
EVENT_ATTRS = ("on",)  # prefix match: onclick, onload, ...
URL_ATTRS = {"src", "href", "data", "action", "formaction", "srcdoc"}

EXEC_MARKUP_RE = re.compile(
    r"<(svg|img|script|iframe|details|body|video|audio|input|button"
    r"|select|textarea|object|embed|form)\b|on\w+\s*=|javascript\s*:",
    re.I)


def classify_sink(sink: str, sample: str,
                  marker: str = DOM_MARKER) -> dict:
    """One hooked sink -> confirmed | suspected | safe (pure, no browser).

    Sink reaching alone is never enough: HTML sinks need executable
    markup/code around the marker, code sinks need the marker in the
    executed string, attribute sinks need an event/js-url attribute.
    """
    s = (sample or "")
    if not sink or marker not in s:
        return {"verdict": "safe", "reason": "marker not in sink sample"}
    name = (sink or "").strip()
    if name in CODE_SINKS:
        return {"verdict": "confirmed",
                "reason": f"marker in code sink ({name})"}
    if name in HTML_SINKS:
        if EXEC_MARKUP_RE.search(s):
            return {"verdict": "confirmed",
                    "reason": f"executable markup in {name}"}
        return {"verdict": "suspected",
                "reason": f"marker in {name} as text (no executable markup)"}
    if name.startswith("setAttribute:"):
        attr = name.split(":", 1)[1].lower()
        if attr.startswith("on"):
            return {"verdict": "confirmed",
                    "reason": f"event-handler attribute ({attr})"}
        if attr in URL_ATTRS:
            if re.search(r"javascript\s*:", s, re.I):
                return {"verdict": "confirmed",
                        "reason": f"js-url in {attr}"}
            return {"verdict": "suspected",
                    "reason": f"marker in {attr} (no js-url scheme)"}
        return {"verdict": "suspected",
                "reason": f"marker in attribute ({attr})"}
    if name in ("location", "location.href") or name in NAV_SINKS:
        if re.search(r"javascript\s*:", s, re.I):
            return {"verdict": "confirmed",
                    "reason": "js-url navigated"}
        return {"verdict": "suspected",
                "reason": f"marker in {name} (navigation, not script exec)"}
    if name in SRC_SINKS:
        if re.search(r"javascript\s*:|data\s*:\s*text/html", s, re.I):
            return {"verdict": "confirmed",
                    "reason": f"active content URL in {name}"}
        return {"verdict": "suspected",
                "reason": f"marker in {name} (resource URL, load unproven)"}
    if name == "domain":
        return {"verdict": "suspected",
                "reason": "document.domain relaxes SOP; verify cross-"
                          "subdomain impact manually"}
    return {"verdict": "suspected",
            "reason": f"marker in {name} (unclassified sink)"}

# Injected before page scripts run (CDP-level, so page CSP can't block
# it). Records any marker-carrying value assigned to dangerous sinks plus
# alert/confirm/prompt executions (execution oracle, dialog-independent).
# IIFE on purpose: a bare arrow function would merely be defined, never
# run, leaving every hook silently uninstalled.
SINK_HOOK_JS = """
(() => {
  window.__gash_sinks = [];
  window.__gash_sink_samples = {};
  window.__gash_fired = [];
  const MARK = 'gxdom';
  const note = (sink, v) => {
    try {
      const s = String(v == null ? '' : v).slice(0, 300);
      if (s.indexOf(MARK) === -1) return;
      // our own probe dispatches travel through the same sinks
      // (page.evaluate source carries the canary): anything quoting
      // our scaffolding is the scanner echoing itself, not page flow.
      if (s.indexOf('__gash_') !== -1) return;
        window.__gash_sinks.push(sink);
        if (!window.__gash_sink_samples[sink]) window.__gash_sink_samples[sink] = s;
    } catch (e) {}
  };
  const hookProp = (proto, prop) => {
    try {
      const desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || typeof desc.set !== 'function') return;
      const orig = desc.set;
      Object.defineProperty(proto, prop, {
        set(v) { note(prop, v); return orig.call(this, v); },
        get: desc.get, configurable: true
      });
    } catch (e) {}
  };
  const hookMethod = (proto, name, idx) => {
    try {
      const orig = proto[name];
      if (typeof orig !== 'function') return;
      proto[name] = function() {
        try { note(name, arguments[idx]); } catch (e) {}
        return orig.apply(this, arguments);
      };
    } catch (e) {}
  };
  const fire = (fn, msg) => {
    try { window.__gash_fired.push(String(msg).slice(0, 120)); } catch (e) {}
  };
  try {
    const _a = window.alert;
    window.alert = function(m) { fire(0, m); try { return _a(m); } catch (e) {} };
    const _c = window.confirm;
    window.confirm = function(m) { fire(0, m); try { return _c(m); } catch (e) { return false; } };
    const _p = window.prompt;
    window.prompt = function(m, d) { fire(0, m); try { return _p(m, d); } catch (e) { return null; } };
  } catch (e) {}
  try {
    hookProp(Element.prototype, 'innerHTML');
    hookProp(Element.prototype, 'outerHTML');
    if (typeof ShadowRoot !== 'undefined') hookProp(ShadowRoot.prototype, 'innerHTML');
    hookMethod(Element.prototype, 'insertAdjacentHTML', 1);
    if (typeof Range !== 'undefined') hookMethod(Range.prototype, 'createContextualFragment', 0);
    const _w = Document.prototype.write;
    Document.prototype.write = function() {
      for (const a of arguments) note('document.write', a);
      return _w.apply(this, arguments);
    };
    const _wn = Document.prototype.writeln;
    Document.prototype.writeln = function() {
      for (const a of arguments) note('document.writeln', a);
      return _wn.apply(this, arguments);
    };
    const _ev = window.eval;
    window.eval = function(x) { note('eval', x); return _ev(x); };
    try {
      const _F = window.Function;
      window.Function = function() {
        try { note('Function', Array.prototype.join.call(arguments, ' ')); } catch (e) {}
        return _F.apply(this, arguments);
      };
    } catch (e) {}
    try {
      const _st = window.setTimeout;
      window.setTimeout = function(a, b) {
        if (typeof a === 'string') note('setTimeout', a);
        return _st.apply(this, arguments);
      };
      const _si = window.setInterval;
      window.setInterval = function(a, b) {
        if (typeof a === 'string') note('setInterval', a);
        return _si.apply(this, arguments);
      };
    } catch (e) {}
    try {
      const _sa = Element.prototype.setAttribute;
      Element.prototype.setAttribute = function(n, v) {
        try {
          const ln = String(n).toLowerCase();
          if (ln.indexOf('on') === 0 || ln === 'src' || ln === 'href' ||
              ln === 'data' || ln === 'action' || ln === 'formaction' ||
              ln === 'srcdoc') note('setAttribute:' + ln, v);
        } catch (e) {}
        return _sa.apply(this, arguments);
      };
    } catch (e) {}
    try {
      if (window.jQuery && window.jQuery.fn) {
        const _h = window.jQuery.fn.html;
        if (typeof _h === 'function') window.jQuery.fn.html = function(v) {
          if (v !== undefined) note('jQuery.html', v);
          return _h.apply(this, arguments);
        };
        const _ap = window.jQuery.fn.append;
        if (typeof _ap === 'function') window.jQuery.fn.append = function(v) {
          note('jQuery.append', v);
          return _ap.apply(this, arguments);
        };
      }
    } catch (e) {}
    try {
      const _assign = Location.prototype.assign;
      Location.prototype.assign = function(u) {
        try { note('location.assign', u); } catch (e) {}
        return _assign.call(this, u);
      };
      const _replace = Location.prototype.replace;
      Location.prototype.replace = function(u) {
        try { note('location.replace', u); } catch (e) {}
        return _replace.call(this, u);
      };
      const _open = window.open;
      window.open = function(u, n, s) {
        try { if (typeof u === 'string') note('window.open', u); } catch (e) {}
        return _open.apply(this, arguments);
      };
    } catch (e) {}
    try {
      if (typeof HTMLIFrameElement !== 'undefined') {
        hookProp(HTMLIFrameElement.prototype, 'src');
        hookProp(HTMLIFrameElement.prototype, 'srcdoc');
      }
      if (typeof HTMLScriptElement !== 'undefined') {
        hookProp(HTMLScriptElement.prototype, 'src');
      }
      hookProp(Document.prototype, 'domain');
    } catch (e) {}
  } catch (e) {}
})();
"""


def _targets(urls: list[str], limit: int = 6) -> list[str]:
    out = []
    for u in urls[:limit]:
        out.append(u)
        base = u.split("#")[0]
        sep = "&" if "?" in base else "?"
        out.append(f"{base}{sep}gxdomq={DOM_QUERY_PAYLOAD}#{DOM_FRAG_PAYLOAD}")
    return list(dict.fromkeys(out))[: limit * 2]


@register_check("dom-xss", "DOM XSS headless sinks+sources+oracle (--dom)", order=12)
def test_dom_xss(urls: list[str], base: str, timeout: int,
                  verbose: bool = False, pages: dict | None = None,
                  dom: bool = False) -> list:
    if not dom:
        return []
    try:
        import importlib.util
        if importlib.util.find_spec("playwright.sync_api") is None:
            raise ImportError
    except ImportError:
        print(warn("  [!] --dom needs Playwright: py -m pip install playwright; "
                   "py -m playwright install chromium"))
        return []
    try:
        return _run(urls, base, timeout, verbose, pages or {})
    except Exception as e:
        msg = str(e)[:150]
        if "Executable doesn't exist" in msg or "browser" in msg.lower():
            print(warn("  [!] No Chromium: py -m playwright install chromium"))
        elif verbose:
            print(warn(f"  [!] dom-xss error: {msg}"))
        return []


def _run(urls, base, timeout, verbose, pages) -> list:
    from playwright.sync_api import sync_playwright
    out = []
    targets = _targets(urls)
    if verbose:
        print(info(f"  [*] DOM scan: {len(targets)} targets (headless)..."))
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            for t in targets:
                hit = _probe_page(browser, t, base, timeout, pages, verbose)
                if hit:
                    out.append(hit)
        finally:
            browser.close()
    return out


def _probe_page(browser, url: str, base: str, timeout: int,
                pages: dict, verbose: bool = False):
    from core.scanner import Finding
    fired: list[str] = []
    console: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()
    suspected: list[str] = []
    page = browser.new_page(ignore_https_errors=True)
    try:
        page.on("dialog", lambda d: (fired.append(d.message), d.dismiss()))

        def _on_console(m):
            try:
                text = m.text if not callable(getattr(m, "text", None)) else m.text()
            except Exception:
                try:
                    text = str(m)
                except Exception:
                    return
            if DOM_MARKER in (text or ""):
                console.append((text or "")[:150])

        def _on_error(e):
            try:
                text = str(e)
            except Exception:
                return
            if DOM_MARKER in text:
                errors.append(text[:150])

        for ev, cb in (("console", _on_console), ("pageerror", _on_error)):
            try:
                page.on(ev, cb)
            except Exception:
                pass
        try:
            page.add_init_script(SINK_HOOK_JS)
        except Exception:
            pass

        def _check_stage(source: str):
            """Alert or sink verdict for one source stage. Returns Finding/None."""
            sinks, samples, alerted = _snapshot(page)
            if any(DOM_MARKER in m for m in fired) or \
                    any(DOM_MARKER in m for m in (alerted or [])):
                if verbose:
                    from core.colors import warn as _w
                    print(_w(f"    [!] DOM XSS (confirmed via {source}): {url}"))
                return Finding(
                    title="DOM XSS (confirmed — alert fired)",
                    severity="CRITICAL",
                    url=url.split("#")[0],
                    detail=f"Headless browser caught script execution via "
                           f"{source} (alert/confirm/prompt with our marker)",
                    evidence=DOM_MARKER,
                    confidence="High",
                    method="GET", location="fragment", confirm="browser",)
            fresh = [s for s in dict.fromkeys(sinks) if s not in seen]
            for s in fresh:
                seen.add(s)
                try:
                    sample = str((samples or {}).get(s, ""))
                except Exception:
                    sample = ""
                verdict = classify_sink(s, sample)
                chain = (f"{source} -> {s} "
                         f"({_transform_note(sample)}; {verdict['reason']}; "
                         f"sample: {sample[:100]})")
                if verdict["verdict"] == "confirmed":
                    if verbose:
                        from core.colors import warn as _w
                        print(_w(f"    [!] DOM XSS (executable {s} via "
                                 f"{source}): {url}"))
                    extra = ""
                    if console:
                        extra = f" console echoed ({len(console)}x)"
                    return Finding(
                        title="DOM XSS (confirmed — executable sink)",
                        severity="CRITICAL",
                        url=url.split("#")[0],
                        detail=f"Marker flows {chain}{extra}",
                        evidence=DOM_MARKER,
                        confidence="High",
                        method="GET", location="fragment",
                        confirm="browser",)
                if verdict["verdict"] == "suspected":
                    suspected.append(chain)
            return None

        ms = (timeout + 10) * 1000
        page.goto(url, timeout=ms, wait_until="domcontentloaded")
        page.wait_for_timeout(2500)
        hit = _check_stage(SRC_LOAD)
        if hit:
            return hit
        # postMessage: canary as string + object; new sinks are attributed.
        # (Self-echo is filtered inside note(): our dispatch source quotes
        # __gash_ scaffolding, genuine page flows never do.)
        try:
            page.evaluate(
                DISPATCH_TAG + "() => { try { window.postMessage('"
                + PM_PAYLOAD + "', '*');"
                " window.postMessage({gash:'" + PM_PAYLOAD + "'}, '*'); }"
                " catch(e) {} }")
            page.wait_for_timeout(1200)
            hit = _check_stage(SRC_POSTMESSAGE)
            if hit:
                return hit
        except Exception:
            pass
        # storage: plant then reload so boot code reads it back.
        try:
            page.evaluate(
                DISPATCH_TAG + "() => { try { localStorage.setItem('"
                + STORAGE_KEY + "', '" + STORAGE_PAYLOAD
                + "'); sessionStorage.setItem('" + STORAGE_KEY + "', '"
                + STORAGE_PAYLOAD + "'); }"
                " catch(e) {} }")
            page.reload(wait_until="domcontentloaded")
            page.wait_for_timeout(2500)
            hit = _check_stage(SRC_STORAGE)
            if hit:
                return hit
        except Exception:
            pass
        # referrer: same URL entered from a marker-carrying page.
        try:
            page.goto(url, timeout=ms, wait_until="domcontentloaded",
                      referer=REFERRER_URL)
            page.wait_for_timeout(2500)
            hit = _check_stage(SRC_REFERRER)
            if hit:
                return hit
        except Exception:
            pass
        if suspected:
            if verbose:
                from core.colors import warn as _w
                print(_w(f"    [-] DOM sinks (need manual PoC): {url}"))
            return Finding(
                title="DOM XSS (suspected — controllable sink)",
                severity="LOW",
                url=url.split("#")[0],
                detail="Marker reaches sink(s) but no executable content "
                       "observed (" + "; ".join(suspected[:3]) + "); craft "
                       "a context PoC manually",
                evidence=DOM_MARKER,
                confidence="Medium",)
        # no dialog: marker in rendered DOM but missing from raw HTML means JS wrote it
        try:
            dom_html = page.content()
        except Exception:
            return None
        from urllib.parse import urlparse as _up
        raw = (pages or {}).get(url.split("#")[0], "")
        if not raw:
            for k, v in (pages or {}).items():
                if _up(k).path == _up(url).path:
                    raw = v
                    break
        if DOM_MARKER in dom_html and DOM_MARKER not in (raw or ""):
            if verbose:
                from core.colors import warn as _w
                print(_w(f"    [!] DOM write (JS): {url}"))
            return Finding(
                title="JS DOM write (review manually)", severity="INFO",
                url=url.split("#")[0],
                detail="Marker is in the rendered DOM but not in the raw HTML; "
                       "review JS sinks (innerHTML/eval) manually",
                evidence=DOM_MARKER,
                confidence="Low",)
    except Exception:
        return None
    finally:
        try:
            page.close()
        except Exception:
            pass
    return None
