"""DOM XSS verification with a headless browser (opt-in --dom).

How it works: the URL gets DOM payloads in query + fragment, a headless
Chromium opens the page with JS sinks hooked (innerHTML/outerHTML,
document.write, eval). If our marker reaches a sink, that's CONFIRMED
DOM XSS (CRITICAL) — no alert() needed, so it works even under a CSP
that blocks inline scripts. Alert dialogs are still watched as backup;
a marker in the rendered DOM (but not raw HTML) is a LOW note.

Skipped quietly without Playwright (prints the install hint instead).
Slow (~4-6s/page), so it only runs with --dom.
"""

from __future__ import annotations

from core.colors import info, warn
from core.registry import check as register_check

DOM_MARKER = "gxdom"
DOM_QUERY_PAYLOAD = DOM_MARKER + '"><img src=x onerror="alert(\'gxdom\')">'
DOM_FRAG_PAYLOAD = DOM_MARKER + '"><svg onload=alert(\'gxdom\')>'

# Injected before page scripts run (CDP-level, so page CSP can't block
# it). Records any marker-carrying value assigned to dangerous sinks.
SINK_HOOK_JS = """
() => {
  window.__gash_sinks = [];
  const MARK = 'gxdom';
  const note = (sink, v) => {
    try {
      const s = String(v == null ? '' : v).slice(0, 200);
      if (s.indexOf(MARK) !== -1) window.__gash_sinks.push(sink);
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
  try {
    hookProp(Element.prototype, 'innerHTML');
    hookProp(Element.prototype, 'outerHTML');
    if (typeof ShadowRoot !== 'undefined') hookProp(ShadowRoot.prototype, 'innerHTML');
    const _w = Document.prototype.write;
    Document.prototype.write = function() {
      for (const a of arguments) note('document.write', a);
      return _w.apply(this, arguments);
    };
    const _ev = window.eval;
    window.eval = function(x) { note('eval', x); return _ev(x); };
  } catch (e) {}
}
"""


def _targets(urls: list[str], limit: int = 6) -> list[str]:
    out = []
    for u in urls[:limit]:
        out.append(u)
        base = u.split("#")[0]
        sep = "&" if "?" in base else "?"
        out.append(f"{base}{sep}gxdomq={DOM_QUERY_PAYLOAD}#{DOM_FRAG_PAYLOAD}")
    return list(dict.fromkeys(out))[: limit * 2]


@register_check("dom-xss", "DOM XSS headless verification (needs --dom)", order=12)
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
    page = browser.new_page(ignore_https_errors=True)
    try:
        page.on("dialog", lambda d: (fired.append(d.message), d.dismiss()))
        try:
            page.add_init_script(SINK_HOOK_JS)
        except Exception:
            pass
        page.goto(url, timeout=(timeout + 10) * 1000, wait_until="domcontentloaded")
        page.wait_for_timeout(2500)
        try:
            sinks = page.evaluate("() => (window.__gash_sinks || []).slice(0, 3)")
        except Exception:
            sinks = []
        if sinks:
            if verbose:
                from core.colors import warn as _w
                print(_w(f"    [!] DOM XSS (sink reached): {url}"))
            return Finding(
                title="DOM XSS (confirmed — sink reached)", severity="CRITICAL",
                url=url.split("#")[0],
                detail=f"Marker flowed into JS sink(s): "
                       f"{', '.join(dict.fromkeys(sinks))}",
                evidence=DOM_MARKER,
                confidence="High",)
        if any(DOM_MARKER in m for m in fired):
            if verbose:
                from core.colors import warn as _w
                print(_w(f"    [!] DOM XSS (confirmed): {url}"))
            return Finding(
                title="DOM XSS (confirmed — alert fired)", severity="CRITICAL",
                url=url.split("#")[0],
                detail="Headless browser caught an alert dialog",
                evidence=DOM_MARKER,
                confidence="High",)
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
