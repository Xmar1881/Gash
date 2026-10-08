"""Plugin registry — a new check is one function + one decorator line.

Checks keep their natural signatures; the dispatcher binds ctx dict
entries by parameter name (session is passed separately). Rules:
  - return a list[Finding], or a (findings, extra_paths) tuple
  - a "ctx" parameter gets the whole shared ctx dict
  - registration order = run order (robots -> smart -> dirs depend on it)
  - --skip-checks disables by name
"""

from __future__ import annotations

import inspect

REGISTRY: dict[str, dict] = {}
_SEQ = [0]


def check(name: str, desc: str = "", deep_only: bool = False, order: int = 100):
    """Register a check function. order: run-order weight."""
    def deco(fn):
        _SEQ[0] += 1
        REGISTRY[name] = {"fn": fn, "desc": desc or fn.__doc__ or "",
                          "deep_only": deep_only, "order": order,
                          "seq": _SEQ[0]}
        return fn
    return deco


def list_checks() -> list[tuple[str, str, bool]]:
    return [(n, m["desc"].split("\n")[0][:70], m["deep_only"])
            for n, m in REGISTRY.items()]


def run_checks(session, ctx: dict, skip: set[str] | None = None,
               deep: bool = True, verbose: bool = False) -> list:
    """Run in order; extra paths accumulate in ctx['extra_paths'].

    Health is recorded in ctx['check_status']: one record per check with
    status passed|findings|skipped|error|aborted, elapsed_ms and (for
    errors) the exception type + short message. Errors never vanish
    silently: one concise line prints even when verbose is off, the rest
    of the checks still run, and the caller must surface SCAN DEGRADED
    instead of a clean bill.
    """
    import time
    from core.net import ScanBudgetExceeded
    skip = skip or set()
    unknown = set(skip) - set(REGISTRY)
    if unknown:
        from core.colors import warn
        print(warn(f"  [!] unknown check (ignored): "
                   f"{', '.join(sorted(unknown))}"))
    ctx.setdefault("extra_paths", [])
    health: list = ctx.setdefault("check_status", [])
    out = []
    ordered = sorted(REGISTRY.items(), key=lambda kv: (kv[1]["order"], kv[1]["seq"]))
    active = [(n, m) for n, m in ordered
              if n not in skip and not (m["deep_only"] and not deep)]
    for n, m in ordered:
        if n in skip:
            health.append({"check": n, "status": "skipped",
                           "reason": "skip-checks", "elapsed_ms": 0,
                           "findings": 0})
        elif m["deep_only"] and not deep:
            health.append({"check": n, "status": "skipped",
                           "reason": "deep-only (needs --deep)",
                           "elapsed_ms": 0, "findings": 0})
    total = len(active)
    if verbose:
        skipped_n = len(ordered) - total
        if skipped_n:
            from core.colors import info
            print(info(f"  [-] skipped: {skipped_n} checks"))
    for i, (name, meta) in enumerate(active, 1):
        from core.colors import info as _info
        print(_info(f"  [{i:>2}/{total}] {name} — {meta['desc'][:60]}"))
        fn = meta["fn"]
        params = inspect.signature(fn).parameters
        t0 = time.perf_counter()
        try:
            if list(params)[:1] == ["ctx"]:
                res = fn(ctx=ctx)  # shared-state fn, takes no session
            else:
                kwargs = {}
                takes_session = list(params)[:1] == ["session"]
                for p in params:
                    if p == "session":
                        continue
                    if p == "ctx":
                        kwargs[p] = ctx
                    elif p in ctx:
                        kwargs[p] = ctx[p]
                # session goes in positionally ONLY when the check asks for
                # it first; otherwise it would collide with that parameter
                # (this silently killed every session-less check before).
                res = fn(session, **kwargs) if takes_session else fn(**kwargs)
        except ScanBudgetExceeded as e:
            from core.net import PartialResults
            health.append({"check": name, "status": "aborted",
                           "reason": str(e)[:150],
                           "elapsed_ms": _ms(t0), "findings": 0})
            raise PartialResults(out, str(e))
        except Exception as e:
            from core.colors import warn
            print(warn(f"  [!] check error ({name}): "
                       f"{type(e).__name__}: {str(e)[:100]}"))
            health.append({"check": name, "status": "error",
                           "error_type": type(e).__name__,
                           "error": str(e)[:150],
                           "elapsed_ms": _ms(t0), "findings": 0})
            continue
        before = len(out)
        if isinstance(res, tuple) and len(res) == 2:
            findings, extra = res
            out += findings or []
            ctx["extra_paths"] += extra or []
        elif res:
            out += res
        for f in out[before:]:
            try:
                if not getattr(f, "check", ""):
                    f.check = name
            except Exception:
                pass
        n_find = (len(findings) if isinstance(res, tuple) and len(res) == 2
                  else len(res or []))
        health.append({"check": name,
                       "status": "findings" if n_find else "passed",
                       "elapsed_ms": _ms(t0), "findings": n_find})
    return out


def _ms(t0: float) -> int:
    import time
    return max(0, int((time.perf_counter() - t0) * 1000))
