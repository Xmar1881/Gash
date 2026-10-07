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
    """Run in order; extra paths accumulate in ctx['extra_paths']."""
    from core.net import ScanBudgetExceeded
    skip = skip or set()
    unknown = set(skip) - set(REGISTRY)
    if unknown:
        from core.colors import warn
        print(warn(f"  [!] unknown check (ignored): "
                   f"{', '.join(sorted(unknown))}"))
    ctx.setdefault("extra_paths", [])
    out = []
    ordered = sorted(REGISTRY.items(), key=lambda kv: (kv[1]["order"], kv[1]["seq"]))
    active = [(n, m) for n, m in ordered
              if n not in skip and not (m["deep_only"] and not deep)]
    total = len(active)
    if verbose:
        skipped_n = len(ordered) - total
        if skipped_n:
            from core.colors import info
            print(info(f"  [-] atlandi: {skipped_n} kontrol"))
    for i, (name, meta) in enumerate(active, 1):
        from core.colors import info as _info
        print(_info(f"  [{i:>2}/{total}] {name} — {meta['desc'][:60]}"))
        fn = meta["fn"]
        params = inspect.signature(fn).parameters
        if list(params)[:1] == ["ctx"]:
            kwargs = {"ctx": ctx}  # paylasimli-durum fonksiyonu, session almaz
            try:
                res = fn(**kwargs)
            except ScanBudgetExceeded:
                raise
            except Exception as e:
                if verbose:
                    from core.colors import warn
                    print(warn(f"  [!] kontrol hatasi ({name}): {str(e)[:100]}"))
                continue
        else:
            kwargs = {}
            for p in params:
                if p == "session":
                    continue
                if p == "ctx":
                    kwargs[p] = ctx
                elif p in ctx:
                    kwargs[p] = ctx[p]
            try:
                res = fn(session, **kwargs)
            except ScanBudgetExceeded:
                raise
            except Exception as e:
                if verbose:
                    from core.colors import warn
                    print(warn(f"  [!] kontrol hatasi ({name}): {str(e)[:100]}"))
                continue
        if isinstance(res, tuple) and len(res) == 2:
            findings, extra = res
            out += findings or []
            ctx["extra_paths"] += extra or []
        elif res:
            out += res
    return out
