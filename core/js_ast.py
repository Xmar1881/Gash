"""Optional JavaScript AST adapter used by the XSS context engine.

The scanner has no mandatory Node runtime.  When the ``jsast`` extra is
installed, tree-sitter parses JavaScript without evaluating it and exposes the
node at a canary offset.  Callers can retain the conservative context fallback
when the optional backend is unavailable.
"""

from __future__ import annotations

from typing import Any


def _parser() -> tuple[Any, str] | None:
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_javascript as javascript
    except Exception:
        return None
    try:
        language = Language(javascript.language())
        return Parser(language), "tree-sitter-javascript"
    except Exception:
        try:
            parser = Parser()
            parser.set_language(Language(javascript.language()))
            return parser, "tree-sitter-javascript"
        except Exception:
            return None


def parse_javascript(source: str, limit: int = 100_000) -> dict:
    """Parse JavaScript to bounded node metadata; never execute source code."""
    backend = _parser()
    if backend is None:
        return {"backend": "unavailable", "parse_ok": False, "nodes": []}
    parser, name = backend
    raw = (source or "")[:max(0, int(limit))].encode("utf-8", "replace")
    try:
        tree = parser.parse(raw)
        nodes: list[dict] = []

        def visit(node: Any, depth: int = 0) -> None:
            if len(nodes) >= 300 or depth > 80:
                return
            if getattr(node, "is_named", True):
                nodes.append({"type": str(node.type),
                              "start": int(node.start_byte),
                              "end": int(node.end_byte)})
            for child in getattr(node, "children", ()):
                visit(child, depth + 1)

        visit(tree.root_node)
        return {"backend": name, "parse_ok": not tree.root_node.has_error,
                "nodes": nodes, "tree": tree}
    except Exception:
        return {"backend": name, "parse_ok": False, "nodes": []}


def context_at(source: str, offset: int) -> dict | None:
    """Return AST context metadata for one byte/character offset."""
    parsed = parse_javascript(source)
    tree = parsed.pop("tree", None)
    if tree is None or not parsed.get("parse_ok"):
        return None
    try:
        # ASCII canaries are used by the scanner, so character and byte
        # offsets are equivalent for the normal path.  Clamp for safety.
        point = max(0, min(int(offset), len(source.encode("utf-8", "replace"))))
        root = tree.root_node
        finder = getattr(root, "named_descendant_for_byte_range", None)
        node = finder(point, point) if finder else root.descendant_for_byte_range(
            point, point)
        ancestors = []
        current = node
        for _ in range(12):
            if current is None:
                break
            ancestors.append(str(current.type))
            current = getattr(current, "parent", None)
        if "template_string" in ancestors or "template_substitution" in ancestors:
            context = "js-template-literal"
        elif "string" in ancestors or "string_fragment" in ancestors:
            context = "js-string-double"
        elif "call_expression" in ancestors or "expression_statement" in ancestors:
            context = "js-expression"
        else:
            context = "js-expression"
        return {"context": context, "ast_node": str(node.type),
                "backend": parsed.get("backend", "")}
    except Exception:
        return None


__all__ = ["parse_javascript", "context_at"]
