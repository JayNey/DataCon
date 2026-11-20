"""Private Tree-sitter extraction subprocess.

The parent (``datacon.tools.source.extract_symbols``) runs this module in a
separate Python process with a hard timeout and, on Linux, an ``RLIMIT_AS``
cap. The worker only receives pinned source bytes plus a validated relative
path/revision/function/role. It emits exactly one compact JSON document.

Error responses never include exception text or a traceback: both can contain
host paths. The parent maps the stable ``error`` code to the public
``SourceToolError`` message.
"""

from __future__ import annotations

import base64
import json
import sys
from typing import Any

# The parent enforces the real source cap before spawning this worker. This is
# a defence-in-depth bound on the request document itself (base64 expands the
# source by 4/3).
MAX_REQUEST_BYTES = 8 * 1024 * 1024


def _function_name(node: Any) -> str | None:
    declarator = node.child_by_field_name("declarator")
    while declarator is not None:
        if declarator.type == "function_declarator":
            inner = declarator.child_by_field_name("declarator")
            if inner is not None and inner.type == "identifier":
                return inner.text.decode("utf-8", "replace")
            return None
        if declarator.type == "identifier":
            return declarator.text.decode("utf-8", "replace")
        declarator = declarator.child_by_field_name("declarator")
    return None


def _walk(node: Any):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _extract(request: dict[str, Any]) -> dict[str, Any]:
    try:
        source = base64.b64decode(request["source"], validate=True)
        path = request["path"]
        revision = request["revision"]
        function_name = request["function_name"]
        role = request["role"]
        max_symbols = request["max_symbols"]
    except (KeyError, TypeError, ValueError):
        return {"ok": False, "error": "internal"}
    if (
        not isinstance(path, str)
        or not isinstance(revision, str)
        or not isinstance(function_name, str)
        or role not in ("definition", "call_site")
        or type(max_symbols) is not int
        or max_symbols < 0
    ):
        return {"ok": False, "error": "internal"}

    try:
        import tree_sitter_c
        from tree_sitter import Language, Parser
    except Exception:  # pragma: no cover - import environment failure
        return {"ok": False, "error": "parser_unavailable"}

    try:
        tree = Parser(Language(tree_sitter_c.language())).parse(source)
    except MemoryError:
        return {"ok": False, "error": "memory"}
    except Exception:
        return {"ok": False, "error": "parse_error"}
    if tree.root_node.has_error:
        return {"ok": False, "error": "syntax_error"}

    symbols: list[dict[str, Any]] = []
    try:
        for node in _walk(tree.root_node):
            if role == "definition" and node.type == "function_definition":
                if _function_name(node) != function_name:
                    continue
            elif role == "call_site" and node.type == "call_expression":
                function = node.child_by_field_name("function")
                if function is None or function.type != "identifier":
                    continue
                if function.text.decode("utf-8", "replace") != function_name:
                    continue
            else:
                continue
            if len(symbols) >= max_symbols:
                return {"ok": False, "error": "too_many_symbols"}
            symbols.append(
                {
                    "name": function_name,
                    "path": path,
                    "role": role,
                    "revision": revision,
                    "start_line": node.start_point.row + 1,
                    "end_line": node.end_point.row + 1,
                }
            )
    except MemoryError:
        return {"ok": False, "error": "memory"}
    except Exception:
        return {"ok": False, "error": "internal"}
    return {"ok": True, "symbols": symbols}


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            response: dict[str, Any] = {"ok": False, "error": "internal"}
        else:
            request = json.loads(raw)
            if not isinstance(request, dict):
                response = {"ok": False, "error": "internal"}
            else:
                response = _extract(request)
    except MemoryError:
        response = {"ok": False, "error": "memory"}
    except BaseException:
        response = {"ok": False, "error": "internal"}
    try:
        sys.stdout.write(json.dumps(response, separators=(",", ":")))
        sys.stdout.flush()
    except OSError:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
