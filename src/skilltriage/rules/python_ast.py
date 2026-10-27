"""Python AST rules (AST01, AST04).

Regex catches text; the AST catches what the text means. These rules are
deliberately precise: parse failures are ignored, and safe equivalents
(``ast.literal_eval``, ``yaml.safe_load``) are not flagged.
"""

from __future__ import annotations

import ast

from ..models import Confidence, Severity
from .base import Rule, RuleContext

RULES: list[Rule] = []

_UNSAFE_CALLS = {
    "eval",
    "exec",
    "execfile",
    "compile",
    "__import__",
    "os.system",
    "os.popen",
    "pickle.loads",
    "pickle.load",
    "marshal.loads",
    "marshal.load",
    "yaml.load",
    "yaml.unsafe_load",
    "yaml.full_load",
    "ctypes.CDLL",
    "ctypes.cdll.LoadLibrary",
}
_SHELL_CALLS = {"os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput"}
_TOP_LEVEL_NETWORK = (
    "subprocess.",
    "requests.",
    "urllib.request.",
    "http.client.",
    "socket.",
    "ftplib.",
    "smtplib.",
)


def _dotted(node: ast.AST) -> str:
    """Resolve a dotted name iteratively.

    A pathological file with a very deep attribute chain must not exhaust the
    Python stack and skip the rest of the package.
    """
    parts: list[str] = []
    while True:
        if isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
            continue
        if isinstance(node, ast.Call):
            node = node.func
            continue
        if isinstance(node, ast.Name):
            parts.append(node.id)
            break
        return ""
    return ".".join(reversed(parts))


def _is_truthy_shell(keyword: ast.keyword) -> bool:
    return keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True


def _safe_yaml_loader(call: ast.Call) -> bool:
    for keyword in call.keywords:
        if keyword.arg == "Loader" and "Safe" in _dotted(keyword.value):
            return True
        if keyword.arg == "loader" and isinstance(keyword.value, ast.Constant):
            if "safe" in str(keyword.value.value).lower():
                return True
    return False


def check_unsafe_calls(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        if record.suffix != ".py":
            continue
        try:
            tree = ast.parse(text, filename=record.path)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted(node.func)
            if name not in _UNSAFE_CALLS:
                continue
            if name in ("yaml.load", "yaml.full_load") and _safe_yaml_loader(node):
                continue
            ctx.emit(
                RULE_PY_UNSAFE_CALL,
                path=record.path,
                line=getattr(node, "lineno", None),
                evidence=f"{name}(...)",
            )
            ctx.signal("unsafe_python_call", name)


def check_shell_exec(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        if record.suffix != ".py":
            continue
        try:
            tree = ast.parse(text, filename=record.path)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _dotted(node.func)
            if name in _SHELL_CALLS:
                ctx.emit(
                    RULE_PY_SHELL,
                    path=record.path,
                    line=getattr(node, "lineno", None),
                    evidence=f"{name}(...)",
                )
                ctx.signal("dynamic_exec", name)
                continue
            if name.startswith(("subprocess.", "os.spawn", "os.exec")) and any(
                _is_truthy_shell(keyword) for keyword in node.keywords
            ):
                ctx.emit(
                    RULE_PY_SHELL,
                    path=record.path,
                    line=getattr(node, "lineno", None),
                    evidence=f"{name}(..., shell=True)",
                )
                ctx.signal("dynamic_exec", f"{name} shell=True")


def check_import_side_effects(ctx: RuleContext) -> None:
    for record, text in ctx.texts():
        if record.suffix != ".py":
            continue
        try:
            tree = ast.parse(text, filename=record.path)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            continue
        for statement in tree.body:
            if isinstance(statement, ast.If):
                # Guarded by __name__ == "__main__" or a conditional: not an import side effect.
                continue
            if not isinstance(statement, (ast.Expr, ast.Assign, ast.AnnAssign)):
                continue
            for node in ast.walk(statement):
                if not isinstance(node, ast.Call):
                    continue
                name = _dotted(node.func)
                if name in _UNSAFE_CALLS or name.startswith(_TOP_LEVEL_NETWORK):
                    ctx.emit(
                        RULE_PY_IMPORT_SIDE_EFFECT,
                        path=record.path,
                        line=getattr(node, "lineno", None),
                        evidence=f"top-level {name}(...)",
                    )
                elif name == "open" and any(
                    isinstance(arg, ast.Constant) and isinstance(arg.value, str) and "w" in arg.value
                    for arg in node.args[1:2]
                ):
                    ctx.emit(
                        RULE_PY_IMPORT_SIDE_EFFECT,
                        path=record.path,
                        line=getattr(node, "lineno", None),
                        evidence="top-level open(..., 'w')",
                    )


RULE_PY_UNSAFE_CALL = Rule(
    id="AST01-PY-UNSAFE-CALL",
    ast="AST01",
    title="Unsafe Python call",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="eval, exec, pickle, marshal, and unsafe YAML loaders execute or deserialise attacker-controlled data.",
    remediation="Use ast.literal_eval for data, yaml.safe_load for YAML, and avoid dynamic code generation.",
    cwes=("CWE-95", "CWE-502"),
    tags=("python", "execution"),
    check=check_unsafe_calls,
)
RULES.append(RULE_PY_UNSAFE_CALL)

RULE_PY_SHELL = Rule(
    id="AST01-PY-SHELL-EXEC",
    ast="AST01",
    title="Python shell execution",
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    description="os.system, os.popen, and subprocess with shell=True interpret strings through a shell, enabling command injection.",
    remediation="Pass an argument list with shell=False and validate every value.",
    cwes=("CWE-78",),
    tags=("python", "execution"),
    check=check_shell_exec,
)
RULES.append(RULE_PY_SHELL)

RULE_PY_IMPORT_SIDE_EFFECT = Rule(
    id="AST04-PY-IMPORT-SIDE-EFFECT",
    ast="AST04",
    title="Python import-time side effect",
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    description="Network calls, shell execution, or writes at module import time run as soon as the loader touches the file, before the skill is invoked.",
    remediation="Move side effects behind an explicit function, a __main__ guard, or operator approval.",
    cwes=("CWE-1059",),
    tags=("python",),
    check=check_import_side_effects,
)
RULES.append(RULE_PY_IMPORT_SIDE_EFFECT)
