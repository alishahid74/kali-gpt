#!/usr/bin/env python3
"""
Shell-injection lint for Kali-GPT (CWE-78 guard rail).

Flags subprocess calls that run a DYNAMICALLY BUILT shell string, i.e.
`subprocess.run/call/Popen/check_output/check_call(<dynamic>, ..., shell=True)`
where <dynamic> is an f-string, a string built with `+`, `%`, or `.format()`.
These are the classic command-injection sinks.

A baseline file (scripts/.shell_lint_baseline.json) records the violations that
already existed and were reviewed. The linter FAILS only on NEW violations, so
the build breaks the moment someone adds a fresh `shell=True` + f-string.

Usage:
    python3 scripts/lint_shell_exec.py            # check; non-zero exit on new hits
    python3 scripts/lint_shell_exec.py --update-baseline   # accept current state

A single call can be exempted with a trailing comment containing `nosec: shell`.
"""

import argparse
import ast
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BASELINE_FILE = Path(__file__).resolve().parent / ".shell_lint_baseline.json"

SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}

# Directories we never scan.
SKIP_DIRS = {".git", "venv", ".venv", "env", "__pycache__", "node_modules",
             "build", "dist", "vscode-extension"}


def _is_dynamic_string(node: ast.AST) -> bool:
    """True if the AST node is a dynamically constructed string."""
    # f"...{x}..."
    if isinstance(node, ast.JoinedStr):
        return True
    # "a" + x  /  x + "a"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return True
    # "...%s..." % x
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        return True
    # "...".format(x)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return True
    return False


def _call_is_subprocess(node: ast.Call) -> bool:
    """True if the call is subprocess.<func>(...) or a bare run/Popen(...)."""
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr in SUBPROCESS_FUNCS:
        return True
    if isinstance(func, ast.Name) and func.id in SUBPROCESS_FUNCS:
        return True
    return False


def _has_shell_true(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _line_is_exempt(source_lines, lineno: int) -> bool:
    """A call is exempt if its line carries a `nosec: shell` comment."""
    if 0 < lineno <= len(source_lines):
        return "nosec: shell" in source_lines[lineno - 1].lower()
    return False


def scan_file(path: Path):
    """Yield (relpath, lineno, snippet) violations for one file."""
    try:
        source = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return

    source_lines = source.splitlines()
    rel = path.relative_to(REPO_ROOT).as_posix()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not _call_is_subprocess(node):
            continue
        if not _has_shell_true(node):
            continue
        if not node.args:
            continue
        if not _is_dynamic_string(node.args[0]):
            continue
        if _line_is_exempt(source_lines, node.lineno):
            continue
        # Use the full call source (whitespace-normalized) so each sink has a
        # unique, line-independent signature even when it spans multiple lines.
        segment = ast.get_source_segment(source, node) or ""
        snippet = " ".join(segment.split())
        yield rel, node.lineno, snippet


def collect_violations():
    violations = []
    for path in REPO_ROOT.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.resolve() == Path(__file__).resolve():
            continue  # don't flag this linter's own example strings
        violations.extend(scan_file(path))
    return violations


def signature(v):
    """Stable identity for a violation: file + code text (survives line shifts)."""
    rel, _lineno, snippet = v
    return f"{rel}::{snippet}"


def load_baseline():
    if BASELINE_FILE.exists():
        return set(json.loads(BASELINE_FILE.read_text()))
    return set()


def main():
    ap = argparse.ArgumentParser(description="Shell-injection lint (CWE-78)")
    ap.add_argument("--update-baseline", action="store_true",
                    help="write the current violations to the baseline file")
    args = ap.parse_args()

    violations = collect_violations()

    if args.update_baseline:
        sigs = sorted({signature(v) for v in violations})
        BASELINE_FILE.write_text(json.dumps(sigs, indent=2) + "\n")
        print(f"Baseline updated: {len(sigs)} accepted violation(s) "
              f"-> {BASELINE_FILE.relative_to(REPO_ROOT)}")
        return 0

    baseline = load_baseline()
    new = [v for v in violations if signature(v) not in baseline]

    if new:
        print("❌ New shell-injection risk(s) detected "
              "(subprocess with shell=True + dynamic string):\n")
        for rel, lineno, snippet in sorted(new):
            print(f"  {rel}:{lineno}: {snippet}")
        print("\nFix by building an argv list and using shell=False, e.g.:")
        print('  subprocess.run(["nmap", "-sV", target], shell=False)')
        print("\nIf this is genuinely safe and reviewed, either add a trailing")
        print("`# nosec: shell` comment on that line, or run:")
        print("  python3 scripts/lint_shell_exec.py --update-baseline")
        return 1

    stale = baseline - {signature(v) for v in violations}
    print(f"✅ No new shell-injection sinks. "
          f"({len(baseline)} baselined, {len(stale)} since removed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
