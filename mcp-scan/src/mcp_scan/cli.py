"""Command-line entry point.

Scan a JSON manifest of tools, a live MCP stdio server's advertised tools, or the built-in demo
fixtures, and print findings. Exit code is non-zero when findings at or above ``--fail-on`` are
present, so the scanner can gate CI.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence

from mcp_scan import fixtures
from mcp_scan.guard import GuardPolicy, guard_tools
from mcp_scan.models import ToolManifest
from mcp_scan.scanner import Finding, Severity, scan_tools

_COLOR = {"HIGH": "\033[31m", "MEDIUM": "\033[33m", "LOW": "\033[36m"}
_RESET = "\033[0m"


def _load_manifest(path: str) -> list[ToolManifest]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    items = raw.get("tools", raw) if isinstance(raw, dict) else raw
    if not isinstance(items, list):
        raise SystemExit(f"{path}: expected a list of tools or an object with a 'tools' key")
    return [ToolManifest.from_dict(item) for item in items]


async def _load_server(command: str, args: Sequence[str]) -> list[ToolManifest]:
    from mcp_scan.scanner import list_stdio_server_tools

    raw = await list_stdio_server_tools(command, args)
    return [ToolManifest.from_dict(item) for item in raw]


def _print_findings(findings: list[Finding], *, color: bool, as_json: bool) -> None:
    if as_json:
        json.dump([f.to_dict() for f in findings], sys.stdout, indent=2)
        sys.stdout.write("\n")
        return
    if not findings:
        print("No findings.")
        return
    by_tool: dict[str, list[Finding]] = {}
    for f in findings:
        by_tool.setdefault(f.tool, []).append(f)
    for tool, group in by_tool.items():
        print(f"\n{tool}")
        for f in sorted(group, key=lambda x: -x.severity):
            tag = f.severity.name
            if color and tag in _COLOR:
                tag = f"{_COLOR[tag]}{tag}{_RESET}"
            print(f"  [{tag}] {f.rule_id} {f.message}")
            print(f"        at {f.location}: {f.evidence}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-scan", description=__doc__)
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("manifest", nargs="?", help="Path to a JSON tool manifest.")
    src.add_argument("--demo", action="store_true", help="Scan the bundled poisoned fixtures.")
    src.add_argument("--server", metavar="CMD", help="Launch an MCP stdio server and scan it.")
    parser.add_argument("--server-arg", action="append", default=[], dest="server_args")
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON.")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--guard", action="store_true",
                        help="Also print the guard action (allow/sanitize/block) per tool.")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH"], default="HIGH",
                        help="Exit non-zero if any finding is at or above this severity.")
    args = parser.parse_args(argv)

    if args.demo:
        tools = fixtures.ALL
    elif args.server:
        tools = asyncio.run(_load_server(args.server, args.server_args))
    else:
        tools = _load_manifest(args.manifest)

    findings = scan_tools([t.to_dict() for t in tools])
    _print_findings(findings, color=not args.no_color, as_json=args.json)

    if args.guard and not args.json:
        print("\nGuard decisions:")
        for d in guard_tools(tools, GuardPolicy()):
            print(f"  {d.tool}: {d.action.value}")

    threshold = Severity[args.fail_on]
    worst = max((f.severity for f in findings), default=None)
    return 1 if worst is not None and worst >= threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())
