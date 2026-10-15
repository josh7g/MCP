"""mcp-scan: find prompt-injection and tool-poisoning patterns in MCP tool metadata.

MCP clients inline every connected tool's name, description and input schema into the model's
context. That metadata is attacker-controllable when a server is third-party or compromised, and
it is read by the model whether or not the tool is ever called. This package scans that metadata
for known tool-poisoning and tool-shadowing patterns and offers a guard that sanitizes it before
it reaches the model.
"""

from mcp_scan.guard import GuardDecision, GuardPolicy, guard_tools
from mcp_scan.models import ToolManifest
from mcp_scan.scanner import Finding, Severity, scan_tool, scan_tools

__all__ = [
    "Finding",
    "GuardDecision",
    "GuardPolicy",
    "Severity",
    "ToolManifest",
    "guard_tools",
    "scan_tool",
    "scan_tools",
]
__version__ = "0.1.0"
