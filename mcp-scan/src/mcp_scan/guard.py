"""Runtime guard: decide what to do with a tool's metadata before a model ever sees it.

The scanner reports problems. The guard turns those reports into an action an MCP client can take
at connect time: allow the tool, allow it with its description sanitized, or block it entirely.
Stripping invisible Unicode and neutralizing embedded pseudo-markup means that even if a scan is
not reviewed by a human, the model is not handed raw attacker instructions.

This is defense in depth, not a guarantee. A determined natural-language injection can be phrased
to miss every pattern here; the guard raises the cost of the easy, high-signal attacks and gives
an operator a policy knob (block at HIGH, sanitize at MEDIUM, and so on).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from mcp_scan.models import ToolManifest
from mcp_scan.scanner import Finding, Severity, decode_tag_characters, scan_tool


class Action(str, Enum):
    ALLOW = "allow"
    SANITIZE = "sanitize"
    BLOCK = "block"


@dataclass(frozen=True)
class GuardDecision:
    tool: str
    action: Action
    findings: list[Finding]
    sanitized_description: str


@dataclass(frozen=True)
class GuardPolicy:
    """Map the worst finding severity for a tool to an action.

    Defaults: block anything with a HIGH finding (hidden instructions, credential references,
    concealed text), sanitize MEDIUM, allow LOW and clean tools.
    """

    block_at: Severity = Severity.HIGH
    sanitize_at: Severity = Severity.MEDIUM

    def action_for(self, worst: Severity | None) -> Action:
        if worst is None:
            return Action.ALLOW
        if worst >= self.block_at:
            return Action.BLOCK
        if worst >= self.sanitize_at:
            return Action.SANITIZE
        return Action.ALLOW


_INVISIBLE = re.compile(
    r"[​-‏‪-‮⁠-⁤⁦-⁩﻿]"
    r"|[\U000e0000-\U000e007f]"
)
_PSEUDO_MARKUP = re.compile(r"<\s*/?\s*(important|system|instructions?|admin|secret)\s*>", re.I)


def sanitize_description(description: str) -> str:
    """Remove the mechanisms an injection relies on, keeping the readable text.

    Invisible characters are dropped (after being surfaced to the scanner elsewhere), and
    authority-faking pseudo-markup like ``<IMPORTANT>`` is defanged so it reads as literal text.
    """
    # Drop any text hidden in tag characters outright; keep visible ASCII intact.
    cleaned = _INVISIBLE.sub("", description)
    cleaned = _PSEUDO_MARKUP.sub(lambda m: m.group(0).replace("<", "(").replace(">", ")"), cleaned)
    return cleaned


def guard_tool(
    manifest: ToolManifest, policy: GuardPolicy, sibling_names: list[str]
) -> GuardDecision:
    findings = scan_tool(
        manifest.name, manifest.description, manifest.input_schema, sibling_names
    )
    worst = max((f.severity for f in findings), default=None)
    action = policy.action_for(worst)
    sanitized = manifest.description if action == Action.ALLOW else sanitize_description(
        manifest.description
    )
    return GuardDecision(manifest.name, action, findings, sanitized)


def guard_tools(
    tools: Iterable[ToolManifest], policy: GuardPolicy | None = None
) -> list[GuardDecision]:
    policy = policy or GuardPolicy()
    manifests = list(tools)
    names = [m.name for m in manifests]
    return [guard_tool(m, policy, names) for m in manifests]


def assert_no_hidden_text(description: str) -> None:
    """Raise if a description contains concealed text. Useful as a hard assertion in CI."""
    hidden = decode_tag_characters(description)
    if hidden:
        raise ValueError(f"tool description contains hidden text: {hidden!r}")
