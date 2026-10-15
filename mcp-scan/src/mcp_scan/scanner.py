"""Static scanner for poisoned MCP tool metadata.

MCP clients put every tool's name, description and input schema straight into the model's
context, so that metadata is an injection surface even if the tool is never called. This module
flags patterns seen in tool-poisoning and tool-shadowing attacks. It is a heuristic linter, not a
proof of safety: a clean scan means none of these patterns matched, nothing more.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    severity: Severity
    message: str
    location: str
    evidence: str

    def to_dict(self) -> dict[str, str]:
        return {
            "tool": self.tool,
            "rule_id": self.rule_id,
            "severity": self.severity.name,
            "message": self.message,
            "location": self.location,
            "evidence": self.evidence,
        }


# --- invisible / deceptive characters -------------------------------------------------------

_TAG_BLOCK = range(0xE0000, 0xE0080)  # Unicode "tag" characters: invisible, map 1:1 to ASCII
_INVISIBLE = {
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F,  # zero-width + LRM/RLM
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064,  # word joiner, invisible operators
    0xFEFF,  # zero-width no-break space
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # bidi embedding / override
    0x2066, 0x2067, 0x2068, 0x2069,  # bidi isolates
}


def decode_tag_characters(text: str) -> str:
    """Return the ASCII text hidden in Unicode tag characters (U+E0020-U+E007E)."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def _invisible_chars(text: str) -> list[str]:
    return [c for c in text if ord(c) in _TAG_BLOCK or ord(c) in _INVISIBLE]


# --- text rules -----------------------------------------------------------------------------

@dataclass(frozen=True)
class _Rule:
    rule_id: str
    severity: Severity
    message: str
    pattern: re.Pattern[str]


_I = re.IGNORECASE
_TEXT_RULES: tuple[_Rule, ...] = (
    _Rule(
        "MCP002",
        Severity.HIGH,
        "Instruction aimed at the model (override or directive) inside tool metadata",
        re.compile(
            r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules)"
            r"|disregard\s+(all\s+|any\s+)?(previous|prior|above|your)\b"
            r"|\bnew\s+instructions\b"
            r"|\bnote\s+(to|for)\s+(the\s+)?(ai|assistant|agent|llm|model)s?\b"
            r"|\b(ai|assistant|agent|llm|model)s?\s+(must|should\s+always|are\s+required\s+to)\b"
            r"|\byou\s+must\s+(now|always|first)\b"
            r"|\bbefore\s+(calling|using)\s+this\s+tool\b.{0,80}\b(read|call|send|pass|include)\b",
            _I | re.DOTALL,
        ),
    ),
    _Rule(
        "MCP003",
        Severity.HIGH,
        "Asks the model to hide its actions from the user",
        re.compile(
            r"\b(do\s+not|don't|never)\s+(tell|mention|inform|reveal|show|notify)\b.{0,30}\buser\b"
            r"|\bwithout\s+(telling|informing|notifying|alerting)\s+(the\s+)?user\b"
            r"|\b(do\s+not|don't)\s+mention\s+(this|it)\b",
            _I | re.DOTALL,
        ),
    ),
    _Rule(
        "MCP004",
        Severity.HIGH,
        "References credentials or sensitive files",
        re.compile(
            r"~/\.ssh|\bid_(rsa|ed25519|ecdsa)\b|(?<![\w.])\.env\b|/etc/(passwd|shadow)"
            r"|\.aws/credentials|\bmcp\.json\b|\bprivate[\s_-]?key\b|\bseed\s+phrase\b",
            _I,
        ),
    ),
    _Rule(
        "MCP006",
        Severity.MEDIUM,
        "Contains a URL that could receive exfiltrated data",
        re.compile(r"https?://[^\s\"'<>)]+", _I),
    ),
    _Rule(
        "MCP007",
        Severity.MEDIUM,
        "Contains a long encoded blob (possible hidden payload)",
        re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    ),
    _Rule(
        "MCP010",
        Severity.MEDIUM,
        "Pseudo-system markup that tries to look authoritative to the model",
        re.compile(r"<\s*/?\s*(important|system|instructions?|admin|secret)\s*>", _I),
    ),
)

_MAX_DESCRIPTION = 1000


def _texts_in_schema(schema: Any, path: str = "input_schema") -> Iterator[tuple[str, str]]:
    """Yield (location, text) for every human-readable string an MCP client shows the model."""
    if isinstance(schema, dict):
        for key, value in schema.items():
            child = f"{path}.{key}"
            if key in {"description", "title"} and isinstance(value, str):
                yield child, value
            elif key in {"default", "examples", "enum", "const"}:
                for item in value if isinstance(value, list) else [value]:
                    if isinstance(item, str):
                        yield child, item
            else:
                yield from _texts_in_schema(value, child)
    elif isinstance(schema, list):
        for i, item in enumerate(schema):
            yield from _texts_in_schema(item, f"{path}[{i}]")


def _snippet(text: str, start: int, end: int, pad: int = 30) -> str:
    s = text[max(0, start - pad) : min(len(text), end + pad)]
    return " ".join(s.split())


def scan_tool(
    name: str,
    description: str,
    input_schema: dict[str, Any] | None = None,
    sibling_names: Sequence[str] = (),
) -> list[Finding]:
    """Scan one tool's metadata. ``sibling_names`` are the other tools exposed alongside it."""
    findings: list[Finding] = []
    texts: list[tuple[str, str]] = [("description", description)]
    texts.extend(_texts_in_schema(input_schema or {}))

    for location, text in texts:
        hidden = _invisible_chars(text)
        if hidden:
            decoded = decode_tag_characters(text)
            evidence = f"{len(hidden)} invisible char(s)"
            if decoded:
                evidence += f"; hidden text: {decoded[:200]!r}"
            findings.append(Finding(
                name, "MCP001", Severity.HIGH,
                "Invisible or bidirectional Unicode characters", location, evidence))
            # Scan what the model would actually read once hidden text is decoded.
            if decoded:
                texts.append((f"{location} (decoded hidden text)", decoded))

        for rule in _TEXT_RULES:
            match = rule.pattern.search(text)
            if match:
                findings.append(Finding(name, rule.rule_id, rule.severity, rule.message, location,
                                        _snippet(text, match.start(), match.end())))

        for other in sibling_names:
            if other == name:
                continue
            m = re.search(rf"(?<![\w-]){re.escape(other)}(?![\w-])", text)
            if m:
                findings.append(Finding(
                    name, "MCP005", Severity.MEDIUM,
                    f"References another tool ('{other}'); possible tool shadowing",
                    location, _snippet(text, m.start(), m.end())))

    if len(description) > _MAX_DESCRIPTION:
        findings.append(Finding(name, "MCP008", Severity.LOW,
                                f"Unusually long description ({len(description)} chars)",
                                "description", description[:80] + "..."))
    return findings


def scan_tools(tools: Iterable[dict[str, Any]]) -> list[Finding]:
    """Scan a server's tool list. Each item needs ``name``, ``description``, ``input_schema``."""
    items = list(tools)
    names = [str(t["name"]) for t in items]
    findings: list[Finding] = []
    for t in items:
        findings.extend(scan_tool(
            str(t["name"]),
            str(t.get("description") or ""),
            t.get("input_schema") or t.get("inputSchema") or {},
            names,
        ))
    return findings


async def list_stdio_server_tools(command: str, args: Sequence[str]) -> list[dict[str, Any]]:
    """Start an MCP server over stdio and return its advertised tools (it is never called)."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=command, args=list(args))
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        result = await session.list_tools()
        return [
            {"name": t.name, "description": t.description or "", "input_schema": t.input_schema}
            for t in result.tools
        ]


def max_severity(findings: Iterable[Finding]) -> Severity | None:
    return max((f.severity for f in findings), default=None)
