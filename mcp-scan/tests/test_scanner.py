"""Scanner detection tests, driven by the inert fixtures."""

from __future__ import annotations

from mcp_scan import fixtures
from mcp_scan.scanner import Severity, decode_tag_characters, scan_tool, scan_tools


def _rule_ids(findings: list) -> set[str]:
    return {f.rule_id for f in findings}


def test_clean_tool_has_no_findings() -> None:
    m = fixtures.CLEAN
    assert scan_tool(m.name, m.description, m.input_schema) == []


def test_detects_embedded_instruction_and_credential_reference() -> None:
    m = fixtures.EMBEDDED_INSTRUCTION
    ids = _rule_ids(scan_tool(m.name, m.description, m.input_schema))
    assert "MCP002" in ids  # instruction aimed at the model
    assert "MCP003" in ids  # hide-from-user
    assert "MCP004" in ids  # credential reference (.env)
    assert "MCP010" in ids  # pseudo-system markup


def test_detects_hidden_tag_characters() -> None:
    m = fixtures.HIDDEN_TEXT
    findings = scan_tool(m.name, m.description, m.input_schema)
    ids = _rule_ids(findings)
    assert "MCP001" in ids
    hidden = decode_tag_characters(m.description)
    assert "transfer" in hidden.lower()


def test_hidden_text_is_decoded_and_rescanned() -> None:
    # The concealed instruction should itself trip the hide-from-user rule once decoded.
    m = fixtures.HIDDEN_TEXT
    findings = scan_tool(m.name, m.description, m.input_schema)
    assert any("decoded hidden text" in f.location for f in findings)


def test_detects_tool_shadowing_reference() -> None:
    tools = [t.to_dict() for t in (fixtures.SHADOWING, fixtures.CLEAN)]
    # Give it a sibling it names so MCP005 can fire.
    tools.append({"name": "send_email", "description": "Send an email.", "input_schema": {}})
    ids = _rule_ids(scan_tools(tools))
    assert "MCP005" in ids


def test_detects_exfil_url_inside_schema() -> None:
    m = fixtures.EXFIL_URL_IN_SCHEMA
    findings = scan_tool(m.name, m.description, m.input_schema)
    assert "MCP006" in _rule_ids(findings)
    assert any(f.location.startswith("input_schema") for f in findings)


def test_scan_tools_runs_over_all_fixtures() -> None:
    findings = scan_tools([t.to_dict() for t in fixtures.ALL])
    flagged = {f.tool for f in findings}
    assert fixtures.CLEAN.name not in flagged
    for m in fixtures.POISONED:
        assert m.name in flagged


def test_severity_ordering() -> None:
    assert Severity.HIGH > Severity.MEDIUM > Severity.LOW
