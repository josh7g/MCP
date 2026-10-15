"""Guard policy and sanitization tests."""

from __future__ import annotations

import pytest

from mcp_scan import fixtures
from mcp_scan.guard import (
    Action,
    GuardPolicy,
    assert_no_hidden_text,
    guard_tools,
    sanitize_description,
)
from mcp_scan.scanner import decode_tag_characters


def _decision(name: str, decisions: list) -> object:
    return next(d for d in decisions if d.tool == name)


def test_clean_tool_is_allowed_unchanged() -> None:
    decisions = guard_tools(fixtures.ALL)
    d = _decision(fixtures.CLEAN.name, decisions)
    assert d.action == Action.ALLOW
    assert d.sanitized_description == fixtures.CLEAN.description


def test_high_severity_tool_is_blocked() -> None:
    decisions = guard_tools(fixtures.ALL)
    d = _decision(fixtures.EMBEDDED_INSTRUCTION.name, decisions)
    assert d.action == Action.BLOCK


def test_sanitize_strips_hidden_text_and_defangs_markup() -> None:
    cleaned = sanitize_description(fixtures.EMBEDDED_INSTRUCTION.description)
    assert "<IMPORTANT>" not in cleaned
    assert "(IMPORTANT)" in cleaned
    assert decode_tag_characters(cleaned) == ""


def test_sanitize_removes_concealed_instruction() -> None:
    cleaned = sanitize_description(fixtures.HIDDEN_TEXT.description)
    assert decode_tag_characters(cleaned) == ""
    assert cleaned == "Look up a customer profile by ID."


def test_policy_thresholds_are_configurable() -> None:
    from mcp_scan.scanner import Severity

    lenient = GuardPolicy(block_at=Severity.HIGH, sanitize_at=Severity.HIGH)
    assert lenient.action_for(Severity.MEDIUM) == Action.ALLOW
    strict = GuardPolicy(block_at=Severity.MEDIUM, sanitize_at=Severity.LOW)
    assert strict.action_for(Severity.MEDIUM) == Action.BLOCK
    assert strict.action_for(None) == Action.ALLOW


def test_assert_no_hidden_text_raises_on_concealment() -> None:
    with pytest.raises(ValueError, match="hidden text"):
        assert_no_hidden_text(fixtures.HIDDEN_TEXT.description)
    assert_no_hidden_text(fixtures.CLEAN.description)  # does not raise
