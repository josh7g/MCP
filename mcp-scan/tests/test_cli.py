"""CLI smoke tests."""

from __future__ import annotations

import json

from mcp_scan import fixtures
from mcp_scan.cli import main


def test_demo_exits_nonzero_on_high(capsys) -> None:  # type: ignore[no-untyped-def]
    code = main(["--demo"])
    out = capsys.readouterr().out
    assert code == 1
    assert "lookup_customer" in out


def test_json_output_is_valid(capsys) -> None:  # type: ignore[no-untyped-def]
    main(["--demo", "--json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert any(item["rule_id"] == "MCP001" for item in data)


def test_manifest_file_is_scanned(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "tools.json"
    path.write_text(json.dumps({"tools": [fixtures.CLEAN.to_dict()]}), encoding="utf-8")
    code = main([str(path)])
    assert code == 0
    assert "No findings." in capsys.readouterr().out


def test_guard_output_lists_decisions(capsys) -> None:  # type: ignore[no-untyped-def]
    main(["--demo", "--guard"])
    out = capsys.readouterr().out
    assert "Guard decisions:" in out
    assert "block" in out
