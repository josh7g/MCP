"""Shared data types for the scanner and guard."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

JSON = dict[str, Any]


@dataclass(frozen=True)
class ToolManifest:
    """A tool exactly as an MCP client would advertise it to a model."""

    name: str
    description: str
    input_schema: JSON

    @classmethod
    def from_dict(cls, raw: JSON) -> ToolManifest:
        return cls(
            name=str(raw["name"]),
            description=str(raw.get("description") or ""),
            input_schema=dict(raw.get("input_schema") or raw.get("inputSchema") or {}),
        )

    def to_dict(self) -> JSON:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }
