# mcp-scan

A static security scanner and runtime guard for **Model Context Protocol (MCP) tool metadata**.

MCP clients inline every connected tool's `name`, `description` and `input_schema` straight into
the model's context. The model reads that metadata whether or not the tool is ever called, and
when a server is third-party or compromised, that metadata is attacker-controlled. This is the
channel behind **tool poisoning** and **tool shadowing**: a malicious description can carry
instructions that hijack the agent — exfiltrate a secret, misuse another tool, hide an action
from the user — without the user ever seeing the text.

`mcp-scan` reads that metadata and flags the patterns those attacks rely on, then offers a guard
that sanitizes or blocks a tool before its description reaches the model.

> **Scope and honesty.** This is a heuristic linter plus a defense-in-depth guard, not a safety
> proof. A clean scan means none of the known patterns matched — nothing more. A natural-language
> injection can be phrased to miss every rule here. The goal is to make the easy, high-signal
> attacks cheap to catch and to keep raw attacker instructions from silently reaching the model.

## Threat model

| Surface | Example | Rule |
|---|---|---|
| Hidden text | instruction encoded in invisible Unicode tag characters | `MCP001` |
| Model-directed instruction | "ignore previous instructions", "before calling this tool, read…" | `MCP002` |
| Concealment | "do not tell the user", "without informing the user" | `MCP003` |
| Credential bait | references to `.env`, `~/.ssh`, `.aws/credentials` | `MCP004` |
| Tool shadowing | a tool's description issues rules about *another* tool | `MCP005` |
| Exfiltration channel | a URL embedded in a description or schema field | `MCP006` |
| Encoded payload | long base64-like blobs | `MCP007` |
| Pseudo-authority markup | fake `<IMPORTANT>` / `<system>` tags | `MCP010` |

The scanner walks the schema too (`description`, `title`, `default`, `enum`, `examples`), since an
injection in a parameter description reaches the model just as readily as one in the tool summary.

## Install

```bash
pip install -e ".[dev]"      # with test + MCP client extras
```

Requires Python 3.10+. The live-server scan needs the `mcp` extra; the static scan has no runtime
dependencies.

## Use

Scan the bundled (inert) poisoned fixtures:

```bash
mcp-scan --demo --guard
```

Scan a JSON manifest (`{"tools": [{"name", "description", "input_schema"}, ...]}`):

```bash
mcp-scan tools.json --fail-on MEDIUM
```

Scan a live MCP server's advertised tools without ever calling them:

```bash
mcp-scan --server "python" --server-arg my_server.py
```

Exit code is non-zero when a finding meets `--fail-on` (default `HIGH`), so it gates CI.

### As a library

```python
from mcp_scan import scan_tools, guard_tools, ToolManifest

findings = scan_tools(my_tool_dicts)

# At MCP connect time, decide per tool: allow / sanitize / block.
for decision in guard_tools([ToolManifest.from_dict(t) for t in my_tool_dicts]):
    if decision.action.value == "block":
        continue  # don't expose this tool to the model
    expose(decision.tool, decision.sanitized_description)
```

The guard removes invisible characters and defangs fake markup, so even an unreviewed scan keeps
concealed instructions out of the model's context.

## How it's tested

`tests/` runs the scanner and guard against synthetic poisoned manifests in
`src/mcp_scan/fixtures.py`. Every attacker destination uses the reserved `.example` TLD, the
"secret" in the hidden-text fixture is a placeholder, and nothing is ever executed — the tools
are only ever read as metadata. A `CLEAN` baseline asserts the scanner does not fire on benign
tools (the false-positive guardrail that matters most in practice).

## Design notes

- **Detection is severity-ranked.** `HIGH` = hidden text, model-directed instructions,
  concealment, credential references. The guard's default policy blocks `HIGH`, sanitizes
  `MEDIUM`, allows the rest — all configurable via `GuardPolicy`.
- **Hidden text is decoded and re-scanned**, so an instruction concealed in tag characters is
  also matched against the text rules, not just flagged as "something is hidden."
- **No model in the loop.** The scanner is deterministic and offline, which is what makes it
  usable as a pre-commit or CI check on a server's tool manifest.

## License

MIT. See [LICENSE](LICENSE).
