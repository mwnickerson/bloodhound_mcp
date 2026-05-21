# BloodHound MCP

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A Model Context Protocol (MCP) server that connects LLMs to BloodHound Community Edition. Ask questions in natural language, get attack path analysis, run Cypher queries, and explore Active Directory, Azure/Entra ID, and OpenGraph environments — all from your AI assistant.

## Demo

[Watch the demonstration video](https://youtu.be/eZBT0Iw9CMA) *(updated demo coming soon)*

---

## How It Works

The server exposes BloodHound CE's REST API and Neo4j graph through a set of **13 composite MCP tools**, **10 reference resources**, and a **system prompt** tuned for offensive security analysis.

### Composite Tools

Each tool uses an `info_type` parameter to select what data is returned, keeping the tool surface small and token-efficient:

| Tool | `info_type` Options |
|------|---------------------|
| `domain_info` | `list`, `info`, `users`, `groups`, `computers`, `ous`, `gpos`, `dc_syncers`, `foreign_admins`, `foreign_group_members`, `linked_gpos`, `search` |
| `user_info` | `info`, `sessions`, `memberships`, `admin_rights`, `rdp_rights`, `dcom_rights`, `ps_remote_rights`, `sql_admin_rights`, `constrained_delegation`, `controllables`, `controllers` |
| `group_info` | `info`, `members`, `memberships`, `admin_rights`, `rdp_rights`, `dcom_rights`, `ps_remote_rights`, `controllers`, `controllables` |
| `computer_info` | `info`, `sessions`, `local_admins`, `rdp_rights`, `dcom_rights`, `ps_remote_rights`, `sql_admins`, `constrained_delegation`, `controllables`, `controllers` |
| `ou_info` | `info`, `users`, `groups`, `computers`, `gpos` |
| `gpo_info` | `info`, `controllers` |
| `graph_analysis` | `shortest_path`, `edge_composition`, `search` |
| `adcs_info` | `templates`, `esc_paths` |
| `cypher_query` | `run`, `saved_list`, `saved_get` |
| `data_quality` | `stats`, `platform_list`, `platform_info` |
| `asset_groups` | `list`, `members`, `custom_selectors` |
| `custom_nodes` | `list`, `get`, `create`, `update`, `delete`, `validate_icon`, `extension_list`, `extension_upsert`, `extension_delete`, `extension_edges` |
| `file_upload` | `upload`, `start_job`, `upload_to_job`, `end_job` |

### Resources

Reference material the LLM loads on demand — no extra API calls:

| Resource URI | Contents |
|---|---|
| `bloodhound://cypher/reference` | Cypher syntax, schema, property names, patterns |
| `bloodhound://cypher/offensive-queries` | Battle-tested templates: DCSync, Kerberoasting, GPO abuse, delegation, ADCS, shadow credentials, NTLM relay, and more |
| `bloodhound://guides/ad` | AD node types and relationships quick reference |
| `bloodhound://guides/ad-methodology` | Full AD attack methodology and workflow |
| `bloodhound://guides/azure` | Azure/Entra ID analysis quick reference |
| `bloodhound://guides/azure-methodology` | Full Azure attack chains |
| `bloodhound://guides/adcs` | ADCS ESC1–ESC13 quick reference |
| `bloodhound://guides/adcs-methodology` | Detailed ESC analysis and exploitation |
| `bloodhound://opengraph/guide` | Custom node schema design and best practices |
| `bloodhound://opengraph/examples` | SQL Server and Web App OpenGraph examples |

### System Prompt

The `bloodhound_assistant` prompt includes behavioral rules that guide the LLM:

- Load the offensive query library before writing Cypher for any attack scenario
- Never draw privilege conclusions without checking group memberships and `admincount`
- Respect BloodHound's property naming conventions (`hasspn`, `enabled`, `admincount` — all lowercase)
- Handle uppercase name storage (`DOMAIN ADMINS@CORP.LOCAL`) correctly in filters
- Follow proper DCSync and GPO edge traversal patterns

---

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/)
- BloodHound Community Edition instance with data loaded
- BloodHound API credentials (Token ID + Token Key)

---

## Installation

```bash
git clone https://github.com/mwnickerson/bloodhound_mcp.git
cd bloodhound-mcp
uv sync
```

Copy the example environment file and fill in your BloodHound API token:

```bash
cp .env.example .env
```

Required values:

```env
BLOODHOUND_DOMAIN=your-bloodhound-instance.domain.com
BLOODHOUND_TOKEN_ID=your-token-id
BLOODHOUND_TOKEN_KEY=your-token-key
```

The server defaults to `https` on port `443`. Override if needed:

```env
BLOODHOUND_PORT=8080
BLOODHOUND_SCHEME=http
BLOODHOUND_VERIFY_TLS=true
```

---

## Configuration

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "bloodhound_mcp": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/bloodhound-mcp",
        "run",
        "main.py"
      ]
    }
  }
}
```

### Claude Code

Add to `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "bloodhound_mcp": {
      "type": "stdio",
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/bloodhound-mcp",
        "run",
        "main.py"
      ]
    }
  }
}
```

### OpenAI Codex CLI

Add to `~/.codex/config.toml` (or `.codex/config.toml` for project-scoped config):

```toml
[mcp_servers.bloodhound_mcp]
command = "uv"
args = ["--directory", "/path/to/bloodhound-mcp", "run", "main.py"]
```

Since the server loads credentials from `.env` automatically, no `env` block is needed. If you prefer to pass them explicitly:

```toml
[mcp_servers.bloodhound_mcp]
command = "uv"
args = ["--directory", "/path/to/bloodhound-mcp", "run", "main.py"]

[mcp_servers.bloodhound_mcp.env]
BLOODHOUND_DOMAIN = "your-bloodhound-instance.domain.com"
BLOODHOUND_TOKEN_ID = "your-token-id"
BLOODHOUND_TOKEN_KEY = "your-token-key"
```

The MCP server uses stdio by default, so it does not listen on a TCP port. `BLOODHOUND_PORT` is only the upstream BloodHound API port.

### MCP Inspector

- **Command:** `uv`
- **Args:** `--directory /path/to/bloodhound-mcp run main.py`

### BloodHound API Token

1. Log into BloodHound CE
2. Navigate to **Administration** → **API Tokens**
3. Create a new token and copy the Token ID and Token Key into your `.env`

---

## Usage

### Example Queries

**Reconnaissance:**
```
What domains are in BloodHound?
Show me all Domain Admins in CORP.LOCAL
Find all kerberoastable users
Which computers have unconstrained delegation?
```

**User and Group Analysis:**
```
What admin rights does jsmith@corp.local have?
Show me all sessions for the administrator account
What groups is this user a member of?
Who controls the IT ADMINS group?
```

**Attack Path Analysis:**
```
Find the shortest path from jsmith@corp.local to Domain Admins
Who has DCSync rights in the domain?
Show me all GPO abuse paths
Find ADCS ESC1 paths in the domain
```

**Custom Cypher:**
```
Run a Cypher query to find all users with SPN set and admincount=1
Find all computers where DOMAIN USERS can RDP
```

---

## OpenGraph Support

BloodHound 8.0+ supports custom node types via OpenGraph, letting you model non-AD infrastructure (cloud resources, databases, custom assets) in the same graph as Active Directory.

The `custom_nodes` tool handles legacy CRUD operations on node type display configurations through `/api/v2/custom-nodes`. For BloodHound v9.0.0+ instances with OpenGraph extension management enabled, the same composite tool also supports `/api/v2/extensions` and `/api/v2/extensions-edges` via `extension_list`, `extension_upsert`, `extension_delete`, and `extension_edges`.

Use the `bloodhound://opengraph/guide` and `bloodhound://opengraph/examples` resources for schema design and Cypher patterns. For structured OpenGraph schemas, upsert the extension schema first, then ingest collection data with `file_upload`.

> Requires BloodHound CE 8.0 or later.
> OpenGraph extension management requires BloodHound 9.0.0+ and the corresponding feature flag to be enabled.

---

## Security Considerations

BloodHound data processed through this tool is transmitted to your LLM provider's servers. **Do not use this with production AD data unless you have assessed that risk.**

Recommended use cases:
- Lab environments (GOAD, DetectionLab, custom ranges)
- Training and certification prep
- Research and tool development
- Non-production domain analysis

Best practices:
- Rotate BloodHound API tokens regularly
- Use a read-only API token where possible
- Consider a local LLM bridge for sensitive environments

---

## Testing

```bash
# Full test suite
uv run pytest

# Specific modules
uv run pytest tests/test_main_mcp_tools.py -v
uv run pytest tests/test_bloodhound_api.py -v

# Integration tests (requires a live BloodHound instance)
BLOODHOUND_INTEGRATION_TESTS=1 uv run pytest tests/test_integration.py -v
```

---

## Roadmap

- [ ] Direct Neo4j access mode (bypass REST API for complex graph traversal)
- [ ] Enhanced Azure/Entra ID tooling
- [ ] Improved ADCS attack path coverage
- [ ] Additional OpenGraph examples and templates

---

## Contributing

Contributions are welcome. Open an issue to discuss significant changes before submitting a PR.

1. Fork the repo
2. Create a feature branch
3. Add tests for new functionality
4. Run `uv run pytest` and confirm everything passes
5. Submit a pull request

---

## Acknowledgments

- **SpecterOps** for [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound)
- **Orange Cyberdefense** for [GOAD](https://github.com/Orange-Cyberdefense/GOAD) (used for testing)
- **@jlowin** for [FastMCP](https://gofastmcp.com)
- **@xpn** for MCP inspiration via the Mythic MCP project

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.
