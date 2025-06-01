# BloodHound Model Context Protocol Server

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

A Model Context Protocol (MCP) server that enables Large Language Models to interact with BloodHound Community Edition data through Claude Desktop. This tool allows security professionals to query and analyze Active Directory attack paths using natural language.

## Architecture

This MCP server provides a comprehensive interface to **BloodHound Community Edition's REST API**, not just a wrapper around Cypher queries. The implementation includes:

### API Coverage
- **Complete REST API Integration**: Utilizes BloodHound CE's full REST API endpoints (`/api/v2/domains`, `/api/v2/users`, `/api/v2/groups`, etc.)
- **Structured Data Access**: Leverages purpose-built API endpoints for users, computers, groups, OUs, and GPOs
- **Advanced Functionality**: Includes ADCS analysis, graph search, shortest path algorithms, and edge composition analysis
- **Authentication**: Implements BloodHound's signature-based authentication system

### Why Not Just Cypher Queries?
While Cypher queries are powerful, this MCP goes beyond simple query execution:

- **Structured API Responses**: Returns properly formatted, paginated data with counts and metadata
- **Built-in Relationships**: Utilizes BloodHound's pre-computed relationship mappings
- **Error Handling**: Proper HTTP status code handling and meaningful error messages
- **Performance**: Leverages BloodHound's optimized endpoints rather than raw graph traversal
- **Completeness**: Access to administrative rights, sessions, group memberships, and other complex relationships through dedicated endpoints

### MCP Benefits
As a proper Model Context Protocol implementation:
- **Tool Discoverability**: LLM automatically discovers available analysis capabilities
- **Type Safety**: Strongly typed parameters and responses
- **Contextual Help**: Built-in documentation and examples for the LLM
- **Resource Access**: Provides Cypher query examples and patterns as MCP resources

## Demo

[Watch the demonstration video](https://youtu.be/eZBT0Iw9CMA)

## Features

### Core Capabilities
- **Domain Analysis**: Query domain information, users, groups, computers, and organizational structure
- **User Intelligence**: Analyze user privileges, group memberships, sessions, and administrative rights
- **Group Analysis**: Examine group memberships, controllers, and privilege relationships
- **Computer Assessment**: Investigate computer privileges, sessions, and administrative access
- **Organizational Units**: Explore OU structure and contained objects
- **Group Policy Objects**: Analyze GPO assignments and controllers
- **Certificate Services**: Investigate ADCS infrastructure and certificate templates
- **Custom Cypher Queries**: Execute advanced Neo4j queries for complex analysis
- **Graph Search**: Find shortest paths between security principals

### Advanced Features
- Natural language querying of BloodHound data
- Attack path visualization and analysis
- Privilege escalation identification
- Cross-domain relationship analysis
- Kerberoasting target identification
- Administrative relationship mapping

## Prerequisites

- **Python 3.11+**
- **uv** (Python package manager)
- **Claude Desktop**
- **BloodHound Community Edition** instance (accessible via network)
- **BloodHound data** loaded (from SharpHound, BloodHound.py, etc.)
- **BloodHound API credentials** (Token ID and Token Key)

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd bloodhound-mcp
   ```

2. **Install dependencies**
   ```bash
   uv sync
   ```

3. **Configure environment variables**
   
   Create a `.env` file in the project root:
   ```env
   BLOODHOUND_DOMAIN=your-bloodhound-instance.domain.com
   BLOODHOUND_TOKEN_ID=your-token-id
   BLOODHOUND_TOKEN_KEY=your-token-key
   ```

## Configuration

### Claude Desktop Setup

1. Open Claude Desktop and navigate to **Settings** → **Developer Tools**
2. Add the following configuration to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "bloodhound_mcp": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/your/bloodhound-mcp",
        "run",
        "main.py"
      ]
    }
  }
}
```

3. Replace `/path/to/your/bloodhound-mcp` with the actual path to your installation
4. Restart Claude Desktop

### BloodHound API Token Setup

1. Log into your BloodHound CE instance
2. Navigate to **Administration** → **API Tokens**
3. Create a new token with appropriate permissions
4. Note the Token ID and Token Key for your `.env` file

## Usage

### Getting Started

1. Start a new conversation in Claude Desktop
2. Look for the hammer icon (🔨) indicating MCP tools are available
3. Begin by asking about your domains:

```
What domains are available in BloodHound?
```

### Example Queries

**Domain Reconnaissance:**
```
Show me all users in the DOMAIN.LOCAL domain
What computers are in the domain?
Find all Domain Admins
```

**User Analysis:**
```
What administrative rights does john.doe@domain.local have?
Show me all sessions for the user administrator
What groups is this user a member of?
```

**Privilege Escalation:**
```
Find all kerberoastable users
Show me users with DCSync privileges
What computers can I RDP to from this user?
```

**Advanced Analysis:**
```
Run a cypher query to find all paths to Domain Admin
Show me the shortest path from user A to user B
Find all users with SPN set
```

## Security Considerations

### Data Sensitivity Warning
This tool processes BloodHound data through Claude Desktop, which means Active Directory information is transmitted to Anthropic's servers. **Do not use this tool with production or sensitive BloodHound data.**

### Recommended Use Cases
- **Training environments** (GOAD, DetectionLab, etc.)
- **Demonstration purposes**
- **Learning and research**
- **Non-production domain analysis**

### Best Practices
- Use isolated lab environments
- Sanitize data before analysis
- Consider local LLM alternatives for sensitive environments
- Regular token rotation for BloodHound API access

## Testing

Run the test suite to verify functionality:

```bash
# Basic functionality tests
uv run pytest tests/test_basics.py -v

# HTTP request testing
uv run pytest tests/test_bloodhound_http.py -v

# MCP tools testing
uv run pytest tests/test_mcp_tools.py -v

# Integration tests (requires running BloodHound instance)
BLOODHOUND_INTEGRATION_TESTS=1 uv run pytest tests/test_integration.py -v
```

## Contributing

Contributions are welcome! This project is designed for learning and experimentation with MCPs and BloodHound APIs.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## Roadmap

- [ ] Enhanced attack path analysis
- [ ] Azure Active Directory support
- [ ] Advanced graph visualizations
- [ ] Asset management integration
- [ ] Local LLM compatibility
- [ ] Additional ADCS attack scenarios

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **Orange Cyberdefense** for [GOAD](https://github.com/Orange-Cyberdefense/GOAD) (used for testing)
- **SpecterOps** for BloodHound Community Edition
- **@jlowin** for [FastMCP](https://github.com/jlowin/fastmcp)
- **@xpn** for MCP inspiration through the Mythic MCP project

