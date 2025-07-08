# BloodHound MCP Server

An **experimental** Model Context Protocol (MCP) server that provides AI tools access to BloodHound Community Edition data for Active Directory security analysis.

> **WARNING**: This is for learning and research in **LAB ENVIRONMENTS ONLY**. Never use with production data. 
> 
> **NEW**: Now supports local LLM analysis via Ollama!

## Features

### Core Capabilities
- **Complete BloodHound API Integration**: 80+ MCP tools for comprehensive AD analysis
- **Cypher Query Support**: Execute custom queries against the BloodHound graph database
- **Multi-Domain Support**: Handle complex enterprise environments
- **Certificate Services Analysis**: Specialized ADCS attack detection tools
- **Local LLM Support**: Privacy-focused analysis using Ollama (no data leaves your network)

### Analysis Types
- Domain enumeration and reconnaissance
- Attack path discovery and analysis
- Privilege escalation identification
- Lateral movement opportunities
- Kerberoasting and AS-REP roasting targets
- Certificate template vulnerabilities (ESC1-10)
- Trust relationship analysis
- GPO abuse detection

## Architecture Options

### Option 1: Claude Desktop (Cloud)
Uses Claude Desktop with MCP for cloud-based analysis.

**WARNING**: BloodHound data is sent to Anthropic's servers. Use only with lab data.

### Option 2: Local Ollama Agent (Recommended)
Fully local analysis using Ollama models - no data leaves your network.

**Privacy Benefit**: All analysis happens locally on your machine.

## Quick Start

### Prerequisites
- Python 3.11+
- BloodHound Community Edition running
- Either Claude Desktop OR Ollama installed

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/bloodhound-mcp.git
cd bloodhound-mcp

# Install dependencies
uv sync
# OR
pip install -r requirements.txt

# Configure BloodHound connection
cp .env.example .env
# Edit .env with your BloodHound credentials
```

### Option 1: Claude Desktop Setup

1. **Configure Claude Desktop MCP**:
   ```json
   {
     "mcpServers": {
       "bloodhound": {
         "command": "uv",
         "args": ["run", "python", "main.py"]
       }
     }
   }
   ```

2. **Start using in Claude Desktop**:
   ```
   "What domains are available in BloodHound?"
   "Find all users with admin rights"
   "Show me attack paths to Domain Admin"
   ```

### Option 2: Local Ollama Agent (NEW)

1. **Install and Start Ollama**:
   ```bash
   # Install Ollama
   curl -fsSL https://ollama.ai/install.sh | sh
   
   # Pull recommended models
   ollama pull deepseek-r1:latest    # Best for complex reasoning
   ollama pull llama3.2:latest       # Faster responses
   ```

2. **Run the Local Agent**:
   ```bash
   # Interactive model selection
   python agent.py
   
   # Or specify model directly
   python agent.py --ollama-model llama3.2:latest
   
   # List available models
   python agent.py --list-models
   ```

3. **Example Agent Usage**:
   ```
   You: What domains are in the database?
   Agent: I found 6 domains in your BloodHound database:
   
   - PHANTOM.CORP (active-directory) - Collected
   - GHOST.CORP (active-directory) - Collected  
   - REVENANT.CORP (active-directory) - Not Collected (WARNING)
   - WRAITH.CORP (active-directory) - Collected
   - CHILD.WRAITH.CORP (active-directory) - Not Collected (WARNING)
   - PHANTOM CORP (azure) - Collected
   
   Security observations:
   - 4/6 domains have been collected
   - 2 domains lack data collection (potential blind spots)
   - Mixed AD and Azure environment detected
   ```

## Agent Commands

### Basic Usage
```bash
# Start with interactive model selection
python agent.py

# Use specific model
python agent.py --ollama-model deepseek-r1:latest

# Different MCP server location
python agent.py --mcp-script /path/to/main.py

# Custom Ollama URL
python agent.py --ollama-url http://other-host:11434
```

### Agent Features
- **Interactive Model Selection**: Choose from available Ollama models
- **Smart Tool Detection**: Automatically uses appropriate BloodHound tools
- **Security-Focused Analysis**: Specialized prompts for offensive security
- **Conversation Memory**: Maintains context across queries
- **Graceful Error Handling**: Continues operation if individual tools fail

### Recommended Models

| Model | Best For | Speed | Reasoning Quality |
|-------|----------|-------|-------------------|
| `deepseek-r1:latest` | Complex attack path analysis | Slow | Excellent |
| `llama3.2:latest` | Quick domain enumeration | Fast | Good |
| `qwen2.5:7b` | Lightweight testing | Very Fast | Adequate |

## Environment Configuration

Create a `.env` file with your BloodHound settings:

```env
# BloodHound Connection
BLOODHOUND_URL=http://localhost:8080
BLOODHOUND_USERNAME=admin
BLOODHOUND_PASSWORD=your_password

# Optional: Custom Ollama settings for agent
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=deepseek-r1:latest
```

## Available Tools

The MCP server provides 80+ tools organized by category:

### Domain Operations
- `get_domains` - List all domains
- `get_users` - Get users from domain
- `get_groups` - Get groups from domain  
- `get_computers` - Get computers from domain
- `search_objects` - Search across all object types

### Advanced Analysis
- `get_shortest_path` - Find attack paths between objects
- `run_cypher_query` - Execute custom Cypher queries
- `get_user_admin_rights` - Find admin privileges
- `get_dc_syncers` - Identify DCSync capabilities

### Certificate Services (ADCS)
- `get_cert_template_info` - Analyze certificate templates
- `get_enterprise_ca_info` - Examine CA configuration
- `get_cert_template_controllers` - Find template control rights

### Security Analysis
- `get_foreign_admins` - Cross-domain administrative access
- `get_constrained_delegation_rights` - Delegation abuse opportunities
- `get_kerberoastable_users` - SPN-enabled accounts

## Example Queries

### Agent Mode (Recommended)
```
You: Find all kerberoastable users
You: Show me attack paths to Domain Admin
You: What certificate templates are vulnerable?
You: Which computers have unconstrained delegation?
You: Find cross-domain admin accounts
```

### Claude Desktop Mode
```
"Analyze the attack surface of CORP.LOCAL domain"
"Find the shortest path from user john.doe to Domain Admin"
"What are the most dangerous certificate templates?"
"Show me all users with DCSync rights"
"Identify lateral movement opportunities"
```

### Advanced Analysis
```
"Run a cypher query to find all paths to Domain Admin"
"Show me the shortest path from user A to user B"
"Find all users with SPN set and admin rights"
"Analyze trust relationships between domains"
```

## Security Considerations

### Data Sensitivity Warning
- **Claude Desktop Mode**: BloodHound data is transmitted to Anthropic's servers
- **Ollama Agent Mode**: All data remains local on your machine ✅

### Recommended Use Cases
- **Training environments** (GOAD, DetectionLab, etc.)
- **Demonstration purposes**
- **Learning and research**
- **Non-production domain analysis**

### Best Practices
- Use isolated lab environments
- Sanitize data before analysis (Claude Desktop mode)
- **Use Ollama agent for sensitive environments**
- Regular token rotation for BloodHound API access

## Development Status

### Completed (Phase 3)
- MCP server with 80+ BloodHound tools
- Full BloodHound API integration
- Cypher query support
- Local Ollama agent implementation
- Interactive model selection
- Graceful error handling
- Security-focused analysis prompts

### In Progress
- Advanced conversation memory
- Smart tool selection optimization
- Performance benchmarking
- Extended ADCS analysis

### Planned Features
- Batch analysis capabilities
- Custom report generation
- Multi-environment support
- Advanced caching system
- Graph visualization integration

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

# Test the local agent
python debug_tools.py
```

## Performance Notes

### Ollama Model Performance (M1 Mac 16GB RAM)
- **deepseek-r1:latest**: 30-180s (excellent reasoning)
- **llama3.2:latest**: 5-15s (good balance)
- **qwen2.5:7b**: 2-8s (quick responses)

### Optimization Tips
- Use faster models for simple queries
- Cache domain listings for repeated analysis
- Increase timeout for complex reasoning models
- Consider model selection based on query complexity

## Contributing

Contributions are welcome! This project is designed for learning and experimentation with MCPs and BloodHound APIs.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## Troubleshooting

### Common Issues

**Agent won't start:**
```bash
# Check Ollama is running
ollama list

# Verify BloodHound connectivity  
curl -u admin:password http://localhost:8080/api/v2/domains
```

**Model timeout errors:**
```bash
# Use faster model
python agent.py --ollama-model llama3.2:latest

# Or increase patience for reasoning models
# (timeout is automatically set to 180s for deepseek-r1)
```

**MCP tools not found:**
```bash
# Debug available tools
python debug_tools.py

# Check MCP server logs
python main.py
```

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **Orange Cyberdefense** for [GOAD](https://github.com/Orange-Cyberdefense/GOAD) (used for testing)
- **SpecterOps** for BloodHound Community Edition
- **@jlowin** for [FastMCP](https://github.com/jlowin/fastmcp)
- **Ollama** team for local LLM infrastructure
- **Anthropic** for Claude and MCP protocol

## TODO
- [ ] Write better model evaluations (possibly look into using strikes from Dreadnode)
