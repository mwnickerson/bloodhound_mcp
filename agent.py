#!/usr/bin/env python3
"""
Simple BloodHound Agent
A simplified approach that's more reliable for BloodHound analysis
"""

import asyncio
import json
import sys
from typing import Dict, List, Optional, Any
import argparse
import aiohttp

from langchain_ollama import OllamaLLM

# Import your existing MCP infrastructure
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class SimpleBloodHoundAgent:
    """Simple BloodHound agent that manually handles tool selection"""
    
    def __init__(self, mcp_server_command: List[str], 
                 ollama_model: str = "llama3.2:latest", 
                 ollama_url: str = "http://localhost:11434"):
        """
        Initialize the Simple BloodHound Agent
        
        Args:
            mcp_server_command: Command to start MCP server (e.g., ["python", "main.py"])
            ollama_model: Ollama model to use
            ollama_url: Ollama server URL
        """
        self.mcp_server_command = mcp_server_command
        self.ollama_url = ollama_url
        self.ollama_model = ollama_model
        
        # MCP session components
        self.mcp_session = None
        self.available_tools = {}
        self.stdio_context = None
        
        # LangChain LLM
        self.llm = None
        
        # HTTP session for Ollama
        self.http_session = None
        
        # Conversation history
        self.conversation_history = []
    
    async def initialize(self):
        """Initialize both MCP and LLM components"""
        print("Initializing Simple BloodHound Agent...")
        
        # Initialize HTTP session
        self.http_session = aiohttp.ClientSession()
        
        # Initialize MCP connection
        await self._initialize_mcp()
        
        # Initialize LLM
        self.llm = OllamaLLM(
            model=self.ollama_model,
            base_url=self.ollama_url
        )
        
        print(f"Simple agent ready with {len(self.available_tools)} MCP tools")
    
    async def _initialize_mcp(self):
        """Initialize MCP connection (copied from your agent.py)"""
        try:
            server_params = StdioServerParameters(
                command=self.mcp_server_command[0],
                args=self.mcp_server_command[1:] if len(self.mcp_server_command) > 1 else [],
            )
            
            print(f"Starting MCP server: {' '.join(self.mcp_server_command)}")
            
            # Use stdio_client as context manager to get streams
            self.stdio_context = stdio_client(server_params)
            read_stream, write_stream = await self.stdio_context.__aenter__()
            
            # Create client session with the streams
            self.mcp_session = ClientSession(read_stream, write_stream)
            await self.mcp_session.__aenter__()
            
            # Initialize the session
            init_result = await self.mcp_session.initialize()
            print(f"MCP server started and initialized")
            
            # Get available tools
            tools_result = await self.mcp_session.list_tools()
            self.available_tools = {tool.name: tool for tool in tools_result.tools}
            
            print(f"Connected to MCP server ({len(self.available_tools)} tools available)")
            
        except Exception as e:
            print(f"Failed to connect to MCP server: {e}")
            raise
    
    async def call_mcp_tool(self, tool_name: str, arguments: Dict = None) -> str:
        """Call an MCP tool directly"""
        try:
            if arguments is None:
                arguments = {}
                
            print(f"Calling tool: {tool_name} with args: {arguments}")
            
            result = await asyncio.wait_for(
                self.mcp_session.call_tool(tool_name, arguments),
                timeout=30.0
            )
            
            # Extract content
            if result.content:
                content_text = ""
                for content_item in result.content:
                    if hasattr(content_item, 'text'):
                        content_text += content_item.text
                
                return content_text
            else:
                return "Tool executed but returned no content"
                
        except asyncio.TimeoutError:
            return f"Tool {tool_name} timed out after 30 seconds"
        except Exception as e:
            return f"Error calling {tool_name}: {str(e)}"
    
    async def _get_domain_ids(self) -> List[Dict]:
        """Helper to get available domain IDs"""
        try:
            domains_result = await self.call_mcp_tool('get_domains', {})
            domains_data = json.loads(domains_result)
            
            if isinstance(domains_data, dict) and 'domains' in domains_data:
                return domains_data['domains']
            elif isinstance(domains_data, list):
                return domains_data
            else:
                return []
        except Exception as e:
            print(f"Error getting domains: {e}")
            return []
    
    async def _select_tool_and_execute(self, user_query: str) -> str:
        """Smart tool selection that handles domain dependencies"""
        query_lower = user_query.lower()
        
        # Domain-related queries
        if any(word in query_lower for word in ['domain', 'domains']):
            return await self.call_mcp_tool('get_domains', {})
        
        # For user/computer/group queries, we need domain_id
        if any(word in query_lower for word in ['user', 'users', 'account', 'accounts']):
            return await self._handle_domain_dependent_query('get_users', user_query)
        
        if any(word in query_lower for word in ['computer', 'computers', 'machine', 'machines', 'host', 'hosts']):
            return await self._handle_domain_dependent_query('get_computers', user_query)
        
        if any(word in query_lower for word in ['group', 'groups']):
            return await self._handle_domain_dependent_query('get_groups', user_query)
        
        # Admin/privilege queries
        if any(word in query_lower for word in ['admin', 'administrator', 'privilege', 'elevated', 'rights', 'dc sync', 'dcsync']):
            return await self._handle_domain_dependent_query('get_dc_syncers', user_query)
        
        # Session queries
        if any(word in query_lower for word in ['session', 'sessions', 'logged in', 'active']):
            # Sessions might be user-specific or general
            if any(word in query_lower for word in ['user', 'for']):
                # Need to search for specific user first
                return await self._handle_user_specific_query('get_user_sessions', user_query)
            else:
                # General session query - get from first domain
                return await self._handle_domain_dependent_query('get_computers', user_query, 
                                                               secondary_tool='get_computer_sessions')
        
        # Search queries
        if any(word in query_lower for word in ['search', 'find', 'look for']):
            # Extract search term
            words = user_query.split()
            if len(words) > 1:
                search_terms = []
                for word in words[1:]:
                    if word.lower() not in ['for', 'the', 'a', 'an']:
                        search_terms.append(word)
                search_term = ' '.join(search_terms)
                return await self.call_mcp_tool('search_objects', {'query': search_term})
        
        # Default to domains
        return await self.call_mcp_tool('get_domains', {})
    
    async def _handle_domain_dependent_query(self, tool_name: str, user_query: str, secondary_tool: str = None) -> str:
        """Handle queries that need domain_id by getting domains first"""
        try:
            # First get domains
            domains = await self._get_domain_ids()
            
            if not domains:
                return "No domains found in BloodHound database"
            
            results = []
            
            # Call the tool for each domain
            for domain in domains[:3]:  # Limit to first 3 domains to avoid overwhelming
                domain_id = domain.get('objectid') or domain.get('id') or domain.get('name')
                if domain_id:
                    domain_name = domain.get('name', domain_id)
                    print(f"Querying {tool_name} for domain: {domain_name}")
                    
                    result = await self.call_mcp_tool(tool_name, {'domain_id': domain_id})
                    
                    # If secondary tool specified, call it too
                    if secondary_tool and result and "error" not in result.lower():
                        secondary_result = await self.call_mcp_tool(secondary_tool, {'domain_id': domain_id})
                        result += f"\n\nSecondary data:\n{secondary_result}"
                    
                    results.append(f"Domain: {domain_name}\n{result}")
            
            return "\n\n" + "="*50 + "\n\n".join(results)
            
        except Exception as e:
            return f"Error executing domain-dependent query: {str(e)}"
    
    async def _handle_user_specific_query(self, tool_name: str, user_query: str) -> str:
        """Handle queries that need specific user IDs"""
        try:
            # Extract potential username from query
            words = user_query.split()
            potential_usernames = []
            
            for word in words:
                if '@' in word or '.' in word or word.lower() not in ['user', 'for', 'sessions', 'show', 'get']:
                    potential_usernames.append(word)
            
            if potential_usernames:
                # Search for the user first
                search_term = potential_usernames[0]
                search_result = await self.call_mcp_tool('search_objects', {'query': search_term, 'object_type': 'User'})
                
                # Try to extract user ID from search result
                try:
                    search_data = json.loads(search_result)
                    if isinstance(search_data, dict) and 'data' in search_data:
                        users = search_data['data']
                        if users and len(users) > 0:
                            user_id = users[0].get('objectid') or users[0].get('id')
                            if user_id:
                                return await self.call_mcp_tool(tool_name, {'user_id': user_id})
                except:
                    pass
            
            # Fallback: show sessions for first domain
            return await self._handle_domain_dependent_query('get_computers', user_query, 'get_computer_sessions')
            
        except Exception as e:
            return f"Error executing user-specific query: {str(e)}"
    
    async def analyze(self, user_input: str) -> str:
        """Analyze user input using smart tool selection + LLM"""
        try:
            print(f"\nProcessing: {user_input}")
            
            # Step 1: Smart tool selection and execution
            tool_result = await self._select_tool_and_execute(user_input)
            
            # Step 2: Use LLM to analyze the results
            analysis_prompt = f"""You are a BloodHound analysis expert specializing in offensive security.

User Question: {user_input}

BloodHound Data Retrieved:
{tool_result}

Please analyze this BloodHound data and provide:
1. A clear answer to the user's question
2. Key findings and statistics (number of users/computers/groups/etc.)
3. Any security observations or risks you notice
4. Potential attack paths or techniques if relevant
5. Actionable recommendations for both attackers and defenders

Focus on practical offensive security analysis that would be useful during a penetration test.

If the data shows multiple domains, summarize findings across all domains.

Analysis:"""

            # Get LLM analysis
            analysis = await self.llm.ainvoke(analysis_prompt)
            
            # Add to conversation history
            self.conversation_history.append({
                "user": user_input,
                "tool_result": tool_result[:1000],  # Truncate for history
                "analysis": analysis
            })
            
            return analysis
            
        except Exception as e:
            error_msg = f"Error during analysis: {str(e)}"
            print(f"Error: {error_msg}")
            return error_msg
    
    async def interactive_session(self):
        """Run an interactive session"""
        print("\n" + "="*60)
        print("Simple BloodHound Agent")
        print("="*60)
        print(f"Model: {self.ollama_model}")
        print("I can help you analyze BloodHound data using AI-powered analysis.")
        print("Type 'quit', 'exit', or 'q' to exit.")
        print("Type 'tools' to see available tools.")
        print("Type 'help' for usage examples.")
        print("Type 'history' to see recent queries.\n")
        
        while True:
            try:
                user_input = input("You: ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("Goodbye!")
                    break
                
                if user_input.lower() == 'tools':
                    print(f"\nAvailable MCP Tools ({len(self.available_tools)}):")
                    for name, tool in list(self.available_tools.items())[:15]:
                        print(f"- {name}: {tool.description}")
                    print("\nThe agent automatically selects tools based on your question.")
                    print()
                    continue
                
                if user_input.lower() == 'history':
                    print(f"\nRecent Queries ({len(self.conversation_history)}):")
                    for i, item in enumerate(self.conversation_history[-5:], 1):
                        print(f"{i}. {item['user']} -> {item['tool']}")
                    print()
                    continue
                
                if user_input.lower() == 'help':
                    print("\nExample queries:")
                    print("- What domains are in the database?")
                    print("- Show me all users")
                    print("- Find computers in the domain")
                    print("- What groups exist?")
                    print("- Show me admin users")
                    print("- Search for john.doe")
                    print("- Find active sessions\n")
                    continue
                
                if not user_input:
                    continue
                
                print("\nAgent: Analyzing...")
                response = await self.analyze(user_input)
                print(f"Agent: {response}\n")
                
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except EOFError:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(f"Error: {e}\n")
    
    async def cleanup(self):
        """Clean up resources"""
        if self.mcp_session:
            try:
                await self.mcp_session.__aexit__(None, None, None)
            except Exception as e:
                print(f"Error during MCP session cleanup: {e}")
        
        if self.stdio_context:
            try:
                await self.stdio_context.__aexit__(None, None, None)
            except Exception as e:
                print(f"Error during stdio cleanup: {e}")
        
        if self.http_session:
            try:
                await self.http_session.close()
            except Exception as e:
                print(f"Error during HTTP session cleanup: {e}")


async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Simple BloodHound Agent")
    parser.add_argument("--mcp-server", default="python", 
                       help="MCP server command (default: python)")
    parser.add_argument("--mcp-script", default="main.py", 
                       help="MCP server script (default: main.py)")
    parser.add_argument("--ollama-model", default="llama3.2:latest", 
                       help="Ollama model to use")
    parser.add_argument("--ollama-url", default="http://localhost:11434", 
                       help="Ollama URL")
    parser.add_argument("--test", action="store_true",
                       help="Run a quick test instead of interactive session")
    
    args = parser.parse_args()
    
    # Create agent
    agent = SimpleBloodHoundAgent(
        mcp_server_command=[args.mcp_server, args.mcp_script],
        ollama_model=args.ollama_model,
        ollama_url=args.ollama_url
    )
    
    try:
        # Initialize
        await agent.initialize()
        
        if args.test:
            # Quick test
            print("\nTesting with a simple query...")
            result = await agent.analyze("What domains are available in the database?")
            print(f"\nTest Result:\n{result}")
        else:
            # Interactive session
            await agent.interactive_session()
            
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        await agent.cleanup()


if __name__ == "__main__":
    asyncio.run(main())