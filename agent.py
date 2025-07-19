#!/usr/bin/env python3
"""
Simple BloodHound Agent - Domains Only
Based on your working agent code but simplified for just get_domains
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
    """Simple BloodHound agent that only handles domains"""
    
    def __init__(self, mcp_server_command: List[str], 
                 ollama_model: str = "llama3.2:latest", 
                 ollama_url: str = "http://localhost:11434"):
        """
        Initialize the Simple BloodHound Agent
        
        Args:
            mcp_server_command: Command to start MCP server (e.g., ["uv", "run", "main.py"])
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
        print("Initializing Simple BloodHound Agent (Domains Only)...")
        
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
        """Initialize MCP connection"""
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
            
            # Check if get_domains is available
            if 'get_domains' not in self.available_tools:
                print("WARNING: get_domains tool not found in MCP server!")
            else:
                print("✅ get_domains tool found")
            
            # Check if search_objects is available
            if 'search_objects' not in self.available_tools:
                print("WARNING: search_objects tool not found in MCP server!")
            else:
                print("✅ search_objects tool found")
            
            # Check if get_users is available
            if 'get_users' not in self.available_tools:
                print("WARNING: get_users tool not found in MCP server!")
            else:
                print("✅ get_users tool found")
            
        except Exception as e:
            print(f"Failed to connect to MCP server: {e}")
            raise
    
    async def call_get_domains(self) -> str:
        """Call the get_domains MCP tool"""
        try:
            print("Calling get_domains tool...")
            
            result = await asyncio.wait_for(
                self.mcp_session.call_tool("get_domains", {}),
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
            return "get_domains tool timed out after 30 seconds"
        except Exception as e:
            return f"Error calling get_domains: {str(e)}"
    
    async def call_search_objects(self, query: str, object_type: str = None, limit: int = 100) -> str:
        """Call the search_objects MCP tool"""
        try:
            print(f"Searching for objects: '{query}' (type: {object_type or 'any'})")
            
            # Build arguments
            args = {"query": query, "limit": limit, "skip": 0}
            if object_type:
                args["object_type"] = object_type
            
            result = await asyncio.wait_for(
                self.mcp_session.call_tool("search_objects", args),
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
            return f"search_objects tool timed out after 30 seconds"
        except Exception as e:
            return f"Error calling search_objects: {str(e)}"
    
    async def call_get_users(self, domain_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_users MCP tool"""
        try:
            print(f"Getting users from domain: {domain_id}")
            
            # Build arguments
            args = {"domain_id": domain_id, "limit": limit, "skip": skip}
            
            result = await asyncio.wait_for(
                self.mcp_session.call_tool("get_users", args),
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
            return f"get_users tool timed out after 30 seconds"
        except Exception as e:
            return f"Error calling get_users: {str(e)}"
    
    async def analyze_query(self, user_input: str) -> str:
        """Determine what tool to use and analyze the results"""
        try:
            print(f"\nProcessing: {user_input}")
            
            # Determine which tool to use based on user query
            query_lower = user_input.lower()
            
            # Domain-related queries
            if any(word in query_lower for word in ['domain', 'domains']) and not any(word in query_lower for word in ['user', 'users']):
                tool_result = await self.call_get_domains()
                context_type = "domains"
            
            # User-related queries
            elif any(word in query_lower for word in ['user', 'users']):
                # Need to get domains first to extract domain IDs
                domains_result = await self.call_get_domains()
                domain_ids = self._extract_domain_ids(domains_result)
                
                if domain_ids:
                    # Get users from the first domain (or all domains)
                    tool_result = await self._get_users_from_domains(domain_ids)
                    context_type = "users"
                else:
                    tool_result = "No domains found to query users from"
                    context_type = "error"
            
            # Search-related queries
            elif any(word in query_lower for word in ['search', 'find', 'look for', 'show me']):
                # Try to extract search terms and object type
                search_term, object_type = self._parse_search_query(user_input)
                tool_result = await self.smart_search(search_term, object_type)
                context_type = "search_results"
            
            # Default to domains for now
            else:
                tool_result = await self.call_get_domains()
                context_type = "domains"
            
            # Determine if this is an analysis request
            is_analysis_request = any(word in user_input.lower() for word in [
                'analyze', 'analysis', 'explain', 'structure', 'relationship', 'parent', 'child',
                'security', 'implications', 'attack', 'risk', 'assessment'
            ])
            
            if is_analysis_request:
                # Use LLM with security context for analysis
                if context_type == "domains":
                    analysis_prompt = f"""You are a BloodHound security expert with deep knowledge of Active Directory and Azure environments.

User asked: "{user_input}"

BloodHound domains data:
{tool_result}

Context: You're analyzing a multi-domain Active Directory forest. Key concepts:
- Domain trusts create attack paths between domains
- Child domains inherit from parent domains (e.g., CHILD.WRAITH.CORP is a child of WRAITH.CORP)
- Cross-domain attacks are common in AD environments
- Azure domains represent hybrid cloud environments
- Domain hierarchy affects privilege escalation opportunities

Provide expert analysis addressing the user's specific question about domain structure, relationships, or security implications.

Analysis:"""
                elif context_type == "users":
                    analysis_prompt = f"""You are a BloodHound security expert analyzing user accounts in Active Directory/Azure environments.

User asked: "{user_input}"

BloodHound users data:
{tool_result}

Context: You're analyzing user accounts in an Active Directory environment. Key concepts:
- User accounts represent potential attack targets and entry points
- Service accounts often have elevated privileges
- Disabled accounts may still have active sessions or cached credentials
- High-privilege users (Domain Admins, Enterprise Admins) are primary targets
- Azure/AzureAD users may have cross-tenant access
- User naming conventions can reveal organizational structure

IMPORTANT: Always format user data clearly with:
- User ID/Object ID
- Username/Display Name
- Domain
- Account status (enabled/disabled)
- Any privilege indicators

Provide expert analysis addressing the user's specific question about the user accounts and their security implications.

Analysis:"""
                else:  # search_results
                    analysis_prompt = f"""You are a BloodHound security expert analyzing search results.

User asked: "{user_input}"

BloodHound search results:
{tool_result}

Context: You're analyzing objects found in Active Directory/Azure environments. Key concepts:
- User accounts can have various privilege levels
- Computer accounts represent workstations and servers
- Group memberships determine access rights
- High-privilege accounts are valuable attack targets
- Service accounts often have elevated permissions

IMPORTANT: Always format search results clearly with:
- Object ID
- Type (User, Computer, Group, AZUser, etc.)
- Name/Distinguished Name
- Any other relevant properties

Provide expert analysis addressing the user's specific question about the found objects and their security implications.

Analysis:"""
            else:
                # Simple response for non-analysis questions  
                if context_type == "users":
                    analysis_prompt = f"""The user asked: "{user_input}"

BloodHound users data:
{tool_result}

Format the user data in a clean, readable list format like this example:

Found 3 users in domain:

1. JOHN.DOE@CORP.COM
   - Object ID: 12345678-1234-1234-1234-123456789012
   - Display Name: John Doe
   - Enabled: true

2. SERVICE.ACCOUNT@CORP.COM
   - Object ID: 87654321-4321-4321-4321-210987654321
   - Display Name: Service Account
   - Enabled: true

3. JANE.SMITH@CORP.COM
   - Object ID: 11111111-2222-3333-4444-555555555555
   - Display Name: Jane Smith
   - Enabled: false

Use this clean format - no tables, just numbered items with details indented below each name.

Response:"""
                elif context_type == "search_results":
                    analysis_prompt = f"""The user asked: "{user_input}"

BloodHound search results:
{tool_result}

Format the search results in a clean, readable list format like this example:

Found 2 users with "williams":

1. DWILLIAMS@PHANTOMCORP.ONMICROSOFT.COM
   - Object ID: 0F98D1D1-2F6D-4139-850A-FAF3E99A141C
   - Type: AZUser

2. JWILLIAMS@PHANTOMCORP.ONMICROSOFT.COM  
   - Object ID: 2175C4BA-A2AB-4433-942D-24BCD26BF65C
   - Type: AZUser

Use this clean format - no tables, just numbered items with details indented below each name.

Response:"""
                else:
                    analysis_prompt = f"""The user asked: "{user_input}"

Here is the BloodHound data:
{tool_result}

Answer only what the user asked. Do not add analysis unless requested.

Response:"""

            # Get LLM analysis
            analysis = await self.llm.ainvoke(analysis_prompt)
            
            # Add to conversation history
            self.conversation_history.append({
                "user": user_input,
                "tool_used": context_type,
                "tool_result": tool_result[:500],  # Truncate for history
                "analysis": analysis
            })
            
            return analysis
            
        except Exception as e:
            error_msg = f"Error during analysis: {str(e)}"
            print(f"Error: {error_msg}")
            return error_msg
    
    async def smart_search(self, search_term: str, requested_object_type: str = None) -> str:
        """Perform intelligent search with multiple attempts like Claude Desktop"""
        print(f"Starting smart search for: '{search_term}' (requested type: {requested_object_type or 'any'})")
        
        search_results = []
        attempts = []
        
        # Attempt 1: Search with requested object type (if specified)
        if requested_object_type:
            print(f"Attempt 1: Searching with type '{requested_object_type}'")
            result1 = await self.call_search_objects(search_term, requested_object_type)
            attempts.append(f"Search with type '{requested_object_type}': {result1[:100]}...")
            
            # Check if we got results
            try:
                result_data = json.loads(result1)
                if result_data.get('count', 0) > 0 or (isinstance(result_data.get('results'), list) and len(result_data['results']) > 0):
                    print("✅ Found results with specific type")
                    return result1
            except:
                pass
        
        # Attempt 2: Search with capitalized term
        capitalized_term = search_term.capitalize()
        if capitalized_term != search_term:
            print(f"Attempt 2: Trying capitalized '{capitalized_term}'")
            result2 = await self.call_search_objects(capitalized_term, requested_object_type)
            attempts.append(f"Capitalized search: {result2[:100]}...")
            
            try:
                result_data = json.loads(result2)
                if result_data.get('count', 0) > 0 or (isinstance(result_data.get('results'), list) and len(result_data['results']) > 0):
                    print("✅ Found results with capitalized term")
                    return result2
            except:
                pass
        
        # Attempt 3: General search without object type filter (this often finds more results)
        print(f"Attempt 3: General search without type filter")
        result3 = await self.call_search_objects(search_term)  # No object type
        attempts.append(f"General search: {result3[:100]}...")
        
        try:
            result_data = json.loads(result3)
            if result_data.get('count', 0) > 0 or (isinstance(result_data.get('results'), list) and len(result_data['results']) > 0):
                print("✅ Found results with general search")
                return result3
        except:
            pass
        
        # Attempt 4: Try uppercase version
        upper_term = search_term.upper()
        if upper_term != search_term and upper_term != capitalized_term:
            print(f"Attempt 4: Trying uppercase '{upper_term}'")
            result4 = await self.call_search_objects(upper_term)
            attempts.append(f"Uppercase search: {result4[:100]}...")
            
            try:
                result_data = json.loads(result4)
                if result_data.get('count', 0) > 0 or (isinstance(result_data.get('results'), list) and len(result_data['results']) > 0):
                    print("✅ Found results with uppercase term")
                    return result4
            except:
                pass
        
        # If all attempts failed, return a summary
        print("❌ No results found in any search attempt")
        failed_summary = f"""Search attempts for '{search_term}':
{chr(10).join(attempts)}

No results found with any variation or object type filter."""
        
        return failed_summary
    
    def _parse_search_query(self, user_input: str) -> tuple:
        """Parse user input to extract search term and object type"""
        query_lower = user_input.lower()
        
        # Determine object type from keywords
        object_type = None
        if any(word in query_lower for word in ['user', 'users', 'account', 'accounts']):
            object_type = "User"
        elif any(word in query_lower for word in ['computer', 'computers', 'machine', 'machines', 'host', 'hosts']):
            object_type = "Computer"
        elif any(word in query_lower for word in ['group', 'groups']):
            object_type = "Group"
        elif any(word in query_lower for word in ['domain', 'domains']):
            object_type = "Domain"
        
        # Extract search term - much simpler approach
        import re
        
        # Look for quoted strings first
        quoted_match = re.search(r'"([^"]*)"', user_input)
        if quoted_match:
            search_term = quoted_match.group(1)
        else:
            # Remove common words and extract the actual search target
            words = user_input.split()
            
            # More comprehensive skip words
            skip_words = {
                'can', 'you', 'please', 'find', 'search', 'look', 'for', 'show', 'me', 'get',
                'any', 'all', 'the', 'a', 'an', 'that', 'contain', 'contains', 'containing', 
                'with', 'named', 'called', 'in', 'bloodhound', 'user', 'users', 'computer', 
                'computers', 'group', 'groups', 'domain', 'domains', 'machine', 'machines', 
                'host', 'hosts', 'account', 'accounts'
            }
            
            # Extract meaningful words
            meaningful_words = []
            for word in words:
                if word.lower() not in skip_words and len(word) > 1:
                    meaningful_words.append(word)
            
            # Take the first meaningful word as the search term
            search_term = meaningful_words[0] if meaningful_words else 'admin'
        
        print(f"DEBUG: Extracted search term: '{search_term}' (type: {object_type}) from: '{user_input}'")
        return search_term, object_type
    
    def _extract_domain_ids(self, domains_result: str) -> list:
        """Extract domain IDs from get_domains result"""
        try:
            import json
            result_data = json.loads(domains_result)
            domains = result_data.get('domains', [])
            domain_ids = []
            
            for domain in domains:
                if isinstance(domain, dict) and 'objectid' in domain:
                    domain_ids.append(domain['objectid'])
                elif isinstance(domain, dict) and 'id' in domain:
                    domain_ids.append(domain['id'])
            
            print(f"DEBUG: Extracted {len(domain_ids)} domain IDs: {domain_ids}")
            return domain_ids
        except Exception as e:
            print(f"Error extracting domain IDs: {e}")
            return []
    
    async def _get_users_from_domains(self, domain_ids: list, limit: int = 50) -> str:
        """Get users from one or more domains"""
        try:
            all_users = []
            total_count = 0
            
            # For now, just get users from the first domain to avoid overwhelming output
            domain_id = domain_ids[0]
            print(f"Getting users from domain: {domain_id}")
            
            users_result = await self.call_get_users(domain_id, limit=limit)
            
            # Try to parse and format the result
            import json
            try:
                result_data = json.loads(users_result)
                users = result_data.get('users', [])
                count = result_data.get('count', 0)
                
                formatted_result = {
                    "message": f"Found {count} users in domain {domain_id}",
                    "users": users,
                    "count": count,
                    "domain_id": domain_id
                }
                return json.dumps(formatted_result)
            except:
                # If parsing fails, return the raw result
                return users_result
                
        except Exception as e:
            return f"Error getting users from domains: {str(e)}"
    
    async def interactive_session(self):
        """Run an interactive session with domains and search capabilities"""
        print("\n" + "="*60)
        print("🩸 BloodHound Agent - Domains, Users & Search")
        print("="*60)
        print(f"Model: {self.ollama_model}")
        print("I can help you analyze BloodHound domains, users, and search for objects.")
        print("Type 'quit', 'exit', or 'q' to exit.")
        print("Type 'help' for usage examples.")
        print("Type 'history' to see recent queries.\n")
        
        while True:
            try:
                user_input = input("BloodHound> ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("Goodbye!")
                    break
                
                if user_input.lower() == 'history':
                    print(f"\nRecent Queries ({len(self.conversation_history)}):")
                    for i, item in enumerate(self.conversation_history[-5:], 1):
                        tool_used = item.get('tool_used', 'unknown')
                        print(f"{i}. {item['user']} -> {tool_used}")
                    print()
                    continue
                
                if user_input.lower() == 'help':
                    print("\nExample queries:")
                    print("\nDomain queries:")
                    print("- What domains are in the database?")
                    print("- List all domains")
                    print("- Analyze the domain structure")
                    print("\nUser queries:")
                    print("- Show me all users")
                    print("- List users in the domain")
                    print("- What users are available?")
                    print("- Analyze user accounts")
                    print("\nSearch queries:")
                    print("- Search for admin")
                    print("- Find user john.doe")
                    print("- Look for computers named DC")
                    print("- Show me groups with 'admin' in the name")
                    print("- Search for 'service' users")
                    print("- Find computers in the domain\n")
                    continue
                
                if not user_input:
                    continue
                
                print("\nAnalyzing...")
                response = await self.analyze_query(user_input)
                print(f"\n{response}\n")
                
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
    parser = argparse.ArgumentParser(description="Simple BloodHound Agent - Domains, Users & Search")
    parser.add_argument("--mcp-command", default="uv", 
                       help="MCP server command (default: uv)")
    parser.add_argument("--mcp-args", default="run,main.py", 
                       help="MCP server args, comma-separated (default: run,main.py)")
    parser.add_argument("--ollama-model", default="llama3.2:latest", 
                       help="Ollama model to use")
    parser.add_argument("--ollama-url", default="http://localhost:11434", 
                       help="Ollama URL")
    parser.add_argument("--test", action="store_true",
                       help="Run a quick test instead of interactive session")
    
    args = parser.parse_args()
    
    # Build MCP command
    mcp_command = [args.mcp_command] + args.mcp_args.split(',')
    
    # Create agent
    agent = SimpleBloodHoundAgent(
        mcp_server_command=mcp_command,
        ollama_model=args.ollama_model,
        ollama_url=args.ollama_url
    )
    
    try:
        # Initialize
        await agent.initialize()
        
        if args.test:
            # Quick test
            print("\nTesting with domain, user, and search queries...")
            
            # Test domains
            result1 = await agent.analyze_query("What domains are available?")
            print(f"\nDomains Test Result:\n{result1}\n")
            
            # Test search
            result2 = await agent.analyze_query("Search for admin users")
            print(f"\nSearch Test Result:\n{result2}")
            
            # Test users
            result3 = await agent.analyze_query("Show me all users")
            print(f"\nUsers Test Result:\n{result3}")
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