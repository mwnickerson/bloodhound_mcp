#!/usr/bin/env python3
"""
BloodHound MCP Agent
An agent that uses MCP to interact with BloodHound data via the MCP server
"""

import asyncio
import json
import sys
from typing import Dict, List, Optional, Any
import argparse
import aiohttp

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class BloodHoundMCPAgent:
    """
    An agent that uses MCP to query BloodHound data and provides LLM-powered analysis
    """
    
    def __init__(self, mcp_server_command: List[str], 
                 ollama_model: str = "deepseek-r1:latest", ollama_url: str = "http://localhost:11434"):
        """
        Initialize the BloodHound MCP Agent
        
        Args:
            mcp_server_command: Command to start the MCP server (e.g., ["python", "main.py"])
            ollama_model: Ollama model to use
            ollama_url: Ollama server URL
        """
        self.mcp_server_command = mcp_server_command
        self.ollama_url = ollama_url
        self.ollama_model = ollama_model
        self.conversation_history = []
        self.mcp_session = None
        self.available_tools = {}
        self.http_session = None
        self.stdio_context = None
        
    async def initialize(self):
        """Initialize connections to MCP server and Ollama"""
        print("Initializing BloodHound MCP Agent...")
        
        # Create HTTP session
        self.http_session = aiohttp.ClientSession()
        
        # Connect to MCP server
        try:
            # The StdioServerParameters will automatically start the MCP server process
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
            print(f"Debug info: {type(e).__name__}: {str(e)}")
            print(f"Command attempted: {' '.join(self.mcp_server_command)}")
            return False
            
        # Test Ollama connection
        try:
            # Check if Ollama is running by listing models
            async with self.http_session.get(f"{self.ollama_url}/api/tags") as response:
                if response.status == 200:
                    models_data = await response.json()
                    available_models = [model['name'] for model in models_data.get('models', [])]
                    
                    # Check for exact match first, then check if model name is contained in any available model
                    model_found = False
                    actual_model_name = self.ollama_model
                    
                    if self.ollama_model in available_models:
                        model_found = True
                    else:
                        # Try to find a partial match (e.g., "deepseek-r1" matches "deepseek-r1:latest")
                        base_model_name = self.ollama_model.split(':')[0]
                        for available_model in available_models:
                            if available_model.startswith(base_model_name):
                                model_found = True
                                actual_model_name = available_model
                                print(f"Using model: {actual_model_name} (requested: {self.ollama_model})")
                                break
                    
                    if not model_found:
                        print(f"Model {self.ollama_model} not found. Available models: {available_models}")
                        return False
                    
                    # Update the model name to the actual one found
                    self.ollama_model = actual_model_name
                    print(f"Connected to Ollama (model: {self.ollama_model})")
                else:
                    print(f"Failed to connect to Ollama: HTTP {response.status}")
                    return False
            
            # Test the model with a simple query (optional - don't fail if this doesn't work)
            test_payload = {
                "model": self.ollama_model,
                "messages": [{"role": "user", "content": "Hello, can you hear me?"}],
                "stream": False
            }
            
            try:
                async with self.http_session.post(f"{self.ollama_url}/api/chat", json=test_payload, timeout=5) as response:
                    if response.status == 200:
                        print(f"Model {self.ollama_model} is responding correctly")
                    else:
                        print(f"Model test got HTTP {response.status}, but continuing anyway")
            except Exception as test_error:
                print(f"Model test failed ({test_error}), but continuing anyway")
                    
        except Exception as e:
            print(f"Failed to connect to Ollama: {e}")
            return False
            
        return True
    
    async def call_mcp_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict:
        """
        Call an MCP tool and return the result
        
        Args:
            tool_name: Name of the tool to call
            arguments: Arguments to pass to the tool
            
        Returns:
            Tool execution result
        """
        try:
            if tool_name not in self.available_tools:
                return {
                    "success": False,
                    "error": f"Tool '{tool_name}' not available. Available tools: {list(self.available_tools.keys())}"
                }
            
            result = await self.mcp_session.call_tool(tool_name, arguments)
            
            # Extract the actual content from MCP response
            if result.content:
                # MCP returns a list of content items
                content_text = ""
                for content_item in result.content:
                    if hasattr(content_item, 'text'):
                        content_text += content_item.text
                
                # Try to parse as JSON if possible
                try:
                    parsed_content = json.loads(content_text)
                    return {
                        "success": True,
                        "data": parsed_content,
                        "tool_name": tool_name
                    }
                except json.JSONDecodeError:
                    # If not JSON, return as text
                    return {
                        "success": True,
                        "data": content_text,
                        "tool_name": tool_name
                    }
            else:
                return {
                    "success": True,
                    "data": None,
                    "tool_name": tool_name
                }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "tool_name": tool_name
            }
    
    async def get_domains_info(self) -> Dict:
        """Get domains information using MCP"""
        return await self.call_mcp_tool("get_domains", {})
    
    async def search_objects(self, query: str, object_type: Optional[str] = None) -> Dict:
        """Search for objects using MCP"""
        args = {"query": query}
        if object_type:
            args["object_type"] = object_type
        return await self.call_mcp_tool("search_objects", args)
    
    def get_available_tools_description(self) -> str:
        """Get a description of available MCP tools"""
        if not self.available_tools:
            return "No tools available"
        
        descriptions = []
        for tool_name, tool in self.available_tools.items():
            descriptions.append(f"- {tool_name}: {tool.description}")
        
        return "\n".join(descriptions)
    
    async def list_ollama_models(self) -> List[str]:
        """Get list of available Ollama models"""
        try:
            async with self.http_session.get(f"{self.ollama_url}/api/tags") as response:
                if response.status == 200:
                    models_data = await response.json()
                    return [model['name'] for model in models_data.get('models', [])]
                else:
                    print(f"Failed to get Ollama models: HTTP {response.status}")
                    return []
        except Exception as e:
            print(f"Error getting Ollama models: {e}")
            return []
    
    async def select_model_interactive(self) -> str:
        """Interactive model selection menu"""
        print("\nFetching available Ollama models...")
        models = await self.list_ollama_models()
        
        if not models:
            print("No models found. Using default: deepseek-r1:latest")
            return "deepseek-r1:latest"
        
        print(f"\nAvailable Ollama models:")
        for i, model in enumerate(models, 1):
            print(f"{i:2d}. {model}")
        
        while True:
            try:
                choice = input(f"\nSelect a model (1-{len(models)}) or press Enter for default ({self.ollama_model}): ").strip()
                
                if not choice:
                    return self.ollama_model
                
                choice_num = int(choice)
                if 1 <= choice_num <= len(models):
                    selected_model = models[choice_num - 1]
                    print(f"Selected model: {selected_model}")
                    return selected_model
                else:
                    print(f"Please enter a number between 1 and {len(models)}")
                    
            except ValueError:
                print("Please enter a valid number")
            except KeyboardInterrupt:
                print(f"\nUsing default model: {self.ollama_model}")
                return self.ollama_model
    
    async def process_user_request(self, user_input: str) -> str:
        """
        Process user request using LLM and MCP tools
        
        Args:
            user_input: User's question or request
            
        Returns:
            Agent's response
        """
        # Determine what BloodHound data to fetch based on user input
        bloodhound_data = {}
        
        # Simple keyword-based tool selection (we'll make this smarter later)
        if any(keyword in user_input.lower() for keyword in ['domain', 'domains']):
            print("DEBUG: Calling get_domains_info...")
            domains_result = await self.get_domains_info()
            print(f"DEBUG: get_domains_info returned: {domains_result}")
            bloodhound_data['domains'] = domains_result
        
        # If user is asking about specific objects, try searching
        if any(keyword in user_input.lower() for keyword in ['user', 'computer', 'group', 'find', 'search']):
            # Extract potential search terms (simple approach for now)
            search_terms = user_input.lower().replace('find', '').replace('search', '').strip()
            if search_terms:
                search_result = await self.search_objects(search_terms)
                bloodhound_data['search_results'] = search_result
        
        # If no specific data was requested, get domains as default
        if not bloodhound_data:
            print("DEBUG: No specific data requested, getting domains as default...")
            domains_result = await self.get_domains_info()
            print(f"DEBUG: Default get_domains_info returned: {domains_result}")
            bloodhound_data['domains'] = domains_result
        
        # Prepare context for the LLM (simplified for faster processing)
        system_prompt = f"""You are a cybersecurity expert analyzing BloodHound Active Directory data. Provide clear, actionable security insights. Focus on attack paths and security risks."""

        # Simplify the data for the LLM to reduce processing time
        simplified_data = {}
        if 'domains' in bloodhound_data and bloodhound_data['domains'].get('success'):
            domain_data = bloodhound_data['domains']['data']
            domains = domain_data.get('domains', [])
            simplified_data['domains'] = {
                'count': len(domains),
                'names': [d['name'] for d in domains],
                'types': {d['type']: [x['name'] for x in domains if x['type'] == d['type']] for d in domains},
                'collected': [d['name'] for d in domains if d.get('collected')],
                'uncollected': [d['name'] for d in domains if not d.get('collected')]
            }

        user_prompt = f"""User Question: {user_input}

BloodHound Data: {json.dumps(simplified_data, indent=2)}

Analyze this data and answer the user's question with key security insights."""

        # Add to conversation history
        self.conversation_history.append({"role": "user", "content": user_input})
        
        try:
            # Query the LLM using HTTP request
            chat_payload = {
                "model": self.ollama_model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "stream": False
            }
            
            print(f"DEBUG: Sending request to Ollama...")
            print(f"DEBUG: Model: {self.ollama_model}")
            print(f"DEBUG: System prompt length: {len(system_prompt)}")
            print(f"DEBUG: User prompt length: {len(user_prompt)}")
            
            async with self.http_session.post(f"{self.ollama_url}/api/chat", json=chat_payload, timeout=360) as response:
                print(f"DEBUG: Ollama response status: {response.status}")
                
                if response.status == 200:
                    response_data = await response.json()
                    llm_response = response_data['message']['content']
                    self.conversation_history.append({"role": "assistant", "content": llm_response})
                    return llm_response
                else:
                    error_text = await response.text()
                    print(f"DEBUG: Ollama error response: {error_text}")
                    return f"Error querying LLM: HTTP {response.status} - {error_text}"
            
        except asyncio.TimeoutError:
            return "Error querying LLM: Request timed out (360 seconds)"
        except Exception as e:
            print(f"DEBUG: Exception details: {type(e).__name__}: {str(e)}")
            import traceback
            print(f"DEBUG: Full traceback:")
            traceback.print_exc()
            return f"Error querying LLM: {e}"
        
        # If the LLM request fails, provide a basic summary
        if 'domains' in bloodhound_data and bloodhound_data['domains'].get('success'):
            domain_data = bloodhound_data['domains']['data']
            domains = domain_data.get('domains', [])
            
            summary = f"BloodHound Analysis Summary:\n\n"
            summary += f"Found {len(domains)} domains in the database:\n\n"
            
            for domain in domains:
                status = "Collected" if domain.get('collected') else "Not Collected"
                summary += f"- {domain['name']} ({domain['type']}) - {status}\n"
            
            summary += f"\nKey observations:\n"
            collected_count = sum(1 for d in domains if d.get('collected'))
            summary += f"- {collected_count}/{len(domains)} domains have been collected\n"
            ad_domains = [d for d in domains if d['type'] == 'active-directory']
            azure_domains = [d for d in domains if d['type'] == 'azure']
            summary += f"- {len(ad_domains)} Active Directory domains, {len(azure_domains)} Azure domains\n"
            
            if not all(d.get('collected') for d in domains):
                uncollected = [d['name'] for d in domains if not d.get('collected')]
                summary += f"- Uncollected domains: {', '.join(uncollected)}\n"
            
            return summary
        
        return "Unable to retrieve domain information from BloodHound."
    
    async def run_interactive(self):
        """Run the agent in interactive mode"""
        print("\n=== BloodHound MCP Agent ===")
        print(f"Connected to MCP server with {len(self.available_tools)} tools available.")
        print("I can help you analyze BloodHound data using MCP tools.")
        print("Type 'quit', 'exit', or 'q' to exit.")
        print("Type 'tools' to see available MCP tools.")
        print("Type 'help' for usage examples.\n")
        
        while True:
            try:
                user_input = input("You: ").strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("Goodbye!")
                    break
                
                if user_input.lower() == 'tools':
                    print(f"\nAvailable MCP Tools:\n{self.get_available_tools_description()}\n")
                    continue
                
                if user_input.lower() == 'help':
                    print("\nExample queries:")
                    print("- What domains are in the database?")
                    print("- Tell me about the domains")
                    print("- Find user admin")
                    print("- Search for computers")
                    print("- How many domains do we have?\n")
                    continue
                
                if not user_input:
                    continue
                
                print("\nAgent: Analyzing...")
                response = await self.process_user_request(user_input)
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
    """Main function to run the agent"""
    parser = argparse.ArgumentParser(description="BloodHound MCP Agent")
    parser.add_argument("--mcp-server", default="python", 
                       help="MCP server command (default: python)")
    parser.add_argument("--mcp-script", default="main.py", 
                       help="MCP server script (default: main.py)")
    parser.add_argument("--ollama-model", default=None, 
                       help="Ollama model to use (if not specified, will show selection menu)")
    parser.add_argument("--ollama-url", default="http://localhost:11434", 
                       help="Ollama URL (default: http://localhost:11434)")
    parser.add_argument("--list-models", action="store_true",
                       help="List available Ollama models and exit")
    
    args = parser.parse_args()
    
    # If user wants to list models only
    if args.list_models:
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"{args.ollama_url}/api/tags") as response:
                    if response.status == 200:
                        models_data = await response.json()
                        models = [model['name'] for model in models_data.get('models', [])]
                        print(f"\nAvailable Ollama models ({len(models)}):")
                        for i, model in enumerate(models, 1):
                            print(f"{i:2d}. {model}")
                        print(f"\nUsage: python agent.py --ollama-model MODEL_NAME")
                    else:
                        print(f"Failed to connect to Ollama: HTTP {response.status}")
            except Exception as e:
                print(f"Error connecting to Ollama: {e}")
        return
    
    # Determine the model to use
    if args.ollama_model:
        # Model specified via command line
        selected_model = args.ollama_model
        print(f"Using model from command line: {selected_model}")
    else:
        # Create temporary agent to access model selection
        temp_agent = BloodHoundMCPAgent(
            mcp_server_command=[args.mcp_server, args.mcp_script],
            ollama_model="deepseek-r1:latest",  # temporary default
            ollama_url=args.ollama_url
        )
        # Create HTTP session for model listing
        temp_agent.http_session = aiohttp.ClientSession()
        
        try:
            selected_model = await temp_agent.select_model_interactive()
        finally:
            await temp_agent.http_session.close()
    
    # Create agent with selected model
    agent = BloodHoundMCPAgent(
        mcp_server_command=[args.mcp_server, args.mcp_script],
        ollama_model=selected_model,
        ollama_url=args.ollama_url
    )
    
    try:
        # Initialize connections
        if not await agent.initialize():
            print("Failed to initialize agent. Exiting.")
            return
        
        # Run interactive mode
        await agent.run_interactive()
    
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        print("Cleaning up...")
        await agent.cleanup()
        print("Done.")


if __name__ == "__main__":
    asyncio.run(main())