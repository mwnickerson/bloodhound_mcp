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
            
            # Check domain-specific tools
            domain_tools = [
                'get_groups', 'get_computers', 'get_security_controllers', 'get_gpos', 'get_ous',
                'get_dc_syncers', 'get_foreign_admins', 'get_foreign_gpo_controllers', 
                'get_foreign_groups', 'get_foreign_users', 'get_inbound_trusts', 
                'get_linked_gpos', 'get_outbound_trusts'
            ]
            
            # Check user-specific tools
            user_tools = [
                'get_user_info', 'get_user_admin_rights', 'get_user_constrained_delegation_rights',
                'get_user_controllables', 'get_user_controllers', 'get_user_dcom_rights',
                'get_user_memberships', 'get_user_ps_remote_rights', 'get_user_rdp_rights',
                'get_user_sessions', 'get_user_sql_admin_rights'
            ]
            
            # Check group-specific tools
            group_tools = [
                'get_group_info', 'get_group_admin_rights', 'get_group_controllables',
                'get_group_controllers', 'get_group_dcom_rights', 'get_group_members',
                'get_group_memberships', 'get_group_ps_remote_rights', 'get_group_rdp_rights',
                'get_group_sessions'
            ]
            
            # Check computer-specific tools
            computer_tools = [
                'get_computer_info', 'get_computer_admin_rights', 'get_computer_admin_users',
                'get_computer_constrained_delegation_rights', 'get_computer_constrained_users',
                'get_computer_controllables', 'get_computer_controllers', 'get_computer_dcom_rights',
                'get_computer_dcom_users', 'get_computer_memberships', 'get_computer_ps_remote_rights',
                'get_computer_ps_remote_users', 'get_computer_rdp_rights', 'get_computer_rdp_users',
                'get_computer_sessions', 'get_computer_sql_admin_rights'
            ]
            
            # Check OU-specific tools
            ou_tools = [
                'get_ou_info', 'get_ou_computers', 'get_ou_groups', 'get_ou_gpos', 'get_ou_users'
            ]
            
            # Check GPO-specific tools
            gpo_tools = [
                'get_gpo_info', 'get_gpo_computers', 'get_gpo_controllers', 'get_gpo_ous',
                'get_gpo_tier_zeros', 'get_gpo_users'
            ]
            
            # Check advanced analysis tools
            analysis_tools = [
                'search_graph', 'get_shortest_path', 'get_edge_composition', 'get_relay_targets',
                'run_cypher_query', 'interpret_cypher_result', 'create_saved_query', 'list_saved_queries'
            ]
            
            # Check certificate tools
            cert_tools = [
                'get_cert_template_info', 'get_cert_template_controllers', 'get_root_ca_info',
                'get_root_ca_controllers', 'get_enterprise_ca_info', 'get_enterprise_ca_controllers',
                'get_aia_ca_controllers'
            ]
            
            # Count available tools by category
            available_domain = sum(1 for tool in domain_tools if tool in self.available_tools)
            available_user = sum(1 for tool in user_tools if tool in self.available_tools)
            available_group = sum(1 for tool in group_tools if tool in self.available_tools)
            available_computer = sum(1 for tool in computer_tools if tool in self.available_tools)
            available_ou = sum(1 for tool in ou_tools if tool in self.available_tools)
            available_gpo = sum(1 for tool in gpo_tools if tool in self.available_tools)
            available_analysis = sum(1 for tool in analysis_tools if tool in self.available_tools)
            available_cert = sum(1 for tool in cert_tools if tool in self.available_tools)
            
            print(f"✅ Domain tools: {available_domain}/{len(domain_tools)}")
            print(f"✅ User tools: {available_user}/{len(user_tools)}")
            print(f"✅ Group tools: {available_group}/{len(group_tools)}")
            print(f"✅ Computer tools: {available_computer}/{len(computer_tools)}")
            print(f"✅ OU tools: {available_ou}/{len(ou_tools)}")
            print(f"✅ GPO tools: {available_gpo}/{len(gpo_tools)}")
            print(f"✅ Analysis tools: {available_analysis}/{len(analysis_tools)}")
            print(f"✅ Certificate tools: {available_cert}/{len(cert_tools)}")
            
            total_expected = 3 + len(domain_tools) + len(user_tools) + len(group_tools) + len(computer_tools) + len(ou_tools) + len(gpo_tools) + len(analysis_tools) + len(cert_tools)
            total_available = 3 + available_domain + available_user + available_group + available_computer + available_ou + available_gpo + available_analysis + available_cert
            print(f"🩸 Total BloodHound tools available: {total_available}/{total_expected}")
            
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
            print(f"Getting users from domain: {domain_id} (limit={limit}, skip={skip})")
            
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
    
    # Domain-specific tool methods
    async def call_get_groups(self, domain_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_groups MCP tool"""
        try:
            print(f"Getting groups from domain: {domain_id} (limit={limit}, skip={skip})")
            args = {"domain_id": domain_id, "limit": limit, "skip": skip}
            result = await asyncio.wait_for(
                self.mcp_session.call_tool("get_groups", args), timeout=30.0
            )
            if result.content:
                content_text = ""
                for content_item in result.content:
                    if hasattr(content_item, 'text'):
                        content_text += content_item.text
                return content_text
            else:
                return "Tool executed but returned no content"
        except asyncio.TimeoutError:
            return f"get_groups tool timed out after 30 seconds"
        except Exception as e:
            return f"Error calling get_groups: {str(e)}"
    
    async def call_get_computers(self, domain_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computers MCP tool"""
        try:
            print(f"Getting computers from domain: {domain_id} (limit={limit}, skip={skip})")
            args = {"domain_id": domain_id, "limit": limit, "skip": skip}
            result = await asyncio.wait_for(
                self.mcp_session.call_tool("get_computers", args), timeout=30.0
            )
            if result.content:
                content_text = ""
                for content_item in result.content:
                    if hasattr(content_item, 'text'):
                        content_text += content_item.text
                return content_text
            else:
                return "Tool executed but returned no content"
        except asyncio.TimeoutError:
            return f"get_computers tool timed out after 30 seconds"
        except Exception as e:
            return f"Error calling get_computers: {str(e)}"
    
    async def call_get_security_controllers(self, domain_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_security_controllers MCP tool"""
        try:
            print(f"Getting security controllers from domain: {domain_id} (limit={limit}, skip={skip})")
            args = {"domain_id": domain_id, "limit": limit, "skip": skip}
            result = await asyncio.wait_for(
                self.mcp_session.call_tool("get_security_controllers", args), timeout=30.0
            )
            if result.content:
                content_text = ""
                for content_item in result.content:
                    if hasattr(content_item, 'text'):
                        content_text += content_item.text
                return content_text
            else:
                return "Tool executed but returned no content"
        except asyncio.TimeoutError:
            return f"get_security_controllers tool timed out after 30 seconds"
        except Exception as e:
            return f"Error calling get_security_controllers: {str(e)}"
    
    async def call_get_gpos(self, domain_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_gpos MCP tool"""
        try:
            print(f"Getting GPOs from domain: {domain_id} (limit={limit}, skip={skip})")
            args = {"domain_id": domain_id, "limit": limit, "skip": skip}
            result = await asyncio.wait_for(
                self.mcp_session.call_tool("get_gpos", args), timeout=30.0
            )
            if result.content:
                content_text = ""
                for content_item in result.content:
                    if hasattr(content_item, 'text'):
                        content_text += content_item.text
                return content_text
            else:
                return "Tool executed but returned no content"
        except asyncio.TimeoutError:
            return f"get_gpos tool timed out after 30 seconds"
        except Exception as e:
            return f"Error calling get_gpos: {str(e)}"
    
    async def call_get_ous(self, domain_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_ous MCP tool"""
        try:
            print(f"Getting OUs from domain: {domain_id} (limit={limit}, skip={skip})")
            args = {"domain_id": domain_id, "limit": limit, "skip": skip}
            result = await asyncio.wait_for(
                self.mcp_session.call_tool("get_ous", args), timeout=30.0
            )
            if result.content:
                content_text = ""
                for content_item in result.content:
                    if hasattr(content_item, 'text'):
                        content_text += content_item.text
                return content_text
            else:
                return "Tool executed but returned no content"
        except asyncio.TimeoutError:
            return f"get_ous tool timed out after 30 seconds"
        except Exception as e:
            return f"Error calling get_ous: {str(e)}"
    
    # Helper method to reduce code duplication
    async def _call_mcp_tool(self, tool_name: str, args: dict, description: str = None) -> str:
        """Generic helper method to call MCP tools"""
        try:
            if description:
                print(description)
            
            result = await asyncio.wait_for(
                self.mcp_session.call_tool(tool_name, args), timeout=30.0
            )
            
            if result.content:
                content_text = ""
                for content_item in result.content:
                    if hasattr(content_item, 'text'):
                        content_text += content_item.text
                return content_text
            else:
                return "Tool executed but returned no content"
                
        except asyncio.TimeoutError:
            return f"{tool_name} tool timed out after 30 seconds"
        except Exception as e:
            return f"Error calling {tool_name}: {str(e)}"
    
    # Continue with remaining domain tools using helper method
    async def call_get_dc_syncers(self, domain_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_dc_syncers MCP tool"""
        args = {"domain_id": domain_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_dc_syncers", args, 
                                       f"Getting DC syncers from domain: {domain_id} (limit={limit}, skip={skip})")
    
    async def call_get_foreign_admins(self, domain_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_foreign_admins MCP tool"""
        args = {"domain_id": domain_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_foreign_admins", args,
                                       f"Getting foreign admins from domain: {domain_id} (limit={limit}, skip={skip})")
    
    async def call_get_foreign_gpo_controllers(self, domain_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_foreign_gpo_controllers MCP tool"""
        args = {"domain_id": domain_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_foreign_gpo_controllers", args,
                                       f"Getting foreign GPO controllers from domain: {domain_id} (limit={limit}, skip={skip})")
    
    async def call_get_foreign_groups(self, domain_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_foreign_groups MCP tool"""
        args = {"domain_id": domain_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_foreign_groups", args,
                                       f"Getting foreign groups from domain: {domain_id} (limit={limit}, skip={skip})")
    
    async def call_get_foreign_users(self, domain_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_foreign_users MCP tool"""
        args = {"domain_id": domain_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_foreign_users", args,
                                       f"Getting foreign users from domain: {domain_id} (limit={limit}, skip={skip})")
    
    async def call_get_inbound_trusts(self, domain_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_inbound_trusts MCP tool"""
        args = {"domain_id": domain_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_inbound_trusts", args,
                                       f"Getting inbound trusts from domain: {domain_id} (limit={limit}, skip={skip})")
    
    async def call_get_linked_gpos(self, domain_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_linked_gpos MCP tool"""
        args = {"domain_id": domain_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_linked_gpos", args,
                                       f"Getting linked GPOs from domain: {domain_id} (limit={limit}, skip={skip})")
    
    async def call_get_outbound_trusts(self, domain_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_outbound_trusts MCP tool"""
        args = {"domain_id": domain_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_outbound_trusts", args,
                                       f"Getting outbound trusts from domain: {domain_id} (limit={limit}, skip={skip})")
    
    # User-specific tool methods
    async def call_get_user_info(self, user_id: str) -> str:
        """Call the get_user_info MCP tool"""
        args = {"user_id": user_id}
        return await self._call_mcp_tool("get_user_info", args,
                                       f"Getting user info for: {user_id}")
    
    async def call_get_user_admin_rights(self, user_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_user_admin_rights MCP tool"""
        args = {"user_id": user_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_user_admin_rights", args,
                                       f"Getting admin rights for user: {user_id} (limit={limit}, skip={skip})")
    
    async def call_get_user_constrained_delegation_rights(self, user_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_user_constrained_delegation_rights MCP tool"""
        args = {"user_id": user_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_user_constrained_delegation_rights", args,
                                       f"Getting constrained delegation rights for user: {user_id} (limit={limit}, skip={skip})")
    
    async def call_get_user_controllables(self, user_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_user_controllables MCP tool"""
        args = {"user_id": user_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_user_controllables", args,
                                       f"Getting controllables for user: {user_id} (limit={limit}, skip={skip})")
    
    async def call_get_user_controllers(self, user_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_user_controllers MCP tool"""
        args = {"user_id": user_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_user_controllers", args,
                                       f"Getting controllers for user: {user_id} (limit={limit}, skip={skip})")
    
    async def call_get_user_dcom_rights(self, user_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_user_dcom_rights MCP tool"""
        args = {"user_id": user_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_user_dcom_rights", args,
                                       f"Getting DCOM rights for user: {user_id} (limit={limit}, skip={skip})")
    
    async def call_get_user_memberships(self, user_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_user_memberships MCP tool"""
        args = {"user_id": user_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_user_memberships", args,
                                       f"Getting memberships for user: {user_id} (limit={limit}, skip={skip})")
    
    async def call_get_user_ps_remote_rights(self, user_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_user_ps_remote_rights MCP tool"""
        args = {"user_id": user_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_user_ps_remote_rights", args,
                                       f"Getting PS remote rights for user: {user_id} (limit={limit}, skip={skip})")
    
    async def call_get_user_rdp_rights(self, user_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_user_rdp_rights MCP tool"""
        args = {"user_id": user_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_user_rdp_rights", args,
                                       f"Getting RDP rights for user: {user_id} (limit={limit}, skip={skip})")
    
    async def call_get_user_sessions(self, user_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_user_sessions MCP tool"""
        args = {"user_id": user_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_user_sessions", args,
                                       f"Getting sessions for user: {user_id} (limit={limit}, skip={skip})")
    
    async def call_get_user_sql_admin_rights(self, user_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_user_sql_admin_rights MCP tool"""
        args = {"user_id": user_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_user_sql_admin_rights", args,
                                       f"Getting SQL admin rights for user: {user_id} (limit={limit}, skip={skip})")
    
    # Group-specific tool methods
    async def call_get_group_info(self, group_id: str) -> str:
        """Call the get_group_info MCP tool"""
        args = {"group_id": group_id}
        return await self._call_mcp_tool("get_group_info", args, f"Getting group info for: {group_id}")
    
    async def call_get_group_admin_rights(self, group_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_group_admin_rights MCP tool"""
        args = {"group_id": group_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_group_admin_rights", args,
                                       f"Getting admin rights for group: {group_id} (limit={limit}, skip={skip})")
    
    async def call_get_group_controllables(self, group_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_group_controllables MCP tool"""
        args = {"group_id": group_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_group_controllables", args,
                                       f"Getting controllables for group: {group_id} (limit={limit}, skip={skip})")
    
    async def call_get_group_controllers(self, group_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_group_controllers MCP tool"""
        args = {"group_id": group_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_group_controllers", args,
                                       f"Getting controllers for group: {group_id} (limit={limit}, skip={skip})")
    
    async def call_get_group_dcom_rights(self, group_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_group_dcom_rights MCP tool"""
        args = {"group_id": group_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_group_dcom_rights", args,
                                       f"Getting DCOM rights for group: {group_id} (limit={limit}, skip={skip})")
    
    async def call_get_group_members(self, group_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_group_members MCP tool"""
        args = {"group_id": group_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_group_members", args,
                                       f"Getting members for group: {group_id} (limit={limit}, skip={skip})")
    
    async def call_get_group_memberships(self, group_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_group_memberships MCP tool"""
        args = {"group_id": group_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_group_memberships", args,
                                       f"Getting memberships for group: {group_id} (limit={limit}, skip={skip})")
    
    async def call_get_group_ps_remote_rights(self, group_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_group_ps_remote_rights MCP tool"""
        args = {"group_id": group_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_group_ps_remote_rights", args,
                                       f"Getting PS remote rights for group: {group_id} (limit={limit}, skip={skip})")
    
    async def call_get_group_rdp_rights(self, group_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_group_rdp_rights MCP tool"""
        args = {"group_id": group_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_group_rdp_rights", args,
                                       f"Getting RDP rights for group: {group_id} (limit={limit}, skip={skip})")
    
    async def call_get_group_sessions(self, group_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_group_sessions MCP tool"""
        args = {"group_id": group_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_group_sessions", args,
                                       f"Getting sessions for group: {group_id} (limit={limit}, skip={skip})")
    
    # Computer-specific tool methods  
    async def call_get_computer_info(self, computer_id: str) -> str:
        """Call the get_computer_info MCP tool"""
        args = {"computer_id": computer_id}
        return await self._call_mcp_tool("get_computer_info", args, f"Getting computer info for: {computer_id}")
    
    async def call_get_computer_admin_rights(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_admin_rights MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_admin_rights", args,
                                       f"Getting admin rights for computer: {computer_id} (limit={limit}, skip={skip})")
    
    async def call_get_computer_admin_users(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_admin_users MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_admin_users", args,
                                       f"Getting admin users for computer: {computer_id} (limit={limit}, skip={skip})")
    
    async def call_get_computer_constrained_delegation_rights(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_constrained_delegation_rights MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_constrained_delegation_rights", args,
                                       f"Getting constrained delegation rights for computer: {computer_id} (limit={limit}, skip={skip})")
    
    async def call_get_computer_constrained_users(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_constrained_users MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_constrained_users", args,
                                       f"Getting constrained users for computer: {computer_id} (limit={limit}, skip={skip})")
    
    async def call_get_computer_controllables(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_controllables MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_controllables", args,
                                       f"Getting controllables for computer: {computer_id} (limit={limit}, skip={skip})")
    
    async def call_get_computer_controllers(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_controllers MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_controllers", args,
                                       f"Getting controllers for computer: {computer_id} (limit={limit}, skip={skip})")
    
    async def call_get_computer_dcom_rights(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_dcom_rights MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_dcom_rights", args,
                                       f"Getting DCOM rights for computer: {computer_id} (limit={limit}, skip={skip})")
    
    async def call_get_computer_dcom_users(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_dcom_users MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_dcom_users", args,
                                       f"Getting DCOM users for computer: {computer_id} (limit={limit}, skip={skip})")
    
    async def call_get_computer_memberships(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_memberships MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_memberships", args,
                                       f"Getting memberships for computer: {computer_id} (limit={limit}, skip={skip})")
    
    async def call_get_computer_ps_remote_rights(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_ps_remote_rights MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_ps_remote_rights", args,
                                       f"Getting PS remote rights for computer: {computer_id} (limit={limit}, skip={skip})")
    
    async def call_get_computer_ps_remote_users(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_ps_remote_users MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_ps_remote_users", args,
                                       f"Getting PS remote users for computer: {computer_id} (limit={limit}, skip={skip})")
    
    async def call_get_computer_rdp_rights(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_rdp_rights MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_rdp_rights", args,
                                       f"Getting RDP rights for computer: {computer_id} (limit={limit}, skip={skip})")
    
    async def call_get_computer_rdp_users(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_rdp_users MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_rdp_users", args,
                                       f"Getting RDP users for computer: {computer_id} (limit={limit}, skip={skip})")
    
    async def call_get_computer_sessions(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_sessions MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_sessions", args,
                                       f"Getting sessions for computer: {computer_id} (limit={limit}, skip={skip})")
    
    async def call_get_computer_sql_admin_rights(self, computer_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_computer_sql_admin_rights MCP tool"""
        args = {"computer_id": computer_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_computer_sql_admin_rights", args,
                                       f"Getting SQL admin rights for computer: {computer_id} (limit={limit}, skip={skip})")
    
    # OU-specific tool methods
    async def call_get_ou_info(self, ou_id: str) -> str:
        """Call the get_ou_info MCP tool"""
        args = {"ou_id": ou_id}
        return await self._call_mcp_tool("get_ou_info", args, f"Getting OU info for: {ou_id}")
    
    async def call_get_ou_computers(self, ou_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_ou_computers MCP tool"""
        args = {"ou_id": ou_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_ou_computers", args,
                                       f"Getting computers for OU: {ou_id} (limit={limit}, skip={skip})")
    
    async def call_get_ou_groups(self, ou_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_ou_groups MCP tool"""
        args = {"ou_id": ou_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_ou_groups", args,
                                       f"Getting groups for OU: {ou_id} (limit={limit}, skip={skip})")
    
    async def call_get_ou_gpos(self, ou_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_ou_gpos MCP tool"""
        args = {"ou_id": ou_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_ou_gpos", args,
                                       f"Getting GPOs for OU: {ou_id} (limit={limit}, skip={skip})")
    
    async def call_get_ou_users(self, ou_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_ou_users MCP tool"""
        args = {"ou_id": ou_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_ou_users", args,
                                       f"Getting users for OU: {ou_id} (limit={limit}, skip={skip})")
    
    # GPO-specific tool methods
    async def call_get_gpo_info(self, gpo_id: str) -> str:
        """Call the get_gpo_info MCP tool"""
        args = {"gpo_id": gpo_id}
        return await self._call_mcp_tool("get_gpo_info", args, f"Getting GPO info for: {gpo_id}")
    
    async def call_get_gpo_computers(self, gpo_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_gpo_computers MCP tool"""
        args = {"gpo_id": gpo_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_gpo_computers", args,
                                       f"Getting computers for GPO: {gpo_id} (limit={limit}, skip={skip})")
    
    async def call_get_gpo_controllers(self, gpo_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_gpo_controllers MCP tool"""
        args = {"gpo_id": gpo_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_gpo_controllers", args,
                                       f"Getting controllers for GPO: {gpo_id} (limit={limit}, skip={skip})")
    
    async def call_get_gpo_ous(self, gpo_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_gpo_ous MCP tool"""
        args = {"gpo_id": gpo_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_gpo_ous", args,
                                       f"Getting OUs for GPO: {gpo_id} (limit={limit}, skip={skip})")
    
    async def call_get_gpo_tier_zeros(self, gpo_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_gpo_tier_zeros MCP tool"""
        args = {"gpo_id": gpo_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_gpo_tier_zeros", args,
                                       f"Getting tier zeros for GPO: {gpo_id} (limit={limit}, skip={skip})")
    
    async def call_get_gpo_users(self, gpo_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_gpo_users MCP tool"""
        args = {"gpo_id": gpo_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_gpo_users", args,
                                       f"Getting users for GPO: {gpo_id} (limit={limit}, skip={skip})")
    
    # Advanced analysis tool methods
    async def call_search_graph(self, query: str, search_type: str = "fuzzy") -> str:
        """Call the search_graph MCP tool"""
        args = {"query": query, "search_type": search_type}
        return await self._call_mcp_tool("search_graph", args,
                                       f"Searching graph with query: {query} (type: {search_type})")
    
    async def call_get_shortest_path(self, start_node: str, end_node: str, relationship_kinds: list = None) -> str:
        """Call the get_shortest_path MCP tool"""
        args = {"start_node": start_node, "end_node": end_node}
        if relationship_kinds:
            args["relationship_kinds"] = relationship_kinds
        return await self._call_mcp_tool("get_shortest_path", args,
                                       f"Finding shortest path from {start_node} to {end_node}")
    
    async def call_get_edge_composition(self, source_node: str, target_node: str, edge_type: str) -> str:
        """Call the get_edge_composition MCP tool"""
        args = {"source_node": source_node, "target_node": target_node, "edge_type": edge_type}
        return await self._call_mcp_tool("get_edge_composition", args,
                                       f"Getting edge composition from {source_node} to {target_node} ({edge_type})")
    
    async def call_get_relay_targets(self, source_node: str, target_node: str, edge_type: str) -> str:
        """Call the get_relay_targets MCP tool"""
        args = {"source_node": source_node, "target_node": target_node, "edge_type": edge_type}
        return await self._call_mcp_tool("get_relay_targets", args,
                                       f"Getting relay targets from {source_node} to {target_node} ({edge_type})")
    
    async def call_run_cypher_query(self, query: str, include_properties: bool = True) -> str:
        """Call the run_cypher_query MCP tool"""
        args = {"query": query, "include_properties": include_properties}
        return await self._call_mcp_tool("run_cypher_query", args,
                                       f"Running Cypher query: {query[:50]}...")
    
    async def call_interpret_cypher_result(self, query: str, result_json: str) -> str:
        """Call the interpret_cypher_result MCP tool"""
        args = {"query": query, "result_json": result_json}
        return await self._call_mcp_tool("interpret_cypher_result", args,
                                       f"Interpreting Cypher result for query: {query[:50]}...")
    
    async def call_create_saved_query(self, name: str, query: str) -> str:
        """Call the create_saved_query MCP tool"""
        args = {"name": name, "query": query}
        return await self._call_mcp_tool("create_saved_query", args,
                                       f"Creating saved query: {name}")
    
    async def call_list_saved_queries(self, skip: int = 0, limit: int = 100, name: str = None) -> str:
        """Call the list_saved_queries MCP tool"""
        args = {"skip": skip, "limit": limit}
        if name:
            args["name"] = name
        return await self._call_mcp_tool("list_saved_queries", args,
                                       f"Listing saved queries (limit={limit}, skip={skip})")
    
    # Certificate tool methods  
    async def call_get_cert_template_info(self, template_id: str) -> str:
        """Call the get_cert_template_info MCP tool"""
        args = {"template_id": template_id}
        return await self._call_mcp_tool("get_cert_template_info", args,
                                       f"Getting certificate template info for: {template_id}")
    
    async def call_get_cert_template_controllers(self, template_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_cert_template_controllers MCP tool"""
        args = {"template_id": template_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_cert_template_controllers", args,
                                       f"Getting controllers for certificate template: {template_id} (limit={limit}, skip={skip})")
    
    async def call_get_root_ca_info(self, ca_id: str) -> str:
        """Call the get_root_ca_info MCP tool"""
        args = {"ca_id": ca_id}
        return await self._call_mcp_tool("get_root_ca_info", args,
                                       f"Getting root CA info for: {ca_id}")
    
    async def call_get_root_ca_controllers(self, ca_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_root_ca_controllers MCP tool"""
        args = {"ca_id": ca_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_root_ca_controllers", args,
                                       f"Getting controllers for root CA: {ca_id} (limit={limit}, skip={skip})")
    
    async def call_get_enterprise_ca_info(self, ca_id: str) -> str:
        """Call the get_enterprise_ca_info MCP tool"""
        args = {"ca_id": ca_id}
        return await self._call_mcp_tool("get_enterprise_ca_info", args,
                                       f"Getting enterprise CA info for: {ca_id}")
    
    async def call_get_enterprise_ca_controllers(self, ca_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_enterprise_ca_controllers MCP tool"""
        args = {"ca_id": ca_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_enterprise_ca_controllers", args,
                                       f"Getting controllers for enterprise CA: {ca_id} (limit={limit}, skip={skip})")
    
    async def call_get_aia_ca_controllers(self, ca_id: str, limit: int = 100, skip: int = 0) -> str:
        """Call the get_aia_ca_controllers MCP tool"""
        args = {"ca_id": ca_id, "limit": limit, "skip": skip}
        return await self._call_mcp_tool("get_aia_ca_controllers", args,
                                       f"Getting AIA CA controllers for: {ca_id} (limit={limit}, skip={skip})")
    
    # Helper methods for intelligent query routing
    def _detect_object_type(self, user_input: str) -> str:
        """Detect the primary object type from user input"""
        query_lower = user_input.lower()
        
        # Object type keywords with priority order
        if any(word in query_lower for word in ['user', 'users', 'account', 'accounts']):
            return "user"
        elif any(word in query_lower for word in ['group', 'groups']):
            return "group"
        elif any(word in query_lower for word in ['computer', 'computers', 'machine', 'machines', 'host', 'hosts', 'server', 'servers']):
            return "computer"
        elif any(word in query_lower for word in ['domain', 'domains']):
            return "domain"
        elif any(word in query_lower for word in ['ou', 'ous', 'organizational unit', 'organizational units']):
            return "ou"
        elif any(word in query_lower for word in ['gpo', 'gpos', 'group policy', 'policy']):
            return "gpo"
        elif any(word in query_lower for word in ['certificate', 'cert', 'ca', 'template']):
            return "certificate"
        else:
            return "general"
    
    def _detect_operation_type(self, user_input: str) -> str:
        """Detect the operation type from user input"""
        query_lower = user_input.lower()
        
        # Operation keywords
        if any(word in query_lower for word in ['info', 'information', 'details', 'about']):
            return "info"
        elif any(word in query_lower for word in ['admin', 'administrative', 'rights', 'privileges']):
            return "admin_rights"
        elif any(word in query_lower for word in ['members', 'membership', 'member of']):
            return "membership"
        elif any(word in query_lower for word in ['sessions', 'session', 'logged in', 'active']):
            return "sessions"
        elif any(word in query_lower for word in ['control', 'controllable', 'controller']):
            return "control"
        elif any(word in query_lower for word in ['dcom', 'rdp', 'powershell', 'ps remote', 'sql']):
            return "access_rights"
        elif any(word in query_lower for word in ['trust', 'trusts', 'foreign']):
            return "trusts"
        elif any(word in query_lower for word in ['path', 'shortest', 'attack path', 'route']):
            return "attack_path"
        elif any(word in query_lower for word in ['cypher', 'query', 'graph']):
            return "cypher"
        elif any(word in query_lower for word in ['search', 'find', 'look for']):
            return "search"
        elif any(word in query_lower for word in ['analyze', 'analysis']):
            return "analysis"
        else:
            return "list"
    
    def _extract_object_identifiers(self, user_input: str) -> dict:
        """Extract object identifiers (IDs, names) from user input"""
        import re
        
        identifiers = {}
        
        # Look for quoted strings
        quoted_matches = re.findall(r'"([^"]*)"', user_input)
        if quoted_matches:
            identifiers['quoted'] = quoted_matches
        
        # Look for GUID patterns
        guid_pattern = r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'
        guid_matches = re.findall(guid_pattern, user_input, re.IGNORECASE)
        if guid_matches:
            identifiers['guids'] = guid_matches
        
        # Look for domain patterns
        domain_pattern = r'\b[a-zA-Z0-9][\w\-\.]*\.(com|corp|local|net|org)\b'
        domain_matches = re.findall(domain_pattern, user_input, re.IGNORECASE)
        if domain_matches:
            identifiers['domains'] = domain_matches
        
        # Look for username patterns
        username_pattern = r'\b[a-zA-Z][a-zA-Z0-9\-\.\_]*@[a-zA-Z0-9\-\.]+\b'
        username_matches = re.findall(username_pattern, user_input)
        if username_matches:
            identifiers['usernames'] = username_matches
        
        return identifiers
    
    async def _route_to_appropriate_tools(self, user_input: str, object_type: str, operation_type: str, identifiers: dict) -> tuple:
        """Route user query to appropriate tools and return results"""
        tool_result = ""
        context_type = ""
        
        try:
            # Get domain IDs for operations that need them
            domains_result = await self.call_get_domains()
            domain_ids = self._extract_domain_ids(domains_result)
            
            if not domain_ids:
                return "No domains found in BloodHound database", "error"
            
            # Route based on object type and operation
            if object_type == "domain":
                if operation_type == "trusts":
                    # Get trust information
                    inbound_trusts = await self.call_get_inbound_trusts(domain_ids[0])
                    outbound_trusts = await self.call_get_outbound_trusts(domain_ids[0])
                    tool_result = f"Inbound Trusts:\n{inbound_trusts}\n\nOutbound Trusts:\n{outbound_trusts}"
                    context_type = "domain_trusts"
                elif operation_type == "analysis":
                    # Get comprehensive domain analysis
                    groups = await self.call_get_groups(domain_ids[0], limit=50)
                    computers = await self.call_get_computers(domain_ids[0], limit=50)
                    foreign_admins = await self.call_get_foreign_admins(domain_ids[0])
                    tool_result = f"Groups:\n{groups}\n\nComputers:\n{computers}\n\nForeign Admins:\n{foreign_admins}"
                    context_type = "domain_analysis"
                else:
                    tool_result = domains_result
                    context_type = "domains"
            
            elif object_type == "user":
                if identifiers.get('guids') or identifiers.get('usernames'):
                    # Specific user analysis
                    user_id = identifiers.get('guids', [None])[0] or identifiers.get('usernames', [None])[0]
                    if user_id:
                        if operation_type == "info":
                            tool_result = await self.call_get_user_info(user_id)
                            context_type = "user_info"
                        elif operation_type == "admin_rights":
                            tool_result = await self.call_get_user_admin_rights(user_id)
                            context_type = "user_admin_rights"
                        elif operation_type == "membership":
                            tool_result = await self.call_get_user_memberships(user_id)
                            context_type = "user_memberships"
                        elif operation_type == "sessions":
                            tool_result = await self.call_get_user_sessions(user_id)
                            context_type = "user_sessions"
                        elif operation_type == "analysis":
                            # Comprehensive user analysis
                            info = await self.call_get_user_info(user_id)
                            rights = await self.call_get_user_admin_rights(user_id)
                            memberships = await self.call_get_user_memberships(user_id)
                            tool_result = f"User Info:\n{info}\n\nAdmin Rights:\n{rights}\n\nMemberships:\n{memberships}"
                            context_type = "user_analysis"
                        else:
                            tool_result = await self.call_get_user_info(user_id)
                            context_type = "user_info"
                    else:
                        # Fall back to user search
                        search_term = identifiers.get('quoted', ['admin'])[0]
                        tool_result = await self.smart_search(search_term, "User")
                        context_type = "search_results"
                else:
                    # List users from domain
                    tool_result = await self._get_users_from_domains(domain_ids)
                    context_type = "users"
            
            elif object_type == "group":
                if identifiers.get('guids'):
                    # Specific group analysis
                    group_id = identifiers['guids'][0]
                    if operation_type == "info":
                        tool_result = await self.call_get_group_info(group_id)
                        context_type = "group_info"
                    elif operation_type == "membership":
                        members = await self.call_get_group_members(group_id)
                        memberships = await self.call_get_group_memberships(group_id)
                        tool_result = f"Group Members:\n{members}\n\nGroup Memberships:\n{memberships}"
                        context_type = "group_membership"
                    elif operation_type == "admin_rights":
                        tool_result = await self.call_get_group_admin_rights(group_id)
                        context_type = "group_admin_rights"
                    elif operation_type == "analysis":
                        # Comprehensive group analysis
                        info = await self.call_get_group_info(group_id)
                        members = await self.call_get_group_members(group_id)
                        rights = await self.call_get_group_admin_rights(group_id)
                        tool_result = f"Group Info:\n{info}\n\nMembers:\n{members}\n\nAdmin Rights:\n{rights}"
                        context_type = "group_analysis"
                    else:
                        tool_result = await self.call_get_group_info(group_id)
                        context_type = "group_info"
                else:
                    # List groups from domain
                    tool_result = await self.call_get_groups(domain_ids[0])
                    context_type = "groups"
            
            elif object_type == "computer":
                if identifiers.get('guids'):
                    # Specific computer analysis
                    computer_id = identifiers['guids'][0]
                    if operation_type == "info":
                        tool_result = await self.call_get_computer_info(computer_id)
                        context_type = "computer_info"
                    elif operation_type == "admin_rights":
                        rights = await self.call_get_computer_admin_rights(computer_id)
                        users = await self.call_get_computer_admin_users(computer_id)
                        tool_result = f"Computer Admin Rights:\n{rights}\n\nAdmin Users:\n{users}"
                        context_type = "computer_admin_rights"
                    elif operation_type == "sessions":
                        tool_result = await self.call_get_computer_sessions(computer_id)
                        context_type = "computer_sessions"
                    elif operation_type == "analysis":
                        # Comprehensive computer analysis
                        info = await self.call_get_computer_info(computer_id)
                        sessions = await self.call_get_computer_sessions(computer_id)
                        admin_users = await self.call_get_computer_admin_users(computer_id)
                        tool_result = f"Computer Info:\n{info}\n\nSessions:\n{sessions}\n\nAdmin Users:\n{admin_users}"
                        context_type = "computer_analysis"
                    else:
                        tool_result = await self.call_get_computer_info(computer_id)
                        context_type = "computer_info"
                else:
                    # List computers from domain
                    tool_result = await self.call_get_computers(domain_ids[0])
                    context_type = "computers"
            
            elif object_type == "gpo":
                if identifiers.get('guids'):
                    # Specific GPO analysis
                    gpo_id = identifiers['guids'][0]
                    if operation_type == "info":
                        tool_result = await self.call_get_gpo_info(gpo_id)
                        context_type = "gpo_info"
                    elif operation_type == "computers":
                        tool_result = await self.call_get_gpo_computers(gpo_id)
                        context_type = "gpo_computers"
                    elif operation_type == "users":
                        tool_result = await self.call_get_gpo_users(gpo_id)
                        context_type = "gpo_users"
                    elif operation_type == "analysis":
                        # Comprehensive GPO analysis
                        info = await self.call_get_gpo_info(gpo_id)
                        computers = await self.call_get_gpo_computers(gpo_id)
                        users = await self.call_get_gpo_users(gpo_id)
                        ous = await self.call_get_gpo_ous(gpo_id)
                        tool_result = f"GPO Info:\n{info}\n\nAffected Computers:\n{computers}\n\nAffected Users:\n{users}\n\nLinked OUs:\n{ous}"
                        context_type = "gpo_analysis"
                    else:
                        tool_result = await self.call_get_gpo_info(gpo_id)
                        context_type = "gpo_info"
                else:
                    # List GPOs from domain - use both get_gpos and get_linked_gpos for comprehensive view
                    gpos = await self.call_get_gpos(domain_ids[0])
                    linked_gpos = await self.call_get_linked_gpos(domain_ids[0])
                    tool_result = f"Domain GPOs:\n{gpos}\n\nLinked GPOs:\n{linked_gpos}"
                    context_type = "gpos"
            
            elif object_type == "certificate":
                if operation_type == "analysis":
                    # Get certificate templates and CAs (would need specific IDs in practice)
                    tool_result = "Certificate analysis requires specific template or CA IDs"
                    context_type = "certificate_analysis"
                else:
                    tool_result = "Certificate operations require specific template or CA IDs"
                    context_type = "certificate_info"
            
            elif operation_type == "cypher":
                # Extract cypher query from user input
                if 'match' in user_input.lower() or 'return' in user_input.lower():
                    # Looks like a cypher query
                    cypher_query = user_input
                    tool_result = await self.call_run_cypher_query(cypher_query)
                    context_type = "cypher_result"
                else:
                    tool_result = "Please provide a valid Cypher query"
                    context_type = "error"
            
            elif operation_type == "attack_path":
                # Attack path analysis
                if len(identifiers.get('guids', [])) >= 2:
                    start_node = identifiers['guids'][0]
                    end_node = identifiers['guids'][1]
                    tool_result = await self.call_get_shortest_path(start_node, end_node)
                    context_type = "attack_path"
                else:
                    tool_result = "Attack path analysis requires start and end node IDs"
                    context_type = "error"
            
            elif operation_type == "search":
                # Use existing smart search
                search_term, object_type_filter = self._parse_search_query(user_input)
                tool_result = await self.smart_search(search_term, object_type_filter)
                context_type = "search_results"
            
            else:
                # Default fallback - show domain overview
                tool_result = domains_result
                context_type = "domains"
            
            return tool_result, context_type
            
        except Exception as e:
            return f"Error during tool routing: {str(e)}", "error"
    
    async def analyze_query(self, user_input: str) -> str:
        """Enhanced query analysis with intelligent routing to all 79 MCP tools"""
        try:
            print(f"\nProcessing: {user_input}")
            
            # Detect object type and operation from user input
            object_type = self._detect_object_type(user_input)
            operation_type = self._detect_operation_type(user_input)
            identifiers = self._extract_object_identifiers(user_input)
            
            print(f"Detected - Object: {object_type}, Operation: {operation_type}, IDs: {list(identifiers.keys()) if identifiers else 'None'}")
            
            # Route to appropriate tools
            tool_result, context_type = await self._route_to_appropriate_tools(user_input, object_type, operation_type, identifiers)
            
            if not tool_result:
                # Fallback to search if no specific routing matched
                search_term, obj_type = self._parse_search_query(user_input)
                tool_result = await self.smart_search(search_term, obj_type)
                context_type = "search_results"
            
            # Determine if this is an analysis request
            is_analysis_request = any(word in user_input.lower() for word in [
                'analyze', 'analysis', 'explain', 'structure', 'relationship', 'parent', 'child',
                'security', 'implications', 'attack', 'risk', 'assessment', 'threat', 'vulnerable'
            ])
            
            # Generate appropriate prompt based on context
            if is_analysis_request:
                analysis_prompt = self._generate_analysis_prompt(user_input, tool_result, context_type)
            else:
                analysis_prompt = self._generate_response_prompt(user_input, tool_result, context_type)

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
    
    def _generate_analysis_prompt(self, user_input: str, tool_result: str, context_type: str) -> str:
        """Generate analysis prompt based on context type"""
        base_prompt = f"""You are a BloodHound security expert with deep knowledge of Active Directory and Azure environments.

User asked: "{user_input}"

BloodHound data:
{tool_result}

"""
        
        if context_type == "domains":
            return base_prompt + """Context: You're analyzing Active Directory domains. Key concepts:
- Domain trusts create attack paths between domains
- Child domains inherit from parent domains
- Cross-domain attacks are common in AD environments
- Azure domains represent hybrid cloud environments
- Domain hierarchy affects privilege escalation opportunities

Provide expert analysis addressing the user's specific question about domain structure, relationships, or security implications.

Analysis:"""
        
        elif context_type == "users":
            return base_prompt + """Context: You're analyzing user accounts. Key concepts:
- User accounts represent potential attack targets and entry points
- Service accounts often have elevated privileges
- Disabled accounts may still have active sessions or cached credentials
- High-privilege users (Domain Admins, Enterprise Admins) are primary targets
- Azure/AzureAD users may have cross-tenant access

Provide expert analysis addressing the user's specific question about the user accounts and their security implications.

Analysis:"""
        
        elif context_type == "groups":
            return base_prompt + """Context: You're analyzing group accounts. Key concepts:
- Group memberships determine access rights and permissions
- Nested groups can create complex privilege chains
- High-privilege groups (Domain Admins, Enterprise Admins) are primary targets
- Service groups often have elevated system access
- Azure groups may have cloud resource access

Provide expert analysis addressing the user's specific question about the groups and their security implications.

Analysis:"""
        
        elif context_type == "computers":
            return base_prompt + """Context: You're analyzing computer accounts. Key concepts:
- Computer accounts represent workstations and servers
- Domain controllers have highest privileges
- Unconstrained delegation computers can impersonate any user
- Local admin sessions create lateral movement opportunities
- Azure-joined computers may have hybrid access

Provide expert analysis addressing the user's specific question about the computers and their security implications.

Analysis:"""
        
        elif context_type == "attack_paths":
            return base_prompt + """Context: You're analyzing attack paths and relationships. Key concepts:
- Attack paths show how attackers can escalate privileges
- Shortest paths are often the most exploitable
- Multiple paths indicate systemic vulnerabilities
- Transitive relationships create indirect access
- High-value targets should have minimal exposure

Provide expert analysis addressing the user's specific question about attack paths and security implications.

Analysis:"""
        
        else:
            return base_prompt + """Context: You're analyzing BloodHound security data. Provide expert analysis addressing the user's specific question and identify any security implications.

Analysis:"""
    
    def _generate_response_prompt(self, user_input: str, tool_result: str, context_type: str) -> str:
        """Generate response prompt for non-analysis queries"""
        if context_type == "users":
            return f"""The user asked: "{user_input}"

BloodHound users data:
{tool_result}

Format the user data in a clean, readable list format. Use numbered items with details indented below each name.

Response:"""
        
        elif context_type == "search_results":
            return f"""The user asked: "{user_input}"

BloodHound search results:
{tool_result}

Format the search results in a clean, readable list format. Use numbered items with details indented below each name.

Response:"""
        
        else:
            return f"""The user asked: "{user_input}"

Here is the BloodHound data:
{tool_result}

Answer only what the user asked. Provide the information in a clean, readable format.

Response:"""
    
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
    
    async def _get_users_from_domains(self, domain_ids: list, limit: int = 500) -> str:
        """Get users from one or more domains"""
        try:
            # For now, just get users from the first domain to avoid overwhelming output
            domain_id = domain_ids[0]
            print(f"Getting users from domain: {domain_id}")
            
            # Try to get all users by setting a high limit
            users_result = await self.call_get_users(domain_id, limit=limit)
            
            # Try to parse and format the result
            import json
            try:
                result_data = json.loads(users_result)
                users = result_data.get('users', [])
                count = result_data.get('count', 0)
                
                print(f"DEBUG: API returned {len(users)} users, count field shows {count}")
                print(f"DEBUG: Requested limit was {limit}")
                
                # If we got fewer users than the count indicates, we might need pagination
                if len(users) < count and len(users) > 0:
                    print(f"WARNING: Only got {len(users)} out of {count} users. You might need pagination.")
                    print(f"TIP: The BloodHound API may have a maximum page size limit.")
                
                formatted_result = {
                    "message": f"Found {count} users in domain {domain_id} (showing {len(users)} users)",
                    "users": users,
                    "count": count,
                    "returned_count": len(users),
                    "domain_id": domain_id,
                    "note": f"Showing {len(users)} out of {count} total users" if len(users) < count else None
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