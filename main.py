#!/usr/bin/env python3
"""
MCP Server for Bloodhound Community Edition
This server provides an interface between an LLM and the Bloodhound CE data
"""

import os
import json
import argparse
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv
import logging

# Import FastMCP
from mcp.server.fastmcp import FastMCP

# Import Bloodhound API client
from lib.bloodhound_api import BloodhoundAPI

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize the MCP server and Bloodhound API client
mcp = FastMCP("bloodhound_mcp")
bloodhound_api = BloodhoundAPI()

# Define prompts
@mcp.prompt()
def bloodhound_assistant() -> str:
    return """You are an AI assistant that helps security professionals analyze Active Directory environments using Bloodhound data.
    You can provide information about domains, users, groups, computers, GPOs, and attack paths.
    To get information, use the available tools to query the Bloodhound database."""

# Define tools for the MCP
@mcp.tool()
def get_domains():
    """
    Retrieves all domains from the Bloodhound database.
    """
    try:
        domains = bloodhound_api.get_domains()
        return json.dumps({
            "message": f"Found {len(domains)} domains in Bloodhound",
            "domains": domains
        })
    except Exception as e:
        logger.error(f"Error retrieving domains: {e}")
        return json.dumps({
            "error": f"Failed to retrieve domains: {str(e)}"
        })

@mcp.tool()
def get_users(domain_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves users from a specific domain in the Bloodhound database.
    
    Args:
        domain_id: The ID of the domain to query
        limit: Maximum number of users to return (default: 100)
        skip: Number of users to skip for pagination (default: 0)
    """
    try:
        users = bloodhound_api.get_users(domain_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {users.get('count', 0)} users in the domain",
            "users": users.get("data", []),
            "count": users.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving users: {e}")
        return json.dumps({
            "error": f"Failed to retrieve users: {str(e)}"
        })

@mcp.tool()
def get_groups(domain_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves groups from a specific domain in the Bloodhound database.
    
    Args:
        domain_id: The ID of the domain to query
        limit: Maximum number of groups to return (default: 100)
        skip: Number of groups to skip for pagination (default: 0)
    """
    try:
        groups = bloodhound_api.get_groups(domain_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {groups.get('count', 0)} groups in the domain",
            "groups": groups.get("data", []),
            "count": groups.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving groups: {e}")
        return json.dumps({
            "error": f"Failed to retrieve groups: {str(e)}"
        })

@mcp.tool()
def get_computers(domain_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves computers from a specific domain in the Bloodhound database.
    
    Args:
        domain_id: The ID of the domain to query
        limit: Maximum number of computers to return (default: 100)
        skip: Number of computers to skip for pagination (default: 0)
    """
    try:
        computers = bloodhound_api.get_computers(domain_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {computers.get('count', 0)} computers in the domain",
            "computers": computers.get("data", []),
            "count": computers.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving computers: {e}")
        return json.dumps({
            "error": f"Failed to retrieve computers: {str(e)}"
        })

@mcp.tool()
def get_controllers(domain_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves the controllers from a specific domain in the Bloodhound database.
    
    Args:
        domain_id: The ID of the domain to query
        limit: Maximum number of controllers to return (default: 100)
        skip: Number of controllers to skip for pagination (default: 0)
    """
    try:
        controllers = bloodhound_api.get_controllers(domain_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {controllers.get('count', 0)} controllers",
            "controllers": controllers.get("data", []),
            "count": controllers.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving controllers: {e}")
        return json.dumps({
            "error": f"Failed to retrieve controllers: {str(e)}"
        })

@mcp.tool()
def get_gpos(domain_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves Group Policy Objects (GPOs) from a specific domain in the Bloodhound database.
    
    Args:
        domain_id: The ID of the domain to query
        limit: Maximum number of GPOs to return (default: 100)
        skip: Number of GPOs to skip for pagination (default: 0)
    """
    try:
        gpos = bloodhound_api.get_gpos(domain_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {gpos.get('count', 0)} GPOs in the domain",
            "gpos": gpos.get("data", []),
            "count": gpos.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving GPOs: {e}")
        return json.dumps({
            "error": f"Failed to retrieve GPOs: {str(e)}"
        })


async def main():
    """Main function to start the server"""
    # Test connection to Bloodhound API
    try:
        version_info = bloodhound_api.test_connection()
        if version_info:
            logger.info(f"Successfully connected to Bloodhound API. Version: {version_info}")
        else:
            logger.error("Failed to connect to Bloodhound API")
    except Exception as e:
        logger.error(f"Error connecting to Bloodhound API: {e}")
    
    # Run the MCP server
    await mcp.run_stdio_async()

if __name__ == "__main__":
    import asyncio
    parser = argparse.ArgumentParser(description="Bloodhound CE MCP Server")
    # Add any command line arguments you need
    
    args = parser.parse_args()
    
    # Start the server
    asyncio.run(main())