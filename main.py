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
    You can provide and anlyze information an organization's active directory environment. 
    Specifics on what informaytion you can provide on and analyse include:
    - Users
    - Groups
    - Computers
    - Controllers
    - Group Policy Objects (GPOs)
    - Organizational Units (OUs)
    - DC Syncers
    - Foreign Admins
    - Foreign GPO Controllers
    - Foreign Groups
    - Foreign Users
    - Inbound Trusts
    - Linked GPOs
    - Outbound Trusts
    To get information, use the available tools to query the Bloodhound database."""

# Define tools for the MCP

# mcp tools for the /domains apis
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
    Controller are specific entities that have control privileges over other entities within the domain.
    These are key for idenitfying potential attack paths.
    
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
    GPOs are containers for policy settings that can be applied to users and computers in Active Directory.
    These can be abused for persistence and privilege escalation and are key in idenitfying GPO related edges.
    
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

@mcp.tool()
def get_ous(domain_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves Organizational Units (OUs) from a specific domain in the Bloodhound database.
    OUs are containers within a domain that can hold users, groups, computers, and other OUs.
    These are key in understanding the structure of the domain.
    
    Args: 
        domain_id: The ID of the domain to query
        limit: Maximum number of OUs to return (default: 100)
        skip: Number of OUs to skip for pagination (default
    """
    try:
        ous = bloodhound_api.get_ous(domain_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {ous.get('count', 0)} OUs in the domain",
            "ous": ous.get("data", []),
            "count": ous.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving OUs: {e}")
        return json.dumps({
            "error": f"Failed to retrieve OUs: {str(e)}"
        })

@mcp.tool()
def get_dc_syncers(domain_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves security principals (users, groups, computers ) that are given the "GetChanges" and "GetChangesAll" permissions on the domain.
    The security principals are therefore able to perform a DCSync attack.
    They are are great targets for lateral movement or privilege escalation or domain compromise.

    Args:
        domain_id: The ID of the domain to query
        limit: Maximum number of DC Syncers to return (default: 100)
        skip: Number of DC Syncers to skip for pagination (default: 0)
    """
    try:
        dc_syncers = bloodhound_api.get_dc_syncers(domain_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {dc_syncers.get('count', 0)} DC Syncers in the domain",
            "dc_syncers": dc_syncers.get("data", []),
            "count": dc_syncers.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving DC Syncers: {e}")
        return json.dumps({
            "error": f"Failed to retrieve DC Syncers: {str(e)}"
        })
    
@mcp.tool()
def get_foreign_admins(domain_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves foreign admins from a specific domain in the Bloodhound database.
     "Foreign Admins" are defined as security principals (users, groups, or computers) from one domain that have administrative privileges in another domain within the same forest.
    These are potential targets for lateral movement and privilege escalation as well as cross domain compromise.
    
    Args:
        domain_id: The ID of the domain to query
        limit: Maximum number of foreign admins to return (default: 100)
        skip: Number of foreign admins to skip for pagination (default: 0)
    """
    try:
        foreign_admins = bloodhound_api.get_foreign_admins(domain_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {foreign_admins.get('count', 0)} foreign admins in the domain",
            "foreign_admins": foreign_admins.get("data", []),
            "count": foreign_admins.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving foreign admins: {e}")
        return json.dumps({
            "error": f"Failed to retrieve foreign admins: {str(e)}"
        })

@mcp.tool()
def get_foreign_gpo_controllers(domain_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves foreign GPO controllers from a specific domain in the Bloodhound database.
    "Foreign GPO Controllers" are defined as security principals (users, groups, or computers) from one domain that have the ability to modify or control Group Policy Objects (GPOs) in another domain within the same forest
    These are potential targets for lateral movement and privilege escalation as well as cross domain compromise.
    
    Args:
        domain_id: The ID of the domain to query
        limit: Maximum number of foreign GPO controllers to return (default: 100)
        skip: Number of foreign GPO controllers to skip for pagination (default: 0)
    """
    try:
        foreign_gpo_controllers = bloodhound_api.get_foreign_gpo_controllers(domain_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {foreign_gpo_controllers.get('count', 0)} foreign GPO controllers in the domain",
            "foreign_gpo_controllers": foreign_gpo_controllers.get("data", []),
            "count": foreign_gpo_controllers.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving foreign GPO controllers: {e}")
        return json.dumps({
            "error": f"Failed to retrieve foreign GPO controllers: {str(e)}"
        })
    
@mcp.tool()
def get_foreign_groups(domain_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves foreign groups from a specific domain in the Bloodhound database.
    "Foreign Groups" are defined as security groups from one domain that have members from another domain within the same forest. They represent cross-domain group memberships in Active Directory.
    These are potential targets for lateral movement and privilege escalation as well as cross domain compromise.
    
    Args:
        domain_id: The ID of the domain to query
        limit: Maximum number of foreign groups to return (default: 100)
        skip: Number of foreign groups to skip for pagination (default: 0)
    """
    try:
        foreign_groups = bloodhound_api.get_foreign_groups(domain_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {foreign_groups.get('count', 0)} foreign groups in the domain",
            "foreign_groups": foreign_groups.get("data", []),
            "count": foreign_groups.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving foreign groups: {e}")
        return json.dumps({
            "error": f"Failed to retrieve foreign groups: {str(e)}"
        })

@mcp.tool()
def get_foreign_users(domain_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves foreign users from a specific domain in the Bloodhound database.
    "Foreign Users" are defined as user accounts from one domain that are referenced in another domain within the same forest. These represent user accounts that have some form of relationship or access across domain boundaries.
    These are potential targets for lateral movement and privilege escalation as well as cross domain compromise.
    
    Args:
        domain_id: The ID of the domain to query
        limit: Maximum number of foreign users to return (default: 100)
        skip: Number of foreign users to skip for pagination (default: 0)
    """
    try:
        foreign_users = bloodhound_api.get_foreign_users(domain_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {foreign_users.get('count', 0)} foreign users in the domain",
            "foreign_users": foreign_users.get("data", []),
            "count": foreign_users.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving foreign users: {e}")
        return json.dumps({
            "error": f"Failed to retrieve foreign users: {str(e)}"
        })
    
@mcp.tool()
def get_inbound_trusts(domain_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves inbound trusts from a specific domain in the Bloodhound database.
    "Inbound Trusts" are defined as trust relationships where the domain is the trusted domain and other domains trust it.
    These are potential targets for moving to other external domains or other domains within the forest
    
    Args:
        domain_id: The ID of the domain to query
        limit: Maximum number of inbound trusts to return (default: 100)
        skip: Number of inbound trusts to skip for pagination (default: 0)
    """
    try:
        inbound_trusts = bloodhound_api.get_inbound_trusts(domain_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {inbound_trusts.get('count', 0)} inbound trusts in the domain",
            "inbound_trusts": inbound_trusts.get("data", []),
            "count": inbound_trusts.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving inbound trusts: {e}")
        return json.dumps({
            "error": f"Failed to retrieve inbound trusts: {str(e)}"
        })

@mcp.tool()
def get_linked_gpos(domain_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves linked GPOs from a specific domain in the Bloodhound database.
    "Linked GPOs" are defined as Group Policy Objects that have been linked to or associated with specific Active Directory containers such as domains, organizational units (OUs), or sites
    These are potential targets for moving laterally, elevating privileges, or maintaining persistence in the domain.
    
    Args:
        domain_id: The ID of the domain to query
        limit: Maximum number of linked GPOs to return (default: 100)
        skip: Number of linked GPOs to skip for pagination (default: 0)
    """
    try:
        linked_gpos = bloodhound_api.get_linked_gpos(domain_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {linked_gpos.get('count', 0)} linked GPOs in the domain",
            "linked_gpos": linked_gpos.get("data", []),
            "count": linked_gpos.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving linked GPOs: {e}")
        return json.dumps({
            "error": f"Failed to retrieve linked GPOs: {str(e)}"
        })

@mcp.tool()
def get_outbound_trusts(domain_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves outbound trusts from a specific domain in the Bloodhound database.
    "Outbound Trusts" are defined as trust relationships where the domain trusts other domains.
    These are potential targets for accessing resources within another domain and may provide a path into the domain if the external one has weaker security.
    
    Args:
        domain_id: The ID of the domain to query
        limit: Maximum number of outbound trusts to return (default: 100)
        skip: Number of outbound trusts to skip for pagination (default: 0)
    """
    try:
        outbound_trusts = bloodhound_api.get_outbound_trusts(domain_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {outbound_trusts.get('count', 0)} outbound trusts in the domain",
            "outbound_trusts": outbound_trusts.get("data", []),
            "count": outbound_trusts.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving outbound trusts: {e}")
        return json.dumps({
            "error": f"Failed to retrieve outbound trusts: {str(e)}"
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