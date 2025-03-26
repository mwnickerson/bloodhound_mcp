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
    Specifics on what information you can provide on and analyse for a domain include:
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
    You also have the ability to look further into indivdual users within a domain. You can analyze which users are prime targets and how they can possibly be exploited.
    By combining all of the below information you can provie on a user you can provide an in dpeth analysis of a user.
    Information on the users includes:
    - User's general information
    - Administrative rights
    - Constrained delegation rights
    - Controllables
    - Controllers
    - DCOM rights
    - Group memberships
    - Remote PowerShell rights
    - RDP rights
    - Sessions
    - SQL administrative rights
    
    To get information, use the available tools to query the Bloodhound database."""

# Define tools for the MCP

# mcp tools for the /domains apis
@mcp.tool()
def get_domains():
    try:
        domains = bloodhound_api.domains.get_all()
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
        users = bloodhound_api.domains.get_users(domain_id, limit=limit, skip=skip)
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
        groups = bloodhound_api.domains.get_groups(domain_id, limit=limit, skip=skip)
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
        computers = bloodhound_api.domains.get_computers(domain_id, limit=limit, skip=skip)
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
        controllers = bloodhound_api.domains.get_controllers(domain_id, limit=limit, skip=skip)
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
        gpos = bloodhound_api.domains.get_gpos(domain_id, limit=limit, skip=skip)
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
        ous = bloodhound_api.domains.get_ous(domain_id, limit=limit, skip=skip)
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
        dc_syncers = bloodhound_api.domains.get_dc_syncers(domain_id, limit=limit, skip=skip)
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
        foreign_admins = bloodhound_api.domains.get_foreign_admins(domain_id, limit=limit, skip=skip)
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
        foreign_gpo_controllers = bloodhound_api.domains.get_foreign_gpo_controllers(domain_id, limit=limit, skip=skip)
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
        foreign_groups = bloodhound_api.domains.get_foreign_groups(domain_id, limit=limit, skip=skip)
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
        foreign_users = bloodhound_api.domains.get_foreign_users(domain_id, limit=limit, skip=skip)
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
        inbound_trusts = bloodhound_api.domains.get_inbound_trusts(domain_id, limit=limit, skip=skip)
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
        linked_gpos = bloodhound_api.domains.get_linked_gpos(domain_id, limit=limit, skip=skip)
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
        outbound_trusts = bloodhound_api.domains.get_outbound_trusts(domain_id, limit=limit, skip=skip)
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

# mcp tools for the /users apis
@mcp.tool()
def get_user_info(user_id: str):
    """
    Retrieves information about a specific user in a specific domain.
    This provides a general overview of a user's information including their name, domain, and other attributes.
    It can be used to conduct reconnaissance and start formulating and targeting users within the domain
    
    Args:
        user_id: The ID of the user to query
    """
    try:
        user_info = bloodhound_api.users.get_info(user_id)
        return json.dumps({
            "message": f"User information for {user_info.get('name')}",
            "user_info": user_info
        })
    except Exception as e:
        logger.error(f"Error retrieving user information: {e}")
        return json.dumps({
            "error": f"Failed to retrieve user information: {str(e)}"
        })

@mcp.tool()
def get_user_admin_rights(user_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves the administrative rights of a specific user in the domain.
    Administrative rights are privileges that allow a user to perform administrative tasks on a Security Principal (user, group, or computer) in Active Directory.
    These rights can be abused in a variety of ways include lateral movement, persistence, and privilege escalation.
    
    Args:
        user_id: The ID of the user to query
        limit: Maximum number of administrative rights to return (default: 100)
        skip: Number of administrative rights to skip for pagination (default: 0)
    """
    try:
        user_admin_rights = bloodhound_api.users.get_admin_rights(user_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {user_admin_rights.get('count', 0)} administrative rights for the user",
            "user_admin_rights": user_admin_rights.get("data", []),
            "count": user_admin_rights.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving user administrative rights: {e}")
        return json.dumps({
            "error": f"Failed to retrieve user administrative rights: {str(e)}"
        })

@mcp.tool()
def get_user_constrained_delegation_rights(user_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves the constrained delegation rights of a specific user within the domain.
    Constrained delegation rights allow a user to impersonate another user or service when communicating with a service on another computer.
    These rights can be abused for privilege escalation and lateral movement within the domain.
    
    Args:
        user_id: The ID of the user to query
        limit: Maximum number of constrained delegation rights to return (default: 100)
        skip: Number of constrained delegation rights to skip for pagination (default: 0)
    """
    try:
        user_constrained_delegation_rights = bloodhound_api.users.get_constrained_delegation_rights(user_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {user_constrained_delegation_rights.get('count', 0)} constrained delegation rights for the user",
            "user_constrained_delegation_rights": user_constrained_delegation_rights.get("data", []),
            "count": user_constrained_delegation_rights.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving user constrained delegation rights: {e}")
        return json.dumps({
            "error": f"Failed to retrieve user constrained delegation rights: {str(e)}"
        })
    
@mcp.tool()
def get_user_controllables(user_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves the Security Princiapls within the domain that a specific user has administrative control over in the domain.
    These are entities that the user can control and manipulate within the domain.
    These are potential targets for lateral movement, privilege escalation, and persistence.
    
    Args:
        user_id: The ID of the user to query
        limit: Maximum number of controllables to return (default: 100)
        skip: Number of controllables to skip for pagination (default: 0)
    """
    try:
        user_controlables = bloodhound_api.users.get_controllables(user_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {user_controlables.get('count', 0)} controlables for the user",
            "user_controlables": user_controlables.get("data", []),
            "count": user_controlables.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving user controlables: {e}")
        return json.dumps({
            "error": f"Failed to retrieve user controlables: {str(e)}"
        })

@mcp.tool()
def get_user_controllers(user_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves the controllers of a specific user in the domain.
    Controllers are entities that have control over the specified user
    This can be used to help identify paths to gain access to a specific user.
    
    Args:
        user_id: The ID of the user to query
        limit: Maximum number of controllers to return (default: 100)
        skip: Number of controllers to skip for pagination (default: 0)
    """
    try:
        user_controllers = bloodhound_api.users.get_controllers(user_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {user_controllers.get('count', 0)} controllers for the user",
            "user_controllers": user_controllers.get("data", []),
            "count": user_controllers.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving user controllers: {e}")
        return json.dumps({
            "error": f"Failed to retrieve user controllers: {str(e)}"
        })

@mcp.tool()
def get_user_dcom_rights(user_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves the DCOM rights of a specific user within the domain.
    DCOM rights allow a user to communicate with COM objects on another computer in the network.
    These rights can be abused for privilege escalation and lateral movement within the domain.
    
    Args:
        user_id: The ID of the user to query
        limit: Maximum number of DCOM rights to return (default: 100)
        skip: Number of DCOM rights to skip for pagination (default: 0)
    """
    try:
        user_dcom_rights = bloodhound_api.users.get_dcom_rights(user_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {user_dcom_rights.get('count', 0)} DCOM rights for the user",
            "user_dcom_rights": user_dcom_rights.get("data", []),
            "count": user_dcom_rights.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving user DCOM rights: {e}")
        return json.dumps({
            "error": f"Failed to retrieve user DCOM rights: {str(e)}"
        })

@mcp.tool()
def get_user_memberships(user_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves the group memberships of a specific user within the domain.
    Group memberships are the groups that a user is a member of within the domain.
    These memberships can be used to identify potential targets for lateral movement and privilege escalation.
    
    Args:
        user_id: The ID of the user to query
        limit: Maximum number of memberships to return (default: 100)
        skip: Number of memberships to skip for pagination (default: 0)
    """
    try:
        user_memberships = bloodhound_api.users.get_memberships(user_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {user_memberships.get('count', 0)} memberships for the user",
            "user_memberships": user_memberships.get("data", []),
            "count": user_memberships.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving user memberships: {e}")
        return json.dumps({
            "error": f"Failed to retrieve user memberships: {str(e)}"
        })
    
@mcp.tool()
def get_user_ps_remote_rights(user_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves the remote PowerShell rights of a specific user within the domain.
    Remote PowerShell rights allow a user to execute PowerShell commands on a remote computer.
    These rights can be abused for lateral movement and privilege escalation within the domain.

    Args:
        user_id: The ID of the user to query
        limit: Maximum number of remote PowerShell rights to return (default: 100)
        skip: Number of remote PowerShell rights to skip for pagination
    """
    try:
        user_ps_remote_rights = bloodhound_api.users.get_ps_remote_rights(user_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {user_ps_remote_rights.get('count', 0)} remote PowerShell rights for the user",
            "user_ps_remote_rights": user_ps_remote_rights.get("data", []),
            "count": user_ps_remote_rights.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving user remote PowerShell rights: {e}")
        return json.dumps({
            "error": f"Failed to retrieve user remote PowerShell rights: {str(e)}"
        })

@mcp.tool()
def get_user_rdp_rights(user_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves the RDP rights of a specific user within the domain.
    RDP rights allow a user to remotely connect to another computer using the Remote Desktop Protocol.
    These rights can be abused for lateral movement and privilege escalation within the domain.
    
    Args:
        user_id: The ID of the user to query
        limit: Maximum number of RDP rights to return (default: 100)
        skip: Number of RDP rights to skip for pagination (default: 0)
    """
    try:
        user_rdp_rights = bloodhound_api.users.get_rdp_rights(user_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {user_rdp_rights.get('count', 0)} RDP rights for the user",
            "user_rdp_rights": user_rdp_rights.get("data", []),
            "count": user_rdp_rights.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving user RDP rights: {e}")
        return json.dumps({
            "error": f"Failed to retrieve user RDP rights: {str(e)}"
        })
    
@mcp.tool()
def get_user_sessions(user_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves the active sessions of a specific user within the domain.
    Active sessions are the current sessions that a user has within the domain.
    These sessions can be used to identify potential targets for lateral movement and privilege escalation.
    It can also be used to indentify and plan attack paths within the domain.
    
    Args:
        user_id: The ID of the user to query
        limit: Maximum number of sessions to return (default: 100)
        skip: Number of sessions to skip for pagination (default: 0)
    """
    try:
        user_sessions = bloodhound_api.users.get_sessions(user_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {user_sessions.get('count', 0)} sessions for the user",
            "user_sessions": user_sessions.get("data", []),
            "count": user_sessions.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving user sessions: {e}")
        return json.dumps({
            "error": f"Failed to retrieve user sessions: {str(e)}"
        })

@mcp.tool()
def get_user_sql_admin_rights(user_id: str, limit: int = 100, skip: int = 0):
    """
    Retrieves the SQL administrative rights of a specific user within the domain.
    SQL administrative rights allow a user to perform administrative tasks on a SQL Server.
    These rights can be abused for lateral movement and privilege escalation within the domain.
    
    Args:
        user_id: The ID of the user to query
        limit: Maximum number of SQL administrative rights to return (default: 100)
        skip: Number of SQL administrative rights to skip for pagination (default: 0)
    """
    try:
        user_sql_admin_rights = bloodhound_api.users.get_sql_admin_rights(user_id, limit=limit, skip=skip)
        return json.dumps({
            "message": f"Found {user_sql_admin_rights.get('count', 0)} SQL administrative rights for the user",
            "user_sql_admin_rights": user_sql_admin_rights.get("data", []),
            "count": user_sql_admin_rights.get("count", 0)
        })
    except Exception as e:
        logger.error(f"Error retrieving user SQL administrative rights: {e}")
        return json.dumps({
            "error": f"Failed to retrieve user SQL administrative rights: {str(e)}"
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