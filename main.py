#!/usr/bin/python3
"""
MCP Server for BloodHound
This server acts as an interface between an LLM and the BloodHound Server
v2.0
Trying to be more token iffecient
"""

import json
import logging
import re
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

# Import FastMCP
from mcp.server.fastmcp import FastMCP

# Import Bloodhound API client
from lib.bloodhound_api import (
    BloodhoundAPI,
    BloodhoundAPIError,
    BloodhoundConnectionError,
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

AGGREGATION_FUNCTIONS = ("COUNT", "COLLECT", "SUM", "AVG", "MIN", "MAX")
AGGREGATION_PATTERN = re.compile(
    r"\b(" + "|".join(AGGREGATION_FUNCTIONS) + r")\s*\(",
    re.IGNORECASE,
)

# Load environment variables
load_dotenv()

# Initialize the MCP server and Bloodhound API client
mcp = FastMCP("bloodhound_mcp")
bloodhound_api = BloodhoundAPI()


# Helper function
# eliminates repitiver error handling boilerplate that was in all of the tools.
def _handle_tool_call(info_type: str, handlers: dict, **context):
    """Dispatch a composite tool call to the appropriate handler"""
    handler = handlers.get(info_type)
    if not handler:
        valid = ", ".join(sorted(handlers.keys()))
        return json.dumps(
            {"error": f"Unknown info_type '{info_type}'. Valid options: {valid}"}
        )
    try:
        result = handler()
        return json.dumps({"info_type": info_type, "data": result, **context})
    except BloodhoundConnectionError as e:
        return json.dumps({"error": f"Connection error: {str(e)}"})
    except BloodhoundAPIError as e:
        return json.dumps({"error": f"API error: (HTTP {e.status_code}) {str(e)}"})
    except Exception as e:
        logger.error(f"Error in {info_type}: {str(e)}")
        return json.dumps({"error": f"Unexpected error in {info_type}: {str(e)}"})


# Create the prompts
# Slimmed down prompt with instructuons to use resources for more information
@mcp.prompt()
def bloodhound_assistant() -> str:
    return """You are a security analysis assistant for BloodHound.

    You help analyze attack paths and security relationships across:
    - Active Directory (users, computers, groups, GPOs, OUs, ADCS, etc.)
    - Azure / Entra ID (users, groups, apps, service principals, tenants)
    - Other infrastructure via OpenGraph (user-defined node types, edges, and relationships)

    BloodHound models all of these as a unified graph.
    Relationships between standard AD/Entra objects and Custom OpenGraph nodes enable attack path
    analysis across the full environment, not just Active Directory.

    ## Workflow
    1. Use domain_info(info_type="search", query="...") to find objects by name or ID
    2. Use composite tools to drill into specific objects or request all information about the object
    3. Use cypher_query(info_type="run") for advanced cross-domain analysis
    4. Use custom_nodes to manage legacy OpenGraph custom node display configs and BloodHound v9 extension schemas
    5. Use file_upload(info_type="upload", file_path="...") to ingest SharpHound/AzureHound collection data (.zip or .json)
    6. For Azure: prefer Cypher queries over REST API tools
    7. For OpenGraph: prompt the user for OpenGraph schema and example queries, then use these to create Cypher queries

    ## Behavioral Rules — Follow These Before Writing Cypher
    1. Before writing custom Cypher for any offensive scenario (DCSync, GPO abuse, delegation,
       Kerberoasting, file servers, shadow credentials, NTLM relay, ADCS, infrastructure enumeration),
       load bloodhound://cypher/offensive-queries and use the relevant template as a starting point.
    2. Never label a user as "regular", "non-privileged", or "standard" without first verifying group
       memberships: MATCH (u:User {objectid: $id})-[:MemberOf*1..]->(g:Group) RETURN g.name
    3. Never label a computer as a "workstation" without checking operatingsystem and DC status.
    4. When results contain User or Computer nodes, cross-reference admincount, group memberships,
       and enabled status before drawing privilege conclusions.
    5. All BloodHound node properties are lowercase: hasspn, enabled, admincount, dontreqpreauth,
       unconstraineddelegation. List properties (serviceprincipalnames, etc.) require
       COALESCE(n.serviceprincipalnames, []) to avoid null errors.
    6. BloodHound stores names as UPPERCASE with domain suffix: 'DOMAIN ADMINS@CORP.LOCAL'.
       Use TOUPPER() or exact uppercase strings when filtering by name.
    7. DCSync rights target Domain nodes, not Groups. Always query:
       MATCH (n)-[:DCSync|GetChanges|GetChangesAll]->(d:Domain)
    8. GPO abuse requires the full chain: principal -> write edge -> GPO -> GPLink -> OU -> Contains -> targets.
       Never skip intermediate nodes — the GPLink edge goes FROM the GPO TO the container.
    9. Load bloodhound://cypher/reference when in doubt about schema, property names, or syntax.
    10. COUNT, COLLECT, SUM, AVG, MIN, and MAX are API-safe but not BloodHound GUI-safe.
        Use them with cypher_query(info_type="run") when you need aggregation. When giving the
        user a query to paste into the GUI, return individual nodes, edges, or paths instead.

    ## Resources
    Quick reference (load as needed):
    - bloodhound://cypher/reference — Cypher syntax, schema, property names, and examples
    - bloodhound://cypher/offensive-queries — Battle-tested templates for DCSync, GPO abuse,
      Kerberoasting, delegation, ADCS, infrastructure enumeration, shadow credentials, and more
    - bloodhound://guides/ad — AD node types, relationships, tool workflow
    - bloodhound://guides/azure — Azure/Entra analysis quick reference
    - bloodhound://guides/adcs — ADCS ESC1-ESC13 quick reference

    Deep methodology (load for in-depth analysis):
    - bloodhound://guides/ad-methodology — Full AD attack patterns and workflow
    - bloodhound://guides/azure-methodology — Full Azure attack chains
    - bloodhound://guides/adcs-methodology — Detailed ESC analysis and exploitation

    OpenGraph (load when working with custom nodes):
    - bloodhound://opengraph/guide — Custom node and extension schema design
    - bloodhound://opengraph/examples — SQL Server and Web App implementation examples

    Each tool's info_type parameter controls what data is retrieved.
"""


# Create the tools
# going with composite tools to cut down on the tokens


# domain info composite tool
@mcp.tool()
def domain_info(
    info_type: str = "list",
    domain_id: str = None,
    query: str = None,
    object_type: str = None,
    limit: int = 100,
    skip: int = 0,
) -> str:
    """Query domain level data from BloodHound
    info_type options:
        list - list all domains (no domain_id needed)
        search - search objects by name/ID (needs query param, domain_id not needed)
        users - users in the domain
        groups - groups in the domain
        computers - computers in the domain
        controllers - security prinicpals with control relationships
        gpos - Group Policy Objects
        ous - Organizational unites
        dc_syncers - Principals with DCSync rights
        foreign_admins - admins from other domains
        foreign_gpo_controllers - GPO controllers from other domains
        foreign_groups - groups with cross domain members
        foreign_users - users referenced across domains
        inbound_trusts - domains that trust this domain
        outbound_trusts - domains this domain trusts
    Args:
        info_type: what to retrieve (default: list)
        domain_id: Domain object ID (required for most info_types)
        query: Search text (for info_type=search only)
        object_type: Filter by type - User, computer, Group, GPO, OU, Domain, AZUer, etc. (search only)
        limit: Max Results (default 100, useful in large environments)
        skip: Pagination offset (default 0)
    """
    handlers = {
        "list": lambda: bloodhound_api.domains.get_all(),
        "search": lambda: bloodhound_api.domains.search_objects(
            query, object_type, limit=limit, skip=skip
        ),
        "users": lambda: bloodhound_api.domains.get_users(
            domain_id, limit=limit, skip=skip
        ),
        "groups": lambda: bloodhound_api.domains.get_groups(
            domain_id, limit=limit, skip=skip
        ),
        "computers": lambda: bloodhound_api.domains.get_computers(
            domain_id, limit=limit, skip=skip
        ),
        "controllers": lambda: bloodhound_api.domains.get_controllers(
            domain_id, limit=limit, skip=skip
        ),
        "gpos": lambda: bloodhound_api.domains.get_gpos(
            domain_id, limit=limit, skip=skip
        ),
        "ous": lambda: bloodhound_api.domains.get_ous(
            domain_id, limit=limit, skip=skip
        ),
        "dc_syncers": lambda: bloodhound_api.domains.get_dc_syncers(
            domain_id, limit=limit, skip=skip
        ),
        "foreign_admins": lambda: bloodhound_api.domains.get_foreign_admins(
            domain_id, limit=limit, skip=skip
        ),
        "foreign_gpo_controllers": lambda: (
            bloodhound_api.domains.get_foreign_gpo_controllers(
                domain_id, limit=limit, skip=skip
            )
        ),
        "foreign_groups": lambda: bloodhound_api.domains.get_foreign_groups(
            domain_id, limit=limit, skip=skip
        ),
        "foreign_users": lambda: bloodhound_api.domains.get_foreign_users(
            domain_id, limit=limit, skip=skip
        ),
        "inbound_trusts": lambda: bloodhound_api.domains.get_inbound_trusts(
            domain_id, limit=limit, skip=skip
        ),
        "outbound_trusts": lambda: bloodhound_api.domains.get_outbound_trusts(
            domain_id, limit=limit, skip=skip
        ),
    }
    return _handle_tool_call(info_type, handlers)


# User info composite tool
@mcp.tool()
def user_info(
    user_id: str,
    info_type: str = "info",
    limit: int = 100,
    skip: int = 0,
) -> str:
    """Query user data from BloodHound
    info_type options:
        info - General user properties and attributes
        admin_rights - machine/objects this user has admin rights on
        constrained_delegation - services this use can delegate to via kerberos
        controllables - objects this use can control (WriteOwner, GenericAll, etc.)
        controllers - principals that have control over this user
        dcom_rights - machines this user can execute DCOM on
        memberships - groups this user belongs to
        ps_remote_rights - machines this user can PSRemote to
        rdp_rights - machines this user can RDP to
        sessions - machines this user has active sessions
        sql_admin_rights - SQL servers this user is admin on

    Args:
        user_id: BloodHound object ID of the user (required)
        info_type: what to retrieve (default: info)
        limit: Max Results (default 100, useful in large environments)
        skip: Pagination offset (default 0)
    """
    handlers = {
        "info": lambda: bloodhound_api.users.get_info(user_id),
        "admin_rights": lambda: bloodhound_api.users.get_admin_rights(
            user_id, limit=limit, skip=skip
        ),
        "constrained_delegation": lambda: (
            bloodhound_api.users.get_constrained_delegation_rights(
                user_id, limit=limit, skip=skip
            )
        ),
        "controllables": lambda: bloodhound_api.users.get_controllables(
            user_id, limit=limit, skip=skip
        ),
        "controllers": lambda: bloodhound_api.users.get_controllers(
            user_id, limit=limit, skip=skip
        ),
        "dcom_rights": lambda: bloodhound_api.users.get_dcom_rights(
            user_id, limit=limit, skip=skip
        ),
        "memberships": lambda: bloodhound_api.users.get_memberships(
            user_id, limit=limit, skip=skip
        ),
        "ps_remote_rights": lambda: bloodhound_api.users.get_ps_remote_rights(
            user_id, limit=limit, skip=skip
        ),
        "rdp_rights": lambda: bloodhound_api.users.get_rdp_rights(
            user_id, limit=limit, skip=skip
        ),
        "sessions": lambda: bloodhound_api.users.get_sessions(
            user_id, limit=limit, skip=skip
        ),
        "sql_admin_rights": lambda: bloodhound_api.users.get_sql_admin_rights(
            user_id, limit=limit, skip=skip
        ),
    }
    return _handle_tool_call(info_type, handlers, user_id=user_id)


# group info composite tool
@mcp.tool()
def group_info(
    group_id: str,
    info_type: str = "info",
    limit: int = 100,
    skip: int = 0,
) -> str:
    """Query group data from BloodHound.
    info_type options:
        info - general group properties and attributes
        admin_rights - machine/objects this group has admin rights on
        controllables - objects this group can control
        controllers - principals that have control over this group
        dcom_rights - machines this group can execute DCOM on
        members - users and groups that are members of this group
        memberships - groups this group belongs to (nested membership)
        ps_remote_rights - machines this group can PSRemote to
        rdp_rights - machines this group can RDP to
        sessions - machines this group has active sessions on
    args:
        group_id: BloodHound object ID of the group (required)
        info_type: what to retrieve (default: info)
        limit: Max Results (default 100, useful in large environments)
        skip: Pagination offset (default 0)
    """
    handlers = {
        "info": lambda: bloodhound_api.groups.get_info(group_id),
        "admin_rights": lambda: bloodhound_api.groups.get_admin_rights(
            group_id, limit=limit, skip=skip
        ),
        "controllables": lambda: bloodhound_api.groups.get_controllables(
            group_id, limit=limit, skip=skip
        ),
        "controllers": lambda: bloodhound_api.groups.get_controllers(
            group_id, limit=limit, skip=skip
        ),
        "dcom_rights": lambda: bloodhound_api.groups.get_dcom_rights(
            group_id, limit=limit, skip=skip
        ),
        "members": lambda: bloodhound_api.groups.get_members(
            group_id, limit=limit, skip=skip
        ),
        "memberships": lambda: bloodhound_api.groups.get_memberships(
            group_id, limit=limit, skip=skip
        ),
        "ps_remote_rights": lambda: bloodhound_api.groups.get_ps_remote_rights(
            group_id, limit=limit, skip=skip
        ),
        "rdp_rights": lambda: bloodhound_api.groups.get_rdp_rights(
            group_id, limit=limit, skip=skip
        ),
        "sessions": lambda: bloodhound_api.groups.get_sessions(
            group_id, limit=limit, skip=skip
        ),
    }
    return _handle_tool_call(info_type, handlers, group_id=group_id)


# computer info composite tool
@mcp.tool()
def computer_info(
    computer_id: str,
    info_type: str = "info",
    limit: int = 100,
    skip: int = 0,
) -> str:
    """Query computer data from BloodHound.
    info_type options:
        info - general computer properties and attributes
        admin_rights - objects this computer has admin rights on
        admin_users - users/groups that have admin rights on this computer
        constrained_delegation - services this computer can delegate to via kerberos
        constrained_users - users with contained delegation TO this computer
        controllables - objects this computer can control
        controllers - principals that have control over this computer
        dcom_rights - machines this computer can execute DCOM on
        dcom_users - users/groups with DCOM rights ON this computer
        group_membership - groups this computer belongs to
        ps_remote_rights - machines this computer can PSRemote to
        ps_remote_users - users/groups with PSRemote rights ON this computer
        rdp_rights - machines this computer can RDP to
        rdp_users - users/groups with RDP rights ON this computer
        sessions - users with active sessions on this computer
        sql_admins - SQL servers this computer is admin on

    args:
        computer_id: BloodHound object ID of the computer (required)
        info_type: what to retrieve (default: info)
        limit: Max Results (default 100, useful in large environments)
        skip: Pagination offset (default 0)
    """
    handlers = {
        "info": lambda: bloodhound_api.computers.get_info(computer_id),
        "admin_rights": lambda: bloodhound_api.computers.get_admin_rights(
            computer_id, limit=limit, skip=skip
        ),
        "admin_users": lambda: bloodhound_api.computers.get_admin_users(
            computer_id, limit=limit, skip=skip
        ),
        "constrained_delegation": lambda: (
            bloodhound_api.computers.get_constrained_delegation_rights(
                computer_id, limit=limit, skip=skip
            )
        ),
        "constrained_users": lambda: bloodhound_api.computers.get_constrained_users(
            computer_id, limit=limit, skip=skip
        ),
        "controllables": lambda: bloodhound_api.computers.get_controllables(
            computer_id, limit=limit, skip=skip
        ),
        "controllers": lambda: bloodhound_api.computers.get_controllers(
            computer_id, limit=limit, skip=skip
        ),
        "dcom_rights": lambda: bloodhound_api.computers.get_dcom_rights(
            computer_id, limit=limit, skip=skip
        ),
        "dcom_users": lambda: bloodhound_api.computers.get_dcom_users(
            computer_id, limit=limit, skip=skip
        ),
        "group_membership": lambda: bloodhound_api.computers.get_group_membership(
            computer_id, limit=limit, skip=skip
        ),
        "ps_remote_rights": lambda: bloodhound_api.computers.get_ps_remote_rights(
            computer_id, limit=limit, skip=skip
        ),
        "ps_remote_users": lambda: bloodhound_api.computers.get_ps_remote_users(
            computer_id, limit=limit, skip=skip
        ),
        "rdp_rights": lambda: bloodhound_api.computers.get_rdp_rights(
            computer_id, limit=limit, skip=skip
        ),
        "rdp_users": lambda: bloodhound_api.computers.get_rdp_users(
            computer_id, limit=limit, skip=skip
        ),
        "sessions": lambda: bloodhound_api.computers.get_sessions(
            computer_id, limit=limit, skip=skip
        ),
        "sql_admins": lambda: bloodhound_api.computers.get_sql_admins(
            computer_id, limit=limit, skip=skip
        ),
    }
    return _handle_tool_call(info_type, handlers, computer_id=computer_id)


# Organizational Unit info composite tool
@mcp.tool()
def ou_info(
    ou_id: str,
    info_type: str = "info",
    limit: int = 100,
    skip: int = 0,
) -> str:
    """Query OU data from BloodHound.
    info_type options:
        info - general OU Properties and attributes
        computers - computers in this OU
        groups - groups in this OU
        gpos - GPOs linked to this OU
        users - users in this OU
    args:
    ou_id: BloodHound object ID of the OU (required)
    info_type: what to retrieve (default: info)
    limit: Max Results (default 100, useful in large environments)
    skip: Pagination offset (default 0)
    """
    handlers = {
        "info": lambda: bloodhound_api.ous.get_info(ou_id),
        "computers": lambda: bloodhound_api.ous.get_computers(
            ou_id, limit=limit, skip=skip
        ),
        "groups": lambda: bloodhound_api.ous.get_groups(ou_id, limit=limit, skip=skip),
        "gpos": lambda: bloodhound_api.ous.get_gpos(ou_id, limit=limit, skip=skip),
        "users": lambda: bloodhound_api.ous.get_users(ou_id, limit=limit, skip=skip),
    }
    return _handle_tool_call(info_type, handlers, ou_id=ou_id)


# Group Policy Object info composite tool
@mcp.tool()
def gpo_info(
    gpo_id: str,
    info_type: str = "info",
    limit: int = 100,
    skip: int = 0,
) -> str:
    """Query GPO data from BloodHound.
    info_type options:
        info - general GPO properties and attributes
        computers - computers this GPO is applied to
        controllers - principals that can modify this GPO
        ous - OUs this GPO is linked to
        tier_zeros - tier-zero principals associated with this GPO
        users - users this GPO is applied to
    args:
        gpo_id: BloodHound object ID of the GPO (required)
        info_type: what to retrieve (default: info)
        limit: Max Results (default 100, useful in large environments)
        skip: Pagination offset (default 0)
    """
    handlers = {
        "info": lambda: bloodhound_api.gpos.get_info(gpo_id),
        "computers": lambda: bloodhound_api.gpos.get_computers(
            gpo_id, limit=limit, skip=skip
        ),
        "controllers": lambda: bloodhound_api.gpos.get_controllers(
            gpo_id, limit=limit, skip=skip
        ),
        "ous": lambda: bloodhound_api.gpos.get_ous(gpo_id, limit=limit, skip=skip),
        "tier_zeros": lambda: bloodhound_api.gpos.get_tier_zeros(
            gpo_id, limit=limit, skip=skip
        ),
        "users": lambda: bloodhound_api.gpos.get_users(gpo_id, limit=limit, skip=skip),
    }
    return _handle_tool_call(info_type, handlers, gpo_id=gpo_id)


# Graph analysis composte tool
@mcp.tool()
def graph_analysis(
    info_type: str,
    query: str = None,
    search_type: str = "fuzzy",
    start_node: str = None,
    end_node: str = None,
    source_node: str = None,
    target_node: str = None,
    edge_type: str = None,
    relationship_kinds: str = None,
) -> str:
    """Perform graph analysis operations in BloodHound

    info_type options:
        search - search for nodes by name (needs: query; optional: search_type)
        shortest_path - find shortest attack path between two nodes (needs: start_node, end_node; optional relationship_kinds)
        edge_composition - decompose a complex edge into underlying relationships (needs: source_node, target_node, edge_type)
        relay_targets - find valid NTLM relay targets for a given node (needs: source_node, target_node, edge_type)

    args:
        info_type: what type of graph operation to perform (required)
        query: search text (for search)
        search_type: type of search - fuzzy (default) or exact (for search)
        start_node: Object ID of source node (for shortest_path)
        end_node: Object ID of target node (for shortest_path)
        source_node: Object ID of source node (for edge_composition and relay_targets)
        target_node: Object ID of target node (for edge_composition and relay_targets)
        edge_type: Realtionship type like "MemberOf", "AdminTo", (for edge_composition and relay_targets)
        relationship_kinds: Comma-separated relationship filter (for shortest_path, optional)
    """
    handlers = {
        "search": lambda: bloodhound_api.graph.search(query, search_type),
        "shortest_path": lambda: bloodhound_api.graph.get_shortest_path(
            start_node, end_node, relationship_kinds
        ),
        "edge_composition": lambda: bloodhound_api.graph.get_edge_composition(
            source_node, target_node, edge_type
        ),
        "relay_targets": lambda: bloodhound_api.graph.get_relay_targets(
            source_node, target_node, edge_type
        ),
    }
    return _handle_tool_call(
        info_type,
        handlers,
        query=query,
        search_type=search_type,
        start_node=start_node,
        end_node=end_node,
        source_node=source_node,
        target_node=target_node,
        edge_type=edge_type,
        relationship_kinds=relationship_kinds,
    )


# Active Directory Certificate Services composite tool
@mcp.tool()
def adcs_info(
    object_id: str,
    info_type: str,
    limit: int = 100,
    skip: int = 0,
) -> str:
    """QUery AD Certificate Services data from BloodHound
    object_id is the template_id or the ca_id depending on the info_type
    info_type options:
        cert_template_info - certificate template properties (object_id = template ID)
        cert_template_controllers - who can modify this template - key for ESC1/ESC2 (object_id = template ID)
        root_ca_info - root ca properties (object_id = CA ID)
        root_ca_controllers - who controls the root ca - key for ESC4/ESC5 (object_id = CA ID)
        enterprise_ca_info - enterprise CA properties (object_id = CA ID)
        enterprise_ca_controllers - who controls the enterprise CA - key for ESC3/ESC6 (object_id = CA ID)
        aia_ca_controllers - who controls the AIA CA (object_id = CA ID)

    args:
        object_id: Template ID or CA ID depending on info_type (required)
        info_type: what to retrieve (required)
        limit: Max Results (default 100, useful in large environments)
        skip: Pagination offset (default 0)
    """
    handlers = {
        "cert_template_info": lambda: bloodhound_api.adcs.get_cert_template_info(
            object_id
        ),
        "cert_template_controllers": lambda: (
            bloodhound_api.adcs.get_cert_template_controllers(
                object_id, limit=limit, skip=skip
            )
        ),
        "root_ca_info": lambda: bloodhound_api.adcs.get_root_ca_info(object_id),
        "root_ca_controllers": lambda: bloodhound_api.adcs.get_root_ca_controllers(
            object_id, limit=limit, skip=skip
        ),
        "enterprise_ca_info": lambda: bloodhound_api.adcs.get_enterprise_ca_info(
            object_id
        ),
        "enterprise_ca_controllers": lambda: (
            bloodhound_api.adcs.get_enterprise_ca_controllers(
                object_id, limit=limit, skip=skip
            )
        ),
        "aia_ca_controllers": lambda: bloodhound_api.adcs.get_aia_ca_controllers(
            object_id, limit=limit, skip=skip
        ),
    }
    return _handle_tool_call(info_type, handlers, object_id=object_id)


# Cypher query composite tool
@mcp.tool()
def cypher_query(
    info_type: str,
    query: str = None,
    include_properties: bool = True,
    name: str = None,
    query_id: str = None,
    result_json: str = None,
    description: str = None,
    user_ids: str = None,
    public: bool = False,
    limit: int = 100,
    skip: int = 0,
) -> str:
    """Execute and manage Cypher queries in BloodHound.

    info_type options:
        run - execute a cypher query (needs: query; optional: include_properties)
        interpret - interpret a natural language query into cypher (needs: query, result_json)
        list_saved - list saved queries (optional: name, skip, limit)
        create_saved - save a new query (needs: name, query)
        get_saved - get details of a saved query (needs: query_id)
        update_saved - update an existing saved query (needs: query_id; optional: name, query, description)
        delete_saved - delete a saved query (needs: query_id)
        share_saved - share a saved query with other users (needs: query_id; optional: user_ids, public)
        validate - validate a cypher query for syntax and semantics (needs: query)

    args:
        info_type: Operation to perform
        query: Cypher query string (for run, create_saved, update_saved, validate)
        include_properties: Include node/edge properties in results (for run, default: True)
        name: Query name (for create_saved, update_saved, list_saved filter)
        query_id: Saved query ID (for get_saved, update_saved, delete_saved, share_saved)
        result_json: JSON result string from a previous run (for interpret)
        description: Query description (for update_saved)
        user_ids: Comma-separated user IDs to share with (for share_saved)
        public: Make query public (for share_saved, default: False)
        limit: Max results (default 100)
        skip: Pagination offset (default 0)
    """
    # run and interpret have special handling
    if info_type == "run":
        return _cypher_run(query, include_properties)
    elif info_type == "interpret":
        return _cypher_interpret(query, result_json)
    # standard dispatch for saved query CRUD
    handlers = {
        "list_saved": lambda: bloodhound_api.cypher.list_saved_queries(
            skip, limit, name
        ),
        "create_saved": lambda: bloodhound_api.cypher.create_saved_query(name, query),
        "get_saved": lambda: bloodhound_api.cypher.get_saved_query(query_id),
        "update_saved": lambda: bloodhound_api.cypher.update_saved_query(
            query_id, name, query, description
        ),
        "delete_saved": lambda: bloodhound_api.cypher.delete_saved_query(query_id),
        "share_saved": lambda: bloodhound_api.cypher.share_saved_query(
            query_id,
            [int(uid.strip()) for uid in user_ids.split(",")] if user_ids else [],
            public,
        ),
        "validate": lambda: bloodhound_api.cypher.validate_query(query),
    }
    return _handle_tool_call(info_type, handlers)


def _cypher_run(query: str, include_properties: bool = True) -> str:
    """Execute a Cypher query with proper HTTP Status interpretation"""
    try:
        result = bloodhound_api.cypher.run_query(query, include_properties)
        compatibility = _cypher_query_compatibility(query)
        # handle metadat enriched resposne formmat
        if isinstance(result, dict) and "metadata" in result:
            has_results = result["metadata"].get(
                "has_results", result["metadata"].get("has_result", True)
            )
            result_data = result.get("data", result)
        else:
            result_data = result
            has_results = bool(result_data.get("nodes") or result_data.get("edges"))
        return json.dumps(
            {
                "info_type": "run",
                "success": True,
                "has_results": has_results,
                "query_compatibility": compatibility,
                "data": result_data,
                "node_count": len(result_data.get("nodes", [])),
                "edge_count": len(result_data.get("edges", [])),
            }
        )
    except BloodhoundAPIError as e:
        return json.dumps(_cypher_api_error_response(e))


def _api_error_status(error: BloodhoundAPIError) -> int | None:
    """Return the best available HTTP status for a BloodHound API error."""
    status = getattr(error, "status_code", None)
    if status is not None:
        return status
    response = getattr(error, "response", None)
    return getattr(response, "status_code", None)


def _api_error_body(error: BloodhoundAPIError) -> tuple[str, str | None]:
    """Extract useful response text and request ID from a BloodHound API error."""
    response = getattr(error, "response", None)
    request_id = None
    if response is None:
        return str(error), request_id

    try:
        payload = response.json()
    except Exception:
        payload = None

    if isinstance(payload, dict):
        request_id = (
            payload.get("request_id")
            or payload.get("requestId")
            or payload.get("requestid")
        )
        for key in ("error", "message", "detail", "details"):
            value = payload.get(key)
            if value:
                return str(value), request_id
        try:
            return json.dumps(payload), request_id
        except TypeError:
            return str(payload), request_id

    body_text = getattr(response, "text", None)
    if body_text:
        return str(body_text), request_id

    return str(error), request_id


def _cypher_error_hint(error_type: str, error_text: str) -> str:
    normalized = error_text.lower()
    if "multiple result columns with the same name" in normalized:
        return (
            "Check Cypher syntax; duplicate RETURN column names are not supported. "
            "Remove duplicates or alias repeated expressions."
        )

    hints = {
        "syntax_error": (
            "Check Cypher syntax, labels, relationship types, property names, and "
            "RETURN aliases."
        ),
        "query_error": (
            "BloodHound/Neo4j rejected the query. Check generated Cypher semantics "
            "and simplify or alias returned expressions."
        ),
        "auth_error": "Authentication failed - check credentials and token validity.",
        "permission_error": "You do not have permission to run this query.",
        "not_found": "The requested Cypher endpoint or query target was not found.",
        "rate_limit": "Rate limit exceeded - wait and retry with a smaller request.",
        "server_error": (
            "BloodHound returned a server error. Retry later or reduce query scope "
            "if the query may be expensive."
        ),
        "api_error": "BloodHound returned an API error without a recognized status.",
    }
    return hints.get(error_type, hints["api_error"])


def _classify_cypher_api_error(status: int | None, error_text: str) -> str:
    normalized = error_text.lower()
    has_syntax_marker = any(
        marker in normalized
        for marker in (
            "syntaxerror",
            "syntax error",
            "statement.syntax",
            "multiple result columns",
        )
    )
    has_query_marker = any(
        marker in normalized
        for marker in ("neo4jerror", "neo.clienterror", "cypher", "query")
    )

    if status == 400:
        return "syntax_error"
    if status == 401:
        return "auth_error"
    if status == 403:
        return "permission_error"
    if status == 404:
        return "not_found"
    if status == 429:
        return "rate_limit"
    if status is not None and status >= 500:
        if has_syntax_marker:
            return "syntax_error"
        if has_query_marker:
            return "query_error"
        return "server_error"
    return "api_error"


def _cypher_api_error_response(error: BloodhoundAPIError) -> dict:
    status = _api_error_status(error)
    error_text, request_id = _api_error_body(error)
    error_type = _classify_cypher_api_error(status, error_text)
    response = {
        "success": False,
        "error_type": error_type,
        "http_status": status,
        "error": error_text,
        "hint": _cypher_error_hint(error_type, error_text),
    }
    if request_id:
        response["request_id"] = request_id
    return response


def _cypher_query_compatibility(query: str) -> dict:
    """Describe whether a Cypher query is safe to run in the BloodHound GUI."""
    aggregation_functions = sorted(
        {match.group(1).upper() for match in AGGREGATION_PATTERN.finditer(query or "")}
    )
    if not aggregation_functions:
        return {
            "api_safe": True,
            "gui_safe": True,
            "uses_aggregation": False,
        }
    return {
        "api_safe": True,
        "gui_safe": False,
        "uses_aggregation": True,
        "aggregation_functions": aggregation_functions,
        "warning": (
            "Aggregation queries are supported through cypher_query but BloodHound's "
            "GUI may not render them correctly."
        ),
        "gui_safe_guidance": (
            "For GUI use, return individual nodes, edges, or paths instead of "
            "COUNT/COLLECT/SUM/AVG/MIN/MAX aggregates."
        ),
    }


# Note: this function may be redundant — needs A/B testing to confirm it adds value vs just extra steps
def _cypher_interpret(query: str, result_json: str) -> str:
    """interpret cypher results for offensive security context"""
    try:
        result = (
            json.loads(result_json) if isinstance(result_json, str) else result_json
        )
        if not result.get("success", False):
            return json.dumps(
                {
                    "info_type": "interpret",
                    "interpretation": "Query failed - see error details in the result",
                    "error": result.get("error", "Unknown"),
                }
            )
        nodes = result.get("data", {}).get("nodes", [])
        edges = result.get("data", {}).get("edges", [])
        return json.dumps(
            {
                "info_type": "interpret",
                "nodes_found": len(nodes),
                "edges_found": len(edges),
                "has_results": len(nodes) > 0 or len(edges) > 0,
            }
        )
    except Exception as e:
        return json.dumps(
            {
                "info_type": "interpret",
                "interpretation": "Failed to interpret query results",
                "error": str(e),
            }
        )


# data quality composite tool
@mcp.tool()
def data_quality(
    info_type: str = "completeness",
    domain_id: str = None,
    tenant_id: str = None,
    platform_id: str = None,
    start: str = None,
    end: str = None,
    sort_by: str = None,
    skip: int = 0,
    limit: int = 100,
) -> str:
    """Query data quality and collection statistics from BloodHound
    info_type options:
        completeness - overall database completeness stats (no params needed)
        ad_domain - collection quality over time for an AD domain (needs: domain_id)
        azure_tenant - collection quality over time for an azure tenant (needs: tenant_id)
        platform - aggregate quality stats for a platform (needs: platform_id - "ad" or "azure")

    args:
    info_type: what to retrieve (default: completeness)
    domain_id: AD domain ID
    platform_id: "ad" or "azure"
    start: Start datetime in RFC-3339 format
    end: end datetime in RFC-3339 format
    sort_by: Sort field - "created_at" or "updated_at" (optional)
    skip: Pagination offset (default 0)
    limit: max results (default 100)
    """
    handlers = {
        "completeness": lambda: bloodhound_api.data_quality.get_completeness_stats(),
        "ad_domain": lambda: (
            bloodhound_api.data_quality.get_ad_domain_data_quality_stats(
                domain_id, start, end, sort_by, skip, limit
            )
        ),
        "azure_tenant": lambda: (
            bloodhound_api.data_quality.get_azure_tenant_data_quality_stats(
                tenant_id, start, end, sort_by, skip, limit
            )
        ),
        "platform": lambda: bloodhound_api.data_quality.get_platform_data_quality_stats(
            platform_id, start, end, sort_by, skip, limit
        ),
    }
    return _handle_tool_call(info_type, handlers)


# Custom OpenGraph nodes composite tool
@mcp.tool()
def custom_nodes(
    info_type: str = "list",
    kind_name: str = None,
    custom_types_json: Any = None,
    config_json: Any = None,
    icon_config_json: Any = None,
    extension_json: Any = None,
    extension_file_path: str = None,
    extension_id: int = None,
    schemas: Any = None,
    is_traversable: Any = None,
) -> str:
    """Manage OpenGraph custom node display configs and v9 extension schemas.
    info_type options:
        list - list all custom node configs
        get - get details for a specific node kind (needs: kind_name)
        create - create new node kind with display metadata (needs: custom_types_json)
        update - update a node kind's display config (needs: kind_name, config_json)
        delete - delete a node kind (needs: kind_name)
        validate_icon - validate icon config before creating/updating (needs: icon_config_json)
        extension_list - list OpenGraph extensions (BloodHound v9+)
        extension_upsert - create/update extension schema (needs: extension_json or extension_file_path)
        extension_delete - delete extension schema by ID (needs: extension_id)
        extension_edges - list extension edge kinds (optional: schemas, is_traversable)

    args:
        info_type: what to retrieve (default: list)
        kind_name: Custom node kind name (for get,update, delete)
        custom_types_json: JSON string or object for creating a new node kind (for create)
        config_json: JSON string or object for updating a node kind's display config (for update)
        icon_config_json: JSON string or object for validating icon config (for validate_icon)
        extension_json: JSON string or object for BloodHound v9 OpenGraph extension upsert
        extension_file_path: local JSON file path for BloodHound v9 OpenGraph extension upsert
        extension_id: OpenGraph extension ID for delete
        schemas: schema name or list of schema names for extension edge filtering
        is_traversable: bool or BloodHound filter string (for example: eq:true)
    """

    def _parse_json_payload(value: Any, argument_name: str):
        if value is None:
            raise ValueError(f"{argument_name} is required")
        if isinstance(value, (dict, list)):
            return value
        if not isinstance(value, str):
            raise ValueError(f"{argument_name} must be a JSON string or object")

        parsed = value
        for _ in range(3):
            if not isinstance(parsed, str):
                return parsed
            parsed = parsed.strip()
            if not parsed:
                raise ValueError(f"{argument_name} cannot be empty")
            parsed = json.loads(parsed)
        return parsed

    def _custom_type_configs(payload: Any):
        if not isinstance(payload, dict):
            raise ValueError("custom_types_json must be a JSON object")
        if "custom_types" in payload and isinstance(payload["custom_types"], dict):
            return payload["custom_types"]
        return payload

    def _validation_error_message(validation: dict) -> str:
        if "error" in validation:
            return validation["error"]
        if validation.get("errors"):
            return "; ".join(validation["errors"])
        return "unknown validation error"

    def _feature_unavailable(endpoint: str) -> dict:
        return {
            "status": "feature_unavailable",
            "endpoint": endpoint,
            "message": (
                "BloodHound returned 404 for this OpenGraph extension endpoint. "
                "The instance may be older than v9.0.0 or the "
                "opengraph_extension_management feature flag may be disabled."
            ),
            "fallback_hint": (
                "Generic OpenGraph ingest can still work through file_upload, "
                "and legacy display metadata can still use custom_nodes "
                "info_type=create/update against /api/v2/custom-nodes."
            ),
        }

    def _extension_call(endpoint: str, operation):
        try:
            return operation()
        except BloodhoundAPIError as e:
            if e.status_code == 404:
                return _feature_unavailable(endpoint)
            raise

    def _extension_payload():
        if extension_file_path:
            path = Path(extension_file_path)
            if not path.exists():
                raise FileNotFoundError(f"Extension file not found: {path}")
            if not path.is_file():
                raise ValueError(f"Extension path is not a file: {path}")
            if path.suffix.lower() != ".json":
                raise ValueError(f"Extension file must be JSON: {path}")
            payload = json.loads(path.read_text(encoding="utf-8"))
            return payload, {
                "type": "file",
                "path": str(path),
                "file_name": path.name,
                "file_size_bytes": path.stat().st_size,
            }

        payload = _parse_json_payload(extension_json, "extension_json")
        if not isinstance(payload, dict):
            raise ValueError("extension_json must be a JSON object")
        return payload, {"type": "argument"}

    def _schemas_filter():
        if schemas is None:
            return None
        if isinstance(schemas, list):
            return [str(schema) for schema in schemas]
        if isinstance(schemas, str):
            value = schemas.strip()
            if not value:
                return None
            if value.startswith("["):
                parsed = _parse_json_payload(value, "schemas")
                if not isinstance(parsed, list):
                    raise ValueError("schemas JSON must be a list")
                return [str(schema) for schema in parsed]
            return [value]
        return [str(schemas)]

    def _is_traversable_filter():
        if is_traversable is None:
            return None
        if isinstance(is_traversable, bool):
            return f"eq:{str(is_traversable).lower()}"
        value = str(is_traversable).strip()
        return value or None

    def _create():
        payload = _parse_json_payload(custom_types_json, "custom_types_json")
        types = _custom_type_configs(payload)
        for name, config in types.items():
            if "icon" in config:
                validation = bloodhound_api.custom_nodes.validate_icon_config(
                    config["icon"]
                )
                if not validation["valid"]:
                    return {
                        "error": (
                            f"Invalid icon config for {name}: "
                            f"{_validation_error_message(validation)}"
                        )
                    }
        return bloodhound_api.custom_nodes.create_custom_nodes(payload)

    def _update():
        config = _parse_json_payload(config_json, "config_json")
        if "icon" in config:
            validation = bloodhound_api.custom_nodes.validate_icon_config(
                config["icon"]
            )
            if not validation["valid"]:
                return {
                    "error": (
                        "Invalid icon config: "
                        f"{_validation_error_message(validation)}"
                    )
                }
        return bloodhound_api.custom_nodes.update_custom_node(kind_name, config)

    def _validate_icon():
        icon = _parse_json_payload(icon_config_json, "icon_config_json")
        return bloodhound_api.custom_nodes.validate_icon_config(icon)

    def _extension_list():
        return _extension_call(
            "/api/v2/extensions",
            lambda: bloodhound_api.opengraph_extensions.list_extensions(),
        )

    def _extension_upsert():
        payload, source = _extension_payload()
        result = _extension_call(
            "/api/v2/extensions",
            lambda: bloodhound_api.opengraph_extensions.upsert_extension(payload),
        )
        if isinstance(result, dict) and result.get("status") == "feature_unavailable":
            return result
        return {"source": source, "result": result}

    def _extension_delete():
        if extension_id is None:
            raise ValueError("extension_id is required")
        normalized_extension_id = int(extension_id)
        result = _extension_call(
            f"/api/v2/extensions/{normalized_extension_id}",
            lambda: bloodhound_api.opengraph_extensions.delete_extension(
                normalized_extension_id
            )
            or {"status": "deleted", "extension_id": normalized_extension_id},
        )
        return result

    def _extension_edges():
        return _extension_call(
            "/api/v2/extensions-edges",
            lambda: bloodhound_api.opengraph_extensions.list_edge_kinds(
                schemas=_schemas_filter(),
                is_traversable=_is_traversable_filter(),
            ),
        )

    handlers = {
        "list": lambda: bloodhound_api.custom_nodes.get_all_custom_nodes(),
        "get": lambda: bloodhound_api.custom_nodes.get_custom_node(kind_name),
        "create": _create,
        "update": _update,
        "delete": lambda: bloodhound_api.custom_nodes.delete_custom_node(kind_name),
        "validate_icon": _validate_icon,
        "extension_list": _extension_list,
        "extension_upsert": _extension_upsert,
        "extension_delete": _extension_delete,
        "extension_edges": _extension_edges,
    }
    return _handle_tool_call(info_type, handlers)


# Asset Group composite tool
@mcp.tool()
def asset_groups(
    info_type: str = "list",
    asset_group_id: str = None,
    asset_group_tag_id: int = None,
    name: str = None,
    tag: str = None,
    sort_by: str = None,
    system_group: bool = None,
    selectors_json: str = None,
    skip: int = 0,
    limit: int = 100,
) -> str:
    """Manage Asset isolation groups and tages in BloodHound

    info_type options:
        list - list all asset groups (optional filters: name, tag, sort_by, system_group)
        get - get a specific asset group (requires: asset_group_id)
        create - create a new asset group (requires: name, tag)
        update - update an existing asset group (requires: asset_group_id)
        delete - delete an asset group (requires: asset_group_id)
        collections - list historical membership snapshots (requires: asset_group_id)
        member_counts - get member counts by object type (requires: asset_group_id)
        update_selectors - set auto membership selectors (requires: asset_group_id, selectors_json)
        list_tags - list asset group tags (optional: name, tag, sort_by)
        create_tag - create a new asset group tag (requires: name, tag)
        tag_members - list members of a tag (requires: asset_group_tag_id)

    args:
        info_type: operation to perform (default: list)
        asset_group_id: Asset group ID (for get, update, delete, collections, member_counts, update_selectors)
        asset_group_tag_id: Tag ID (for tag_members)
        name: Group/tag name (for create, update, create_tag, or filters)
        tag: Tag value (for create, update, create_tag, or filters)
        sort_by: Sort field (for list, list tags)
        system_group: Filter by system group (for list)
        selectors_json: JSON array of selector specs (for update_selectors)
        skip: Pagination offset (default 0)
        limit: Max results (default 100)
    """
    handlers = {
        "list": lambda: bloodhound_api.asset_groups.list_asset_groups(
            sort_by=sort_by, name=name, tag=tag, system_group=system_group
        ),
        "get": lambda: bloodhound_api.asset_groups.get_asset_group(asset_group_id),
        "create": lambda: bloodhound_api.asset_groups.create_asset_group(name, tag),
        "update": lambda: bloodhound_api.asset_groups.update_asset_group(
            asset_group_id, name
        ),
        "delete": lambda: bloodhound_api.asset_groups.delete_asset_group(
            asset_group_id
        ),
        "collections": lambda: bloodhound_api.asset_groups.list_asset_group_collections(
            asset_group_id, skip=skip, limit=limit
        ),
        "member_counts": lambda: (
            bloodhound_api.asset_groups.list_asset_group_member_counts(asset_group_id)
        ),
        "update_selectors": lambda: (
            bloodhound_api.asset_groups.update_asset_group_selectors(
                asset_group_id, json.loads(selectors_json)
            )
        ),
        "list_tags": lambda: bloodhound_api.asset_groups.list_asset_group_tags(
            sort_by=sort_by, name=name, tag=tag, skip=skip, limit=limit
        ),
        "create_tag": lambda: bloodhound_api.asset_groups.create_asset_group_tag(
            name, tag
        ),
        "tag_members": lambda: bloodhound_api.asset_groups.list_asset_group_tag_members(
            asset_group_tag_id, skip=skip, limit=limit
        ),
    }
    return _handle_tool_call(info_type, handlers)


def _upload_to_job(job_id: int, file_path: str) -> dict:
    """Helper for multi-file upload: validate, detect content type, upload to existing job."""
    path = Path(file_path)
    bloodhound_api.file_upload._validate_file(path)
    content_type = (
        "application/zip" if path.suffix.lower() == ".zip" else "application/json"
    )
    file_data = path.read_bytes()
    bloodhound_api.file_upload.upload_file(job_id, file_data, content_type)
    return {
        "job_id": job_id,
        "file_name": path.name,
        "file_size_bytes": len(file_data),
        "status": "uploaded",
    }


@mcp.tool()
def file_upload(
    info_type: str = "upload",
    file_path: str = None,
    job_id: int = None,
) -> str:
    """Upload SharpHound/AzureHound collection files to BloodHound CE for ingest.
    Accepts .zip (SharpHound ZIP archive) or .json (individual collection file).

    info_type options:
        upload        - full workflow for a single file: start -> upload -> end
                        (requires: file_path)
        start_job     - start a new upload job, returns job_id for multi-file uploads
        upload_to_job - upload a file to an existing job (requires: job_id, file_path)
        end_job       - finalize an upload job and trigger ingest (requires: job_id)

    Args:
        info_type: operation to perform (default: upload)
        file_path: absolute path to collection file (.zip or .json)
        job_id: upload job ID (required for upload_to_job and end_job)
    """
    handlers = {
        "upload": lambda: bloodhound_api.file_upload.upload_collection_file(file_path),
        "start_job": lambda: {"job_id": bloodhound_api.file_upload.start_upload()},
        "upload_to_job": lambda: _upload_to_job(job_id, file_path),
        "end_job": lambda: (
            bloodhound_api.file_upload.end_upload(job_id)
            or {"status": "ingest_started", "job_id": job_id}
        ),
    }
    return _handle_tool_call(info_type, handlers)


# MCP Resources
# These are called by the main prompt
# Cypher References
@mcp.resource("bloodhound://cypher/reference")
def cypher_reference() -> str:
    """Cypher query syntax, schema, property names, patterns, and examples for BloodHound"""
    return """BloodHound Cypher Reference
    ============================
    Syntax Basics
    -------------
    - Nodes: (n:NodeType) or (n:NodeType {property: 'value'})
    - Relationships: -[r:REL_TYPE]-> (directed) or -[r:REL_TYPE*1..]->(variable length)
    - Patterns chain nodes and relationships: (a)-[r]->(b)
    - MATCH finds patterns, WHERE filters, RETURN outputs results
    - shortestPath((a)-[*1..]->(b)) finds the most direct path
    - Use *1..N to limit path length (e.g., *1..5 for max 5 hops)

    GUI vs API Limitation
    ---------------------
    COUNT and other aggregation functions (COLLECT, SUM, AVG) work correctly
    when executed via the cypher_query tool (API). However, the BloodHound GUI
    does NOT render aggregation results properly. When suggesting queries for
    the user to run manually in the GUI, return individual results instead:
    GUI-safe:  MATCH (u:User) WHERE u.hasspn=true RETURN u
    API-only:  MATCH (u:User) WHERE u.hasspn=true RETURN count(u)

    Query Size Limits
    -----------------
    A 500 error from the BloodHound API often means the query returned too much data.
    1. Add LIMIT to constrain result size: RETURN p LIMIT 100
    2. Use SKIP for pagination: RETURN p SKIP 100 LIMIT 100
    3. Chain paginated calls to build the full result set
    4. Add WHERE filters to narrow scope before pagination

    Example — paginated path query:
    Page 1: MATCH p=(n)-[:MemberOf*1..]->(g:Group) RETURN p LIMIT 100
    Page 2: MATCH p=(n)-[:MemberOf*1..]->(g:Group) RETURN p SKIP 100 LIMIT 100

    Node Types
    ----------
    Active Directory:
    User, Computer, Group, Domain, OU, GPO, Container,
    CertTemplate, RootCA, EnterpriseCA, AIACA, NTAuthStore

    Azure / Entra ID:
    AZUser, AZGroup, AZApp, AZServicePrincipal, AZTenant,
    AZDevice, AZRole, AZSubscription, AZResourceGroup,
    AZManagementGroup, AZKeyVault

    Custom (OpenGraph):
    User-defined types (e.g., SQLServer, WebApp, NetworkDevice)

    BH CE Property Reference — Exact Names and Types
    -------------------------------------------------
    IMPORTANT: All BloodHound property names are lowercase. Using wrong case causes queries to
    silently return no results. Key properties by node type:

    User / Computer (shared):
    - enabled (boolean) — account is active
    - admincount (boolean) — AdminSDHolder-protected; correlates with privilege but is not definitive
    - objectid (string) — SID, e.g. "S-1-5-21-..."
    - name (string) — UPPERCASE with domain suffix: "JSMITH@CORP.LOCAL"
    - distinguishedname (string)
    - description (string) — often contains passwords left by admins
    - whencreated (integer) — epoch timestamp
    - lastlogon / lastlogontimestamp (integer) — epoch timestamps
    - system_tags (string) — contains 'owned', 'tier zero', etc.

    User-specific:
    - hasspn (boolean) — has Service Principal Names (Kerberoastable if enabled=true)
    - dontreqpreauth (boolean) — AS-REP Roastable if true
    - serviceprincipalnames (list of strings) — SPNs; use COALESCE(u.serviceprincipalnames, [])
    - pwdlastset (integer) — epoch timestamp
    - gmsa (boolean) — is a Group Managed Service Account
    - msa (boolean) — is a Managed Service Account

    Computer-specific:
    - unconstraineddelegation (boolean) — has unconstrained Kerberos delegation
    - operatingsystem (string) — e.g. "Windows Server 2019 Standard"
    - serviceprincipalnames (list of strings) — use COALESCE(c.serviceprincipalnames, [])
    - haslaps (boolean) — LAPS is configured on this computer

    Domain-specific:
    - objectid (string) — domain SID (S-1-5-21-...) used for trust/DCSync queries

    Name Format Convention
    ----------------------
    BloodHound stores ALL names in UPPERCASE with the domain suffix appended:
    - Groups:     "DOMAIN ADMINS@CORP.LOCAL"  (not "Domain Admins")
    - Users:      "JSMITH@CORP.LOCAL"
    - Computers:  "WS01.CORP.LOCAL"
    - Domains:    "CORP.LOCAL"

    When filtering by name, use exact uppercase strings or TOUPPER():
    WRONG:  WHERE g.name = "Domain Admins"
    CORRECT: WHERE g.name = "DOMAIN ADMINS@CORP.LOCAL"
    CORRECT: WHERE TOUPPER(g.name) STARTS WITH "DOMAIN ADMINS"

    COALESCE Patterns for List Properties
    --------------------------------------
    List properties (serviceprincipalnames, etc.) may be null. Always use COALESCE:
    - Filter by SPN prefix:
      WHERE ANY(spn IN COALESCE(n.serviceprincipalnames, []) WHERE spn STARTS WITH 'CIFS/')
    - Collect with null safety:
      RETURN COALESCE(u.serviceprincipalnames, []) AS spns
    - Boolean null safety:
      WHERE COALESCE(u.gmsa, false) = false
      WHERE COALESCE(c.unconstraineddelegation, false) = true

    DCSync Edge Clarification
    -------------------------
    IMPORTANT: DCSync rights target Domain nodes, NOT Group nodes.
    The pre-computed DCSync edge AND the raw GetChanges/GetChangesAll edges all point to Domain.

    WRONG:  MATCH (n)-[:DCSync]->(g:Group)   -- returns nothing
    CORRECT: MATCH (n)-[:DCSync]->(d:Domain)

    To find all principals with DCSync (both pre-computed edge and raw privileges):
    MATCH (n)-[:DCSync|GetChanges|GetChangesAll]->(d:Domain)
    RETURN n.name, labels(n) AS node_type, d.name AS domain

    Note: A principal needs BOTH GetChanges AND GetChangesAll to perform DCSync.
    The pre-computed DCSync edge represents this combined condition.

    GPO Abuse Path Structure
    ------------------------
    GPO abuse requires traversing the full chain — never skip intermediate nodes:
    principal -[write edge]-> GPO -[GPLink]-> OU/Container -[Contains*1..]-> targets

    Write edges on GPOs: GenericAll, GenericWrite, WriteOwner, WriteDacl, Owns
    The GPLink edge direction: GPO -> OU (FROM GPO TO the linked container)

    Full GPO abuse path query:
    MATCH p=(n)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl|Owns]->(g:GPO)-[:GPLink]->
            (ou:OU)-[:Contains*1..]->(target)
    WHERE g.domain = 'DOMAIN.LOCAL'
    RETURN n.name, g.name AS gpo, collect(DISTINCT target.name) AS affected_targets
    LIMIT 100

    AD Relationship Types
    ---------------------
    - MemberOf: Group membership
    - AdminTo: Local admin rights
    - HasSession: Active logon session
    - GenericAll: Full control
    - GenericWrite: Write access to attributes
    - WriteOwner / WriteDacl: ACL modification
    - ForceChangePassword: Password reset
    - AddMember: Add to group
    - AddSelf: Add self to group
    - DCSync: Pre-computed DCSync right (targets Domain node)
    - GetChanges / GetChangesAll: Raw replication privileges (both required for DCSync)
    - Owns: Object owner
    - AllExtendedRights: All extended permissions
    - CanRDP / CanPSRemote / ExecuteDCOM: Remote access methods
    - AllowedToDelegate: Kerberos constrained delegation
    - AllowedToAct: Resource-based constrained delegation (RBCD)
    - ReadLAPSPassword / ReadGMSAPassword / SyncLAPSPassword: Credential access
    - DumpSMSAPassword: Standalone MSA password dump
    - SQLAdmin: SQL Server admin
    - HasSIDHistory: SID History abuse
    - AddKeyCredentialLink: Shadow Credentials attack
    - WriteSPN: SPN manipulation (targeted Kerberoasting)
    - WriteAccountRestrictions: Write userAccountControl / msDS-AllowedToActOnBehalfOfOtherIdentity
    - GPLink: GPO linked to OU/Container (direction: GPO -> container)
    - Contains: OU/container membership
    - TrustedBy: Domain trust
    - CoerceToTGT: Kerberos coercion to TGT
    - AddAllowedToAct: Write RBCD
    - WriteGPLink: Write GPLink attribute
    - ADCSESC1/ESC3/ESC4/ESC6a/ESC6b/ESC9a/ESC9b/ESC10a/ESC10b/ESC13: ADCS abuse edges
    - GoldenCert: Golden certificate attack
    - CoerceAndRelayNTLMToSMB/ADCS/LDAP/LDAPS: NTLM relay paths

    Azure Relationship Types
    ------------------------
    - AZGlobalAdmin: Global Administrator role
    - AZPrivilegedRoleAdmin: Privileged Role Administrator
    - AZApplicationAdministrator / AZCloudApplicationAdministrator
    - AZResetPassword: Can reset passwords
    - AZOwns: Owns the object
    - AZExecuteCommand: Can execute commands
    - AZAddMembers: Can add group members
    - AZGrantAccess: Can grant access

    Common Patterns
    ---------------
    Find members of a group:
    MATCH (n)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.COM"})
    RETURN n

    Shortest attack path:
    MATCH p=shortestPath((s)-[*1..]->(t))
    WHERE s.objectid = 'source-id' AND t.objectid = 'target-id'
    RETURN p

    All paths within N hops:
    MATCH p=(s)-[*1..5]->(t:Group {name:"DOMAIN ADMINS@DOMAIN.COM"})
    RETURN p

    Permission count per object:
    MATCH (obj)-[r]->(target)
    WITH obj, count(r) as perm_count
    RETURN obj.name, perm_count
    ORDER BY perm_count DESC

    Cross-reference user privilege before labeling:
    MATCH (u:User {objectid: $user_id})
    OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)
    OPTIONAL MATCH (u)-[:AdminTo]->(c:Computer)
    RETURN u.name, u.enabled, u.admincount,
           collect(DISTINCT g.name) AS groups,
           collect(DISTINCT c.name) AS admin_on

    Example Queries
    ---------------
    Find all Domain Admins:
    MATCH p=(n)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@DOMAIN.COM"})
    RETURN p

    Find Kerberoastable users:
    MATCH (u:User)
    WHERE u.hasspn=true AND u.enabled=true
    AND NOT u.objectid ENDS WITH '-502'
    AND NOT COALESCE(u.gmsa, false) = true
    AND NOT COALESCE(u.msa, false) = true
    RETURN u

    Find paths from owned principals to high-value targets:
    MATCH p=shortestPath((s:Base)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|SyncedToEntraUser|CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS|CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS|Contains|DCFor|TrustedBy*1..]->(t:Base))
    WHERE COALESCE(s.system_tags, '') CONTAINS 'owned' AND s<>t
    RETURN p

    Find Azure Global Admins:
    MATCH p=(:AZBase)-[:AZGlobalAdmin*1..]->(:AZTenant)
    RETURN p

    Find Azure users with admin roles:
    MATCH p=(u:AZUser)-[r:AZGlobalAdmin|AZPrivilegedRoleAdmin]->(t:AZTenant)
    RETURN u.displayname, u.objectid, type(r) as role_type

    Find Azure users with most permissions:
    MATCH (u:AZUser)
    OPTIONAL MATCH (u)-[r]->(t)
    WITH u, count(r) as num_permissions
    RETURN u.displayname, num_permissions
    ORDER BY num_permissions DESC LIMIT 10
    """


# Active Directory Resource
@mcp.resource("bloodhound://guides/ad")
def ad_guide() -> str:
    """Active Directory analysis quick reference for BloodHound."""
    return """AD Analysis Quick Reference
    ==========================

    Node Types
    ----------
    User       — AD user accounts
    Computer   — Domain-joined machines
    Group      — Security and distribution groups
    Domain     — AD domain objects
    OU         — Organizational Units
    GPO        — Group Policy Objects
    Container  — AD containers

    Key Relationships
    -----------------
    Privilege:    AdminTo, GenericAll, GenericWrite, WriteOwner, WriteDacl, Owns
    Membership:   MemberOf, Contains, GPLink
    Credential:   HasSession, DCSync, ReadLAPSPassword, ReadGMSAPassword
    Remote:       CanRDP, CanPSRemote, ExecuteDCOM, SQLAdmin
    Delegation:   AllowedToDelegate, AllowedToAct, CoerceToTGT
    Modification: ForceChangePassword, AddMember, WriteSPN, AddKeyCredentialLink

    Tool Workflow
    -------------
    1. domain_info(info_type="list") — get domain IDs
    2. domain_info(info_type="search", query="...") — find specific objects
    3. Drill into objects:
    - user_info(user_id, info_type="controllables|sessions|admin_rights")
    - group_info(group_id, info_type="members|memberships")
    - computer_info(computer_id, info_type="admin_users|sessions|controllers")
    4. graph_analysis(info_type="shortest_path", start_node=..., end_node=...)
    5. cypher_query(info_type="run", query="...") for complex analysis

    Quick Attack Checks
    -------------------
    - DCSync rights: domain_info(info_type="dc_syncers")
    - Cross-domain admins: domain_info(info_type="foreign_admins")
    - Kerberoastable: cypher_query with hasspn=true
    - Delegation abuse: user_info/computer_info with info_type="constrained_delegation"
    """


# Azure Resource
@mcp.resource("bloodhound://guides/azure")
def azure_guide() -> str:
    """Azure / Entra ID analysis quick reference for BloodHound."""
    return """Azure / Entra ID Quick Reference
    ================================

    IMPORTANT: For Azure environments, always prefer Cypher queries via
    cypher_query(info_type="run") over REST API tools. Cypher provides
    more comprehensive and flexible Azure analysis.

    Node Types
    ----------
    AZUser              — Entra ID user
    AZGroup             — Entra ID group
    AZApp               — Azure application registration
    AZServicePrincipal  — Service principal (app identity)
    AZTenant            — Entra ID tenant
    AZDevice            — Azure AD joined/registered device
    AZRole              — Entra ID role
    AZSubscription      — Azure subscription
    AZResourceGroup     — Azure resource group
    AZManagementGroup   — Management group
    AZKeyVault          — Key vault

    Key Relationships
    -----------------
    Admin:      AZGlobalAdmin, AZPrivilegedRoleAdmin, AZApplicationAdministrator
    Control:    AZOwns, AZGrantAccess, AZAddMembers
    Credential: AZResetPassword
    Execution:  AZExecuteCommand

    Always use AZ-prefixed node types in Cypher queries for Azure objects.

    Key Queries
    -----------
    Global Admins:
    MATCH p=(:AZBase)-[:AZGlobalAdmin*1..]->(:AZTenant) RETURN p

    Users with admin roles:
    MATCH p=(u:AZUser)-[r:AZGlobalAdmin|AZPrivilegedRoleAdmin]->(t:AZTenant)
    RETURN u.displayname, u.objectid, type(r) as role_type

    Service principals with dangerous permissions:
    MATCH p=(sp:AZServicePrincipal)-[r:AZApplicationAdministrator|AZCloudApplicationAdministrator]->(t:AZTenant)
    RETURN sp.displayname, sp.objectid, type(r) as permission

    Attack paths to Global Admin:
    MATCH p=shortestPath((n:AZUser {name:'target@domain.com'})-[*1..]->(a:AZGlobalAdmin))
    RETURN p

    Users who can reset passwords:
    MATCH p=(u:AZUser)-[r:AZResetPassword]->(target:AZUser)
    RETURN u.displayname, count(target) as can_reset_count
    ORDER BY can_reset_count DESC
    """


# Adcs Resource
@mcp.resource("bloodhound://guides/adcs")
def adcs_guide() -> str:
    """ADCS attack vector quick reference for BloodHound."""
    return """ADCS Attack Quick Reference
    ===========================

    Node Types
    ----------
    CertTemplate  — Certificate template definitions
    RootCA        — Root Certificate Authorities
    EnterpriseCA  — Enterprise CAs (issue certificates)
    AIACA         — Authority Information Access CAs
    NTAuthStore   — NTAuth certificate store

    Tool Workflow
    -------------
    Enumerate templates:  adcs_info(object_id=template_id, info_type="cert_template_info")
    Template ACLs:        adcs_info(object_id=template_id, info_type="cert_template_controllers")
    Enterprise CA config: adcs_info(object_id=ca_id, info_type="enterprise_ca_info")
    Enterprise CA ACLs:   adcs_info(object_id=ca_id, info_type="enterprise_ca_controllers")
    Root CA config:       adcs_info(object_id=ca_id, info_type="root_ca_info")
    Root CA ACLs:         adcs_info(object_id=ca_id, info_type="root_ca_controllers")
    AIA CA ACLs:          adcs_info(object_id=ca_id, info_type="aia_ca_controllers")

    ESC Attack Vectors
    ------------------
    ESC1  — Misconfigured template: enrollee supplies SAN + low-priv enrollment
    ESC2  — Any Purpose EKU or no EKU restriction
    ESC3  — Enrollment agent template abuse
    ESC4  — Vulnerable template ACLs (low-priv write access)
    ESC6  — EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
    ESC8  — NTLM relay to CA HTTP enrollment endpoint
    ESC9  — CT_FLAG_NO_SECURITY_EXTENSION on template
    ESC10 — Weak certificate-to-account mapping
    ESC13 — OID group link (issuance policy grants group membership)

    Quick Cypher: Find All ADCS Edges
    MATCH p=()-[:ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|GoldenCert]->(n)
    RETURN p
    """


# Ad methodology resource
@mcp.resource("bloodhound://guides/ad-methodology")
def ad_methodology() -> str:
    """Full Active Directory attack methodology and analysis workflow."""
    return """AD Attack Methodology
    =====================

    Phase 1: Domain Reconnaissance
    -------------------------------
    1. List domains: domain_info(info_type="list")
    2. For each domain:
    - domain_info(info_type="dc_syncers") — non-standard DCSync = immediate win
    - domain_info(info_type="controllers") — who has control edges?
    - domain_info(info_type="foreign_admins") — cross-domain admin paths
    - domain_info(info_type="inbound_trusts") / domain_info(info_type="outbound_trusts")

    Phase 2: High-Value Target Identification
    ------------------------------------------
    3. Identify privileged groups:
    domain_info(info_type="search", query="Domain Admins", object_type="Group")
    group_info(group_id, info_type="members")

    4. Enumerate tier-zero:
    MATCH (n) WHERE COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0' RETURN n

    Phase 3: Attack Path Analysis
    -----------------------------
    5. From owned principals:
    MATCH p=shortestPath((s:Base)-[*1..]->(t:Group {name:"DOMAIN ADMINS@DOMAIN.COM"}))
    WHERE COALESCE(s.system_tags, '') CONTAINS 'owned'
    RETURN p

    6. Session hunting:
    user_info(user_id, info_type="sessions") — where are DA creds cached?
    computer_info(computer_id, info_type="sessions") — who's logged into this box?

    Attack Patterns
    ---------------

    Kerberoasting:
    MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true
    AND NOT u.objectid ENDS WITH '-502'
    AND NOT COALESCE(u.gmsa, false) = true
    RETURN u.name, u.serviceprincipalnames

    AS-REP Roasting:
    MATCH (u:User) WHERE u.dontreqpreauth=true AND u.enabled=true
    RETURN u.name

    Unconstrained Delegation:
    MATCH (c:Computer) WHERE c.unconstraineddelegation=true
    AND NOT c.objectid ENDS WITH '$' RETURN c.name

    Constrained Delegation:
    user_info(user_id, info_type="constrained_delegation")
    computer_info(computer_id, info_type="constrained_delegation")
    MATCH (n) WHERE n.allowedtodelegate IS NOT NULL RETURN n.name, n.allowedtodelegate

    Resource-Based Constrained Delegation (RBCD):
    MATCH p=(s)-[:AllowedToAct]->(t:Computer) RETURN p

    LAPS Password Readers:
    MATCH p=(n)-[:ReadLAPSPassword]->(c:Computer) RETURN p
    computer_info(computer_id, info_type="controllers") — check for ReadLAPSPassword

    gMSA Password Readers:
    MATCH p=(n)-[:ReadGMSAPassword]->(t) RETURN p

    Shadow Credentials:
    MATCH p=(n)-[:AddKeyCredentialLink]->(t) RETURN p

    Targeted Kerberoasting (WriteSPN):
    MATCH p=(n)-[:WriteSPN]->(u:User) RETURN p

    DCSync:
    MATCH p=(n)-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain)
    RETURN p

    SID History:
    MATCH p=(n)-[:HasSIDHistory]->(t) RETURN p

    Cross-Domain Trust Exploitation:
    MATCH p=(d1:Domain)-[:TrustedBy]->(d2:Domain) RETURN p
    domain_info(info_type="inbound_trusts") / domain_info(info_type="outbound_trusts")

    NTLM Relay Paths:
    MATCH p=()-[:CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS|CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS]->()
    RETURN p

    GPO Abuse:
    MATCH p=(n)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl]->(g:GPO)-[:GPLink]->(ou:OU)-[:Contains*1..]->(target)
    RETURN p
    """


# Azure Methodology resource
@mcp.resource("bloodhound://guides/azure-methodology")
def azure_methodology() -> str:
    """Full Azure / Entra ID attack methodology and analysis workflow."""
    return """Azure / Entra ID Attack Methodology
    ====================================

    Always prefer Cypher over REST tools for Azure analysis.

    Phase 1: Tenant Reconnaissance
    -------------------------------
    1. Find all tenants:
    MATCH (t:AZTenant) RETURN t.name, t.objectid

    2. Enumerate Global Admins:
    MATCH p=(:AZBase)-[:AZGlobalAdmin*1..]->(:AZTenant) RETURN p

    3. Enumerate privileged roles:
    MATCH p=(n)-[r:AZGlobalAdmin|AZPrivilegedRoleAdmin|AZApplicationAdministrator|AZCloudApplicationAdministrator]->(t:AZTenant)
    RETURN n.displayname, type(r) as role

    Phase 2: Service Principal Analysis
    ------------------------------------
    4. Find high-privilege service principals:
    MATCH p=(sp:AZServicePrincipal)-[r]->(t:AZTenant)
    RETURN sp.displayname, type(r) as permission

    5. App registrations with dangerous permissions:
    MATCH (app:AZApp)-[:AZRunsAs]->(sp:AZServicePrincipal)-[r]->(target)
    RETURN app.displayname, sp.displayname, type(r) as permission, target.name

    Phase 3: Attack Path Discovery
    -------------------------------
    6. Paths from user to Global Admin:
    MATCH p=shortestPath((u:AZUser)-[*1..]->(ga:AZTenant))
    WHERE u.name = 'target@domain.com'
    RETURN p

    7. Password reset chains:
    MATCH p=(u:AZUser)-[:AZResetPassword*1..]->(target:AZUser)
    RETURN u.displayname, length(p) as chain_length, target.displayname

    8. Users who can reset the most passwords:
    MATCH (u:AZUser)-[:AZResetPassword]->(target:AZUser)
    RETURN u.displayname, count(target) as can_reset
    ORDER BY can_reset DESC LIMIT 20

    Attack Patterns
    ---------------

    Consent Grant Abuse:
    MATCH (app:AZApp)-[:AZHasAppRole|AZGrantedAppRole]->(target)
    RETURN app.displayname, target.name

    Hybrid Environment (On-Prem to Azure):
    MATCH p=(u:User)-[:SyncedToEntraUser]->(au:AZUser)-[*1..]->(t:AZTenant)
    RETURN p
    (Compromising an on-prem user synced to Entra can pivot to Azure)

    Azure to On-Prem:
    MATCH p=(au:AZUser)-[*1..]->(c:Computer)
    RETURN p

    Key Vault Access:
    MATCH p=(n)-[r]->(kv:AZKeyVault)
    RETURN n.displayname, type(r) as access_type, kv.name

    Device Join Abuse:
    MATCH (d:AZDevice) WHERE d.trusttype = 'AzureAd'
    OPTIONAL MATCH (d)<-[:AZOwns]-(owner)
    RETURN d.displayname, owner.displayname

    Management Group to Subscription Paths:
    MATCH p=(mg:AZManagementGroup)-[:AZContains*1..]->(s:AZSubscription)
    RETURN p
    """


# ADCS Attack Methodology resource
@mcp.resource("bloodhound://guides/adcs-methodology")
def adcs_methodology() -> str:
    """Full ADCS attack methodology with detailed ESC analysis."""
    return """ADCS Attack Methodology
    =======================

    Analysis Workflow
    -----------------
    1. Enumerate all certificate templates:
    MATCH (ct:CertTemplate) RETURN ct.name, ct.objectid

    2. Enumerate all CAs:
    MATCH (ca:EnterpriseCA) RETURN ca.name, ca.objectid
    MATCH (ca:RootCA) RETURN ca.name, ca.objectid

    3. Check for ADCS edges (quick scan):
    MATCH p=()-[:ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|GoldenCert]->(n)
    RETURN p

    4. For each finding, drill into template/CA details with adcs_info tool.

    Detailed ESC Analysis
    ---------------------

    ESC1 — Misconfigured Certificate Templates
    Condition: Template allows enrollment by low-priv users AND enrollee can
    specify a Subject Alternative Name (SAN).
    Check: adcs_info(info_type="cert_template_info") — look for:
        - enrollee_supplies_subject = true
        - Low-priv enrollment rights
        - Client Authentication EKU
    Cypher: MATCH p=()-[:ADCSESC1]->(n) RETURN p
    Impact: Impersonate any user (including DA) by requesting cert with their SAN.

    ESC2 — Any Purpose / No EKU Templates
    Condition: Template has Any Purpose EKU (OID 2.5.29.37.0) or no EKU.
    Check: adcs_info(info_type="cert_template_info") — examine EKU list
    Impact: Certificate can be used for any purpose including client auth.

    ESC3 — Enrollment Agent Templates
    Condition: Template allows enrollment agent certificates + another template
    allows enrollment on behalf of others.
    Check: Two-stage — find enrollment agent templates, then find templates
    that accept enrollment-on-behalf-of.
    Cypher: MATCH p=()-[:ADCSESC3]->(n) RETURN p
    Impact: Enroll as enrollment agent, then request certs for any user.

    ESC4 — Vulnerable Template ACLs
    Condition: Low-priv user has write access to the template object itself.
    Check: adcs_info(info_type="cert_template_controllers") — look for
    non-admin principals with:
        - GenericAll, GenericWrite, WriteOwner, WriteDacl, WritePKIEnrollmentFlag
    Cypher: MATCH p=()-[:ADCSESC4]->(n) RETURN p
    Impact: Modify template to enable ESC1 conditions, then exploit.

    ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2
    Condition: Enterprise CA has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set.
    Check: adcs_info(info_type="enterprise_ca_info") — check CA flags
    Cypher: MATCH p=()-[:ADCSESC6a|ADCSESC6b]->(n) RETURN p
    Impact: ANY certificate request can include arbitrary SANs.
    Variants: ESC6a (direct), ESC6b (via relay)

    ESC8 — NTLM Relay to AD CS HTTP Endpoints
    Condition: CA has HTTP enrollment endpoint (certsrv) and NTLM is accepted.
    Check: adcs_info(info_type="enterprise_ca_info") — check for HTTP endpoints
    Impact: Relay machine account NTLM auth to CA, get cert as that machine.

    ESC9 — No Security Extension
    Condition: Template has CT_FLAG_NO_SECURITY_EXTENSION flag.
    This removes the szOID_NTDS_CA_SECURITY_EXT from issued certs.
    Cypher: MATCH p=()-[:ADCSESC9a|ADCSESC9b]->(n) RETURN p
    Impact: Bypass StrongCertificateBindingEnforcement.

    ESC10 — Weak Certificate Mappings
    Condition: Registry allows weak certificate-to-account mapping.
    CertificateMappingMethods includes UPN mapping (0x4) without strong binding.
    Cypher: MATCH p=()-[:ADCSESC10a|ADCSESC10b]->(n) RETURN p
    Impact: Map cert to arbitrary user via UPN matching.

    ESC13 — OID Group Link
    Condition: Issuance policy OID is linked to a group via msDS-OIDToGroupLink.
    Enrolling in a template with that policy grants group membership.
    Cypher: MATCH p=()-[:ADCSESC13]->(n) RETURN p
    Impact: Gain membership in the linked group by enrolling for a certificate.

    Golden Certificate:
    Condition: Attacker has CA private key.
    Cypher: MATCH p=()-[:GoldenCert]->(n) RETURN p
    Impact: Forge any certificate. Requires root/enterprise CA key compromise.

    Template Analysis Checklist
    ---------------------------
    For each certificate template, check:
    1. Who can enroll? (enrollment rights)
    2. Can enrollee specify SAN? (enrollee_supplies_subject)
    3. What EKUs are set? (Client Auth, Any Purpose, etc.)
    4. Who has write access to the template? (cert_template_controllers)
    5. Is manager approval required? (issuance requirements)
    6. Are there enrollment agents? (authorized signatures)
    """


# OpenGraph Guide Resource
@mcp.resource("bloodhound://opengraph/guide")
def opengraph_guide() -> str:
    """BloodHound OpenGraph schema design and custom node guide."""
    return """OpenGraph Custom Nodes Guide
    ============================

    Custom node types are user-defined and vary by environment. When working
    with OpenGraph data, ask the user for their specific schema definition
    and example Cypher queries. Use their schema to construct environment-
    specific analysis. The examples in bloodhound://opengraph/examples show
    the general pattern.

    Key Concepts
    ------------
    1. Custom Node Types: User-defined categories (e.g., SQLServer, WebApp)
    2. OpenGraph Schema: JSON structure for ingesting nodes and edges
    3. Visual Config: Icons and colors for node display in BloodHound UI
    4. Relationships: Directed edges connecting custom nodes to AD/Azure objects
    5. Extension Schemas: BloodHound v9 structured schemas for node kinds,
       relationship kinds, environments, icons, properties, and findings

    Schema Structure
    ----------------
    {
    "graph": {
        "nodes": [
        {
            "id": "unique-identifier",
            "kinds": ["CustomNodeType", "Base"],
            "properties": {
            "name": "Display Name",
            "custom_property": "value"
            }
        }
        ],
        "edges": [
        {
            "kind": "CustomRelationship",
            "start": {"value": "source-node-id"},
            "end": {"value": "target-node-id"},
            "properties": {}
        }
        ]
    }
    }

    Property Rules
    --------------
    - Properties must be primitive types (strings, numbers, booleans)
    - Arrays must be homogeneous (all elements same type)
    - No nested objects
    - First 'kind' in the kinds array determines visual representation

    Icon Configuration
    ------------------
    - Font Awesome free, solid icons only
    - Name without 'fa-' prefix (e.g., "database" not "fa-database")
    - Colors in #RGB or #RRGGBB format
    - Example:
    {"icon": {"type": "font-awesome", "name": "database", "color": "#CC2936"}}
    - Validate before creating: custom_nodes(info_type="validate_icon", icon_config_json=...)

    Best Practices
    --------------
    - Every node must have a globally unique ID (GUID, SID, thumbprint, FQDN)
    - Every edge must be directed (one-way) — think "map of one-way streets"
    - Edge direction should follow "access or attack" flow
    - Create paths connecting non-adjacent nodes for attack path discovery
    - If not modeling multi-node paths, consider a relational database instead
    - Connect custom nodes to existing AD/Azure objects where applicable

    Tool Workflow
    -------------
    Legacy custom-node display configuration:
    - custom_nodes(info_type="list") — list all custom node type configs
    - custom_nodes(info_type="get", kind_name="...") — get specific type config
    - custom_nodes(info_type="create", custom_types_json="...") — create types
    - custom_nodes(info_type="update", kind_name="...", config_json="...") — update
    - custom_nodes(info_type="delete", kind_name="...") — delete type config

    BloodHound v9 OpenGraph extension management:
    - custom_nodes(info_type="extension_list") — list extension schemas
    - custom_nodes(info_type="extension_upsert", extension_json={...}) — upsert inline schema
    - custom_nodes(info_type="extension_upsert", extension_file_path="...") — upsert schema file
    - custom_nodes(info_type="extension_delete", extension_id=123) — delete extension schema
    - custom_nodes(info_type="extension_edges", schemas=["..."], is_traversable=True) — list extension edge kinds

    If extension endpoints return feature_unavailable, the BloodHound instance
    is likely older than v9.0.0 or opengraph_extension_management is disabled.
    Generic OpenGraph ingest may still work through file_upload, but structured
    extension schema management is unavailable until the server supports it.
    """


# OpenGraph Examples Resource
@mcp.resource("bloodhound://opengraph/examples")
def opengraph_examples() -> str:
    """Practical examples of custom node implementations for OpenGraph."""
    return """OpenGraph Implementation Examples
    =================================

    These examples demonstrate the pattern for creating custom nodes. For your
    specific environment, provide your OpenGraph schema definition and example
    Cypher queries, and the model will adapt analysis accordingly.

    Example 1: SQL Server Environment
    ----------------------------------
    Custom Node Types:
    MSSQL_Server  — SQL Server instance
    MSSQL_Database — Individual database

    Icon Configuration:
    {
    "MSSQL_Server": {
        "icon": {"type": "font-awesome", "name": "server", "color": "#CC2936"}
    },
    "MSSQL_Database": {
        "icon": {"type": "font-awesome", "name": "database", "color": "#4472C4"}
    }
    }

    Relationships:
    User -[SQLAdmin]-> MSSQL_Server
    MSSQL_Server -[Contains]-> MSSQL_Database
    MSSQL_Server -[RunsAs]-> User (service account)

    OpenGraph Data:
    {
    "graph": {
        "nodes": [
        {
            "id": "sql01.corp.local",
            "kinds": ["MSSQL_Server", "Base"],
            "properties": {
            "name": "SQL01",
            "version": "SQL Server 2019",
            "instance": "MSSQLSERVER"
            }
        }
        ],
        "edges": [
        {
            "kind": "SQLAdmin",
            "start": {"value": "user-object-id"},
            "end": {"value": "sql01.corp.local"}
        }
        ]
    }
    }

    Attack Path: User -> SQLAdmin -> MSSQL_Server -> RunsAs -> ServiceAccount -> Domain

    Example 2: Web Application Stack
    ---------------------------------
    Custom Node Types:
    WebApp    — Web application
    WebServer — Web server (IIS, Apache, Nginx)
    AppPool   — IIS application pool

    Icon Configuration:
    {
    "WebApp": {
        "icon": {"type": "font-awesome", "name": "globe", "color": "#00B04F"}
    },
    "WebServer": {
        "icon": {"type": "font-awesome", "name": "server", "color": "#FF6600"}
    }
    }

    Relationships:
    WebApp -[RunsOn]-> WebServer
    WebServer -[RunsAs]-> User (service account)
    User -[WebAdmin]-> WebApp
    AppPool -[IdentityOf]-> User (app pool identity)

    Attack Path: User -> WebAdmin -> WebApp -> RunsOn -> WebServer -> RunsAs -> ServiceAccount -> Domain

    Example Cypher Queries:
    Find all SQL Servers with admin paths:
        MATCH p=(u:User)-[:SQLAdmin]->(s:MSSQL_Server) RETURN p

    Find web app service accounts:
        MATCH p=(w:WebServer)-[:RunsAs]->(u:User) RETURN p

    Attack paths through custom nodes to DA:
        MATCH p=shortestPath((s:Base)-[*1..]->(t:Group {name:"DOMAIN ADMINS@DOMAIN.COM"}))
        WHERE s.name = 'SQL01'
        RETURN p
    """


@mcp.resource("bloodhound://cypher/offensive-queries")
def offensive_query_library() -> str:
    """Battle-tested Cypher query templates for common offensive scenarios. Load this before writing custom Cypher for attack path analysis."""
    return """BloodHound Offensive Query Library
    ====================================
    Use these templates as starting points. Replace placeholders (DOMAIN.LOCAL, $domain_id, etc.)
    with actual values. Always verify results by cross-referencing group memberships and privilege context.

    == DCSync ==

    Standard DCSync — pre-computed edge (most reliable):
    MATCH (n)-[:DCSync]->(d:Domain)
    WHERE d.name = 'DOMAIN.LOCAL'
    RETURN n.name, labels(n) AS node_type, n.objectid
    LIMIT 100

    Non-standard DCSync — raw GetChanges + GetChangesAll (catches misconfigurations):
    MATCH (n)-[:GetChanges]->(d:Domain {name: 'DOMAIN.LOCAL'})
    MATCH (n)-[:GetChangesAll]->(d)
    RETURN n.name, labels(n) AS node_type, n.objectid
    LIMIT 100

    All DCSync principals combined (standard + non-standard):
    MATCH (n)-[:DCSync|GetChanges|GetChangesAll]->(d:Domain {name: 'DOMAIN.LOCAL'})
    WITH n, d, collect(DISTINCT type(r)) AS edges
    MATCH (n)-[r2:DCSync|GetChanges|GetChangesAll]->(d)
    RETURN DISTINCT n.name, labels(n) AS node_type, n.admincount,
           COALESCE(n.system_tags, '') AS tags
    LIMIT 100

    DCSync principals with group context (verify privilege level):
    MATCH (n)-[:DCSync]->(d:Domain {name: 'DOMAIN.LOCAL'})
    OPTIONAL MATCH (n)-[:MemberOf*1..]->(g:Group)
    RETURN n.name, n.admincount, n.enabled,
           collect(DISTINCT g.name) AS group_memberships
    LIMIT 100

    == GPO Abuse ==

    Principals with write access to GPOs (GenericAll/GenericWrite/WriteOwner/WriteDacl/Owns):
    MATCH (n)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl|Owns]->(g:GPO)
    WHERE g.domain = 'DOMAIN.LOCAL'
    OPTIONAL MATCH (g)-[:GPLink]->(ou:OU)-[:Contains*1..]->(target)
    RETURN n.name, labels(n) AS attacker_type, g.name AS gpo_name,
           collect(DISTINCT target.name) AS affected_targets
    LIMIT 100

    Full GPO abuse path (attacker -> GPO -> OU -> targets):
    MATCH p=(n)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl|Owns]->(g:GPO)
            -[:GPLink]->(ou:OU)-[:Contains*1..]->(target)
    WHERE g.domain = 'DOMAIN.LOCAL'
    RETURN n.name, g.name AS gpo_name, ou.name AS linked_ou,
           labels(target) AS target_type, target.name AS target
    LIMIT 100

    Principals with WriteGPLink (can link GPOs to OUs):
    MATCH (n)-[:WriteGPLink]->(ou:OU)
    WHERE ou.domain = 'DOMAIN.LOCAL'
    RETURN n.name, labels(n) AS attacker_type, ou.name AS target_ou
    LIMIT 100

    == Kerberoasting ==

    Kerberoastable users (enabled, has SPN, not krbtgt or MSA/gMSA):
    MATCH (u:User)
    WHERE u.hasspn = true AND u.enabled = true
    AND NOT u.objectid ENDS WITH '-502'
    AND NOT COALESCE(u.gmsa, false) = true
    AND NOT COALESCE(u.msa, false) = true
    AND u.domain = 'DOMAIN.LOCAL'
    RETURN u.name, u.objectid, u.admincount, u.serviceprincipalnames
    LIMIT 100

    Kerberoastable users with privilege context (group memberships + admin rights):
    MATCH (u:User)
    WHERE u.hasspn = true AND u.enabled = true
    AND NOT u.objectid ENDS WITH '-502'
    AND NOT COALESCE(u.gmsa, false) = true
    AND NOT COALESCE(u.msa, false) = true
    AND u.domain = 'DOMAIN.LOCAL'
    OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)
    OPTIONAL MATCH (u)-[:AdminTo]->(c:Computer)
    RETURN u.name, u.admincount, u.serviceprincipalnames,
           collect(DISTINCT g.name) AS groups,
           collect(DISTINCT c.name) AS admin_on
    LIMIT 100

    Targeted Kerberoasting — who can set SPNs on other users (WriteSPN):
    MATCH (n)-[:WriteSPN]->(t:User)
    WHERE t.domain = 'DOMAIN.LOCAL'
    RETURN n.name, labels(n) AS attacker_type, t.name AS target,
           t.hasspn AS already_has_spn, t.enabled, t.admincount
    LIMIT 100

    == AS-REP Roasting ==

    Users with pre-auth disabled (AS-REP Roastable):
    MATCH (u:User)
    WHERE u.dontreqpreauth = true AND u.enabled = true
    AND u.domain = 'DOMAIN.LOCAL'
    RETURN u.name, u.objectid, u.admincount
    LIMIT 100

    == Delegation Abuse ==

    Unconstrained delegation computers (excluding DCs — objectid ends with -516 or -521):
    MATCH (c:Computer)
    WHERE COALESCE(c.unconstraineddelegation, false) = true
    AND c.domain = 'DOMAIN.LOCAL'
    AND NOT c.objectid ENDS WITH '-516'
    AND NOT c.objectid ENDS WITH '-521'
    RETURN c.name, c.objectid, c.operatingsystem
    LIMIT 100

    Constrained delegation — who can delegate to what services:
    MATCH (n)-[:AllowedToDelegate]->(c:Computer)
    WHERE c.domain = 'DOMAIN.LOCAL'
    RETURN n.name, labels(n) AS principal_type, c.name AS delegate_to,
           n.allowedtodelegate AS allowed_spns
    LIMIT 100

    RBCD — who can act on behalf of whom (AllowedToAct):
    MATCH (s)-[:AllowedToAct]->(t:Computer)
    WHERE t.domain = 'DOMAIN.LOCAL'
    RETURN s.name AS delegator, labels(s) AS delegator_type,
           t.name AS target_computer
    LIMIT 100

    AddAllowedToAct — who can write RBCD on computers:
    MATCH (n)-[:AddAllowedToAct]->(c:Computer)
    WHERE c.domain = 'DOMAIN.LOCAL'
    RETURN n.name, labels(n) AS attacker_type, c.name AS target_computer
    LIMIT 100

    == Shadow Credentials ==

    AddKeyCredentialLink — who can add shadow credentials to what targets:
    MATCH (n)-[:AddKeyCredentialLink]->(t)
    WHERE t.domain = 'DOMAIN.LOCAL'
    RETURN n.name AS attacker, labels(n) AS attacker_type,
           t.name AS target, labels(t) AS target_type
    LIMIT 100

    == Privileged Group Membership (Cross-Reference Before Labeling) ==

    Check if a specific user is a member of any privileged groups:
    MATCH (u:User {objectid: $user_objectid})-[:MemberOf*1..]->(g:Group)
    RETURN g.name AS group, g.admincount AS group_is_privileged
    ORDER BY g.admincount DESC

    Find users who can add members to privileged groups WITH group membership context:
    MATCH (n)-[:AddMember|AddSelf]->(g:Group)
    WHERE g.domain = 'DOMAIN.LOCAL' AND g.admincount = true
    OPTIONAL MATCH (n)-[:MemberOf*1..]->(mg:Group)
    RETURN n.name, labels(n) AS principal_type, n.admincount AS already_privileged,
           g.name AS target_group,
           collect(DISTINCT mg.name) AS principal_groups
    LIMIT 100

    == LAPS and gMSA ==

    ReadLAPSPassword — who can read LAPS passwords:
    MATCH (n)-[:ReadLAPSPassword]->(c:Computer)
    WHERE c.domain = 'DOMAIN.LOCAL'
    RETURN n.name, labels(n) AS principal_type, c.name AS computer
    LIMIT 100

    ReadGMSAPassword — who can read gMSA passwords:
    MATCH (n)-[:ReadGMSAPassword]->(u:User)
    WHERE u.domain = 'DOMAIN.LOCAL'
    RETURN n.name, labels(n) AS principal_type, u.name AS gmsa_account
    LIMIT 100

    Computers with LAPS configured:
    MATCH (c:Computer)
    WHERE COALESCE(c.haslaps, false) = true AND c.domain = 'DOMAIN.LOCAL'
    RETURN c.name, c.operatingsystem
    LIMIT 100

    == Infrastructure Enumeration ==

    File servers — computers with CIFS or NFS SPNs:
    MATCH (c:Computer)
    WHERE ANY(spn IN COALESCE(c.serviceprincipalnames, [])
              WHERE spn STARTS WITH 'CIFS/' OR spn STARTS WITH 'nfs/')
    AND c.domain = 'DOMAIN.LOCAL'
    RETURN c.name, c.operatingsystem,
           [spn IN c.serviceprincipalnames WHERE spn STARTS WITH 'CIFS/' OR spn STARTS WITH 'nfs/'] AS file_spns
    LIMIT 100

    SQL servers — computers with MSSQLSvc SPNs or SQLAdmin relationships:
    MATCH (c:Computer)
    WHERE ANY(spn IN COALESCE(c.serviceprincipalnames, []) WHERE spn STARTS WITH 'MSSQLSvc/')
    AND c.domain = 'DOMAIN.LOCAL'
    RETURN c.name, c.operatingsystem,
           [spn IN c.serviceprincipalnames WHERE spn STARTS WITH 'MSSQLSvc/'] AS sql_spns
    LIMIT 100

    SQL admins (via SQLAdmin edge):
    MATCH (n)-[:SQLAdmin]->(c:Computer)
    WHERE c.domain = 'DOMAIN.LOCAL'
    RETURN c.name AS sql_server, c.operatingsystem,
           collect(DISTINCT n.name) AS sql_admins
    LIMIT 100

    Web/IIS servers — computers with HTTP/HTTPS SPNs:
    MATCH (c:Computer)
    WHERE ANY(spn IN COALESCE(c.serviceprincipalnames, [])
              WHERE spn STARTS WITH 'HTTP/' OR spn STARTS WITH 'HTTPS/')
    AND c.domain = 'DOMAIN.LOCAL'
    RETURN c.name, c.operatingsystem,
           [spn IN c.serviceprincipalnames WHERE spn STARTS WITH 'HTTP/' OR spn STARTS WITH 'HTTPS/'] AS web_spns
    LIMIT 100

    Computers with passwords in description:
    MATCH (c:Computer)
    WHERE c.domain = 'DOMAIN.LOCAL'
    AND c.description IS NOT NULL
    AND (toLower(c.description) CONTAINS 'password' OR toLower(c.description) CONTAINS 'pass' OR toLower(c.description) CONTAINS 'pwd')
    RETURN c.name, c.description, c.operatingsystem
    LIMIT 100

    Users with passwords in description:
    MATCH (u:User)
    WHERE u.domain = 'DOMAIN.LOCAL'
    AND u.description IS NOT NULL
    AND (toLower(u.description) CONTAINS 'password' OR toLower(u.description) CONTAINS 'pass' OR toLower(u.description) CONTAINS 'pwd')
    RETURN u.name, u.description, u.enabled, u.admincount
    LIMIT 100

    Domain controllers — computers with DC SIDs:
    MATCH (c:Computer)-[:MemberOf*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-516' OR g.objectid ENDS WITH '-521'
    AND c.domain = 'DOMAIN.LOCAL'
    RETURN c.name, c.objectid, c.operatingsystem
    LIMIT 100

    == High-Value Session Harvesting ==

    Admin user sessions on non-DC computers (lateral movement targets):
    MATCH (u:User)-[:HasSession]->(c:Computer)
    WHERE u.admincount = true AND u.enabled = true
    AND u.domain = 'DOMAIN.LOCAL'
    AND NOT c.objectid ENDS WITH '-516'
    AND NOT c.objectid ENDS WITH '-521'
    RETURN u.name, c.name AS computer, c.operatingsystem
    LIMIT 100

    Tier-zero sessions (owned tag or system_tags):
    MATCH (u:User)-[:HasSession]->(c:Computer)
    WHERE COALESCE(u.system_tags, '') CONTAINS 'tier zero'
    AND c.domain = 'DOMAIN.LOCAL'
    RETURN u.name, c.name AS computer
    LIMIT 100

    == NTLM Relay Paths ==

    Computers that can be coerced and relayed to SMB:
    MATCH p=(src:Computer)-[:CoerceAndRelayNTLMToSMB]->(dst:Computer)
    WHERE src.domain = 'DOMAIN.LOCAL'
    RETURN src.name AS coerce_target, dst.name AS relay_to
    LIMIT 100

    Computers that can be coerced and relayed to ADCS:
    MATCH p=(src:Computer)-[:CoerceAndRelayNTLMToADCS]->(ca:EnterpriseCA)
    WHERE src.domain = 'DOMAIN.LOCAL'
    RETURN src.name AS coerce_target, ca.name AS enterprise_ca
    LIMIT 100

    Full NTLM relay paths:
    MATCH (src)-[r:CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS|CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS]->(dst)
    WHERE src.domain = 'DOMAIN.LOCAL'
    RETURN src.name, type(r) AS relay_type, dst.name AS relay_target,
           labels(dst) AS target_type
    LIMIT 100

    == Domain Trusts ==

    All outbound trusts (this domain trusts these):
    MATCH (d:Domain)-[:TrustedBy]->(t:Domain)
    WHERE d.name = 'DOMAIN.LOCAL'
    RETURN d.name AS source_domain, t.name AS trusted_domain

    Cross-domain attack paths via trusts:
    MATCH p=(n)-[*1..5]->(t:Group)
    WHERE t.name STARTS WITH 'DOMAIN ADMINS@'
    AND n.domain <> t.domain
    RETURN p LIMIT 50

    Foreign admins (users from other domains with local admin rights):
    MATCH (u:User)-[:AdminTo]->(c:Computer)
    WHERE u.domain <> c.domain
    RETURN u.name, u.domain AS user_domain, c.name AS computer, c.domain AS computer_domain
    LIMIT 100

    SID History abuse:
    MATCH (n)-[:HasSIDHistory]->(t)
    WHERE n.domain = 'DOMAIN.LOCAL'
    RETURN n.name, labels(n) AS attacker_type, t.name AS sid_history_target,
           labels(t) AS target_type
    LIMIT 100

    == ADCS Attack Paths ==

    All ADCS ESC paths in the domain:
    MATCH p=(n)-[:ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13]->(t)
    WHERE n.domain = 'DOMAIN.LOCAL'
    RETURN n.name, labels(n) AS attacker_type,
           type(relationships(p)[0]) AS esc_type, t.name AS target
    LIMIT 100

    Certificate templates with dangerous configurations (enrollee supplies subject):
    MATCH (t:CertTemplate)
    WHERE t.domain = 'DOMAIN.LOCAL'
    AND COALESCE(t.enrolleesuppliessubject, false) = true
    RETURN t.name, t.displayname, t.ekus, t.requiresmanagerapproval
    LIMIT 100

    Enterprise CAs — overview:
    MATCH (ca:EnterpriseCA)
    WHERE ca.domain = 'DOMAIN.LOCAL'
    RETURN ca.name, ca.objectid, ca.caname
    LIMIT 100

    ESC paths from owned principals:
    MATCH p=(s:Base)-[:ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13]->(t)
    WHERE COALESCE(s.system_tags, '') CONTAINS 'owned'
    RETURN s.name AS owned_principal, type(relationships(p)[0]) AS esc_type,
           t.name AS target
    LIMIT 100

    == Attack Paths from Owned Nodes ==

    Shortest paths from all owned principals to any tier-zero/high-value targets:
    MATCH p=shortestPath((s:Base)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|SyncedToEntraUser|CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS|CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS|Contains|DCFor|TrustedBy*1..]->(t:Base))
    WHERE COALESCE(s.system_tags, '') CONTAINS 'owned'
    AND COALESCE(t.system_tags, '') CONTAINS 'tier zero'
    AND s <> t
    RETURN p LIMIT 25

    Paths from a specific owned user to Domain Admins:
    MATCH p=shortestPath((s:User)-[*1..]->(g:Group))
    WHERE s.objectid = $user_objectid
    AND g.name STARTS WITH 'DOMAIN ADMINS@'
    RETURN p LIMIT 10

    All outbound edges from a specific user (effective permissions):
    MATCH (u:User {objectid: $user_objectid})-[r]->(t)
    WHERE type(r) IN ['GenericAll','GenericWrite','WriteOwner','WriteDacl',
                      'ForceChangePassword','AddMember','Owns','AllExtendedRights',
                      'AddKeyCredentialLink','WriteSPN','AddSelf','AdminTo',
                      'ReadLAPSPassword','ReadGMSAPassword','DCSync','AllowedToAct',
                      'AllowedToDelegate','AddAllowedToAct','WriteAccountRestrictions']
    RETURN t.name AS target, labels(t) AS target_type, type(r) AS permission
    LIMIT 100
    """


if __name__ == "__main__":
    mcp.run()
