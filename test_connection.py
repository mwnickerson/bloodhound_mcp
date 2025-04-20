#!/usr/bin/env python3
"""
Test script to interact with BloodHound API functions
"""

import os
import sys
import json
from lib.bloodhound_api import BloodhoundAPI

def display_menu():
    """Display the menu of available API functions to test"""
    print("\n=== BloodHound API Test Menu ===")
    print("1. Test Connection (get_self_info)")
    print("2. Get Domains")
    print("3. Get Users from Domain")
    print("4. Get Groups from Domain")
    print("5. Get Computers from Domain")
    print("\n=== Graph API Tests ===")
    print("6. Search Graph")
    print("7. Test Shortest Path")
    print("8. Test Edge Composition")
    print("9. Test Relay Targets")
    print("0. Exit")
    return input("\nSelect an option (0-9): ")

def test_connection(api):
    """Test basic connection to the API"""
    print(f"\nTesting connection to {api.domain}")
    
    user_info = api.get_self_info()
    
    if user_info:
        print("✅ Connection successful!")
        print("User Information:")
        print(json.dumps(user_info, indent=2))
        
        if 'data' in user_info:
            data = user_info['data']
            if isinstance(data, dict):
                username = data.get('username', 'Unknown')
                print(f"\nAuthenticated as: {username}")
        return True
    else:
        print("❌ Connection failed. Please check your domain and API tokens.")
        return False

def get_domains(api):
    """Get and display all domains"""
    print("\nRetrieving domains...")
    domains = api.domains.get_all()
    
    if domains:
        print(f"Found {len(domains)} domains:")
        for i, domain in enumerate(domains):
            print(f"{i+1}. {domain.get('name')} (ID: {domain.get('id')})")
        return domains
    else:
        print("No domains found or error occurred.")
        return []

def get_users_from_domain(api, domains):
    """Get users from a selected domain"""
    if not domains:
        print("No domains available. Please retrieve domains first (option 2).")
        return
    
    # Display domains for selection
    print("\nAvailable domains:")
    for i, domain in enumerate(domains):
        print(f"{i+1}. {domain.get('name')}")
    
    # Get domain selection
    try:
        selection = int(input(f"\nSelect a domain (1-{len(domains)}): "))
        if 1 <= selection <= len(domains):
            selected_domain = domains[selection-1]
        else:
            print("Invalid selection.")
            return
    except ValueError:
        print("Please enter a number.")
        return
    
    # Get limit for user retrieval
    try:
        limit = int(input("Enter number of users to retrieve (default 10): ") or "10")
    except ValueError:
        print("Using default limit of 10.")
        limit = 10
    
    # Get users from selected domain
    print(f"\nRetrieving up to {limit} users from domain {selected_domain.get('name')}...")
    users = api.domains.get_users(selected_domain.get('id'), limit=limit)
    
    if users and users.get('data'):
        print(f"Found {users.get('count')} total users (showing up to {limit}):")
        for i, user in enumerate(users.get('data')):
            # Use the objectID as the SID
            sid = user.get('objectid', 'N/A')
            print(f"{i+1}. {user.get('label')} ({user.get('name')}) - SID: {sid}")
        
        # Return the users for potential further testing
        return users.get('data')
    else:
        print("No users found or error occurred.")
        return []

def get_groups_from_domain(api, domains):
    """Get groups from a selected domain"""
    if not domains:
        print("No domains available. Please retrieve domains first (option 2).")
        return
    
    # Display domains for selection
    print("\nAvailable domains:")
    for i, domain in enumerate(domains):
        print(f"{i+1}. {domain.get('name')}")
    
    # Get domain selection
    try:
        selection = int(input(f"\nSelect a domain (1-{len(domains)}): "))
        if 1 <= selection <= len(domains):
            selected_domain = domains[selection-1]
        else:
            print("Invalid selection.")
            return
    except ValueError:
        print("Please enter a number.")
        return
    
    # Get limit for group retrieval
    try:
        limit = int(input("Enter number of groups to retrieve (default 10): ") or "10")
    except ValueError:
        print("Using default limit of 10.")
        limit = 10
    
    # Get groups from selected domain
    print(f"\nRetrieving up to {limit} groups from domain {selected_domain.get('name')}...")
    groups = api.domains.get_groups(selected_domain.get('id'), limit=limit)
    
    if groups and groups.get('data'):
        print(f"Found {groups.get('count')} total groups (showing up to {limit}):")
        for i, group in enumerate(groups.get('data')):
            sid = group.get('objectid', 'N/A')
            print(f"{i+1}. {group.get('label')} ({group.get('name')}) - SID: {sid}")
            
        # Return the groups for potential further testing
        return groups.get('data')
    else:
        print("No groups found or error occurred.")
        return []

def get_computers_from_domain(api, domains):
    """Get computers from a selected domain"""
    if not domains:
        print("No domains available. Please retrieve domains first (option 2).")
        return
    
    # Display domains for selection
    print("\nAvailable domains:")
    for i, domain in enumerate(domains):
        print(f"{i+1}. {domain.get('name')}")
    
    # Get domain selection
    try:
        selection = int(input(f"\nSelect a domain (1-{len(domains)}): "))
        if 1 <= selection <= len(domains):
            selected_domain = domains[selection-1]
        else:
            print("Invalid selection.")
            return
    except ValueError:
        print("Please enter a number.")
        return
    
    # Get limit for computer retrieval
    try:
        limit = int(input("Enter number of computers to retrieve (default 10): ") or "10")
    except ValueError:
        print("Using default limit of 10.")
        limit = 10
    
    # Get computers from selected domain
    print(f"\nRetrieving up to {limit} computers from domain {selected_domain.get('name')}...")
    computers = api.domains.get_computers(selected_domain.get('id'), limit=limit)
    
    if computers and computers.get('data'):
        print(f"Found {computers.get('count')} total computers (showing up to {limit}):")
        for i, computer in enumerate(computers.get('data')):
            sid = computer.get('objectid', 'N/A')
            print(f"{i+1}. {computer.get('label')} ({computer.get('name')}) - SID: {sid}")
            
        # Return the computers for potential further testing
        return computers.get('data')
    else:
        print("No computers found or error occurred.")
        return []

# New Graph API test functions
def test_search_graph(api):
    """Test searching the Bloodhound graph"""
    print("\n=== Testing Graph Search ===")
    
    # Get search query from user
    query = input("Enter a search term (e.g., 'admin', 'domain'): ")
    search_type = input("Search type ('fuzzy' or 'exact') [default: fuzzy]: ") or "fuzzy"
    
    if search_type not in ["fuzzy", "exact"]:
        print(f"Warning: Invalid search type '{search_type}'. Using 'fuzzy' instead.")
        search_type = "fuzzy"
    
    print(f"\nSearching graph for '{query}' using {search_type} search...")
    
    try:
        results = api.graph.search(query, search_type)
        
        if results and 'data' in results:
            print("✅ Search successful!")
            
            # Pretty print the results structure
            print("\nResults structure:")
            print(json.dumps(results, indent=2, default=str)[:1000])  # Limit output size
            
            # Display the count of results if available
            if isinstance(results['data'], list):
                print(f"\nFound {len(results['data'])} results.")
                
                # Display the first few results
                max_display = min(5, len(results['data']))
                print(f"\nFirst {max_display} results:")
                
                for i, result in enumerate(results['data'][:max_display]):
                    print(f"{i+1}. {result.get('name', 'Unknown')} - Type: {result.get('type', 'Unknown')}")
            
            return results
        else:
            print("❌ Search returned no results or an unexpected format.")
            print(f"Response: {results}")
            return None
            
    except Exception as e:
        print(f"❌ Error searching graph: {e}")
        print(f"Exception type: {type(e).__name__}")
        return None

def test_shortest_path(api, domains=None, users=None, groups=None):
    """Test finding the shortest path between two nodes"""
    print("\n=== Testing Shortest Path ===")
    
    # If we don't have domains, try to get them
    if not domains:
        domains = get_domains(api)
        if not domains:
            print("Failed to retrieve domains. Cannot test shortest path.")
            return
    
    # For this test, we need to get two nodes to find a path between
    print("\nWe need to select two nodes (start and end) to find a path between.")
    
    # Function to get a node selection
    def select_node(node_type):
        if node_type == 'user':
            # If we have users already, use them, otherwise fetch them
            nonlocal users
            if not users:
                users = get_users_from_domain(api, domains)
                if not users:
                    print(f"Failed to retrieve users. Cannot test shortest path.")
                    return None
            
            # Display users for selection
            print("\nSelect a user as the node:")
            for i, user in enumerate(users):
                print(f"{i+1}. {user.get('name')} (ID: {user.get('objectid', 'N/A')})")
            
        elif node_type == 'group':
            # If we have groups already, use them, otherwise fetch them
            nonlocal groups
            if not groups:
                groups = get_groups_from_domain(api, domains)
                if not groups:
                    print(f"Failed to retrieve groups. Cannot test shortest path.")
                    return None
            
            # Display groups for selection
            print("\nSelect a group as the node:")
            for i, group in enumerate(groups):
                print(f"{i+1}. {group.get('name')} (ID: {group.get('objectid', 'N/A')})")
        
        # Get node selection
        try:
            if node_type == 'user' and users:
                selection = int(input(f"\nSelect a {node_type} (1-{len(users)}): "))
                if 1 <= selection <= len(users):
                    return users[selection-1]
            elif node_type == 'group' and groups:
                selection = int(input(f"\nSelect a {node_type} (1-{len(groups)}): "))
                if 1 <= selection <= len(groups):
                    return groups[selection-1]
            
            print("Invalid selection.")
            return None
        except ValueError:
            print("Please enter a number.")
            return None
    
    # Get start node type
    start_node_type = input("\nSelect start node type ('user' or 'group'): ").lower()
    if start_node_type not in ['user', 'group']:
        print(f"Invalid node type '{start_node_type}'. Please use 'user' or 'group'.")
        return
    
    # Get end node type
    end_node_type = input("\nSelect end node type ('user' or 'group'): ").lower()
    if end_node_type not in ['user', 'group']:
        print(f"Invalid node type '{end_node_type}'. Please use 'user' or 'group'.")
        return
    
    # Select the actual nodes
    start_node = select_node(start_node_type)
    if not start_node:
        return
    
    end_node = select_node(end_node_type)
    if not end_node:
        return
    
    # Get relationship filter if desired
    relationship_kinds = input("\nEnter relationship types to filter by (comma-separated, or leave empty for all): ")
    
    print(f"\nFinding shortest path from {start_node.get('name')} to {end_node.get('name')}...")
    
    try:
        # Get the object IDs
        start_id = start_node.get('objectid')
        end_id = end_node.get('objectid')
        
        # Call the API
        path_result = api.graph.get_shortest_path(start_id, end_id, relationship_kinds if relationship_kinds else None)
        
        if path_result and 'data' in path_result:
            print("✅ Shortest path query successful!")
            
            # Pretty print the first part of the result structure
            print("\nResult structure (truncated):")
            result_str = json.dumps(path_result, indent=2, default=str)
            print(result_str[:1000] + ("..." if len(result_str) > 1000 else ""))
            
            # Extract and display the path if possible
            if 'nodes' in path_result['data'] and 'edges' in path_result['data']:
                nodes = path_result['data']['nodes']
                edges = path_result['data']['edges']
                
                print(f"\nPath contains {len(nodes)} nodes and {len(edges)} edges.")
                
                # Display node details if not too many
                if len(nodes) <= 10:
                    print("\nNodes in path:")
                    for i, node in enumerate(nodes):
                        print(f"{i+1}. {node.get('label', 'Unknown')} - Type: {node.get('type', 'Unknown')}")
                
                # Display edge details if not too many
                if len(edges) <= 10:
                    print("\nEdges in path:")
                    for i, edge in enumerate(edges):
                        print(f"{i+1}. {edge.get('label', 'Unknown')} from {edge.get('source', 'Unknown')} to {edge.get('target', 'Unknown')}")
            
            return path_result
        else:
            print("❌ Shortest path query returned no results or an unexpected format.")
            print(f"Response: {path_result}")
            return None
            
    except Exception as e:
        print(f"❌ Error finding shortest path: {e}")
        print(f"Exception type: {type(e).__name__}")
        return None

def test_edge_composition(api, domains=None, users=None, groups=None):
    """Test analyzing the composition of an edge between two nodes"""
    print("\n=== Testing Edge Composition ===")
    
    # This test is a bit more complex and depends on the actual data model
    # So we'll make it simpler for testing purposes
    
    print("\nThis test requires you to know the internal node IDs (integers) and the edge type.")
    print("These are typically visible in the Bloodhound UI when examining relationships.")
    
    try:
        source_id = int(input("\nEnter source node ID (integer): "))
        target_id = int(input("Enter target node ID (integer): "))
        edge_type = input("Enter edge type (e.g., 'MemberOf', 'AdminTo'): ")
        
        print(f"\nAnalyzing composition of '{edge_type}' edge from node {source_id} to node {target_id}...")
        
        try:
            result = api.graph.get_edge_composition(source_id, target_id, edge_type)
            
            if result and 'data' in result:
                print("✅ Edge composition query successful!")
                
                # Pretty print the first part of the result structure
                print("\nResult structure (truncated):")
                result_str = json.dumps(result, indent=2, default=str)
                print(result_str[:1000] + ("..." if len(result_str) > 1000 else ""))
                
                return result
            else:
                print("❌ Edge composition query returned no results or an unexpected format.")
                print(f"Response: {result}")
                return None
                
        except Exception as e:
            print(f"❌ Error analyzing edge composition: {e}")
            print(f"Exception type: {type(e).__name__}")
            return None
            
    except ValueError:
        print("Node IDs must be integers.")
        return None

def test_relay_targets(api, domains=None, users=None, groups=None):
    """Test finding relay targets for an edge"""
    print("\n=== Testing Relay Targets ===")
    
    # Similar to edge composition, this requires specific node IDs and edge type
    
    print("\nThis test requires you to know the internal node IDs (integers) and the edge type.")
    print("These are typically visible in the Bloodhound UI when examining relationships.")
    
    try:
        source_id = int(input("\nEnter source node ID (integer): "))
        target_id = int(input("Enter target node ID (integer): "))
        edge_type = input("Enter edge type (e.g., 'MemberOf', 'AdminTo'): ")
        
        print(f"\nFinding relay targets for '{edge_type}' edge from node {source_id} to node {target_id}...")
        
        try:
            result = api.graph.get_relay_targets(source_id, target_id, edge_type)
            
            if result and 'data' in result:
                print("✅ Relay targets query successful!")
                
                # Pretty print the first part of the result structure
                print("\nResult structure (truncated):")
                result_str = json.dumps(result, indent=2, default=str)
                print(result_str[:1000] + ("..." if len(result_str) > 1000 else ""))
                
                return result
            else:
                print("❌ Relay targets query returned no results or an unexpected format.")
                print(f"Response: {result}")
                return None
                
        except Exception as e:
            print(f"❌ Error finding relay targets: {e}")
            print(f"Exception type: {type(e).__name__}")
            return None
            
    except ValueError:
        print("Node IDs must be integers.")
        return None

def main():
    try:
        # Initialize the API client
        api = BloodhoundAPI()
        
        # Store data for reuse
        domains = []
        users = []
        groups = []
        computers = []
        
        # Main menu loop
        while True:
            choice = display_menu()
            
            if choice == '0':
                print("Exiting...")
                break
            elif choice == '1':
                test_connection(api)
            elif choice == '2':
                domains = get_domains(api)
            elif choice == '3':
                users = get_users_from_domain(api, domains)
            elif choice == '4':
                groups = get_groups_from_domain(api, domains)            
            elif choice == '5':
                computers = get_computers_from_domain(api, domains)
            elif choice == '6':
                test_search_graph(api)
            elif choice == '7':
                test_shortest_path(api, domains, users, groups)
            elif choice == '8':
                test_edge_composition(api, domains, users, groups)
            elif choice == '9':
                test_relay_targets(api, domains, users, groups)
            else:
                print("Invalid option. Please try again.")
            
                
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())