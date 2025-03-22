#!/usr/bin/env python3
"""
Test script to interact with BloodHound API functions
"""

import os
import sys
import json
from bloodhound_api import BloodhoundAPI

def display_menu():
    """Display the menu of available API functions to test"""
    print("\n=== BloodHound API Test Menu ===")
    print("1. Test Connection (get_self_info)")
    print("2. Get Domains")
    print("3. Get Users from Domain")
    print("0. Exit")
    return input("\nSelect an option (0-3): ")

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
    domains = api.get_domains()
    
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
    users = api.get_users(selected_domain.get('id'), limit=limit)
    
    if users and users.get('data'):
        print(f"Found {users.get('count')} total users (showing up to {limit}):")
        for i, user in enumerate(users.get('data')):
            print(f"{i+1}. {user.get('label')} ({user.get('name')})")
    else:
        print("No users found or error occurred.")

def main():
    try:
        # Initialize the API client
        api = BloodhoundAPI()
        
        # Store domains for reuse
        domains = []
        
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
                if not domains:
                    print("Please retrieve domains first (option 2).")
                    continue
                get_users_from_domain(api, domains)
            else:
                print("Invalid option. Please try again.")
                
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())