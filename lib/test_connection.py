#!/usr/bin/env python3
"""
Test script to verify BloodHound API connection
"""

import os
import sys
import json
from bloodhound_api import BloodhoundAPI

def main():
    try:
        # Initialize the API client - it will load values from .env automatically
        api = BloodhoundAPI()
        
        # Print some info about what we're doing
        print(f"Testing connection to {api.domain}")
        
        # Test the connection with /api/v2/self endpoint
        user_info = api.get_self_info()
        
        if user_info:
            print("✅ Connection successful!")
            print("User Information:")
            # Pretty print the JSON with indentation
            print(json.dumps(user_info, indent=2))
            
            # Extract specific fields if needed
            if 'data' in user_info:
                data = user_info['data']
                if isinstance(data, dict):
                    username = data.get('username', 'Unknown')
                    print(f"\nAuthenticated as: {username}")
        else:
            print("❌ Connection failed. Please check your domain and API tokens.")
            return 1
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())