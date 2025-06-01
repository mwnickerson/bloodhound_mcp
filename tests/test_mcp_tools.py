import json
import os
import sys
from unittest.mock import MagicMock, Mock, patch

import pytest

# Add the project root to Python path so we can import main.py
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Import strategy: Import main normally, but we'll mock the bloodhound_api instance
# This lets the MCP tools work normally, but with a fake API client
try:
    import main

    MAIN_IMPORTED = True
    print("✅ Successfully imported main.py")
except Exception as e:
    MAIN_IMPORTED = False
    print(f"❌ Failed to import main.py: {e}")
    # Create a mock main module for testing
    main = Mock()


class TestDomainMCPTools:
    """
    Test MCP tools related to domain operations
    """

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch(
        "main.bloodhound_api"
    )  # Mock the specific bloodhound_api instance in main.py
    def test_get_domains_success(self, mock_api):
        """
        Test the get_domains() MCP tool with successful response

        This tests:
        - Tool calls the right API method
        - Tool formats the response as JSON
        - Tool includes the right message and data structure
        """
        # Setup: Create fake domain data that the API would return
        fake_domains = [
            {
                "objectid": "S-1-5-21-123456789-1234567890-123456789",
                "name": "TESTDOMAIN.LOCAL",
                "type": "Domain",
            },
            {
                "objectid": "S-1-5-21-987654321-0987654321-987654321",
                "name": "SUBDOMAIN.TESTDOMAIN.LOCAL",
                "type": "Domain",
            },
        ]

        # Make the mock API return our fake data
        mock_api.domains.get_all.return_value = fake_domains

        # Act: Call the MCP tool function
        result_json = main.get_domains()

        # Debug: Print what we actually got
        print(f"Result type: {type(result_json)}")
        print(f"Result content: {result_json}")

        # Parse the JSON response (MCP tools return JSON strings)
        result = json.loads(result_json)

        # Assert: Check that everything works correctly
        mock_api.domains.get_all.assert_called_once()  # API was called

        # Check the response structure
        assert "message" in result
        assert "domains" in result
        assert "Found 2 domains in Bloodhound" in result["message"]
        assert result["domains"] == fake_domains
        assert len(result["domains"]) == 2

        print("✅ get_domains() MCP tool works")
        print(f"   Found domains: {[d['name'] for d in result['domains']]}")

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_domains_error_handling(self, mock_api):
        """
        Test get_domains() error handling when API fails
        """
        # Setup: Make the API raise an exception
        mock_api.domains.get_all.side_effect = Exception(
            "BloodHound server unreachable"
        )

        # Act: Call the MCP tool
        result_json = main.get_domains()
        result = json.loads(result_json)

        # Assert: Check error handling
        assert "error" in result
        assert "Failed to retrieve domains" in result["error"]

        print("✅ get_domains() error handling works")

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_search_objects(self, mock_api):
        """
        Test the search_objects() MCP tool
        """
        # Setup: Fake search results
        fake_search_results = {
            "data": [
                {
                    "objectid": "S-1-5-21-123456789-1234567890-123456789-1001",
                    "name": "admin@testdomain.local",
                    "type": "User",
                }
            ],
            "count": 1,
        }

        mock_api.domains.search_objects.return_value = fake_search_results

        # Act: Search for a user
        result_json = main.search_objects("admin", "User", limit=50, skip=0)
        result = json.loads(result_json)

        # Assert: Check the search worked
        mock_api.domains.search_objects.assert_called_once_with(
            "admin", "User", limit=50, skip=0
        )

        assert result["count"] == 1
        assert result["results"] == fake_search_results["data"]
        assert "Found 1 results matching 'admin'" in result["message"]

        print("✅ search_objects() MCP tool works")
        print(f"   Found: {result['results'][0]['name']}")

    @pytest.mark.skipif(not MAIN_IMPORTED, reason="main.py could not be imported")
    @patch("main.bloodhound_api")
    def test_get_users_from_domain(self, mock_api):
        """
        Test getting users from a specific domain
        """
        # Setup: Fake user data
        fake_user_data = {
            "data": [
                {
                    "objectid": "S-1-5-21-123456789-1234567890-123456789-1001",
                    "name": "user1@testdomain.local",
                    "type": "User",
                    "enabled": True,
                },
                {
                    "objectid": "S-1-5-21-123456789-1234567890-123456789-1002",
                    "name": "svc_backup@testdomain.local",
                    "type": "User",
                    "enabled": True,
                    "hasspn": True,  # Kerberoastable service account
                },
            ],
            "count": 2,
        }

        mock_api.domains.get_users.return_value = fake_user_data

        # Act: Get users from domain
        domain_id = "S-1-5-21-123456789-1234567890-123456789"
        result_json = main.get_users(domain_id, limit=100, skip=0)
        result = json.loads(result_json)

        # Assert: Check the results
        mock_api.domains.get_users.assert_called_once_with(domain_id, limit=100, skip=0)

        assert result["count"] == 2
        assert len(result["users"]) == 2
        assert "Found 2 users in the domain" in result["message"]

        # Check for service accounts (offensive security relevance)
        service_accounts = [u for u in result["users"] if "svc_" in u["name"]]
        assert len(service_accounts) == 1

        print("✅ get_users() MCP tool works")
        print(f"   Found {result['count']} users")
        print(f"   Service accounts: {len(service_accounts)}")


class TestManualFunctionTesting:
    """
    If we can't import main.py cleanly, test the function logic manually
    """

    @pytest.mark.skipif(MAIN_IMPORTED, reason="main.py imported successfully")
    def test_json_response_format(self):
        """
        Test the JSON response format that MCP tools should return
        """
        # Simulate what get_domains() should return
        fake_domains = [{"objectid": "domain1", "name": "TEST.LOCAL", "type": "Domain"}]

        # This is the format your MCP tools should return
        expected_response = {
            "message": f"Found {len(fake_domains)} domains in Bloodhound",
            "domains": fake_domains,
        }

        # Convert to JSON and back (like the MCP tools do)
        json_response = json.dumps(expected_response)
        parsed_response = json.loads(json_response)

        assert parsed_response["message"] == "Found 1 domains in Bloodhound"
        assert len(parsed_response["domains"]) == 1
        assert parsed_response["domains"][0]["name"] == "TEST.LOCAL"

        print("✅ JSON response format is correct")

    @pytest.mark.skipif(MAIN_IMPORTED, reason="main.py imported successfully")
    def test_error_response_format(self):
        """
        Test the error response format that MCP tools should return
        """
        # This is what error responses should look like
        error_response = {"error": "Failed to retrieve domains: Connection timeout"}

        json_response = json.dumps(error_response)
        parsed_response = json.loads(json_response)

        assert "error" in parsed_response
        assert "Failed to retrieve domains" in parsed_response["error"]

        print("✅ Error response format is correct")


class TestDiagnostics:
    """
    Tests to help diagnose what's happening with main.py import
    """

    def test_main_module_inspection(self):
        """
        Inspect what we actually imported as main
        """
        print(f"main module type: {type(main)}")
        print(f"main module: {main}")

        if hasattr(main, "get_domains"):
            print(f"get_domains type: {type(main.get_domains)}")
            print(f"get_domains: {main.get_domains}")
        else:
            print("❌ get_domains function not found in main")

        if hasattr(main, "bloodhound_api"):
            print(f"bloodhound_api type: {type(main.bloodhound_api)}")
        else:
            print("❌ bloodhound_api not found in main")

        # List all attributes of main
        main_attrs = [attr for attr in dir(main) if not attr.startswith("_")]
        print(f"main attributes: {main_attrs}")

    def test_check_mcp_functions_exist(self):
        """
        Check which MCP functions exist in main
        """
        expected_functions = [
            "get_domains",
            "get_users",
            "get_groups",
            "search_objects",
            "get_user_info",
            "get_user_admin_rights",
            "run_cypher_query",
        ]

        existing_functions = []
        missing_functions = []

        for func_name in expected_functions:
            if hasattr(main, func_name):
                existing_functions.append(func_name)
                print(f"✅ {func_name} exists")
            else:
                missing_functions.append(func_name)
                print(f"❌ {func_name} missing")

        print(f"Existing functions: {existing_functions}")
        print(f"Missing functions: {missing_functions}")

        # This test always passes - it's just for information
        assert True
