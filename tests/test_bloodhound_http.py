import json
from unittest.mock import MagicMock, Mock, patch

import pytest
import requests

from lib.bloodhound_api import (
    BloodhoundAPI,
    BloodhoundAPIError,
    BloodhoundAuthError,
    BloodhoundBaseClient,
    BloodhoundConnectionError,
)


class TestHTTPRequestFormation:
    """
    Test that your BloodHound client builds HTTP requests correctly

    This tests the authentication, headers, and URL formation
    without actually making network calls.
    """

    @patch(
        "requests.request"
    )  # This replaces the real requests.request with a fake one
    def test_basic_http_request(self, mock_request):
        """
        Test that a basic HTTP request is formed correctly

        The @patch decorator replaces requests.request with mock_request
        So when your code calls requests.request(), it actually calls our fake version
        """
        # Setup: Create a fake response that our mock will return
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"test": "success"}}
        mock_response.raise_for_status.return_value = None  # No exception = success

        # Tell our mock to return this fake response
        mock_request.return_value = mock_response

        # Act: Create a client and make a request
        client = BloodhoundBaseClient(
            domain="test.bloodhound.local",
            token_id="test_token_id",
            token_key="test_token_key",
        )

        result = client.request("GET", "/api/v2/test")

        # Assert: Check that the request was made correctly
        mock_request.assert_called_once()  # Verify requests.request was called

        # Get the arguments that were passed to requests.request
        call_args = mock_request.call_args

        # Check the method and URL
        assert call_args[1]["method"] == "GET"
        assert "test.bloodhound.local:443/api/v2/test" in call_args[1]["url"]

        # Check that authentication headers were added
        headers = call_args[1]["headers"]
        assert "Authorization" in headers
        assert "RequestDate" in headers
        assert "Signature" in headers
        assert headers["Authorization"] == "bhesignature test_token_id"

        # Check that we got the expected result
        assert result == {"data": {"test": "success"}}

        print("✅ Basic HTTP request formation works")
        print(f"   URL: {call_args[1]['url']}")
        print(f"   Headers: {list(headers.keys())}")

    @patch("requests.request")
    def test_request_with_query_parameters(self, mock_request):
        """
        Test that query parameters are added to URLs correctly
        """
        # Setup mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": []}
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response

        # Create client and make request with parameters
        client = BloodhoundBaseClient(
            domain="test.bloodhound.local", token_id="test_id", token_key="test_key"
        )

        result = client.request(
            "GET", "/api/v2/domains", params={"limit": 10, "skip": 5}
        )

        # Check that query parameters were added to the URL
        call_args = mock_request.call_args
        url = call_args[1]["url"]
        assert "limit=10" in url
        assert "skip=5" in url

        print("✅ Query parameters work correctly")
        print(f"   URL with params: {url}")

    @patch("requests.request")
    def test_request_with_json_data(self, mock_request):
        """
        Test that JSON data is sent correctly (for POST requests like Cypher queries)
        """
        # Setup mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"nodes": [], "edges": []}}
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response

        # Create client and make POST request with data
        client = BloodhoundBaseClient(
            domain="test.bloodhound.local", token_id="test_id", token_key="test_key"
        )

        cypher_query = {"query": "MATCH (n) RETURN n LIMIT 10"}
        result = client.request("POST", "/api/v2/graphs/cypher", data=cypher_query)

        # Check that data was JSON-encoded correctly
        call_args = mock_request.call_args
        sent_data = call_args[1]["data"]
        assert sent_data == json.dumps(cypher_query).encode("utf8")

        print("✅ JSON data encoding works correctly")


class TestHTTPErrorHandling:
    """
    Test how your client handles various HTTP errors

    This is crucial for robust error handling in production
    """

    @patch("requests.request")
    def test_connection_error_handling(self, mock_request):
        """
        Test handling of network connection errors
        """
        # Simulate a connection error
        mock_request.side_effect = requests.exceptions.ConnectionError(
            "Connection failed"
        )

        client = BloodhoundBaseClient(
            domain="unreachable.domain.com", token_id="test_id", token_key="test_key"
        )

        # This should raise a BloodhoundConnectionError
        with pytest.raises(BloodhoundConnectionError) as exc_info:
            client.request("GET", "/api/v2/test")

        assert "Failed to connect" in str(exc_info.value)
        print("✅ Connection error handling works")

    @patch("requests.request")
    def test_authentication_error_handling(self, mock_request):
        """
        Test handling of authentication errors (401 Unauthorized)
        """
        # Create a mock response that simulates 401 Unauthorized
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.json.return_value = {"error": "Invalid token"}
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            "401 Unauthorized"
        )
        mock_request.return_value = mock_response

        client = BloodhoundBaseClient(
            domain="test.domain.com", token_id="bad_token", token_key="bad_key"
        )

        # This should raise a BloodhoundAPIError
        with pytest.raises(BloodhoundAPIError) as exc_info:
            client.request("GET", "/api/v2/test")

        error = exc_info.value
        assert error.status_code == 401
        assert "401 Unauthorized" in str(error)

        print("✅ Authentication error handling works")

    @patch("requests.request")
    def test_invalid_json_response(self, mock_request):
        """
        Test handling of invalid JSON responses
        """
        # Create a response that can't be parsed as JSON
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_request.return_value = mock_response

        client = BloodhoundBaseClient(
            domain="test.domain.com", token_id="test_id", token_key="test_key"
        )

        with pytest.raises(BloodhoundAPIError) as exc_info:
            client.request("GET", "/api/v2/test")

        assert "Invalid JSON response" in str(exc_info.value)
        print("✅ Invalid JSON error handling works")


class TestBloodhoundAPIClientMethods:
    """
    Test the high-level BloodHound API client methods

    This tests methods like get_domains(), get_users(), etc.
    """

    @patch.object(BloodhoundBaseClient, "request")
    def test_get_domains(self, mock_request):
        """
        Test the get_domains() method

        We patch the request method instead of requests.request directly
        This tests the domain client logic specifically
        """
        # Setup: Create fake domain data that BloodHound would return
        fake_domain_data = {
            "data": [
                {
                    "objectid": "S-1-5-21-123456789-1234567890-123456789",
                    "name": "TESTDOMAIN.LOCAL",
                    "type": "Domain",
                    "distinguishedname": "DC=testdomain,DC=local",
                }
            ]
        }

        # Make our mock return this fake data
        mock_request.return_value = fake_domain_data

        # Act: Use the API client to get domains
        api = BloodhoundAPI(
            domain="test.domain.com", token_id="test_id", token_key="test_key"
        )

        result = api.domains.get_all()

        # Assert: Check that it called the right endpoint and returned the right data
        mock_request.assert_called_once_with("GET", "/api/v2/available-domains")
        assert result == fake_domain_data["data"]
        assert len(result) == 1
        assert result[0]["name"] == "TESTDOMAIN.LOCAL"

        print("✅ get_domains() method works")
        print(f"   Found domain: {result[0]['name']}")

    @patch.object(BloodhoundBaseClient, "request")
    def test_search_objects(self, mock_request):
        """
        Test the search_objects() method
        """
        # Setup: Fake search results
        fake_search_results = {
            "data": [
                {
                    "objectid": "S-1-5-21-123456789-1234567890-123456789-1001",
                    "name": "admin@testdomain.local",
                    "type": "User",
                    "distinguishedname": "CN=admin,CN=Users,DC=testdomain,DC=local",
                }
            ],
            "count": 1,
        }

        mock_request.return_value = fake_search_results

        # Act: Search for a user
        api = BloodhoundAPI(
            domain="test.domain.com", token_id="test_id", token_key="test_key"
        )

        result = api.domains.search_objects("admin", "User", limit=10)

        # Assert: Check the API call and results
        mock_request.assert_called_once_with(
            "GET",
            "/api/v2/search",
            params={"q": "admin", "type": "User", "limit": 10, "skip": 0},
        )

        assert result == fake_search_results
        assert result["count"] == 1
        assert result["data"][0]["name"] == "admin@testdomain.local"

        print("✅ search_objects() method works")
        print(f"   Found user: {result['data'][0]['name']}")

    @patch.object(BloodhoundBaseClient, "request")
    def test_get_users_from_domain(self, mock_request):
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
                    "admincount": False,
                },
                {
                    "objectid": "S-1-5-21-123456789-1234567890-123456789-1002",
                    "name": "svc_sql@testdomain.local",
                    "type": "User",
                    "enabled": True,
                    "admincount": False,
                    "hasspn": True,  # Kerberoastable!
                },
            ],
            "count": 2,
        }

        mock_request.return_value = fake_user_data

        # Act: Get users from a domain
        api = BloodhoundAPI(
            domain="test.domain.com", token_id="test_id", token_key="test_key"
        )

        domain_id = "S-1-5-21-123456789-1234567890-123456789"
        result = api.domains.get_users(domain_id, limit=50)

        # Assert: Check the API call
        mock_request.assert_called_once_with(
            "GET",
            f"/api/v2/domains/{domain_id}/users",
            params={"limit": 50, "skip": 0, "type": "list"},
        )

        assert result == fake_user_data
        assert result["count"] == 2

        # Check for Kerberoastable users (offensive security check!)
        users = result["data"]
        kerberoastable = [u for u in users if u.get("hasspn", False)]
        assert len(kerberoastable) == 1
        assert "svc_sql" in kerberoastable[0]["name"]

        print("✅ get_users() method works")
        print(f"   Found {result['count']} users")
        print(f"   Kerberoastable users: {len(kerberoastable)}")


class TestOffensiveSecurityHTTPScenarios:
    """
    Test HTTP scenarios specific to offensive security analysis
    """

    @patch.object(BloodhoundBaseClient, "request")
    def test_cypher_query_execution(self, mock_request):
        """
        Test executing Cypher queries (key for custom analysis)
        """
        # Setup: Fake Cypher query results
        fake_cypher_results = {
            "data": {
                "nodes": [
                    {
                        "objectid": "S-1-5-21-123456789-1234567890-123456789-512",
                        "name": "DOMAIN ADMINS@TESTDOMAIN.LOCAL",
                        "type": "Group",
                    }
                ],
                "edges": [],
            }
        }

        mock_request.return_value = fake_cypher_results

        # Act: Execute a Cypher query
        api = BloodhoundAPI(
            domain="test.domain.com", token_id="test_id", token_key="test_key"
        )

        query = 'MATCH (g:Group) WHERE g.name =~ "(?i).*domain admins.*" RETURN g'
        result = api.cypher.run_query(query, include_properties=True)

        # Assert: Check the API call
        mock_request.assert_called_once_with(
            "POST",
            "/api/v2/graphs/cypher",
            data={"query": query, "includeproperties": True},
        )

        assert result == fake_cypher_results
        assert len(result["data"]["nodes"]) == 1
        assert "DOMAIN ADMINS" in result["data"]["nodes"][0]["name"]

        print("✅ Cypher query execution works")
        print(f"   Found: {result['data']['nodes'][0]['name']}")
