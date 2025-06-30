import base64
import datetime
import hashlib
import hmac
import json
import os
from unittest.mock import MagicMock, Mock, patch

import pytest
import requests
import responses

from lib.bloodhound_api import (
    ADCSClient,
    BloodhoundError,
    BloodhoundAPI,
    BloodhoundAPIError,
    BloodhoundAuthError,
    BloodhoundBaseClient,
    BloodhoundConnectionError,
    ComputerClient,
    CypherClient,
    DomainClient,
    GPOsClient,
    GraphClient,
    GroupClient,
    OUsClient,
    UserClient,
)


class TestExceptions:
    """Test custom exception classes"""

    def test_bloodhound_error_inheritance(self):
        """Test that all custom exceptions inherit from BloodhoundError"""
        assert issubclass(BloodhoundAuthError, BloodhoundError)
        assert issubclass(BloodhoundConnectionError, BloodhoundError)
        assert issubclass(BloodhoundAPIError, BloodhoundError)

    def test_bloodhound_api_error_with_response(self):
        """Test BloodhoundAPIError stores response information"""
        mock_response = Mock()
        mock_response.status_code = 404
        
        error = BloodhoundAPIError("Test error", mock_response)
        assert str(error) == "Test error"
        assert error.response == mock_response
        assert error.status_code == 404

    def test_bloodhound_api_error_without_response(self):
        """Test BloodhoundAPIError when response is None"""
        error = BloodhoundAPIError("Test error", None)
        assert str(error) == "Test error"
        assert error.response is None
        assert error.status_code is None


class TestBloodhoundBaseClient:
    """Test the BloodhoundBaseClient class"""

    def test_initialization_with_all_params(self):
        """Test client initialization with all parameters provided"""
        client = BloodhoundBaseClient(
            domain="test.bloodhound.local",
            token_id="test_token_id",
            token_key="test_token_key",
            port=8080,
            scheme="http"
        )
        
        assert client.domain == "test.bloodhound.local"
        assert client.token_id == "test_token_id"
        assert client.token_key == "test_token_key"
        assert client.port == 8080
        assert client.scheme == "http"

    @patch.dict(os.environ, {
        "BLOODHOUND_DOMAIN": "env.test.local",
        "BLOODHOUND_TOKEN_ID": "env_token_id",
        "BLOODHOUND_TOKEN_KEY": "env_token_key"
    })
    def test_initialization_from_environment(self):
        """Test client initialization using environment variables"""
        client = BloodhoundBaseClient()
        
        assert client.domain == "env.test.local"
        assert client.token_id == "env_token_id"
        assert client.token_key == "env_token_key"
        assert client.port == 443  # Default
        assert client.scheme == "https"  # Default

    @patch.dict(os.environ, {}, clear=True)
    def test_initialization_missing_domain(self):
        """Test that missing domain raises BloodhoundAuthError"""
        with pytest.raises(BloodhoundAuthError) as exc_info:
            BloodhoundBaseClient(
                token_id="test_id",
                token_key="test_key"
            )
        assert "domain" in str(exc_info.value).lower()

    @patch.dict(os.environ, {}, clear=True)
    def test_initialization_missing_token_id(self):
        """Test that missing token_id raises BloodhoundAuthError"""
        with pytest.raises(BloodhoundAuthError) as exc_info:
            BloodhoundBaseClient(
                domain="test.local",
                token_key="test_key"
            )
        assert "token id" in str(exc_info.value).lower()

    @patch.dict(os.environ, {}, clear=True)
    def test_initialization_missing_token_key(self):
        """Test that missing token_key raises BloodhoundAuthError"""
        with pytest.raises(BloodhoundAuthError) as exc_info:
            BloodhoundBaseClient(
                domain="test.local",
                token_id="test_id"
            )
        assert "token key" in str(exc_info.value).lower()

    def test_format_url_with_leading_slash(self):
        """Test URL formatting with leading slash"""
        client = BloodhoundBaseClient(
            domain="test.local",
            token_id="id",
            token_key="key"
        )
        
        url = client._format_url("/api/v2/domains")
        expected = "https://test.local:443/api/v2/domains"
        assert url == expected

    def test_format_url_without_leading_slash(self):
        """Test URL formatting without leading slash"""
        client = BloodhoundBaseClient(
            domain="test.local",
            token_id="id",
            token_key="key"
        )
        
        url = client._format_url("api/v2/domains")
        expected = "https://test.local:443/api/v2/domains"
        assert url == expected

    def test_format_url_custom_port_scheme(self):
        """Test URL formatting with custom port and scheme"""
        client = BloodhoundBaseClient(
            domain="test.local",
            token_id="id",
            token_key="key",
            port=8080,
            scheme="http"
        )
        
        url = client._format_url("/api/v2/domains")
        expected = "http://test.local:8080/api/v2/domains"
        assert url == expected

    @patch('requests.request')
    def test_request_signature_generation(self, mock_request):
        """Test that request signatures are generated correctly"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}
        mock_request.return_value = mock_response
        
        client = BloodhoundBaseClient(
            domain="test.local",
            token_id="test_id",
            token_key="test_key"
        )
        
        with patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value.astimezone.return_value.isoformat.return_value = "2023-01-01T12:00:00+00:00"
            
            response = client._request("GET", "/api/v2/test")
            
            # Verify the request was called with proper headers
            mock_request.assert_called_once()
            args, kwargs = mock_request.call_args
            
            assert kwargs['method'] == "GET"
            assert kwargs['url'] == "https://test.local:443/api/v2/test"
            
            headers = kwargs['headers']
            assert headers['User-Agent'] == "bloodhound-api-client 0.1"
            assert headers['Authorization'] == "bhesignature test_id"
            assert headers['RequestDate'] == "2023-01-01T12:00:00+00:00"
            assert 'Signature' in headers
            assert headers['Content-Type'] == "application/json"

    @patch('requests.request')
    def test_request_with_body(self, mock_request):
        """Test request with body data"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"success": True}
        mock_request.return_value = mock_response
        
        client = BloodhoundBaseClient(
            domain="test.local",
            token_id="test_id",
            token_key="test_key"
        )
        
        body_data = b'{"test": "data"}'
        response = client._request("POST", "/api/v2/test", body_data)
        
        mock_request.assert_called_once()
        args, kwargs = mock_request.call_args
        assert kwargs['data'] == body_data

    @patch('requests.request')
    def test_request_connection_error(self, mock_request):
        """Test that connection errors are properly handled"""
        mock_request.side_effect = requests.exceptions.ConnectionError("Connection failed")
        
        client = BloodhoundBaseClient(
            domain="test.local",
            token_id="test_id",
            token_key="test_key"
        )
        
        with pytest.raises(BloodhoundConnectionError) as exc_info:
            client._request("GET", "/api/v2/test")
        
        assert "Failed to connect to BloodHound API" in str(exc_info.value)

    @patch('requests.request')
    def test_request_with_params_and_data(self, mock_request):
        """Test request method with params and data"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "success"}
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response
        
        client = BloodhoundBaseClient(
            domain="test.local",
            token_id="test_id",
            token_key="test_key"
        )
        
        params = {"limit": 100, "skip": 0}
        data = {"query": "test"}
        
        result = client.request("GET", "/api/v2/search", params=params, data=data)
        
        assert result == {"result": "success"}
        mock_request.assert_called_once()
        
        # Check that params were added to URL
        args, kwargs = mock_request.call_args
        assert "limit=100" in kwargs['url']
        assert "skip=0" in kwargs['url']
        
        # Check that data was JSON encoded
        assert kwargs['data'] == b'{"query": "test"}'

    @patch('requests.request')
    def test_request_http_error_with_json_response(self, mock_request):
        """Test HTTP error handling with JSON error response"""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("400 Bad Request")
        mock_response.json.return_value = {"error": "Invalid query parameter"}
        mock_request.return_value = mock_response
        
        client = BloodhoundBaseClient(
            domain="test.local",
            token_id="test_id",
            token_key="test_key"
        )
        
        with pytest.raises(BloodhoundAPIError) as exc_info:
            client.request("GET", "/api/v2/test")
        
        error_msg = str(exc_info.value)
        assert "HTTP Error" in error_msg
        assert "Invalid query parameter" in error_msg
        assert exc_info.value.status_code == 400

    @patch('requests.request')
    def test_request_http_error_without_json_response(self, mock_request):
        """Test HTTP error handling without JSON error response"""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Internal Server Error")
        mock_response.json.side_effect = json.JSONDecodeError("No JSON", "", 0)
        mock_request.return_value = mock_response
        
        client = BloodhoundBaseClient(
            domain="test.local",
            token_id="test_id",
            token_key="test_key"
        )
        
        with pytest.raises(BloodhoundAPIError) as exc_info:
            client.request("GET", "/api/v2/test")
        
        assert "HTTP Error" in str(exc_info.value)
        assert exc_info.value.status_code == 500

    @patch('requests.request')
    def test_request_invalid_json_response(self, mock_request):
        """Test handling of invalid JSON response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_request.return_value = mock_response
        
        client = BloodhoundBaseClient(
            domain="test.local",
            token_id="test_id",
            token_key="test_key"
        )
        
        with pytest.raises(BloodhoundAPIError) as exc_info:
            client.request("GET", "/api/v2/test")
        
        assert "Invalid JSON response" in str(exc_info.value)


class TestBloodhoundAPI:
    """Test the main BloodhoundAPI class"""

    def test_initialization(self):
        """Test BloodhoundAPI initialization"""
        api = BloodhoundAPI(
            domain="test.local",
            token_id="test_id",
            token_key="test_key"
        )
        
        # Check that base client was created
        assert api.base_client is not None
        assert api.base_client.domain == "test.local"
        
        # Check that all resource clients were initialized
        assert isinstance(api.domains, DomainClient)
        assert isinstance(api.users, UserClient)
        assert isinstance(api.groups, GroupClient)
        assert isinstance(api.computers, ComputerClient)
        assert isinstance(api.ous, OUsClient)
        assert isinstance(api.gpos, GPOsClient)
        assert isinstance(api.graph, GraphClient)
        assert isinstance(api.adcs, ADCSClient)
        assert isinstance(api.cypher, CypherClient)

    @patch.object(BloodhoundBaseClient, 'request')
    def test_test_connection_success(self, mock_request):
        """Test successful connection test"""
        mock_request.return_value = {"data": {"version": "4.0.0"}}
        
        api = BloodhoundAPI(
            domain="test.local",
            token_id="test_id",
            token_key="test_key"
        )
        
        result = api.test_connection()
        assert result == {"version": "4.0.0"}
        mock_request.assert_called_once_with("GET", "/api/version")

    @patch.object(BloodhoundBaseClient, 'request')
    def test_test_connection_failure(self, mock_request):
        """Test connection test failure"""
        mock_request.side_effect = Exception("Connection failed")
        
        api = BloodhoundAPI(
            domain="test.local",
            token_id="test_id",
            token_key="test_key"
        )
        
        result = api.test_connection()
        assert result is None

    @patch.object(BloodhoundBaseClient, 'request')
    def test_get_self_info_success(self, mock_request):
        """Test successful get_self_info"""
        mock_request.return_value = {"id": "123", "name": "test_user"}
        
        api = BloodhoundAPI(
            domain="test.local",
            token_id="test_id",
            token_key="test_key"
        )
        
        result = api.get_self_info()
        assert result == {"id": "123", "name": "test_user"}
        mock_request.assert_called_once_with("GET", "/api/v2/self")

    @patch.object(BloodhoundBaseClient, 'request')
    def test_get_self_info_failure(self, mock_request):
        """Test get_self_info failure"""
        mock_request.side_effect = Exception("Request failed")
        
        api = BloodhoundAPI(
            domain="test.local",
            token_id="test_id",
            token_key="test_key"
        )
        
        result = api.get_self_info()
        assert result is None


class TestDomainClient:
    """Test the DomainClient class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_base_client = Mock()
        self.domain_client = DomainClient(self.mock_base_client)

    def test_get_all(self):
        """Test get_all domains"""
        self.mock_base_client.request.return_value = {
            "data": [{"id": "1", "name": "domain1.local"}]
        }
        
        result = self.domain_client.get_all()
        assert result == [{"id": "1", "name": "domain1.local"}]
        self.mock_base_client.request.assert_called_once_with("GET", "/api/v2/available-domains")

    def test_search_objects_with_all_params(self):
        """Test search_objects with all parameters"""
        self.mock_base_client.request.return_value = {"data": []}
        
        result = self.domain_client.search_objects(
            query="admin",
            type="User",
            limit=50,
            skip=10
        )
        
        expected_params = {
            "q": "admin",
            "type": "User",
            "limit": 50,
            "skip": 10
        }
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/search", params=expected_params
        )

    def test_search_objects_without_type(self):
        """Test search_objects without type parameter"""
        self.mock_base_client.request.return_value = {"data": []}
        
        result = self.domain_client.search_objects(query="admin")
        
        expected_params = {
            "q": "admin",
            "limit": 100,
            "skip": 0
        }
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/search", params=expected_params
        )

    def test_get_users(self):
        """Test get_users"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.domain_client.get_users("domain_id_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/domains/domain_id_123/users", params=expected_params
        )

    def test_get_groups(self):
        """Test get_groups"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.domain_client.get_groups("domain_id_123", limit=50, skip=25)
        
        expected_params = {"limit": 50, "skip": 25, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/domains/domain_id_123/groups", params=expected_params
        )

    def test_get_computers(self):
        """Test get_computers"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.domain_client.get_computers("domain_id_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/domains/domain_id_123/computers", params=expected_params
        )

    def test_get_controllers(self):
        """Test get_controllers"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.domain_client.get_controllers("domain_id_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/domains/domain_id_123/controllers", params=expected_params
        )

    def test_get_gpos(self):
        """Test get_gpos"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.domain_client.get_gpos("domain_id_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/domains/domain_id_123/gpos", params=expected_params
        )

    def test_get_ous(self):
        """Test get_ous"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.domain_client.get_ous("domain_id_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/domains/domain_id_123/ous", params=expected_params
        )

    def test_get_dc_syncers(self):
        """Test get_dc_syncers"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.domain_client.get_dc_syncers("domain_id_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/domains/domain_id_123/dc-syncers", params=expected_params
        )

    def test_get_foreign_admins(self):
        """Test get_foreign_admins"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.domain_client.get_foreign_admins("domain_id_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/domains/domain_id_123/foreign-admins", params=expected_params
        )

    def test_get_foreign_gpo_controllers(self):
        """Test get_foreign_gpo_controllers"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.domain_client.get_foreign_gpo_controllers("domain_id_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/domains/domain_id_123/foreign-gpo-controllers", params=expected_params
        )

    def test_get_foreign_groups(self):
        """Test get_foreign_groups"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.domain_client.get_foreign_groups("domain_id_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/domains/domain_id_123/foreign-groups", params=expected_params
        )

    def test_get_foreign_users(self):
        """Test get_foreign_users"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.domain_client.get_foreign_users("domain_id_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/domains/domain_id_123/foreign-users", params=expected_params
        )

    def test_get_inbound_trusts(self):
        """Test get_inbound_trusts"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.domain_client.get_inbound_trusts("domain_id_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/domains/domain_id_123/inbound-trusts", params=expected_params
        )

    def test_get_outbound_trusts(self):
        """Test get_outbound_trusts"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.domain_client.get_outbound_trusts("domain_id_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/domains/domain_id_123/outbound-trusts", params=expected_params
        )


class TestUserClient:
    """Test the UserClient class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_base_client = Mock()
        self.user_client = UserClient(self.mock_base_client)

    def test_get_info(self):
        """Test get_info"""
        self.mock_base_client.request.return_value = {"data": {"id": "user_123"}}
        
        result = self.user_client.get_info("user_123")
        
        expected_params = {"counts": "true"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/users/user_123", params=expected_params
        )

    def test_get_admin_rights(self):
        """Test get_admin_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.user_client.get_admin_rights("user_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/users/user_123/admin-rights", params=expected_params
        )

    def test_get_constrained_delegation_rights(self):
        """Test get_constrained_delegation_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.user_client.get_constrained_delegation_rights("user_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/users/user_123/constrained-delegation-rights", params=expected_params
        )

    def test_get_controllables(self):
        """Test get_controllables"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.user_client.get_controllables("user_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/users/user_123/controllables", params=expected_params
        )

    def test_get_controllers(self):
        """Test get_controllers"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.user_client.get_controllers("user_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/users/user_123/controllers", params=expected_params
        )

    def test_get_dcom_rights(self):
        """Test get_dcom_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.user_client.get_dcom_rights("user_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/users/user_123/dcom-rights", params=expected_params
        )

    def test_get_memberships(self):
        """Test get_memberships"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.user_client.get_memberships("user_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/users/user_123/memberships", params=expected_params
        )

    def test_get_ps_remote_rights(self):
        """Test get_ps_remote_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.user_client.get_ps_remote_rights("user_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/users/user_123/ps-remote-rights", params=expected_params
        )

    def test_get_rdp_rights(self):
        """Test get_rdp_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.user_client.get_rdp_rights("user_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/users/user_123/rdp-rights", params=expected_params
        )

    def test_get_sessions(self):
        """Test get_sessions"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.user_client.get_sessions("user_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/users/user_123/sessions", params=expected_params
        )

    def test_get_sql_admin_rights(self):
        """Test get_sql_admin_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.user_client.get_sql_admin_rights("user_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/users/user_123/sql-admin-rights", params=expected_params
        )


class TestGroupClient:
    """Test the GroupClient class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_base_client = Mock()
        self.group_client = GroupClient(self.mock_base_client)

    def test_get_info(self):
        """Test get_info"""
        self.mock_base_client.request.return_value = {"data": {"id": "group_123"}}
        
        result = self.group_client.get_info("group_123")
        
        expected_params = {"counts": "true"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/groups/group_123", params=expected_params
        )

    def test_get_admin_rights(self):
        """Test get_admin_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.group_client.get_admin_rights("group_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/groups/group_123/admin-rights", params=expected_params
        )

    def test_get_controllables(self):
        """Test get_controllables"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.group_client.get_controllables("group_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/groups/group_123/controllables", params=expected_params
        )

    def test_get_controllers(self):
        """Test get_controllers"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.group_client.get_controllers("group_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/groups/group_123/controllers", params=expected_params
        )

    def test_get_dcom_rights(self):
        """Test get_dcom_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.group_client.get_dcom_rights("group_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/groups/group_123/dcom-rights", params=expected_params
        )

    def test_get_members(self):
        """Test get_members"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.group_client.get_members("group_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/groups/group_123/members", params=expected_params
        )

    def test_get_memberships(self):
        """Test get_memberships"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.group_client.get_memberships("group_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/groups/group_123/memberships", params=expected_params
        )

    def test_get_ps_remote_rights(self):
        """Test get_ps_remote_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.group_client.get_ps_remote_rights("group_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/groups/group_123/ps-remote-rights", params=expected_params
        )

    def test_get_rdp_rights(self):
        """Test get_rdp_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.group_client.get_rdp_rights("group_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/groups/group_123/rdp-rights", params=expected_params
        )

    def test_get_sessions(self):
        """Test get_sessions"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.group_client.get_sessions("group_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/groups/group_123/sessions", params=expected_params
        )


class TestComputerClient:
    """Test the ComputerClient class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_base_client = Mock()
        self.computer_client = ComputerClient(self.mock_base_client)

    def test_get_info(self):
        """Test get_info"""
        self.mock_base_client.request.return_value = {"data": {"id": "computer_123"}}
        
        result = self.computer_client.get_info("computer_123")
        
        expected_params = {"counts": "true"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123", params=expected_params
        )

    def test_get_admin_rights(self):
        """Test get_admin_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_admin_rights("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/admin-rights", params=expected_params
        )

    def test_get_admin_users(self):
        """Test get_admin_users"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_admin_users("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/admin-users", params=expected_params
        )

    def test_get_constrained_delegation_rights(self):
        """Test get_constrained_delegation_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_constrained_delegation_rights("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/constrained-delegation-rights", 
            params=expected_params
        )

    def test_get_constrained_users(self):
        """Test get_constrained_users"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_constrained_users("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/constrained-users", params=expected_params
        )

    def test_get_controllables(self):
        """Test get_controllables"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_controllables("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/controllables", params=expected_params
        )

    def test_get_controllers(self):
        """Test get_controllers"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_controllers("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/controllers", params=expected_params
        )

    def test_get_dcom_rights(self):
        """Test get_dcom_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_dcom_rights("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/dcom-rights", params=expected_params
        )

    def test_get_dcom_users(self):
        """Test get_dcom_users"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_dcom_users("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/dcom-users", params=expected_params
        )

    def test_get_group_membership(self):
        """Test get_group_membership"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_group_membership("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/group-membership", params=expected_params
        )

    def test_get_ps_remote_rights(self):
        """Test get_ps_remote_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_ps_remote_rights("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/ps-remote-rights", params=expected_params
        )

    def test_get_ps_remote_users(self):
        """Test get_ps_remote_users"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_ps_remote_users("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/ps-remote-users", params=expected_params
        )

    def test_get_rdp_rights(self):
        """Test get_rdp_rights"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_rdp_rights("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/rdp-rights", params=expected_params
        )

    def test_get_rdp_users(self):
        """Test get_rdp_users"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_rdp_users("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/rdp-users", params=expected_params
        )

    def test_get_sessions(self):
        """Test get_sessions"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_sessions("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/sessions", params=expected_params
        )

    def test_get_sql_admins(self):
        """Test get_sql_admins"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.computer_client.get_sql_admins("computer_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/computers/computer_123/sql-admins", params=expected_params
        )


class TestOUsClient:
    """Test the OUsClient class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_base_client = Mock()
        self.ous_client = OUsClient(self.mock_base_client)

    def test_get_info(self):
        """Test get_info"""
        self.mock_base_client.request.return_value = {"data": {"id": "ou_123"}}
        
        result = self.ous_client.get_info("ou_123")
        
        expected_params = {"counts": "true"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/ous/ou_123", params=expected_params
        )

    def test_get_computers(self):
        """Test get_computers"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.ous_client.get_computers("ou_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/ous/ou_123/computers", params=expected_params
        )

    def test_get_gpos(self):
        """Test get_gpos"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.ous_client.get_gpos("ou_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/ous/ou_123/gpos", params=expected_params
        )

    def test_get_groups(self):
        """Test get_groups"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.ous_client.get_groups("ou_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/ous/ou_123/groups", params=expected_params
        )

    def test_get_users(self):
        """Test get_users"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.ous_client.get_users("ou_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/ous/ou_123/users", params=expected_params
        )


class TestGPOsClient:
    """Test the GPOsClient class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_base_client = Mock()
        self.gpos_client = GPOsClient(self.mock_base_client)

    def test_get_info(self):
        """Test get_info"""
        self.mock_base_client.request.return_value = {"data": {"id": "gpo_123"}}
        
        result = self.gpos_client.get_info("gpo_123")
        
        expected_params = {"counts": "true"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/gpos/gpo_123", params=expected_params
        )

    def test_get_computer(self):
        """Test get_computer"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.gpos_client.get_computer("gpo_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/gpos/gpo_123/computers", params=expected_params
        )

    def test_get_controllers(self):
        """Test get_controllers"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.gpos_client.get_controllers("gpo_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/gpos/gpo_123/controllers", params=expected_params
        )

    def test_get_ous(self):
        """Test get_ous"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.gpos_client.get_ous("gpo_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/gpos/gpo_123/ous", params=expected_params
        )

    def test_get_tier_zeros(self):
        """Test get_tier_zeros"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.gpos_client.get_tier_zeros("gpo_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/gpos/gpo_123/tier-zeros", params=expected_params
        )

    def test_get_users(self):
        """Test get_users"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.gpos_client.get_users("gpo_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/gpos/gpo_123/users", params=expected_params
        )


class TestGraphClient:
    """Test the GraphClient class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_base_client = Mock()
        self.graph_client = GraphClient(self.mock_base_client)

    def test_search_fuzzy(self):
        """Test search with fuzzy type"""
        self.mock_base_client.request.return_value = {"data": []}
        
        result = self.graph_client.search("admin", "fuzzy")
        
        expected_params = {"query": "admin", "type": "fuzzy"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/graph-search", params=expected_params
        )

    def test_search_exact(self):
        """Test search with exact type"""
        self.mock_base_client.request.return_value = {"data": []}
        
        result = self.graph_client.search("Domain Admins", "exact")
        
        expected_params = {"query": "Domain Admins", "type": "exact"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/graph-search", params=expected_params
        )

    def test_get_shortest_path_basic(self):
        """Test get_shortest_path without relationship kinds"""
        self.mock_base_client.request.return_value = {"data": {"nodes": [], "edges": []}}
        
        result = self.graph_client.get_shortest_path("start_node_123", "end_node_456")
        
        expected_params = {"start_node": "start_node_123", "end_node": "end_node_456"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/graphs/shortest-path", params=expected_params
        )

    def test_get_shortest_path_with_relationship_kinds(self):
        """Test get_shortest_path with relationship kinds"""
        self.mock_base_client.request.return_value = {"data": {"nodes": [], "edges": []}}
        
        result = self.graph_client.get_shortest_path(
            "start_node_123", 
            "end_node_456", 
            "MemberOf,AdminTo"
        )
        
        expected_params = {
            "start_node": "start_node_123", 
            "end_node": "end_node_456",
            "relationshipkinds": "MemberOf,AdminTo"
        }
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/graphs/shortest-path", params=expected_params
        )

    def test_get_edge_composition(self):
        """Test get_edge_composition"""
        self.mock_base_client.request.return_value = {"data": {"nodes": [], "edges": []}}
        
        result = self.graph_client.get_edge_composition(123, 456, "AdminTo")
        
        expected_params = {
            "sourcenode": 123,
            "targetnode": 456,
            "edgetype": "AdminTo"
        }
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/graphs/edge-composition", params=expected_params
        )

    def test_get_relay_targets(self):
        """Test get_relay_targets"""
        self.mock_base_client.request.return_value = {"data": {"nodes": [], "edges": []}}
        
        result = self.graph_client.get_relay_targets(123, 456, "CanRDP")
        
        expected_params = {
            "sourcenode": 123,
            "targetnode": 456,
            "edgetype": "CanRDP"
        }
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/graphs/relay-targets", params=expected_params
        )


class TestADCSClient:
    """Test the ADCSClient class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_base_client = Mock()
        self.adcs_client = ADCSClient(self.mock_base_client)

    def test_get_cert_template_info(self):
        """Test get_cert_template_info"""
        self.mock_base_client.request.return_value = {"data": {"id": "template_123"}}
        
        result = self.adcs_client.get_cert_template_info("template_123")
        
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/certtemplates/template_123"
        )

    def test_get_cert_template_controllers(self):
        """Test get_cert_template_controllers"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.adcs_client.get_cert_template_controllers("template_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/certtemplates/template_123/controllers", params=expected_params
        )

    def test_get_root_ca_info(self):
        """Test get_root_ca_info"""
        self.mock_base_client.request.return_value = {"data": {"id": "rootca_123"}}
        
        result = self.adcs_client.get_root_ca_info("rootca_123")
        
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/rootcas/rootca_123"
        )

    def test_get_root_ca_controllers(self):
        """Test get_root_ca_controllers"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.adcs_client.get_root_ca_controllers("rootca_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/rootcas/rootca_123/controllers", params=expected_params
        )

    def test_get_enterprise_ca_info(self):
        """Test get_enterprise_ca_info"""
        self.mock_base_client.request.return_value = {"data": {"id": "entca_123"}}
        
        result = self.adcs_client.get_enterprise_ca_info("entca_123")
        
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/enterprisecas/entca_123"
        )

    def test_get_enterprise_ca_controllers(self):
        """Test get_enterprise_ca_controllers"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.adcs_client.get_enterprise_ca_controllers("entca_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/enterprisecas/entca_123/controllers", params=expected_params
        )

    def test_get_aia_ca_controllers(self):
        """Test get_aia_ca_controllers"""
        self.mock_base_client.request.return_value = {"data": [], "count": 0}
        
        result = self.adcs_client.get_aia_ca_controllers("aiaca_123")
        
        expected_params = {"limit": 100, "skip": 0, "type": "list"}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/aia-cas/aiaca_123/controllers", params=expected_params
        )


class TestCypherClient:
    """Test the enhanced CypherClient class"""

    def setup_method(self):
        """Set up test fixtures"""
        self.mock_base_client = Mock()
        self.cypher_client = CypherClient(self.mock_base_client)

    @patch('requests.request')
    def test_run_query_success_with_results(self, mock_request):
        """Test run_query with successful 200 response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {"nodes": [{"id": 1, "name": "test"}], "edges": []}
        }
        mock_request.return_value = mock_response
        self.mock_base_client._request = mock_request
        
        result = self.cypher_client.run_query("MATCH (n) RETURN n LIMIT 10", True)
        
        assert result["success"] is True
        assert result["data"]["nodes"][0]["name"] == "test"
        assert result["metadata"]["status"] == "success_with_results"
        assert result["metadata"]["has_results"] is True
        assert result["metadata"]["status_code"] == 200

    @patch('requests.request')
    def test_run_query_success_no_results_404(self, mock_request):
        """Test run_query with 404 response (no results found)"""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_request.return_value = mock_response
        self.mock_base_client._request = mock_request
        
        result = self.cypher_client.run_query("MATCH (n:NonExistent) RETURN n", True)
        
        assert result["success"] is True
        assert result["data"]["nodes"] == []
        assert result["data"]["edges"] == []
        assert result["metadata"]["status"] == "success_no_results"
        assert result["metadata"]["has_results"] is False
        assert result["metadata"]["status_code"] == 404
        assert "Query executed successfully but found no matching data" in result["metadata"]["message"]

    @patch('requests.request')
    def test_run_query_syntax_error_400(self, mock_request):
        """Test run_query with 400 syntax error"""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "Syntax error near 'INVALID'"}
        mock_request.return_value = mock_response
        self.mock_base_client._request = mock_request
        
        with pytest.raises(BloodhoundAPIError) as exc_info:
            self.cypher_client.run_query("INVALID CYPHER QUERY", True)
        
        assert "Cypher query syntax error" in str(exc_info.value)
        assert "Syntax error near 'INVALID'" in str(exc_info.value)
        assert exc_info.value.status_code == 400

    @patch('requests.request')
    def test_run_query_auth_error_401(self, mock_request):
        """Test run_query with 401 authentication error"""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_request.return_value = mock_response
        self.mock_base_client._request = mock_request
        
        with pytest.raises(BloodhoundAPIError) as exc_info:
            self.cypher_client.run_query("MATCH (n) RETURN n", True)
        
        assert "Authentication failed" in str(exc_info.value)
        assert exc_info.value.status_code == 401

    @patch('requests.request')
    def test_run_query_permission_error_403(self, mock_request):
        """Test run_query with 403 permission error"""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_request.return_value = mock_response
        self.mock_base_client._request = mock_request
        
        with pytest.raises(BloodhoundAPIError) as exc_info:
            self.cypher_client.run_query("MATCH (n) RETURN n", True)
        
        assert "Permission denied" in str(exc_info.value)
        assert exc_info.value.status_code == 403

    @patch('requests.request')
    def test_run_query_rate_limit_429(self, mock_request):
        """Test run_query with 429 rate limit error"""
        mock_response = Mock()
        mock_response.status_code = 429
        mock_request.return_value = mock_response
        self.mock_base_client._request = mock_request
        
        with pytest.raises(BloodhoundAPIError) as exc_info:
            self.cypher_client.run_query("MATCH (n) RETURN n", True)
        
        assert "Rate limit exceeded" in str(exc_info.value)
        assert exc_info.value.status_code == 429

    @patch('requests.request')
    def test_run_query_server_error_500(self, mock_request):
        """Test run_query with 500 server error"""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.json.return_value = {"error": "Internal database error"}
        mock_request.return_value = mock_response
        self.mock_base_client._request = mock_request
        
        with pytest.raises(BloodhoundAPIError) as exc_info:
            self.cypher_client.run_query("MATCH (n) RETURN n", True)
        
        assert "BloodHound server error" in str(exc_info.value)
        assert "Internal database error" in str(exc_info.value)
        assert exc_info.value.status_code == 500

    @patch('requests.request')
    def test_run_query_connection_error(self, mock_request):
        """Test run_query with connection error"""
        mock_request.side_effect = requests.exceptions.ConnectionError("Connection failed")
        self.mock_base_client._request = mock_request
        
        with pytest.raises(BloodhoundConnectionError) as exc_info:
            self.cypher_client.run_query("MATCH (n) RETURN n", True)
        
        assert "Failed to connect to BloodHound for Cypher query" in str(exc_info.value)

    @patch('requests.request')
    def test_run_query_timeout_error(self, mock_request):
        """Test run_query with timeout error"""
        mock_request.side_effect = requests.exceptions.Timeout("Request timeout")
        self.mock_base_client._request = mock_request
        
        with pytest.raises(BloodhoundConnectionError) as exc_info:
            self.cypher_client.run_query("MATCH (n) RETURN n", True)
        
        assert "Request timeout during Cypher query" in str(exc_info.value)

    @patch('requests.request')
    def test_run_query_invalid_json_response(self, mock_request):
        """Test run_query with invalid JSON response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_request.return_value = mock_response
        self.mock_base_client._request = mock_request
        
        with pytest.raises(BloodhoundAPIError) as exc_info:
            self.cypher_client.run_query("MATCH (n) RETURN n", True)
        
        assert "Invalid JSON response from Cypher query" in str(exc_info.value)

    @patch('time.sleep')
    @patch('requests.request')
    def test_run_query_with_retry_success_after_failure(self, mock_request, mock_sleep):
        """Test run_query_with_retry succeeds after initial failure"""
        # First call fails with 500, second succeeds
        mock_responses = [
            Mock(status_code=500, json=lambda: {"error": "Temporary error"}),
            Mock(status_code=200, json=lambda: {"data": {"nodes": [], "edges": []}})
        ]
        mock_request.side_effect = mock_responses
        self.mock_base_client._request = mock_request
        
        result = self.cypher_client.run_query_with_retry("MATCH (n) RETURN n", True, max_retries=2)
        
        assert result["success"] is True
        assert mock_request.call_count == 2
        mock_sleep.assert_called_once_with(1)  # Exponential backoff: 2^0 for first retry

    @patch('time.sleep')
    @patch('requests.request')
    def test_run_query_with_retry_rate_limit_handling(self, mock_request, mock_sleep):
        """Test run_query_with_retry handles rate limiting with longer wait"""
        # First call fails with 429, second succeeds
        mock_responses = [
            Mock(status_code=429),
            Mock(status_code=200, json=lambda: {"data": {"nodes": [], "edges": []}})
        ]
        mock_request.side_effect = mock_responses
        self.mock_base_client._request = mock_request
        
        result = self.cypher_client.run_query_with_retry("MATCH (n) RETURN n", True, max_retries=2)
        
        assert result["success"] is True
        assert mock_request.call_count == 2
        mock_sleep.assert_called_once_with(10)  # Minimum 10 seconds for rate limiting

    @patch('requests.request')
    def test_run_query_with_retry_no_retry_on_client_errors(self, mock_request):
        """Test run_query_with_retry doesn't retry client errors (400, 401, 403)"""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {"error": "Bad syntax"}
        mock_request.return_value = mock_response
        self.mock_base_client._request = mock_request
        
        with pytest.raises(BloodhoundAPIError):
            self.cypher_client.run_query_with_retry("BAD QUERY", True, max_retries=3)
        
        # Should only be called once (no retries for client errors)
        assert mock_request.call_count == 1

    def test_validate_query_empty(self):
        """Test validate_query with empty query"""
        result = self.cypher_client.validate_query("")
        
        assert result["valid"] is False
        assert result["checks"]["is_empty"] is True
        assert "Query appears empty" in [w for w in result["warnings"] if w]

    def test_validate_query_valid_simple(self):
        """Test validate_query with valid simple query"""
        result = self.cypher_client.validate_query("MATCH (n) RETURN n")
        
        assert result["valid"] is True
        assert result["checks"]["is_empty"] is False
        assert result["checks"]["has_return"] is True
        assert result["checks"]["has_match"] is True
        assert result["checks"]["estimated_complexity"] == "medium"

    def test_validate_query_high_complexity(self):
        """Test validate_query with high complexity query"""
        result = self.cypher_client.validate_query("MATCH (n) RETURN * COLLECT(n)")
        
        assert result["valid"] is True
        assert result["checks"]["estimated_complexity"] == "high"
        assert "Query may have high complexity" in [w for w in result["warnings"] if w]

    def test_get_saved_query(self):
        """Test get_saved_query method"""
        self.mock_base_client.request.return_value = {"data": {"id": 123, "name": "Test Query"}}
        
        result = self.cypher_client.get_saved_query(123)
        
        self.mock_base_client.request.assert_called_once_with("GET", "/api/v2/saved-queries/123")

    def test_create_saved_query_with_description(self):
        """Test create_saved_query with description parameter"""
        self.mock_base_client.request.return_value = {"data": {"id": 123}}
        
        result = self.cypher_client.create_saved_query(
            "Test Query", 
            "MATCH (n) RETURN n", 
            description="A test query"
        )
        
        expected_data = {
            "name": "Test Query", 
            "query": "MATCH (n) RETURN n",
            "description": "A test query"
        }
        self.mock_base_client.request.assert_called_once_with(
            "POST", "/api/v2/saved-queries", data=expected_data
        )

    def test_update_saved_query_with_description(self):
        """Test update_saved_query with description parameter"""
        self.mock_base_client.request.return_value = {"data": {"id": 123}}
        
        result = self.cypher_client.update_saved_query(
            123, 
            name="Updated Name", 
            query="UPDATED MATCH (n) RETURN n",
            description="Updated description"
        )
        
        expected_data = {
            "name": "Updated Name", 
            "query": "UPDATED MATCH (n) RETURN n",
            "description": "Updated description"
        }
        self.mock_base_client.request.assert_called_once_with(
            "PUT", "/api/v2/saved-queries/123", data=expected_data
        )

    def test_list_saved_queries_basic(self):
        """Test list_saved_queries with basic parameters"""
        self.mock_base_client.request.return_value = {"data": []}
        
        result = self.cypher_client.list_saved_queries()
        
        expected_params = {"skip": 0, "limit": 100}
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/saved-queries", params=expected_params
        )

    def test_list_saved_queries_with_filters(self):
        """Test list_saved_queries with all filters"""
        self.mock_base_client.request.return_value = {"data": []}
        
        result = self.cypher_client.list_saved_queries(
            skip=10,
            limit=50,
            sort_by="name",
            name="test",
            query="MATCH",
            user_id="user123",
            scope="public"
        )
        
        expected_params = {
            "skip": 10,
            "limit": 50,
            "sortby": "name",
            "name": "test",
            "query": "MATCH",
            "userid": "user123",
            "scope": "public"
        }
        self.mock_base_client.request.assert_called_once_with(
            "GET", "/api/v2/saved-queries", params=expected_params
        )

    def test_create_saved_query_basic(self):
        """Test create_saved_query without description"""
        self.mock_base_client.request.return_value = {"data": {"id": 123}}
        
        result = self.cypher_client.create_saved_query("Test Query", "MATCH (n) RETURN n")
        
        expected_data = {"name": "Test Query", "query": "MATCH (n) RETURN n"}
        self.mock_base_client.request.assert_called_once_with(
            "POST", "/api/v2/saved-queries", data=expected_data
        )

    def test_update_saved_query_name_only(self):
        """Test update_saved_query with name only"""
        self.mock_base_client.request.return_value = {"data": {"id": 123}}
        
        result = self.cypher_client.update_saved_query(123, name="New Name")
        
        expected_data = {"name": "New Name"}
        self.mock_base_client.request.assert_called_once_with(
            "PUT", "/api/v2/saved-queries/123", data=expected_data
        )

    def test_update_saved_query_query_only(self):
        """Test update_saved_query with query only"""
        self.mock_base_client.request.return_value = {"data": {"id": 123}}
        
        result = self.cypher_client.update_saved_query(123, query="NEW MATCH (n) RETURN n")
        
        expected_data = {"query": "NEW MATCH (n) RETURN n"}
        self.mock_base_client.request.assert_called_once_with(
            "PUT", "/api/v2/saved-queries/123", data=expected_data
        )

    def test_delete_saved_query(self):
        """Test delete_saved_query"""
        result = self.cypher_client.delete_saved_query(123)
        
        self.mock_base_client.request.assert_called_once_with(
            "DELETE", "/api/v2/saved-queries/123"
        )

    def test_share_saved_query_with_users(self):
        """Test share_saved_query with specific users"""
        self.mock_base_client.request.return_value = {"data": {"success": True}}
        
        result = self.cypher_client.share_saved_query(
            123, 
            user_ids=["user1", "user2"], 
            public=False
        )
        
        expected_data = {"public": False, "userids": ["user1", "user2"]}
        self.mock_base_client.request.assert_called_once_with(
            "PUT", "/api/v2/saved-queries/123/permissions", data=expected_data
        )

    def test_share_saved_query_public(self):
        """Test share_saved_query as public"""
        self.mock_base_client.request.return_value = {"data": {"success": True}}
        
        result = self.cypher_client.share_saved_query(123, public=True)
        
        expected_data = {"public": True}
        self.mock_base_client.request.assert_called_once_with(
            "PUT", "/api/v2/saved-queries/123/permissions", data=expected_data
        )

    def test_delete_saved_query_permissions(self):
        """Test delete_saved_query_permissions"""
        result = self.cypher_client.delete_saved_query_permissions(
            123, 
            ["user1", "user2"]
        )
        
        expected_data = {"userids": ["user1", "user2"]}
        self.mock_base_client.request.assert_called_once_with(
            "DELETE", "/api/v2/saved-queries/123/permissions", data=expected_data
        )


class TestIntegration:
    """Integration tests that test multiple components together"""

    @patch.dict(os.environ, {
        "BLOODHOUND_DOMAIN": "test.bloodhound.local",
        "BLOODHOUND_TOKEN_ID": "test_token_id",
        "BLOODHOUND_TOKEN_KEY": "test_token_key"
    })
    @patch('requests.request')
    def test_full_api_workflow(self, mock_request):
        """Test a complete API workflow"""
        # Mock responses for different API calls
        mock_responses = [
            # Version check
            Mock(status_code=200, json=lambda: {"data": {"version": "4.0.0"}}),
            # Get domains
            Mock(status_code=200, json=lambda: {"data": [{"id": "domain_123", "name": "test.local"}]}),
            # Search for users
            Mock(status_code=200, json=lambda: {"data": [{"id": "user_123", "name": "admin@test.local"}]})
        ]
        
        # Set up mock to return different responses for each call
        mock_request.side_effect = mock_responses
        for response in mock_responses:
            response.raise_for_status.return_value = None
        
        # Create API client
        api = BloodhoundAPI()
        
        # Test connection
        version_info = api.test_connection()
        assert version_info["version"] == "4.0.0"
        
        # Get domains
        domains = api.domains.get_all()
        assert len(domains) == 1
        assert domains[0]["name"] == "test.local"
        
        # Search for objects
        search_results = api.domains.search_objects("admin")
        assert len(search_results["data"]) == 1
        assert search_results["data"][0]["name"] == "admin@test.local"
        
        # Verify all requests were made
        assert mock_request.call_count == 3

    def test_client_inheritance_structure(self):
        """Test that all client classes have the expected structure"""
        base_client = Mock()
        
        # Test that all clients can be instantiated with base_client
        clients = [
            DomainClient(base_client),
            UserClient(base_client),
            GroupClient(base_client),
            ComputerClient(base_client),
            OUsClient(base_client),
            GPOsClient(base_client),
            GraphClient(base_client),
            ADCSClient(base_client),
            CypherClient(base_client)
        ]
        
        # Verify all clients store the base_client reference
        for client in clients:
            assert client.base_client is base_client

    def test_signature_generation_consistency(self):
        """Test that signature generation is consistent and follows the expected pattern"""
        client = BloodhoundBaseClient(
            domain="test.local",
            token_id="test_id",
            token_key="test_key"
        )
        
        # Mock datetime to ensure consistent signatures
        with patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value.astimezone.return_value.isoformat.return_value = "2023-01-01T12:00:00+00:00"
            
            # Test signature for GET request
            method = "GET"
            uri = "/api/v2/test"
            body = None
            
            # Calculate expected signature manually
            digester = hmac.new("test_key".encode(), None, hashlib.sha256)
            digester.update(f"{method}{uri}".encode())
            digester = hmac.new(digester.digest(), None, hashlib.sha256)
            digester.update("2023-01-01T12".encode())
            digester = hmac.new(digester.digest(), None, hashlib.sha256)
            expected_signature = base64.b64encode(digester.digest())
            
            # Mock requests to capture the actual signature
            with patch('requests.request') as mock_request:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_request.return_value = mock_response
                
                client._request(method, uri, body)
                
                # Get the signature from the request headers
                args, kwargs = mock_request.call_args
                actual_signature = kwargs['headers']['Signature']
                
                assert actual_signature == expected_signature