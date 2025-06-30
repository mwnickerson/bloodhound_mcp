# bloodhound_api.py
import base64
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)


class BloodhoundError(Exception):
    """Custom exception for BloodHound API errors"""

    pass


class BloodhoundAuthError(BloodhoundError):
    """Custom exception for BloodHound authentication errors"""

    pass


class BloodhoundConnectionError(BloodhoundError):
    """Custom exception for BloodHound connection errors"""

    pass


class BloodhoundAPIError(BloodhoundError):
    """Custom exception for BloodHound API errors"""

    def __init__(self, message: str, response: requests.Response):
        super().__init__(message)
        self.response = response
        self.status_code = response.status_code if response else None


class BloodhoundBaseClient:
    def __init__(
        self,
        domain: str = None,
        token_id: str = None,
        token_key: str = None,
        port: int = 443,
        scheme: str = "https",
    ):
        """
        Initialize BloodHound API base client

        Args:
            domain: BloodHound Enterprise domain (e.g. xyz.bloodhoundenterprise.io)
            token_id: API token ID
            token_key: API token key
            port: API port (default: 443)
            scheme: URL scheme (default: https)
        """
        # Load from parameters or environment variables
        self.scheme = scheme
        self.domain = domain or os.getenv("BLOODHOUND_DOMAIN")
        self.port = port
        self.token_id = token_id or os.getenv("BLOODHOUND_TOKEN_ID")
        self.token_key = token_key or os.getenv("BLOODHOUND_TOKEN_KEY")

        # Validate required fields
        if not self.domain:
            raise BloodhoundAuthError(
                "BloodHound domain must be provided either directly or via BLOODHOUND_DOMAIN environment variable"
            )
        if not self.token_id:
            raise BloodhoundAuthError(
                "API token ID must be provided either directly or via BLOODHOUND_TOKEN_ID environment variable"
            )
        if not self.token_key:
            raise BloodhoundAuthError(
                "API token key must be provided either directly or via BLOODHOUND_TOKEN_KEY environment variable"
            )

    def _format_url(self, uri: str) -> str:
        """Format the complete URL from the URI path"""
        formatted_uri = uri
        if uri.startswith("/"):
            formatted_uri = formatted_uri[1:]

        return f"{self.scheme}://{self.domain}:{self.port}/{formatted_uri}"

    def _request(
        self, method: str, uri: str, body: Optional[bytes] = None
    ) -> requests.Response:
        """
        Make a signed request to the BloodHound API

        Args:
            method: HTTP method (GET, POST, etc.)
            uri: Request URI
            body: Optional request body

        Returns:
            Response from the API
        """
        # Digester is initialized with HMAC-SHA-256 using the token key as the HMAC digest key
        digester = hmac.new(self.token_key.encode(), None, hashlib.sha256)

        # OperationKey - first link in signature chain (method + URI)
        digester.update(f"{method}{uri}".encode())

        # Update digester for further chaining
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        # DateKey - next link in signature chain (RFC3339 datetime to hour)
        datetime_formatted = datetime.datetime.now().astimezone().isoformat("T")
        digester.update(datetime_formatted[:13].encode())

        # Update digester for further chaining
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        # Body signing - last link in signature chain
        if body is not None:
            digester.update(body)

        # Make the request with signed headers
        try:
            return requests.request(
                method=method,
                url=self._format_url(uri),
                headers={
                    "User-Agent": "bloodhound-api-client 0.1",
                    "Authorization": f"bhesignature {self.token_id}",
                    "RequestDate": datetime_formatted,
                    "Signature": base64.b64encode(digester.digest()),
                    "Content-Type": "application/json",
                },
                data=body,
            )
        except requests.exceptions.ConnectionError as e:
            raise BloodhoundConnectionError(f"Failed to connect to BloodHound API: {e}")

    def request(
        self,
        method: str,
        uri: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Make an API request and return the parsed JSON response

        Args:
            method: HTTP method (GET, POST, etc.)
            uri: Request URI
            params: Optional query parameters
            data: Optional request body data (will be JSON encoded)

        Returns:
            Parsed JSON response
        """
        # Add query parameters if provided
        if params:
            param_strings = []
            for key, value in params.items():
                param_strings.append(f"{key}={value}")
            uri = f"{uri}?{'&'.join(param_strings)}"

        # Prepare request body if provided
        body = None
        if data:
            body = json.dumps(data).encode("utf8")

        # Make the request
        response = self._request(method, uri, body)

        # Handle response
        try:
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            error_msg = f"HTTP Error: {e}"
            try:
                error_data = response.json()
                if "error" in error_data:
                    error_msg = f"{error_msg} - {error_data['error']}"
            except:
                pass
            raise BloodhoundAPIError(error_msg, response=response)
        except json.JSONDecodeError:
            raise BloodhoundAPIError("Invalid JSON response", response=response)


class BloodhoundAPI:
    """
    BloodHound API Client

    Provides access to BloodHound API endpoints through resource-specific clients.
    """

    def __init__(
        self,
        domain: str = None,
        token_id: str = None,
        token_key: str = None,
        port: int = 443,
        scheme: str = "https",
    ):
        """
        Initialize BloodHound API client

        Args:
            domain: BloodHound Enterprise domain (e.g. xyz.bloodhoundenterprise.io)
            token_id: API token ID
            token_key: API token key
            port: API port (default: 443)
            scheme: URL scheme (default: https)

        If domain, token_id, or token_key are not provided, they will be loaded from
        environment variables: BLOODHOUND_DOMAIN, BLOODHOUND_TOKEN_ID, BLOODHOUND_TOKEN_KEY
        """
        # Initialize base client
        self.base_client = BloodhoundBaseClient(
            domain, token_id, token_key, port, scheme
        )

        # Initialize resource clients
        self.domains = DomainClient(self.base_client)
        self.users = UserClient(self.base_client)
        self.groups = GroupClient(self.base_client)
        self.computers = ComputerClient(self.base_client)
        self.ous = OUsClient(self.base_client)
        self.gpos = GPOsClient(self.base_client)
        self.graph = GraphClient(self.base_client)
        self.adcs = ADCSClient(self.base_client)
        self.cypher = CypherClient(self.base_client)

    def test_connection(self) -> Dict[str, Any]:
        """
        Test connection to the BloodHound API

        Returns:
            API version information
        """
        try:
            response = self.base_client.request("GET", "/api/version")
            return response["data"]
        except Exception as e:
            print(f"Connection test failed: {e}")
            return None

    def get_self_info(self) -> Dict[str, Any]:
        """
        Get information about the authenticated user

        Returns:
            User information dictionary
        """
        try:
            return self.base_client.request("GET", "/api/v2/self")
        except Exception as e:
            print(f"Failed to get user info: {e}")
            return None


class DomainClient:
    """Client for domain-related BloodHound API endpoints"""

    def __init__(self, base_client: BloodhoundBaseClient):
        self.base_client = base_client

    def get_all(self) -> List[Dict[str, Any]]:
        """
        Get all domains in the Bloodhound CE Instance

        Returns:
            List of domain information dictionaries
        """
        response = self.base_client.request("GET", "/api/v2/available-domains")
        return response["data"]

    def search_objects(
        self, query: str, type: str = None, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Search for objects by name, Object ID. They can also be filtered by type.
        Args:
            query: search parameter for the name or object ID of the node (required)
            type: type of object to search for (optional)
                - For AD: Base, User, Computer, Group, Container, GPO, OU, Cert template, Trust
                - For Azure: AZBase, AZbase, AZDevice
            skip: Number of results to skip for pagination (default: 0) (optional)
            limit: Maximum number of results to return (default: 100) (optional)

            Returns:
                Dictionary with information on the object found. The information includes:
                - objectid: Object ID
                - type: the type of the object
                - name: Name of the object
                - distinguishedname : Distinguished Name of the object
                - system_tags: System tags associated with the object
        """
        params = {
            "q": query,  # Changed from "query" to "q" to match the API
            "limit": limit,
            "skip": skip,
        }

        # Only add the type parameter if it's provided
        if type:
            params["type"] = type

        return self.base_client.request("GET", "/api/v2/search", params=params)

    def get_users(
        self, domain_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get users in a specific domain

        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of users to return
            skip: Number of users to skip for pagination

        Returns:
            Dictionary with data (list of users) and count (total number of users)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/domains/{domain_id}/users", params=params
        )

    def get_groups(
        self, domain_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get groups in a specific domain

        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of groups to return
            skip: Number of groups to skip for pagination

        Returns:
            Dictionary with data (list of groups) and count (total number of groups)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/domains/{domain_id}/groups", params=params
        )

    def get_computers(
        self, domain_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get computers in a specific domain

        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of computers to return
            skip: Number of computers to skip for pagination

        Returns:
            Dictionary with data (list of computers) and count (total number of computers)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/domains/{domain_id}/computers", params=params
        )

    def get_controllers(
        self, domain_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get controllers in a specific domain

        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of controllers to return
            skip: Number of controllers to skip for pagination

        Returns:
            Dictionary with data (list of controllers) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/domains/{domain_id}/controllers", params=params
        )

    def get_gpos(
        self, domain_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get Group Policy Objects (GPOs) in a specific domain

        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of GPOs to return
            skip: Number of GPOs to skip for pagination

        Returns:
            Dictionary with data (list of GPOs) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/domains/{domain_id}/gpos", params=params
        )

    def get_ous(
        self, domain_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get Organizational Units (OUs) in a specific domain

        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of OUs to return
            skip: Number of OUs to skip for pagination

        Returns:
            Dictionary with data (list of OUs) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/domains/{domain_id}/ous", params=params
        )

    def get_dc_syncers(
        self, domain_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get DC Syncers in a specific domain

        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of DC Syncers to return
            skip: Number of DC Syncers to skip for pagination

        Returns:
            Dictionary with data (list of DC Syncers) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/domains/{domain_id}/dc-syncers", params=params
        )

    def get_foreign_admins(
        self, domain_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get foreign admins in a specific domain

        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of foreign admins to return
            skip: Number of foreign admins to skip for pagination

        Returns:
            Dictionary with data (list of foreign admins) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/domains/{domain_id}/foreign-admins", params=params
        )

    def get_foreign_gpo_controllers(
        self, domain_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get foreign GPO controllers in a specific domain

        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of foreign GPO controllers to return
            skip: Number of foreign GPO controllers to skip for pagination

        Returns:
            Dictionary with data (list of foreign GPO controllers) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/domains/{domain_id}/foreign-gpo-controllers", params=params
        )

    def get_foreign_groups(
        self, domain_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get foreign groups in a specific domain

        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of foreign groups to return
            skip: Number of foreign groups to skip for pagination

        Returns:
            Dictionary with data (list of foreign groups) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/domains/{domain_id}/foreign-groups", params=params
        )

    def get_foreign_users(
        self, domain_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get foreign users in a specific domain

        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of foreign users to return
            skip: Number of foreign users to skip for pagination

        Returns:
            Dictionary with data (list of foreign users) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/domains/{domain_id}/foreign-users", params=params
        )

    def get_inbound_trusts(
        self, domain_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get inbound trusts in a specific domain

        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of inbound trusts to return
            skip: Number of inbound trusts to skip for pagination

        Returns:
            Dictionary with data (list of inbound trusts) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/domains/{domain_id}/inbound-trusts", params=params
        )

    def get_outbound_trusts(
        self, domain_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get outbound trusts in a specific domain

        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of outbound trusts to return
            skip: Number of outbound trusts to skip for pagination

        Returns:
            Dictionary with data (list of outbound trusts) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/domains/{domain_id}/outbound-trusts", params=params
        )


class UserClient:
    """Client for user-related BloodHound API endpoints"""

    def __init__(self, base_client: BloodhoundBaseClient):
        self.base_client = base_client

    def get_info(self, user_id: str) -> Dict[str, Any]:
        """
        Get information about a specific user

        Args:
            user_id: The ID of the user to query

        Returns:
            User information dictionary
        """
        params = {"counts": "true"}
        return self.base_client.request(
            "GET", f"/api/v2/users/{user_id}", params=params
        )

    def get_admin_rights(
        self, user_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get administrative rights of a specific user

        Args:
            user_id: The ID of the user to query
            limit: Maximum number of rights to return
            skip: Number of rights to skip for pagination

        Returns:
            Dictionary with data (list of rights) and count (total number of rights)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/users/{user_id}/admin-rights", params=params
        )

    def get_constrained_delegation_rights(
        self, user_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get constrained delegation rights of a specific user

        Args:
            user_id: The ID of the user to query
            limit: Maximum number of constrained delegation rights to return
            skip: Number of constrained delegation rights to skip for pagination

        Returns:
            Dictionary with data (list of rights) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET",
            f"/api/v2/users/{user_id}/constrained-delegation-rights",
            params=params,
        )

    def get_controllables(
        self, user_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get controllable objects for a specific user

        Args:
            user_id: The ID of the user to query
            limit: Maximum number of controllables to return
            skip: Number of controllables to skip for pagination

        Returns:
            Dictionary with data (list of controllables) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/users/{user_id}/controllables", params=params
        )

    def get_controllers(
        self, user_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get controllers of a specific user

        Args:
            user_id: The ID of the user to query
            limit: Maximum number of controllers to return
            skip: Number of controllers to skip for pagination

        Returns:
            Dictionary with data (list of controllers) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/users/{user_id}/controllers", params=params
        )

    def get_dcom_rights(
        self, user_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get DCOM rights of a specific user

        Args:
            user_id: The ID of the user to query
            limit: Maximum number of DCOM rights to return
            skip: Number of DCOM rights to skip for pagination

        Returns:
            Dictionary with data (list of DCOM rights) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/users/{user_id}/dcom-rights", params=params
        )

    def get_memberships(
        self, user_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get group memberships of a specific user

        Args:
            user_id: The ID of the user to query
            limit: Maximum number of memberships to return
            skip: Number of memberships to skip for pagination

        Returns:
            Dictionary with data (list of memberships) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/users/{user_id}/memberships", params=params
        )

    def get_ps_remote_rights(
        self, user_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get PowerShell Remote rights of a specific user

        Args:
            user_id: The ID of the user to query
            limit: Maximum number of PS Remote rights to return
            skip: Number of PS Remote rights to skip for pagination

        Returns:
            Dictionary with data (list of PS Remote rights) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/users/{user_id}/ps-remote-rights", params=params
        )

    def get_rdp_rights(
        self, user_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get RDP rights of a specific user

        Args:
            user_id: The ID of the user to query
            limit: Maximum number of RDP rights to return
            skip: Number of RDP rights to skip for pagination

        Returns:
            Dictionary with data (list of RDP rights) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/users/{user_id}/rdp-rights", params=params
        )

    def get_sessions(
        self, user_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get active sessions of a specific user

        Args:
            user_id: The ID of the user to query
            limit: Maximum number of sessions to return
            skip: Number of sessions to skip for pagination

        Returns:
            Dictionary with data (list of sessions) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/users/{user_id}/sessions", params=params
        )

    def get_sql_admin_rights(
        self, user_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get SQL admin rights of a specific user

        Args:
            user_id: The ID of the user to query
            limit: Maximum number of SQL admin rights to return
            skip: Number of SQL admin rights to skip for pagination

        Returns:
            Dictionary with data (list of SQL admin rights) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/users/{user_id}/sql-admin-rights", params=params
        )


class GroupClient:
    """Client for group-related BloodHound API endpoints"""

    def __init__(self, base_client: BloodhoundBaseClient):
        self.base_client = base_client

    def get_info(self, group_id: str) -> Dict[str, Any]:
        """
        Get information about a specific group

        Args:
            group_id: The ID of the group to query

        Returns:
            Group information dictionary
        """
        params = {"counts": "true"}
        return self.base_client.request(
            "GET", f"/api/v2/groups/{group_id}", params=params
        )

    def get_admin_rights(
        self, group_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get administrative rights of a specific group

        Args:
            group_id: The ID of the group to query
            limit: Maximum number of rights to return
            skip: Number of rights to skip for pagination

        Returns:
            Dictionary with data (list of rights) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/groups/{group_id}/admin-rights", params=params
        )

    def get_controllables(
        self, group_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get controllable objects for a specific group

        Args:
            group_id: The ID of the group to query
            limit: Maximum number of controllables to return
            skip: Number of controllables to skip for pagination

        Returns:
            Dictionary with data (list of controllables) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/groups/{group_id}/controllables", params=params
        )

    def get_controllers(
        self, group_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get controllers of a specific group

        Args:
            group_id: The ID of the group to query
            limit: Maximum number of controllers to return
            skip: Number of controllers to skip for pagination

        Returns:
            Dictionary with data (list of controllers) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/groups/{group_id}/controllers", params=params
        )

    def get_dcom_rights(
        self, group_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get DCOM rights of a specific group

        Args:
            group_id: The ID of the group to query
            limit: Maximum number of DCOM rights to return
            skip: Number of DCOM rights to skip for pagination

        Returns:
            Dictionary with data (list of DCOM rights) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/groups/{group_id}/dcom-rights", params=params
        )

    def get_members(
        self, group_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get members of a specific group

        Args:
            group_id: The ID of the group to query
            limit: Maximum number of members to return
            skip: Number of members to skip for pagination

        Returns:
            Dictionary with data (list of members) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/groups/{group_id}/members", params=params
        )

    def get_memberships(
        self, group_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get group memberships of a specific group

        Args:
            group_id: The ID of the group to query
            limit: Maximum number of memberships to return
            skip: Number of memberships to skip for pagination

        Returns:
            Dictionary with data (list of memberships) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/groups/{group_id}/memberships", params=params
        )

    def get_ps_remote_rights(
        self, group_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get PowerShell Remote rights of a specific group

        Args:
            group_id: The ID of the group to query
            limit: Maximum number of PS Remote rights to return
            skip: Number of PS Remote rights to skip for pagination

        Returns:
            Dictionary with data (list of PS Remote rights) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/groups/{group_id}/ps-remote-rights", params=params
        )

    def get_rdp_rights(
        self, group_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get RDP rights of a specific group
        Args:
            group_id: The ID of the group to query
            limit: Maximum number of RDP rights to return
            skip: Number of RDP rights to skip for pagination
        Returns:
            Dictionary with data (list of RDP rights) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/groups/{group_id}/rdp-rights", params=params
        )

    def get_sessions(
        self, group_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get active sessions of a specific group

        Args:
            group_id: The ID of the group to query
            limit: Maximum number of sessions to return
            skip: Number of sessions to skip for pagination

        Returns:
            Dictionary with data (list of sessions) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/groups/{group_id}/sessions", params=params
        )


class ComputerClient:
    """Client for computer-related BloodHound API endpoints"""

    def __init__(self, base_client: BloodhoundBaseClient):
        self.base_client = base_client

    def get_info(self, computer_id: str) -> Dict[str, Any]:
        """
        Get information about a specific computer

        Args:
            computer_id: The ID of the computer to query

        Returns:
            Computer information dictionary
        """
        params = {"counts": "true"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}", params=params
        )

    def get_admin_rights(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get administrative rights of a specific computer

        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of rights to return
            skip: Number of rights to skip for pagination

        Returns:
            Dictionary with data (list of rights) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}/admin-rights", params=params
        )

    def get_admin_users(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get administrative users of a specific computer

        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of users to return
            skip: Number of users to skip for pagination

        Returns:
            Dictionary with data (list of users) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}/admin-users", params=params
        )

    def get_constrained_delegation_rights(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the principals that this computer has constrained delegations rights to.
        This is a list of the computers that this computer can impersonate.

        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of rights to return
            skip: Number of rights to skip for pagination

        Returns:
            Dictionary with data (list of rights) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET",
            f"/api/v2/computers/{computer_id}/constrained-delegation-rights",
            params=params,
        )

    def get_constrained_users(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the principals that have constrained delegation rights to this computer

        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of users to return
            skip: Number of users to skip for pagination

        Returns:
            Dictionary with data (list of users) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}/constrained-users", params=params
        )

    def get_controllables(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the principals this computer can control.


        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of controllables to return
            skip: Number of controllables to skip for pagination

        Returns:
            Dictionary with data (list of controllables) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}/controllables", params=params
        )

    def get_controllers(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the principals that can control this computer

        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of controllers to return
            skip: Number of controllers to skip for pagination

        Returns:
            Dictionary with data (list of controllers) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}/controllers", params=params
        )

    def get_dcom_rights(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the systems this computer can execute DCOM on.
        This is a list of the computers that this computer can impersonate.

        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of DCOM rights to return
            skip: Number of DCOM rights to skip for pagination

        Returns:
            Dictionary with data (list of DCOM rights) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}/dcom-rights", params=params
        )

    def get_dcom_users(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the users that have DCOM rights to this computer

        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of users to return
            skip: Number of users to skip for pagination

        Returns:
            Dictionary with data (list of users) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}/dcom-users", params=params
        )

    def get_group_membership(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the groups this computer is a member of

        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of memberships to return
            skip: Number of memberships to skip for pagination

        Returns:
            Dictionary with data (list of memberships) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}/group-membership", params=params
        )

    def get_ps_remote_rights(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the systems this computer has remote PowerShell rights on.


        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of PS Remote rights to return
            skip: Number of PS Remote rights to skip for pagination

        Returns:
            Dictionary with data (list of PS Remote rights) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}/ps-remote-rights", params=params
        )

    def get_ps_remote_users(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the users that have remote PowerShell rights to this computer

        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of users to return
            skip: Number of users to skip for pagination

        Returns:
            Dictionary with data (list of users) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}/ps-remote-users", params=params
        )

    def get_rdp_rights(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the systems this computer has RDP rights on.

        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of RDP rights to return
            skip: Number of RDP rights to skip for pagination
        Returns:
            Dictionary with data (list of RDP rights) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}/rdp-rights", params=params
        )

    def get_rdp_users(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the users that have RDP rights to this computer

        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of users to return
            skip: Number of users to skip for pagination

        Returns:
            Dictionary with data (list of users) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}/rdp-users", params=params
        )

    def get_sessions(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the principals with active sessions on this computer.

        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of sessions to return
            skip: Number of sessions to skip for pagination

        Returns:
            Dictionary with data (list of sessions) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}/sessions", params=params
        )

    def get_sql_admins(
        self, computer_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the SQL administrators on this computer

        Args:
            computer_id: The ID of the computer to query
            limit: Maximum number of SQL admins to return
            skip: Number of SQL admins to skip for pagination

        Returns:
            Dictionary with data (list of SQL admins) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/computers/{computer_id}/sql-admins", params=params
        )


class OUsClient:
    """Client for OU related BloodHound API endpoints"""

    def __init__(self, base_client: BloodhoundBaseClient):
        self.base_client = base_client

    def get_info(self, ou_id: str) -> Dict[str, Any]:
        """
        Get information about a specific OU
        Args:
            ou_id: The ID of the OU to query
        Returns:
            OU information dictionary
        """
        params = {"counts": "true"}
        return self.base_client.request("GET", f"/api/v2/ous/{ou_id}", params=params)

    def get_computers(
        self, ou_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the computers contained by this OU.

        Args:
            ou_id: The ID of the OU to query
            limit: Maximum number of computers to return
            skip: Number of computers to skip for pagination

        Returns:
            Dictionary with data (list of computers) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/ous/{ou_id}/computers", params=params
        )

    def get_gpos(self, ou_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the GPOs that affect this OU.


        Args:
            ou_id: The ID of the OU to query
            limit: Maximum number of GPOs to return
            skip: Number of GPOs to skip for pagination

        Returns:
            Dictionary with data (list of GPOs) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/ous/{ou_id}/gpos", params=params
        )

    def get_groups(self, ou_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the groups contained by this OU.

        Args:
            ou_id: The ID of the OU to query
            limit: Maximum number of groups to return
            skip: Number of groups to skip for pagination

        Returns:
            Dictionary with data (list of groups) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/ous/{ou_id}/groups", params=params
        )

    def get_users(self, ou_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the users contained by this OU.

        Args:
            ou_id: The ID of the OU to query
            limit: Maximum number of users to return
            skip: Number of users to skip for pagination

        Returns:
            Dictionary with data (list of users) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/ous/{ou_id}/users", params=params
        )


class GPOsClient:
    """Client for GPO related Bloodhound API Endpoints"""

    def __init__(self, base_client: BloodhoundBaseClient):
        self.base_client = base_client

    def get_info(self, gpo_id: str) -> Dict[str, Any]:
        """
        Get information about a specific GPO

        Args:
            gpo_id: The ID of the GPO to query

        Returns:
            GPO information dictionary
        """
        params = {"counts": "true"}
        return self.base_client.request("GET", f"/api/v2/gpos/{gpo_id}", params=params)

    def get_computer(
        self, gpo_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the computers that this GPO applies to.

        Args:
            gpo_id: The ID of the GPO to query
            limit: Maximum number of computers to return
            skip: Number of computers to skip for pagination

        Returns:
            Dictionary with data (list of computers) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/gpos/{gpo_id}/computers", params=params
        )

    def get_controllers(
        self, gpo_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the Security Principals that can control this GPO.

        Args:
            gpo_id: The ID of the GPO to query
            limit: the maximum number of controller security principals to return (default is 100)
            skip: Number of controller security principals to skip for pagination (Default is 0)

        Returns:
            Dictionary with data (list of controllers) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/gpos/{gpo_id}/controllers", params=params
        )

    def get_ous(self, gpo_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the OUs that this GPO applies to.

        Args:
            gpo_id: The ID of the GPO to query
            limit: Maximum number of OUs to return
            skip: Number of OUs to skip for pagination

        Returns:
            Dictionary with data (list of OUs) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/gpos/{gpo_id}/ous", params=params
        )

    def get_tier_zeros(
        self, gpo_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the Tier zero security principals that this GPO applies to.

        Args:
            gpo_id: The ID of the GPO to query
            limit: Maximum number of Tier 0s to return
            skip: Number of Tier 0s to skip for pagination

        Returns:
            Dictionary with data (list of Tier 0s) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/gpos/{gpo_id}/tier-zeros", params=params
        )

    def get_users(self, gpo_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get a list, graph, or count of the users that this GPO applies to.

        Args:
            gpo_id: The ID of the GPO to query
            limit: Maximum number of users to return
            skip: Number of users to skip for pagination

        Returns:
            Dictionary with data (list of users) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/gpos/{gpo_id}/users", params=params
        )


class GraphClient:
    """Client for Graph related Bloodhound API Endpoints"""

    def __init__(self, base_client: BloodhoundBaseClient):
        self.base_client = base_client

    # I am getting a 401 error when searching for some objects and it works on others
    # for example if i search for Domain Admins it fails with a 401 error but if i search for TargetUserB it works fine
    def search(self, query: str, search_type: str = "fuzzy") -> Dict[str, Any]:
        """
        Search for nodes in the graph by name

        Args:
            query: Search query text
            search_type: Type of search strategy ('fuzzy' or 'exact')

        Returns:
            Search results
        """
        params = {"query": query, "type": search_type}
        return self.base_client.request("GET", "/api/v2/graph-search", params=params)

    def get_shortest_path(
        self, start_node: str, end_node: str, relationship_kinds: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get the shortest path between two nodes in the graph

        Args:
            start_node: The object ID of the starting node
            end_node: The object ID of the ending node
            relationship_kinds: Optional filter for relationship types

        Returns:
            Graph data of the shortest path
        """
        params = {"start_node": start_node, "end_node": end_node}

        if relationship_kinds:
            params["relationshipkinds"] = relationship_kinds

        return self.base_client.request(
            "GET", "/api/v2/graphs/shortest-path", params=params
        )

    def get_edge_composition(
        self, source_node: int, target_node: int, edge_type: str
    ) -> Dict[str, Any]:
        """
        Get the composition of a complex edge between two nodes

        Args:
            source_node: ID of the source node
            target_node: ID of the target node
            edge_type: Type of edge to analyze

        Returns:
            Graph data showing the composition of the edge
        """
        params = {
            "sourcenode": source_node,
            "targetnode": target_node,
            "edgetype": edge_type,
        }

        return self.base_client.request(
            "GET", "/api/v2/graphs/edge-composition", params=params
        )

    def get_relay_targets(
        self, source_node: int, target_node: int, edge_type: str
    ) -> Dict[str, Any]:
        """
        Get nodes that are valid relay targets for a given edge

        Args:
            source_node: ID of the source node
            target_node: ID of the target node
            edge_type: Type of edge

        Returns:
            Graph data with valid relay targets
        """
        params = {
            "sourcenode": source_node,
            "targetnode": target_node,
            "edgetype": edge_type,
        }

        return self.base_client.request(
            "GET", "/api/v2/graphs/relay-targets", params=params
        )


class ADCSClient:
    """Client for ADCS-related Bloodhound API endpoints"""

    def __init__(self, base_client: BloodhoundBaseClient):
        self.base_client = base_client

    # Certificate Templates methods
    def get_cert_template_info(self, template_id: str) -> Dict[str, Any]:
        """
        Get information about a specific Certificate Template

        Args:
            template_id: The ID of the Certificate Template to query

        Returns:
            Certificate Template information dictionary
        """
        return self.base_client.request("GET", f"/api/v2/certtemplates/{template_id}")

    def get_cert_template_controllers(
        self, template_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get controllers of a specific Certificate Template

        Args:
            template_id: The ID of the Certificate Template to query
            limit: Maximum number of controllers to return
            skip: Number of controllers to skip for pagination

        Returns:
            Dictionary with data (list of controllers) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/certtemplates/{template_id}/controllers", params=params
        )

    # Root Certificate Authorities methods
    def get_root_ca_info(self, ca_id: str) -> Dict[str, Any]:
        """
        Get information about a specific Root Certificate Authority

        Args:
            ca_id: The ID of the Root CA to query

        Returns:
            Root CA information dictionary
        """
        return self.base_client.request("GET", f"/api/v2/rootcas/{ca_id}")

    def get_root_ca_controllers(
        self, ca_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get controllers of a specific Root Certificate Authority

        Args:
            ca_id: The ID of the Root CA to query
            limit: Maximum number of controllers to return
            skip: Number of controllers to skip for pagination

        Returns:
            Dictionary with data (list of controllers) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/rootcas/{ca_id}/controllers", params=params
        )

    # Enterprise Certificate Authorities methods
    def get_enterprise_ca_info(self, ca_id: str) -> Dict[str, Any]:
        """
        Get information about a specific Enterprise Certificate Authority

        Args:
            ca_id: The ID of the Enterprise CA to query

        Returns:
            Enterprise CA information dictionary
        """
        return self.base_client.request("GET", f"/api/v2/enterprisecas/{ca_id}")

    def get_enterprise_ca_controllers(
        self, ca_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get controllers of a specific Enterprise Certificate Authority

        Args:
            ca_id: The ID of the Enterprise CA to query
            limit: Maximum number of controllers to return
            skip: Number of controllers to skip for pagination

        Returns:
            Dictionary with data (list of controllers) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/enterprisecas/{ca_id}/controllers", params=params
        )

    # AIA Certificate Authorities methods
    def get_aia_ca_controllers(
        self, ca_id: str, limit: int = 100, skip: int = 0
    ) -> Dict[str, Any]:
        """
        Get controllers of a specific AIA Certificate Authority

        Args:
            ca_id: The ID of the AIA CA to query
            limit: Maximum number of controllers to return
            skip: Number of controllers to skip for pagination

        Returns:
            Dictionary with data (list of controllers) and count (total number)
        """
        params = {"limit": limit, "skip": skip, "type": "list"}
        return self.base_client.request(
            "GET", f"/api/v2/aia-cas/{ca_id}/controllers", params=params
        )

class CypherClient:
    """Client for Cypher query related BloodHound API endpoints"""

    def __init__(self, base_client: BloodhoundBaseClient):
        self.base_client = base_client

    def run_query(self, query: str, include_properties: bool = True) -> Dict[str, Any]:
        """
        Run a custom Cypher query directly against the database

        Args:
            query: The Cypher query to execute
            include_properties: Whether to include node/edge properties in response

        Returns:
            Dictionary with graph data (nodes and edges) and metadata about the query result

        Raises:
            BloodhoundAPIError: For authentication, server errors, or malformed queries
            BloodhoundConnectionError: For network connectivity issues
            
        Note: 404 responses are treated as successful queries with no results, not errors
        """
        data = {"query": query, "includeproperties": include_properties}
        
        try:
            response = self.base_client._request("POST", "/api/v2/graphs/cypher", 
                                               json.dumps(data).encode("utf8"))
            
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    return {
                        "success": True,
                        "data": json_data.get("data", {}),
                        "metadata": {
                            "status": "success_with_results",
                            "query": query,
                            "has_results": True,
                            "status_code": 200
                        }
                    }
                except json.JSONDecodeError:
                    raise BloodhoundAPIError("Invalid JSON response from Cypher query", response=response)
            
            elif response.status_code == 404:
                return {
                    "success": True,
                    "data": {"nodes": [], "edges": []},
                    "metadata": {
                        "status": "success_no_results", 
                        "query": query,
                        "has_results": False,
                        "status_code": 404,
                        "message": "Query executed successfully but found no matching data"
                    }
                }
            
            elif response.status_code == 400:
                try:
                    error_data = response.json()
                    error_detail = error_data.get("error", "Unknown syntax error")
                except json.JSONDecodeError:
                    error_detail = "Malformed Cypher query"
                
                raise BloodhoundAPIError(
                    f"Cypher query syntax error: {error_detail}", 
                    response=response
                )
            
            elif response.status_code == 401:
                raise BloodhoundAPIError(
                    "Authentication failed - check your BloodHound API credentials", 
                    response=response
                )
            
            elif response.status_code == 403:
                raise BloodhoundAPIError(
                    "Permission denied - insufficient privileges for Cypher queries", 
                    response=response
                )
            
            elif response.status_code == 429:
                raise BloodhoundAPIError(
                    "Rate limit exceeded - too many requests. Please wait before retrying.", 
                    response=response
                )
            
            elif response.status_code >= 500:
                try:
                    error_data = response.json()
                    error_detail = error_data.get("error", "Unknown server error")
                except json.JSONDecodeError:
                    error_detail = f"HTTP {response.status_code}"
                
                raise BloodhoundAPIError(
                    f"BloodHound server error: {error_detail}", 
                    response=response
                )
            
            else:
                raise BloodhoundAPIError(
                    f"Unexpected response status: {response.status_code}", 
                    response=response
                )
                
        except requests.exceptions.ConnectionError as e:
            raise BloodhoundConnectionError(f"Failed to connect to BloodHound for Cypher query: {e}")
        except requests.exceptions.Timeout as e:
            raise BloodhoundConnectionError(f"Request timeout during Cypher query: {e}")
        except requests.exceptions.RequestException as e:
            raise BloodhoundConnectionError(f"Network error during Cypher query: {e}")

    def run_query_with_retry(self, query: str, include_properties: bool = True, max_retries: int = 3) -> Dict[str, Any]:
        """
        Run a Cypher query with automatic retry logic for transient failures
        
        Args:
            query: The Cypher query to execute
            include_properties: Whether to include node/edge properties
            max_retries: Maximum number of retry attempts
            
        Returns:
            Query result dictionary
            
        Raises:
            BloodhoundAPIError: For non-retryable errors (syntax, auth, permissions)
            BloodhoundConnectionError: For persistent connection issues
        """
        import time
        
        last_exception = None
        
        for attempt in range(max_retries + 1):
            try:
                return self.run_query(query, include_properties)
            
            except BloodhoundConnectionError as e:
                last_exception = e
                if attempt < max_retries:
                    wait_time = 2 ** attempt  # Exponential backoff: 2, 4, 8 seconds
                    time.sleep(wait_time)
                    continue
                else:
                    raise
            
            except BloodhoundAPIError as e:
                # Don't retry client errors (4xx) except rate limiting
                if e.status_code in [400, 401, 403]:
                    raise
                
                # Retry rate limiting and server errors
                last_exception = e
                if attempt < max_retries and (e.status_code == 429 or e.status_code >= 500):
                    wait_time = 2 ** attempt
                    if e.status_code == 429:
                        wait_time = max(wait_time, 10)  # Minimum 10 seconds for rate limiting
                    time.sleep(wait_time)
                    continue
                else:
                    raise
        
        raise last_exception

    def validate_query(self, query: str) -> Dict[str, Any]:
        """
        Validate a Cypher query without executing it
        
        Args:
            query: The Cypher query to validate
            
        Returns:
            Dictionary with validation results
        """
        basic_checks = {
            "is_empty": not query.strip(),
            "has_return": "RETURN" in query.upper(),
            "has_match": "MATCH" in query.upper(),
            "estimated_complexity": "high" if any(keyword in query.upper() for keyword in ["*", "ALL", "COLLECT"]) else "medium"
        }
        
        return {
            "valid": not basic_checks["is_empty"],
            "checks": basic_checks,
            "warnings": [
                "Query appears empty" if basic_checks["is_empty"] else None,
                "Query may have high complexity" if basic_checks["estimated_complexity"] == "high" else None
            ]
        }

    def list_saved_queries(self, skip: int = 0, limit: int = 100, sort_by: str = None, 
                          name: str = None, query: str = None, user_id: str = None, 
                          scope: str = None) -> Dict[str, Any]:
        """
        List saved Cypher queries with optional filtering
        
        Args:
            skip: Number of results to skip for pagination
            limit: Maximum number of results to return
            sort_by: Field to sort by
            name: Filter by query name
            query: Filter by query content
            user_id: Filter by user ID
            scope: Filter by scope
            
        Returns:
            Dictionary with saved queries list and metadata
        """
        params = {"skip": skip, "limit": limit}
        
        if sort_by:
            params["sortby"] = sort_by
        if name:
            params["name"] = name
        if query:
            params["query"] = query
        if user_id:
            params["userid"] = user_id
        if scope:
            params["scope"] = scope

        return self.base_client.request("GET", "/api/v2/saved-queries", params=params)

    def get_saved_query(self, query_id: int) -> Dict[str, Any]:
        """
        Get a specific saved query by ID
        
        Args:
            query_id: ID of the saved query
            
        Returns:
            Dictionary with saved query details
        """
        return self.base_client.request("GET", f"/api/v2/saved-queries/{query_id}")

    def create_saved_query(self, name: str, query: str, description: str = None) -> Dict[str, Any]:
        """
        Create a new saved Cypher query
        
        Args:
            name: Name for the saved query
            query: The Cypher query to save
            description: Optional description
            
        Returns:
            Dictionary with created saved query
        """
        data = {"name": name, "query": query}
        if description:
            data["description"] = description
        return self.base_client.request("POST", "/api/v2/saved-queries", data=data)

    def update_saved_query(
        self, query_id: int, name: str = None, query: str = None, description: str = None
    ) -> Dict[str, Any]:
        """
        Update an existing saved query

        Args:
            query_id: ID of the saved query to update
            name: New name for the query (optional)
            query: New query string (optional)
            description: New description (optional)

        Returns:
            Dictionary with the updated saved query
        """
        data = {}
        if name:
            data["name"] = name
        if query:
            data["query"] = query
        if description:
            data["description"] = description

        return self.base_client.request(
            "PUT", f"/api/v2/saved-queries/{query_id}", data=data
        )

    def delete_saved_query(self, query_id: int) -> None:
        """
        Delete a saved query

        Args:
            query_id: ID of the saved query to delete
        """
        self.base_client.request("DELETE", f"/api/v2/saved-queries/{query_id}")

    def share_saved_query(
        self, query_id: int, user_ids: List[str] = None, public: bool = False
    ) -> Dict[str, Any]:
        """
        Share a saved query with users or make it public

        Args:
            query_id: ID of the saved query to share
            user_ids: List of user IDs to share with
            public: Whether to make the query public

        Returns:
            Dictionary with sharing information
        """
        data = {"public": public}
        if user_ids:
            data["userids"] = user_ids

        return self.base_client.request(
            "PUT", f"/api/v2/saved-queries/{query_id}/permissions", data=data
        )

    def delete_saved_query_permissions(
        self, query_id: int, user_ids: List[str]
    ) -> None:
        """
        Revoke saved query permissions from users

        Args:
            query_id: ID of the saved query
            user_ids: List of user IDs to revoke access from
        """
        data = {"userids": user_ids}
        self.base_client.request(
            "DELETE", f"/api/v2/saved-queries/{query_id}/permissions", data=data
        )
