# bloodhound_api.py
import hmac
import hashlib
import base64
import requests
import datetime
import json
import os
from typing import Optional, Dict, List, Any
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from .env file
env_path = (Path(__file__).resolve().parent.parent / ".env")
load_dotenv(dotenv_path=env_path)

class BlooodhoundError(Exception):
    """Custom exception for BloodHound API errors"""
    pass

class BloodhoundAuthError(BlooodhoundError):
    """Custom exception for BloodHound authentication errors"""
    pass

class BloodhoundConnectionError(BlooodhoundError):
    """Custom exception for BloodHound connection errors"""
    pass

class BloodhoundAPIError(BlooodhoundError):
    """Custom exception for BloodHound API errors"""
    def __init__(self, message: str, response: requests.Response):
        super().__init__(message)
        self.response = response
        self.status_code = response.status_code if response else None

class BloodhoundBaseClient:
    def __init__(self, domain: str = None, token_id: str = None, token_key: str = None, 
                 port: int = 443, scheme: str = "https"):
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
            raise BloodhoundAuthError("BloodHound domain must be provided either directly or via BLOODHOUND_DOMAIN environment variable")
        if not self.token_id:
            raise BloodhoundAuthError("API token ID must be provided either directly or via BLOODHOUND_TOKEN_ID environment variable")
        if not self.token_key:
            raise BloodhoundAuthError("API token key must be provided either directly or via BLOODHOUND_TOKEN_KEY environment variable")
    
    def _format_url(self, uri: str) -> str:
        """Format the complete URL from the URI path"""
        formatted_uri = uri
        if uri.startswith("/"):
            formatted_uri = formatted_uri[1:]
            
        return f"{self.scheme}://{self.domain}:{self.port}/{formatted_uri}"
    
    def _request(self, method: str, uri: str, body: Optional[bytes] = None) -> requests.Response:
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
    
    def request(self, method: str, uri: str, 
                params: Optional[Dict[str, Any]] = None, 
                data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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
            body = json.dumps(data).encode('utf8')
        
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
    
    def __init__(self, domain: str = None, token_id: str = None, token_key: str = None, 
                 port: int = 443, scheme: str = "https"):
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
        self.base_client = BloodhoundBaseClient(domain, token_id, token_key, port, scheme)
        
        # Initialize resource clients
        self.domains = DomainClient(self.base_client)
        self.users = UserClient(self.base_client)
        self.groups = GroupClient(self.base_client)
        #self.computers = ComputerClient(self.base_client)
    
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
    
    def get_users(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get users in a specific domain
        
        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of users to return
            skip: Number of users to skip for pagination
            
        Returns:
            Dictionary with data (list of users) and count (total number of users)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/domains/{domain_id}/users", params=params)
    
    def get_groups(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get groups in a specific domain
        
        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of groups to return
            skip: Number of groups to skip for pagination
            
        Returns:
            Dictionary with data (list of groups) and count (total number of groups)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/domains/{domain_id}/groups", params=params)
    
    def get_computers(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get computers in a specific domain
        
        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of computers to return
            skip: Number of computers to skip for pagination
            
        Returns:
            Dictionary with data (list of computers) and count (total number of computers)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/domains/{domain_id}/computers", params=params)
    
    def get_controllers(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get controllers in a specific domain
        
        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of controllers to return
            skip: Number of controllers to skip for pagination
            
        Returns:
            Dictionary with data (list of controllers) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/domains/{domain_id}/controllers", params=params)
    
    def get_gpos(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get Group Policy Objects (GPOs) in a specific domain
        
        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of GPOs to return
            skip: Number of GPOs to skip for pagination
            
        Returns:
            Dictionary with data (list of GPOs) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/domains/{domain_id}/gpos", params=params)
    
    def get_ous(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get Organizational Units (OUs) in a specific domain
        
        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of OUs to return
            skip: Number of OUs to skip for pagination
            
        Returns:
            Dictionary with data (list of OUs) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/domains/{domain_id}/ous", params=params)
    
    def get_dc_syncers(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get DC Syncers in a specific domain
        
        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of DC Syncers to return
            skip: Number of DC Syncers to skip for pagination
            
        Returns:
            Dictionary with data (list of DC Syncers) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/domains/{domain_id}/dc-syncers", params=params)
    
    def get_foreign_admins(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get foreign admins in a specific domain
        
        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of foreign admins to return
            skip: Number of foreign admins to skip for pagination
            
        Returns:
            Dictionary with data (list of foreign admins) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/domains/{domain_id}/foreign-admins", params=params)
    
    def get_foreign_gpo_controllers(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get foreign GPO controllers in a specific domain
        
        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of foreign GPO controllers to return
            skip: Number of foreign GPO controllers to skip for pagination
            
        Returns:
            Dictionary with data (list of foreign GPO controllers) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/domains/{domain_id}/foreign-gpo-controllers", params=params)
    
    def get_foreign_groups(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get foreign groups in a specific domain
        
        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of foreign groups to return
            skip: Number of foreign groups to skip for pagination
            
        Returns:
            Dictionary with data (list of foreign groups) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/domains/{domain_id}/foreign-groups", params=params)
    
    def get_foreign_users(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get foreign users in a specific domain
        
        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of foreign users to return
            skip: Number of foreign users to skip for pagination
            
        Returns:
            Dictionary with data (list of foreign users) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/domains/{domain_id}/foreign-users", params=params)
    
    def get_inbound_trusts(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get inbound trusts in a specific domain
        
        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of inbound trusts to return
            skip: Number of inbound trusts to skip for pagination
            
        Returns:
            Dictionary with data (list of inbound trusts) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/domains/{domain_id}/inbound-trusts", params=params)
    
    def get_outbound_trusts(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get outbound trusts in a specific domain
        
        Args:
            domain_id: The ID of the domain to query
            limit: Maximum number of outbound trusts to return
            skip: Number of outbound trusts to skip for pagination
            
        Returns:
            Dictionary with data (list of outbound trusts) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/domains/{domain_id}/outbound-trusts", params=params)

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
        return self.base_client.request("GET", f"/api/v2/users/{user_id}", params=params)
    
    def get_admin_rights(self, user_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get administrative rights of a specific user
        
        Args:
            user_id: The ID of the user to query
            limit: Maximum number of rights to return
            skip: Number of rights to skip for pagination
            
        Returns:
            Dictionary with data (list of rights) and count (total number of rights)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/users/{user_id}/admin-rights", params=params)
    
    def get_constrained_delegation_rights(self, user_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get constrained delegation rights of a specific user
        
        Args:
            user_id: The ID of the user to query
            limit: Maximum number of constrained delegation rights to return
            skip: Number of constrained delegation rights to skip for pagination
            
        Returns:
            Dictionary with data (list of rights) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/users/{user_id}/constrained-delegation-rights", params=params)
    
    def get_controllables(self, user_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get controllable objects for a specific user
        
        Args:
            user_id: The ID of the user to query
            limit: Maximum number of controllables to return
            skip: Number of controllables to skip for pagination
            
        Returns:
            Dictionary with data (list of controllables) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/users/{user_id}/controllables", params=params)
    
    def get_controllers(self, user_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get controllers of a specific user
        
        Args:
            user_id: The ID of the user to query
            limit: Maximum number of controllers to return
            skip: Number of controllers to skip for pagination
            
        Returns:
            Dictionary with data (list of controllers) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/users/{user_id}/controllers", params=params)
    
    def get_dcom_rights(self, user_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get DCOM rights of a specific user
        
        Args:
            user_id: The ID of the user to query
            limit: Maximum number of DCOM rights to return
            skip: Number of DCOM rights to skip for pagination
            
        Returns:
            Dictionary with data (list of DCOM rights) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/users/{user_id}/dcom-rights", params=params)
    
    def get_memberships(self, user_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get group memberships of a specific user
        
        Args:
            user_id: The ID of the user to query
            limit: Maximum number of memberships to return
            skip: Number of memberships to skip for pagination
            
        Returns:
            Dictionary with data (list of memberships) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/users/{user_id}/memberships", params=params)
    
    def get_ps_remote_rights(self, user_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get PowerShell Remote rights of a specific user
        
        Args:
            user_id: The ID of the user to query
            limit: Maximum number of PS Remote rights to return
            skip: Number of PS Remote rights to skip for pagination
            
        Returns:
            Dictionary with data (list of PS Remote rights) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/users/{user_id}/ps-remote-rights", params=params)
    
    def get_rdp_rights(self, user_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get RDP rights of a specific user
        
        Args:
            user_id: The ID of the user to query
            limit: Maximum number of RDP rights to return
            skip: Number of RDP rights to skip for pagination
            
        Returns:
            Dictionary with data (list of RDP rights) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/users/{user_id}/rdp-rights", params=params)
    
    def get_sessions(self, user_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get active sessions of a specific user
        
        Args:
            user_id: The ID of the user to query
            limit: Maximum number of sessions to return
            skip: Number of sessions to skip for pagination
            
        Returns:
            Dictionary with data (list of sessions) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/users/{user_id}/sessions", params=params)
    
    def get_sql_admin_rights(self, user_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get SQL admin rights of a specific user
        
        Args:
            user_id: The ID of the user to query
            limit: Maximum number of SQL admin rights to return
            skip: Number of SQL admin rights to skip for pagination
            
        Returns:
            Dictionary with data (list of SQL admin rights) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/users/{user_id}/sql-admin-rights", params=params)


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
        return self.base_client.request("GET", f"/api/v2/groups/{group_id}", params=params)
    
    def get_members(self, group_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get members of a specific group
        
        Args:
            group_id: The ID of the group to query
            limit: Maximum number of members to return
            skip: Number of members to skip for pagination
            
        Returns:
            Dictionary with data (list of members) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/groups/{group_id}/members", params=params)
    
    def get_memberships(self, group_id: str, limit: int = 100, skip: int = 0) -> Dict[str, Any]:
        """
        Get group memberships of a specific group
        
        Args:
            group_id: The ID of the group to query
            limit: Maximum number of memberships to return
            skip: Number of memberships to skip for pagination
            
        Returns:
            Dictionary with data (list of memberships) and count (total number)
        """
        params = {
            "limit": limit,
            "skip": skip,
            "type": "list"
        }
        return self.base_client.request("GET", f"/api/v2/groups/{group_id}/memberships", params=params)
    






   # /api/v2/computers/{computer_id}/ api use




   # /api/v2/ous/{ou_id}/ api use




    # /api/v2/gpos/{gpo_id}/ api use


    # /api/v2/graphs/cypher api use
    # for custom cypher queries

    