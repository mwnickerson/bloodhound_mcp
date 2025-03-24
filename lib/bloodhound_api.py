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

class BloodhoundAPI:
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
        the environment variables: BLOODHOUND_DOMAIN, BLOODHOUND_TOKEN_ID, and BLOODHOUND_TOKEN_KEY
        """
        # Load from parameters or environment variables
        self.scheme = scheme
        self.domain = domain or os.getenv("BLOODHOUND_DOMAIN")
        self.port = port
        self.token_id = token_id or os.getenv("BLOODHOUND_TOKEN_ID")
        self.token_key = token_key or os.getenv("BLOODHOUND_TOKEN_KEY")
        
        # Validate required fields
        if not self.domain:
            raise ValueError("BloodHound domain must be provided either directly or via BLOODHOUND_DOMAIN environment variable")
        if not self.token_id:
            raise ValueError("API token ID must be provided either directly or via BLOODHOUND_TOKEN_ID environment variable")
        if not self.token_key:
            raise ValueError("API token key must be provided either directly or via BLOODHOUND_TOKEN_KEY environment variable")        
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
    def test_connection(self) -> Dict:
        """Test connection to the BloodHound API"""
        try:
            response = self._request("GET", "/api/version")
            response.raise_for_status()
            return response.json()["data"]
        except requests.exceptions.RequestException as e:
            print(f"Connection test failed: {e}")
            return None            
    def get_self_info(self) -> Dict:
        """
        Get information about the authenticated user
        
        Returns:
            User information dictionary
        """
        try:
            response = self._request("GET", "/api/v2/self")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get user info: {e}")
            return None
    # /api/v2/available-domains api use
    def get_domains(self) -> List[Dict]:
        """
        Get all domains in the Bloodhound CE Instance
        
        Returns:
            List of domain dictionaries
        """
        try:
            response = self._request("GET", "/api/v2/available-domains")
            response.raise_for_status()
            return response.json()["data"]
        except requests.exceptions.RequestException as e:
            print(f"Failed to get domains: {e}")
            return []
    # /api/v2/domains/{domain_id}/ api use
    # used for finding general information about the domain
    # this information will be fed into subsequent specific apis (users, gpos, ous, computers, etc )
    def get_users(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Users in a specific domain
        Limit: maixmum number of users to return (default: 100)
        Skip: number of users to skip (default: 0)
        
        returns:
            Dictionary of users and their data and the total number of users
        """

        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/users?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get users: {e}")
            return {"data": [], "count": 0}
    def get_groups(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Groups in a specific domain
        Returns:
            Dictionary of groups and their data and the total number of groups
        """
        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/groups?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get groups: {e}")
            return {"data": [], "count": 0}        
    def get_computers(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Computers in specified domain
        Returns:
            Dictionary of computers and their data and the total number of computers
        """
        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/computers?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get computers: {e}")
            return {"data": [], "count": 0}
    def get_controllers(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Controllers of the specified domain
        Returns:
            Dictionary of controller of the domain and their data and the total number ofcontrollers
        """
        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/controllers?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get controllers: {e}")
            return {"data": [], "count": 0}
    def get_dc_syncers(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets DC Syncers of the specified domain
        Returns:
            Dictionary of DC Syncers of the domain and their data and the total number of DC Syncers
        """
        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/dc-syncers?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get DC Syncers: {e}")
            return {"data": [], "count": 0}    
    def get_foreign_admins(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Foreign Admins of the specified domain
        Returns:
            Dictionary of Foreign Admins of the domain and their data and the total number of Foreign Admins
        """
        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/foreign-admins?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get Foreign Admins: {e}")
            return {"data": [], "count": 0}        
    def get_foreign_gpo_controllers(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Foreign GPO Controllers of the specified domain
        Returns:
            Dictionary of Foreign GPO Controllers of the domain and their data and the total number of Foreign GPO Controllers
        """
        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/foreign-gpo-controllers?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get Foreign GPO Controllers: {e}")
            return {"data": [], "count": 0}
    def get_foreign_groups(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Foreign Groups of the specified domain
        Returns:
            Dictionary of Foreign Groups of the domain and their data and the total number of Foreign Groups
        """
        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/foreign-groups?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get Foreign Groups: {e}")
            return {"data": [], "count": 0}
    def get_foreign_users(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Foreign Users of the specified domain
        Returns:
            Dictionary of Foreign Users of the domain and their data and the total number of Foreign Users
        """
        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/foreign-users?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get Foreign Users: {e}")
            return {"data": [], "count": 0}    
    def get_gpos(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets GPOs of the specified domain
        Returns:
            Dictionary of GPOs of the domain and their data and the total number of GPOs
        """
        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/gpos?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get GPOs: {e}")
            return {"data": [], "count": 0}    
    def get_inbound_trusts(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Inbound Trusts of the specified domain
        Returns:
            Dictionary of Inbound Trusts of the domain and their data and the total number of Inbound Trusts
        """
        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/inbound-trusts?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get Inbound Trusts: {e}")
            return {"data": [], "count": 0}        
    def get_linked_gpos(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Linked GPOs of the specified domain
        Returns:
            Dictionary of Linked GPOs of the domain and their data and the total number of Linked GPOs
        """
        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/linked-gpos?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get Linked GPOs: {e}")
            return {"data": [], "count": 0}        
    def get_ous(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets OUs of the specified domain
        Returns:
            Dictionary of OUs of the domain and their data and the total number of OUs
        """
        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/ous?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get OUs: {e}")
            return {"data": [], "count": 0}        
    def get_outbound_trusts(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Outbound Trusts of the specified domain
        Returns:
            Dictionary of Outbound Trusts of the domain and their data and the total number of Outbound Trusts
        """
        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/outbound-trusts?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get Outbound Trusts: {e}")
            return {"data": [], "count": 0}
        
   # /api/v2/users/{user_id}/ api use
   # Using the user_id from the get_users api, we can get more detailed information about a specific user
   # this api will be used to get more detailed information about a user and their relationships with other objects
    def get_user_info(self, user_id: str) -> Dict:
        """
        Gets detailed information about a specific user
        Returns:
            Dictionary of detailed information about the user
        """
        try:
            response = self._request("GET", f"/api/v2/users/{user_id}?counts=true")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get user info: {e}")
            return {}
    def get_user_admin_rights(self, used_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Admin Rights of the specified user
        Returns:
            Dictionary of Admin Rights of the user and their data and the total number of Admin Rights
        """
        try:
            response = self._request("GET", f"/api/v2/users/{used_id}/admin-rights?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get Admin Rights: {e}")
            return {"data": [], "count": 0}
    def get_user_constrained_delegation_rights(self, used_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Constrained Delegation Rights of the specified user
        Returns:
            Dictionary of Constrained Delegation Rights of the user and their data and the total number of Constrained Delegation Rights
        """
        try:
            response = self._request("GET", f"/api/v2/users/{used_id}/constrained-delegation-rights?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get Constrained Delegation Rights: {e}")
            return {"data": [], "count": 0}
    def get_user_controllables(self, used_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Controllables of the specified user
        Returns:
            Dictionary of Controllables of the user and their data and the total number of Controllables
        """
        try:
            response = self._request("GET", f"/api/v2/users/{used_id}/controllables?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get Controllables: {e}")
            return {"data": [], "count": 0}
    def get_user_controllers(self, used_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Controllers of the specified user
        Returns:
            Dictionary of Controllers of the user and their data and the total number of Controllers
        """
        try:
            response = self._request("GET", f"/api/v2/users/{used_id}/controllers?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get Controllers: {e}")
            return {"data": [], "count": 0}
    def get_user_dcom_rights(self, used_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets DCOM Rights of the specified user
        Returns:
            Dictionary of DCOM Rights of the user and their data and the total number of DCOM Rights
        """
        try:
            response = self._request("GET", f"/api/v2/users/{used_id}/dcom-rights?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get DCOM Rights: {e}")
            return {"data": [], "count": 0}
    def get_user_memberships(self, used_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Memberships of the specified user
        Returns:
            Dictionary of Memberships of the user and their data and the total number of Memberships
        """
        try:
            response = self._request("GET", f"/api/v2/users/{used_id}/memberships?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get Memberships: {e}")
            return {"data": [], "count": 0}
    def get_user_ps_remote_rights(self, used_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets PowerShell Remote Rights of the specified user
        Returns:
            Dictionary of objects the user can initiate PowerShell Remote sessions to and their data and the total number of PS Remote Rights
        """
        try:
            response = self._request("GET", f"/api/v2/users/{used_id}/ps-remote-rights?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get PS Remote Rights: {e}")
            return {"data": [], "count": 0}
    def get_user_rdp_rights(self, used_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Remote Desktop Protocol Rights of the specified user
        Returns:
            Dictionary of objects the user can Remote Desktop to and their data and the total number of RDP Rights
        """
        try:
            response = self._request("GET", f"/api/v2/users/{used_id}/rdp-rights?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get RDP Rights: {e}")
            return {"data": [], "count": 0}
    def get_user_sessions(self, used_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Active Sessions of the specified user
        Returns:
            Dictionary of Sessions of the user and their data and the total number of Sessions
        """
        try:
            response = self._request("GET", f"/api/v2/users/{used_id}/sessions?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get Sessions: {e}")
            return {"data": [], "count": 0}
    def get_user_sql_admin_rights(self, used_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets SQL Admin Rights of the specified user
        Returns:
            Dictionary of SQL Admin Rights of the user and their data and the total number of SQL Admin Rights
        """
        try:
            response = self._request("GET", f"/api/v2/users/{used_id}/sql-admin-rights?limit={limit}&skip={skip}&type=list")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get SQL Admin Rights: {e}")
            return {"data": [], "count": 0}
    
   # /api/v2/groups/{group_id}/ api use



   # /api/v2/computers/{computer_id}/ api use




   # /api/v2/ous/{ou_id}/ api use




    # /api/v2/gpos/{gpo_id}/ api use


    # /api/v2/graphs/cypher api use
    # for custom cypher queries

    