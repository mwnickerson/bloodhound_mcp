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

# Load environment variables from .env file
load_dotenv()

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
    def get_users(self, domain_id: str, limit: int = 100, skip: int = 0) -> Dict:
        """
        Gets Users in a specific domain
        Limit: maixmum number of users to return (default: 100)
        Skip: number of users to skip (default: 0)
        
        returns:
            Dictionary of users and their data and the total number of users
        """

        try:
            response = self._request("GET", f"/api/v2/domains/{domain_id}/users?limit={limit}&skip={skip}")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get users: {e}")
            return {"data": [], "count": 0}


        
