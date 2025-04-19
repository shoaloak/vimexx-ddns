#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Dynamic DNS updater for Vimexx/WHMC
# Copyright (C) 2025 Axel Koolhaas (shoaloak)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import requests
import os
import json
import logging
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WhmcsSDK:

    VALID_WHMCS_VERSIONS = [
        '6.0.1-release.1',
        '7.5.2-release.1',
        '7.6.1-release.1',
        '8.6.1-release.1'
    ]

    ENVIRONMENTS = {
        'test': '/apitest/v1',
        'prod': '/api/v1'
    }

    def __init__(self, client_id: str, client_secret: str, username: str, password: str, 
                 base_url: str = 'https://api.vimexx.nl', token_file: str = 'config/token.json'):
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.base_url = base_url
        self.token_file = token_file
        self.token_data = self._load_token_data()
        self.whmcs_version = self.VALID_WHMCS_VERSIONS[-1]
        self.environment = self.ENVIRONMENTS['prod']
        
        if not self.token_data or not self._is_token_valid():
            self.token_data = self._fetch_new_token()
    
    def _load_token_data(self) -> Optional[Dict[str, Any]]:
        """
        Load token data from file if it exists.
        
        Returns:
            Optional[Dict[str, Any]]: The token data if found, None otherwise
        """
        if not os.path.exists(self.token_file):
            logger.info("Token file not found. A new token will be requested.")
            return None
        
        try:
            with open(self.token_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to load token data: {e}")
            return None
    
    def _save_token_data(self) -> None:
        """
        Store token data to file.
        """
        if not self.token_data:
            return
        
        try:
            with open(self.token_file, 'w') as f:
                json.dump(self.token_data, f)
            # Set file permissions to read/write for owner only
            os.chmod(self.token_file, 0o600)
        except IOError as e:
            logger.error(f"Failed to save token data: {e}")
    
    def _fetch_new_token(self) -> Dict[str, Any]:
        """
        Request a new access token.
        
        Returns:
            Dict[str, Any]: The token response data
        
        Raises:
            ValueError: If the token request fails
        """
        logger.info("Requesting a new access token.")
        response = requests.post(
            f"{self.base_url}/auth/token",
            data={
                'grant_type': 'password',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'username': self.username,
                'password': self.password,
                'scope': 'whmcs-access'
            }
        )
        response.raise_for_status()
        token_data = response.json()
        if "access_token" in token_data:
            self.token_data = token_data
            self._save_token_data()
            return token_data
        raise ValueError("Failed to fetch a valid access token.")
    
    def _is_token_valid(self) -> bool:
        """
        Check if the current token is valid based on expiration.
        
        Returns:
            bool: True if the token is still valid, False otherwise
        """
        if not self.token_data or 'expires_in' not in self.token_data or 'access_token' not in self.token_data:
            return False
        
        token_age = self.token_data.get('token_age', 0)
        expires_in = self.token_data['expires_in']
        
        return token_age < expires_in
    
    def get_access_token(self) -> str:
        """
        Get the access token, requesting a new one if necessary.
        
        Returns:
            str: The access token
        """
        if not self._is_token_valid():
            self.token_data = self._fetch_new_token()
        return self.token_data['access_token']
    
    def api_request(self, endpoint: str, method: str = 'GET', body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Make an authenticated API request.
        
        Args:
            endpoint (str): API endpoint to request
            method (str): HTTP method to use (GET, POST, etc.)
            data (Optional[Dict[str, Any]]): Request data for POST, PUT methods
            
        Returns:
            Dict[str, Any]: JSON response from the API
            
        Raises:
            requests.HTTPError: If the request fails
        """
        token = self.get_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        url = f"{self.base_url}{self.environment}{endpoint}"
        data = {
            "body": body,
            "version": self.whmcs_version
        }
        try:
            response = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                json=data if method.upper() in ["POST", "PUT", "PATCH"] and data else None,
                params=data if method.upper() == "GET" and data else None
            )
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as e:
            logger.error(f"HTTP Error for {method} {url}: {e}")
            raise
    
    def get_domain_dns_records(self, sld: str, tld: str) -> Optional[List[Dict[str, Any]]]:
        """
        Fetch domain DNS records
        
        Args:
            sld (str): Second-level domain (e.g., "example")
            tld (str): Top-level domain (e.g., "eu")
            
        Returns:
            Optional[List[Dict[str, Any]]]: A list of DNS record dictionaries, or None if the request fails.
        """
        body = {
            "sld": sld,
            "tld": tld
        }

        response = self.api_request('/whmcs/domain/dns', 'POST', body)
        # Check if the response is valid
        if not response or not isinstance(response, dict):
            logger.error("Invalid response format")
            return None

        # Handle errors in the response
        if not response.get('result', False):
            logger.error(f"{response.get('message', 'Unknown error occurred.')}")
            return None

        # Extract and return DNS records
        dns_records = response.get('data', {}).get('dns_records', [])
        if not dns_records:
            logger.warning("Warning: No DNS records found.")
            return None

        return dns_records

    def set_domain_dns_records(self, sld: str, tld: str, dns_records: List[Dict[str, str]]) -> bool:
        """
        Save domain DNS records
        Warning: This will wipe all previous records.
        
        Args:
            sld (str): Second-level domain (e.g., "example")
            tld (str): Top-level domain (e.g., "eu")
            dns_records (List): 
            
        Returns:
            bool: 
        """
        # Validate DNS record types
        unsupported_types = {'MXE', 'FRAME', 'URL'}
        for record in dns_records:
            record_type = record.get('type')
            if record_type in unsupported_types:
                logger.error(f"Record type {record_type} is not supported.")
                return False

        body = {
            "sld": sld,
            "tld": tld,
            "dns_records": dns_records
        }

        response = self.api_request('/whmcs/domain/dns', 'PUT', body)
        # Check if the response is valid
        if not response or not isinstance(response, dict):
            logger.error("Invalid response format")
            return False

        # Handle errors in the response
        if not response.get('result', False):
            logger.error(f"{response.get('message', 'Unknown error occurred.')}")
            return False
        
        # Return success response
        logger.info("DNS records updated successfully.")
        return True
