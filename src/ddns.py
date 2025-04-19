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

from whmc_sdk import WhmcsSDK
import json
import os
import requests
from typing import Any, Dict, List, Optional, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VimexxDDNS")

# Configuration globals
TTL = str(60*60)    # 1 hour TTL seems reasonable
ENABLE_IPV4 = True  # Toggle IPv4 support
ENABLE_IPV6 = True  # Toggle IPv6 support

def main():
    # Load configurations
    credentials = load_json('config/credentials.json')
    subdomains = load_json('config/subdomains.json')

    sdk = WhmcsSDK(
        credentials['client_id'],
        credentials['client_key'],
        credentials['email'],
        credentials['password']
    )
    
    # Get IP addresses based on configuration
    public_ipv4 = None
    public_ipv6 = None
    
    if ENABLE_IPV4:
        public_ipv4 = get_public_ipv4()
        logger.info(f"Public IPv4: {public_ipv4}")
    else:
        logger.info("IPv4 support disabled")
        
    if ENABLE_IPV6:
        public_ipv6 = get_public_ipv6()
        logger.info(f"Public IPv6: {public_ipv6}")
    else:
        logger.info("IPv6 support disabled")

    sld, tld = credentials['domain'].split('.')
    logger.info(f"Processing domain: {sld}.{tld}")

    # Check for DNS record mismatches
    dns_records = sdk.get_domain_dns_records(sld, tld)
    domains = prepare_domains(credentials['domain'], subdomains)
    
    # Process IPv4 records if enabled
    ipv4_mismatched_domains = []
    if ENABLE_IPV4 and public_ipv4:
        ipv4_mismatched_domains = get_mismatched_record_domains(dns_records, domains, public_ipv4, 'A')
        
        if not ipv4_mismatched_domains:
            logger.info("All IPv4 domain(s) match our public IP")
        else:
            logger.info(f"IPv4 records to patch: {ipv4_mismatched_domains}")
    
    # Process IPv6 records if enabled
    ipv6_mismatched_domains = []
    if ENABLE_IPV6 and public_ipv6:
        ipv6_mismatched_domains = get_mismatched_record_domains(dns_records, domains, public_ipv6, 'AAAA')
        
        if not ipv6_mismatched_domains:
            logger.info("All IPv6 domain(s) match our public IP")
        else:
            logger.info(f"IPv6 records to patch: {ipv6_mismatched_domains}")

    # If nothing to update, we're done
    if not ipv4_mismatched_domains and not ipv6_mismatched_domains:
        logger.info("No DNS records need updating")
        return

    # Update DNS records for both IPv4 and IPv6
    updated_dns_records = update_dns_records(dns_records, 
                                            ipv4_mismatched_domains, public_ipv4, 'A',
                                            ipv6_mismatched_domains, public_ipv6, 'AAAA')
    
    if not sdk.set_domain_dns_records(sld, tld, updated_dns_records):
        logger.error("Failed to update DNS records")
        return
    
    logger.info("Successfully updated DNS records")

def load_json(name: str) -> Optional[Dict]:
    if os.path.exists(name):
        with open(name, "r") as f:
            return json.load(f)
    else:
        logger.error(f"No {name} found! aborting...")
        exit(-1)

def get_public_ipv4() -> Optional[str]:
    try:
        response = requests.get('https://v4.ident.me', timeout=5)
        ip = response.text.strip()
        return ip
    except requests.RequestException as e:
        logger.error(f"Fetching public IPv4: {e}")
        exit(-1)

def get_public_ipv6() -> Optional[str]:
    try:
        response = requests.get('https://v6.ident.me', timeout=5)
        ip = response.text.strip()
        return ip
    except requests.RequestException as e:
        logger.error(f"Fetching public IPv6: {e}")
        exit(-1)

def prepare_domains(domain: str, subdomains: List[str]) -> List[str]:
    if not domain.endswith('.'):
        domain += '.'
    return [domain] + [f"{subdomain}.{domain}" for subdomain in subdomains]

def get_mismatched_record_domains(dns_records: List[Dict[str, Any]], domains: List[str], 
                                  ip: str, record_type: str) -> List[str]:
    """
    Identify DNS records that do not match the specified IP.

    Args:
        dns_records (List[Dict[str, Any]]): List of DNS records.
        domains (List[str]): List of domain names to check.
        ip (str): Expected IP address.
        record_type (str): DNS record type ('A' for IPv4, 'AAAA' for IPv6)

    Returns:
        List[str]: List of mismatched DNS records.
    """
    mismatched_domains = []

    for domain in domains:
        # Filter records for the current domain of the specified type
        domain_records = [
            record for record in dns_records
            if record.get('type') == record_type and record.get('name') == domain
        ]

        # Check if any record exists and matches the IP
        if not domain_records:
            # No record exists, need to create one
            mismatched_domains.append(domain)
        elif any(record.get("content") != ip for record in domain_records):
            # Record exists but doesn't match the IP
            mismatched_domains.append(domain)

    if mismatched_domains:
        logger.debug(f"Mismatched {record_type} records found: {mismatched_domains}")
    
    return mismatched_domains

def update_dns_records(current_records: List[Dict[str, Any]], 
                       ipv4_mismatched_domains: List[str], ipv4: Optional[str], ipv4_record_type: str,
                       ipv6_mismatched_domains: List[str], ipv6: Optional[str], ipv6_record_type: str) -> List[Dict[str, Any]]:
    """
    Update DNS records for mismatched domains while preserving all other records.

    Args:
        current_records (List[Dict[str, Any]]): Current DNS records.
        ipv4_mismatched_domains (List[str]): List of mismatched IPv4 domains.
        ipv4 (Optional[str]): The IPv4 address to set for the domains.
        ipv4_record_type (str): Record type for IPv4 (typically 'A')
        ipv6_mismatched_domains (List[str]): List of mismatched IPv6 domains.
        ipv6 (Optional[str]): The IPv6 address to set for the domains.
        ipv6_record_type (str): Record type for IPv6 (typically 'AAAA')

    Returns:
        List[Dict[str, Any]]: Updated DNS records.
    """
    # Create a deep copy of current records to avoid modifying the original
    updated_records = []
    
    # Keep track of domains that we've updated
    ipv4_domains_updated = set()
    ipv6_domains_updated = set()
    
    # First, copy all records that aren't to be updated
    for record in current_records:
        record_name = record.get('name')
        record_type = record.get('type')
        
        # Skip IPv4 records for mismatched domains
        if ENABLE_IPV4 and record_type == ipv4_record_type and record_name in ipv4_mismatched_domains:
            continue
            
        # Skip IPv6 records for mismatched domains
        if ENABLE_IPV6 and record_type == ipv6_record_type and record_name in ipv6_mismatched_domains:
            continue

        # Ensure TTL is included in all records
        updated_record = record.copy()
        if 'ttl' not in updated_record:
            updated_record['ttl'] = TTL

        updated_records.append(updated_record)
    
    # Add updated IPv4 records if enabled
    if ENABLE_IPV4 and ipv4:
        for domain in ipv4_mismatched_domains:
            updated_records.append({
                "content": ipv4,
                "type": ipv4_record_type,
                "name": domain,
                "ttl": TTL
            })
            ipv4_domains_updated.add(domain)
    
    # Add updated IPv6 records if enabled
    if ENABLE_IPV6 and ipv6:
        for domain in ipv6_mismatched_domains:
            updated_records.append({
                "content": ipv6,
                "type": ipv6_record_type,
                "name": domain,
                "ttl": TTL
            })
            ipv6_domains_updated.add(domain)
    
    logger.info(f"Total records to be submitted: {len(updated_records)}")
    return updated_records

if __name__ == '__main__':
    main()