"""
Enrichment utilities for IOCBuilder

This module provides lightweight enrichment for domains and IPs using
free, public APIs (no authentication required). Includes WHOIS lookup
and basic DNS resolution.

"""

import requests
import logging

HEADERS = {"User-Agent": "IOCBuilder/1.0"}

def get_domain_creation_year(domain):
    """
    Fetch WHOIS creation year for a given domain using a public API.

    Parameters:
        domain (str): The domain name to query.

    Returns:
        str: Creation year (or 'unknown' if unavailable).
    """
    try:
        url = f"https://api.whois.vu/?q={domain}"
        response = requests.get(url, headers=HEADERS, timeout=5)
        response.raise_for_status()
        data = response.json()
        return data.get("creation_date", "unknown")
    except Exception as e:
        logging.warning(f"WHOIS lookup failed for {domain}: {e}")
        return "unknown"


def resolve_ip(domain):
    """
    Resolve domain to IP using Google's DNS over HTTPS API.

    Parameters:
        domain (str): The domain name to resolve.

    Returns:
        dict: {'Answer': [IP address list]} or empty dict if failed.
    """
    try:
        url = f"https://dns.google/resolve?name={domain}&type=A"
        response = requests.get(url, headers=HEADERS, timeout=5)
        response.raise_for_status()
        data = response.json()
        if "Answer" in data:
            ip_list = [entry["data"] for entry in data["Answer"] if entry.get("type") == 1]
            return {"domain": domain, "ips": ip_list}
    except Exception as e:
        logging.warning(f"DNS resolution failed for {domain}: {e}")
    return {}
