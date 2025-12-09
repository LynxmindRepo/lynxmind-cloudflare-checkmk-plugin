#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
# Authors:	Ricardo and Elicarlos - checkmk@lynxmind.com
# ThanksTo:	Lynxmind CloudFlare team
# URL:	https://github.com/LynxmindRepo/lynxmind-cloudflare-checkmk-plugin
# License: GNU General Public License v2
 
"""
Fetch and monitor Cloudflare essential resources:
- CDN + Cache (zones, cache settings, analytics)
- DNS (DNS records)
- SSL/TLS (SSL settings and certificates)
- Firewall/DDoS (firewall events and WAF)
- Workers/Pages (Serverless resources)
 
Output metrics in key-value format for monitoring tools.
"""
 
import argparse
import sys
from datetime import datetime, timezone, timedelta
import aiohttp
import asyncio
import logging
from typing import Optional, Dict, List, Any
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
 
CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"
 
def setup_logging(verbose: bool) -> None:
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stderr)]
    )
 
def parse_arguments(argv: Optional[List[str]]) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Fetch Cloudflare essential resources: CDN/Cache, DNS, SSL/TLS, Firewall/DDoS, Workers/Pages.\n"
            "Output format: key-value pairs for monitoring tools."
        )
    )
    parser.add_argument("--email", required=True, help="Cloudflare account email")
    parser.add_argument("--api-key", help="Cloudflare API key (Global API Key, required if --api-token not provided)")            
    parser.add_argument("--api-token", help="Cloudflare API Token (alternative to API key, required if --api-key not provided)")  
    parser.add_argument("--account-id", help="Cloudflare Account ID (for Workers/Pages)")
    parser.add_argument("--timeout", "-t", type=float, default=30, help="API call timeout in seconds")
    parser.add_argument("--cdn-cache", action="store_true", help="Fetch CDN/Cache settings and analytics")
    parser.add_argument("--dns", action="store_true", help="Fetch DNS records")
    parser.add_argument("--ssl-tls", action="store_true", help="Fetch SSL/TLS settings")
    parser.add_argument("--firewall", action="store_true", help="Fetch Firewall/DDoS events")
    parser.add_argument("--workers-pages", action="store_true", help="Fetch Workers and Pages projects")
    parser.add_argument("--d1", action="store_true", help="Fetch D1 Databases")
    parser.add_argument("--secrets", action="store_true", help="Fetch Secrets Stores")
    parser.add_argument("--devices", action="store_true", help="List all WARP devices")
    parser.add_argument("--apps", action="store_true", help="List all applications")
    parser.add_argument("--gateway", action="store_true", help="Retrieve information about the current Zero Trust account")
    parser.add_argument("--analytics", action="store_true", help="Fetch Cloudflare One Analytics (Access, Gateway HTTP/Network/DNS)")
    parser.add_argument("--all", action="store_true", help="Fetch all resources (CDN/Cache, DNS, SSL/TLS, Firewall, Workers/Pages)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    return parser.parse_args(argv)
 
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError))
)
async def fetch_json(session: aiohttp.ClientSession, url: str, headers: Dict[str, str],
                    timeout: float, silent_errors: bool = False) -> Optional[Dict[str, Any]]:
    """Fetch JSON data from the given URL.
    
    Args:
        silent_errors: If True, 400/405 errors are logged as DEBUG instead of ERROR
    """
    try:
        async with session.get(url, headers=headers, timeout=timeout) as response:
            # Handle expected "not found" or "not allowed" responses silently
            if response.status in (404, 405):
                return None
            if response.status == 400 and silent_errors:
                # 400 Bad Request - endpoint may not be available or parameters incorrect
                return None
            
            response.raise_for_status()
            data = await response.json()
            if isinstance(data, dict) and 'success' in data:
                if not data.get('success'):
                    errors = data.get('errors', [])
                    if silent_errors:
                        logging.debug(f"Cloudflare API error (silent): {errors}")
                    else:
                        logging.error(f"Cloudflare API error: {errors}")
                    return None
                return data.get('result')
            return data
    except asyncio.TimeoutError:
        logging.error(f"Timeout fetching: {url}")
        return None
    except aiohttp.ClientError as e:
        if silent_errors:
            logging.debug(f"Error fetching {url} (silent): {e}")
        else:
            logging.error(f"Error fetching {url}: {e}")
        return None
 
async def fetch_all_pages(session: aiohttp.ClientSession, url: str, headers: Dict[str, str],
                        timeout: float, max_items: int = 1000) -> List[Dict[str, Any]]:
    """Fetch all pages of data from a paginated Cloudflare API endpoint."""
    results = []
    page = 1
    per_page = 50
   
    while len(results) < max_items:
        separator = "&" if "?" in url else "?"
        paginated_url = f"{url}{separator}page={page}&per_page={per_page}"
        data = await fetch_json(session, paginated_url, headers, timeout)
       
        if not data:
            break
       
        if isinstance(data, list):
            page_items = data[:max_items - len(results)]
            results.extend(page_items)
            if len(data) < per_page:
                break
        elif isinstance(data, dict):
            results.append(data)
            break
        else:
            break
       
        if len(data) < per_page:
            break
       
        page += 1
   
    return results
 
# ============================================================================
# Core Resource Fetching Functions
# ============================================================================
 
async def get_zones(session: aiohttp.ClientSession, headers: Dict[str, str],
                    timeout: float, verbose: bool = False) -> List[Dict[str, Any]]:
    """Fetch all Cloudflare zones."""
    url = f"{CLOUDFLARE_API_BASE}/zones"
    try:
        zones = await fetch_all_pages(session, url, headers, timeout)
        if verbose:
            logging.debug(f"Found {len(zones)} zones")
        return zones
    except Exception as e:
        logging.error(f"Failed to fetch zones: {e}")
        return []
 
async def get_zone_cache_settings(session: aiohttp.ClientSession, zone_id: str,
                                  headers: Dict[str, str], timeout: float) -> Optional[Dict[str, Any]]:
    """Fetch cache settings for a zone."""
    url = f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/settings/cache_level"
    try:
        data = await fetch_json(session, url, headers, timeout)
        return data
    except Exception as e:
        logging.debug(f"Failed to fetch cache settings for zone {zone_id}: {e}")
        return None
 
async def get_zone_analytics(session: aiohttp.ClientSession, zone_id: str,
                            headers: Dict[str, str], timeout: float,
                            since: datetime, verbose: bool = False) -> Optional[Dict[str, Any]]:
    """Fetch analytics dashboard for a zone (CDN metrics)."""
    since_str = since.strftime('%Y-%m-%dT%H:%M:%SZ')
    url = f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/analytics/dashboard"
    params = f"?since={since_str}"
    try:
        data = await fetch_json(session, url + params, headers, timeout)
        if verbose:
            logging.debug(f"Analytics data for zone {zone_id}: {data}")
        return data
    except Exception as e:
        if verbose:
            logging.warning(f"Failed to fetch analytics for zone {zone_id}: {e}")
        else:
            logging.debug(f"Failed to fetch analytics for zone {zone_id}: {e}")
        return None
 
async def get_zone_dns_records(session: aiohttp.ClientSession, zone_id: str,
                               headers: Dict[str, str], timeout: float) -> List[Dict[str, Any]]:
    """Fetch DNS records for a zone."""
    url = f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/dns_records"
    try:
        records = await fetch_all_pages(session, url, headers, timeout)
        return records
    except Exception as e:
        logging.error(f"Failed to fetch DNS records for zone {zone_id}: {e}")
        return []
 
async def get_zone_ssl_settings(session: aiohttp.ClientSession, zone_id: str,
                               headers: Dict[str, str], timeout: float) -> Optional[Dict[str, Any]]:
    """Fetch SSL/TLS settings for a zone."""
    url = f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/settings/ssl"
    try:
        data = await fetch_json(session, url, headers, timeout)
        return data
    except Exception as e:
        logging.debug(f"Failed to fetch SSL settings for zone {zone_id}: {e}")
        return None
 
async def get_firewall_events(session: aiohttp.ClientSession, zone_id: str,
                             headers: Dict[str, str], timeout: float,
                             since: datetime, verbose: bool = False) -> Optional[Dict[str, Any]]:
    """Fetch firewall/WAF events for a zone."""
    since_str = since.strftime('%Y-%m-%dT%H:%M:%SZ')
    url = f"{CLOUDFLARE_API_BASE}/zones/{zone_id}/security/events"
    params = f"?since={since_str}"
    try:
        data = await fetch_json(session, url + params, headers, timeout)
        return data
    except Exception as e:
        if verbose:
            logging.debug(f"Failed to fetch firewall events for zone {zone_id}: {e}")
        return None
 
async def get_account_id(session: aiohttp.ClientSession, headers: Dict[str, str],
                        timeout: float, verbose: bool = False) -> Optional[str]:
    """Get the account ID from accounts endpoint."""
    url = f"{CLOUDFLARE_API_BASE}/accounts"
    try:
        accounts = await fetch_all_pages(session, url, headers, timeout)
        if accounts and isinstance(accounts, list) and len(accounts) > 0:
            account_id = accounts[0].get('id')
            if account_id and verbose:
                logging.debug(f"Found account ID: {account_id}")
            return account_id
    except Exception as e:
        if verbose:
            logging.debug(f"Could not fetch account ID: {e}")
    return None
 
async def get_workers(session: aiohttp.ClientSession, account_id: str,
                     headers: Dict[str, str], timeout: float,
                     verbose: bool = False) -> List[Dict[str, Any]]:
    """Fetch Cloudflare Workers."""
    if not account_id:
        return []
   
    url = f"{CLOUDFLARE_API_BASE}/accounts/{account_id}/workers/scripts"
    try:
        data = await fetch_json(session, url, headers, timeout)
        if data is None:
            return []
        if isinstance(data, list):
            workers = data
        elif isinstance(data, dict):
            workers = data.get('result', []) if 'result' in data else []
        else:
            workers = []
        if verbose:
            logging.debug(f"Found {len(workers)} Workers")
        return workers
    except Exception as e:
        if verbose:
            logging.debug(f"Failed to fetch Workers: {e}")
        return []
 
async def get_d1_databases(session: aiohttp.ClientSession, account_id: str, headers: Dict[str, str], timeout: float, verbose: bool = False) -> List[Dict[str, Any]]:
    """Fetch Cloudflare D1 Databases."""
    if not account_id:
        return []
    # Endpoint oficial para listar bancos D1
    url = f"{CLOUDFLARE_API_BASE}/accounts/{account_id}/d1/database"
    try:
        data = await fetch_json(session, url, headers, timeout)
        # O resultado costuma vir dentro de uma lista direta ou chave result
        if data and isinstance(data, list):
            if verbose: logging.debug(f"Found {len(data)} D1 databases")
            return data
        elif data and isinstance(data, dict) and 'result' in data:
             # Caso a API mude o formato
             dbs = data.get('result', [])
             return dbs
        return []
    except Exception as e:
        if verbose: logging.debug(f"Failed to fetch D1 databases: {e}")
        return []
   
async def get_apps(session: aiohttp.ClientSession,
                   account_id: str,
                   headers: Dict[str, str],
                   timeout: float,
                   verbose: bool = False) -> List[Dict[str, Any]]:
    if not account_id:
        return []
    url = f"{CLOUDFLARE_API_BASE}/accounts/{account_id}/access/apps"
 
    try:
        apps = await fetch_all_pages(session, url, headers, timeout)
        if verbose:
            logging.debug(f"Found {len(apps)} Access Applications")
        return apps
    except Exception as e:
        if verbose:
            logging.debug(f"Failed to fetch Access Apps: {e}")
        return []
   
async def get_gateway_account(session: aiohttp.ClientSession, account_id: str,
                              headers: Dict[str, str], timeout: float,
                              verbose: bool = False) -> Optional[Dict[str, Any]]:
    """Fetch Cloudflare Gateway Account Configuration."""
    if not account_id:
        return None
   
    url = f"{CLOUDFLARE_API_BASE}/accounts/{account_id}/gateway"
   
    try:
        data = await fetch_json(session, url, headers, timeout)
        if verbose:
            logging.debug(f"Gateway Account info: {data}")
        return data
    except Exception as e:
        if verbose:
            logging.debug(f"Failed to fetch Gateway Account: {e}")
        return None
 
async def get_gateway_rules(session: aiohttp.ClientSession, account_id: str,
                            headers: Dict[str, str], timeout: float,
                            verbose: bool = False) -> List[Dict[str, Any]]:
    """Fetch Cloudflare Gateway Rules."""
    if not account_id:
        return []
 
    url = f"{CLOUDFLARE_API_BASE}/accounts/{account_id}/gateway/rules"
   
    try:
        rules = await fetch_all_pages(session, url, headers, timeout)
        if verbose:
            logging.debug(f"Found {len(rules)} Gateway Rules")
        return rules
    except Exception as e:
        if verbose:
            logging.debug(f"Failed to fetch Gateway Rules: {e}")
        return []
 
 
 
async def get_warp_devices(session: aiohttp.ClientSession, account_id: str,
                           headers: Dict[str, str], timeout: float,
                           verbose: bool = False) -> List[Dict[str, Any]]:
    """Fetch Cloudflare WARP Physical Devices using Cursor Pagination."""
    if not account_id:
        return []
 
    base_url = f"{CLOUDFLARE_API_BASE}/accounts/{account_id}/devices/physical-devices"
    results = []
    cursor = None
   
    while True:
 
        params = [f"per_page=50"]
        if cursor:
            params.append(f"cursor={cursor}")
       
        query_string = "&".join(params)
        full_url = f"{base_url}?{query_string}"
       
        try:
            if verbose:
                logging.debug(f"Fetching devices batch. Cursor: {cursor if cursor else 'Initial'}")
 
 
            async with session.get(full_url, headers=headers, timeout=timeout) as response:
                if response.status == 404:
                    break
               
               
                if response.status >= 400:
                    text = await response.text()
                    logging.error(f"Error fetching devices: {response.status} - {text}")
                    break
 
                data = await response.json()
               
                if not data.get('success', False):
                    errors = data.get('errors', [])
                    logging.error(f"API Error fetching devices: {errors}")
                    break
 
               
                batch = data.get('result', [])
                if not batch:
                    break
               
                results.extend(batch)
               
                result_info = data.get('result_info', {})
                cursor = result_info.get('cursor')
               
                if not cursor:
                    break
                   
        except Exception as e:
            logging.error(f"Exception fetching WARP devices: {e}")
            break
 
    if verbose:
        logging.debug(f"Found total {len(results)} WARP devices")
       
    return results
   
async def get_secrets_store(session: aiohttp.ClientSession, account_id: str,
                            headers: Dict[str, str], timeout: float,
                            verbose: bool = False) -> Dict[str, Any]:
    """Fetch Secrets Stores and count secrets inside them."""
    if not account_id:
        return {}
   
    # 1. Fetch Stores
    stores_url = f"{CLOUDFLARE_API_BASE}/accounts/{account_id}/secrets_store/stores"
    try:
        stores = await fetch_all_pages(session, stores_url, headers, timeout)
    except Exception as e:
        if verbose: logging.debug(f"Failed to fetch Secrets Stores list: {e}")
        return {}
 
    if not stores:
        if verbose: logging.debug("No Secrets Stores found.")
        return {}
 
    secrets_data = {}
   
    # 2. Fetch Secrets for each store
    for store in stores:
        store_id = store.get('id')
        store_name = store.get('name')
        if not store_id:
            continue
       
        secrets_url = f"{CLOUDFLARE_API_BASE}/accounts/{account_id}/secrets_store/stores/{store_id}/secrets"
        try:
            secrets = await fetch_all_pages(session, secrets_url, headers, timeout)
            secrets_data[store_name] = {
                'id': store_id,
                'count': len(secrets)
            }
        except Exception as e:
            if verbose: logging.debug(f"Failed to fetch secrets for store {store_name}: {e}")
           
    if verbose: logging.debug(f"Found {len(stores)} stores with secrets.")
    return secrets_data
 
async def get_pages_projects(session: aiohttp.ClientSession, account_id: str,
                            headers: Dict[str, str], timeout: float,
                            verbose: bool = False) -> List[Dict[str, Any]]:
    """Fetch Cloudflare Pages projects."""
    if not account_id:
        return []
   
    url = f"{CLOUDFLARE_API_BASE}/accounts/{account_id}/pages/projects"
    try:
        data = await fetch_json(session, url, headers, timeout)
        if data is None:
            return []
        if isinstance(data, list):
            projects = data
        elif isinstance(data, dict):
            projects = data.get('result', []) if 'result' in data else [data]
        else:
            projects = []
        if verbose:
            logging.debug(f"Found {len(projects)} Pages projects")
        return projects
    except Exception as e:
        if verbose:
            logging.debug(f"Failed to fetch Pages projects: {e}")
        return []

async def get_access_analytics(session: aiohttp.ClientSession, account_id: str,
                               headers: Dict[str, str], timeout: float,
                               since: datetime, verbose: bool = False) -> Optional[Dict[str, Any]]:
    """Fetch Cloudflare Access Analytics.
    
    Note: This endpoint may not be available via REST API v4.
    Cloudflare One Analytics are typically accessed via GraphQL Analytics API.
    """
    if not account_id:
        return None
    
    since_str = since.strftime('%Y-%m-%dT%H:%M:%SZ')
    url = f"{CLOUDFLARE_API_BASE}/accounts/{account_id}/access/analytics"
    params = f"?since={since_str}"
    
    try:
        # Use silent_errors=True as this endpoint may not be available
        data = await fetch_json(session, url + params, headers, timeout, silent_errors=True)
        if verbose:
            logging.debug(f"Access Analytics data: {data}")
        return data
    except Exception as e:
        if verbose:
            logging.debug(f"Failed to fetch Access Analytics: {e}")
        return None

async def get_gateway_http_analytics(session: aiohttp.ClientSession, account_id: str,
                                     headers: Dict[str, str], timeout: float,
                                     since: datetime, verbose: bool = False) -> Optional[Dict[str, Any]]:
    """Fetch Cloudflare Gateway HTTP Traffic Analytics.
    
    Note: This endpoint may not be available via REST API v4.
    Cloudflare One Analytics are typically accessed via GraphQL Analytics API.
    """
    if not account_id:
        return None
    
    since_str = since.strftime('%Y-%m-%dT%H:%M:%SZ')
    url = f"{CLOUDFLARE_API_BASE}/accounts/{account_id}/gateway/analytics/http"
    params = f"?since={since_str}"
    
    try:
        # Use silent_errors=True as this endpoint may not be available
        data = await fetch_json(session, url + params, headers, timeout, silent_errors=True)
        if verbose:
            logging.debug(f"Gateway HTTP Analytics data: {data}")
        return data
    except Exception as e:
        if verbose:
            logging.debug(f"Failed to fetch Gateway HTTP Analytics: {e}")
        return None

async def get_gateway_network_analytics(session: aiohttp.ClientSession, account_id: str,
                                        headers: Dict[str, str], timeout: float,
                                        since: datetime, verbose: bool = False) -> Optional[Dict[str, Any]]:
    """Fetch Cloudflare Gateway Network Traffic Analytics.
    
    Note: This endpoint may not be available via REST API v4.
    Cloudflare One Analytics are typically accessed via GraphQL Analytics API.
    """
    if not account_id:
        return None
    
    since_str = since.strftime('%Y-%m-%dT%H:%M:%SZ')
    url = f"{CLOUDFLARE_API_BASE}/accounts/{account_id}/gateway/analytics/network"
    params = f"?since={since_str}"
    
    try:
        # Use silent_errors=True as this endpoint may not be available
        data = await fetch_json(session, url + params, headers, timeout, silent_errors=True)
        if verbose:
            logging.debug(f"Gateway Network Analytics data: {data}")
        return data
    except Exception as e:
        if verbose:
            logging.debug(f"Failed to fetch Gateway Network Analytics: {e}")
        return None

async def get_gateway_dns_analytics(session: aiohttp.ClientSession, account_id: str,
                                    headers: Dict[str, str], timeout: float,
                                    since: datetime, verbose: bool = False) -> Optional[Dict[str, Any]]:
    """Fetch Cloudflare Gateway DNS Traffic Analytics.
    
    Note: This endpoint may not be available via REST API v4.
    Cloudflare One Analytics are typically accessed via GraphQL Analytics API.
    """
    if not account_id:
        return None
    
    since_str = since.strftime('%Y-%m-%dT%H:%M:%SZ')
    url = f"{CLOUDFLARE_API_BASE}/accounts/{account_id}/gateway/analytics/dns"
    params = f"?since={since_str}"
    
    try:
        # Use silent_errors=True as this endpoint may not be available
        data = await fetch_json(session, url + params, headers, timeout, silent_errors=True)
        if verbose:
            logging.debug(f"Gateway DNS Analytics data: {data}")
        return data
    except Exception as e:
        if verbose:
            logging.debug(f"Failed to fetch Gateway DNS Analytics: {e}")
        return None

async def get_zero_trust_seats(session: aiohttp.ClientSession, account_id: str,
                               headers: Dict[str, str], timeout: float,
                               verbose: bool = False) -> Optional[Dict[str, Any]]:
    """Fetch Cloudflare Zero Trust seat usage information.
    
    Note: This endpoint may not be available via REST API v4.
    Seat information may be available through other endpoints or GraphQL API.
    """
    if not account_id:
        return None
    
    url = f"{CLOUDFLARE_API_BASE}/accounts/{account_id}/zt/seats"
    
    try:
        # Use silent_errors=True as this endpoint may not be available
        data = await fetch_json(session, url, headers, timeout, silent_errors=True)
        if verbose:
            logging.debug(f"Zero Trust Seats data: {data}")
        return data
    except Exception as e:
        if verbose:
            logging.debug(f"Failed to fetch Zero Trust Seats: {e}")
        return None

# ============================================================================
# Print Functions
# ============================================================================
 
def print_cdn_cache_stats(zones_data: Dict[str, Dict[str, Any]]) -> None:
    """Print CDN/Cache statistics."""
    if not zones_data:
        return
   
    print("\n<<<cloudflare_cdn_cache>>>\n")
    for zone_name, zone_info in zones_data.items():
        zone_id = zone_info.get('id', '')
       
        # Cache level setting
        cache_settings = zone_info.get('cache_settings')
        if cache_settings:
            cache_level = cache_settings.get('value', 'unknown')
            print(f"zone.{zone_name}.cache_level={cache_level}")
       
        # Analytics (CDN metrics)
        analytics = zone_info.get('analytics')
       
        # Initialize defaults
        requests_total = 0
        bandwidth_total = 0
        cached_requests = 0
        cache_hit_rate = 0.0
       
        if analytics:
            # Try to get metrics from analytics data
            # The structure might be: analytics['result']['timeseries'][0] or direct
            result_data = analytics.get('result', analytics)
           
            # Check if it's a timeseries format
            if 'timeseries' in result_data and isinstance(result_data['timeseries'], list) and len(result_data['timeseries']) > 0:
                # Get the latest data point
                latest = result_data['timeseries'][0]
                requests_data = latest.get('requests', {})
                bandwidth_data = latest.get('bandwidth', {})
            else:
                # Direct format
                requests_data = result_data.get('requests', {})
                bandwidth_data = result_data.get('bandwidth', {})
           
            if isinstance(requests_data, dict):
                requests_total = requests_data.get('all', 0)
                cached_requests = requests_data.get('cached', 0)
            elif isinstance(requests_data, (int, float)):
                requests_total = int(requests_data)
           
            if isinstance(bandwidth_data, dict):
                bandwidth_total = bandwidth_data.get('all', 0)
            elif isinstance(bandwidth_data, (int, float)):
                bandwidth_total = int(bandwidth_data)
           
            # Calculate cache hit rate
            if requests_total > 0:
                cache_hit_rate = (cached_requests / requests_total) * 100
            else:
                cache_hit_rate = 0.0
       
        # Always print metrics, even if 0 or analytics not available
        print(f"zone.{zone_name}.requests_total={requests_total}")
        print(f"zone.{zone_name}.bandwidth_total={bandwidth_total}")
        print(f"zone.{zone_name}.cached_requests={cached_requests}")
        print(f"zone.{zone_name}.cache_hit_rate={cache_hit_rate:.2f}%")
       
        print()
 
def print_dns_stats(zones_data: Dict[str, Dict[str, Any]]) -> None:
    """Print DNS statistics."""
    if not zones_data:
        return
   
    print("\n<<<cloudflare_dns>>>\n")
    for zone_name, zone_info in zones_data.items():
        dns_count = zone_info.get('dns_records_count', 0)
        dns_records = zone_info.get('dns_records', [])
       
        print(f"zone.{zone_name}.dns_records_total={dns_count}")
       
        # Count by type
        type_counts = {}
        for record in dns_records:
            record_type = record.get('type', 'unknown')
            type_counts[record_type] = type_counts.get(record_type, 0) + 1
       
        for record_type, count in type_counts.items():
            print(f"zone.{zone_name}.dns_records_type.{record_type}={count}")
       
        print()
 
def print_warp_device_stats(devices_data: List[Dict[str, Any]]) -> None:
    """Print WARP Devices statistics."""
    if not devices_data:
        return
 
    print("\n<<<cloudflare_warp_devices>>>\n")
   
    # Métrica de total global
    print(f"warp.devices_total={len(devices_data)}")
 
    for device in devices_data:
        # O ID é usado como item único no Checkmk
        dev_id = device.get('id', 'unknown')
        if dev_id == 'unknown':
            continue
 
        # Extração de dados seguros com valores por defeito
        name = device.get('name', 'unknown').replace(' ', '_') # Sanitizar espaços
        platform = device.get('device_type', 'unknown')
        version = device.get('os_version', 'unknown')
        last_seen = device.get('last_seen_at', '')
       
        # Mapeamento do status (deleted = true significa inativo/revogado)
        is_deleted = device.get('deleted', False)
        status = "revoked" if is_deleted else "active"
 
        # Output formatado para o parse_function ler depois
        # Formato: warp.device.{id}.{metric}={value}
        print(f"warp.device.{dev_id}.name={name}")
        print(f"warp.device.{dev_id}.platform={platform}")
        print(f"warp.device.{dev_id}.version={version}")
        print(f"warp.device.{dev_id}.status={status}")
       
        if last_seen:
            print(f"warp.device.{dev_id}.last_seen={last_seen}")
 
    print()
 
def print_apps_stats(apps_data: Dict[str, Dict[str, Any]]) -> None:
    """Print Apps statistics."""
    if not apps_data:
        return
 
    print("\n<<<cloudflare_access_apps>>>\n")
   
    print(f"access.apps_total={len(apps_data)}")
 
    for app in apps_data:
        app_id = app.get('id')
        if not app_id:
            continue
 
        # 1. Identidade e Sanitização
        name = app.get('name', 'unknown').replace(' ', '_')
        domain = app.get('domain', 'unknown')
        app_type = app.get('type', 'unknown')
        updated_at = app.get('updated_at', '')
 
        # 2. Contagens (Métricas Numéricas para Gráficos)
        # Conta quantos itens existem nas listas. Se a lista não existir, retorna 0.
        policies_count = len(app.get('policies', []))
        destinations_count = len(app.get('destinations', []))
        allowed_idps_count = len(app.get('allowed_idps', []))
       
        # Tags podem ser úteis para agrupar no Checkmk depois
        tags_list = ",".join(app.get('tags', []))
 
        # 3. Output Formatado
        print(f"access.app.{app_id}.name={name}")
        print(f"access.app.{app_id}.domain={domain}")
        print(f"access.app.{app_id}.type={app_type}")
        print(f"access.app.{app_id}.updated_at={updated_at}")
       
        # Métricas
        print(f"access.app.{app_id}.policies_count={policies_count}")
        print(f"access.app.{app_id}.destinations_count={destinations_count}")
        print(f"access.app.{app_id}.idps_count={allowed_idps_count}")
       
        if tags_list:
            print(f"access.app.{app_id}.tags={tags_list}")
 
    print()
 
def print_gateway_stats(account_data: Optional[Dict[str, Any]], rules_data: List[Dict[str, Any]]) -> None:
    """Print Gateway statistics."""
    # Se não houver dados de conta nem de regras, não imprime nada
    if not account_data and not rules_data:
        return
 
    print("\n<<<cloudflare_gateway>>>\n")
 
    # 1. Informações da Conta
    if account_data:
        provider = account_data.get('provider_name', 'unknown')
        # Tenta pegar o ID da conta gateway (diferente do account_id geral)
        gateway_tag = account_data.get('id', '')
        print(f"gateway.account.provider={provider}")
        print(f"gateway.account.tag={gateway_tag}")
 
    # 2. Estatísticas das Regras
    if rules_data:
        print(f"gateway.rules_total={len(rules_data)}")
       
        # Contadores por tipo (DNS, HTTP, NETWORK) e Ação (BLOCK, ALLOW)
        type_counts = {}
        action_counts = {}
       
        for rule in rules_data:
            # Contar Tipos (dns, http, l4)
            # A API pode retornar 'dns' ou 'http'. Vamos normalizar.
            r_type = rule.get('filters', ['unknown'])[0] if rule.get('filters') else 'unknown'
            # Alternativa: algumas versões da API têm campo 'type' direto, verificar JSON se necessário
           
            # Contar Ações (block, allow, log)
            action = rule.get('action', 'unknown')
           
            action_counts[action] = action_counts.get(action, 0) + 1
           
            # Imprimir detalhes de regras críticas (Opcional, pode poluir se forem muitas)
            # rule_id = rule.get('id')
            # rule_name = rule.get('name', 'unknown').replace(' ', '_')
            # enabled = rule.get('enabled', True)
            # print(f"gateway.rule.{rule_id}.name={rule_name}")
            # print(f"gateway.rule.{rule_id}.enabled={enabled}")
 
        # Imprimir agregados
        for action, count in action_counts.items():
            print(f"gateway.rules_action.{action}={count}")

    print()

def print_access_analytics_stats(analytics_data: Optional[Dict[str, Any]]) -> None:
    """Print Access Analytics statistics."""
    if not analytics_data:
        return
    
    print("\n<<<cloudflare_access_analytics>>>\n")
    
    # Extract metrics from analytics data
    # The structure may vary, so we'll handle different formats
    result_data = analytics_data.get('result', analytics_data)
    
    # Total access attempts
    total_attempts = result_data.get('total_attempts', 0)
    granted = result_data.get('granted', 0)
    denied = result_data.get('denied', 0)
    active_logins = result_data.get('active_logins', 0)
    
    print(f"access.analytics.total_attempts={total_attempts}")
    print(f"access.analytics.granted={granted}")
    print(f"access.analytics.denied={denied}")
    print(f"access.analytics.active_logins={active_logins}")
    
    # Top applications (if available)
    top_apps = result_data.get('top_applications', [])
    if top_apps:
        for idx, app in enumerate(top_apps[:10]):  # Limit to top 10
            app_name = app.get('name', 'unknown').replace(' ', '_')
            logins = app.get('logins', 0)
            print(f"access.analytics.top_app.{idx+1}.name={app_name}")
            print(f"access.analytics.top_app.{idx+1}.logins={logins}")
    
    print()

def print_gateway_http_analytics_stats(analytics_data: Optional[Dict[str, Any]]) -> None:
    """Print Gateway HTTP Traffic Analytics statistics."""
    if not analytics_data:
        return
    
    print("\n<<<cloudflare_gateway_http_analytics>>>\n")
    
    result_data = analytics_data.get('result', analytics_data)
    
    total_requests = result_data.get('total_requests', 0)
    allowed_requests = result_data.get('allowed_requests', 0)
    blocked_requests = result_data.get('blocked_requests', 0)
    isolated_requests = result_data.get('isolated_requests', 0)
    do_not_inspect = result_data.get('do_not_inspect', 0)
    
    print(f"gateway.http.total_requests={total_requests}")
    print(f"gateway.http.allowed={allowed_requests}")
    print(f"gateway.http.blocked={blocked_requests}")
    print(f"gateway.http.isolated={isolated_requests}")
    print(f"gateway.http.do_not_inspect={do_not_inspect}")
    
    # Top bandwidth consumers (if available)
    top_bandwidth = result_data.get('top_bandwidth_consumers', [])
    if top_bandwidth:
        for idx, consumer in enumerate(top_bandwidth[:10]):
            consumer_name = consumer.get('name', 'unknown').replace(' ', '_')
            bandwidth_gb = consumer.get('bandwidth_gb', 0)
            print(f"gateway.http.top_bandwidth.{idx+1}.name={consumer_name}")
            print(f"gateway.http.top_bandwidth.{idx+1}.gb={bandwidth_gb}")
    
    # Top denied users (if available)
    top_denied = result_data.get('top_denied_users', [])
    if top_denied:
        for idx, user in enumerate(top_denied[:10]):
            user_name = user.get('name', 'unknown').replace(' ', '_')
            denied_count = user.get('denied_count', 0)
            print(f"gateway.http.top_denied.{idx+1}.name={user_name}")
            print(f"gateway.http.top_denied.{idx+1}.count={denied_count}")
    
    print()

def print_gateway_network_analytics_stats(analytics_data: Optional[Dict[str, Any]]) -> None:
    """Print Gateway Network Traffic Analytics statistics."""
    if not analytics_data:
        return
    
    print("\n<<<cloudflare_gateway_network_analytics>>>\n")
    
    result_data = analytics_data.get('result', analytics_data)
    
    total_sessions = result_data.get('total_sessions', 0)
    authenticated_sessions = result_data.get('authenticated_sessions', 0)
    blocked_sessions = result_data.get('blocked_sessions', 0)
    audit_ssh_sessions = result_data.get('audit_ssh_sessions', 0)
    allowed_sessions = result_data.get('allowed_sessions', 0)
    override_sessions = result_data.get('override_sessions', 0)
    
    print(f"gateway.network.total_sessions={total_sessions}")
    print(f"gateway.network.authenticated={authenticated_sessions}")
    print(f"gateway.network.blocked={blocked_sessions}")
    print(f"gateway.network.audit_ssh={audit_ssh_sessions}")
    print(f"gateway.network.allowed={allowed_sessions}")
    print(f"gateway.network.override={override_sessions}")
    
    # Top bandwidth consumers (if available)
    top_bandwidth = result_data.get('top_bandwidth_consumers', [])
    if top_bandwidth:
        for idx, consumer in enumerate(top_bandwidth[:10]):
            consumer_name = consumer.get('name', 'unknown').replace(' ', '_')
            bandwidth_gb = consumer.get('bandwidth_gb', 0)
            print(f"gateway.network.top_bandwidth.{idx+1}.name={consumer_name}")
            print(f"gateway.network.top_bandwidth.{idx+1}.gb={bandwidth_gb}")
    
    # Top denied users (if available)
    top_denied = result_data.get('top_denied_users', [])
    if top_denied:
        for idx, user in enumerate(top_denied[:10]):
            user_name = user.get('name', 'unknown').replace(' ', '_')
            denied_count = user.get('denied_count', 0)
            print(f"gateway.network.top_denied.{idx+1}.name={user_name}")
            print(f"gateway.network.top_denied.{idx+1}.count={denied_count}")
    
    print()

def print_gateway_dns_analytics_stats(analytics_data: Optional[Dict[str, Any]]) -> None:
    """Print Gateway DNS Traffic Analytics statistics."""
    if not analytics_data:
        return
    
    print("\n<<<cloudflare_gateway_dns_analytics>>>\n")
    
    result_data = analytics_data.get('result', analytics_data)
    
    total_queries = result_data.get('total_queries', 0)
    allowed_queries = result_data.get('allowed_queries', 0)
    blocked_queries = result_data.get('blocked_queries', 0)
    override_queries = result_data.get('override_queries', 0)
    safe_search_queries = result_data.get('safe_search_queries', 0)
    restricted_queries = result_data.get('restricted_queries', 0)
    other_queries = result_data.get('other_queries', 0)
    
    print(f"gateway.dns.total_queries={total_queries}")
    print(f"gateway.dns.allowed={allowed_queries}")
    print(f"gateway.dns.blocked={blocked_queries}")
    print(f"gateway.dns.override={override_queries}")
    print(f"gateway.dns.safe_search={safe_search_queries}")
    print(f"gateway.dns.restricted={restricted_queries}")
    print(f"gateway.dns.other={other_queries}")
    
    print()

def print_zero_trust_seats_stats(seats_data: Optional[Dict[str, Any]]) -> None:
    """Print Zero Trust seat usage statistics."""
    if not seats_data:
        return
    
    print("\n<<<cloudflare_zero_trust_seats>>>\n")
    
    result_data = seats_data.get('result', seats_data)
    
    total_seats = result_data.get('total_seats', 0)
    used_seats = result_data.get('used_seats', 0)
    unused_seats = result_data.get('unused_seats', 0)
    
    print(f"zt.seats.total={total_seats}")
    print(f"zt.seats.used={used_seats}")
    print(f"zt.seats.unused={unused_seats}")
    
    # Calculate usage percentage
    if total_seats > 0:
        usage_percent = (used_seats / total_seats) * 100
        print(f"zt.seats.usage_percent={usage_percent:.2f}%")
    
    print()

def print_ssl_tls_stats(zones_data: Dict[str, Dict[str, Any]]) -> None:
    """Print SSL/TLS statistics."""
    if not zones_data:
        return
   
    print("\n<<<cloudflare_ssl_tls>>>\n")
    for zone_name, zone_info in zones_data.items():
        ssl_settings = zone_info.get('ssl_settings')
        if ssl_settings:
            ssl_status = ssl_settings.get('value', 'unknown')
            print(f"zone.{zone_name}.ssl_status={ssl_status}")
       
        # SSL info from zone data
        ssl_info = zone_info.get('ssl', {})
        if isinstance(ssl_info, dict):
            ssl_status_alt = ssl_info.get('status', 'unknown')
            if ssl_status_alt != 'unknown':
                print(f"zone.{zone_name}.ssl_status_alt={ssl_status_alt}")
       
        print()
 
 
def print_d1_stats(d1_data: List[Dict[str, Any]]) -> None:
    """Print D1 Databases statistics."""
    if not d1_data:
        return
    print("\n<<<cloudflare_d1>>>\n")
    print(f"d1.databases_total={len(d1_data)}")
    for db in d1_data:
        name = db.get('name', 'unknown')
        uuid = db.get('uuid', 'unknown')
        size = db.get('file_size', 0)
        created_at = db.get('created_at', '')
        version = db.get('version', '')
       
        print(f"d1.db.{name}.uuid={uuid}")
        print(f"d1.db.{name}.size={size}")
        if created_at:
            print(f"d1.db.{name}.created_at={created_at}")
        if version:
            print(f"d1.db.{name}.version={version}")
    print()
 
 
def print_secrets_stats(secrets_data: Dict[str, Any]) -> None:
    """Print Secrets Store statistics."""
    if not secrets_data:
        return
    print("\n<<<cloudflare_secrets>>>\n")
    print(f"secrets.stores_total={len(secrets_data)}")
    for store_name, info in secrets_data.items():
        print(f"secrets.store.{store_name}.id={info['id']}")
        print(f"secrets.store.{store_name}.secrets_count={info['count']}")
    print()
 
 
def print_firewall_stats(zones_data: Dict[str, Dict[str, Any]]) -> None:
    """Print Firewall/DDoS statistics."""
    has_data = False
    for zone_name, zone_info in zones_data.items():
        if zone_info.get('firewall_events'):
            has_data = True
            break
   
    if not has_data:
        return
   
    print("\n<<<cloudflare_firewall>>>\n")
    for zone_name, zone_info in zones_data.items():
        firewall_data = zone_info.get('firewall_events')
        if not firewall_data:
            continue
       
        blocked_total = 0
        challenged_total = 0
        allowed_total = 0
       
        events = firewall_data.get('events', []) if isinstance(firewall_data, dict) else []
        for event in events:
            action = event.get('action', '')
            if action == 'block':
                blocked_total += 1
            elif action == 'challenge':
                challenged_total += 1
            elif action == 'allow':
                allowed_total += 1
       
        print(f"zone.{zone_name}.firewall.blocked_total={blocked_total}")
        print(f"zone.{zone_name}.firewall.challenged_total={challenged_total}")
        print(f"zone.{zone_name}.firewall.allowed_total={allowed_total}")
        print(f"zone.{zone_name}.firewall.events_total={len(events)}")
        print()
 
def print_workers_pages_stats(workers_data: List[Dict[str, Any]], pages_data: List[Dict[str, Any]]) -> None:
    """Print Workers and Pages statistics."""
    if not workers_data and not pages_data:
        return
   
    if workers_data:
        print("\n<<<cloudflare_workers>>>\n")
        for worker in workers_data:
            worker_id = worker.get('id', 'unknown')
            worker_name = worker_id
            created_on = worker.get('created_on', '')
            modified_on = worker.get('modified_on', '')
            usage_model = worker.get('usage_model', '')
            etag = worker.get('etag', '')
           
            print(f"worker.{worker_name}.id={worker_id}")
            if created_on:
                print(f"worker.{worker_name}.created_on={created_on}")
            if modified_on:
                print(f"worker.{worker_name}.modified_on={modified_on}")
            if usage_model:
                print(f"worker.{worker_name}.usage_model={usage_model}")
            if etag:
                print(f"worker.{worker_name}.etag={etag}")
            print()
   
    if pages_data:
        print("\n<<<cloudflare_pages>>>\n")
        print(f"pages.projects_total={len(pages_data)}\n")
        for project in pages_data:
            project_name = project.get('name', 'unknown')
            project_id = project.get('id', '')
            created_on = project.get('created_on', '')
            production_branch = project.get('production_branch', 'unknown')
            latest_deployment = project.get('latest_deployment', {})
            domains = project.get('domains', [])
            build_config = project.get('build_config', {})
           
            print(f"pages.project.{project_name}.id={project_id}")
            print(f"pages.project.{project_name}.created_on={created_on}")
            print(f"pages.project.{project_name}.production_branch={production_branch}")
           
            # Additional fields if available
            if latest_deployment and isinstance(latest_deployment, dict):
                latest_deployment_id = latest_deployment.get('id', '')
                latest_deployment_status = latest_deployment.get('latest_stage', {}).get('status', '') if isinstance(latest_deployment.get('latest_stage'), dict) else ''
                if latest_deployment_id:
                    print(f"pages.project.{project_name}.latest_deployment_id={latest_deployment_id}")
                if latest_deployment_status:
                    print(f"pages.project.{project_name}.latest_deployment_status={latest_deployment_status}")
           
            if domains and isinstance(domains, list):
                domains_count = len(domains)
                print(f"pages.project.{project_name}.domains_count={domains_count}")
           
            if build_config and isinstance(build_config, dict):
                build_command = build_config.get('build_command', '')
                if build_command:
                    print(f"pages.project.{project_name}.build_command={build_command}")
            print()
 
async def main(argv: Optional[List[str]] = None) -> None:
    """Main function to fetch and calculate metrics for Cloudflare resources."""
    if argv is None:
        argv = sys.argv[1:]
   
    args = parse_arguments(argv)
    setup_logging(args.verbose)
   
    # Validate authentication
    if not args.api_token and not args.api_key:
        logging.error("Either --api-token or --api-key must be provided")
        sys.exit(1)
   
    # Prepare headers
    headers = {
        'Content-Type': 'application/json'
    }
   
    if args.api_token:
        headers['Authorization'] = f'Bearer {args.api_token}'
    else:
        headers['X-Auth-Email'] = args.email
        headers['X-Auth-Key'] = args.api_key
   
    async with aiohttp.ClientSession() as session:
        try:
            # ---------------------------------------------------------
            # 1. Determine flags (WHAT to fetch)
            # ---------------------------------------------------------
            if args.all:
                fetch_cdn_cache = True
                fetch_dns = True
                fetch_ssl_tls = True
                fetch_firewall = True
                fetch_workers_pages = True
                fetch_d1 = True
                fetch_secrets = True
                fetch_warp_devices = True
                fetch_access_apps = True
                fetch_gateway = True
                fetch_analytics = True
            else:
                fetch_cdn_cache = args.cdn_cache
                fetch_dns = args.dns
                fetch_ssl_tls = args.ssl_tls
                fetch_firewall = args.firewall
                fetch_workers_pages = args.workers_pages
                fetch_d1 = args.d1
                fetch_secrets = args.secrets
                fetch_warp_devices = args.devices
                fetch_access_apps = args.apps
                fetch_gateway = args.gateway
                fetch_analytics = args.analytics
           
            # Default: fetch all if no specific flags are set
            # (Updated to include new flags in the check)
            if not any([fetch_cdn_cache, fetch_dns, fetch_ssl_tls, fetch_firewall,
                       fetch_workers_pages, fetch_d1, fetch_secrets,
                       fetch_warp_devices, fetch_access_apps, fetch_gateway, fetch_analytics]):
                fetch_cdn_cache = True
                fetch_dns = True
                fetch_ssl_tls = True
                fetch_firewall = True
                fetch_workers_pages = True
                fetch_d1 = True
                fetch_secrets = True
                fetch_warp_devices = True
                fetch_access_apps = True
                fetch_gateway = True
                fetch_analytics = True
           
            # ---------------------------------------------------------
            # 2. Initialize Data Containers
            # ---------------------------------------------------------
            zones_data = {}
            workers_data = []
            pages_data = []
            d1_data = []
            secrets_data = {}
            warp_devices_data = []
            access_apps_data = []
            gateway_account_data = None
            gateway_rules_data = []
            access_analytics_data = None
            gateway_http_analytics_data = None
            gateway_network_analytics_data = None
            gateway_dns_analytics_data = None
            zero_trust_seats_data = None

            since = datetime.now(timezone.utc) - timedelta(hours=24)
           
            # ---------------------------------------------------------
            # 3. Zone Level Resources Fetching
            # ---------------------------------------------------------
            if fetch_cdn_cache or fetch_dns or fetch_ssl_tls or fetch_firewall:
                zones = await get_zones(session, headers, args.timeout, args.verbose)
               
                if zones:
                    for zone in zones:
                        zone_id = zone.get('id', '')
                        zone_name = zone.get('name', 'unknown')
                       
                        if zone_name == 'unknown' or not zone_id:
                            continue
                       
                        zones_data[zone_name] = zone.copy()
                       
                        if fetch_cdn_cache:
                            cache_settings = await get_zone_cache_settings(session, zone_id, headers, args.timeout)
                            if cache_settings:
                                zones_data[zone_name]['cache_settings'] = cache_settings
                           
                            analytics = await get_zone_analytics(session, zone_id, headers, args.timeout, since, args.verbose)
                            if analytics:
                                zones_data[zone_name]['analytics'] = analytics
                            elif args.verbose:
                                logging.warning(f"No analytics data returned for zone {zone_name} (ID: {zone_id})")
                       
                        if fetch_dns:
                            dns_records = await get_zone_dns_records(session, zone_id, headers, args.timeout)
                            zones_data[zone_name]['dns_records'] = dns_records
                            zones_data[zone_name]['dns_records_count'] = len(dns_records)
                       
                        if fetch_ssl_tls:
                            ssl_settings = await get_zone_ssl_settings(session, zone_id, headers, args.timeout)
                            if ssl_settings:
                                zones_data[zone_name]['ssl_settings'] = ssl_settings
                       
                        if fetch_firewall:
                            firewall_events = await get_firewall_events(session, zone_id, headers, args.timeout, since, args.verbose)
                            if firewall_events:
                                zones_data[zone_name]['firewall_events'] = firewall_events
           
            # ---------------------------------------------------------
            # 4. Account Level Resources Fetching
            # ---------------------------------------------------------
            # Grouping all account-level checks to fetch account_id only once
            fetch_account_resources = any([
                fetch_workers_pages,
                fetch_d1,
                fetch_secrets,
                fetch_warp_devices,
                fetch_access_apps
            ])
 
            if fetch_account_resources:
                account_id = args.account_id
                # Auto-detect account ID if not provided
                if not account_id:
                    account_id = await get_account_id(session, headers, args.timeout, args.verbose)
                    if account_id and args.verbose:
                        logging.debug(f"Auto-detected account ID: {account_id}")
               
                if account_id:
                    # Workers & Pages
                    if fetch_workers_pages:
                        workers_data = await get_workers(session, account_id, headers, args.timeout, args.verbose)
                        pages_data = await get_pages_projects(session, account_id, headers, args.timeout, args.verbose)
                   
                    # D1 Databases
                    if fetch_d1:
                        d1_data = await get_d1_databases(session, account_id, headers, args.timeout, args.verbose)
 
                    # Secrets
                    if fetch_secrets:
                        secrets_data = await get_secrets_store(session, account_id, headers, args.timeout, args.verbose)
 
                    # Zero Trust: Devices (NEW) Mateus
                    if fetch_warp_devices:
                        warp_devices_data = await get_warp_devices(session, account_id, headers, args.timeout, args.verbose)
 
                    # Zero Trust: Access Apps (NEW) Mateus
                    if fetch_access_apps:
                        # Nota: Certifique-se que a função get_apps está definida corretamente no script
                        access_apps_data = await get_apps(session, account_id, headers, args.timeout, args.verbose)
 
                    # Zero Trust: Gateway (NEW) Mateus
                    if fetch_gateway:
                        gateway_account_data = await get_gateway_account(session, account_id, headers, args.timeout, args.verbose)
                        gateway_rules_data = await get_gateway_rules(session, account_id, headers, args.timeout, args.verbose)
            
            # ---------------------------------------------------------
            # 4.5. Analytics Resources Fetching
            # ---------------------------------------------------------
            if fetch_analytics:
                # Need account_id for analytics
                if not account_id:
                    account_id = args.account_id
                    if not account_id:
                        account_id = await get_account_id(session, headers, args.timeout, args.verbose)
                
                if account_id:
                    # Access Analytics
                    access_analytics_data = await get_access_analytics(session, account_id, headers, args.timeout, since, args.verbose)
                    
                    # Gateway HTTP Analytics
                    gateway_http_analytics_data = await get_gateway_http_analytics(session, account_id, headers, args.timeout, since, args.verbose)
                    
                    # Gateway Network Analytics
                    gateway_network_analytics_data = await get_gateway_network_analytics(session, account_id, headers, args.timeout, since, args.verbose)
                    
                    # Gateway DNS Analytics
                    gateway_dns_analytics_data = await get_gateway_dns_analytics(session, account_id, headers, args.timeout, since, args.verbose)
                    
                    # Zero Trust Seats
                    zero_trust_seats_data = await get_zero_trust_seats(session, account_id, headers, args.timeout, args.verbose)
           
            # ---------------------------------------------------------
            # 5. Output / Printing
            # ---------------------------------------------------------
            print_cdn_cache_stats(zones_data)
            print_dns_stats(zones_data)
            print_ssl_tls_stats(zones_data)
            print_firewall_stats(zones_data)
            print_workers_pages_stats(workers_data, pages_data)
            print_d1_stats(d1_data)
            print_secrets_stats(secrets_data)
            print_warp_device_stats(warp_devices_data)
            print_apps_stats(access_apps_data)
            print_gateway_stats(gateway_account_data, gateway_rules_data)
            print_access_analytics_stats(access_analytics_data)
            print_gateway_http_analytics_stats(gateway_http_analytics_data)
            print_gateway_network_analytics_stats(gateway_network_analytics_data)
            print_gateway_dns_analytics_stats(gateway_dns_analytics_data)
            print_zero_trust_seats_stats(zero_trust_seats_data)
           
            # Check for empty data
            total_items = (len(zones_data) + len(workers_data) + len(pages_data) +
                           len(d1_data) + len(secrets_data) +
                           len(warp_devices_data) + len(access_apps_data))
           
            if total_items == 0:
                logging.warning("No data collected. Check if you have resources configured or verify API permissions.")
           
        except Exception as e:
            logging.error(f"Main execution failed: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
 
if __name__ == "__main__":
    asyncio.run(main())
 