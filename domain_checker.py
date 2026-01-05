#!/usr/bin/env python3
"""
Domain Checker Script
Checks SSL certificate expiry dates, domain expiry, health status, and response time for one or more domains.
"""

import sys
import json
import socket
import ssl
import argparse
import os
import time
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


# Pre-compile patterns and formats for better performance
EXPIRY_PATTERNS = [
    'registry expiry date:',
    'expiry date:',
    'expiration date:',
    'expires:',
    'expires on:',
    'expiration:',
    'paid-till:',
    'expire:',
    'expiry:',
    'registrar registration expiration date:',
    'expiration date',
]

DATE_FORMATS = [
    '%Y-%m-%dT%H:%M:%SZ',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%d',
    '%d-%b-%Y',
    '%d %b %Y',
    '%b %d %Y',
    '%Y/%m/%d',
    '%d/%m/%Y',
    '%m/%d/%Y',
    '%d.%m.%Y',
    '%Y.%m.%d',
    '%Y%m%d',
]

TIMEZONE_SUFFIXES = ['(utc)', '(gmt)', 'utc', 'gmt', '+00:00', '-00:00']

# Cache configuration - can be overridden via CACHE_DIR environment variable
CACHE_BASE_DIR = os.getenv('CACHE_DIR', '/tmp/ssl-checker-cache')
CACHE_DIR = Path(CACHE_BASE_DIR)
CACHE_FILE = CACHE_DIR / 'cache.json'
CACHE_EXPIRY_THRESHOLD_DAYS = 2  # Threshold for different refresh intervals
CACHE_REFRESH_INTERVAL_EXPIRING_HOURS = 1  # Refresh once per hour if expires in <= 2 days
CACHE_REFRESH_INTERVAL_STABLE_HOURS = 24  # Refresh once per day if expires in > 2 days


def load_cache() -> Dict[str, Dict[str, Any]]:
    """Load cache from file."""
    if not CACHE_FILE.exists():
        return {}
    try:
        with open(CACHE_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def save_cache(cache: Dict[str, Dict[str, Any]]) -> None:
    """Save cache to file."""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f)
    except IOError:
        pass  # Silently fail if cache can't be written


def should_refresh_cache(cached_entry: Dict[str, Any]) -> bool:
    """
    Determine if cache entry should be refreshed using smart caching.
    
    Returns True if:
    - Cache entry is invalid/missing required fields
    - Expires in > 2 days AND last check was >= 24 hours ago (refresh once per day)
    - Expires in <= 2 days AND last check was >= 1 hour ago (refresh once per hour)
    
    Returns False if:
    - Expires in > 2 days AND last check was < 24 hours ago (use cache)
    - Expires in <= 2 days AND last check was < 1 hour ago (use cache)
    """
    if not cached_entry:
        return True
    
    # Check if required fields exist
    if 'ssl_days_left' not in cached_entry or 'last_checked' not in cached_entry:
        return True
    
    ssl_days_left = cached_entry.get('ssl_days_left', 999)
    last_checked_str = cached_entry.get('last_checked')
    
    if not last_checked_str:
        return True
    
    try:
        last_checked = datetime.fromisoformat(last_checked_str.replace('Z', '+00:00'))
        if last_checked.tzinfo is None:
            last_checked = last_checked.replace(tzinfo=timezone.utc)
        
        hours_since_check = (datetime.now(timezone.utc) - last_checked).total_seconds() / 3600
        
        # If expires in <= 2 days, refresh if last check was >= 1 hour ago
        if ssl_days_left <= CACHE_EXPIRY_THRESHOLD_DAYS:
            return hours_since_check >= CACHE_REFRESH_INTERVAL_EXPIRING_HOURS
        
        # If expires in > 2 days, refresh if last check was >= 24 hours ago
        return hours_since_check >= CACHE_REFRESH_INTERVAL_STABLE_HOURS
    except (ValueError, TypeError):
        return True


def get_cached_domain_expiry(main_domain: str) -> Optional[str]:
    """
    Get cached domain expiry for main domain using smart caching.
    
    Smart caching logic:
    - If domain expires in > 2 days: Refresh if last check was >= 24 hours ago (once per day)
    - If domain expires in <= 2 days: Refresh if last check was >= 1 hour ago (once per hour)
    - Never return cached result if it has an error (e.g., "No WHOIS output received")
    """
    cache = load_cache()
    cached_entry = cache.get(main_domain)
    
    if not cached_entry or 'domain_expiry_date' not in cached_entry:
        return None
    
    # Check if cached entry has an error - don't use cache if it does
    if 'domain_check_details' in cached_entry:
        whois_info = cached_entry['domain_check_details'].get('whois_info', {})
        if whois_info.get('error'):
            # Don't return cached result if there's an error
            return None
    
    last_checked_str = cached_entry.get('last_checked')
    if not last_checked_str:
        # If no timestamp, assume it's valid (backward compatibility)
        return cached_entry.get('domain_expiry_date')
    
    try:
        last_checked = datetime.fromisoformat(last_checked_str.replace('Z', '+00:00'))
        if last_checked.tzinfo is None:
            last_checked = last_checked.replace(tzinfo=timezone.utc)
        
        hours_since_check = (datetime.now(timezone.utc) - last_checked).total_seconds() / 3600
        
        # Get domain days left from cache
        domain_days_left = cached_entry.get('domain_days_left')
        if domain_days_left is None:
            # If days left not in cache, try to calculate from expiry date
            try:
                expiry_date_str = cached_entry.get('domain_expiry_date')
                if expiry_date_str:
                    expiry_dt = datetime.strptime(expiry_date_str, '%Y-%m-%d %H:%M:%S')
                    expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    domain_days_left = (expiry_dt - now).days
            except (ValueError, TypeError):
                # If we can't calculate, use cache anyway (backward compatibility)
                return cached_entry.get('domain_expiry_date')
        
        # Smart caching: same logic as SSL caching
        # If domain expires in <= 2 days, refresh if last check was >= 1 hour ago
        if domain_days_left is not None and domain_days_left <= CACHE_EXPIRY_THRESHOLD_DAYS:
            if hours_since_check >= CACHE_REFRESH_INTERVAL_EXPIRING_HOURS:
                return None  # Need to refresh
            else:
                return cached_entry.get('domain_expiry_date')  # Use cache
        
        # If domain expires in > 2 days, refresh if last check was >= 24 hours ago
        if hours_since_check >= CACHE_REFRESH_INTERVAL_STABLE_HOURS:
            return None  # Need to refresh
        
        return cached_entry.get('domain_expiry_date')  # Use cache
        
    except (ValueError, TypeError):
        # If parsing fails, return cached value (backward compatibility)
        return cached_entry.get('domain_expiry_date')


def save_domain_expiry_to_cache(main_domain: str, domain_expiry: str, domain_days_left: int, whois_details: Optional[Dict[str, Any]] = None) -> None:
    """
    Save domain expiry to cache using main domain as key.
    
    Note: This function should only be called when domain_expiry is valid and whois_details has no error.
    """
    cache = load_cache()
    
    # Get or create entry for main domain
    if main_domain not in cache:
        cache[main_domain] = {}
    
    # Only save if there's no error in whois_details
    if whois_details and whois_details.get('error'):
        # Don't cache entries with errors
        return
    
    cache[main_domain]['domain_expiry_date'] = domain_expiry
    cache[main_domain]['domain_days_left'] = domain_days_left
    cache[main_domain]['last_checked'] = datetime.now(timezone.utc).isoformat()
    
    # Save WHOIS details if provided (and no error)
    if whois_details and not whois_details.get('error'):
        if 'domain_check_details' not in cache[main_domain]:
            cache[main_domain]['domain_check_details'] = {}
        cache[main_domain]['domain_check_details']['whois_info'] = whois_details
    
    save_cache(cache)


def get_cached_result(domain: str) -> Optional[Dict[str, Any]]:
    """Get cached result for domain if valid, otherwise None."""
    cache = load_cache()
    cached_entry = cache.get(domain)
    main_domain = _get_main_domain(domain)
    
    # Check if we have a valid cache entry for this specific domain
    if cached_entry and not should_refresh_cache(cached_entry):
        # Return cached result (remove cache metadata)
        result = {k: v for k, v in cached_entry.items() if k != 'last_checked'}
        
        # Always check for domain expiry from main domain cache if domain is a subdomain
        # This ensures we get domain expiry even if it wasn't in the subdomain cache
        if main_domain != domain:
            main_domain_expiry = get_cached_domain_expiry(main_domain)
            if main_domain_expiry:
                result['domain_expiry_date'] = main_domain_expiry
                # Get days left from main domain cache
                main_domain_entry = cache.get(main_domain, {})
                if 'domain_days_left' in main_domain_entry:
                    result['domain_days_left'] = main_domain_entry['domain_days_left']
                # Get domain check details from main domain cache
                if 'domain_check_details' in main_domain_entry:
                    result['domain_check_details'] = main_domain_entry['domain_check_details'].copy()
                    result['domain_check_details']['checked_domain'] = domain
        
        return result
    
    # Even if domain-specific cache doesn't exist, check main domain cache for domain expiry
    if main_domain != domain:
        main_domain_expiry = get_cached_domain_expiry(main_domain)
        if main_domain_expiry:
            # Return partial result with domain expiry from cache
            # This allows us to skip whois lookup even if SSL cache doesn't exist
            main_domain_entry = cache.get(main_domain, {})
            result = {
                'domain_expiry_date': main_domain_expiry,
                'domain_days_left': main_domain_entry.get('domain_days_left')
            }
            # Include domain check details if available
            if 'domain_check_details' in main_domain_entry:
                result['domain_check_details'] = main_domain_entry['domain_check_details'].copy()
                result['domain_check_details']['checked_domain'] = domain
            return result
    
    return None


def save_to_cache(domain: str, result: Dict[str, Any]) -> None:
    """Save check result to cache."""
    cache = load_cache()
    result_with_timestamp = result.copy()
    result_with_timestamp['last_checked'] = datetime.now(timezone.utc).isoformat()
    cache[domain] = result_with_timestamp
    
    # Also save domain expiry to main domain cache if present
    if 'domain_expiry_date' in result:
        main_domain = _get_main_domain(domain)
        if main_domain != domain:
            save_domain_expiry_to_cache(
                main_domain,
                result['domain_expiry_date'],
                result.get('domain_days_left', 0)
            )
    
    save_cache(cache)


def clear_cache(domains: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Clear cache for specific domains or all domains.
    
    Args:
        domains: List of domains to clear cache for. If None or empty, clears all cache.
                 Can include subdomains - will clear both subdomain and main domain cache.
    
    Returns:
        Dictionary with cleared domains count and status
    """
    cache = load_cache()
    
    if not domains or len(domains) == 0:
        # Clear all cache
        cleared_count = len(cache)
        cache.clear()
        save_cache(cache)
        return {
            "status": "success",
            "action": "cleared_all",
            "domains_cleared": cleared_count,
            "message": f"Cleared cache for all {cleared_count} domain(s)"
        }
    
    # Clear specific domains
    cleared_domains = []
    main_domains_to_clear = set()
    
    for domain in domains:
        clean_domain = _clean_domain(domain)
        main_domain = _get_main_domain(clean_domain)
        
        # Remove domain-specific cache
        if clean_domain in cache:
            del cache[clean_domain]
            cleared_domains.append(clean_domain)
        
        # Also clear main domain cache (for domain expiry)
        if main_domain in cache:
            main_domains_to_clear.add(main_domain)
    
    # Remove main domain cache entries
    for main_domain in main_domains_to_clear:
        if main_domain in cache:
            del cache[main_domain]
            if main_domain not in cleared_domains:
                cleared_domains.append(main_domain)
    
    save_cache(cache)
    
    return {
        "status": "success",
        "action": "cleared_specific",
        "domains_cleared": len(cleared_domains),
        "cleared_domains": cleared_domains,
        "message": f"Cleared cache for {len(cleared_domains)} domain(s)"
    }


def _clean_domain(domain: str) -> str:
    """Clean domain name - remove protocol and trailing slashes."""
    return domain.replace('https://', '').replace('http://', '').strip('/')


def _get_main_domain(domain: str) -> str:
    """
    Extract main domain from subdomain.
    Examples:
    - pro.mytallyho.net -> mytallyho.net
    - www.example.com -> example.com
    - example.co.uk -> example.co.uk (handles multi-part TLDs)
    """
    clean_domain = _clean_domain(domain)
    
    # Split domain into parts
    parts = clean_domain.split('.')
    
    # Common multi-part TLDs (add more if needed)
    multi_part_tlds = ['co.uk', 'com.au', 'co.nz', 'com.br', 'co.za', 'com.mx']
    
    # Check if it's a multi-part TLD
    if len(parts) >= 3:
        last_two = '.'.join(parts[-2:])
        if last_two in multi_part_tlds:
            # For multi-part TLDs, we need at least 3 parts (subdomain.domain.tld)
            if len(parts) >= 3:
                return '.'.join(parts[-3:])
    
    # For standard domains, return last 2 parts (domain.tld)
    # If only 2 parts, return as-is (already main domain)
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    
    return clean_domain


def _parse_expiry_date(date_part: str) -> Optional[str]:
    """Parse expiry date from string using multiple formats."""
    # Clean up the date string
    date_part = date_part.split('\n')[0].split('\t')[0].split('#')[0].split(';')[0].strip()
    
    # Handle ISO format with milliseconds (e.g., "2026-08-06T23:59:59.0Z")
    if '.0Z' in date_part or '.Z' in date_part:
        date_part = date_part.replace('.0Z', 'Z').replace('.Z', 'Z')
    
    # Remove timezone suffixes (but keep Z for ISO format)
    for suffix in TIMEZONE_SUFFIXES:
        if date_part.lower().endswith(suffix.lower()):
            date_part = date_part[:-len(suffix)].strip()
    date_part = date_part.strip('()').strip()
    
    # Try parsing with various formats
    date_str = date_part.split()[0] if date_part.split() else date_part
    for fmt in DATE_FORMATS:
        try:
            parsed_date = datetime.strptime(date_str, fmt)
            parsed_date = parsed_date.replace(tzinfo=timezone.utc)
            return parsed_date.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, IndexError):
            continue
    return None


def check_domain_expiry(domain: str) -> Tuple[Optional[str], Dict[str, Any]]:
    """
    Check domain expiry date using whois.
    Follows WHOIS referrals (like whois.registry.co for .co domains) similar to
    https://github.com/ak545/dns-domain-expiration-checker
    
    Args:
        domain: Domain name to check
        
    Returns:
        Tuple of (domain expiry date string in YYYY-MM-DD HH:MM:SS format or None, details dict)
    """
    details = {
        "whois_server": None,
        "registrar": None,
        "registration_date": None,
        "last_updated": None,
        "name_servers": [],
        "domain_status": [],
        "raw_whois_preview": "",  # First 500 chars of raw output
        "error": None
    }
    
    try:
        clean_domain = _clean_domain(domain)
        whois_output = ""
        whois_server = None
        
        # First attempt: query default WHOIS server
        result = subprocess.run(
            ['whois', clean_domain],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Known TLD-specific WHOIS servers (fallback if default whois fails)
        tld_whois_servers = {
            'co': 'whois.registry.co',
            'uk': 'whois.nominet.uk',
            'au': 'whois.aunic.net',
            'nz': 'whois.dnc.org.nz',
        }
        
        # Extract TLD for fallback lookup
        domain_parts = clean_domain.split('.')
        tld = domain_parts[-1].lower() if len(domain_parts) > 1 else None
        
        if result.stdout:
            whois_output = result.stdout
            whois_lower = whois_output.lower()
            
            # Check for referral to another WHOIS server (common for .co, .uk, etc.)
            # Look for patterns like "refer: whois.registry.co" or "whois: whois.registry.co"
            referral_patterns = [
                'refer:',
                'whois:',
                'whois server:',
                'registrar whois server:'
            ]
            
            for pattern in referral_patterns:
                if pattern in whois_lower:
                    for line in whois_output.split('\n'):
                        line_lower = line.lower()
                        if pattern in line_lower:
                            # Extract WHOIS server from referral
                            parts = line.split(':', 1)
                            if len(parts) > 1:
                                potential_server = parts[1].strip().split()[0].strip()
                                # Validate it looks like a hostname
                                if '.' in potential_server and not potential_server.startswith('http'):
                                    whois_server = potential_server
                                    break
                    if whois_server:
                        break
            
            # If we found a referral and haven't found expiry date yet, query the referred server
            if whois_server and 'registry expiry date:' not in whois_lower and 'expiry date:' not in whois_lower:
                # Query the referred WHOIS server directly
                referral_result = subprocess.run(
                    ['whois', '-h', whois_server, clean_domain],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if referral_result.stdout:
                    whois_output = referral_result.stdout
                    details["whois_server"] = whois_server
        elif tld and tld in tld_whois_servers:
            # Fallback: if default whois failed and we know the TLD-specific server, try it
            fallback_server = tld_whois_servers[tld]
            fallback_result = subprocess.run(
                ['whois', '-h', fallback_server, clean_domain],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if fallback_result.stdout:
                whois_output = fallback_result.stdout
                details["whois_server"] = fallback_server
        
        if not whois_output:
            details["error"] = "No WHOIS output received"
            return None, details
        
        details["raw_whois_preview"] = whois_output[:500]  # First 500 chars
        
        whois_lower = whois_output.lower()
        
        # Extract additional information from WHOIS output
        lines = whois_output.split('\n')
        for line in lines:
            line_lower = line.lower().strip()
            
            # Extract registrar
            if 'registrar:' in line_lower and not details["registrar"]:
                details["registrar"] = line.split(':', 1)[1].strip() if ':' in line else None
            
            # Extract registration date
            if 'registration date:' in line_lower or 'created date:' in line_lower or 'created:' in line_lower:
                if not details["registration_date"]:
                    date_part = line.split(':', 1)[1].strip() if ':' in line else ''
                    parsed_date = _parse_expiry_date(date_part)
                    if parsed_date:
                        details["registration_date"] = parsed_date
            
            # Extract last updated date
            if 'updated date:' in line_lower or 'last updated:' in line_lower:
                if not details["last_updated"]:
                    date_part = line.split(':', 1)[1].strip() if ':' in line else ''
                    parsed_date = _parse_expiry_date(date_part)
                    if parsed_date:
                        details["last_updated"] = parsed_date
            
            # Extract name servers
            if 'name server:' in line_lower or 'nameserver:' in line_lower:
                ns = line.split(':', 1)[1].strip().lower() if ':' in line else ''
                if ns and ns not in details["name_servers"]:
                    details["name_servers"].append(ns)
            
            # Extract domain status
            if 'domain status:' in line_lower or 'status:' in line_lower:
                status = line.split(':', 1)[1].strip() if ':' in line else ''
                if status and status not in details["domain_status"]:
                    details["domain_status"].append(status)
            
            # Extract WHOIS server
            if 'whois server:' in line_lower:
                if not details["whois_server"]:
                    details["whois_server"] = line.split(':', 1)[1].strip() if ':' in line else None
        
        # Search for expiry date patterns - stop at first match
        for pattern in EXPIRY_PATTERNS:
            pattern_lower = pattern.lower()
            if pattern_lower not in whois_lower:
                continue
            
            # Find matching line
            for line in lines:
                line_lower = line.lower()
                if pattern_lower in line_lower:
                    idx = line_lower.find(pattern_lower)
                    if idx >= 0:
                        date_part = line[idx + len(pattern):].strip()
                        parsed_date = _parse_expiry_date(date_part)
                        if parsed_date:
                            return parsed_date, details
        
        details["error"] = "Expiry date not found in WHOIS output"
        return None, details
        
    except subprocess.TimeoutExpired:
        details["error"] = "WHOIS query timeout (10 seconds)"
        return None, details
    except FileNotFoundError:
        details["error"] = "WHOIS command not found"
        return None, details
    except Exception as e:
        details["error"] = f"Unexpected error: {str(e)}"
        return None, details


def check_health_and_response_time(domain: str) -> Dict[str, Any]:
    """
    Check HTTP/HTTPS health status and measure response time.
    SSL certificate verification is disabled for health checks to handle
    domains with self-signed or invalid certificates.
    
    Args:
        domain: Domain name to check
        
    Returns:
        Dictionary with health_status, response_time_ms, and detailed health_check_info
    """
    clean_domain = _clean_domain(domain)
    result = {
        "health_status": "UNKNOWN",
        "response_time_ms": None,
        "health_check_details": {
            "protocol_attempted": [],
            "final_protocol": None,
            "final_url": None,
            "status_code": None,
            "response_headers": {},
            "connection_info": {},
            "error": None
        }
    }
    
    # Create SSL context that doesn't verify certificates for health checks
    ssl_context = ssl._create_unverified_context()
    
    # Try HTTPS first, then HTTP
    for protocol in ['https', 'http']:
        url = f"{protocol}://{clean_domain}"
        result["health_check_details"]["protocol_attempted"].append(protocol)
        start_time = time.time()
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'SSL-Checker/1.0'})
            
            # Use SSL context for HTTPS, normal for HTTP
            if protocol == 'https':
                # Create opener with unverified SSL context
                https_handler = urllib.request.HTTPSHandler(context=ssl_context)
                opener = urllib.request.build_opener(https_handler)
                with opener.open(req, timeout=8) as response:
                    elapsed_time = (time.time() - start_time) * 1000
                    status_code = response.getcode()
                    result["health_status"] = "UP" if 200 <= status_code < 400 else "DOWN"
                    result["response_time_ms"] = round(elapsed_time, 2)
                    
                    # Add detailed information
                    result["health_check_details"]["final_protocol"] = "HTTPS"
                    result["health_check_details"]["final_url"] = response.geturl()
                    result["health_check_details"]["status_code"] = status_code
                    
                    # Extract important headers
                    headers = dict(response.headers)
                    result["health_check_details"]["response_headers"] = {
                        "content-type": headers.get("Content-Type", ""),
                        "content-length": headers.get("Content-Length", ""),
                        "server": headers.get("Server", ""),
                        "date": headers.get("Date", ""),
                        "location": headers.get("Location", "")  # For redirects
                    }
                    
                    # Connection info
                    result["health_check_details"]["connection_info"] = {
                        "protocol": "HTTPS",
                        "ssl_verified": False,  # We're using unverified context
                        "response_time_ms": round(elapsed_time, 2)
                    }
                    
                    return result
            else:
                # HTTP - no SSL needed
                with urllib.request.urlopen(req, timeout=8) as response:
                    elapsed_time = (time.time() - start_time) * 1000
                    status_code = response.getcode()
                    result["health_status"] = "UP" if 200 <= status_code < 400 else "DOWN"
                    result["response_time_ms"] = round(elapsed_time, 2)
                    
                    # Add detailed information
                    result["health_check_details"]["final_protocol"] = "HTTP"
                    result["health_check_details"]["final_url"] = response.geturl()
                    result["health_check_details"]["status_code"] = status_code
                    
                    # Extract important headers
                    headers = dict(response.headers)
                    result["health_check_details"]["response_headers"] = {
                        "content-type": headers.get("Content-Type", ""),
                        "content-length": headers.get("Content-Length", ""),
                        "server": headers.get("Server", ""),
                        "date": headers.get("Date", ""),
                        "location": headers.get("Location", "")  # For redirects
                    }
                    
                    # Connection info
                    result["health_check_details"]["connection_info"] = {
                        "protocol": "HTTP",
                        "response_time_ms": round(elapsed_time, 2)
                    }
                    
                    return result
        except urllib.error.HTTPError as e:
            elapsed_time = (time.time() - start_time) * 1000
            status_code = e.code
            result["health_status"] = "UP" if 200 <= status_code < 500 else "DOWN"
            result["response_time_ms"] = round(elapsed_time, 2)
            
            # Add detailed information for HTTP errors
            result["health_check_details"]["final_protocol"] = protocol.upper()
            result["health_check_details"]["final_url"] = e.url if hasattr(e, 'url') else url
            result["health_check_details"]["status_code"] = status_code
            result["health_check_details"]["error"] = f"HTTP {status_code}: {e.reason}"
            
            # Extract headers from error response
            if hasattr(e, 'headers'):
                headers = dict(e.headers)
                result["health_check_details"]["response_headers"] = {
                    "content-type": headers.get("Content-Type", ""),
                    "server": headers.get("Server", ""),
                    "date": headers.get("Date", "")
                }
            
            return result
        except urllib.error.URLError as e:
            result["health_check_details"]["error"] = f"URL Error ({protocol}): {str(e)}"
            continue
        except socket.timeout:
            result["health_check_details"]["error"] = f"Connection timeout ({protocol})"
            continue
        except ssl.SSLError as e:
            result["health_check_details"]["error"] = f"SSL Error ({protocol}): {str(e)}"
            continue
        except Exception as e:
            result["health_check_details"]["error"] = f"Unexpected error ({protocol}): {str(e)}"
            continue
    
    result["health_status"] = "DOWN"
    result["health_check_details"]["error"] = "All connection attempts failed"
    return result


def _perform_ssl_check(clean_domain: str, now: datetime) -> Dict[str, Any]:
    """Perform actual SSL check (internal function)."""
    result = {
        "ssl_check_details": {
            "certificate": {},
            "connection": {},
            "error": None
        }
    }
    
    # Check SSL certificate
    try:
        context = ssl.create_default_context()
        with socket.create_connection((clean_domain, 443), timeout=8) as sock:
            # Get IP address before SSL handshake
            ip_address = sock.getpeername()[0]
            
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date_str = cert['notAfter']
                expiry_date = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
                expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                days_left = (expiry_date - now).days
                
                result["ssl_expiry_date"] = expiry_date.strftime('%Y-%m-%d %H:%M:%S')
                result["ssl_days_left"] = days_left
                result["ssl_status"] = "EXPIRED" if days_left < 0 else ("EXPIRING" if days_left <= 30 else "OK")
                
                # Extract detailed certificate information
                result["ssl_check_details"]["certificate"] = {
                    "subject": dict(x[0] for x in cert.get('subject', [])),
                    "issuer": dict(x[0] for x in cert.get('issuer', [])),
                    "serial_number": cert.get('serialNumber', ''),
                    "version": cert.get('version', ''),
                    "not_before": cert.get('notBefore', ''),
                    "not_after": cert.get('notAfter', ''),
                    "subject_alt_name": cert.get('subjectAltName', []),
                    "fingerprint": cert.get('fingerprint', '') if 'fingerprint' in cert else 'N/A'
                }
                
                # Connection details
                result["ssl_check_details"]["connection"] = {
                    "ip_address": ip_address,
                    "port": 443,
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher(),
                    "compression": ssock.compression(),
                    "server_hostname": clean_domain
                }
                
    except socket.gaierror as e:
        result["ssl_error"] = f"DNS resolution failed: {str(e)}"
        result["ssl_check_details"]["error"] = f"DNS resolution failed: {str(e)}"
        result["ssl_check_details"]["connection"] = {
            "error_type": "DNS_RESOLUTION_FAILED",
            "domain": clean_domain
        }
    except socket.timeout:
        result["ssl_error"] = "Connection timeout"
        result["ssl_check_details"]["error"] = "Connection timeout after 8 seconds"
        result["ssl_check_details"]["connection"] = {
            "error_type": "TIMEOUT",
            "timeout_seconds": 8,
            "domain": clean_domain
        }
    except ssl.SSLError as e:
        result["ssl_error"] = f"SSL error: {str(e)}"
        result["ssl_check_details"]["error"] = f"SSL error: {str(e)}"
        result["ssl_check_details"]["connection"] = {
            "error_type": "SSL_ERROR",
            "domain": clean_domain,
            "ssl_error_code": e.errno if hasattr(e, 'errno') else None
        }
    except Exception as e:
        result["ssl_error"] = f"Unexpected SSL error: {str(e)}"
        result["ssl_check_details"]["error"] = f"Unexpected error: {str(e)}"
        result["ssl_check_details"]["connection"] = {
            "error_type": "UNEXPECTED_ERROR",
            "domain": clean_domain
        }
    
    # Check health and response time
    health_info = check_health_and_response_time(clean_domain)
    result.update(health_info)
    
    # Check domain expiry using main domain
    main_domain = _get_main_domain(clean_domain)
    result["domain_check_details"] = {
        "main_domain": main_domain,
        "checked_domain": clean_domain,
        "whois_info": {}
    }
    
    # First check cache for main domain
    cached_domain_expiry = get_cached_domain_expiry(main_domain)
    if cached_domain_expiry:
        result["domain_expiry_date"] = cached_domain_expiry
        cache = load_cache()
        main_domain_entry = cache.get(main_domain, {})
        if 'domain_days_left' in main_domain_entry:
            result["domain_days_left"] = main_domain_entry['domain_days_left']
        
        # Get cached WHOIS details if available
        if 'domain_check_details' in main_domain_entry:
            result["domain_check_details"]["whois_info"] = main_domain_entry['domain_check_details'].get('whois_info', {})
            result["domain_check_details"]["whois_info"]["cached"] = True
    else:
        # Perform whois check on main domain
        domain_expiry, whois_details = check_domain_expiry(main_domain)
        result["domain_check_details"]["whois_info"] = whois_details
        result["domain_check_details"]["whois_info"]["cached"] = False
        
        # Only cache if we successfully got domain expiry and no error occurred
        if domain_expiry and not whois_details.get('error'):
            result["domain_expiry_date"] = domain_expiry
            try:
                expiry_dt = datetime.strptime(domain_expiry, '%Y-%m-%d %H:%M:%S')
                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                domain_days_left = (expiry_dt - now).days
                result["domain_days_left"] = domain_days_left
                # Save to main domain cache (including details) - only if no error
                save_domain_expiry_to_cache(main_domain, domain_expiry, domain_days_left, whois_details)
            except ValueError:
                pass
        elif whois_details.get('error'):
            # Don't cache failed WHOIS lookups - they will be retried next time
            pass
    
    return result


def check_ssl_certificate(domain: str, original_input: Optional[str] = None) -> Dict[str, Any]:
    """
    Check SSL certificate for a given domain with caching.
    
    Args:
        domain: Domain name to check
        original_input: Original user input (as provided) - optional
        
    Returns:
        Dictionary with domain, expiry_date, days_left, status, and detailed information
    """
    clean_domain = _clean_domain(domain)
    result = {
        "domain": clean_domain,
        "input": original_input if original_input else domain  # Store original input as-is
    }
    now = datetime.now(timezone.utc)
    
    # Check cache first
    cached_result = get_cached_result(clean_domain)
    if cached_result:
        # Use cached result
        result.update(cached_result)
        # Ensure input is preserved
        result["input"] = original_input if original_input else domain
        # Mark as cached
        if "ssl_check_details" not in result:
            result["ssl_check_details"] = {"cached": True}
        else:
            result["ssl_check_details"]["cached"] = True
        if "health_check_details" not in result:
            result["health_check_details"] = {"cached": True}
        else:
            result["health_check_details"]["cached"] = True
        if "domain_check_details" not in result:
            result["domain_check_details"] = {"cached": True}
        else:
            if "whois_info" in result["domain_check_details"]:
                result["domain_check_details"]["whois_info"]["cached"] = True
        return result
    
    # Cache miss or needs refresh - perform actual checks
    check_result = _perform_ssl_check(clean_domain, now)
    result.update(check_result)
    
    # Ensure input is preserved
    result["input"] = original_input if original_input else domain
    
    # Save to cache
    save_to_cache(clean_domain, result)
    
    return result


def get_domains_from_args() -> List[str]:
    """
    Get domain names from command-line arguments or environment variable.
    
    Returns:
        List of domain names
    """
    parser = argparse.ArgumentParser(
        description='Check SSL certificate expiry, domain expiry, health status, and response time for domains'
    )
    parser.add_argument(
        'domains',
        nargs='*',
        help='Domain names to check (can be multiple)'
    )
    parser.add_argument(
        '--env',
        action='store_true',
        help='Read domains from DOMAINS environment variable (comma-separated)'
    )
    
    args = parser.parse_args()
    
    # Check environment variable if --env flag is set or no args provided
    if args.env or (not args.domains and os.getenv('DOMAINS')):
        env_domains = os.getenv('DOMAINS', '')
        if env_domains:
            domains = [d.strip() for d in env_domains.split(',') if d.strip()]
            return domains
    
    # Use command-line arguments
    if args.domains:
        return args.domains
    
    # If no domains provided, show usage
    parser.print_help()
    sys.exit(1)


def main():
    """Main function to check SSL certificates."""
    domains = get_domains_from_args()
    
    if not domains:
        print("Error: No domains provided", file=sys.stderr)
        sys.exit(1)
    
    # Use parallel execution for multiple domains
    if len(domains) > 1:
        results = []
        with ThreadPoolExecutor(max_workers=min(len(domains), 10)) as executor:
            future_to_domain = {executor.submit(check_ssl_certificate, domain): domain for domain in domains}
            for future in as_completed(future_to_domain):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    domain = future_to_domain[future]
                    results.append({"domain": domain, "error": str(e)})
        # Sort results to match input order
        domain_order = {domain: idx for idx, domain in enumerate(domains)}
        results.sort(key=lambda x: domain_order.get(x.get("domain"), 999))
    else:
        # Single domain - no need for threading overhead
        results = [check_ssl_certificate(domains[0])]
    
    # Output results as JSON array
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()

