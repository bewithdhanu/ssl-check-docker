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
from typing import List, Dict, Any, Optional
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
    """
    cache = load_cache()
    cached_entry = cache.get(main_domain)
    
    if not cached_entry or 'domain_expiry_date' not in cached_entry:
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


def save_domain_expiry_to_cache(main_domain: str, domain_expiry: str, domain_days_left: int) -> None:
    """Save domain expiry to cache using main domain as key."""
    cache = load_cache()
    
    # Get or create entry for main domain
    if main_domain not in cache:
        cache[main_domain] = {}
    
    cache[main_domain]['domain_expiry_date'] = domain_expiry
    cache[main_domain]['domain_days_left'] = domain_days_left
    cache[main_domain]['last_checked'] = datetime.now(timezone.utc).isoformat()
    
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
        
        return result
    
    # Even if domain-specific cache doesn't exist, check main domain cache for domain expiry
    if main_domain != domain:
        main_domain_expiry = get_cached_domain_expiry(main_domain)
        if main_domain_expiry:
            # Return partial result with domain expiry from cache
            # This allows us to skip whois lookup even if SSL cache doesn't exist
            return {'domain_expiry_date': main_domain_expiry, 'domain_days_left': cache.get(main_domain, {}).get('domain_days_left')}
    
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


def check_domain_expiry(domain: str) -> Optional[str]:
    """
    Check domain expiry date using whois.
    
    Args:
        domain: Domain name to check
        
    Returns:
        Domain expiry date string in YYYY-MM-DD HH:MM:SS format or None if not found
    """
    try:
        clean_domain = _clean_domain(domain)
        
        # Run whois command with reduced timeout
        result = subprocess.run(
            ['whois', clean_domain],
            capture_output=True,
            text=True,
            timeout=10  # Reduced from 15
        )
        
        if not result.stdout:
            return None
        
        whois_output = result.stdout
        whois_lower = whois_output.lower()
        
        # Search for patterns - stop at first match
        for pattern in EXPIRY_PATTERNS:
            pattern_lower = pattern.lower()
            if pattern_lower not in whois_lower:
                continue
            
            # Find matching line
            for line in whois_output.split('\n'):
                line_lower = line.lower()
                if pattern_lower in line_lower:
                    idx = line_lower.find(pattern_lower)
                    if idx >= 0:
                        date_part = line[idx + len(pattern):].strip()
                        parsed_date = _parse_expiry_date(date_part)
                        if parsed_date:
                            return parsed_date
        
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None


def check_health_and_response_time(domain: str) -> Dict[str, Any]:
    """
    Check HTTP/HTTPS health status and measure response time.
    SSL certificate verification is disabled for health checks to handle
    domains with self-signed or invalid certificates.
    
    Args:
        domain: Domain name to check
        
    Returns:
        Dictionary with health_status and response_time_ms
    """
    clean_domain = _clean_domain(domain)
    result = {
        "health_status": "UNKNOWN",
        "response_time_ms": None
    }
    
    # Create SSL context that doesn't verify certificates for health checks
    ssl_context = ssl._create_unverified_context()
    
    # Try HTTPS first, then HTTP
    for protocol in ['https', 'http']:
        url = f"{protocol}://{clean_domain}"
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
                    return result
            else:
                # HTTP - no SSL needed
                with urllib.request.urlopen(req, timeout=8) as response:
                    elapsed_time = (time.time() - start_time) * 1000
                    status_code = response.getcode()
                    result["health_status"] = "UP" if 200 <= status_code < 400 else "DOWN"
                    result["response_time_ms"] = round(elapsed_time, 2)
                    return result
        except urllib.error.HTTPError as e:
            elapsed_time = (time.time() - start_time) * 1000
            result["health_status"] = "UP" if 200 <= e.code < 500 else "DOWN"
            result["response_time_ms"] = round(elapsed_time, 2)
            return result
        except (urllib.error.URLError, socket.timeout, ssl.SSLError, Exception):
            # Continue to next protocol or return DOWN if both fail
            continue
    
    result["health_status"] = "DOWN"
    return result


def _perform_ssl_check(clean_domain: str, now: datetime) -> Dict[str, Any]:
    """Perform actual SSL check (internal function)."""
    result = {}
    
    # Check SSL certificate
    try:
        context = ssl.create_default_context()
        with socket.create_connection((clean_domain, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date_str = cert['notAfter']
                expiry_date = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
                expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                days_left = (expiry_date - now).days
                
                result["ssl_expiry_date"] = expiry_date.strftime('%Y-%m-%d %H:%M:%S')
                result["ssl_days_left"] = days_left
                result["ssl_status"] = "EXPIRED" if days_left < 0 else ("EXPIRING" if days_left <= 30 else "OK")
    except socket.gaierror as e:
        result["ssl_error"] = f"DNS resolution failed: {str(e)}"
    except socket.timeout:
        result["ssl_error"] = "Connection timeout"
    except ssl.SSLError as e:
        result["ssl_error"] = f"SSL error: {str(e)}"
    except Exception as e:
        result["ssl_error"] = f"Unexpected SSL error: {str(e)}"
    
    # Check health and response time
    health_info = check_health_and_response_time(clean_domain)
    result.update(health_info)
    
    # Check domain expiry using main domain
    main_domain = _get_main_domain(clean_domain)
    
    # First check cache for main domain
    cached_domain_expiry = get_cached_domain_expiry(main_domain)
    if cached_domain_expiry:
        result["domain_expiry_date"] = cached_domain_expiry
        cache = load_cache()
        main_domain_entry = cache.get(main_domain, {})
        if 'domain_days_left' in main_domain_entry:
            result["domain_days_left"] = main_domain_entry['domain_days_left']
    else:
        # Perform whois check on main domain
        domain_expiry = check_domain_expiry(main_domain)
        if domain_expiry:
            result["domain_expiry_date"] = domain_expiry
            try:
                expiry_dt = datetime.strptime(domain_expiry, '%Y-%m-%d %H:%M:%S')
                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                domain_days_left = (expiry_dt - now).days
                result["domain_days_left"] = domain_days_left
                # Save to main domain cache
                save_domain_expiry_to_cache(main_domain, domain_expiry, domain_days_left)
            except ValueError:
                pass
    
    return result


def check_ssl_certificate(domain: str) -> Dict[str, Any]:
    """
    Check SSL certificate for a given domain with caching.
    
    Args:
        domain: Domain name to check
        
    Returns:
        Dictionary with domain, expiry_date, days_left, and status
    """
    clean_domain = _clean_domain(domain)
    result = {"domain": clean_domain}
    now = datetime.now(timezone.utc)
    
    # Check cache first
    cached_result = get_cached_result(clean_domain)
    if cached_result:
        # Use cached result
        result.update(cached_result)
        return result
    
    # Cache miss or needs refresh - perform actual checks
    check_result = _perform_ssl_check(clean_domain, now)
    result.update(check_result)
    
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

