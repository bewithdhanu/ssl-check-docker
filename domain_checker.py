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
import urllib.parse
import re
import logging
from html.parser import HTMLParser
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


# Pre-compile patterns and formats for better performance
EXPIRY_PATTERNS = [
    'registry expiry date:',  # Most common (ICANN standard)
    'expiry date:',
    'expiration date:',
    'expires:',
    'expires on:',
    'expiration:',
    'paid-till:',  # Common in European registries
    'expire:',
    'expiry:',
    'registrar registration expiration date:',
    'expiration date',
    'registry expiration date:',  # Alternative format
    'expiry:',  # Short form
    'renewal date:',  # Some registries
    'valid until:',  # Alternative wording
    'expires at:',  # Alternative wording
    'expiration:',  # Without "date"
    'paid until:',  # Alternative to paid-till
]

DATE_FORMATS = [
    '%Y-%m-%dT%H:%M:%SZ',  # ISO 8601 with Z
    '%Y-%m-%dT%H:%M:%S.%fZ',  # ISO 8601 with milliseconds
    '%Y-%m-%dT%H:%M:%S',  # ISO 8601 without timezone
    '%Y-%m-%dT%H:%M:%S%z',  # ISO 8601 with timezone offset
    '%Y-%m-%d %H:%M:%S',  # Standard format
    '%Y-%m-%d',  # Date only
    '%d-%b-%Y',  # DD-Mon-YYYY (e.g., 06-Aug-2026)
    '%d %b %Y',  # DD Mon YYYY
    '%b %d %Y',  # Mon DD YYYY
    '%d-%B-%Y',  # DD-Month-YYYY (full month name)
    '%d %B %Y',  # DD Month YYYY
    '%B %d %Y',  # Month DD YYYY
    '%Y/%m/%d',  # YYYY/MM/DD
    '%d/%m/%Y',  # DD/MM/YYYY
    '%m/%d/%Y',  # MM/DD/YYYY
    '%d.%m.%Y',  # DD.MM.YYYY
    '%Y.%m.%d',  # YYYY.MM.DD
    '%Y%m%d',  # YYYYMMDD
    '%d-%m-%Y',  # DD-MM-YYYY
    '%Y-%m-%d %H:%M:%S.%f',  # With microseconds
]

TIMEZONE_SUFFIXES = [
    '(utc)', '(gmt)', 'utc', 'gmt', '+00:00', '-00:00',
    'utc+0', 'gmt+0', 'z', 'zulu',
    '+0000', '-0000',  # Without colon
    'utc+00:00', 'gmt+00:00',
]

# Cache configuration - can be overridden via CACHE_DIR environment variable
CACHE_BASE_DIR = os.getenv('CACHE_DIR', '/tmp/ssl-checker-cache')
CACHE_DIR = Path(CACHE_BASE_DIR)
CACHE_FILE = CACHE_DIR / 'cache.json'
# Unified cache expiry: 1 hour for all checks (SSL, domain, logo)
CACHE_EXPIRY_HOURS = 1  # Cache all checks for 1 hour
LOGO_CACHE_EXPIRY_HOURS = 1  # Cache logo for 1 hour (same as other checks)
DOMAIN_CACHE_EXPIRY_HOURS = 1  # Cache domain expiry for 1 hour (same as other checks)

# Retry and timeout configuration - separate defaults for each check type
DEFAULT_HTTP_RETRIES = 1  # Default number of retries for HTTP/health checks
DEFAULT_SSL_RETRIES = 1  # Default number of retries for SSL checks
DEFAULT_DOMAIN_RETRIES = 1  # Default number of retries for domain expiry checks
DEFAULT_HTTP_TIMEOUT = 10  # Default HTTP timeout in seconds (reduced from 30 for faster failure detection)
DEFAULT_SSL_TIMEOUT = 5  # Default SSL connection timeout in seconds
DEFAULT_WHOIS_TIMEOUT = 5  # Default WHOIS lookup timeout in seconds


def load_cache() -> Dict[str, Dict[str, Any]]:
    """Load cache from file."""
    if not CACHE_FILE.exists():
        logger.debug(f"Cache file does not exist: {CACHE_FILE}")
        return {}
    try:
        with open(CACHE_FILE, 'r') as f:
            cache = json.load(f)
            logger.debug(f"Loaded cache with {len(cache)} entries from {CACHE_FILE}")
            return cache
    except (json.JSONDecodeError, IOError) as e:
        logger.warning(f"Failed to load cache from {CACHE_FILE}: {e}")
        return {}


def save_cache(cache: Dict[str, Dict[str, Any]]) -> None:
    """Save cache to file."""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f)
        logger.debug(f"Saved cache with {len(cache)} entries to {CACHE_FILE}")
    except IOError as e:
        logger.warning(f"Failed to save cache to {CACHE_FILE}: {e}")


def should_refresh_cache(cached_entry: Dict[str, Any], force: bool = False) -> bool:
    """
    Determine if cache entry should be refreshed.
    
    Args:
        cached_entry: Cached entry dictionary
        force: If True, always refresh (bypass cache)
    
    Returns True if:
    - force is True (bypass cache)
    - Cache entry is invalid/missing required fields
    - Last check was >= 1 hour ago
    
    Returns False if:
    - Last check was < 1 hour ago (use cache)
    """
    if force:
        return True
    
    if not cached_entry:
        return True
    
    # Check if required fields exist
    if 'last_checked' not in cached_entry:
        return True
    
    last_checked_str = cached_entry.get('last_checked')
    
    if not last_checked_str:
        return True
    
    try:
        last_checked = datetime.fromisoformat(last_checked_str.replace('Z', '+00:00'))
        if last_checked.tzinfo is None:
            last_checked = last_checked.replace(tzinfo=timezone.utc)
        
        hours_since_check = (datetime.now(timezone.utc) - last_checked).total_seconds() / 3600
        
        # Refresh if last check was >= 1 hour ago
        return hours_since_check >= CACHE_EXPIRY_HOURS
    except (ValueError, TypeError):
        return True


def get_cached_domain_expiry(main_domain: str, force: bool = False) -> Optional[str]:
    """
    Get cached domain expiry for main domain.
    
    Args:
        main_domain: Main domain name
        force: If True, bypass cache and return None
    
    Cache expires after 1 hour.
    Never return cached result if it has an error (e.g., "No WHOIS output received").
    """
    if force:
        return None
    
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
        
        # Cache expires after 1 hour
        if hours_since_check >= DOMAIN_CACHE_EXPIRY_HOURS:
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
    
    save_cache(cache)


def get_cached_result(domain: str, force: bool = False) -> Optional[Dict[str, Any]]:
    """
    Get cached result for domain if valid, otherwise None.
    
    Args:
        domain: Domain name
        force: If True, bypass cache and return None
    """
    if force:
        logger.debug(f"Cache bypassed for domain: {domain} (force=True)")
        return None
    
    cache = load_cache()
    cached_entry = cache.get(domain)
    main_domain = _get_main_domain(domain)
    
    # Check if we have a valid cache entry for this specific domain
    if cached_entry and not should_refresh_cache(cached_entry, force=force):
        logger.info(f"Cache hit for domain: {domain}")
        # Return cached result (remove cache metadata)
        result = {k: v for k, v in cached_entry.items() if k != 'last_checked'}
        
        # Always check for domain expiry from main domain cache if domain is a subdomain
        # This ensures we get domain expiry even if it wasn't in the subdomain cache
        if main_domain != domain:
            main_domain_expiry = get_cached_domain_expiry(main_domain, force=force)
            if main_domain_expiry:
                result['domain_expiry_date'] = main_domain_expiry
                # Get days left from main domain cache
                main_domain_entry = cache.get(main_domain, {})
                if 'domain_days_left' in main_domain_entry:
                    result['domain_days_left'] = main_domain_entry['domain_days_left']
        
        return result
    
    # Even if domain-specific cache doesn't exist, check main domain cache for domain expiry
    if main_domain != domain:
        main_domain_expiry = get_cached_domain_expiry(main_domain, force=force)
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


def _extract_domain_from_url(url: str) -> str:
    """
    Extract domain from full URL (with path and query params).
    
    Args:
        url: Full URL (e.g., "https://pro.example.com/path?query=value")
        
    Returns:
        Domain name (e.g., "pro.example.com")
    """
    # Remove protocol if present
    url = url.replace('https://', '').replace('http://', '')
    
    # Extract domain (everything before first /)
    domain = url.split('/')[0]
    
    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]
    
    return domain.strip()


def _extract_subdomain_from_url(url: str) -> str:
    """
    Extract subdomain from full URL for SSL check.
    If URL is https://pro.example.com/path, returns "pro.example.com"
    If URL is https://example.com/path, returns "example.com"
    
    Args:
        url: Full URL
        
    Returns:
        Subdomain/domain for SSL check
    """
    return _extract_domain_from_url(url)


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
    # Also handle various millisecond formats
    if '.0Z' in date_part or '.Z' in date_part:
        date_part = date_part.replace('.0Z', 'Z').replace('.Z', 'Z')
    
    # Handle microseconds (e.g., "2026-08-06T23:59:59.123456Z")
    if '.' in date_part and 'T' in date_part and 'Z' in date_part:
        # Keep only up to 6 digits for microseconds, remove excess
        date_part = re.sub(r'\.(\d{1,6})Z', r'.\1Z', date_part)
    
    # Remove timezone suffixes (but keep Z for ISO format)
    for suffix in TIMEZONE_SUFFIXES:
        if date_part.lower().endswith(suffix.lower()):
            date_part = date_part[:-len(suffix)].strip()
    
    # Remove parentheses and extra whitespace
    date_part = date_part.strip('()').strip()
    
    # Handle timezone offsets (e.g., "+02:00", "-05:00")
    # Remove timezone offset for parsing, we'll assume UTC
    import re
    timezone_offset_pattern = r'[+-]\d{2}:?\d{2}$'
    date_part = re.sub(timezone_offset_pattern, '', date_part).strip()
    
    # Try parsing with various formats
    # Safely get first word if available, otherwise use the whole string
    if not date_part:
        return None
    date_parts = date_part.split()
    date_str = date_parts[0] if date_parts else date_part
    for fmt in DATE_FORMATS:
        try:
            parsed_date = datetime.strptime(date_str, fmt)
            parsed_date = parsed_date.replace(tzinfo=timezone.utc)
            return parsed_date.strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, IndexError):
            continue
    return None


def _try_rdap_lookup(domain: str) -> Optional[str]:
    """
    Try to get domain expiry date using RDAP (Registration Data Access Protocol).
    RDAP is a modern replacement for WHOIS that provides structured JSON data.
    
    Args:
        domain: Domain name to check
        
    Returns:
        Domain expiry date string in YYYY-MM-DD HH:MM:SS format or None
    """
    try:
        import json
        
        # RDAP endpoint - try rdapserver.net first
        rdap_url = f"https://rdapserver.net/domain/{domain}"
        
        req = urllib.request.Request(
            rdap_url,
            headers={
                'Accept': 'application/json, application/rdap+json',
                'User-Agent': 'Domain-Checker/1.0'
            }
        )
        
        with urllib.request.urlopen(req, timeout=10) as response:
            rdap_data = json.loads(response.read().decode())
            
            # Look for expiry date in events array
            if 'events' in rdap_data:
                for event in rdap_data['events']:
                    if event.get('eventAction') == 'registrar expiration':
                        expiry_date_str = event.get('eventDate')
                        if expiry_date_str:
                            # Parse ISO 8601 format (e.g., "2026-04-04T19:22:04Z")
                            try:
                                # Remove timezone and microseconds if present
                                expiry_date_str = expiry_date_str.split('.')[0].replace('Z', '')
                                expiry_date = datetime.strptime(expiry_date_str, '%Y-%m-%dT%H:%M:%S')
                                expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                                return expiry_date.strftime('%Y-%m-%d %H:%M:%S')
                            except (ValueError, AttributeError):
                                pass
        
        return None
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, Exception):
        # RDAP lookup failed, return None to fall back to WHOIS error
        return None


def check_domain_expiry_with_retry(domain: str, retries: int = DEFAULT_DOMAIN_RETRIES, timeout: int = DEFAULT_WHOIS_TIMEOUT) -> Tuple[Optional[str], Dict[str, Any]]:
    """
    Check domain expiry date using whois with retry logic.
    
    Args:
        domain: Domain name to check (will extract domain from URL if full URL provided)
        retries: Number of retries if check fails (default: 1)
        
    Returns:
        Tuple of (domain expiry date string in YYYY-MM-DD HH:MM:SS format or None, details dict)
    """
    # Extract domain from URL if it's a full URL
    domain_to_check = _extract_domain_from_url(domain) if ('://' in domain or '/' in domain) else domain
    logger.debug(f"Checking domain expiry for: {domain_to_check} (retries={retries})")
    
    last_error = None
    last_details = None
    
    for attempt in range(retries + 1):
        if attempt > 0:
            logger.info(f"Domain expiry retry attempt {attempt + 1}/{retries + 1} for {domain_to_check}")
        expiry, details = check_domain_expiry(domain_to_check, timeout=timeout)
        
        # If successful or non-retryable error, return immediately
        if expiry:
            logger.info(f"Domain expiry check successful for {domain_to_check}: {expiry}")
            return expiry, details
        
        # Check if error is retryable
        error_msg = details.get('error', '')
        if error_msg:
            # Don't retry on rate limits or permanent errors
            if 'rate limit' in error_msg.lower() or 'permanent' in error_msg.lower() or 'not found' in error_msg.lower():
                logger.warning(f"Non-retryable error for {domain_to_check}: {error_msg}")
                return expiry, details
        
        last_error = error_msg
        last_details = details
        
        # Wait before retry
        if attempt < retries:
            logger.debug(f"Waiting before retry for {domain_to_check}")
            time.sleep(1)
    
    # All retries failed
    logger.error(f"Domain expiry check failed after {retries + 1} attempts for {domain_to_check}: {last_error}")
    if last_details:
        if last_error:
            last_details["error"] = f"{last_error} (after {retries + 1} attempts)"
        return None, last_details
    
    return None, {"error": "Domain expiry check failed after retries"}


def check_domain_expiry(domain: str, timeout: int = DEFAULT_WHOIS_TIMEOUT) -> Tuple[Optional[str], Dict[str, Any]]:
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
        "registrar": None,
        "error": None
    }
    
    try:
        clean_domain = _clean_domain(domain)
        whois_output = ""
        whois_server = None
        
        # First attempt: query default WHOIS server
        logger.debug(f"Querying WHOIS for {clean_domain} (timeout={timeout}s)")
        result = subprocess.run(
            ['whois', clean_domain],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        # Known TLD-specific WHOIS servers (fallback if default whois fails)
        # Expanded list based on common TLDs that require specific servers
        tld_whois_servers = {
            'co': 'whois.registry.co',
            'uk': 'whois.nominet.uk',
            'au': 'whois.aunic.net',
            'nz': 'whois.dnc.org.nz',
            'de': 'whois.denic.de',
            'fr': 'whois.afnic.fr',
            'it': 'whois.nic.it',
            'nl': 'whois.domain-registry.nl',
            'be': 'whois.dns.be',
            'ch': 'whois.nic.ch',
            'at': 'whois.nic.at',
            'se': 'whois.iis.se',
            'no': 'whois.norid.no',
            'dk': 'whois.dk-hostmaster.dk',
            'pl': 'whois.dns.pl',
            'ru': 'whois.tcinet.ru',
            'jp': 'whois.jprs.jp',
            'cn': 'whois.cnnic.net.cn',
            'kr': 'whois.krnic.net',
            'in': 'whois.inregistry.net',
            'br': 'whois.registro.br',
            'mx': 'whois.mx',
            'ca': 'whois.cira.ca',
            'io': 'whois.nic.io',
            'ai': 'whois.nic.ai',
            'tv': 'whois.tv',
            'me': 'whois.nic.me',
            'co.uk': 'whois.nominet.uk',  # Multi-part TLD
            'com.au': 'whois.aunic.net',  # Multi-part TLD
            'co.nz': 'whois.dnc.org.nz',  # Multi-part TLD
            'co.za': 'whois.registry.net.za',  # Multi-part TLD
        }
        
        # Extract TLD for fallback lookup (handle multi-part TLDs)
        domain_parts = clean_domain.split('.')
        tld = None
        if len(domain_parts) >= 2:
            # Try two-part TLD first (e.g., co.uk, com.au)
            two_part_tld = '.'.join(domain_parts[-2:]).lower()
            if two_part_tld in tld_whois_servers:
                tld = two_part_tld
            else:
                # Fall back to single-part TLD
                tld = domain_parts[-1].lower()
        
        if result.stdout:
            whois_output = result.stdout
            whois_lower = whois_output.lower()
            lines = whois_output.split('\n')  # Define lines early for use in referral checking
            
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
                    for line in lines:
                        line_lower = line.lower()
                        if pattern in line_lower:
                            # Extract WHOIS server from referral
                            parts = line.split(':', 1)
                            if len(parts) > 1:
                                server_parts = parts[1].strip().split()
                                if server_parts:
                                    potential_server = server_parts[0].strip()
                                    # Validate it looks like a hostname
                                    if '.' in potential_server and not potential_server.startswith('http'):
                                        whois_server = potential_server
                                        break
                    if whois_server:
                        break
            
            # If we found a referral and haven't found expiry date yet, query the referred server
            # Also check for registrar-specific WHOIS server referrals
            registrar_whois_server = None
            for line in lines:
                line_lower = line.lower()
                if 'registrar whois server:' in line_lower:
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        potential_server = parts[1].strip().split()[0].strip()
                        if '.' in potential_server and not potential_server.startswith('http'):
                            registrar_whois_server = potential_server
                            break
            
            # Priority: 1) Registry referral, 2) Registrar referral, 3) Check if expiry already found
            if whois_server and 'registry expiry date:' not in whois_lower and 'expiry date:' not in whois_lower:
                # Query the referred WHOIS server directly
                referral_result = subprocess.run(
                    ['whois', '-h', whois_server, clean_domain],
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                
                if referral_result.stdout:
                    whois_output = referral_result.stdout
                    details["whois_server"] = whois_server
                    whois_lower = whois_output.lower()  # Update for next checks
                    lines = whois_output.split('\n')  # Update lines after referral
            elif registrar_whois_server and 'registry expiry date:' not in whois_lower and 'expiry date:' not in whois_lower:
                # Try registrar-specific WHOIS server as fallback
                registrar_result = subprocess.run(
                    ['whois', '-h', registrar_whois_server, clean_domain],
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                
                if registrar_result.stdout:
                    whois_output = registrar_result.stdout
                    details["whois_server"] = registrar_whois_server
                    whois_lower = whois_output.lower()  # Update for next checks
                    lines = whois_output.split('\n')  # Update lines after registrar lookup
        elif tld and tld in tld_whois_servers:
            # Fallback: if default whois failed and we know the TLD-specific server, try it
            fallback_server = tld_whois_servers[tld]
            fallback_result = subprocess.run(
                ['whois', '-h', fallback_server, clean_domain],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if fallback_result.stdout:
                whois_output = fallback_result.stdout
                details["whois_server"] = fallback_server
                whois_lower = whois_output.lower()  # Update for next checks
                lines = whois_output.split('\n')  # Define lines for fallback case
        
        # Check stderr for errors (some WHOIS servers return errors in stderr)
        if result.stderr and not whois_output:
            stderr_lower = result.stderr.lower()
            # Common error patterns
            if 'rate limit' in stderr_lower or 'too many' in stderr_lower:
                details["error"] = "WHOIS rate limit exceeded - please try again later"
                return None, details
            elif 'not found' in stderr_lower or 'no match' in stderr_lower:
                details["error"] = "Domain not found in WHOIS database"
                return None, details
            elif 'timeout' in stderr_lower or 'timed out' in stderr_lower:
                details["error"] = "WHOIS query timeout"
                return None, details
        
        if not whois_output:
            # Try RDAP as fallback when WHOIS fails
            rdap_expiry = _try_rdap_lookup(clean_domain)
            if rdap_expiry:
                return rdap_expiry, details
            # This is not necessarily an error - some TLDs don't provide WHOIS
            details["error"] = "No WHOIS output received - domain may not support WHOIS lookup"
            return None, details
        
        whois_lower = whois_output.lower()
        
        # Extract additional information from WHOIS output
        lines = whois_output.split('\n')
        
        # Search for expiry date patterns - stop at first match
        # Handle multi-line expiry dates and comments
        for pattern in EXPIRY_PATTERNS:
            pattern_lower = pattern.lower()
            if pattern_lower not in whois_lower:
                continue
            
            # Find matching line (skip comment lines starting with # or %)
            for line in lines:
                # Skip comment lines
                stripped_line = line.strip()
                if stripped_line.startswith('#') or stripped_line.startswith('%'):
                    continue
                
                line_lower = line.lower()
                if pattern_lower in line_lower:
                    idx = line_lower.find(pattern_lower)
                    if idx >= 0:
                        # Extract date part after the pattern
                        date_part = line[idx + len(pattern):].strip()
                        
                        # Handle cases where date might continue on next line
                        if not date_part:
                            line_idx = lines.index(line)
                            if line_idx + 1 < len(lines):
                                next_line = lines[line_idx + 1].strip()
                                if next_line and not next_line.startswith('#') and not next_line.startswith('%'):
                                    date_part = next_line
                        
                        parsed_date = _parse_expiry_date(date_part)
                        if parsed_date:
                            return parsed_date, details
        
        # If no expiry found, check for domains that might not have expiry dates
        # (some TLDs like .ai, .io might not show expiry in standard WHOIS)
        if 'no expiry' in whois_lower or 'permanent' in whois_lower or 'never expires' in whois_lower:
            details["error"] = "Domain does not have an expiry date (permanent registration)"
            return None, details
        
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


def check_health_and_response_time(domain: str, timeout: int = DEFAULT_HTTP_TIMEOUT, retries: int = DEFAULT_HTTP_RETRIES) -> Dict[str, Any]:
    """
    Check HTTP/HTTPS health status and measure response time with retry logic.
    SSL certificate verification is disabled for health checks to handle
    domains with self-signed or invalid certificates.
    
    Args:
        domain: Domain name or full URL to check
        timeout: HTTP timeout in seconds (default: 30)
        retries: Number of retries if check fails (default: 1)
        
    Returns:
        Dictionary with health_status, response_time_ms, and http_status_code
    """
    # Handle full URLs - preserve original URL for health check
    if domain.startswith('http://') or domain.startswith('https://'):
        url_to_check = domain
        clean_domain = _extract_domain_from_url(domain)
    else:
        clean_domain = _clean_domain(domain)
        url_to_check = None  # Will construct below
    
    result = {
        "health_status": "UNKNOWN",
        "response_time_ms": None,
        "http_status_code": None
    }
    
    # Create SSL context that doesn't verify certificates for health checks
    ssl_context = ssl._create_unverified_context()
    
    # Determine protocols to try
    if url_to_check:
        # Use the original URL's protocol
        protocols = [url_to_check.split('://')[0]]
        base_url = url_to_check
    else:
        # Try HTTPS first, then HTTP
        protocols = ['https', 'http']
        base_url = None
    
    last_error = None
    
    # Retry logic
    logger.debug(f"Checking health for: {clean_domain} (timeout={timeout}s, retries={retries})")
    for attempt in range(retries + 1):
        if attempt > 0:
            logger.info(f"Health check retry attempt {attempt + 1}/{retries + 1} for {clean_domain}")
        for protocol in protocols:
            if url_to_check:
                url = url_to_check
            else:
                url = f"{protocol}://{clean_domain}"
            
            logger.debug(f"Trying {protocol} for {clean_domain}")
            start_time = time.time()
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'SSL-Checker/1.0'})
                
                # Use SSL context for HTTPS, normal for HTTP
                if protocol == 'https' or url.startswith('https://'):
                    # Create opener with unverified SSL context
                    https_handler = urllib.request.HTTPSHandler(context=ssl_context)
                    opener = urllib.request.build_opener(https_handler)
                    with opener.open(req, timeout=timeout) as response:
                        elapsed_time = (time.time() - start_time) * 1000
                        status_code = response.getcode()
                        result["health_status"] = "UP" if 200 <= status_code < 400 else "DOWN"
                        result["response_time_ms"] = round(elapsed_time, 2)
                        result["http_status_code"] = status_code
                        logger.info(f"Health check successful for {clean_domain}: {protocol} - status={status_code}, time={result['response_time_ms']}ms")
                        return result
                else:
                    # HTTP - no SSL needed
                    with urllib.request.urlopen(req, timeout=timeout) as response:
                        elapsed_time = (time.time() - start_time) * 1000
                        status_code = response.getcode()
                        result["health_status"] = "UP" if 200 <= status_code < 400 else "DOWN"
                        result["response_time_ms"] = round(elapsed_time, 2)
                        result["http_status_code"] = status_code
                        return result
            except urllib.error.HTTPError as e:
                elapsed_time = (time.time() - start_time) * 1000
                status_code = e.code
                result["health_status"] = "UP" if 200 <= status_code < 500 else "DOWN"
                result["response_time_ms"] = round(elapsed_time, 2)
                result["http_status_code"] = status_code
                return result
            except (urllib.error.URLError, socket.timeout, ssl.SSLError, Exception) as e:
                last_error = str(e)
                logger.debug(f"Health check failed for {clean_domain} ({protocol}): {e}")
                # Continue to next protocol or retry
                if attempt < retries:
                    time.sleep(0.5)  # Brief delay before retry
                    continue
                continue
        
        # If all protocols failed and we have retries left, wait before retrying
        if attempt < retries:
            time.sleep(1)  # Wait 1 second between retries
    
    # All attempts failed
    result["health_status"] = "DOWN"
    result["http_status_code"] = None
    return result


class LogoExtractor(HTMLParser):
    """HTML parser to extract logo/favicon URLs from HTML content."""
    
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.logo_url = None
        self.found_logo = False
        
    def handle_starttag(self, tag, attrs):
        """Handle HTML start tags to find logo/favicon links."""
        if self.found_logo:
            return
            
        attrs_dict = dict(attrs)
        
        # Check for favicon links
        if tag == 'link':
            rel = attrs_dict.get('rel', '').lower()
            href = attrs_dict.get('href', '')
            
            # Priority order: apple-touch-icon > icon > shortcut icon
            if 'apple-touch-icon' in rel:
                self.logo_url = self._resolve_url(href)
                self.found_logo = True
            elif rel in ['icon', 'shortcut icon'] and not self.logo_url:
                self.logo_url = self._resolve_url(href)
                # Don't set found_logo yet - might find apple-touch-icon later
        
        # Check for Open Graph image
        elif tag == 'meta' and not self.found_logo:
            property_attr = attrs_dict.get('property', '').lower()
            content = attrs_dict.get('content', '')
            
            if property_attr == 'og:image' and content:
                self.logo_url = self._resolve_url(content)
                self.found_logo = True
        
        # Check for Twitter Card image
        elif tag == 'meta' and not self.found_logo:
            name = attrs_dict.get('name', '').lower()
            content = attrs_dict.get('content', '')
            
            if name == 'twitter:image' and content:
                self.logo_url = self._resolve_url(content)
                self.found_logo = True
        
        # Check for img tags with logo-related classes/ids
        elif tag == 'img' and not self.found_logo:
            src = attrs_dict.get('src', '')
            class_attr = attrs_dict.get('class', '').lower()
            id_attr = attrs_dict.get('id', '').lower()
            alt = attrs_dict.get('alt', '').lower()
            
            # Look for logo-related keywords
            logo_keywords = ['logo', 'brand', 'icon']
            if any(keyword in class_attr or keyword in id_attr or keyword in alt for keyword in logo_keywords):
                if src:
                    self.logo_url = self._resolve_url(src)
                    self.found_logo = True
    
    def _resolve_url(self, url: str) -> Optional[str]:
        """Resolve relative URLs to absolute URLs."""
        if not url:
            return None
        
        # Already absolute URL
        if url.startswith(('http://', 'https://', '//')):
            if url.startswith('//'):
                return 'https:' + url
            return url
        
        # Relative URL - resolve against base URL
        try:
            return urllib.parse.urljoin(self.base_url, url)
        except Exception:
            return url
    
    def get_logo_url(self) -> Optional[str]:
        """Get the extracted logo URL."""
        return self.logo_url


def extract_website_logo(domain: str) -> Optional[str]:
    """
    Extract website logo URL from HTML content.
    
    Args:
        domain: Domain name to check
        
    Returns:
        Logo URL or None if not found
    """
    clean_domain = _clean_domain(domain)
    
    # Try HTTPS first, then HTTP
    for protocol in ['https', 'http']:
        url = f"{protocol}://{clean_domain}"
        try:
            # Create SSL context that doesn't verify certificates
            ssl_context = ssl._create_unverified_context()
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            if protocol == 'https':
                https_handler = urllib.request.HTTPSHandler(context=ssl_context)
                opener = urllib.request.build_opener(https_handler)
                with opener.open(req, timeout=5) as response:
                    if response.getcode() == 200:
                        content_type = response.headers.get('Content-Type', '').lower()
                        if 'text/html' in content_type:
                            html_content = response.read().decode('utf-8', errors='ignore')
                            parser = LogoExtractor(url)
                            parser.feed(html_content)
                            logo_url = parser.get_logo_url()
                            
                            # If no logo found in HTML, try default favicon
                            if not logo_url:
                                logo_url = urllib.parse.urljoin(url, '/favicon.ico')
                            
                            return logo_url
            else:
                with urllib.request.urlopen(req, timeout=5) as response:
                    if response.getcode() == 200:
                        content_type = response.headers.get('Content-Type', '').lower()
                        if 'text/html' in content_type:
                            html_content = response.read().decode('utf-8', errors='ignore')
                            parser = LogoExtractor(url)
                            parser.feed(html_content)
                            logo_url = parser.get_logo_url()
                            
                            # If no logo found in HTML, try default favicon
                            if not logo_url:
                                logo_url = urllib.parse.urljoin(url, '/favicon.ico')
                            
                            return logo_url
        except Exception:
            continue
    
    # If all methods fail, try default favicon
    try:
        for protocol in ['https', 'http']:
            favicon_url = f"{protocol}://{clean_domain}/favicon.ico"
            try:
                req = urllib.request.Request(favicon_url, headers={'User-Agent': 'Mozilla/5.0'})
                if protocol == 'https':
                    ssl_context = ssl._create_unverified_context()
                    https_handler = urllib.request.HTTPSHandler(context=ssl_context)
                    opener = urllib.request.build_opener(https_handler)
                    with opener.open(req, timeout=3) as response:
                        if response.getcode() == 200:
                            return favicon_url
                else:
                    with urllib.request.urlopen(req, timeout=3) as response:
                        if response.getcode() == 200:
                            return favicon_url
            except Exception:
                continue
    except Exception:
        pass
    
    return None


def get_cached_logo(domain: str, force: bool = False) -> Optional[str]:
    """
    Get cached logo URL for domain.
    
    Args:
        domain: Domain name to check
        force: If True, bypass cache and return None
    
    Logo cache expires after 1 hour.
    
    Returns:
        Cached logo URL or None if not cached or expired
    """
    if force:
        return None
    
    cache = load_cache()
    cached_entry = cache.get(domain)
    
    if not cached_entry or 'website_logo' not in cached_entry:
        return None
    
    logo_url = cached_entry.get('website_logo')
    if not logo_url:
        return None
    
    # Check if logo cache is expired (1 hour)
    last_checked_str = cached_entry.get('logo_last_checked')
    if not last_checked_str:
        return logo_url  # No timestamp, assume valid (backward compatibility)
    
    try:
        last_checked = datetime.fromisoformat(last_checked_str.replace('Z', '+00:00'))
        if last_checked.tzinfo is None:
            last_checked = last_checked.replace(tzinfo=timezone.utc)
        
        hours_since_check = (datetime.now(timezone.utc) - last_checked).total_seconds() / 3600
        
        # Logo cache expires after 1 hour
        if hours_since_check >= LOGO_CACHE_EXPIRY_HOURS:
            return None  # Cache expired
        
        return logo_url
    except (ValueError, TypeError):
        return logo_url  # If parsing fails, return cached value


def save_logo_to_cache(domain: str, logo_url: Optional[str]) -> None:
    """
    Save logo URL to cache with timestamp.
    
    Args:
        domain: Domain name
        logo_url: Logo URL to cache (can be None)
    """
    cache = load_cache()
    
    if domain not in cache:
        cache[domain] = {}
    
    cache[domain]['website_logo'] = logo_url
    cache[domain]['logo_last_checked'] = datetime.now(timezone.utc).isoformat()
    
    save_cache(cache)


def _perform_ssl_check(clean_domain: str, now: datetime, force: bool = False, ssl_retries: int = DEFAULT_SSL_RETRIES, http_retries: int = DEFAULT_HTTP_RETRIES, domain_retries: int = DEFAULT_DOMAIN_RETRIES, timeout: int = DEFAULT_HTTP_TIMEOUT, ssl_timeout: int = DEFAULT_SSL_TIMEOUT) -> Dict[str, Any]:
    """
    Perform actual SSL check (internal function) with retry logic.
    
    Args:
        clean_domain: Domain name or full URL (will extract subdomain for SSL check)
        now: Current datetime
        force: If True, bypass cache
        retries: Number of retries if SSL check fails (default: 1)
        timeout: HTTP timeout in seconds (default: 30)
    """
    # Initialize all fields with null to ensure they're always present
    result = {
        "ssl_expiry_date": None,
        "ssl_days_left": None,
        "ssl_status": None,
        "ssl_error": None,
        "health_status": None,
        "response_time_ms": None,
        "http_status_code": None,
        "domain_expiry_date": None,
        "domain_days_left": None,
        "domain_error": None,
        "website_logo": None
    }
    
    # Extract subdomain from URL if it's a full URL
    ssl_domain = _extract_subdomain_from_url(clean_domain) if ('://' in clean_domain or '/' in clean_domain) else clean_domain
    logger.debug(f"Performing SSL check for: {ssl_domain} (retries={ssl_retries})")
    
    # Check SSL certificate with retry logic
    last_error = None
    for attempt in range(ssl_retries + 1):
        if attempt > 0:
            logger.info(f"SSL check retry attempt {attempt + 1}/{ssl_retries + 1} for {ssl_domain}")
        try:
            logger.debug(f"Connecting to {ssl_domain}:443 for SSL check (timeout={ssl_timeout}s)")
            context = ssl.create_default_context()
            with socket.create_connection((ssl_domain, 443), timeout=ssl_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ssl_domain) as ssock:
                    cert = ssock.getpeercert()
                    expiry_date_str = cert['notAfter']
                    expiry_date = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
                    expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                    days_left = (expiry_date - now).days
                    
                    result["ssl_expiry_date"] = expiry_date.strftime('%Y-%m-%d %H:%M:%S')
                    result["ssl_days_left"] = days_left
                    result["ssl_status"] = "EXPIRED" if days_left < 0 else ("EXPIRING" if days_left <= 30 else "OK")
                    logger.info(f"SSL check successful for {ssl_domain}: expires={result['ssl_expiry_date']}, days_left={days_left}, status={result['ssl_status']}")
                    break  # Success, exit retry loop
                    
        except socket.gaierror as e:
            last_error = f"DNS resolution failed: {str(e)}"
            result["ssl_error"] = last_error
            result["ssl_status"] = "DNS_ERROR"
            logger.warning(f"DNS resolution failed for {ssl_domain}: {e}")
            if attempt < ssl_retries:
                time.sleep(0.5)
                continue
        except socket.timeout:
            last_error = "Connection timeout - site appears to be down"
            result["ssl_status"] = "SITE_DOWN"
            result["ssl_error"] = last_error
            logger.warning(f"Connection timeout for {ssl_domain} - site appears to be down")
            if attempt < ssl_retries:
                time.sleep(1)
                continue
        except ssl.SSLError as e:
            last_error = f"SSL error: {str(e)}"
            result["ssl_error"] = last_error
            result["ssl_status"] = "SSL_ERROR"
            logger.warning(f"SSL error for {ssl_domain}: {e}")
            if attempt < ssl_retries:
                time.sleep(0.5)
                continue
        except Exception as e:
            last_error = f"Unexpected SSL error: {str(e)}"
            result["ssl_error"] = last_error
            result["ssl_status"] = "ERROR"
            logger.error(f"Unexpected SSL error for {ssl_domain}: {e}", exc_info=True)
            if attempt < ssl_retries:
                time.sleep(0.5)
                continue
    
    if last_error and result["ssl_status"] != "OK":
        logger.error(f"SSL check failed for {ssl_domain} after {ssl_retries + 1} attempts: {last_error}")
    
    # Check health and response time (use configurable timeout and HTTP retries)
    health_info = check_health_and_response_time(clean_domain, timeout=timeout, retries=http_retries)
    # Update result with health info (will overwrite None values)
    result.update(health_info)
    
    # Check domain expiry using main domain
    # Extract domain from URL if it's a full URL
    domain_for_expiry = _extract_domain_from_url(clean_domain) if ('://' in clean_domain or '/' in clean_domain) else clean_domain
    main_domain = _get_main_domain(domain_for_expiry)
    
    # First check cache for main domain
    cached_domain_expiry = get_cached_domain_expiry(main_domain, force=force)
    if cached_domain_expiry:
        result["domain_expiry_date"] = cached_domain_expiry
        cache = load_cache()
        main_domain_entry = cache.get(main_domain, {})
        if 'domain_days_left' in main_domain_entry:
            result["domain_days_left"] = main_domain_entry['domain_days_left']
    else:
        # Perform whois check on main domain with retry logic
        domain_expiry, whois_details = check_domain_expiry_with_retry(main_domain, retries=domain_retries, timeout=whois_timeout)
        
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
            error_msg = whois_details.get('error')
            # Provide user-friendly error messages
            if "No WHOIS output received" in error_msg:
                result["domain_error"] = "WHOIS data not available for this domain"
            elif "rate limit" in error_msg.lower():
                result["domain_error"] = "WHOIS rate limit exceeded - please try again later"
            elif "timeout" in error_msg.lower():
                result["domain_error"] = "WHOIS query timeout"
            elif "not found" in error_msg.lower():
                result["domain_error"] = "Domain not found in WHOIS database"
            else:
                result["domain_error"] = f"WHOIS lookup failed: {error_msg}"
    
    # Check website logo (with 1-hour cache)
    # Use domain key (not full URL) for logo cache
    logo_domain = domain_for_expiry if ('://' in clean_domain or '/' in clean_domain) else clean_domain
    cached_logo = get_cached_logo(logo_domain, force=force)
    if cached_logo:
        result["website_logo"] = cached_logo
    else:
        # Extract logo from website (use original URL if it's a full URL)
        logo_url = extract_website_logo(clean_domain)
        result["website_logo"] = logo_url
        # Save to cache (even if None, to avoid repeated failed attempts)
        save_logo_to_cache(logo_domain, logo_url)
    
    return result


def check_ssl_certificate(domain: str, original_input: Optional[str] = None, force: bool = False, http_retries: int = DEFAULT_HTTP_RETRIES, ssl_retries: int = DEFAULT_SSL_RETRIES, domain_retries: int = DEFAULT_DOMAIN_RETRIES, timeout: int = DEFAULT_HTTP_TIMEOUT, ssl_timeout: int = DEFAULT_SSL_TIMEOUT, whois_timeout: int = DEFAULT_WHOIS_TIMEOUT) -> Dict[str, Any]:
    """
    Check SSL certificate for a given domain with caching, retry logic, and configurable timeout.
    
    Args:
        domain: Domain name or full URL to check
        original_input: Original user input (as provided) - optional
        force: If True, bypass cache and force fresh check
        http_retries: Number of retries for HTTP/health checks (default: 1)
        ssl_retries: Number of retries for SSL checks (default: 1)
        domain_retries: Number of retries for domain expiry checks (default: 1)
        timeout: HTTP timeout in seconds (default: 30)
        
    Returns:
        Dictionary with all required fields always present (null if data unavailable)
    """
    # Handle full URLs - preserve original for display but extract domain for processing
    if domain.startswith('http://') or domain.startswith('https://'):
        clean_domain = domain  # Keep full URL for health check
        domain_key = _extract_domain_from_url(domain)  # Use domain for cache key
    else:
        clean_domain = _clean_domain(domain)
        domain_key = clean_domain
    
    now = datetime.now(timezone.utc)
    
    # Initialize result with all required fields
    result = {
        "domain": domain_key,  # Store domain (not full URL) in result
        "input": original_input if original_input else domain,  # Store original input as-is
        "request_sent_datetime": now.strftime('%Y-%m-%d %H:%M:%S'),  # Request timestamp
        # SSL fields
        "ssl_expiry_date": None,
        "ssl_days_left": None,
        "ssl_status": None,
        "ssl_error": None,
        # Health check fields
        "health_status": None,
        "response_time_ms": None,
        "http_status_code": None,
        # Domain expiry fields
        "domain_expiry_date": None,
        "domain_days_left": None,
        "domain_error": None,
        # Website logo field
        "website_logo": None
    }
    
    logger.info(f"Checking SSL certificate for: {domain_key} (force={force}, http_retries={http_retries}, ssl_retries={ssl_retries}, domain_retries={domain_retries}, timeout={timeout}s)")
    
    # Check cache first (unless force=True)
    cached_result = get_cached_result(domain_key, force=force)
    if cached_result:
        logger.info(f"Using cached result for {domain_key}")
        # Update result with cached values, but ensure all fields are present
        result.update(cached_result)
        # Ensure input and timestamp are preserved
        result["input"] = original_input if original_input else domain
        result["request_sent_datetime"] = now.strftime('%Y-%m-%d %H:%M:%S')
        # Ensure all fields exist (fill missing ones with None)
        for field in ["ssl_expiry_date", "ssl_days_left", "ssl_status", "ssl_error",
                     "health_status", "response_time_ms", "http_status_code",
                     "domain_expiry_date", "domain_days_left", "domain_error", "website_logo"]:
            if field not in result:
                result[field] = None
        return result
    
    logger.info(f"Cache miss for {domain_key} - performing fresh checks")
    # Cache miss or needs refresh - perform actual checks
    check_result = _perform_ssl_check(clean_domain, now, force=force, ssl_retries=ssl_retries, http_retries=http_retries, domain_retries=domain_retries, timeout=timeout, ssl_timeout=ssl_timeout, whois_timeout=whois_timeout)
    result.update(check_result)
    
    # Ensure input is preserved
    result["input"] = original_input if original_input else domain
    
    # Save to cache (use domain_key, not full URL)
    logger.debug(f"Saving result to cache for {domain_key}")
    save_to_cache(domain_key, result)
    
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
                    # Ensure all required fields are present even in error case
                    error_result = {
                        "domain": domain,
                        "input": domain,
                        "request_sent_datetime": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
                        "ssl_expiry_date": None,
                        "ssl_days_left": None,
                        "ssl_status": None,
                        "ssl_error": f"Unexpected error: {str(e)}",
                        "health_status": None,
                        "response_time_ms": None,
                        "http_status_code": None,
                        "domain_expiry_date": None,
                        "domain_days_left": None,
                        "domain_error": None
                    }
                    results.append(error_result)
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

