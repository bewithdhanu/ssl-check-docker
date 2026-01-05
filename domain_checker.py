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
import re
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


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
        "registrar": None,
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
                    timeout=10
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
                    timeout=10
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
                timeout=10
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
            status_code = e.code
            result["health_status"] = "UP" if 200 <= status_code < 500 else "DOWN"
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
        result["ssl_status"] = "DNS_ERROR"
    except socket.timeout:
        # Connection timeout means site is likely down, SSL check not relevant
        result["ssl_status"] = "DOWN"
        result["ssl_error"] = "Connection timeout - site appears to be down"
    except ssl.SSLError as e:
        result["ssl_error"] = f"SSL error: {str(e)}"
        result["ssl_status"] = "SSL_ERROR"
    except Exception as e:
        result["ssl_error"] = f"Unexpected SSL error: {str(e)}"
        result["ssl_status"] = "ERROR"
    
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
        domain_expiry, whois_details = check_domain_expiry(main_domain)
        
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
    
    return result


def check_ssl_certificate(domain: str, original_input: Optional[str] = None) -> Dict[str, Any]:
    """
    Check SSL certificate for a given domain with caching.
    
    Args:
        domain: Domain name to check
        original_input: Original user input (as provided) - optional
        
    Returns:
        Dictionary with domain, expiry_date, days_left, status, and request timestamp
    """
    clean_domain = _clean_domain(domain)
    now = datetime.now(timezone.utc)
    result = {
        "domain": clean_domain,
        "input": original_input if original_input else domain,  # Store original input as-is
        "request_sent_datetime": now.strftime('%Y-%m-%d %H:%M:%S')  # Request timestamp
    }
    
    # Check cache first
    cached_result = get_cached_result(clean_domain)
    if cached_result:
        # Use cached result
        result.update(cached_result)
        # Ensure input and timestamp are preserved
        result["input"] = original_input if original_input else domain
        result["request_sent_datetime"] = now.strftime('%Y-%m-%d %H:%M:%S')
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

