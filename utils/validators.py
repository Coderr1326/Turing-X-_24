"""
Input Validators
Validates IP addresses, domains, URLs, etc.
"""

import re
import ipaddress

def is_valid_ip(ip_string):
    """Validate if string is a valid IPv4 or IPv6 address"""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

def is_valid_domain(domain):
    """Validate if string is a valid domain name"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

def is_valid_url(url):
    """Validate if string is a valid URL"""
    pattern = r'^https?://(?:www\.)?[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/.*)?$'
    return re.match(pattern, url) is not None

def sanitize_ip(ip_string):
    """Sanitize and normalize IP address"""
    try:
        return str(ipaddress.ip_address(ip_string.strip()))
    except ValueError:
        return None

def validate_confidence_score(score):
    """Validate confidence score is between 0 and 100"""
    try:
        score_float = float(score)
        return 0 <= score_float <= 100
    except (ValueError, TypeError):
        return False
