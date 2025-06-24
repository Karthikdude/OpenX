"""
Utility functions for OpenX scanner
"""

import re
import urllib.parse
import socket
from urllib.parse import urlparse

def validate_url(url):
    """Validate if a URL is properly formatted"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def load_urls_from_file(filepath):
    """Load URLs from a file, one per line"""
    urls = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#') and validate_url(url):
                    urls.append(url)
    except FileNotFoundError:
        raise FileNotFoundError(f"URL file not found: {filepath}")
    except Exception as e:
        raise Exception(f"Error reading URL file: {str(e)}")
    
    return urls

def get_domain_from_url(url):
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return None

def is_external_redirect(original_url, redirect_url):
    """Check if redirect URL is external to the original domain"""
    if not redirect_url:
        return False
    
    # Handle relative URLs
    if redirect_url.startswith('/'):
        return False
    
    # Handle protocol-relative URLs
    if redirect_url.startswith('//'):
        redirect_url = 'http:' + redirect_url
    
    # Handle URLs without protocol
    if not redirect_url.startswith(('http://', 'https://')):
        # Check for other protocols that might be dangerous
        if redirect_url.startswith(('javascript:', 'data:', 'ftp:', 'file:')):
            return True
        # Assume it's a domain if it contains a dot
        if '.' in redirect_url and not redirect_url.startswith('./'):
            redirect_url = 'http://' + redirect_url
        else:
            return False
    
    original_domain = get_domain_from_url(original_url)
    redirect_domain = get_domain_from_url(redirect_url)
    
    if not original_domain or not redirect_domain:
        return False
    
    # Remove www. prefix for comparison
    original_domain = original_domain.replace('www.', '')
    redirect_domain = redirect_domain.replace('www.', '')
    
    # Check if domains are different
    return original_domain != redirect_domain

def extract_redirect_url(response_text, payload):
    """Extract redirect URLs from response text"""
    redirect_urls = []
    
    # Look for the payload in the response
    if payload not in response_text:
        return redirect_urls
    
    # Find URLs that contain our payload
    url_patterns = [
        r'https?://[^\s<>"\'\)]+',
        r'//[^\s<>"\'\)]+',
        r'[a-zA-Z][a-zA-Z0-9+.-]*://[^\s<>"\'\)]+'
    ]
    
    for pattern in url_patterns:
        matches = re.findall(pattern, response_text)
        for match in matches:
            if payload in match:
                redirect_urls.append(match)
    
    return redirect_urls

def parse_response_for_redirects(response_text, payload):
    """Parse response text for JavaScript and meta refresh redirects"""
    redirects = []
    
    if not response_text or payload not in response_text:
        return redirects
    
    # JavaScript window.location redirects
    js_patterns = [
        r'window\.location\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'window\.location\.href\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'window\.location\.replace\s*\(\s*[\'"]([^\'"]+)[\'"]',
        r'location\.href\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'location\s*=\s*[\'"]([^\'"]+)[\'"]',
        r'document\.location\s*=\s*[\'"]([^\'"]+)[\'"]',
    ]
    
    for pattern in js_patterns:
        matches = re.findall(pattern, response_text, re.IGNORECASE)
        for match in matches:
            if payload in match:
                redirects.append(match)
    
    # Meta refresh redirects
    meta_pattern = r'<meta[^>]+http-equiv=[\'"]refresh[\'"][^>]+content=[\'"][^;]*;\s*url=([^\'"]+)[\'"]'
    meta_matches = re.findall(meta_pattern, response_text, re.IGNORECASE)
    for match in meta_matches:
        if payload in match:
            redirects.append(match)
    
    # HTML form action redirects (if payload is in action)
    form_pattern = r'<form[^>]+action=[\'"]([^\'"]+)[\'"]'
    form_matches = re.findall(form_pattern, response_text, re.IGNORECASE)
    for match in form_matches:
        if payload in match:
            redirects.append(match)
    
    return list(set(redirects))  # Remove duplicates

def is_valid_domain(domain):
    """Check if domain is valid"""
    try:
        # Remove protocol if present
        if '://' in domain:
            domain = domain.split('://', 1)[1]
        
        # Remove path if present
        if '/' in domain:
            domain = domain.split('/', 1)[0]
        
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':', 1)[0]
        
        # Basic domain validation
        if not domain or len(domain) > 253:
            return False
        
        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
            return False
        
        # Check if it resolves (optional, might be slow)
        # socket.gethostbyname(domain)
        
        return True
    except Exception:
        return False

def normalize_url(url):
    """Normalize URL for consistent processing"""
    if not url:
        return url
    
    # Add protocol if missing
    if url.startswith('//'):
        url = 'http:' + url
    elif not url.startswith(('http://', 'https://')):
        if '.' in url and not url.startswith('./'):
            url = 'http://' + url
    
    return url

def get_severity_score(vulnerability):
    """Calculate severity score for vulnerability"""
    score = 0
    
    # Base score for open redirect
    score += 5
    
    # Higher score for direct redirects vs JavaScript/Meta
    if vulnerability.get('method') == 'URL Parameter':
        score += 3
    elif vulnerability.get('method') == 'Header Injection':
        score += 4
    elif 'JavaScript' in vulnerability.get('method', ''):
        score += 2
    
    # Higher score for HTTPS targets
    if vulnerability.get('url', '').startswith('https://'):
        score += 1
    
    # Lower score for localhost/internal redirects
    location = vulnerability.get('location_header', '')
    if any(internal in location for internal in ['127.0.0.1', 'localhost', '192.168.', '10.', '172.16.']):
        score -= 2
    
    # Determine severity level
    if score >= 8:
        return 'Critical'
    elif score >= 6:
        return 'High'
    elif score >= 4:
        return 'Medium'
    else:
        return 'Low'
