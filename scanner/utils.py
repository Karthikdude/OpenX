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
    """Check if a redirect is to an external domain"""
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
    
    # If domains are identical, it's not an external redirect
    if original_domain == redirect_domain:
        return False
    
    # Check for WordPress oEmbed API endpoints (common false positive)
    if 'wp-json/oembed' in original_url and 'url=' in original_url:
        # Extract the domain from the url parameter
        url_param_match = re.search(r'url=([^&]+)', original_url)
        if url_param_match:
            url_param = url_param_match.group(1)
            # URL decode the parameter
            url_param = urllib.parse.unquote(url_param)
            # Extract domain from the url parameter
            url_param_domain = get_domain_from_url(url_param)
            if url_param_domain:
                url_param_domain = url_param_domain.replace('www.', '')
                # If the redirect domain matches the domain in the url parameter, it's not external
                if redirect_domain == url_param_domain or url_param_domain in redirect_domain:
                    return False
    
    # Check for queue systems with target parameter (common false positive)
    if ('queue.' in original_domain or '/queue/' in original_url) and 'target=' in original_url:
        # Extract the domain from the target parameter
        target_param_match = re.search(r'target=([^&]+)', original_url)
        if target_param_match:
            target_param = target_param_match.group(1)
            # URL decode the parameter
            target_param = urllib.parse.unquote(target_param)
            # Extract domain from the target parameter
            target_param_domain = get_domain_from_url(target_param)
            if target_param_domain:
                target_param_domain = target_param_domain.replace('www.', '')
                # If the redirect domain matches the domain in the target parameter, it's not external
                if redirect_domain == target_param_domain or target_param_domain in redirect_domain:
                    return False
                # Check if the original domain without 'queue.' prefix matches the redirect domain
                queue_prefix_removed = original_domain.replace('queue.', '')
                if queue_prefix_removed == target_param_domain:
                    return False
    
    # Check for subdomains of the same parent domain
    original_parts = original_domain.split('.')
    redirect_parts = redirect_domain.split('.')
    
    # Extract the parent domain (last two parts, e.g., example.com)
    if len(original_parts) >= 2 and len(redirect_parts) >= 2:
        original_parent = '.'.join(original_parts[-2:])
        redirect_parent = '.'.join(redirect_parts[-2:])
        
        # If parent domains match, check if this is a legitimate subdomain change
        if original_parent == redirect_parent:
            # List of critical subdomains that should still be flagged even within same parent domain
            critical_subdomains = ['admin', 'secure', 'login', 'auth', 'account', 'payment', 'billing']
            
            # Only flag as external if redirecting to/from critical subdomains
            if any(sub in original_domain for sub in critical_subdomains) or \
               any(sub in redirect_domain for sub in critical_subdomains):
                return True
            else:
                # Non-critical subdomain changes within same parent domain are not external
                return False
    
    # Default: domains are different, so it's an external redirect
    return True

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

def verify_evil_com_redirect(url):
    """Verify that a redirect to evil.com is legitimate by checking for specific markers"""
    try:
        import requests
        from urllib.parse import urlparse
        
        # Parse the URL to check if it's pointing to evil.com or a subdomain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Check if the domain is evil.com or a subdomain
        if not (domain == 'evil.com' or domain.endswith('.evil.com')):
            return False
        
        # Make a request to verify the content
        response = requests.get(url, timeout=10, allow_redirects=True, verify=True)
        
        # Check for specific markers in the response
        markers = [
            'Evil.Com - We get it...Daily.',  # Title
            'we get it... daily',             # Tagline
            'check back daily',                # Footer text
            'www.evil.com'                     # URL in content
        ]
        
        # Count how many markers we find
        marker_count = sum(1 for marker in markers if marker in response.text)
        
        # If we find at least 2 markers, it's likely the real evil.com
        return marker_count >= 2
    except Exception as e:
        # If verification fails, log the error and return False
        print(f"Error verifying evil.com redirect: {str(e)}")
        return False

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
