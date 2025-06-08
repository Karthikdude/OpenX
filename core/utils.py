"""
OpenX Utility Functions
Helper functions for URL validation, parsing, and other utilities
"""

import re
import urllib.parse
from colorama import Fore, Back, Style

def display_banner():
    """Display OpenX banner"""
    banner = f"""
 ██████╗ ██████╗ ███████╗███╗   ██╗██╗  ██╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║╚██╗██╔╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ╚███╔╝ 
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ██╔██╗ 
╚██████╔╝██║     ███████╗██║ ╚████║██╔╝ ██╗
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝

{Fore.CYAN}OpenX - Advanced Open Redirect Scanner v1.0
{Fore.CYAN}Developed by: Karthik S Sathyan
{Fore.YELLOW}Advanced vulnerability detection with multi-threading support
{Style.RESET_ALL}
"""
    print(banner)

def validate_url(url):
    """Validate URL format"""
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def normalize_url(url):
    """Normalize URL format"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url

def load_urls_from_file(file_path):
    """Load URLs from a file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            urls = []
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    # Normalize and validate URL
                    normalized_url = normalize_url(line)
                    if validate_url(normalized_url):
                        urls.append(normalized_url)
                    else:
                        print(f"{Fore.YELLOW}[WARNING] Invalid URL at line {line_num}: {line}{Style.RESET_ALL}")
            return urls
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR] File not found: {file_path}{Style.RESET_ALL}")
        return []
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to read file {file_path}: {str(e)}{Style.RESET_ALL}")
        return []

def extract_redirect_params(url):
    """Extract potential redirect parameters from URL"""
    common_redirect_params = [
        'url', 'redirect', 'return', 'callback', 'next', 'target', 'goto', 'link',
        'forward', 'continue', 'destination', 'redir', 'location', 'site',
        'returnUrl', 'returnURL', 'redirect_uri', 'redirectUrl', 'redirectURL',
        'returnTo', 'return_to', 'backUrl', 'back_url', 'successUrl', 'success_url'
    ]
    
    try:
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Find parameters that might be used for redirection
        potential_params = []
        for param in query_params.keys():
            if param.lower() in [p.lower() for p in common_redirect_params]:
                potential_params.append(param)
        
        # If no obvious redirect params found, return common ones to test
        if not potential_params:
            potential_params = common_redirect_params[:10]  # Test top 10 common params
        
        return potential_params
    except:
        return common_redirect_params[:10]

def validate_redirect(payload, redirect_location, callback_url=None):
    """Validate if a redirect is successful and potentially vulnerable
    
    A redirect is considered vulnerable if:
    1. The redirect_location domain exactly matches the payload domain
    2. The redirect_location contains the payload domain as a subdomain
    3. The redirect uses a javascript: or data: URI scheme
    4. If a callback_url is provided, the redirect matches that domain
    """
    try:
        # Normalize the redirect location
        redirect_location = redirect_location.strip()
        
        # If no redirect location, it's not vulnerable
        if not redirect_location:
            return False
        
        # Check for JavaScript/data scheme redirects (these are always vulnerable)
        if redirect_location.startswith(('javascript:', 'data:', 'vbscript:')):
            return True
            
        # Extract the payload domain for comparison
        payload_domain = None
        if '://' in payload:
            try:
                payload_parsed = urllib.parse.urlparse(payload)
                payload_domain = payload_parsed.netloc.lower()
            except:
                pass
        
        # If we couldn't extract a domain from the payload, it's not vulnerable
        if not payload_domain:
            return False
        
        # Extract the redirect domain for comparison
        redirect_domain = None
        if redirect_location.startswith(('http://', 'https://', '//')):
            try:
                # Handle protocol-relative URLs
                if redirect_location.startswith('//'):
                    redirect_location = 'http:' + redirect_location
                    
                redirect_parsed = urllib.parse.urlparse(redirect_location)
                redirect_domain = redirect_parsed.netloc.lower()
            except:
                pass
        
        # If we couldn't extract a domain from the redirect, it's not vulnerable
        if not redirect_domain:
            return False
        
        # If callback URL is provided, check for exact domain match
        if callback_url and redirect_domain:
            callback_parsed = urllib.parse.urlparse(callback_url)
            callback_domain = callback_parsed.netloc.lower()
            return callback_domain == redirect_domain
        
        # Check for exact domain match with payload
        if payload_domain == redirect_domain:
            return True
        
        # Check if redirect domain ends with the payload domain (subdomain case)
        if redirect_domain.endswith('.' + payload_domain):
            return True
            
        # Check if the redirect URL contains the payload domain as a parameter
        # This is NOT a vulnerability - the domain must be the actual destination
        # HubSpot and similar services often include the original URL as a parameter
        
        # Check for common malicious domains that we're testing with
        vulnerability_indicators = [
            'evil.com', 'attacker.com', 'malicious.com', 'example.com', 'test.com',
            'xss.rocks', 'hackme.com', 'attacker-site.com'
        ]
        
        # Only consider it vulnerable if the redirect_domain itself matches our test domains
        for indicator in vulnerability_indicators:
            if redirect_domain == indicator or redirect_domain.endswith('.' + indicator):
                return True
        
        # If the payload domain is in our list of test domains and the redirect is NOT to
        # a known safe domain like login pages, then it might be vulnerable
        if any(payload_domain == indicator or payload_domain.endswith('.' + indicator) 
               for indicator in vulnerability_indicators):
            
            # Check against known safe domains that are not vulnerable
            safe_domains = ['hubspot.com', 'app.hubspot.com', 'login', 'auth', 'sso']
            if any(safe in redirect_domain for safe in safe_domains):
                return False
                
            return True
        
        return False
        
    except Exception as e:
        print(f"Error in validate_redirect: {str(e)}")
        return False

def extract_domain(url):
    """Extract domain from URL"""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc
    except:
        return None

def is_same_domain(url1, url2):
    """Check if two URLs belong to the same domain"""
    try:
        domain1 = extract_domain(url1)
        domain2 = extract_domain(url2)
        return domain1 and domain2 and domain1.lower() == domain2.lower()
    except:
        return False

def clean_url(url):
    """Clean and normalize URL"""
    try:
        # Remove fragments and normalize
        parsed = urllib.parse.urlparse(url)
        cleaned = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, parsed.query, ''
        ))
        return cleaned
    except:
        return url

def encode_payload(payload, encoding_type='url'):
    """Encode payload based on encoding type"""
    try:
        if encoding_type == 'url':
            return urllib.parse.quote(payload)
        elif encoding_type == 'double_url':
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding_type == 'html':
            return payload.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        else:
            return payload
    except:
        return payload

def format_time(seconds):
    """Format time duration in human readable format"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds // 60
        secs = seconds % 60
        return f"{int(minutes)}m {secs:.1f}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{int(hours)}h {int(minutes)}m"

def truncate_string(text, max_length=100):
    """Truncate string to specified length"""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."
