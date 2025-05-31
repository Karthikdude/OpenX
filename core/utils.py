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
{Fore.RED}  ██████  ██▓███  ▓█████  ███▄    █ ▒██   ██▒
{Fore.RED}▒██    ▒ ▓██░  ██▒▓█   ▀  ██ ▀█   █ ▒▒ █ █ ▒░
{Fore.RED}░ ▓██▄   ▓██░ ██▓▒▒███   ▓██  ▀█ ██▒░░  █   ░
{Fore.RED}  ▒   ██▒▒██▄█▓▒ ▒▒▓█  ▄ ▓██▒  ▐▌██▒ ░ █ █ ▒ 
{Fore.RED}▒██████▒▒▒██▒ ░  ░░▒████▒▒██░   ▓██░▒██▒ ▒██▒
{Fore.RED}▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░░░ ▒░ ░░ ▒░   ▒ ▒ ▒▒ ░ ░▓ ░
{Fore.RED}░ ░▒  ░ ░░▒ ░      ░ ░  ░░ ░░   ░ ▒░░░   ░▒ ░
{Fore.RED}░  ░  ░  ░░          ░      ░   ░ ░  ░    ░  
{Fore.RED}      ░              ░  ░         ░  ░    ░  

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
    """Validate if a redirect is successful and potentially vulnerable"""
    try:
        # Normalize the redirect location
        redirect_location = redirect_location.strip()
        
        # If callback URL is provided, check for it specifically
        if callback_url:
            return callback_url.lower() in redirect_location.lower()
        
        # Check if the redirect location contains our payload
        if payload.lower() in redirect_location.lower():
            return True
        
        # Check for common vulnerability indicators
        vulnerability_indicators = [
            'evil.com', 'attacker.com', 'malicious.com', 'google.com', 'example.com'
        ]
        
        for indicator in vulnerability_indicators:
            if indicator in redirect_location.lower():
                return True
        
        # Check for external redirects (different domain)
        if redirect_location.startswith(('http://', 'https://')):
            return True
        
        # Check for protocol-relative URLs
        if redirect_location.startswith('//'):
            return True
        
        # Check for JavaScript schemes
        if redirect_location.startswith(('javascript:', 'data:', 'vbscript:')):
            return True
        
        return False
        
    except Exception:
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
