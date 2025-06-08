"""
OpenX Utility Functions
Helper functions for URL validation, parsing, and other utilities
"""

import re
from urllib.parse import urlparse, parse_qs, quote, urlunparse
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
        result = urlparse(url)
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
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
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


def get_normalized_hostname_util(url_str):
    if not url_str:
        return None
    try:
        parsed_url = urlparse(url_str) # urlparse is already imported in utils.py
        hostname = parsed_url.hostname
        if not hostname: # Handles cases like 'javascript:' or 'data:' URIs
            return None
        hostname = hostname.lower()
        # Remove default ports for comparison
        if (parsed_url.scheme == 'http' and parsed_url.port == 80) or \
           (parsed_url.scheme == 'https' and parsed_url.port == 443):
            return hostname
        # If port is non-standard, use netloc (which includes port), else just hostname
        return parsed_url.netloc.lower() if parsed_url.port else hostname
    except ValueError: # Handle malformed URLs that urlparse might struggle with
        return None

def validate_redirect(original_url_str, final_redirect_location_str, payload_value_str, callback_url=None):
    """
    Validate if a redirect is successful and potentially vulnerable.
    A redirect is considered a successful exploitation if:
    1. The redirect_location uses a javascript:, data:, or vbscript: URI scheme.
    2. The redirect_location's normalized hostname matches the payload's normalized hostname,
       AND this hostname is different from the original_url's normalized hostname.
    3. If a callback_url is provided, the redirect_location's normalized hostname matches 
       the callback_url's normalized hostname and is different from the original.
    """
    try:
        final_redirect_location_str = final_redirect_location_str.strip()
        if not final_redirect_location_str:
            return False

        # Check for JavaScript/data/vbscript scheme redirects (these are always a direct hit)
        if final_redirect_location_str.startswith(('javascript:', 'data:', 'vbscript:')):
            return True
            
        original_hostname = get_normalized_hostname_util(original_url_str)
        redirect_hostname = get_normalized_hostname_util(final_redirect_location_str)
        payload_hostname = get_normalized_hostname_util(payload_value_str)

        if not redirect_hostname: # Could be a malformed redirect or non-HTTP scheme not caught above
            return False

        # If callback URL is provided, it takes precedence for validation
        if callback_url:
            callback_hostname = get_normalized_hostname_util(callback_url)
            # Validate if redirect is to the callback host and not a self-redirect to original if original is also callback
            if callback_hostname and redirect_hostname == callback_hostname and original_hostname != callback_hostname:
                return True 
            # If callback is set, and redirect doesn't match it as per above, then it's not a valid redirect for callback purposes.
            return False


        if not payload_hostname: # If payload has no discernible hostname, can't match
            return False

        # Core open redirect validation:
        # 1. Redirect hostname must match payload hostname
        # 2. Redirect hostname must be different from original hostname (to prevent self-redirects being flagged as open)
        if redirect_hostname == payload_hostname and original_hostname != payload_hostname:
            return True
            
        return False
        
    except Exception as e:
        # print(f"Error in validate_redirect: {str(e)}") # Optional: for debugging
        return False

def extract_domain(url):
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
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
        parsed = urlparse(url)
        cleaned = urlunparse((
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
            return quote(payload)
        elif encoding_type == 'double_url':
            return quote(quote(payload))
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
