"""
OpenX Scanner Core Module
Main scanning engine for open redirect vulnerability detection
"""

import requests
import threading
import time
import random
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from colorama import Fore, Style


from .payloads import PayloadManager
from .utils import normalize_url, extract_redirect_params, validate_redirect
from .analyzer import URLAnalyzer
from config.user_agents import get_random_user_agent

class OpenRedirectScanner:
    """Main scanner class for open redirect vulnerability detection"""
    
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.payload_manager = PayloadManager(config.get('custom_payloads'))
        self.analyzer = URLAnalyzer()
        self.total_requests = 0
        self.results_lock = threading.Lock()
        
        # Configure session
        self.session.headers.update({
            'User-Agent': config.get('user_agent') or get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Configure proxy if specified
        if config.get('proxy'):
            self.session.proxies = {
                'http': config['proxy'],
                'https': config['proxy']
            }
        
        # Configure request timeout
        self.timeout = config.get('timeout', 10)
        
        # Configure redirect following
        self.session.max_redirects = config.get('follow_redirects', 5)
    
    def get_total_requests(self):
        """Get total number of requests made"""
        return self.total_requests
    
    def make_request(self, url, method='GET', headers=None, cookies=None, allow_redirects=True):
        """Make HTTP request with error handling"""
        try:
            with self.results_lock:
                self.total_requests += 1
            
            # Add delay if configured
            if self.config.get('delay', 0) > 0:
                time.sleep(self.config['delay'])
            
            # Prepare headers
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
            
            # Rotate user agent randomly
            if not self.config.get('user_agent'):
                request_headers['User-Agent'] = get_random_user_agent()
            
            response = self.session.request(
                method=method,
                url=url,
                headers=request_headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                cookies=cookies
            )
            
            return response
            
        except requests.exceptions.Timeout:
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[WARNING] Timeout for URL: {url}{Style.RESET_ALL}")
            return None
        except requests.exceptions.ConnectionError:
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[WARNING] Connection error for URL: {url}{Style.RESET_ALL}")
            return None
        except requests.exceptions.RequestException as e:
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[WARNING] Request error for {url}: {str(e)}{Style.RESET_ALL}")
            return None
    
    def test_url_parameter(self, url, param, payload):
        """Test a URL parameter with a specific payload"""
        try:
            # Parse URL and add/modify parameter
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            # Set the parameter with the payload
            query_params[param] = [payload]
            
            # Reconstruct URL
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            # Make request without following redirects to analyze response
            response = self.make_request(test_url, allow_redirects=False)
            if not response:
                return None
            
            redirect_chain = []
            final_location = None
            # Store headers of the response that issues the confirmed malicious redirect
            headers_of_redirecting_response = response.headers 

            if response.status_code in [301, 302, 303, 307, 308]:
                first_location_header = response.headers.get('Location', '')
                if first_location_header:
                    redirect_chain.append(first_location_header)
                    current_location_to_follow = first_location_header
                    final_location = first_location_header # Initialize with first redirect
                    headers_of_redirecting_response = response.headers # Default to first response

                    try:
                        max_redirects = self.config.get('follow_redirects', 5)
                        redirect_count = 0
                        
                        # Base URL for resolving relative redirects, using the test_url (URL with payload)
                        # as it's the one making the requests in this context.
                        base_for_relative_redirects = test_url

                        while redirect_count < max_redirects:
                            # Resolve relative URLs against the last known absolute URL in the chain or test_url
                            absolute_url_to_follow = urljoin(base_for_relative_redirects, current_location_to_follow)
                            
                            if self.config.get('verbose'):
                                print(f"{Fore.CYAN}[DEBUG SCANNER] Following redirect from {base_for_relative_redirects} to {current_location_to_follow} (resolved: {absolute_url_to_follow}){Style.RESET_ALL}")

                            follow_response = self.make_request(absolute_url_to_follow, allow_redirects=False)
                            if not follow_response:
                                break 
                                
                            if follow_response.status_code not in [301, 302, 303, 307, 308]:
                                final_location = absolute_url_to_follow # This is where we landed
                                # headers_of_redirecting_response remains from the *previous* redirecting response
                                break
                                
                            next_location_header = follow_response.headers.get('Location', '')
                            if not next_location_header:
                                final_location = absolute_url_to_follow # No more Location, so this is it
                                break
                                
                            redirect_chain.append(next_location_header)
                            current_location_to_follow = next_location_header
                            final_location = next_location_header # Update final_location at each step
                            headers_of_redirecting_response = follow_response.headers # This response issued the (potential) next redirect
                            base_for_relative_redirects = absolute_url_to_follow # Update base for next relative resolution
                            redirect_count += 1
                            
                            if self.config.get('verbose'):
                                print(f"{Fore.CYAN}[INFO] Redirect {redirect_count}/{max_redirects}: {next_location_header}{Style.RESET_ALL}")
                        else: # Max redirects reached
                            if self.config.get('verbose'):
                                 print(f"{Fore.YELLOW}[WARNING] Max redirects ({max_redirects}) reached for {test_url}. Final location in chain: {final_location}{Style.RESET_ALL}")
                    
                    except Exception as e:
                        if self.config.get('verbose'):
                            print(f"{Fore.YELLOW}[WARNING] Error following redirect chain for {test_url}: {str(e)}{Style.RESET_ALL}")
                    
                    if final_location and self._is_external_redirect(url, final_location, payload):
                        result = {
                            'vulnerable': True,
                            'url': test_url,                     # The URL tested (with payload)
                            'original_url': url,                 # The original URL before payload injection
                            'parameter': param,
                            'payload': payload,
                            'method': 'URL Parameter',
                            'status_code': response.status_code, # Status code of the *first* redirecting response
                            'first_location_header': first_location_header, # Location header from the *first* redirecting response
                            'final_location': final_location,    # The ultimate destination URL after all redirects
                            'redirect_chain': redirect_chain,    # List of all Location headers encountered
                            'response_headers': dict(headers_of_redirecting_response) if headers_of_redirecting_response else None # Headers of the response that *issued the last redirect* in the chain (or the first if no chain)
                        }
                        if self.config.get('show_response_headers'):
                            result['vulnerable_response_headers'] = dict(headers_of_redirecting_response)
                        return result
            
            # Check for meta refresh redirects
            if response.status_code == 200:
                content = response.text.lower()
                if 'http-equiv="refresh"' in content or 'meta http-equiv="refresh"' in content:
                    # Extract redirect URL from meta refresh
                    import re
                    meta_pattern = r'content=["\']?\d+;\s*url=([^"\'>\s]+)'
                    match = re.search(meta_pattern, content, re.IGNORECASE)
                    if match:
                        redirect_url = match.group(1)
                        redirect_chain.append(redirect_url)
                        
                        # Try to follow this redirect to verify
                        try:
                            # Handle relative URLs
                            if redirect_url.startswith('/'):
                                full_redirect_url = f"{parsed.scheme}://{parsed.netloc}{redirect_url}"
                            else:
                                full_redirect_url = redirect_url
                                
                            follow_response = self.make_request(full_redirect_url, allow_redirects=False)
                            if follow_response and follow_response.status_code == 200:
                                # Successfully followed the redirect
                                if validate_redirect(payload, redirect_url, self.config.get('callback_url')):
                                    return {
                                        'vulnerable': True,
                                        'url': test_url,
                                        'original_url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'method': 'Meta Refresh',
                                        'status_code': response.status_code,
                                        'redirect_location': redirect_url,
                                        'redirect_chain': redirect_chain,
                                        'severity': self._determine_severity(payload, redirect_url)
                                    }
                        except Exception as e:
                            if self.config.get('verbose'):
                                print(f"{Fore.YELLOW}[WARNING] Error following meta refresh: {str(e)}{Style.RESET_ALL}")
                
                # Check for JavaScript redirects
                js_patterns = [
                    r'window\.location\s*=\s*["\']([^"\']+)["\']',
                    r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
                    r'document\.location\s*=\s*["\']([^"\']+)["\']',
                    r'location\.replace\(["\']([^"\']+)["\']\)',
                    r'window\.location\s*=\s*"([^"]+)"',
                    r'location\.href\s*=\s*["\']([^"\']+)["\']',
                    r'location\.assign\(["\']([^"\']+)["\']\)',
                    r'window\.open\(["\']([^"\']+)["\']',
                    r'document\.location\.href\s*=\s*["\']([^"\']+)["\']',
                    r'top\.location\s*=\s*["\']([^"\']+)["\']',
                    r'parent\.location\s*=\s*["\']([^"\']+)["\']'
                ]
                
                import re
                for pattern in js_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        # Only consider it a vulnerability if we can validate the redirect
                        if validate_redirect(payload, match, self.config.get('callback_url')):
                            # Try to follow this redirect to verify if possible
                            try:
                                # Handle relative URLs
                                if match.startswith('/'):
                                    full_redirect_url = f"{parsed.scheme}://{parsed.netloc}{match}"
                                    follow_response = self.make_request(full_redirect_url, allow_redirects=False)
                                    if not follow_response or follow_response.status_code >= 400:
                                        # Failed to follow the redirect, might be a false positive
                                        continue
                            except Exception:
                                pass  # JavaScript redirects are harder to verify, so we'll accept them
                                
                            return {
                                'vulnerable': True,
                                'url': test_url,
                                'original_url': url,
                                'parameter': param,
                                'payload': payload,
                                'method': 'JavaScript Redirect',
                                'status_code': response.status_code,
                                'redirect_location': match,
                                'severity': self._determine_severity(payload, match)
                            }
            
            return {
                'vulnerable': False,
                'url': test_url,
                'original_url': url,
                'parameter': param,
                'payload': payload,
                'status_code': response.status_code if response else None
            }
            
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[WARNING] Error testing {url} with payload {payload}: {str(e)}{Style.RESET_ALL}")
            return None
    
    def test_header_injection(self, url, header_name, payload):
        """Test header-based open redirect injection"""
        try:
            headers = {header_name: payload}
            response = self.make_request(url, headers=headers, allow_redirects=False)
            
            if not response:
                return None
            
            # Check if the server redirects based on the header
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                # Validate redirect: original_url, final_location, payload_value, callback_url
                if location and validate_redirect(url, location, payload, self.config.get('callback_url')):
                    return {
                        'vulnerable': True,
                        'original_url': url,
                        'url': url, # For header tests, the tested URL is the original URL
                        'header_name': header_name,
                        'payload': payload,
                        'method': 'Header Injection',
                        'status_code': response.status_code,
                        'final_location': location,
                        'response_headers': dict(response.headers) if response.headers else None
                        # Severity to be determined by the caller
                    }
            
            # If not vulnerable or no redirect, return non-vulnerable result
            return {
                'vulnerable': False,
                'original_url': url,
                'url': url,
                'header_name': header_name,
                'payload': payload,
                'status_code': response.status_code,
                'final_location': response.headers.get('Location'), # Include if present
                'response_headers': dict(response.headers) if response.headers else None
            }
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[WARNING] Error testing header {header_name} on {url}: {str(e)}{Style.RESET_ALL}")
            return None
    
    def test_form_redirects(self, url):
        """Test form-based redirect vulnerabilities"""
        results = []
        
        try:
            # First check if there are forms on the page
            response = self.make_request(url)
            if not response or response.status_code != 200:
                return results
            
            content = response.text.lower()
            if '<form' not in content:
                return results
            
            # Test common form redirect parameters
            form_params = ['redirect_to', 'next', 'return', 'success_url', 'failure_url']
            # In fast mode, use fewer payloads
            if self.config.get('fast'):
                test_payloads = ['http://evil.com', '//evil.com'] # Example payloads
            else:
                # Consider expanding these payloads or loading from a configurable list
                test_payloads = ['http://evil.com', '//evil.com', 'javascript:alert(1)'] 
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[WARNING] Error during initial check for forms on {url}: {str(e)}{Style.RESET_ALL}")
            return results # Return if initial check fails or error occurs

        # If initial check passed, proceed to test form parameters
        for param in form_params:
            for payload in test_payloads:
                form_data = {param: payload}
                post_response = None # Initialize post_response
                try:
                    with self.results_lock:
                        self.total_requests += 1 # Increment for the POST request attempt
                    post_response = self.session.post(
                        url,
                        data=form_data,
                        allow_redirects=False,
                        timeout=self.timeout,
                        headers=self.headers # Use consistent headers
                    )
                except requests.exceptions.Timeout:
                    if self.config.get('verbose'):
                        print(f"{Fore.YELLOW}[WARNING] Timeout testing form POST on {url} with param '{param}' and payload '{payload}'{Style.RESET_ALL}")
                    continue # To next payload/param
                except requests.exceptions.RequestException as e:
                    if self.config.get('verbose'):
                        print(f"{Fore.YELLOW}[WARNING] Error testing form POST on {url} with param '{param}': {str(e)}{Style.RESET_ALL}")
                    continue # To next payload/param

                if post_response and post_response.status_code in [301, 302, 303, 307, 308]:
                    location_header = post_response.headers.get('Location', '')
                    if location_header:
                        redirect_chain = [location_header]
                        final_location = location_header
                        current_base_url_for_redirect = url 

                        try:
                            resolved_follow_url = urljoin(current_base_url_for_redirect, location_header)
                            if self.config.get('verbose'):
                                print(f"{Fore.CYAN}[DEBUG SCANNER] Form POST to {url} with {param}={payload} redirected to {location_header}. Attempting to follow to {resolved_follow_url}{Style.RESET_ALL}")
                            
                            follow_response = self.make_request(resolved_follow_url, allow_redirects=False)

                            if follow_response and follow_response.status_code in [301, 302, 303, 307, 308]:
                                next_location_header = follow_response.headers.get('Location', '')
                                if next_location_header:
                                    redirect_chain.append(next_location_header)
                                    final_location = next_location_header 
                                    if self.config.get('verbose'):
                                        print(f"{Fore.CYAN}[DEBUG SCANNER] Form redirect followed to: {final_location}{Style.RESET_ALL}")

                        except Exception as e:
                            if self.config.get('verbose'):
                                print(f"{Fore.YELLOW}[WARNING] Error while trying to follow form redirect from {location_header} for {url}: {str(e)}{Style.RESET_ALL}")
                        
                        if validate_redirect(url, final_location, payload, self.config.get('callback_url')):
                            results.append({
                                'vulnerable': True,
                                'original_url': url,
                                'url': url, 
                                'parameter': param, 
                                'payload': payload,
                                'method': 'Form POST Redirect',
                                'status_code': post_response.status_code, 
                                'final_location': final_location,
                                'redirect_chain': redirect_chain,
                                'response_headers': dict(post_response.headers) if post_response.headers else None
                            })
                            if self.config.get('verbose'):
                                print(f"{Fore.RED}[VULNERABLE] {url} - Form Parameter: {param}, Payload: {payload}, Redirects to: {final_location}{Style.RESET_ALL}")
                            if self.config.get('fast'):
                                return results 
        return results

    def test_cookie_redirects(self, url):
        """Test cookie-based redirect vulnerabilities"""
        results = []
        cookie_names = [
            'redirect_url', 'redirect_uri', 'return_url', 'return_to', 'next_url',
            'next', 'url_redirect', 'redirect', 'return', 'target', 'goto', 'location_cookie',
            'dest', 'destination', 'redir_url', 'callback_url', 'redirect_after_login'
        ]
        if self.config.get('fast'):
            test_payloads = ['http://evil.com', '//evil.com']
        else:
            test_payloads = ['http://evil.com', '//evil.com', 'javascript:alert(1)']

        for cookie_name in cookie_names:
            for payload in test_payloads:
                cookies = {cookie_name: payload}
                response = None
                try:
                    response = self.make_request(url, cookies=cookies, allow_redirects=False)
                    
                    if not response:
                        continue

                    if response.status_code in [301, 302, 303, 307, 308]:
                        location_header = response.headers.get('Location', '')
                        if location_header:
                            redirect_chain = [location_header]
                            final_location = location_header
                            current_base_url_for_redirect = url

                            try:
                                resolved_follow_url = urljoin(current_base_url_for_redirect, location_header)
                                if self.config.get('verbose'):
                                    print(f"{Fore.CYAN}[DEBUG SCANNER] Cookie '{cookie_name}' payload '{payload}' for {url} redirected to {location_header}. Following to {resolved_follow_url}{Style.RESET_ALL}")
                                
                                follow_response = self.make_request(resolved_follow_url, allow_redirects=False)

                                if follow_response and follow_response.status_code in [301, 302, 303, 307, 308]:
                                    next_location_header = follow_response.headers.get('Location', '')
                                    if next_location_header:
                                        redirect_chain.append(next_location_header)
                                        final_location = next_location_header
                                        if self.config.get('verbose'):
                                            print(f"{Fore.CYAN}[DEBUG SCANNER] Cookie redirect for '{cookie_name}' followed to: {final_location}{Style.RESET_ALL}")
                            
                            except Exception as e_follow:
                                if self.config.get('verbose'):
                                    print(f"{Fore.YELLOW}[WARNING] Error following cookie redirect from {location_header} for {url} (cookie: {cookie_name}): {str(e_follow)}{Style.RESET_ALL}")

                            if validate_redirect(url, final_location, payload, self.config.get('callback_url')):
                                results.append({
                                    'vulnerable': True,
                                    'original_url': url,
                                    'url': url,
                                    'cookie_name': cookie_name,
                                    'payload': payload,
                                    'method': 'Cookie Redirect',
                                    'status_code': response.status_code,
                                    'final_location': final_location,
                                    'redirect_chain': redirect_chain,
                                    'response_headers': dict(response.headers) if response.headers else None
                                })
                                if self.config.get('verbose'):
                                    print(f"{Fore.RED}[VULNERABLE] {url} - Cookie: {cookie_name}, Payload: {payload}, Redirects to: {final_location}{Style.RESET_ALL}")
                                if self.config.get('fast'):
                                    return results
                
                except requests.exceptions.Timeout:
                    if self.config.get('verbose'):
                        print(f"{Fore.YELLOW}[WARNING] Timeout testing cookie '{cookie_name}' on {url} with payload '{payload}'{Style.RESET_ALL}")
                except requests.exceptions.RequestException as e_req:
                    if self.config.get('verbose'):
                        print(f"{Fore.YELLOW}[WARNING] Request error testing cookie '{cookie_name}' on {url}: {str(e_req)}{Style.RESET_ALL}")
                except Exception as e_gen:
                    if self.config.get('verbose'):
                         print(f"{Fore.YELLOW}[WARNING] General error testing cookie '{cookie_name}' on {url} with payload '{payload}': {str(e_gen)}{Style.RESET_ALL}")
        return results

    def _test_url_parameters_smart(self, url, smart_payloads, url_analysis):
        """Test URL parameters with intelligent payload selection"""
        results = []
        
        # Extract parameters from URL
        params = extract_redirect_params(url)
        
        # Prioritize parameters based on analysis
        priority_params = [p['name'] for p in url_analysis['priority_parameters']]
        
        # Test high-priority parameters first
        for param in priority_params:
            if param in params:
                for payload in smart_payloads:
                    result = self.test_url_parameter(url, param, payload)
                    if result and result.get('vulnerable'):
                        results.append(result)
                        if self.config.get('fast'):
                            return results
        
        # Test remaining parameters if not in fast mode or no vulnerabilities found
        if not self.config.get('fast') or not results:
            remaining_params = [p for p in params if p not in priority_params]
            for param in remaining_params:
                for payload in smart_payloads:
                    result = self.test_url_parameter(url, param, payload)
                    if result and result.get('vulnerable'):
                        results.append(result)
                        if self.config.get('fast'):
                            return results
        
        return results
    
    def _test_header_injection_smart(self, url, smart_payloads):
        """Test header injection with intelligent payload selection"""
        results = []
        
        # Priority headers for testing
        priority_headers = [
            'Host', 'X-Forwarded-Host', 'X-Real-IP', 'X-HTTP-Host-Override'
        ]
        
        # Test with reduced payload set for headers
        header_payloads = smart_payloads[:10]  # Limit to most effective payloads
        
        for header_name in priority_headers:
            for payload in header_payloads:
                result = self.test_header_injection(url, header_name, payload)
                if result and result.get('vulnerable'):
                    results.append(result)
                    if self.config.get('fast'):
                        return results
        
        return results
    
    def _enhanced_vulnerability_verification(self, url, payload, response):
        """Enhanced vulnerability verification with multiple checks"""
        if not response:
            return False
        
        # Check status code
        if response.status_code not in [301, 302, 303, 307, 308]:
            return False
        
        # Get redirect location
        location = response.headers.get('Location', '')
        if not location:
            return False
        
        # Enhanced validation
        if validate_redirect(payload, location, self.config.get('callback_url')):
            # Additional verification - check if it's a real external redirect
            if self._is_external_redirect(url, location):
                return True
            
            # Check for protocol-relative URLs
            if location.startswith('//') and 'evil.com' in location:
                return True
            
            # Check for JavaScript/data URI schemes

    def _is_external_redirect(self, original_url_str, final_redirect_location_str, payload_value_str):
        """Check if redirect is to an external domain, considering the payload."""
        try:
            def get_normalized_hostname(url_str):
                parsed_url = urlparse(url_str)
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

            original_hostname = get_normalized_hostname(original_url_str)
            redirect_hostname = get_normalized_hostname(final_redirect_location_str)
            payload_hostname = get_normalized_hostname(payload_value_str)

            if not redirect_hostname: # e.g. redirect to "javascript:alert(1)"
                if self.config.get('verbose'):
                    print(f"{Fore.CYAN}[DEBUG SCANNER] Not external: Redirect location has no valid hostname. Original: {original_hostname}, Final Dest: {final_redirect_location_str}, Payload: {payload_hostname}{Style.RESET_ALL}")
                return False

            # Case 1: Redirect to the exact same normalized hostname (internal redirect)
            if original_hostname and original_hostname == redirect_hostname:
                if self.config.get('verbose'):
                    print(f"{Fore.CYAN}[DEBUG SCANNER] Not external: Redirect to same normalized hostname. Original: {original_hostname}, Redirected: {redirect_hostname}, Payload: {payload_hostname}{Style.RESET_ALL}")
                return False

            # Case 2: Redirect to the payload's normalized hostname (potential vulnerability)
            if payload_hostname and redirect_hostname == payload_hostname:
                # This is the primary condition for an open redirect to a controlled payload domain.
                # We've already established original_hostname != redirect_hostname (or original_hostname is None).
                if self.config.get('verbose'):
                    print(f"{Fore.GREEN}[DEBUG SCANNER] External redirect CONFIRMED: Original Host: {original_hostname}, Redirected Host: {redirect_hostname} (Matches payload host: {payload_hostname}){Style.RESET_ALL}")
                return True
        
            # Case 3: Redirect is to a different domain, but not the payload's domain
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[DEBUG SCANNER] Not external: Redirect host ({redirect_hostname}) differs from original ({original_hostname}) but does NOT match payload host ({payload_hostname}). Final Dest: {final_redirect_location_str}{Style.RESET_ALL}")
            return False
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Fore.RED}[DEBUG SCANNER ERROR] Exception in _is_external_redirect: {e}. Original: {original_url_str}, Location: {final_redirect_location_str}, Payload: {payload_value_str}{Style.RESET_ALL}")
            return False

            if payload_domain and redirect_domain == payload_domain:
                if self.config.get('verbose'):
                    print(f"{Fore.GREEN}[DEBUG SCANNER] External redirect CONFIRMED: Original: {original_domain}, Redirected to: {redirect_domain} (Matches payload domain: {payload_domain}){Style.RESET_ALL}")
                return True
            
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[DEBUG SCANNER] Not external: Redirect domain ({redirect_domain}) differs from original ({original_domain}) but does NOT match payload domain ({payload_domain}). Final Dest: {final_redirect_location_str}{Style.RESET_ALL}")
            return False
            

    def _determine_severity(self, original_url_str, payload_value_str, final_redirect_location_str):
        """Determine vulnerability severity based on payload and redirect location."""
        
        # JavaScript/Data URIs are always High
        if final_redirect_location_str.startswith(('javascript:', 'data:', 'vbscript:')):
            return 'High'

        # Check if it's an external redirect to the payload's domain
        # _is_external_redirect already handles hostname normalization and comparison.
        is_vuln_external_redirect = self._is_external_redirect(original_url_str, final_redirect_location_str, payload_value_str)
        if is_vuln_external_redirect:
            return 'High'
        
        # If not a high-severity script URI or direct payload domain redirect,
        # check if it's any other form of HTTP/HTTPS redirect.
        if final_redirect_location_str.startswith(('http://', 'https://', '//')):
            try:
                # We need to compare hostnames to see if it's an internal or external (to non-payload) redirect
                # Accessing the nested get_normalized_hostname directly is tricky / not ideal from here.
                # So, we call urlparse here again. This is slightly redundant but ensures correctness for this method's scope.
                parsed_original_url = urlparse(original_url_str)
                parsed_redirect_url = urlparse(final_redirect_location_str)

                # Use netloc for comparison as it includes port, which is important for same-site check.
                original_netloc = parsed_original_url.netloc.lower() if parsed_original_url.netloc else None
                redirect_netloc = parsed_redirect_url.netloc.lower() if parsed_redirect_url.netloc else None

                if original_netloc and redirect_netloc: # Both URLs have network locations
                    if original_netloc != redirect_netloc:
                        # Different netloc implies an external redirect.
                        # Since it wasn't caught by _is_external_redirect, it's to a non-payload domain.
                        return 'Medium' 
                    else:
                        # Same netloc, so it's an internal redirect.
                        return 'Low' 
                elif redirect_netloc: 
                    # Original_netloc is empty (e.g. 'file://' or malformed), but redirect_netloc is not.
                    # This is likely an external redirect.
                    return 'Medium'
                else: 
                    # Both netlocs might be empty, or redirect_netloc is empty (e.g. 'javascript:').
                    # javascript: case is handled above. Other cases are likely Low.
                    return 'Low'    
            except Exception: # pylint: disable=broad-except
                # If any parsing error occurs, default to Low.
                if self.config.get('verbose'):
                    print(f"{Fore.YELLOW}[DEBUG SCANNER] Error during severity determination (medium/low check) for: {original_url_str} -> {final_redirect_location_str}{Style.RESET_ALL}")
                return 'Low' 
                
        return 'Low' # Default for non-HTTP/S redirects or other cases not caught (e.g. 'mailto:', 'ftp:')
    
    def scan_single_url(self, url):
        """Scan a single URL for open redirect vulnerabilities"""
        results = []
        
        if self.config.get('verbose'):
            print(f"{Fore.CYAN}[INFO] Scanning: {url}{Style.RESET_ALL}")
        
        # Extract potential redirect parameters from URL
        redirect_params = extract_redirect_params(url)
        
        # If no parameters found, try common ones
        if not redirect_params:
            redirect_params = [
                'url', 'redirect', 'return', 'callback', 'next', 'target', 'goto', 'link', 
                'destination', 'forward', 'continue', 'redirect_url', 'redirect_uri', 
                'returnUrl', 'returnURL', 'return_url', 'backUrl', 'back_url', 'successUrl', 
                'success_url', 'failureUrl', 'failure_url', 'redirectTo', 'redirect_to',
                'site', 'domain', 'host', 'location', 'path', 'page', 'ref', 'referer',
                'source', 'from', 'origin', 'redir', 'exit', 'out', 'away', 'external'
            ]
        
        # Get payloads for testing
        all_payloads = self.payload_manager.get_payloads()
        
        # In fast mode, limit payloads per parameter but test all likely parameters
        if self.config.get('fast'):
            effective_payloads_param = all_payloads[:3]
        else:
            effective_payloads_param = all_payloads
        
        url_vulnerable_flag = False # Tracks if any vulnerability is found for this URL
        
        # Test URL parameters
        for param in redirect_params:
            if url_vulnerable_flag and self.config.get('fast'):
                break 
            
            for payload_item in effective_payloads_param:
                result = self.test_url_parameter(url, param, payload_item)
                if result:
                    if result.get('vulnerable'):
                        try:
                            severity = self._determine_severity(
                                result.get('original_url'), 
                                result.get('payload'), 
                                result.get('final_location')
                            )
                            result['severity'] = severity
                        except KeyError as e_key:
                            if self.config.get('verbose'): print(f"{Fore.RED}[ERROR SCANNER] Param Sev Det: Missing key {e_key} in {result}{Style.RESET_ALL}")
                            result['severity'] = 'ErrorDeterminingSeverity'
                        except Exception as e_sev:
                            if self.config.get('verbose'): print(f"{Fore.RED}[ERROR SCANNER] Param Sev Det: Error for {result}: {e_sev}{Style.RESET_ALL}")
                            result['severity'] = 'ErrorDeterminingSeverity'
                        
                        url_vulnerable_flag = True
                        if self.config.get('verbose'):
                            print(f"{Fore.RED}[VULNERABLE] {url} - Parameter: {param}, Payload: {payload_item}, Severity: {result.get('severity')}{Style.RESET_ALL}")
                        
                        results.append(result)
                        if self.config.get('fast'):
                            if self.config.get('verbose'): print(f"{Fore.YELLOW}[FAST MODE] Param test: Found vulnerability on URL '{url}', stopping all further tests on this URL.{Style.RESET_ALL}")
                            return results 
                    else:
                        results.append(result) 
        
        # Test header injection if enabled
        if self.config.get('headers_test'):
            header_payloads_all = self.payload_manager.get_header_payloads()
            if self.config.get('fast'):
                effective_payloads_header = header_payloads_all[:3] 
            else:
                effective_payloads_header = header_payloads_all
            
            header_names = [
                'Host', 'X-Forwarded-Host', 'X-Forwarded-For', 'X-Real-IP', 
                'X-Forwarded-Proto', 'X-Forwarded-Server', 'X-Host', 'X-HTTP-Host-Override',
                'Referer', 'Origin', 'X-Original-URL', 'X-Rewrite-URL', 'CF-Connecting-IP'
            ]
            
            for header_name in header_names:
                if url_vulnerable_flag and self.config.get('fast'):
                    break

                for payload_item in effective_payloads_header:
                    result = self.test_header_injection(url, header_name, payload_item)
                    if result:
                        if result.get('vulnerable'):
                            try:
                                severity = self._determine_severity(
                                    result.get('original_url'), 
                                    result.get('payload'), 
                                    result.get('final_location')
                                )
                                result['severity'] = severity
                            except KeyError as e_key:
                                if self.config.get('verbose'): print(f"{Fore.RED}[ERROR SCANNER] Header Sev Det: Missing key {e_key} in {result}{Style.RESET_ALL}")
                                result['severity'] = 'ErrorDeterminingSeverity'
                            except Exception as e_sev:
                                if self.config.get('verbose'): print(f"{Fore.RED}[ERROR SCANNER] Header Sev Det: Error for {result}: {e_sev}{Style.RESET_ALL}")
                                result['severity'] = 'ErrorDeterminingSeverity'

                            url_vulnerable_flag = True
                            if self.config.get('verbose'):
                                print(f"{Fore.RED}[VULNERABLE] {url} - Header: {header_name}, Payload: {payload_item}, Severity: {result.get('severity')}{Style.RESET_ALL}")
                            
                            results.append(result)
                            if self.config.get('fast'):
                                if self.config.get('verbose'): print(f"{Fore.YELLOW}[FAST MODE] Header test: Found vulnerability on URL '{url}', stopping all further tests on this URL.{Style.RESET_ALL}")
                                return results 
                        else:
                            results.append(result)
        
        # Test form-based redirects
        form_results_list = self.test_form_redirects(url)
        if form_results_list:
            processed_form_results = []
            any_form_vulnerable_in_batch = False
            for res_item in form_results_list:
                if res_item.get('vulnerable'):
                    try:
                        severity = self._determine_severity(
                            res_item.get('original_url'),
                            res_item.get('payload'),
                            res_item.get('final_location')
                        )
                        res_item['severity'] = severity
                    except KeyError as e_key:
                        if self.config.get('verbose'): print(f"{Fore.RED}[ERROR SCANNER] Form Sev Det: Missing key {e_key} in {res_item}{Style.RESET_ALL}")
                        res_item['severity'] = 'ErrorDeterminingSeverity'
                    except Exception as e_sev:
                        if self.config.get('verbose'): print(f"{Fore.RED}[ERROR SCANNER] Form Sev Det: Error for {res_item}: {e_sev}{Style.RESET_ALL}")
                        res_item['severity'] = 'ErrorDeterminingSeverity'
                    
                    any_form_vulnerable_in_batch = True
                    url_vulnerable_flag = True
                    if self.config.get('verbose'):
                        print(f"{Fore.RED}[VULNERABLE SCANNER] {res_item.get('url')} - Form Param: {res_item.get('parameter', 'N/A')}, Payload: {res_item.get('payload')}, Method: {res_item.get('method')}, Severity: {res_item.get('severity')}{Style.RESET_ALL}")
                processed_form_results.append(res_item)
            
            results.extend(processed_form_results)
            if self.config.get('fast') and any_form_vulnerable_in_batch:
                if self.config.get('verbose'): print(f"{Fore.YELLOW}[FAST MODE] Form test: Found vulnerability on URL '{url}', stopping all further tests on this URL.{Style.RESET_ALL}")
                return results
        
        # Test cookie-based redirects
        cookie_results_list = self.test_cookie_redirects(url)
        if cookie_results_list:
            processed_cookie_results = []
            any_cookie_vulnerable_in_batch = False
            for res_item in cookie_results_list:
                if res_item.get('vulnerable'):
                    try:
                        severity = self._determine_severity(
                            res_item.get('original_url'),
                            res_item.get('payload'),
                            res_item.get('final_location')
                        )
                        res_item['severity'] = severity
                    except KeyError as e_key:
                        if self.config.get('verbose'): print(f"{Fore.RED}[ERROR SCANNER] Cookie Sev Det: Missing key {e_key} in {res_item}{Style.RESET_ALL}")
                        res_item['severity'] = 'ErrorDeterminingSeverity'
                    except Exception as e_sev:
                        if self.config.get('verbose'): print(f"{Fore.RED}[ERROR SCANNER] Cookie Sev Det: Error for {res_item}: {e_sev}{Style.RESET_ALL}")
                        res_item['severity'] = 'ErrorDeterminingSeverity'

                    any_cookie_vulnerable_in_batch = True
                    url_vulnerable_flag = True
                    if self.config.get('verbose'):
                         print(f"{Fore.RED}[VULNERABLE SCANNER] {res_item.get('url')} - Cookie: {res_item.get('cookie_name', 'N/A')}, Payload: {res_item.get('payload')}, Method: {res_item.get('method')}, Severity: {res_item.get('severity')}{Style.RESET_ALL}")
                processed_cookie_results.append(res_item)

            results.extend(processed_cookie_results)
            if self.config.get('fast') and any_cookie_vulnerable_in_batch:
                if self.config.get('verbose'): print(f"{Fore.YELLOW}[FAST MODE] Cookie test: Found vulnerability on URL '{url}', stopping all further tests on this URL.{Style.RESET_ALL}")
                return results
        
        return results
        
        # In fast mode, scan URLs sequentially, stop testing each URL after first vulnerability found
        if self.config.get('fast'):
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[FAST MODE] Scanning each URL until first vulnerability found, then moving to next URL{Style.RESET_ALL}")
            
            with tqdm(total=len(urls), desc="Scanning URLs (Fast Mode)", 
                     bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                     disable=self.config.get('verbose', False)) as pbar:
                
                for url in urls:
                    try:
                        results = self.scan_single_url(url)
                        if results:
                            all_results.extend(results)
                            # Check if any vulnerability was found on this URL
                            vulnerable_results = [r for r in results if r.get('vulnerable', False)]
                            if vulnerable_results and self.config.get('verbose'):
                                print(f"{Fore.YELLOW}[FAST MODE] Found {len(vulnerable_results)} vulnerability(ies) on {url}, moving to next URL{Style.RESET_ALL}")
                    except Exception as e:
                        if self.config.get('verbose'):
                            print(f"{Fore.RED}[ERROR] Failed to scan {url}: {str(e)}{Style.RESET_ALL}")
                    finally:
                        pbar.update(1)
        else:
            # Regular mode: scan all URLs concurrently
            with tqdm(total=len(urls), desc="Scanning URLs", 
                     bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                     disable=self.config.get('verbose', False)) as pbar:
                
                # Use ThreadPoolExecutor for concurrent scanning
                with ThreadPoolExecutor(max_workers=self.config.get('threads', 10)) as executor:
                    # Submit all URLs for scanning
                    future_to_url = {executor.submit(self.scan_single_url, url): url for url in urls}
                    
                    # Process completed scans
                    for future in as_completed(future_to_url):
                        url = future_to_url[future]
                        try:
                            results = future.result()
                            if results:
                                all_results.extend(results)
                        except Exception as e:
                            if self.config.get('verbose'):
                                print(f"{Fore.RED}[ERROR] Failed to scan {url}: {str(e)}{Style.RESET_ALL}")
                        finally:
                            pbar.update(1)
        
        return all_results
