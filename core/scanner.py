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
    
    def make_request(self, url, method='GET', headers=None, allow_redirects=True):
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
                allow_redirects=allow_redirects
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
                            'url': test_url,
                            'original_url': url,
                            'parameter': param,
                            'payload': payload,
                            'method': 'URL Parameter',
                            'status_code': response.status_code, # Initial redirect status
                            'redirects_to': final_location,
                            'response_location_header': first_location_header, # From the first 3xx response
                            'redirect_chain': redirect_chain,
                            'severity': self._determine_severity(payload, final_location)
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
                if location and validate_redirect(payload, location, self.config.get('callback_url')):
                    return {
                        'vulnerable': True,
                        'url': url,
                        'header': header_name,
                        'payload': payload,
                        'method': 'Header Injection',
                        'status_code': response.status_code,
                        'redirect_location': location,
                        'severity': self._determine_severity(payload, location)
                    }
            
            return {
                'vulnerable': False,
                'url': url,
                'header': header_name,
                'payload': payload,
                'status_code': response.status_code
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
                test_payloads = ['http://evil.com', '//evil.com']
            else:
                test_payloads = ['http://evil.com', '//evil.com', 'javascript:alert(1)']
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[WARNING] Error checking for forms on {url}: {str(e)}{Style.RESET_ALL}")
            return results
            
            for param in form_params:
                for payload in test_payloads:
                    form_data = {param: payload}
                    
                    # Test POST request
                    try:
                        post_response = self.session.post(
                            url, 
                            data=form_data, 
                            allow_redirects=False, 
                            timeout=self.timeout
                        )
                    except Exception as e:
                        if self.config.get('verbose'):
                            print(f"{Fore.YELLOW}[WARNING] Error testing form POST on {url}: {str(e)}{Style.RESET_ALL}")
                        continue
                        
                        with self.results_lock:
                            self.total_requests += 1
                        
                        if post_response.status_code in [301, 302, 303, 307, 308]:
                            location = post_response.headers.get('Location', '')
                            if location:
                                # Store redirect chain for verification
                                redirect_chain = [location]
                                final_location = location
                                
                                # Follow the redirect manually to verify it works
                                try:
                                    # Handle relative URLs
                                    parsed = urllib.parse.urlparse(url)
                                    if location.startswith('/'):
                                        redirect_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                                    else:
                                        redirect_url = location
                                        
                                    # Make a follow-up request to verify the redirect
                                    follow_response = self.make_request(redirect_url, allow_redirects=False)
                                    if follow_response and follow_response.status_code in [200, 301, 302, 303, 307, 308]:
                                        # If this is another redirect, add to chain
                                        if follow_response.status_code in [301, 302, 303, 307, 308]:
                                            next_location = follow_response.headers.get('Location', '')
                                            if next_location:
                                                redirect_chain.append(next_location)
                                                final_location = next_location
                                except Exception as e:
                                    if self.config.get('verbose'):
                                        print(f"{Fore.YELLOW}[WARNING] Error following form redirect: {str(e)}{Style.RESET_ALL}")
                                
                                # Validate if this is a successful redirect to our payload
                                if validate_redirect(payload, final_location, self.config.get('callback_url')):
                                    results.append({
                                        'vulnerable': True,
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'method': 'Form POST Redirect',
                                        'status_code': post_response.status_code,
                                        'redirect_location': final_location,
                                        'redirect_chain': redirect_chain,
                                        'severity': self._determine_severity(payload, final_location)
                                    })
                                    
                                    if self.config.get('verbose'):
                                        print(f"{Fore.RED}[VULNERABLE] {url} - Form Parameter: {param}, Payload: {payload}{Style.RESET_ALL}")
                                    
                                    # In fast mode, return immediately after first vulnerability
                                    if self.config.get('fast'):
                                        return results
        return results
    
    def test_cookie_redirects(self, url):
        """Test cookie-based redirect vulnerabilities"""
        results = []
        
        try:
            # Common cookie names used for redirects
            cookie_names = [
                'redirect_url', 'redirect_uri', 'return_url', 'return_to', 'next_url',
                'next', 'url', 'redirect', 'return', 'target', 'goto', 'location'
            ]
            
            # Get payloads
            payloads = self.payload_manager.get_payloads()
            
            # Test each cookie with each payload
            for cookie_name in cookie_names:
                for payload in payloads[:3]:  # Limit to first 3 payloads for efficiency
                    # Create cookie with payload
                    cookies = {cookie_name: payload}
                    
                    # Make request with cookie
                    response = self.make_request(url, headers={'Cookie': f"{cookie_name}={payload}"}, allow_redirects=False)
                    if not response:
                        continue
                    
                    # Store redirect chain for verification
                    redirect_chain = []
                    final_location = None
                    
                    # Check for redirect response
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if location:
                            # Add to redirect chain
                            redirect_chain.append(location)
                            final_location = location
                            
                            # Follow the redirect manually to verify it works
                            try:
                                # Handle relative URLs
                                parsed = urllib.parse.urlparse(url)
                                if location.startswith('/'):
                                    redirect_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                                else:
                                    redirect_url = location
                                    
                                # Make a follow-up request to verify the redirect
                                follow_response = self.make_request(redirect_url, allow_redirects=False)
                                if follow_response and follow_response.status_code in [200, 301, 302, 303, 307, 308]:
                                    # If this is another redirect, add to chain
                                    if follow_response.status_code in [301, 302, 303, 307, 308]:
                                        next_location = follow_response.headers.get('Location', '')
                                        if next_location:
                                            redirect_chain.append(next_location)
                                            final_location = next_location
                            except Exception as e:
                                if self.config.get('verbose'):
                                    print(f"{Fore.YELLOW}[WARNING] Error following cookie redirect: {str(e)}{Style.RESET_ALL}")
                            
                            # Validate if this is a successful redirect to our payload
                            if validate_redirect(payload, final_location, self.config.get('callback_url')):
                                result = {
                                    'vulnerable': True,
                                    'url': url,
                                    'original_url': url,
                                    'cookie': cookie_name,
                                    'payload': payload,
                                    'method': 'Cookie-based Redirect',
                                    'status_code': response.status_code,
                                    'redirect_location': final_location,
                                    'redirect_chain': redirect_chain,
                                    'severity': self._determine_severity(payload, final_location)
                                }
                                results.append(result)
                                
                                if self.config.get('verbose'):
                                    print(f"{Fore.RED}[VULNERABLE] {url} - Cookie: {cookie_name}, Payload: {payload}{Style.RESET_ALL}")
                                
                                # If in fast mode, return after first vulnerability
                                if self.config.get('fast'):
                                    print(f"{Fore.YELLOW}[FAST MODE] Found vulnerability on cookie '{cookie_name}', moving to next parameter{Style.RESET_ALL}")
                                    break
                    
                    # Check for meta refresh or JavaScript redirects in response content
                    elif response.status_code == 200:
                        content = response.text.lower()
                        
                        # Check for meta refresh
                        if 'http-equiv="refresh"' in content or 'meta http-equiv="refresh"' in content:
                            import re
                            meta_pattern = r'content=["\']?\d+;\s*url=([^"\'>\s]+)'
                            match = re.search(meta_pattern, content, re.IGNORECASE)
                            if match:
                                redirect_url = match.group(1)
                                redirect_chain.append(redirect_url)
                                
                                # Try to follow this redirect to verify
                                try:
                                    # Handle relative URLs
                                    parsed = urllib.parse.urlparse(url)
                                    if redirect_url.startswith('/'):
                                        full_redirect_url = f"{parsed.scheme}://{parsed.netloc}{redirect_url}"
                                    else:
                                        full_redirect_url = redirect_url
                                        
                                    follow_response = self.make_request(full_redirect_url, allow_redirects=False)
                                    if follow_response and follow_response.status_code == 200:
                                        # Successfully followed the redirect
                                        if validate_redirect(payload, redirect_url, self.config.get('callback_url')):
                                            result = {
                                                'vulnerable': True,
                                                'url': url,
                                                'original_url': url,
                                                'cookie': cookie_name,
                                                'payload': payload,
                                                'method': 'Cookie-based Meta Refresh',
                                                'status_code': response.status_code,
                                                'redirect_location': redirect_url,
                                                'redirect_chain': redirect_chain,
                                                'severity': self._determine_severity(payload, redirect_url)
                                            }
                                            results.append(result)
                                            
                                            if self.config.get('verbose'):
                                                print(f"{Fore.RED}[VULNERABLE] {url} - Cookie: {cookie_name}, Payload: {payload} (Meta Refresh){Style.RESET_ALL}")
                                            
                                            # If in fast mode, return after first vulnerability
                                            if self.config.get('fast'):
                                                break
                                except Exception as e:
                                    if self.config.get('verbose'):
                                        print(f"{Fore.YELLOW}[WARNING] Error following meta refresh: {str(e)}{Style.RESET_ALL}")
            
            return results
            
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[WARNING] Error testing cookie redirects for {url}: {str(e)}{Style.RESET_ALL}")
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
            original_domain = urlparse(original_url_str).netloc.lower()
            redirect_domain = urlparse(final_redirect_location_str).netloc.lower()
            payload_domain = urlparse(payload_value_str).netloc.lower()

            if not redirect_domain:
                if self.config.get('verbose'):
                    print(f"{Fore.CYAN}[DEBUG SCANNER] Not external: Redirect location has no domain. Original: {original_domain}, Final Dest: {final_redirect_location_str}, Payload: {payload_domain}{Style.RESET_ALL}")
                return False

            if original_domain == redirect_domain:
                if self.config.get('verbose'):
                    print(f"{Fore.CYAN}[DEBUG SCANNER] Not external: Redirect to same domain. Original: {original_domain}, Final Dest: {redirect_domain}, Payload: {payload_domain}{Style.RESET_ALL}")
                return False

            if payload_domain and redirect_domain == payload_domain:
                if self.config.get('verbose'):
                    print(f"{Fore.GREEN}[DEBUG SCANNER] External redirect CONFIRMED: Original: {original_domain}, Redirected to: {redirect_domain} (Matches payload domain: {payload_domain}){Style.RESET_ALL}")
                return True
            
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[DEBUG SCANNER] Not external: Redirect domain ({redirect_domain}) differs from original ({original_domain}) but does NOT match payload domain ({payload_domain}). Final Dest: {final_redirect_location_str}{Style.RESET_ALL}")
            return False
            
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Fore.RED}[DEBUG SCANNER ERROR] Exception in _is_external_redirect: {e}. Original: {original_url_str}, Location: {final_redirect_location_str}, Payload: {payload_value_str}{Style.RESET_ALL}")
            return False

    def _determine_severity(self, payload, redirect_location):
        """Determine vulnerability severity based on payload and redirect location"""
        if any(domain in redirect_location.lower() for domain in ['evil.com', 'attacker.com', 'malicious.com']):
            return 'High'
        elif redirect_location.startswith('http'):
            return 'Medium'
        else:
            return 'Low'
    
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
        payloads = self.payload_manager.get_payloads()
        
        # In fast mode, limit payloads per parameter but test all likely parameters
        if self.config.get('fast'):
            payloads = payloads[:3]  # Only test first 3 most effective payloads per parameter
        
        # Flag to track if we found any vulnerability on this URL
        url_vulnerable = False
        
        # Test URL parameters
        for param in redirect_params:
            if url_vulnerable and self.config.get('fast'):
                # If we already found a vulnerability and we're in fast mode, stop testing this URL
                break
                
            for payload in payloads:
                result = self.test_url_parameter(url, param, payload)
                if result:
                    results.append(result)
                    if result['vulnerable']:
                        url_vulnerable = True
                        if self.config.get('verbose'):
                            print(f"{Fore.RED}[VULNERABLE] {url} - Parameter: {param}, Payload: {payload}{Style.RESET_ALL}")
                        
                        # In fast mode, stop testing this URL completely after finding any vulnerability
                        if self.config.get('fast'):
                            if self.config.get('verbose'):
                                print(f"{Fore.YELLOW}[FAST MODE] Found vulnerability on URL '{url}', stopping further tests on this URL{Style.RESET_ALL}")
                            return results  # Return immediately with the first vulnerability
        
        # If we're in fast mode and already found a vulnerability, return early
        if url_vulnerable and self.config.get('fast'):
            return results
        
        # Test header injection if enabled
        if self.config.get('headers_test'):
            header_payloads = self.payload_manager.get_header_payloads()
            header_names = [
                'Host', 'X-Forwarded-Host', 'X-Forwarded-For', 'X-Real-IP', 
                'X-Forwarded-Proto', 'X-Forwarded-Server', 'X-Host', 'X-HTTP-Host-Override',
                'Referer', 'Origin', 'X-Original-URL', 'X-Rewrite-URL', 'CF-Connecting-IP'
            ]
            
            for header_name in header_names:
                for payload in header_payloads:
                    result = self.test_header_injection(url, header_name, payload)
                    if result:
                        results.append(result)
                        if result['vulnerable']:
                            if self.config.get('verbose'):
                                print(f"{Fore.RED}[VULNERABLE] {url} - Header: {header_name}, Payload: {payload}{Style.RESET_ALL}")
                            if self.config.get('fast'):
                                return results  # In fast mode, return after first vulnerability
        
        # Test form-based redirects
        form_results = self.test_form_redirects(url)
        if form_results:
            results.extend(form_results)
            # Check if any form results were vulnerable
            if self.config.get('fast') and any(r.get('vulnerable', False) for r in form_results):
                return results  # In fast mode, return after first vulnerability
        
        # Test cookie-based redirects
        cookie_results = self.test_cookie_redirects(url)
        if cookie_results:
            results.extend(cookie_results)
            # Check if any cookie results were vulnerable
            if self.config.get('fast') and any(r.get('vulnerable', False) for r in cookie_results):
                return results  # In fast mode, return after first vulnerability
        
        return results
    
    def scan_urls(self, urls):
        """Scan multiple URLs using thread pool"""
        all_results = []
        
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
