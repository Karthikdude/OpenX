"""
OpenX Scanner Core Module
Main scanning engine for open redirect vulnerability detection
"""

import requests
import threading
import time
import random
import urllib.parse
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
            parsed = urllib.parse.urlparse(url)
            query_params = urllib.parse.parse_qs(parsed.query)
            
            # Set the parameter with the payload
            query_params[param] = [payload]
            
            # Reconstruct URL
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            # Make request without following redirects to analyze response
            response = self.make_request(test_url, allow_redirects=False)
            if not response:
                return None
            
            # Check for redirect response
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if location:
                    # Validate if this is a successful redirect to our payload
                    if validate_redirect(payload, location, self.config.get('callback_url')):
                        return {
                            'vulnerable': True,
                            'url': test_url,
                            'original_url': url,
                            'parameter': param,
                            'payload': payload,
                            'method': 'URL Parameter',
                            'status_code': response.status_code,
                            'redirect_location': location,
                            'severity': self._determine_severity(payload, location)
                        }
            
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
                                'severity': self._determine_severity(payload, redirect_url)
                            }
                
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
                        if validate_redirect(payload, match, self.config.get('callback_url')):
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
            test_payloads = ['http://evil.com', '//evil.com', 'javascript:alert(1)']
            
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
                        
                        with self.results_lock:
                            self.total_requests += 1
                        
                        if post_response.status_code in [301, 302, 303, 307, 308]:
                            location = post_response.headers.get('Location', '')
                            if validate_redirect(payload, location, self.config.get('callback_url')):
                                results.append({
                                    'vulnerable': True,
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'method': 'Form POST Redirect',
                                    'status_code': post_response.status_code,
                                    'redirect_location': location,
                                    'severity': self._determine_severity(payload, location)
                                })
                                
                                if self.config.get('verbose'):
                                    print(f"{Fore.RED}[VULNERABLE] {url} - Form Parameter: {param}, Payload: {payload}{Style.RESET_ALL}")
                                
                                # In fast mode, return immediately after first vulnerability
                                if self.config.get('fast'):
                                    return results
                    
                    except Exception as e:
                        if self.config.get('verbose'):
                            print(f"{Fore.YELLOW}[WARNING] Form test error for {url}: {str(e)}{Style.RESET_ALL}")
                        continue
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[WARNING] Form redirect test failed for {url}: {str(e)}{Style.RESET_ALL}")
        
        return results
    
    def test_cookie_redirects(self, url):
        """Test cookie-based redirect vulnerabilities"""
        results = []
        
        try:
            # Test common cookie redirect patterns
            cookie_names = ['redirect_url', 'return_to', 'next_page', 'success_url', 'callback_url']
            test_payloads = ['http://evil.com', '//evil.com', 'javascript:alert(1)']
            
            for cookie_name in cookie_names:
                for payload in test_payloads:
                    # Set cookie and make request
                    cookies = {cookie_name: payload}
                    
                    try:
                        response = self.session.get(
                            url, 
                            cookies=cookies, 
                            allow_redirects=False, 
                            timeout=self.timeout
                        )
                        
                        with self.results_lock:
                            self.total_requests += 1
                        
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if validate_redirect(payload, location, self.config.get('callback_url')):
                                results.append({
                                    'vulnerable': True,
                                    'url': url,
                                    'cookie': cookie_name,
                                    'payload': payload,
                                    'method': 'Cookie-based Redirect',
                                    'status_code': response.status_code,
                                    'redirect_location': location,
                                    'severity': self._determine_severity(payload, location)
                                })
                                
                                if self.config.get('verbose'):
                                    print(f"{Fore.RED}[VULNERABLE] {url} - Cookie: {cookie_name}, Payload: {payload}{Style.RESET_ALL}")
                                
                                # In fast mode, return immediately after first vulnerability
                                if self.config.get('fast'):
                                    return results
                    
                    except Exception as e:
                        if self.config.get('verbose'):
                            print(f"{Fore.YELLOW}[WARNING] Cookie test error for {url}: {str(e)}{Style.RESET_ALL}")
                        continue
        
        except Exception as e:
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[WARNING] Cookie redirect test failed for {url}: {str(e)}{Style.RESET_ALL}")
        
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
            if location.startswith(('javascript:', 'data:')):
                return True
        
        return False
    
    def _is_external_redirect(self, original_url, redirect_location):
        """Check if redirect is to an external domain"""
        try:
            from urllib.parse import urlparse
            
            original_domain = urlparse(original_url).netloc
            redirect_domain = urlparse(redirect_location).netloc
            
            # Consider it external if domains are different
            if redirect_domain and redirect_domain != original_domain:
                return True
            
            # Check for suspicious domains
            suspicious_domains = ['evil.com', 'attacker.com', 'malicious.com']
            if any(domain in redirect_location.lower() for domain in suspicious_domains):
                return True
                
        except Exception:
            pass
        
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
        
        # Test URL parameters
        for param in redirect_params:
            for payload in payloads:
                result = self.test_url_parameter(url, param, payload)
                if result:
                    results.append(result)
                    if result['vulnerable']:
                        if self.config.get('verbose'):
                            print(f"{Fore.RED}[VULNERABLE] {url} - Parameter: {param}, Payload: {payload}{Style.RESET_ALL}")
                        # In fast mode, stop testing after first vulnerability found
                        if self.config.get('fast'):
                            if self.config.get('verbose'):
                                print(f"{Fore.YELLOW}[FAST MODE] Stopping scan after first vulnerability found{Style.RESET_ALL}")
                            return results
        
        # Test header injection if enabled (only if no vulnerability found in fast mode)
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
                            # In fast mode, stop testing after first vulnerability found
                            if self.config.get('fast'):
                                if self.config.get('verbose'):
                                    print(f"{Fore.YELLOW}[FAST MODE] Stopping scan after first vulnerability found{Style.RESET_ALL}")
                                return results
        
        # Test form-based redirects (only if no vulnerability found in fast mode)
        form_results = self.test_form_redirects(url)
        if form_results:
            results.extend(form_results)
            # Check if any form results are vulnerable and we're in fast mode
            if self.config.get('fast'):
                for result in form_results:
                    if result.get('vulnerable'):
                        if self.config.get('verbose'):
                            print(f"{Fore.YELLOW}[FAST MODE] Stopping scan after first vulnerability found{Style.RESET_ALL}")
                        return results
        
        # Test cookie-based redirects (only if no vulnerability found in fast mode)
        cookie_results = self.test_cookie_redirects(url)
        if cookie_results:
            results.extend(cookie_results)
            # Check if any cookie results are vulnerable and we're in fast mode
            if self.config.get('fast'):
                for result in cookie_results:
                    if result.get('vulnerable'):
                        if self.config.get('verbose'):
                            print(f"{Fore.YELLOW}[FAST MODE] Stopping scan after first vulnerability found{Style.RESET_ALL}")
                        return results
        
        return results
    
    def scan_urls(self, urls):
        """Scan multiple URLs using thread pool"""
        all_results = []
        
        # In fast mode, scan URLs sequentially and stop after first vulnerability
        if self.config.get('fast'):
            if self.config.get('verbose'):
                print(f"{Fore.YELLOW}[FAST MODE] Scanning URLs sequentially until first vulnerability found{Style.RESET_ALL}")
            
            with tqdm(total=len(urls), desc="Scanning URLs (Fast Mode)", 
                     bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                     disable=self.config.get('verbose', False)) as pbar:
                
                for url in urls:
                    try:
                        results = self.scan_single_url(url)
                        if results:
                            all_results.extend(results)
                            # Check if any vulnerability was found
                            vulnerable_results = [r for r in results if r.get('vulnerable', False)]
                            if vulnerable_results:
                                if self.config.get('verbose'):
                                    print(f"{Fore.YELLOW}[FAST MODE] Vulnerability found, stopping scan{Style.RESET_ALL}")
                                pbar.update(1)
                                break
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
