"""
Core scanning functionality for OpenX
"""

import requests
import urllib.parse
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from .payloads import PayloadManager
from .utils import is_external_redirect, extract_redirect_url, parse_response_for_redirects

class Scanner:
    """Main scanner class for open redirect vulnerability detection"""
    
    def __init__(self, threads=10, timeout=10, delay=0, user_agent=None, 
                 proxy=None, follow_redirects=5, verbose=False, silent=False,
                 fast_mode=False, small_mode=False, test_headers=False,
                 callback_url=None, custom_payloads=None, show_status_codes=False,
                 verify_ssl=True):
        """Initialize scanner with configuration
        
        Args:
            verify_ssl (bool): Whether to verify SSL certificates. Defaults to True.
        """
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.user_agent = user_agent or 'OpenX/1.0 (Security Scanner)'
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.follow_redirects = follow_redirects
        self.verbose = verbose
        self.silent = silent
        self.fast_mode = fast_mode
        self.small_mode = small_mode
        self.test_headers = test_headers
        self.callback_url = callback_url
        self.show_status_codes = show_status_codes
        self.verify_ssl = verify_ssl
        
        # Thread lock for output synchronization
        self.output_lock = threading.Lock()
        
        # Initialize payload manager
        self.payload_manager = PayloadManager(
            callback_url=callback_url,
            custom_payloads_file=custom_payloads,
            small_mode=small_mode
        )
        
        # Session configuration
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})
        if self.proxy:
            self.session.proxies.update(self.proxy)
        
        # Configure session to handle Unicode properly
        self.session.encoding = 'utf-8'
    
    def log(self, message, level='INFO', color=Fore.WHITE):
        """Thread-safe logging"""
        if self.silent and level != 'VULN':
            return
        
        with self.output_lock:
            if level == 'VULN':
                print(f"{Fore.GREEN}[VULN] {message}{Style.RESET_ALL}")
            elif level == 'ERROR':
                print(f"{Fore.RED}[ERROR] {message}{Style.RESET_ALL}")
            elif level == 'VERBOSE' and self.verbose:
                print(f"{color}[VERBOSE] {message}{Style.RESET_ALL}")
            elif level == 'INFO' and not self.silent:
                print(f"{color}[INFO] {message}{Style.RESET_ALL}")
    
    def make_request(self, url, method='GET', headers=None, allow_redirects=True):
        """Make HTTP request with error handling"""
        try:
            extra_headers = headers or {}
            # Ensure URL is properly encoded
            if isinstance(url, str):
                url = url.encode('utf-8', errors='ignore').decode('utf-8')
            
            response = self.session.request(
                method=method,
                url=url,
                headers=extra_headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                verify=self.verify_ssl
            )
            return response
        except UnicodeEncodeError as e:
            self.log(f"Unicode encoding error for {url}: {str(e)}", 'ERROR')
            return None
        except requests.exceptions.RequestException as e:
            self.log(f"Request failed for {url}: {str(e)}", 'ERROR')
            return None
    
    def test_url_parameter(self, base_url, param_name, payload):
        """Test a specific URL parameter with a payload"""
        vulnerabilities = []
        
        # Parse URL and add/modify parameter
        parsed_url = urllib.parse.urlparse(base_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        query_params[param_name] = [payload]
        
        # Reconstruct URL with payload
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        test_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))
        
        self.log(f"Testing: {test_url}", 'VERBOSE', Fore.BLUE)
        
        # Test without following redirects first
        response = self.make_request(test_url, allow_redirects=False)
        if not response:
            return vulnerabilities
        
        # Check for redirect response
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            if location and is_external_redirect(base_url, location):
                vulnerability = {
                    'url': test_url,
                    'parameter': param_name,
                    'payload': payload,
                    'method': 'URL Parameter',
                    'status_code': response.status_code,
                    'location_header': location,
                    'severity': 'High',
                    'description': f'Open redirect via {param_name} parameter'
                }
                vulnerabilities.append(vulnerability)
                self.log(f"Found vulnerability: {test_url} -> {location}", 'VULN')
        
        # Test with redirect following for deeper analysis
        if self.follow_redirects > 0:
            response_full = self.make_request(test_url, allow_redirects=True)
            if response_full and response_full.url != test_url:
                final_url = response_full.url
                if is_external_redirect(base_url, final_url):
                    # Check if this is a new vulnerability or already found
                    existing = any(v['location_header'] == final_url for v in vulnerabilities)
                    if not existing:
                        vulnerability = {
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'URL Parameter (Redirect Chain)',
                            'status_code': response_full.status_code,
                            'location_header': final_url,
                            'severity': 'High',
                            'description': f'Open redirect via {param_name} parameter (redirect chain)'
                        }
                        vulnerabilities.append(vulnerability)
                        self.log(f"Found redirect chain vulnerability: {test_url} -> {final_url}", 'VULN')
        
        # Check response body for JavaScript/Meta redirects
        if response.content:
            js_redirects = parse_response_for_redirects(response.text, payload)
            for js_redirect in js_redirects:
                if is_external_redirect(base_url, js_redirect):
                    vulnerability = {
                        'url': test_url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': 'JavaScript/Meta Redirect',
                        'status_code': response.status_code,
                        'location_header': js_redirect,
                        'severity': 'Medium',
                        'description': f'Open redirect via {param_name} parameter (JavaScript/Meta)'
                    }
                    vulnerabilities.append(vulnerability)
                    self.log(f"Found JavaScript/Meta redirect: {test_url} -> {js_redirect}", 'VULN')
        
        return vulnerabilities
    
    def test_header_injection(self, url, payload):
        """Test header-based injection"""
        vulnerabilities = []
        
        if not self.test_headers:
            return vulnerabilities
        
        # Headers to test (expanded for real-world scenarios including 2025 findings)
        test_headers = [
            'X-Redirect-To',
            'X-Forward-To', 
            'X-Forwarded-Host',     # Critical: Used in dashboard.omise.co attack
            'X-Forwarded-For',
            'X-Real-IP',
            'Location',
            'Referer',
            'Origin',
            'Host',
            'X-Original-Host',
            'X-Host',
            'Forwarded',
            'Via',
            'X-Forwarded-Proto',
            'X-Forwarded-Port',
            'X-Custom-Redirect',
            'X-Return-To',
            'X-Continue-To',
            # Additional headers from 2025 research
            'X-Forwarded-URI',
            'X-Original-URI',
            'X-Rewrite-URL',
            'CF-Connecting-IP',     # Cloudflare specific
            'True-Client-IP',       # Akamai specific
            'X-Cluster-Client-IP',  # AWS ALB specific
            'X-Forwarded-Server',
            'X-ProxyUser-Ip'
        ]
        
        for header_name in test_headers:
            headers = {header_name: payload}
            
            self.log(f"Testing header {header_name}: {url}", 'VERBOSE', Fore.BLUE)
            
            response = self.make_request(url, headers=headers, allow_redirects=False)
            if not response:
                continue
            
            # Check if the header value is reflected in response
            location = response.headers.get('Location', '')
            if location and payload in location and is_external_redirect(url, location):
                vulnerability = {
                    'url': url,
                    'parameter': header_name,
                    'payload': payload,
                    'method': 'Header Injection',
                    'status_code': response.status_code,
                    'location_header': location,
                    'severity': 'High',
                    'description': f'Open redirect via {header_name} header injection'
                }
                vulnerabilities.append(vulnerability)
                self.log(f"Found header injection vulnerability: {url} ({header_name}) -> {location}", 'VULN')
        
        return vulnerabilities
    
    def test_advanced_scenarios(self, url, payload):
        """Test advanced real-world scenarios"""
        vulnerabilities = []
        
        # Test for chain redirects
        chain_vulns = self.test_chain_redirects(url, payload)
        vulnerabilities.extend(chain_vulns)
        
        # Test for OAuth scenarios
        oauth_vulns = self.test_oauth_scenarios(url, payload)
        vulnerabilities.extend(oauth_vulns)
        
        # Test for enterprise scenarios
        enterprise_vulns = self.test_enterprise_scenarios(url, payload)
        vulnerabilities.extend(enterprise_vulns)
        
        return vulnerabilities
    
    def test_chain_redirects(self, url, payload):
        """Test for chain redirect vulnerabilities"""
        vulnerabilities = []
        
        # Look for chain redirect patterns
        chain_params = ['first', 'second', 'third', 'chain', 'hop', 'intermediate']
        
        for param in chain_params:
            if param in url.lower():
                # Test the chain redirect
                test_vuln = self.test_url_parameter(url, param, payload)
                for vuln in test_vuln:
                    vuln['method'] = 'Chain Redirect'
                    vuln['severity'] = 'High'
                    vulnerabilities.extend([vuln])
        
        return vulnerabilities
    
    def test_oauth_scenarios(self, url, payload):
        """Test OAuth-specific vulnerabilities"""
        vulnerabilities = []
        
        # OAuth endpoints and parameters
        oauth_indicators = ['oauth', 'authorize', 'redirect_uri', 'client_id', 'response_type']
        
        if any(indicator in url.lower() for indicator in oauth_indicators):
            # Test OAuth redirect_uri parameter specifically
            oauth_params = ['redirect_uri', 'callback_url', 'return_url', 'state']
            
            for param in oauth_params:
                test_vuln = self.test_url_parameter(url, param, payload)
                for vuln in test_vuln:
                    vuln['method'] = 'OAuth Redirect'
                    vuln['severity'] = 'Critical'  # OAuth vulnerabilities are often critical
                    vulnerabilities.extend([vuln])
        
        return vulnerabilities
    
    def test_enterprise_scenarios(self, url, payload):
        """Test enterprise application scenarios"""
        vulnerabilities = []
        
        # Enterprise application indicators
        enterprise_indicators = [
            'grafana', 'jenkins', 'gitlab', 'github', 'jira', 'confluence',
            'admin', 'dashboard', 'login', 'sso', 'saml', 'ldap',
            'payment', 'checkout', 'success', 'confirm', 'verify'
        ]
        
        if any(indicator in url.lower() for indicator in enterprise_indicators):
            # Test enterprise-specific parameters
            enterprise_params = [
                'returnTo', 'return_to', 'success_url', 'cancel_url',
                'confirm_url', 'verify_url', 'next_page', 'continue_to'
            ]
            
            for param in enterprise_params:
                test_vuln = self.test_url_parameter(url, param, payload)
                for vuln in test_vuln:
                    vuln['method'] = 'Enterprise Application'
                    vuln['severity'] = 'High'
                    vulnerabilities.extend([vuln])
        
        return vulnerabilities
    
    def test_csrf_chaining(self, url, payload):
        """Test for CSRF chaining opportunities based on 2025 research"""
        vulnerabilities = []
        
        # Check if this could be a GET-based CSRF target
        csrf_indicators = ['/api/', '/account/', '/profile/', '/settings/', '/admin/', '/update/', '/delete/', '/change/']
        
        if any(indicator in url.lower() for indicator in csrf_indicators):
            # Test if open redirect can bypass SameSite protections
            test_vuln = self.test_url_parameter(url, 'redirect', payload)
            for vuln in test_vuln:
                vuln['method'] = 'CSRF Chain Potential'
                vuln['severity'] = 'High'
                vuln['description'] = 'Open redirect may bypass SameSite cookie protections for CSRF'
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def test_path_traversal_bypass(self, url, payload):
        """Test for path traversal bypasses like CVE-2025-4123"""
        vulnerabilities = []
        
        # Test double-encoded path traversal sequences
        path_traversal_payloads = [
            "..%2F" + payload.replace("http://", "").replace("https://", ""),
            "..%252F" + payload.replace("http://", "").replace("https://", ""),
            payload + "/..%2F",
            payload + "/..%252F"
        ]
        
        for traversal_payload in path_traversal_payloads:
            # Test common redirect parameters
            for param in ['url', 'redirect', 'path', 'file']:
                if param in url.lower():
                    test_url = url.replace(f"{param}=", f"{param}={traversal_payload}")
                    response = self.make_request(test_url, allow_redirects=False)
                    
                    if response and response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if payload.replace("http://", "").replace("https://", "") in location:
                            vulnerability = {
                                'url': test_url,
                                'parameter': param,
                                'method': 'Path Traversal Bypass',
                                'payload': traversal_payload,
                                'redirect_to': location,
                                'status_code': response.status_code,
                                'severity': 'Critical',
                                'description': 'Path traversal bypass enables open redirect (CVE-2025-4123 style)'
                            }
                            vulnerabilities.append(vulnerability)
                            self.log(f"Found path traversal bypass vulnerability: {test_url} -> {location}", 'VULN')
        
        return vulnerabilities
    
    def scan_single_url(self, url):
        """Scan a single URL for open redirect vulnerabilities"""
        self.log(f"Scanning: {url}", 'INFO', Fore.CYAN)
        
        vulnerabilities = []
        
        # Parse URL to identify existing parameters
        parsed_url = urllib.parse.urlparse(url)
        existing_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Get parameters to test
        params_to_test = self.payload_manager.get_parameters_to_test(existing_params.keys())
        
        # Get payloads to test
        payloads = self.payload_manager.get_payloads()
        
        # Test each parameter with each payload
        for param_name in params_to_test:
            for payload in payloads:
                # Test URL parameter
                param_vulns = self.test_url_parameter(url, param_name, payload)
                vulnerabilities.extend(param_vulns)
                
                # Test header injection
                header_vulns = self.test_header_injection(url, payload)
                vulnerabilities.extend(header_vulns)
                
                # Test advanced real-world scenarios
                advanced_vulns = self.test_advanced_scenarios(url, payload)
                vulnerabilities.extend(advanced_vulns)
                
                # Test CSRF chaining potential (2025 research)
                csrf_vulns = self.test_csrf_chaining(url, payload)
                vulnerabilities.extend(csrf_vulns)
                
                # Test path traversal bypasses (CVE-2025-4123 style)
                traversal_vulns = self.test_path_traversal_bypass(url, payload)
                vulnerabilities.extend(traversal_vulns)
                
                # Apply delay if configured
                if self.delay > 0:
                    time.sleep(self.delay)
                
                # Fast mode: stop after first vulnerability found
                if self.fast_mode and vulnerabilities:
                    break
            
            if self.fast_mode and vulnerabilities:
                break
        
        result = {
            'url': url,
            'vulnerabilities': vulnerabilities,
            'total_requests': len(params_to_test) * len(payloads),
            'timestamp': time.time()
        }
        
        if vulnerabilities:
            self.log(f"Found {len(vulnerabilities)} vulnerabilities in {url}", 'INFO', Fore.GREEN)
        else:
            self.log(f"No vulnerabilities found in {url}", 'VERBOSE', Fore.YELLOW)
        
        return result
    
    def scan_urls(self, urls):
        """Scan multiple URLs using thread pool"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all URLs for scanning
            future_to_url = {
                executor.submit(self.scan_single_url, url): url 
                for url in urls
            }
            
            # Process completed scans
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    self.log(f"Error scanning {url}: {str(e)}", 'ERROR')
                    # Add error result
                    results.append({
                        'url': url,
                        'vulnerabilities': [],
                        'error': str(e),
                        'timestamp': time.time()
                    })
        
        return results
