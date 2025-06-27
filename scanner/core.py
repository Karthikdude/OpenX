"""
Core scanning functionality for OpenX
"""

import requests
import urllib.parse
import re
import time
import threading
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
from .payloads import PayloadManager
from .utils import is_external_redirect, extract_redirect_url, parse_response_for_redirects, get_domain_from_url, verify_evil_com_redirect

class Scanner:
    """Main scanner class for open redirect vulnerability detection"""
    
    def __init__(self, threads=10, timeout=10, delay=0, user_agent=None, 
                 proxy=None, follow_redirects=5, verbose=False, silent=False,
                 fast_mode=False, small_mode=False, test_headers=False,
                 callback_url=None, custom_payloads=None, show_status_codes=False,
                 verify_ssl=True, reduce_false_positives=False, ignore_same_domain=False,
                 ignore_wp_oembed=False, ignore_queue_systems=False, verify_evil_com=True):
        """Initialize scanner with configuration
        
        Args:
            verify_ssl (bool): Whether to verify SSL certificates. Defaults to True.
            reduce_false_positives (bool): Enable enhanced false positive reduction. Defaults to False.
            ignore_same_domain (bool): Ignore redirects to the same domain or subdomains. Defaults to False.
            ignore_wp_oembed (bool): Ignore WordPress oEmbed API endpoints. Defaults to False.
            ignore_queue_systems (bool): Ignore queue systems with target parameters. Defaults to False.
            verify_evil_com (bool): Verify that redirects to evil.com are legitimate. Defaults to True.
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
        
        # False positive reduction options
        self.reduce_false_positives = reduce_false_positives
        self.ignore_same_domain = ignore_same_domain
        self.ignore_wp_oembed = ignore_wp_oembed
        self.ignore_queue_systems = ignore_queue_systems
        self.verify_evil_com = verify_evil_com
        
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
        
        # Suppress only the InsecureRequestWarning if verify_ssl is False
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
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
                # Check if it's an evil.com redirect and needs verification
                is_evil_com = 'evil.com' in location.lower()
                verified = True  # Default to true for non-evil.com redirects
                
                # Verify evil.com redirects if enabled
                if is_evil_com and self.verify_evil_com:
                    self.log(f"Verifying evil.com redirect: {location}", 'VERBOSE', Fore.YELLOW)
                    verified = verify_evil_com_redirect(location)
                    if not verified:
                        self.log(f"Failed to verify evil.com redirect: {location}", 'VERBOSE', Fore.RED)
                
                # Only report as vulnerability if verified or verification is disabled
                if verified or not self.verify_evil_com:
                    vulnerability = {
                        'url': test_url,
                        'parameter': param_name,
                        'payload': payload,
                        'method': 'URL Parameter',
                        'status_code': response.status_code,
                        'location_header': location,
                        'severity': 'High',
                        'description': f'Open redirect via {param_name} parameter',
                        'verified': verified
                    }
                    vulnerabilities.append(vulnerability)
                    verification_status = "(verified)" if verified else "(unverified)"
                    self.log(f"Found vulnerability: {test_url} -> {location} {verification_status}", 'VULN')
        
        # Test with redirect following for deeper analysis
        if self.follow_redirects > 0:
            response_full = self.make_request(test_url, allow_redirects=True)
            if response_full and response_full.url != test_url:
                final_url = response_full.url
                if is_external_redirect(base_url, final_url):
                    # Check if this is a new vulnerability or already found
                    existing = any(v['location_header'] == final_url for v in vulnerabilities)
                    if not existing:
                        # Check if it's an evil.com redirect and needs verification
                        is_evil_com = 'evil.com' in final_url.lower()
                        verified = True  # Default to true for non-evil.com redirects
                        
                        # Verify evil.com redirects if enabled
                        if is_evil_com and self.verify_evil_com:
                            self.log(f"Verifying evil.com redirect chain: {final_url}", 'VERBOSE', Fore.YELLOW)
                            verified = verify_evil_com_redirect(final_url)
                            if not verified:
                                self.log(f"Failed to verify evil.com redirect chain: {final_url}", 'VERBOSE', Fore.RED)
                        
                        # Only report as vulnerability if verified or verification is disabled
                        if verified or not self.verify_evil_com:
                            vulnerability = {
                                'url': test_url,
                                'parameter': param_name,
                                'payload': payload,
                                'method': 'URL Parameter (Redirect Chain)',
                                'status_code': response_full.status_code,
                                'location_header': final_url,
                                'severity': 'High',
                                'description': f'Open redirect via {param_name} parameter (redirect chain)',
                                'verified': verified
                            }
                            vulnerabilities.append(vulnerability)
                            verification_status = "(verified)" if verified else "(unverified)"
                            self.log(f"Found redirect chain vulnerability: {test_url} -> {final_url} {verification_status}", 'VULN')
        
        # Check response body for JavaScript/Meta redirects
        if response.content:
            js_redirects = parse_response_for_redirects(response.text, payload)
            for js_redirect in js_redirects:
                if is_external_redirect(base_url, js_redirect):
                    # Check if it's an evil.com redirect and needs verification
                    is_evil_com = 'evil.com' in js_redirect.lower()
                    verified = True  # Default to true for non-evil.com redirects
                    
                    # Verify evil.com redirects if enabled
                    if is_evil_com and self.verify_evil_com:
                        self.log(f"Verifying evil.com JS/Meta redirect: {js_redirect}", 'VERBOSE', Fore.YELLOW)
                        verified = verify_evil_com_redirect(js_redirect)
                        if not verified:
                            self.log(f"Failed to verify evil.com JS/Meta redirect: {js_redirect}", 'VERBOSE', Fore.RED)
                    
                    # Only report as vulnerability if verified or verification is disabled
                    if verified or not self.verify_evil_com:
                        vulnerability = {
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'method': 'JavaScript/Meta Redirect',
                            'status_code': response.status_code,
                            'location_header': js_redirect,
                            'severity': 'Medium',
                            'description': f'Open redirect via {param_name} parameter (JavaScript/Meta)',
                            'verified': verified
                        }
                        vulnerabilities.append(vulnerability)
                        verification_status = "(verified)" if verified else "(unverified)"
                        self.log(f"Found JavaScript/Meta redirect: {test_url} -> {js_redirect} {verification_status}", 'VULN')
        
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
                # Check if it's an evil.com redirect and needs verification
                is_evil_com = 'evil.com' in location.lower()
                verified = True  # Default to true for non-evil.com redirects
                
                # Verify evil.com redirects if enabled
                if is_evil_com and self.verify_evil_com:
                    self.log(f"Verifying evil.com header redirect: {location}", 'VERBOSE', Fore.YELLOW)
                    verified = verify_evil_com_redirect(location)
                    if not verified:
                        self.log(f"Failed to verify evil.com header redirect: {location}", 'VERBOSE', Fore.RED)
                
                # Only report as vulnerability if verified or verification is disabled
                if verified or not self.verify_evil_com:
                    vulnerability = {
                        'url': url,
                        'parameter': header_name,
                        'payload': payload,
                        'method': 'Header Injection',
                        'status_code': response.status_code,
                        'location_header': location,
                        'severity': 'High',
                        'description': f'Open redirect via {header_name} header injection',
                        'verified': verified
                    }
                    vulnerabilities.append(vulnerability)
                    verification_status = "(verified)" if verified else "(unverified)"
                    self.log(f"Found header injection vulnerability: {url} ({header_name}) -> {location} {verification_status}", 'VULN')
        
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
    

    
    def scan_single_url(self, url):
        """Scan a single URL for open redirect vulnerabilities"""
        self.log(f"Scanning: {url}", 'INFO', Fore.CYAN)
        
        # Skip URLs that match known false positive patterns
        if self.should_skip_url(url):
            self.log(f"Skipping URL with known false positive pattern: {url}", 'VERBOSE', Fore.YELLOW)
            return {
                'url': url,
                'vulnerabilities': [],
                'total_requests': 0,
                'timestamp': time.time(),
                'skipped': True,
                'reason': 'Known false positive pattern'
            }
        
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
            # Skip parameters that are likely to cause false positives
            if self.should_skip_parameter(url, param_name):
                self.log(f"Skipping parameter with false positive potential: {param_name}", 'VERBOSE', Fore.YELLOW)
                continue
                
            for payload in payloads:
                # Test URL parameter
                param_vulns = self.test_url_parameter(url, param_name, payload)
                
                # Filter out false positives
                filtered_vulns = self.filter_false_positives(url, param_vulns)
                vulnerabilities.extend(filtered_vulns)
                
                # Test header injection
                header_vulns = self.test_header_injection(url, payload)
                filtered_header_vulns = self.filter_false_positives(url, header_vulns)
                vulnerabilities.extend(filtered_header_vulns)
                
                # Test advanced real-world scenarios
                advanced_vulns = self.test_advanced_scenarios(url, payload)
                filtered_advanced_vulns = self.filter_false_positives(url, advanced_vulns)
                vulnerabilities.extend(filtered_advanced_vulns)
                
                # Test CSRF chaining potential (2025 research)
                csrf_vulns = self.test_csrf_chaining(url, payload)
                filtered_csrf_vulns = self.filter_false_positives(url, csrf_vulns)
                vulnerabilities.extend(filtered_csrf_vulns)
                
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
        
    def should_skip_url(self, url):
        """Check if URL should be skipped based on known false positive patterns"""
        # Only apply these checks if false positive reduction is enabled
        if not self.reduce_false_positives:
            return False
            
        # Skip WordPress oEmbed API endpoints
        if self.ignore_wp_oembed and 'wp-json/oembed' in url and 'url=' in url:
            # Extract the domain from the url parameter
            url_param_match = re.search(r'url=([^&]+)', url)
            if url_param_match:
                url_param = url_param_match.group(1)
                # URL decode the parameter
                url_param = urllib.parse.unquote(url_param)
                # Extract domain from the url parameter and from the original URL
                url_param_domain = get_domain_from_url(url_param)
                original_domain = get_domain_from_url(url)
                
                if url_param_domain and original_domain:
                    # Remove www. prefix for comparison
                    url_param_domain = url_param_domain.replace('www.', '')
                    original_domain = original_domain.replace('www.', '')
                    
                    # If domains match, it's likely a false positive
                    if url_param_domain == original_domain:
                        return True
        
        # Skip queue systems with target parameter pointing to same domain
        if self.ignore_queue_systems:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
            
            if ('queue.' in domain or '/queue/' in url) and 'target=' in url:
                # Extract the domain from the target parameter
                target_param_match = re.search(r'target=([^&]+)', url)
                if target_param_match:
                    target_param = target_param_match.group(1)
                    # URL decode the parameter
                    target_param = urllib.parse.unquote(target_param)
                    # Extract domain from the target parameter
                    target_param_domain = get_domain_from_url(target_param)
                    
                    if target_param_domain:
                        # Remove www. prefix for comparison
                        target_param_domain = target_param_domain.replace('www.', '')
                        domain_without_queue = domain.replace('queue.', '')
                        
                        # If domains are related, it's likely a false positive
                        if target_param_domain == domain_without_queue or domain_without_queue in target_param_domain:
                            return True
        
        return False
    
    def should_skip_parameter(self, url, param_name):
        """Check if parameter should be skipped based on URL context"""
        # Only apply these checks if false positive reduction is enabled
        if not self.reduce_false_positives:
            return False
            
        # Skip 'url' parameter in WordPress oEmbed API endpoints
        if self.ignore_wp_oembed and 'wp-json/oembed' in url and param_name == 'url':
            return True
            
        # Skip 'target' parameter in queue systems
        if self.ignore_queue_systems:
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc.lower()
            
            if ('queue.' in domain or '/queue/' in url) and param_name == 'target':
                return True
            
        return False
        
    def filter_false_positives(self, url, vulnerabilities):
        """Filter out false positives from detected vulnerabilities"""
        filtered_vulns = []
        
        for vuln in vulnerabilities:
            # Skip if the vulnerability is a known false positive pattern
            if self.is_false_positive(url, vuln):
                self.log(f"Filtered out false positive: {vuln.get('url')} -> {vuln.get('location_header')}", 'VERBOSE', Fore.YELLOW)
                continue
                
            filtered_vulns.append(vuln)
            
        return filtered_vulns
        
    def is_false_positive(self, url, vulnerability):
        """Check if a detected vulnerability is a false positive"""
        # Only apply these checks if false positive reduction is enabled
        if not self.reduce_false_positives:
            return False
            
        # Get the redirect URL from the vulnerability
        redirect_url = vulnerability.get('location_header', '')
        if not redirect_url:
            return False
            
        # Parse the URLs
        original_parsed = urllib.parse.urlparse(url)
        redirect_parsed = urllib.parse.urlparse(redirect_url)
        
        # Get domains
        original_domain = original_parsed.netloc.lower()
        redirect_domain = redirect_parsed.netloc.lower()
        
        # Remove www. prefix for comparison
        original_domain = original_domain.replace('www.', '')
        redirect_domain = redirect_domain.replace('www.', '')
        
        # Check for same domain or subdomains
        if self.ignore_same_domain:
            # Check for exact domain match
            if original_domain == redirect_domain:
                return True
                
            # Check for same parent domain (e.g., sub1.example.com and sub2.example.com)
            original_parts = original_domain.split('.')
            redirect_parts = redirect_domain.split('.')
            
            if len(original_parts) >= 2 and len(redirect_parts) >= 2:
                original_parent = '.'.join(original_parts[-2:])
                redirect_parent = '.'.join(redirect_parts[-2:])
                
                # If parent domains match and it's not a critical service
                if original_parent == redirect_parent:
                    # Check if this is a legitimate subdomain change
                    critical_subdomains = ['admin', 'secure', 'login', 'auth', 'account', 'payment', 'billing']
                    
                    # Only flag as false positive if not redirecting to/from critical subdomains
                    if not any(sub in original_domain for sub in critical_subdomains) and \
                       not any(sub in redirect_domain for sub in critical_subdomains):
                        return True
        
        # Check for WordPress oEmbed API endpoints
        if self.ignore_wp_oembed and 'wp-json/oembed' in url and 'url=' in url:
            url_param_match = re.search(r'url=([^&]+)', url)
            if url_param_match:
                url_param = url_param_match.group(1)
                url_param = urllib.parse.unquote(url_param)
                url_param_domain = get_domain_from_url(url_param)
                
                if url_param_domain:
                    url_param_domain = url_param_domain.replace('www.', '')
                    if redirect_domain == url_param_domain or url_param_domain in redirect_domain:
                        return True
        
        # Check for queue systems
        if self.ignore_queue_systems and ('queue.' in original_domain or '/queue/' in url) and 'target=' in url:
            target_param_match = re.search(r'target=([^&]+)', url)
            if target_param_match:
                target_param = target_param_match.group(1)
                target_param = urllib.parse.unquote(target_param)
                target_param_domain = get_domain_from_url(target_param)
                
                if target_param_domain:
                    target_param_domain = target_param_domain.replace('www.', '')
                    if redirect_domain == target_param_domain or target_param_domain in redirect_domain:
                        return True
        
        return False
    
    def scan_urls(self, urls):
        """Scan multiple URLs using thread pool"""
        results = []
        
        # Use a flag to track if we're shutting down
        self._shutdown = False
        
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Submit all URLs for scanning
                future_to_url = {}
                for url in urls:
                    if self._shutdown:
                        break
                    future = executor.submit(self.scan_single_url, url)
                    future_to_url[future] = url
                
                # Process completed scans
                try:
                    for future in as_completed(future_to_url):
                        if self._shutdown:
                            break
                            
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
                except KeyboardInterrupt:
                    self.log("Shutting down gracefully...", 'INFO')
                    self._shutdown = True
                    # Cancel all pending futures
                    for future in future_to_url:
                        future.cancel()
                    # Wait for running tasks to complete
                    for future in future_to_url:
                        if not future.done():
                            try:
                                future.result(timeout=1)  # Give it a moment to finish
                            except:
                                pass
                    raise
        except KeyboardInterrupt:
            self._shutdown = True
            raise
            
        return results
