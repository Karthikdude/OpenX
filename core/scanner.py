#!/usr/bin/env python3
"""
Core scanner module for OpenX
Handles the main scanning functionality
"""
import asyncio
import logging
import random
import time
import urllib.parse
from typing import List, Dict, Set, Tuple, Optional, Any

import aiohttp
from aiohttp import ClientSession, ClientError, ClientTimeout, TCPConnector
from tqdm.asyncio import tqdm
from colorama import Fore, Style

# Import user agent manager
from fake_useragent_data import UserAgentManager

# For headless browser support
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

class Scanner:
    """Main scanner class for OpenX"""
    
    def __init__(self, config=None, payload_manager=None):
        """
        Initialize the scanner
        
        Args:
            config (dict, optional): Configuration dictionary
            payload_manager (PayloadManager, optional): Payload manager instance
        """
        self.config = config or {}
        self.payload_manager = payload_manager
        self.logger = logging.getLogger("openx.scanner")
        
        # Scanner settings
        self.timeout = self.config.get('timeout', 10)
        self.concurrency = self.config.get('concurrency', 100)
        self.max_retries = self.config.get('max_retries', 3)
        self.retry_delay = self.config.get('retry_delay', 2)
        self.verify_ssl = self.config.get('verify_ssl', False)
        self.user_agent_rotation = self.config.get('user_agent_rotation', True)
        self.smart_scan = self.config.get('smart_scan', False)
        
        # Authentication settings
        self.auth_enabled = self.config.get('auth', {}).get('enabled', False)
        self.auth_type = self.config.get('auth', {}).get('type')
        self.auth_username = self.config.get('auth', {}).get('username')
        self.auth_password = self.config.get('auth', {}).get('password')
        self.auth_token = self.config.get('auth', {}).get('token')
        
        # Browser settings
        self.browser_enabled = self.config.get('browser', {}).get('enabled', False)
        self.browser_type = self.config.get('browser', {}).get('type', 'playwright')
        self.browser_headless = self.config.get('browser', {}).get('headless', True)
        self.browser_timeout = self.config.get('browser', {}).get('timeout', 30)
        
        # Evasion settings
        self.random_delay = self.config.get('evasion', {}).get('random_delay', False)
        self.min_delay = self.config.get('evasion', {}).get('min_delay', 0.5)
        self.max_delay = self.config.get('evasion', {}).get('max_delay', 3.0)
        
        # Proxy settings
        self.proxy = self.config.get('proxy')
        self.proxy_auth = self.config.get('proxy_auth')
        
        # Results storage
        self.results = []
        self.result_set = set()
        self.vulnerable_count = 0
        self.total_urls = 0
        self.start_time = 0
        self.end_time = 0
        
        # User agents for rotation
        self.user_agents = self._load_user_agents()
    
    def _load_user_agents(self) -> List[str]:
        """
        Load user agents using UserAgentManager
        
        Returns:
            List[str]: List of user agents
        """
        # Initialize user agent manager
        user_agent_manager = UserAgentManager()
        
        try:
            # Try to load from file
            user_agent_file = self.config.get('user_agent_file')
            if user_agent_file:
                if user_agent_manager.load_from_file(user_agent_file):
                    self.logger.info(f"Loaded user agents from {user_agent_file}")
                    return user_agent_manager.user_agents
        except Exception as e:
            self.logger.error(f"Error loading user agents: {e}")
        
        # Return default user agents from manager
        return user_agent_manager.user_agents
    
    def get_random_user_agent(self) -> str:
        """
        Get a random user agent
        
        Returns:
            str: Random user agent string
        """
        # Create a new instance to ensure we get the latest user agents
        user_agent_manager = UserAgentManager()
        
        # Get browser type from config if specified
        browser_type = self.config.get('preferred_browser', 'random')
        
        if browser_type == 'chrome':
            return user_agent_manager.get_chrome()
        elif browser_type == 'firefox':
            return user_agent_manager.get_firefox()
        elif browser_type == 'safari':
            return user_agent_manager.get_safari()
        elif browser_type == 'edge':
            return user_agent_manager.get_edge()
        elif browser_type == 'opera':
            return user_agent_manager.get_opera()
        else:
            # Default to random
            return user_agent_manager.get_random()
    
    async def scan_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Scan a list of URLs for open redirect vulnerabilities
        
        Args:
            urls (List[str]): List of URLs to scan
            
        Returns:
            List[Dict[str, Any]]: Scan results
        """
        self.results = []
        self.result_set = set()
        self.vulnerable_count = 0
        self.total_urls = len(urls)
        self.start_time = time.time()
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.concurrency)
        
        # Setup HTTP client
        connector = TCPConnector(limit_per_host=0, ssl=self.verify_ssl)
        headers = {"User-Agent": self.get_random_user_agent()} if self.user_agent_rotation else None
        
        # Setup proxy if configured
        proxy = None
        proxy_auth = None
        if self.proxy:
            proxy = self.proxy
            if self.proxy_auth:
                proxy_auth = aiohttp.BasicAuth(
                    login=self.proxy_auth.get('username', ''),
                    password=self.proxy_auth.get('password', '')
                )
        
        # Setup client session
        timeout = ClientTimeout(total=self.timeout)
        async with ClientSession(
            connector=connector,
            headers=headers,
            timeout=timeout,
            trust_env=True
        ) as session:
            # Set authentication if enabled
            if self.auth_enabled:
                if self.auth_type == 'basic':
                    session.auth = aiohttp.BasicAuth(
                        login=self.auth_username,
                        password=self.auth_password
                    )
                elif self.auth_type == 'bearer':
                    session.headers.update({
                        'Authorization': f'Bearer {self.auth_token}'
                    })
            
            # Create tasks for each URL
            tasks = []
            for url in urls:
                tasks.append(self.test_url(semaphore, session, url))
            
            # Add browser-based tasks if enabled
            if self.browser_enabled:
                if (self.browser_type == 'playwright' and PLAYWRIGHT_AVAILABLE) or \
                   (self.browser_type == 'selenium' and SELENIUM_AVAILABLE):
                    tasks.extend([self.test_url_with_browser(url) for url in urls])
                else:
                    self.logger.warning(f"{self.browser_type} is not available. Install it with pip.")
            
            # Run tasks with progress bar
            try:
                await tqdm.gather(*tasks, desc="Scanning URLs", unit="URLs")
            except asyncio.CancelledError:
                self.logger.warning("Tasks cancelled.")
            except Exception as e:
                self.logger.error(f"Error during scanning: {e}")
        
        self.end_time = time.time()
        self.logger.info(f"Scan completed. Found {self.vulnerable_count} vulnerable URLs.")
        
        return self.results
    
    async def test_url(self, semaphore: asyncio.Semaphore, session: ClientSession, target: str) -> None:
        """
        Test a URL for open redirect vulnerabilities
        
        Args:
            semaphore (asyncio.Semaphore): Concurrency semaphore
            session (ClientSession): HTTP client session
            target (str): Target URL to test
        """
        async with semaphore:
            self.logger.debug(f"Starting test for URL: {target}")
            vulnerable = False
            
            # Get payloads based on scan type
            payloads = self.payload_manager.get_all_payloads()
            if self.smart_scan:
                # Add path-based payloads
                payloads.extend(self.payload_manager.get_path_payloads())
            
            # Test each payload
            for payload in payloads:
                # Apply random delay if enabled
                if self.random_delay:
                    await asyncio.sleep(random.uniform(self.min_delay, self.max_delay))
                
                # Inject payload
                payload_url = self.payload_manager.inject_payload(target, payload)
                self.logger.debug(f"Testing URL: {payload_url}")
                
                # Test the URL with retries
                for retry in range(self.max_retries):
                    try:
                        # Rotate user agent if enabled
                        if self.user_agent_rotation:
                            session.headers.update({"User-Agent": self.get_random_user_agent()})
                        
                        async with session.get(
                            payload_url,
                            timeout=self.timeout,
                            allow_redirects=True,
                            proxy=self.proxy
                        ) as response:
                            # Get final URL and response body
                            final_url = str(response.url)
                            response_body = await response.text()
                            
                            # Get domain from original URL
                            domain = urllib.parse.urlparse(target).netloc
                            
                            # Skip 404 responses
                            if response.status == 404:
                                print(Fore.YELLOW + f"[SKIPPED] {domain} [404] -> {payload_url} (Not a valid endpoint)")
                                break
                                
                            # Check if response indicates vulnerability
                            is_vuln, severity, details = self.payload_manager.is_vulnerable(
                                final_url, response_body
                            )
                            
                            if is_vuln:
                                result = {
                                    "url": target,
                                    "payload_url": payload_url,
                                    "status_code": response.status,
                                    "final_url": final_url,
                                    "severity": severity,
                                    "details": details,
                                    "type": "redirect",
                                    "payload": payload
                                }
                                
                                result_key = f"{target}:{payload}"
                                if result_key not in self.result_set:
                                    self.results.append(result)
                                    self.result_set.add(result_key)
                                    self.vulnerable_count += 1
                                    
                                    # Print to console
                                    print(Fore.RED + f"[VULNERABLE] {domain} [{response.status}] -> {payload_url} (Severity: {severity})")
                                
                                vulnerable = True
                            elif 300 <= response.status < 400:
                                # Redirect but not to target domain
                                print(Fore.GREEN + f"[REDIRECT] {domain} [{response.status}] -> {payload_url}")
                            
                            # Check for JS-based redirects
                            if not is_vuln and "window.location" in response_body or "document.location" in response_body:
                                print(Fore.YELLOW + f"[JS REDIRECT] {target} may be vulnerable!")
                                
                                # Add as potential vulnerability with low severity
                                result = {
                                    "url": target,
                                    "payload_url": payload_url,
                                    "status_code": response.status,
                                    "final_url": final_url,
                                    "severity": "low",
                                    "details": "Potential JavaScript-based redirect detected",
                                    "type": "js_redirect",
                                    "payload": payload
                                }
                                
                                result_key = f"{target}:{payload}:js"
                                if result_key not in self.result_set:
                                    self.results.append(result)
                                    self.result_set.add(result_key)
                        
                        # Successfully tested, break retry loop
                        break
                    
                    except asyncio.TimeoutError:
                        if retry == self.max_retries - 1:
                            self.logger.error(f"Timeout accessing URL {payload_url} after {self.max_retries} retries")
                            print(Fore.YELLOW + f"[TIMEOUT] {payload_url}")
                        else:
                            await asyncio.sleep(self.retry_delay)
                    
                    except ClientError as e:
                        if retry == self.max_retries - 1:
                            self.logger.error(f"Client error accessing URL {payload_url}: {e}")
                            print(Fore.YELLOW + f"[CLIENT ERROR] {payload_url} - {e}")
                        else:
                            await asyncio.sleep(self.retry_delay)
                    
                    except Exception as e:
                        if retry == self.max_retries - 1:
                            self.logger.error(f"Error accessing URL {payload_url}: {e}")
                            print(Fore.YELLOW + f"[ERROR] {payload_url} - {e}")
                        else:
                            await asyncio.sleep(self.retry_delay)
            
            if not vulnerable:
                self.logger.info(f"No redirection or vulnerability found for URL: {target}")
    
    async def test_url_with_browser(self, url: str) -> None:
        """
        Test a URL using a headless browser for deeper JS-based redirect detection
        
        Args:
            url (str): URL to test
        """
        if self.browser_type == 'playwright' and PLAYWRIGHT_AVAILABLE:
            await self._test_with_playwright(url)
        elif self.browser_type == 'selenium' and SELENIUM_AVAILABLE:
            await self._test_with_selenium(url)
        else:
            self.logger.warning(f"Browser testing with {self.browser_type} is not available")
    
    async def _test_with_playwright(self, url: str) -> None:
        """
        Test a URL using Playwright for deeper JS-based redirect detection
        
        Args:
            url (str): URL to test
        """
        self.logger.debug(f"Testing URL with Playwright: {url}")
        
        if not PLAYWRIGHT_AVAILABLE:
            self.logger.warning("Playwright is not available. Install it with 'pip install playwright' and 'playwright install'")
            return
        
        try:
            async with async_playwright() as p:
                # Launch browser based on config
                browser_type = self.config.get('browser', {}).get('browser_type', 'chromium')
                if browser_type == 'firefox':
                    browser = await p.firefox.launch(headless=self.browser_headless)
                elif browser_type == 'webkit':
                    browser = await p.webkit.launch(headless=self.browser_headless)
                else:  # default to chromium
                    browser = await p.chromium.launch(headless=self.browser_headless)
                
                # Create context with options
                context_options = {}
                
                # Set proxy if configured
                if self.proxy:
                    context_options['proxy'] = {
                        'server': self.proxy
                    }
                    if self.proxy_auth:
                        context_options['proxy']['username'] = self.proxy_auth.get('username')
                        context_options['proxy']['password'] = self.proxy_auth.get('password')
                
                # Create context
                context = await browser.new_context(**context_options)
                
                # Create page
                page = await context.new_page()
                
                # Set user agent
                if self.user_agent_rotation:
                    await page.set_extra_http_headers({
                        'User-Agent': self.get_random_user_agent()
                    })
                
                # Setup authentication if needed
                if self.auth_enabled and self.auth_type == 'basic' and self.auth_username and self.auth_password:
                    await context.set_http_credentials({
                        'username': self.auth_username,
                        'password': self.auth_password
                    })
                
                # Setup navigation timeout
                page.set_default_timeout(self.browser_timeout * 1000)
                
                # Track redirects
                redirects = []
                
                # Monitor requests and responses
                async def handle_request(request):
                    if request.resource_type == "document":
                        redirects.append(request.url)
                
                async def handle_response(response):
                    if response.status >= 300 and response.status < 400:
                        location = response.headers.get('location')
                        if location:
                            redirects.append(location)
                
                page.on("request", handle_request)
                page.on("response", handle_response)
                
                # Navigate to URL
                try:
                    response = await page.goto(url, wait_until="networkidle")
                    if response:
                        self.logger.debug(f"Page loaded with status: {response.status}")
                except Exception as e:
                    self.logger.error(f"Error navigating to {url}: {e}")
                
                # Get final URL
                final_url = page.url
                
                # Inject script to detect JS redirects
                await page.evaluate("""
                    () => {
                        window._redirects = [];
                        
                        // Save original methods
                        const originalAssign = window.location.assign;
                        const originalReplace = window.location.replace;
                        const originalHref = Object.getOwnPropertyDescriptor(window.location, 'href');
                        
                        // Override methods to track redirects
                        window.location.assign = function(url) {
                            window._redirects.push(url);
                            return originalAssign.apply(this, arguments);
                        };
                        
                        window.location.replace = function(url) {
                            window._redirects.push(url);
                            return originalReplace.apply(this, arguments);
                        };
                        
                        if (originalHref && originalHref.set) {
                            Object.defineProperty(window.location, 'href', {
                                set: function(url) {
                                    window._redirects.push(url);
                                    return originalHref.set.call(this, url);
                                },
                                get: originalHref.get
                            });
                        }
                    }
                """)
                
                # Wait for potential redirects
                await page.wait_for_timeout(2000)
                
                # Get JS redirects
                js_redirects = await page.evaluate("window._redirects || []")
                
                # Get page content
                content = await page.content()
                
                # Check for meta refresh redirects
                meta_refresh_redirects = []
                meta_refresh_elements = await page.query_selector_all('meta[http-equiv="refresh"]')
                for element in meta_refresh_elements:
                    content_attr = await element.get_attribute('content')
                    if content_attr and 'url=' in content_attr.lower():
                        url_part = content_attr.lower().split('url=')[1].strip()
                        meta_refresh_redirects.append(url_part)
                
                # Check for form-based redirects
                form_redirects = []
                form_elements = await page.query_selector_all('form')
                for form in form_elements:
                    action = await form.get_attribute('action')
                    if action and any(domain in action for domain in self.payload_manager.target_domains):
                        form_redirects.append(action)
                
                # Close browser
                await browser.close()
                
                # Process results
                all_redirects = redirects + js_redirects + meta_refresh_redirects + form_redirects
                if all_redirects:
                    self.logger.info(f"Found {len(all_redirects)} redirects in browser testing")
                    for redirect_url in all_redirects:
                        is_vuln, severity, details = self.payload_manager.is_vulnerable(redirect_url, content)
                        if is_vuln:
                            result = {
                                "url": url,
                                "payload_url": url,
                                "status_code": 200,
                                "final_url": final_url,
                                "severity": severity,
                                "details": f"Browser-detected redirect: {details}",
                                "type": "browser_redirect",
                                "evidence": f"Detected redirect to: {redirect_url}",
                                "payload": "N/A"
                            }
                            
                            result_key = f"{url}:browser:{redirect_url}"
                            if result_key not in self.result_set:
                                self.results.append(result)
                                self.result_set.add(result_key)
                                self.vulnerable_count += 1
                                
                                print(Fore.RED + f"[BROWSER VULNERABLE] {url} -> {redirect_url} (Severity: {severity})")
                
                # Check if final URL indicates vulnerability
                if final_url != url:
                    is_vuln, severity, details = self.payload_manager.is_vulnerable(final_url, content)
                    if is_vuln:
                        result = {
                            "url": url,
                            "payload_url": url,
                            "status_code": 200,
                            "final_url": final_url,
                            "severity": severity,
                            "details": details,
                            "type": "browser_redirect",
                            "evidence": f"Final URL: {final_url}",
                            "payload": "N/A"
                        }
                        
                        result_key = f"{url}:browser:final"
                        if result_key not in self.result_set:
                            self.results.append(result)
                            self.result_set.add(result_key)
                            self.vulnerable_count += 1
                            
                            print(Fore.RED + f"[BROWSER VULNERABLE] {url} -> {final_url} (Severity: {severity})")
        
        except Exception as e:
            self.logger.error(f"Error in Playwright testing: {e}", exc_info=True)
    
    async def _test_with_selenium(self, url: str) -> None:
        """
        Test a URL using Selenium for deeper JS-based redirect detection
        
        Args:
            url (str): URL to test
        """
        self.logger.debug(f"Testing URL with Selenium: {url}")
        
        if not SELENIUM_AVAILABLE:
            self.logger.warning("Selenium is not available. Install it with 'pip install selenium webdriver-manager'")
            return
        
        try:
            # Setup browser options based on config
            browser_type = self.config.get('browser', {}).get('browser_type', 'chrome')
            
            if browser_type.lower() == 'firefox':
                # Setup Firefox options
                options = FirefoxOptions()
                if self.browser_headless:
                    options.add_argument('--headless')
                
                # Set user agent
                if self.user_agent_rotation:
                    options.set_preference("general.useragent.override", self.get_random_user_agent())
                
                # Set proxy if configured
                if self.proxy:
                    proxy_url = urllib.parse.urlparse(self.proxy)
                    options.set_preference("network.proxy.type", 1)
                    options.set_preference("network.proxy.http", proxy_url.hostname)
                    options.set_preference("network.proxy.http_port", proxy_url.port or 80)
                    options.set_preference("network.proxy.ssl", proxy_url.hostname)
                    options.set_preference("network.proxy.ssl_port", proxy_url.port or 443)
                    
                    if self.proxy_auth and proxy_url.username and proxy_url.password:
                        options.set_preference("network.proxy.username", proxy_url.username)
                        options.set_preference("network.proxy.password", proxy_url.password)
                
                # Create driver
                from webdriver_manager.firefox import GeckoDriverManager
                driver = webdriver.Firefox(options=options, executable_path=GeckoDriverManager().install())
            else:  # Default to Chrome
                # Setup Chrome options
                options = ChromeOptions()
                if self.browser_headless:
                    options.add_argument('--headless')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                
                # Set user agent
                if self.user_agent_rotation:
                    options.add_argument(f'--user-agent={self.get_random_user_agent()}')
                
                # Set proxy if configured
                if self.proxy:
                    options.add_argument(f'--proxy-server={self.proxy}')
                
                # Create driver
                from webdriver_manager.chrome import ChromeDriverManager
                driver = webdriver.Chrome(options=options, executable_path=ChromeDriverManager().install())
            
            # Set timeouts
            driver.set_page_load_timeout(self.browser_timeout)
            driver.set_script_timeout(self.browser_timeout)
            
            # Setup authentication if needed
            if self.auth_enabled and self.auth_type == 'basic' and self.auth_username and self.auth_password:
                # Create URL with auth credentials
                parsed_url = urllib.parse.urlparse(url)
                auth_url = f"{parsed_url.scheme}://{self.auth_username}:{self.auth_password}@{parsed_url.netloc}{parsed_url.path}"
                if parsed_url.query:
                    auth_url += f"?{parsed_url.query}"
                if parsed_url.fragment:
                    auth_url += f"#{parsed_url.fragment}"
                
                # Navigate to URL with auth
                driver.get(auth_url)
            else:
                # Navigate to URL
                driver.get(url)
            
            # Wait for page to load
            await asyncio.sleep(2)  # Give time for JS to execute
            
            # Get final URL
            final_url = driver.current_url
            
            # Inject script to detect JS redirects
            driver.execute_script("""
                window._redirects = [];
                
                // Save original methods
                const originalAssign = window.location.assign;
                const originalReplace = window.location.replace;
                
                // Override methods to track redirects
                window.location.assign = function(url) {
                    window._redirects.push(url);
                    return originalAssign.apply(this, arguments);
                };
                
                window.location.replace = function(url) {
                    window._redirects.push(url);
                    return originalReplace.apply(this, arguments);
                };
                
                // Override href property
                try {
                    const originalHref = Object.getOwnPropertyDescriptor(window.location, 'href');
                    if (originalHref && originalHref.set) {
                        Object.defineProperty(window.location, 'href', {
                            set: function(url) {
                                window._redirects.push(url);
                                return originalHref.set.call(this, url);
                            },
                            get: originalHref.get
                        });
                    }
                } catch (e) {
                    console.error('Error overriding href property:', e);
                }
            """)
            
            # Wait for potential redirects
            await asyncio.sleep(2)
            
            # Get JS redirects
            js_redirects = driver.execute_script("return window._redirects || [];")
            
            # Get page content
            content = driver.page_source
            
            # Check for meta refresh redirects
            meta_refresh_redirects = []
            try:
                from selenium.webdriver.common.by import By
                meta_elements = driver.find_elements(By.CSS_SELECTOR, 'meta[http-equiv="refresh"]')
                for element in meta_elements:
                    content_attr = element.get_attribute('content')
                    if content_attr and 'url=' in content_attr.lower():
                        url_part = content_attr.lower().split('url=')[1].strip()
                        meta_refresh_redirects.append(url_part)
            except Exception as e:
                self.logger.error(f"Error checking meta refresh: {e}")
            
            # Check for form-based redirects
            form_redirects = []
            try:
                from selenium.webdriver.common.by import By
                form_elements = driver.find_elements(By.TAG_NAME, 'form')
                for form in form_elements:
                    action = form.get_attribute('action')
                    if action and any(domain in action for domain in self.payload_manager.target_domains):
                        form_redirects.append(action)
            except Exception as e:
                self.logger.error(f"Error checking forms: {e}")
            
            # Close driver
            driver.quit()
            
            # Process results
            all_redirects = js_redirects + meta_refresh_redirects + form_redirects
            if all_redirects:
                self.logger.info(f"Found {len(all_redirects)} redirects in Selenium testing")
                for redirect_url in all_redirects:
                    is_vuln, severity, details = self.payload_manager.is_vulnerable(redirect_url, content)
                    if is_vuln:
                        result = {
                            "url": url,
                            "payload_url": url,
                            "status_code": 200,
                            "final_url": final_url,
                            "severity": severity,
                            "details": f"Browser-detected redirect: {details}",
                            "type": "browser_redirect",
                            "evidence": f"Detected redirect to: {redirect_url}",
                            "payload": "N/A"
                        }
                        
                        result_key = f"{url}:selenium:{redirect_url}"
                        if result_key not in self.result_set:
                            self.results.append(result)
                            self.result_set.add(result_key)
                            self.vulnerable_count += 1
                            
                            print(Fore.RED + f"[BROWSER VULNERABLE] {url} -> {redirect_url} (Severity: {severity})")
            
            # Check if final URL indicates vulnerability
            if final_url != url:
                is_vuln, severity, details = self.payload_manager.is_vulnerable(final_url, content)
                if is_vuln:
                    result = {
                        "url": url,
                        "payload_url": url,
                        "status_code": 200,
                        "final_url": final_url,
                        "severity": severity,
                        "details": details,
                        "type": "browser_redirect",
                        "evidence": f"Final URL: {final_url}",
                        "payload": "N/A"
                    }
                    
                    result_key = f"{url}:selenium:final"
                    if result_key not in self.result_set:
                        self.results.append(result)
                        self.result_set.add(result_key)
                        self.vulnerable_count += 1
                        
                        print(Fore.RED + f"[BROWSER VULNERABLE] {url} -> {final_url} (Severity: {severity})")
        
        except Exception as e:
            self.logger.error(f"Error in Selenium testing: {e}", exc_info=True)
    
    def get_scan_stats(self) -> Dict[str, Any]:
        """
        Get scan statistics
        
        Returns:
            Dict[str, Any]: Scan statistics
        """
        elapsed_time = self.end_time - self.start_time
        urls_per_sec = self.total_urls / elapsed_time if elapsed_time > 0 else 0
        
        return {
            "total_urls": self.total_urls,
            "vulnerable_urls": self.vulnerable_count,
            "elapsed_time": elapsed_time,
            "urls_per_sec": urls_per_sec
        }
