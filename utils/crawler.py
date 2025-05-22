#!/usr/bin/env python3
"""
OpenX URL Crawler
A utility script to crawl websites and discover potential URLs for open redirect testing
"""

import argparse
import asyncio
import logging
import re
import sys
from typing import List, Set, Dict, Any, Optional
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp import ClientSession, ClientTimeout
from bs4 import BeautifulSoup
import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('openx-crawler')

class Crawler:
    """Website crawler to discover URLs for open redirect testing"""
    
    def __init__(
        self, 
        base_url: str, 
        max_depth: int = 2, 
        concurrency: int = 10, 
        timeout: int = 10,
        user_agent: str = None,
        proxy: str = None,
        output_file: str = None,
        include_params: bool = True,
        exclude_extensions: List[str] = None,
        redirect_params: List[str] = None
    ):
        """
        Initialize the crawler
        
        Args:
            base_url (str): Base URL to start crawling from
            max_depth (int): Maximum crawl depth
            concurrency (int): Maximum number of concurrent requests
            timeout (int): Request timeout in seconds
            user_agent (str): Custom user agent
            proxy (str): Proxy URL
            output_file (str): Output file to save discovered URLs
            include_params (bool): Include URLs with parameters
            exclude_extensions (List[str]): File extensions to exclude
            redirect_params (List[str]): Parameter names likely used for redirects
        """
        self.base_url = base_url
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.timeout = timeout
        self.user_agent = user_agent or "OpenX-Crawler/1.0"
        self.proxy = proxy
        self.output_file = output_file
        self.include_params = include_params
        self.exclude_extensions = exclude_extensions or [
            '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg',
            '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.tar', '.gz'
        ]
        
        # Common parameter names used for redirects
        self.redirect_params = redirect_params or [
            'redirect', 'redirect_to', 'redirecturl', 'redirect_uri', 'return', 'return_url',
            'returnurl', 'return_to', 'goto', 'next', 'url', 'link', 'target', 'dest', 
            'destination', 'redir', 'redirection', 'continue', 'forward', 'location'
        ]
        
        # Ensure base URL has a trailing slash for urljoin to work correctly
        if not self.base_url.endswith('/'):
            self.base_url += '/'
            
        # Parse base URL to get domain for filtering
        self.base_domain = urlparse(self.base_url).netloc
        
        # Set of visited URLs
        self.visited_urls: Set[str] = set()
        
        # Set of discovered URLs
        self.discovered_urls: Set[str] = set()
        
        # Set of potential redirect URLs
        self.potential_redirect_urls: Set[str] = set()
        
        # Semaphore for concurrency control
        self.semaphore = asyncio.Semaphore(self.concurrency)
        
        # Progress bar
        self.pbar = None
    
    async def crawl(self) -> Set[str]:
        """
        Start the crawling process
        
        Returns:
            Set[str]: Set of discovered URLs
        """
        logger.info(f"Starting crawl from {self.base_url} with max depth {self.max_depth}")
        
        # Initialize progress bar
        self.pbar = tqdm.tqdm(desc="Crawling", unit="URLs")
        
        # Create a client session
        timeout = ClientTimeout(total=self.timeout)
        headers = {"User-Agent": self.user_agent}
        
        async with ClientSession(timeout=timeout, headers=headers) as session:
            # Start crawling from the base URL
            await self._crawl_url(session, self.base_url, 0)
            
        self.pbar.close()
        
        # Save discovered URLs to file if specified
        if self.output_file:
            self._save_urls()
        
        logger.info(f"Crawling completed. Discovered {len(self.discovered_urls)} URLs")
        logger.info(f"Found {len(self.potential_redirect_urls)} potential redirect URLs")
        
        return self.discovered_urls
    
    async def _crawl_url(self, session: ClientSession, url: str, depth: int) -> None:
        """
        Crawl a URL and extract links
        
        Args:
            session (ClientSession): aiohttp session
            url (str): URL to crawl
            depth (int): Current crawl depth
        """
        # Skip if max depth reached or URL already visited
        if depth > self.max_depth or url in self.visited_urls:
            return
        
        # Add URL to visited set
        self.visited_urls.add(url)
        
        # Update progress bar
        self.pbar.update(1)
        
        try:
            # Use semaphore to limit concurrency
            async with self.semaphore:
                # Make request
                proxy = self.proxy
                async with session.get(url, proxy=proxy, allow_redirects=True) as response:
                    # Skip if not HTML
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' not in content_type:
                        return
                    
                    # Get response text
                    html = await response.text()
                    
                    # Parse HTML
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Extract links
                    links = self._extract_links(soup, url)
                    
                    # Add to discovered URLs
                    self.discovered_urls.update(links)
                    
                    # Check for potential redirect parameters
                    self._find_redirect_params(links)
                    
                    # Recursively crawl links
                    tasks = []
                    for link in links:
                        if link not in self.visited_urls:
                            tasks.append(self._crawl_url(session, link, depth + 1))
                    
                    if tasks:
                        await asyncio.gather(*tasks)
        
        except Exception as e:
            logger.debug(f"Error crawling {url}: {e}")
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> Set[str]:
        """
        Extract links from HTML
        
        Args:
            soup (BeautifulSoup): BeautifulSoup object
            base_url (str): Base URL for resolving relative links
            
        Returns:
            Set[str]: Set of extracted links
        """
        links = set()
        
        # Extract links from <a> tags
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            
            # Skip empty links, anchors, and javascript links
            if not href or href.startswith('#') or href.startswith('javascript:'):
                continue
            
            # Resolve relative URL
            full_url = urljoin(base_url, href)
            
            # Parse URL
            parsed_url = urlparse(full_url)
            
            # Skip external domains
            if parsed_url.netloc and parsed_url.netloc != self.base_domain:
                continue
            
            # Skip excluded extensions
            if any(parsed_url.path.endswith(ext) for ext in self.exclude_extensions):
                continue
            
            # Skip URLs with fragments
            url_without_fragment = full_url.split('#')[0]
            
            # Add to links
            links.add(url_without_fragment)
        
        # Extract links from <form> tags
        for form in soup.find_all('form', action=True):
            action = form['action']
            
            # Skip empty actions
            if not action:
                continue
            
            # Resolve relative URL
            full_url = urljoin(base_url, action)
            
            # Parse URL
            parsed_url = urlparse(full_url)
            
            # Skip external domains
            if parsed_url.netloc and parsed_url.netloc != self.base_domain:
                continue
            
            # Add to links
            links.add(full_url)
        
        # Extract meta refresh redirects
        for meta in soup.find_all('meta', attrs={'http-equiv': 'refresh'}):
            content = meta.get('content', '')
            if 'url=' in content.lower():
                redirect_url = content.lower().split('url=')[1].strip()
                full_url = urljoin(base_url, redirect_url)
                links.add(full_url)
        
        return links
    
    def _find_redirect_params(self, urls: Set[str]) -> None:
        """
        Find potential redirect parameters in URLs
        
        Args:
            urls (Set[str]): Set of URLs to check
        """
        for url in urls:
            parsed_url = urlparse(url)
            
            # Skip URLs without query parameters
            if not parsed_url.query:
                continue
            
            # Check if URL contains redirect parameters
            query_params = parsed_url.query.split('&')
            for param in query_params:
                if '=' not in param:
                    continue
                
                name, value = param.split('=', 1)
                if name.lower() in self.redirect_params:
                    self.potential_redirect_urls.add(url)
                    break
    
    def _save_urls(self) -> None:
        """Save discovered URLs to file"""
        try:
            with open(self.output_file, 'w') as f:
                # Write potential redirect URLs first
                for url in sorted(self.potential_redirect_urls):
                    f.write(f"{url}\n")
                
                # Write other URLs if include_params is True
                if self.include_params:
                    other_urls = self.discovered_urls - self.potential_redirect_urls
                    for url in sorted(other_urls):
                        if '?' in url:  # Only include URLs with parameters
                            f.write(f"{url}\n")
            
            logger.info(f"Saved {len(self.potential_redirect_urls)} potential redirect URLs to {self.output_file}")
            
        except Exception as e:
            logger.error(f"Error saving URLs to file: {e}")

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='OpenX URL Crawler')
    parser.add_argument('-u', '--url', required=True, help='Base URL to crawl')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Maximum crawl depth')
    parser.add_argument('-c', '--concurrency', type=int, default=10, help='Maximum concurrent requests')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('-o', '--output', help='Output file to save discovered URLs')
    parser.add_argument('-a', '--user-agent', help='Custom user agent')
    parser.add_argument('-p', '--proxy', help='Proxy URL')
    parser.add_argument('--include-all', action='store_true', help='Include all URLs, not just potential redirect URLs')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Create crawler
    crawler = Crawler(
        base_url=args.url,
        max_depth=args.depth,
        concurrency=args.concurrency,
        timeout=args.timeout,
        user_agent=args.user_agent,
        proxy=args.proxy,
        output_file=args.output,
        include_params=args.include_all
    )
    
    # Start crawling
    await crawler.crawl()

if __name__ == '__main__':
    asyncio.run(main())
