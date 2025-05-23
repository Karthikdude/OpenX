#!/usr/bin/env python3
"""
WAF Bypass Module for OpenX
Implements advanced evasion techniques for bypassing WAF protections
"""

import os
import re
import random
import time
import logging
import base64
import hashlib
import urllib.parse
import asyncio
from typing import Dict, List, Set, Tuple, Any, Optional
import aiohttp

logger = logging.getLogger('openx.evasion.waf_bypass')

class WafBypass:
    """
    Implements advanced evasion techniques for bypassing WAF protections
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the WAF bypass module
        
        Args:
            config (Optional[Dict[str, Any]]): Configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        log_level = self.config.get('general', {}).get('verbose', False)
        logger.setLevel(logging.DEBUG if log_level else logging.INFO)
        
        # WAF bypass settings
        self.enabled = self.config.get('evasion', {}).get('waf_bypass', True)
        self.adaptive_delay = self.config.get('evasion', {}).get('adaptive_delay', True)
        self.pattern_randomization = self.config.get('evasion', {}).get('pattern_randomization', True)
        self.custom_encoding = self.config.get('evasion', {}).get('custom_encoding', True)
        
        # Initialize evasion techniques
        self._initialize_techniques()
        
        # Server response patterns
        self.response_patterns = {}
        self.delay_multiplier = 1.0
    
    def _initialize_techniques(self):
        """Initialize evasion techniques"""
        # Custom encoding techniques
        self.encoding_techniques = [
            self._url_encode,
            self._double_url_encode,
            self._hex_encode,
            self._unicode_encode,
            self._mixed_case_encode,
            self._null_byte_encode,
            self._path_bypass_encode
        ]
        
        # Request pattern randomization
        self.header_variations = [
            {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'},
            {'Accept': 'application/json, text/javascript, */*; q=0.01'},
            {'Accept': 'text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8'},
            {'Accept-Language': 'en-US,en;q=0.5'},
            {'Accept-Language': 'en-US,en;q=0.9'},
            {'Accept-Encoding': 'gzip, deflate, br'},
            {'Accept-Encoding': 'gzip, deflate'},
            {'Connection': 'keep-alive'},
            {'Connection': 'close'},
            {'Cache-Control': 'no-cache'},
            {'Cache-Control': 'max-age=0'},
            {'Pragma': 'no-cache'},
            {'Upgrade-Insecure-Requests': '1'},
            {'DNT': '1'},
            {'TE': 'Trailers'}
        ]
        
        # WAF evasion user agents
        self.evasion_user_agents = [
            # Legitimate browser user agents
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            
            # Less common but legitimate browsers
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.277',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36 Vivaldi/4.0.2312.41',
            
            # Uncommon but legitimate user agents
            'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Brave/1.27.111'
        ]
    
    async def apply_evasion_techniques(self, url: str, headers: Dict[str, str] = None) -> Tuple[str, Dict[str, str]]:
        """
        Apply WAF evasion techniques to a URL and headers
        
        Args:
            url (str): Original URL
            headers (Dict[str, str], optional): Original headers
            
        Returns:
            Tuple[str, Dict[str, str]]: Evaded URL and headers
        """
        if not self.enabled:
            return url, headers or {}
        
        # Initialize headers if not provided
        if headers is None:
            headers = {}
        
        # Apply URL encoding evasion
        if self.custom_encoding:
            url = self._apply_encoding_technique(url)
        
        # Apply request pattern randomization
        if self.pattern_randomization:
            headers = self._randomize_headers(headers)
        
        # Add evasion user agent if not already set
        if 'User-Agent' not in headers:
            headers['User-Agent'] = random.choice(self.evasion_user_agents)
        
        logger.debug(f"Applied WAF evasion techniques to URL: {url}")
        return url, headers
    
    def _apply_encoding_technique(self, url: str) -> str:
        """
        Apply a random encoding technique to the URL
        
        Args:
            url (str): Original URL
            
        Returns:
            str: Encoded URL
        """
        # Parse URL
        parsed = urllib.parse.urlparse(url)
        
        # Only encode the query parameters
        if parsed.query:
            # Choose a random encoding technique
            encoding_func = random.choice(self.encoding_techniques)
            
            # Apply encoding to query parameters
            encoded_query = encoding_func(parsed.query)
            
            # Rebuild URL
            url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                encoded_query,
                parsed.fragment
            ))
        
        return url
    
    def _randomize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Randomize headers to evade pattern detection
        
        Args:
            headers (Dict[str, str]): Original headers
            
        Returns:
            Dict[str, str]: Randomized headers
        """
        # Add 1-3 random headers
        num_headers = random.randint(1, 3)
        random_headers = random.sample(self.header_variations, num_headers)
        
        for header in random_headers:
            for key, value in header.items():
                if key not in headers:
                    headers[key] = value
        
        return headers
    
    async def calculate_adaptive_delay(self, response_time: float, status_code: int) -> float:
        """
        Calculate adaptive delay based on server response patterns
        
        Args:
            response_time (float): Server response time in seconds
            status_code (int): HTTP status code
            
        Returns:
            float: Delay in seconds
        """
        if not self.adaptive_delay:
            return 0.0
        
        # Update response patterns
        status_key = f"status_{status_code}"
        if status_key not in self.response_patterns:
            self.response_patterns[status_key] = []
        
        self.response_patterns[status_key].append(response_time)
        
        # Keep only the last 5 response times
        if len(self.response_patterns[status_key]) > 5:
            self.response_patterns[status_key].pop(0)
        
        # Calculate average response time
        avg_response_time = sum(self.response_patterns[status_key]) / len(self.response_patterns[status_key])
        
        # Adjust delay multiplier based on status code
        if status_code == 403 or status_code == 429:
            # Increase delay for blocked requests
            self.delay_multiplier = min(self.delay_multiplier * 1.5, 10.0)
        elif status_code == 200:
            # Decrease delay for successful requests
            self.delay_multiplier = max(self.delay_multiplier * 0.8, 1.0)
        
        # Calculate delay (between 1-2x average response time)
        delay = avg_response_time * self.delay_multiplier * random.uniform(1.0, 2.0)
        
        # Add random jitter (±20%)
        jitter = random.uniform(-0.2, 0.2)
        delay = delay * (1 + jitter)
        
        # Ensure delay is reasonable
        delay = min(max(delay, 0.5), 10.0)
        
        logger.debug(f"Adaptive delay: {delay:.2f}s (multiplier: {self.delay_multiplier:.2f})")
        return delay
    
    async def apply_request_timing(self, session: aiohttp.ClientSession) -> aiohttp.ClientSession:
        """
        Apply request timing randomization to mimic human behavior
        
        Args:
            session (aiohttp.ClientSession): HTTP client session
            
        Returns:
            aiohttp.ClientSession: Modified session
        """
        if not self.enabled:
            return session
        
        # Create a custom trace config
        trace_config = aiohttp.TraceConfig()
        
        # Add timing randomization
        async def on_request_start(session, trace_config_ctx, params):
            # Add random delay before request (0.1-0.5s)
            await asyncio.sleep(random.uniform(0.1, 0.5))
        
        trace_config.on_request_start.append(on_request_start)
        session._trace_configs.append(trace_config)
        
        return session
    
    # Encoding techniques
    
    def _url_encode(self, text: str) -> str:
        """URL encode the text"""
        return urllib.parse.quote(text)
    
    def _double_url_encode(self, text: str) -> str:
        """Double URL encode the text"""
        return urllib.parse.quote(urllib.parse.quote(text))
    
    def _hex_encode(self, text: str) -> str:
        """Hex encode the text"""
        # Convert to hex but keep the structure
        parts = []
        for part in text.split('&'):
            if '=' in part:
                key, value = part.split('=', 1)
                hex_value = ''.join([f'%{ord(c):02X}' for c in value])
                parts.append(f"{key}={hex_value}")
            else:
                parts.append(part)
        
        return '&'.join(parts)
    
    def _unicode_encode(self, text: str) -> str:
        """Unicode encode the text"""
        # Convert to unicode but keep the structure
        parts = []
        for part in text.split('&'):
            if '=' in part:
                key, value = part.split('=', 1)
                unicode_value = ''.join([f'%u00{ord(c):02X}' for c in value])
                parts.append(f"{key}={unicode_value}")
            else:
                parts.append(part)
        
        return '&'.join(parts)
    
    def _mixed_case_encode(self, text: str) -> str:
        """Mix the case of URL encoded characters"""
        # URL encode first
        encoded = urllib.parse.quote(text)
        
        # Randomly change the case of percent-encoded characters
        result = ''
        i = 0
        while i < len(encoded):
            if encoded[i] == '%' and i + 2 < len(encoded):
                if random.choice([True, False]):
                    result += '%' + encoded[i+1:i+3].upper()
                else:
                    result += '%' + encoded[i+1:i+3].lower()
                i += 3
            else:
                result += encoded[i]
                i += 1
        
        return result
    
    def _null_byte_encode(self, text: str) -> str:
        """Insert null bytes into the text"""
        # URL encode first
        encoded = urllib.parse.quote(text)
        
        # Insert null bytes at random positions
        result = ''
        for i, c in enumerate(encoded):
            result += c
            if random.random() < 0.1:  # 10% chance
                result += '%00'
        
        return result
    
    def _path_bypass_encode(self, text: str) -> str:
        """Use path traversal sequences to confuse WAFs"""
        # URL encode first
        encoded = urllib.parse.quote(text)
        
        # Insert path traversal sequences at random positions
        traversal_sequences = ['../', './', '//', '/./', '/../']
        
        result = ''
        for i, c in enumerate(encoded):
            if random.random() < 0.05:  # 5% chance
                result += random.choice(traversal_sequences)
            result += c
        
        return result
    
    # Custom request functions
    
    async def make_evasive_request(self, url: str, session: Optional[aiohttp.ClientSession] = None, **kwargs) -> Tuple[aiohttp.ClientResponse, float]:
        """
        Make a request with WAF evasion techniques
        
        Args:
            url (str): URL to request
            session (Optional[aiohttp.ClientSession]): HTTP client session
            **kwargs: Additional arguments for the request
            
        Returns:
            Tuple[aiohttp.ClientResponse, float]: Response and response time
        """
        if not self.enabled:
            if session:
                return await session.get(url, **kwargs), 0.0
            else:
                async with aiohttp.ClientSession() as session:
                    return await session.get(url, **kwargs), 0.0
        
        # Apply evasion techniques
        evaded_url, headers = await self.apply_evasion_techniques(url, kwargs.get('headers', {}))
        kwargs['headers'] = headers
        
        # Create session if not provided
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        # Apply request timing
        session = await self.apply_request_timing(session)
        
        try:
            # Make request and measure response time
            start_time = time.time()
            response = await session.get(evaded_url, **kwargs)
            response_time = time.time() - start_time
            
            # Calculate adaptive delay
            delay = await self.calculate_adaptive_delay(response_time, response.status)
            
            # Apply delay
            if delay > 0:
                await asyncio.sleep(delay)
            
            return response, response_time
        finally:
            if close_session:
                await session.close()
    
    def get_evasion_status(self) -> Dict[str, Any]:
        """
        Get the current status of WAF evasion techniques
        
        Returns:
            Dict[str, Any]: Evasion status
        """
        return {
            'enabled': self.enabled,
            'adaptive_delay': self.adaptive_delay,
            'pattern_randomization': self.pattern_randomization,
            'custom_encoding': self.custom_encoding,
            'delay_multiplier': self.delay_multiplier,
            'response_patterns': {k: len(v) for k, v in self.response_patterns.items()}
        }
