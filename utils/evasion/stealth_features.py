#!/usr/bin/env python3
"""
Stealth Features Module for OpenX
Implements advanced stealth techniques for evading detection
"""

import os
import re
import random
import time
import logging
import asyncio
import json
import uuid
from typing import Dict, List, Set, Tuple, Any, Optional
import aiohttp
from urllib.parse import urlparse, parse_qs, urlencode

logger = logging.getLogger('openx.evasion.stealth_features')

class StealthFeatures:
    """
    Implements advanced stealth techniques for evading detection:
    - Traffic mimicking (simulate normal user behavior)
    - Distributed request sourcing
    - Request timing randomization based on human patterns
    - Session management with realistic user flows
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the stealth features module
        
        Args:
            config (Optional[Dict[str, Any]]): Configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        log_level = self.config.get('general', {}).get('verbose', False)
        logger.setLevel(logging.DEBUG if log_level else logging.INFO)
        
        # Stealth settings
        self.enabled = self.config.get('stealth', {}).get('enabled', True)
        self.traffic_mimicking = self.config.get('stealth', {}).get('traffic_mimicking', True)
        self.distributed_requests = self.config.get('stealth', {}).get('distributed_requests', False)
        self.timing_randomization = self.config.get('stealth', {}).get('timing_randomization', True)
        self.session_management = self.config.get('stealth', {}).get('session_management', True)
        
        # Initialize stealth components
        self._initialize_components()
        
        # Session storage
        self.sessions = {}
        self.current_session_id = None
    
    def _initialize_components(self):
        """Initialize stealth components"""
        # Human-like timing patterns (in seconds)
        self.timing_patterns = {
            'page_view': {
                'min': 2.0,
                'max': 30.0,
                'mean': 8.0,
                'std_dev': 5.0
            },
            'link_click': {
                'min': 0.5,
                'max': 5.0,
                'mean': 1.5,
                'std_dev': 0.8
            },
            'form_fill': {
                'min': 3.0,
                'max': 45.0,
                'mean': 15.0,
                'std_dev': 8.0
            },
            'search': {
                'min': 1.0,
                'max': 10.0,
                'mean': 3.0,
                'std_dev': 2.0
            }
        }
        
        # Common user actions for traffic mimicking
        self.common_actions = [
            'page_view',
            'link_click',
            'form_fill',
            'search',
            'navigation'
        ]
        
        # Common page types for realistic user flows
        self.page_types = [
            'home',
            'login',
            'product',
            'category',
            'search',
            'cart',
            'checkout',
            'account',
            'about',
            'contact'
        ]
        
        # Proxy rotation for distributed requests
        self.proxy_list = self.config.get('stealth', {}).get('proxy_list', [])
        self.current_proxy_index = 0
    
    async def create_session(self) -> str:
        """
        Create a new session with realistic user attributes
        
        Returns:
            str: Session ID
        """
        if not self.enabled or not self.session_management:
            return str(uuid.uuid4())
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Create session with realistic attributes
        self.sessions[session_id] = {
            'id': session_id,
            'created_at': time.time(),
            'last_activity': time.time(),
            'user_agent': self._generate_user_agent(),
            'referrer': self._generate_referrer(),
            'cookies': {},
            'history': [],
            'current_page': 'home',
            'actions': [],
            'form_data': {},
            'viewport': self._generate_viewport(),
            'geolocation': self._generate_geolocation(),
            'connection_type': random.choice(['wifi', '4g', 'cable', 'dsl']),
            'device_type': random.choice(['desktop', 'mobile', 'tablet']),
            'os': random.choice(['windows', 'macos', 'linux', 'ios', 'android']),
            'browser': random.choice(['chrome', 'firefox', 'safari', 'edge'])
        }
        
        self.current_session_id = session_id
        logger.debug(f"Created new session: {session_id}")
        
        return session_id
    
    def get_session(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get a session by ID
        
        Args:
            session_id (Optional[str]): Session ID (uses current session if None)
            
        Returns:
            Dict[str, Any]: Session data
        """
        if not session_id:
            session_id = self.current_session_id
        
        if not session_id or session_id not in self.sessions:
            # Create a new session if none exists
            session_id = asyncio.run(self.create_session())
        
        return self.sessions[session_id]
    
    async def update_session(self, session_id: str, url: str, action_type: str = 'page_view') -> Dict[str, Any]:
        """
        Update session with new activity
        
        Args:
            session_id (str): Session ID
            url (str): URL of the activity
            action_type (str): Type of action
            
        Returns:
            Dict[str, Any]: Updated session
        """
        if not self.enabled or not self.session_management or session_id not in self.sessions:
            return {}
        
        session = self.sessions[session_id]
        
        # Update session activity
        session['last_activity'] = time.time()
        
        # Add to history
        if url not in session['history']:
            session['history'].append(url)
            
            # Limit history size
            if len(session['history']) > 20:
                session['history'].pop(0)
        
        # Add action
        action = {
            'type': action_type,
            'url': url,
            'timestamp': time.time()
        }
        session['actions'].append(action)
        
        # Update current page type
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()
        
        if '/login' in path or '/signin' in path:
            session['current_page'] = 'login'
        elif '/product' in path or '/item' in path:
            session['current_page'] = 'product'
        elif '/category' in path or '/catalog' in path:
            session['current_page'] = 'category'
        elif '/search' in path:
            session['current_page'] = 'search'
        elif '/cart' in path or '/basket' in path:
            session['current_page'] = 'cart'
        elif '/checkout' in path:
            session['current_page'] = 'checkout'
        elif '/account' in path or '/profile' in path:
            session['current_page'] = 'account'
        elif '/about' in path:
            session['current_page'] = 'about'
        elif '/contact' in path:
            session['current_page'] = 'contact'
        elif path == '/' or path == '':
            session['current_page'] = 'home'
        
        logger.debug(f"Updated session {session_id} with {action_type} action: {url}")
        
        return session
    
    async def get_next_action(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get the next realistic user action based on current session state
        
        Args:
            session_id (Optional[str]): Session ID (uses current session if None)
            
        Returns:
            Dict[str, Any]: Next action details
        """
        if not self.enabled or not self.traffic_mimicking:
            return {'type': 'direct', 'delay': 0}
        
        session = self.get_session(session_id)
        current_page = session.get('current_page', 'home')
        
        # Determine next action based on current page
        if current_page == 'home':
            action_type = random.choice(['link_click', 'search', 'navigation'])
            next_page = random.choice(['product', 'category', 'search', 'login', 'about'])
        elif current_page == 'login':
            action_type = random.choice(['form_fill', 'link_click'])
            next_page = random.choice(['home', 'account'])
        elif current_page == 'product':
            action_type = random.choice(['link_click', 'page_view'])
            next_page = random.choice(['cart', 'category', 'home'])
        elif current_page == 'category':
            action_type = 'link_click'
            next_page = random.choice(['product', 'home', 'search'])
        elif current_page == 'search':
            action_type = 'link_click'
            next_page = random.choice(['product', 'category', 'home'])
        elif current_page == 'cart':
            action_type = random.choice(['link_click', 'form_fill'])
            next_page = random.choice(['checkout', 'product', 'home'])
        elif current_page == 'checkout':
            action_type = 'form_fill'
            next_page = random.choice(['home', 'account'])
        else:
            action_type = 'link_click'
            next_page = random.choice(['home', 'product', 'search'])
        
        # Calculate realistic delay
        delay = self._calculate_realistic_delay(action_type)
        
        return {
            'type': action_type,
            'next_page': next_page,
            'delay': delay
        }
    
    def _calculate_realistic_delay(self, action_type: str) -> float:
        """
        Calculate a realistic delay for a user action
        
        Args:
            action_type (str): Type of action
            
        Returns:
            float: Delay in seconds
        """
        if not self.enabled or not self.timing_randomization:
            return 0.0
        
        # Get timing pattern for action type
        pattern = self.timing_patterns.get(action_type, self.timing_patterns['page_view'])
        
        # Generate random delay using normal distribution
        delay = random.normalvariate(pattern['mean'], pattern['std_dev'])
        
        # Ensure delay is within bounds
        delay = max(pattern['min'], min(delay, pattern['max']))
        
        return delay
    
    async def get_next_proxy(self) -> Optional[str]:
        """
        Get the next proxy from the rotation list
        
        Returns:
            Optional[str]: Proxy URL or None if not available
        """
        if not self.enabled or not self.distributed_requests or not self.proxy_list:
            return None
        
        # Rotate through proxy list
        proxy = self.proxy_list[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
        
        return proxy
    
    async def apply_stealth_techniques(self, url: str, session_id: Optional[str] = None) -> Tuple[str, Dict[str, Any], float]:
        """
        Apply stealth techniques to a request
        
        Args:
            url (str): URL to request
            session_id (Optional[str]): Session ID (uses current session if None)
            
        Returns:
            Tuple[str, Dict[str, Any], float]: URL, headers, and delay
        """
        if not self.enabled:
            return url, {}, 0.0
        
        # Get or create session
        if not session_id:
            session_id = self.current_session_id
            if not session_id:
                session_id = await self.create_session()
        
        session = self.get_session(session_id)
        
        # Update session with this request
        await self.update_session(session_id, url)
        
        # Get next action
        next_action = await self.get_next_action(session_id)
        delay = next_action['delay']
        
        # Create headers with session information
        headers = {
            'User-Agent': session['user_agent'],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        
        # Add referrer if available
        if session['history'] and len(session['history']) > 0:
            headers['Referer'] = session['history'][-1]
        elif session['referrer']:
            headers['Referer'] = session['referrer']
        
        logger.debug(f"Applied stealth techniques to request: {url}")
        
        return url, headers, delay
    
    async def make_stealthy_request(self, url: str, session: Optional[aiohttp.ClientSession] = None, session_id: Optional[str] = None, **kwargs) -> Tuple[aiohttp.ClientResponse, Dict[str, Any]]:
        """
        Make a request with stealth techniques
        
        Args:
            url (str): URL to request
            session (Optional[aiohttp.ClientSession]): HTTP client session
            session_id (Optional[str]): Session ID
            **kwargs: Additional arguments for the request
            
        Returns:
            Tuple[aiohttp.ClientResponse, Dict[str, Any]]: Response and session data
        """
        if not self.enabled:
            if session:
                return await session.get(url, **kwargs), {}
            else:
                async with aiohttp.ClientSession() as session:
                    return await session.get(url, **kwargs), {}
        
        # Apply stealth techniques
        stealth_url, headers, delay = await self.apply_stealth_techniques(url, session_id)
        
        # Merge headers with any provided in kwargs
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
        kwargs['headers'] = headers
        
        # Get proxy if distributed requests are enabled
        proxy = await self.get_next_proxy()
        if proxy:
            kwargs['proxy'] = proxy
        
        # Apply delay
        if delay > 0:
            await asyncio.sleep(delay)
        
        # Create session if not provided
        close_session = False
        if session is None:
            session = aiohttp.ClientSession()
            close_session = True
        
        try:
            # Make request
            response = await session.get(stealth_url, **kwargs)
            
            # Update session with cookies from response
            if session_id and session_id in self.sessions:
                cookies = {}
                for cookie in response.cookies.items():
                    cookies[cookie[0]] = cookie[1]
                
                self.sessions[session_id]['cookies'].update(cookies)
            
            return response, self.get_session(session_id)
        finally:
            if close_session:
                await session.close()
    
    def _generate_user_agent(self) -> str:
        """
        Generate a realistic user agent
        
        Returns:
            str: User agent string
        """
        # Common user agents
        user_agents = [
            # Chrome
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
            
            # Firefox
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux i686; rv:89.0) Gecko/20100101 Firefox/89.0',
            
            # Safari
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            
            # Edge
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',
            
            # Opera
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.277'
        ]
        
        return random.choice(user_agents)
    
    def _generate_referrer(self) -> str:
        """
        Generate a realistic referrer
        
        Returns:
            str: Referrer URL
        """
        # Common referrers
        referrers = [
            'https://www.google.com/',
            'https://www.bing.com/',
            'https://www.yahoo.com/',
            'https://www.facebook.com/',
            'https://www.twitter.com/',
            'https://www.linkedin.com/',
            'https://www.reddit.com/',
            'https://www.youtube.com/',
            'https://www.instagram.com/',
            ''  # Empty referrer (direct navigation)
        ]
        
        return random.choice(referrers)
    
    def _generate_viewport(self) -> Dict[str, int]:
        """
        Generate a realistic viewport size
        
        Returns:
            Dict[str, int]: Viewport dimensions
        """
        # Common viewport sizes
        viewports = [
            {'width': 1920, 'height': 1080},  # Full HD
            {'width': 1366, 'height': 768},   # Laptop
            {'width': 1440, 'height': 900},   # MacBook
            {'width': 1536, 'height': 864},   # Common laptop
            {'width': 2560, 'height': 1440},  # QHD
            {'width': 3840, 'height': 2160},  # 4K
            {'width': 375, 'height': 667},    # iPhone
            {'width': 414, 'height': 896},    # iPhone Plus
            {'width': 768, 'height': 1024},   # iPad
            {'width': 360, 'height': 740}     # Android
        ]
        
        return random.choice(viewports)
    
    def _generate_geolocation(self) -> Dict[str, float]:
        """
        Generate a realistic geolocation
        
        Returns:
            Dict[str, float]: Geolocation coordinates
        """
        # Common locations (latitude, longitude)
        locations = [
            {'lat': 40.7128, 'lon': -74.0060},    # New York
            {'lat': 34.0522, 'lon': -118.2437},   # Los Angeles
            {'lat': 51.5074, 'lon': -0.1278},     # London
            {'lat': 48.8566, 'lon': 2.3522},      # Paris
            {'lat': 35.6762, 'lon': 139.6503},    # Tokyo
            {'lat': 37.7749, 'lon': -122.4194},   # San Francisco
            {'lat': 52.5200, 'lon': 13.4050},     # Berlin
            {'lat': 19.4326, 'lon': -99.1332},    # Mexico City
            {'lat': -33.8688, 'lon': 151.2093},   # Sydney
            {'lat': 55.7558, 'lon': 37.6173}      # Moscow
        ]
        
        return random.choice(locations)
    
    def get_stealth_status(self) -> Dict[str, Any]:
        """
        Get the current status of stealth features
        
        Returns:
            Dict[str, Any]: Stealth status
        """
        return {
            'enabled': self.enabled,
            'traffic_mimicking': self.traffic_mimicking,
            'distributed_requests': self.distributed_requests,
            'timing_randomization': self.timing_randomization,
            'session_management': self.session_management,
            'active_sessions': len(self.sessions),
            'current_session': self.current_session_id,
            'proxy_list_size': len(self.proxy_list)
        }
