#!/usr/bin/env python3
"""
Enhanced Detection Module for OpenX
Implements advanced detection techniques for various redirect types
"""

import re
import logging
import json
import asyncio
import urllib.parse
from typing import Dict, List, Set, Tuple, Any, Optional
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger('openx.detection.enhanced')

class EnhancedDetector:
    """
    Enhanced detection for various redirect types including:
    - Meta refresh with delays
    - Iframe redirects
    - History.pushState redirects
    - WebSocket redirects
    - POST-based redirects and form submissions
    - Chained redirects (A→B→C scenarios)
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the enhanced detector
        
        Args:
            config (Optional[Dict[str, Any]]): Configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        log_level = self.config.get('general', {}).get('verbose', False)
        logger.setLevel(logging.DEBUG if log_level else logging.INFO)
        
        # Initialize detection patterns
        self._initialize_patterns()
        
        # Tracking for chained redirects
        self.redirect_chains = {}
        self.max_chain_depth = self.config.get('max_chain_depth', 5)
        
        # WebSocket detection
        self.websocket_enabled = self.config.get('websocket_detection', True)
        
        # Form submission detection
        self.form_detection_enabled = self.config.get('form_detection', True)
        
        # History API detection
        self.history_api_detection = self.config.get('history_api_detection', True)
    
    def _initialize_patterns(self):
        """Initialize detection patterns for various redirect types"""
        # Meta refresh patterns with delay extraction
        self.meta_refresh_patterns = [
            r'<meta\s+http-equiv=["\']refresh["\']\s+content=["\'](\d*);?\s*url=([^"\']+)["\']',
            r'<meta\s+http-equiv=["\']refresh["\']\s+content=["\']\d*;?\s*url=([^"\']+)["\']',
            r'<meta\s+content=["\'](\d*);?\s*url=([^"\']+)["\']\s+http-equiv=["\']refresh["\']',
            r'<meta\s+content=["\']\d*;?\s*url=([^"\']+)["\']\s+http-equiv=["\']refresh["\']'
        ]
        
        # Iframe redirect patterns
        self.iframe_patterns = [
            r'<iframe\s+src=["\']([^"\']+)["\']',
            r'<iframe\s+.*?src=["\']([^"\']+)["\']'
        ]
        
        # JavaScript history.pushState patterns
        self.history_patterns = [
            r'history\.pushState\s*\(\s*[^,]*,\s*[^,]*,\s*["\']([^"\']+)["\']',
            r'history\.replaceState\s*\(\s*[^,]*,\s*[^,]*,\s*["\']([^"\']+)["\']'
        ]
        
        # WebSocket redirect patterns
        self.websocket_patterns = [
            r'new\s+WebSocket\s*\(\s*["\']ws[s]?://([^"\']+)["\']',
            r'WebSocket\s*\(\s*["\']ws[s]?://([^"\']+)["\']'
        ]
        
        # Form submission patterns
        self.form_patterns = [
            r'<form\s+action=["\']([^"\']+)["\']',
            r'<form\s+.*?action=["\']([^"\']+)["\']',
            r'<form\s+method=["\']post["\'].*?action=["\']([^"\']+)["\']'
        ]
    
    async def detect_meta_refresh(self, content: str) -> List[Dict[str, Any]]:
        """
        Detect meta refresh redirects including those with delays
        
        Args:
            content (str): HTML content to analyze
            
        Returns:
            List[Dict[str, Any]]: List of detected meta refresh redirects with details
        """
        results = []
        
        for pattern in self.meta_refresh_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple) and len(match) == 2:
                    delay, url = match
                    try:
                        delay = int(delay)
                    except (ValueError, TypeError):
                        delay = 0
                else:
                    url = match
                    delay = 0
                
                results.append({
                    'type': 'meta_refresh',
                    'url': url,
                    'delay': delay
                })
        
        logger.debug(f"Detected {len(results)} meta refresh redirects")
        return results
    
    async def detect_iframe_redirects(self, content: str) -> List[Dict[str, Any]]:
        """
        Detect iframe-based redirects
        
        Args:
            content (str): HTML content to analyze
            
        Returns:
            List[Dict[str, Any]]: List of detected iframe redirects
        """
        results = []
        
        for pattern in self.iframe_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for url in matches:
                results.append({
                    'type': 'iframe',
                    'url': url
                })
        
        logger.debug(f"Detected {len(results)} iframe redirects")
        return results
    
    async def detect_history_redirects(self, content: str) -> List[Dict[str, Any]]:
        """
        Detect history.pushState/replaceState redirects
        
        Args:
            content (str): HTML/JavaScript content to analyze
            
        Returns:
            List[Dict[str, Any]]: List of detected history API redirects
        """
        if not self.history_api_detection:
            return []
            
        results = []
        
        for pattern in self.history_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for url in matches:
                results.append({
                    'type': 'history_api',
                    'url': url
                })
        
        logger.debug(f"Detected {len(results)} history API redirects")
        return results
    
    async def detect_websocket_redirects(self, content: str) -> List[Dict[str, Any]]:
        """
        Detect WebSocket-based redirects
        
        Args:
            content (str): HTML/JavaScript content to analyze
            
        Returns:
            List[Dict[str, Any]]: List of detected WebSocket redirects
        """
        if not self.websocket_enabled:
            return []
            
        results = []
        
        for pattern in self.websocket_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for url in matches:
                results.append({
                    'type': 'websocket',
                    'url': f"ws://{url}"
                })
        
        logger.debug(f"Detected {len(results)} WebSocket redirects")
        return results
    
    async def detect_form_redirects(self, content: str) -> List[Dict[str, Any]]:
        """
        Detect form-based redirects and submissions
        
        Args:
            content (str): HTML content to analyze
            
        Returns:
            List[Dict[str, Any]]: List of detected form redirects
        """
        if not self.form_detection_enabled:
            return []
            
        results = []
        
        for pattern in self.form_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for url in matches:
                # Check if it's a POST form
                is_post = False
                if re.search(r'method=["\']post["\']', content, re.IGNORECASE):
                    is_post = True
                
                results.append({
                    'type': 'form',
                    'url': url,
                    'method': 'POST' if is_post else 'GET'
                })
        
        logger.debug(f"Detected {len(results)} form redirects")
        return results
    
    async def track_redirect_chain(self, session_id: str, url: str, final_url: str):
        """
        Track a redirect chain for a given session
        
        Args:
            session_id (str): Unique session identifier
            url (str): Original URL
            final_url (str): Final URL after redirect
        """
        if session_id not in self.redirect_chains:
            self.redirect_chains[session_id] = []
        
        # Add to chain if it's not already the last URL
        chain = self.redirect_chains[session_id]
        if not chain or chain[-1] != final_url:
            if not chain:
                chain.append(url)
            chain.append(final_url)
            
            # Limit chain depth
            if len(chain) > self.max_chain_depth:
                chain.pop(0)
            
            logger.debug(f"Redirect chain for session {session_id}: {' -> '.join(chain)}")
    
    async def get_redirect_chain(self, session_id: str) -> List[str]:
        """
        Get the redirect chain for a session
        
        Args:
            session_id (str): Session identifier
            
        Returns:
            List[str]: List of URLs in the redirect chain
        """
        return self.redirect_chains.get(session_id, [])
    
    async def detect_all_redirects(self, content: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Detect all types of redirects in the content
        
        Args:
            content (str): HTML/JavaScript content to analyze
            
        Returns:
            Dict[str, List[Dict[str, Any]]]: Dictionary of detected redirects by type
        """
        results = {
            'meta_refresh': await self.detect_meta_refresh(content),
            'iframe': await self.detect_iframe_redirects(content),
            'history_api': await self.detect_history_redirects(content),
            'websocket': await self.detect_websocket_redirects(content),
            'form': await self.detect_form_redirects(content)
        }
        
        total_redirects = sum(len(redirects) for redirects in results.values())
        logger.info(f"Detected {total_redirects} total redirects across all types")
        
        return results
