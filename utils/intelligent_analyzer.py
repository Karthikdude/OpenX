#!/usr/bin/env python3
"""
Intelligent Analysis Module for OpenX
Provides rule-based scoring heuristics to analyze and prioritize URLs
for open redirect vulnerability testing.
"""

import re
import logging
import base64
import urllib.parse
from typing import Dict, List, Set, Tuple, Any, Optional
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger('openx.intelligent_analyzer')

class IntelligentAnalyzer:
    """
    Intelligent URL analyzer that uses rule-based scoring heuristics
    to identify and prioritize potentially vulnerable URLs
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the intelligent analyzer
        
        Args:
            config (Optional[Dict[str, Any]]): Configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        log_level = self.config.get('general', {}).get('verbose', False)
        logger.setLevel(logging.DEBUG if log_level else logging.INFO)
        
        # Initialize scoring rules
        self.rules = self._initialize_rules()
        
        # Blacklisted domains (commonly used in open redirect attacks)
        self.blacklisted_domains = {
            'evil.com', 'attacker.com', 'malicious.com', 'hacker.com', 
            'example.com', 'test.com', 'localhost', '127.0.0.1',
            'malware.com', 'phishing.com', 'xss.com', 'csrf.com'
        }
        
        # Risk categories based on score
        self.risk_categories = {
            'high': 8,    # Score >= 8
            'medium': 5,  # Score >= 5 and < 8
            'low': 3,     # Score >= 3 and < 5
            'info': 0     # Score < 3
        }
    
    def _initialize_rules(self) -> List[Dict[str, Any]]:
        """
        Initialize the scoring rules for URL analysis
        
        Returns:
            List[Dict[str, Any]]: List of rule dictionaries
        """
        return [
            # Rule 1: URLs with common redirect parameters
            {
                'name': 'common_redirect_params',
                'description': 'URL contains common redirect parameters',
                'score': 3,
                'check': self._check_redirect_params,
                'params': {
                    'keywords': [
                        'url', 'redirect', 'next', 'goto', 'target', 'destination',
                        'return', 'returnto', 'return_to', 'returnurl', 'return_url',
                        'continue', 'forward', 'forward_url', 'location', 'redirect_to',
                        'redirect_uri', 'redirecturl', 'redirect_url', 'u', 'uri', 'path',
                        'r', 'ref', 'q', 'to', 'out', 'view', 'dir'
                    ]
                }
            },
            
            # Rule 2: Parameter values starting with http:// or https://
            {
                'name': 'url_in_param_value',
                'description': 'Parameter value starts with http:// or https://',
                'score': 4,
                'check': self._check_url_in_param_value,
                'params': {}
            },
            
            # Rule 3: Parameter values starting with //
            {
                'name': 'protocol_relative_url',
                'description': 'Parameter value starts with // (protocol-relative URL)',
                'score': 4,
                'check': self._check_protocol_relative_url,
                'params': {}
            },
            
            # Rule 4: Parameter values containing blacklisted domains
            {
                'name': 'blacklisted_domain',
                'description': 'Parameter value contains blacklisted domain',
                'score': 5,
                'check': self._check_blacklisted_domain,
                'params': {}
            },
            
            # Rule 5: Parameter values containing encoded characters
            {
                'name': 'encoded_characters',
                'description': 'Parameter value contains URL-encoded characters',
                'score': 2,
                'check': self._check_encoded_characters,
                'params': {}
            },
            
            # Rule 6: Parameter values containing base64-encoded content
            {
                'name': 'base64_encoded',
                'description': 'Parameter value contains possible base64-encoded content',
                'score': 3,
                'check': self._check_base64_encoded,
                'params': {}
            },
            
            # Rule 7: URLs with multiple redirect parameters
            {
                'name': 'multiple_redirect_params',
                'description': 'URL contains multiple redirect parameters',
                'score': 3,
                'check': self._check_multiple_redirect_params,
                'params': {
                    'keywords': [
                        'url', 'redirect', 'next', 'goto', 'target', 'destination',
                        'return', 'returnto', 'return_to', 'returnurl', 'return_url',
                        'continue', 'forward', 'forward_url', 'location', 'redirect_to',
                        'redirect_uri', 'redirecturl', 'redirect_url', 'u', 'uri', 'path',
                        'r', 'ref', 'q', 'to', 'out', 'view', 'dir'
                    ]
                }
            },
            
            # Rule 8: Parameter values containing path traversal sequences
            {
                'name': 'path_traversal',
                'description': 'Parameter value contains path traversal sequences',
                'score': 4,
                'check': self._check_path_traversal,
                'params': {}
            },
            
            # Rule 9: Parameter values containing JavaScript protocol
            {
                'name': 'javascript_protocol',
                'description': 'Parameter value contains JavaScript protocol',
                'score': 5,
                'check': self._check_javascript_protocol,
                'params': {}
            },
            
            # Rule 10: Parameter values containing data URI scheme
            {
                'name': 'data_uri',
                'description': 'Parameter value contains data URI scheme',
                'score': 4,
                'check': self._check_data_uri,
                'params': {}
            }
        ]
    
    def _check_redirect_params(self, url: str, rule: Dict[str, Any]) -> bool:
        """
        Check if URL contains common redirect parameters
        
        Args:
            url (str): URL to check
            rule (Dict[str, Any]): Rule dictionary
            
        Returns:
            bool: True if the rule matches, False otherwise
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        keywords = rule['params']['keywords']
        
        for param in query_params:
            if param.lower() in keywords:
                return True
        
        return False
    
    def _check_url_in_param_value(self, url: str, rule: Dict[str, Any]) -> bool:
        """
        Check if any parameter value starts with http:// or https://
        
        Args:
            url (str): URL to check
            rule (Dict[str, Any]): Rule dictionary
            
        Returns:
            bool: True if the rule matches, False otherwise
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param, values in query_params.items():
            for value in values:
                if value.lower().startswith(('http://', 'https://')):
                    return True
        
        return False
    
    def _check_protocol_relative_url(self, url: str, rule: Dict[str, Any]) -> bool:
        """
        Check if any parameter value starts with // (protocol-relative URL)
        
        Args:
            url (str): URL to check
            rule (Dict[str, Any]): Rule dictionary
            
        Returns:
            bool: True if the rule matches, False otherwise
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param, values in query_params.items():
            for value in values:
                if value.startswith('//'):
                    return True
        
        return False
    
    def _check_blacklisted_domain(self, url: str, rule: Dict[str, Any]) -> bool:
        """
        Check if any parameter value contains a blacklisted domain
        
        Args:
            url (str): URL to check
            rule (Dict[str, Any]): Rule dictionary
            
        Returns:
            bool: True if the rule matches, False otherwise
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param, values in query_params.items():
            for value in values:
                try:
                    # Try to parse the value as a URL
                    value_parsed = urlparse(value)
                    if value_parsed.netloc:
                        domain = value_parsed.netloc.lower()
                        
                        # Check if domain or any part of it is blacklisted
                        if domain in self.blacklisted_domains:
                            return True
                        
                        # Check domain parts (e.g., evil.example.com)
                        domain_parts = domain.split('.')
                        for part in domain_parts:
                            if part in self.blacklisted_domains:
                                return True
                except:
                    # If parsing fails, check if value contains any blacklisted domain
                    for domain in self.blacklisted_domains:
                        if domain in value.lower():
                            return True
        
        return False
    
    def _check_encoded_characters(self, url: str, rule: Dict[str, Any]) -> bool:
        """
        Check if any parameter value contains URL-encoded characters
        
        Args:
            url (str): URL to check
            rule (Dict[str, Any]): Rule dictionary
            
        Returns:
            bool: True if the rule matches, False otherwise
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param, values in query_params.items():
            for value in values:
                # Check for URL encoding patterns (%xx)
                if re.search(r'%[0-9A-Fa-f]{2}', value):
                    return True
        
        return False
    
    def _check_base64_encoded(self, url: str, rule: Dict[str, Any]) -> bool:
        """
        Check if any parameter value contains possible base64-encoded content
        
        Args:
            url (str): URL to check
            rule (Dict[str, Any]): Rule dictionary
            
        Returns:
            bool: True if the rule matches, False otherwise
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Regular expression for base64-encoded strings
        base64_pattern = r'^[A-Za-z0-9+/]+={0,2}$'
        
        for param, values in query_params.items():
            for value in values:
                # Only check values that are at least 16 characters long
                if len(value) >= 16:
                    # Try to decode if it matches the base64 pattern
                    if re.match(base64_pattern, value):
                        try:
                            # Try to decode and check if it contains http:// or https://
                            decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
                            if 'http://' in decoded or 'https://' in decoded or '//' in decoded:
                                return True
                        except:
                            pass
        
        return False
    
    def _check_multiple_redirect_params(self, url: str, rule: Dict[str, Any]) -> bool:
        """
        Check if URL contains multiple redirect parameters
        
        Args:
            url (str): URL to check
            rule (Dict[str, Any]): Rule dictionary
            
        Returns:
            bool: True if the rule matches, False otherwise
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        keywords = rule['params']['keywords']
        
        redirect_params_count = 0
        for param in query_params:
            if param.lower() in keywords:
                redirect_params_count += 1
                if redirect_params_count >= 2:
                    return True
        
        return False
    
    def _check_path_traversal(self, url: str, rule: Dict[str, Any]) -> bool:
        """
        Check if any parameter value contains path traversal sequences
        
        Args:
            url (str): URL to check
            rule (Dict[str, Any]): Rule dictionary
            
        Returns:
            bool: True if the rule matches, False otherwise
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param, values in query_params.items():
            for value in values:
                if '../' in value or '..\\' in value:
                    return True
        
        return False
    
    def _check_javascript_protocol(self, url: str, rule: Dict[str, Any]) -> bool:
        """
        Check if any parameter value contains JavaScript protocol
        
        Args:
            url (str): URL to check
            rule (Dict[str, Any]): Rule dictionary
            
        Returns:
            bool: True if the rule matches, False otherwise
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param, values in query_params.items():
            for value in values:
                if value.lower().startswith('javascript:'):
                    return True
        
        return False
    
    def _check_data_uri(self, url: str, rule: Dict[str, Any]) -> bool:
        """
        Check if any parameter value contains data URI scheme
        
        Args:
            url (str): URL to check
            rule (Dict[str, Any]): Rule dictionary
            
        Returns:
            bool: True if the rule matches, False otherwise
        """
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param, values in query_params.items():
            for value in values:
                if value.lower().startswith('data:'):
                    return True
        
        return False
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a URL using rule-based scoring heuristics
        
        Args:
            url (str): URL to analyze
            
        Returns:
            Dict[str, Any]: Analysis result with score, risk level, and matched rules
        """
        score = 0
        matched_rules = []
        
        for rule in self.rules:
            if rule['check'](url, rule):
                score += rule['score']
                matched_rules.append({
                    'name': rule['name'],
                    'description': rule['description'],
                    'score': rule['score']
                })
        
        # Determine risk level based on score
        risk_level = 'info'
        for level, threshold in sorted(self.risk_categories.items(), key=lambda x: x[1], reverse=True):
            if score >= threshold:
                risk_level = level
                break
        
        return {
            'url': url,
            'score': score,
            'risk_level': risk_level,
            'matched_rules': matched_rules
        }
    
    def analyze_urls(self, urls: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Analyze multiple URLs and categorize them by risk level
        
        Args:
            urls (List[str]): List of URLs to analyze
            
        Returns:
            Dict[str, List[Dict[str, Any]]]: URLs categorized by risk level
        """
        results = {
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for url in urls:
            analysis = self.analyze_url(url)
            results[analysis['risk_level']].append(analysis)
        
        # Sort each category by score (highest first)
        for level in results:
            results[level] = sorted(results[level], key=lambda x: x['score'], reverse=True)
        
        logger.info(f"Analyzed {len(urls)} URLs: {len(results['high'])} high, {len(results['medium'])} medium, {len(results['low'])} low, {len(results['info'])} info")
        
        return results
    
    def get_prioritized_urls(self, urls: List[str]) -> List[str]:
        """
        Get URLs prioritized by risk level
        
        Args:
            urls (List[str]): List of URLs to analyze and prioritize
            
        Returns:
            List[str]: Prioritized list of URLs
        """
        analysis_results = self.analyze_urls(urls)
        
        # Combine results in order of priority (high -> medium -> low -> info)
        prioritized_urls = []
        
        for level in ['high', 'medium', 'low', 'info']:
            level_urls = [result['url'] for result in analysis_results[level]]
            prioritized_urls.extend(level_urls)
        
        return prioritized_urls


# Example usage
def main():
    """Example usage of IntelligentAnalyzer"""
    import argparse
    
    parser = argparse.ArgumentParser(description="OpenX Intelligent URL Analyzer")
    parser.add_argument("-u", "--url", help="Single URL to analyze")
    parser.add_argument("-l", "--url-file", help="File containing URLs to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize analyzer
    config = {
        'general': {
            'verbose': args.verbose
        }
    }
    
    analyzer = IntelligentAnalyzer(config)
    
    # Analyze URLs
    urls = []
    
    if args.url:
        urls.append(args.url)
    elif args.url_file:
        with open(args.url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        # Example URLs for testing
        urls = [
            "https://example.com/redirect?url=https://evil.com",
            "https://example.com/goto?next=//attacker.com",
            "https://example.com/login?returnUrl=https%3A%2F%2Fevil.com",
            "https://example.com/page?param=value",
            "https://example.com/redirect?url=javascript:alert(1)",
            "https://example.com/path?data=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
        ]
    
    # Analyze and print results
    for url in urls:
        result = analyzer.analyze_url(url)
        print(f"\nURL: {result['url']}")
        print(f"Score: {result['score']}")
        print(f"Risk Level: {result['risk_level'].upper()}")
        
        if result['matched_rules']:
            print("Matched Rules:")
            for rule in result['matched_rules']:
                print(f"  - {rule['description']} (+{rule['score']})")
    
    # Get prioritized URLs
    prioritized_urls = analyzer.get_prioritized_urls(urls)
    
    print("\nPrioritized URLs:")
    for i, url in enumerate(prioritized_urls):
        print(f"{i+1}. {url}")

if __name__ == "__main__":
    main()
