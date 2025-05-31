"""
OpenX URL Analyzer
Intelligent URL analysis for optimized payload selection
"""

import re
import urllib.parse
from typing import List, Dict, Set, Tuple

class URLAnalyzer:
    """Analyzes URLs to determine optimal payload strategies"""
    
    def __init__(self):
        self.parameter_patterns = {
            'direct_redirect': {
                'patterns': [r'\b(redirect|url|location|goto|next|return|target|dest|destination|forward|continue)\b'],
                'payloads': ['external_urls', 'protocol_relative', 'javascript', 'data_uri'],
                'priority': 1
            },
            'callback_patterns': {
                'patterns': [r'\b(callback|cb|jsonp|success|failure|error|complete)\b'],
                'payloads': ['external_urls', 'javascript', 'data_uri'],
                'priority': 2
            },
            'oauth_patterns': {
                'patterns': [r'\b(state|redirect_uri|return_to|success_url|failure_url)\b'],
                'payloads': ['external_urls', 'protocol_relative', 'bypass_techniques'],
                'priority': 1
            },
            'encoded_patterns': {
                'patterns': [r'\b(b64|base64|encoded|enc|decode)\b'],
                'payloads': ['encoded_payloads', 'double_encoded'],
                'priority': 2
            },
            'host_patterns': {
                'patterns': [r'\b(host|domain|origin|referer|referrer)\b'],
                'payloads': ['host_manipulation', 'subdomain_bypass'],
                'priority': 3
            }
        }
        
        self.payload_categories = {
            'external_urls': [
                'http://evil.com',
                'https://evil.com',
                'http://attacker.com',
                'https://attacker.com'
            ],
            'protocol_relative': [
                '//evil.com',
                '///evil.com',
                '\\\\evil.com'
            ],
            'javascript': [
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>'
            ],
            'data_uri': [
                'data:text/html,<h1>XSS</h1>',
                'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='
            ],
            'encoded_payloads': [
                'http%3A//evil.com',
                'http%3A%2F%2Fevil.com',
                '%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%63%6f%6d'
            ],
            'double_encoded': [
                'http%253A//evil.com',
                'http%253A%252F%252Fevil.com'
            ],
            'bypass_techniques': [
                'http://evil.com#.example.com',
                'http://evil.com?.example.com',
                'http://example.com@evil.com',
                'http://example.com:80@evil.com'
            ],
            'host_manipulation': [
                'evil.com',
                'http://192.168.1.1',
                'http://127.0.0.1'
            ],
            'subdomain_bypass': [
                'http://evil.com.example.com',
                'http://example.evil.com'
            ],
            'whitespace_bypass': [
                ' http://evil.com',
                'http://evil.com ',
                '\thttp://evil.com',
                'http://evil.com%20',
                'http://evil.com%09'
            ],
            'crlf_injection': [
                'http://evil.com%0d%0aLocation:http://attacker.com',
                'http://evil.com%0aLocation:http://attacker.com',
                'http://evil.com\r\nLocation:http://attacker.com'
            ]
        }

    def analyze_url(self, url: str) -> Dict:
        """Analyze URL to determine optimal testing strategy"""
        parsed = urllib.parse.urlparse(url)
        analysis = {
            'url': url,
            'parameters': [],
            'suggested_payloads': [],
            'detection_hints': [],
            'priority_parameters': [],
            'estimated_requests': 0
        }
        
        # Analyze query parameters
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query)
            for param_name in params.keys():
                param_analysis = self._analyze_parameter(param_name, params[param_name])
                analysis['parameters'].append(param_analysis)
        
        # Analyze path for potential parameters
        path_params = self._extract_path_parameters(parsed.path)
        for param in path_params:
            param_analysis = self._analyze_parameter(param, [''])
            analysis['parameters'].append(param_analysis)
        
        # Sort parameters by priority
        analysis['parameters'].sort(key=lambda x: x['priority'])
        analysis['priority_parameters'] = [p for p in analysis['parameters'] if p['priority'] <= 2]
        
        # Generate suggested payload strategy
        analysis['suggested_payloads'] = self._generate_payload_strategy(analysis['parameters'])
        analysis['estimated_requests'] = self._estimate_requests(analysis['suggested_payloads'])
        
        return analysis

    def _analyze_parameter(self, param_name: str, param_values: List[str]) -> Dict:
        """Analyze individual parameter for redirect potential"""
        param_lower = param_name.lower()
        
        param_info = {
            'name': param_name,
            'values': param_values,
            'priority': 5,  # Default low priority
            'matched_patterns': [],
            'suggested_payloads': [],
            'detection_type': 'generic'
        }
        
        # Check against known patterns
        for pattern_type, pattern_info in self.parameter_patterns.items():
            for pattern in pattern_info['patterns']:
                if re.search(pattern, param_lower, re.IGNORECASE):
                    param_info['matched_patterns'].append(pattern_type)
                    param_info['priority'] = min(param_info['priority'], pattern_info['priority'])
                    param_info['suggested_payloads'].extend(pattern_info['payloads'])
                    param_info['detection_type'] = pattern_type
        
        # Remove duplicates
        param_info['suggested_payloads'] = list(set(param_info['suggested_payloads']))
        
        return param_info

    def _extract_path_parameters(self, path: str) -> List[str]:
        """Extract potential parameter names from URL path"""
        # Look for common redirect parameter patterns in path
        redirect_indicators = [
            'redirect', 'goto', 'forward', 'next', 'return',
            'callback', 'success', 'failure', 'continue'
        ]
        
        found_params = []
        path_lower = path.lower()
        
        for indicator in redirect_indicators:
            if indicator in path_lower:
                found_params.append(indicator)
        
        return found_params

    def _generate_payload_strategy(self, parameters: List[Dict]) -> List[str]:
        """Generate optimized payload strategy based on parameter analysis"""
        all_payload_categories = set()
        
        # Collect all suggested payload categories from high-priority parameters
        for param in parameters:
            if param['priority'] <= 3:  # Focus on high and medium priority
                all_payload_categories.update(param['suggested_payloads'])
        
        # If no specific patterns found, use basic strategy
        if not all_payload_categories:
            all_payload_categories = ['external_urls', 'protocol_relative']
        
        # Generate ordered payload list
        ordered_payloads = []
        
        # Priority order for payload categories
        priority_order = [
            'external_urls', 'protocol_relative', 'javascript',
            'bypass_techniques', 'encoded_payloads', 'crlf_injection',
            'whitespace_bypass', 'data_uri', 'double_encoded'
        ]
        
        for category in priority_order:
            if category in all_payload_categories:
                ordered_payloads.extend(self.payload_categories[category])
        
        return ordered_payloads

    def _estimate_requests(self, payloads: List[str]) -> int:
        """Estimate number of requests needed for testing"""
        # Base requests for parameter testing
        base_requests = len(payloads)
        
        # Add form testing requests
        form_requests = 15
        
        # Add cookie testing requests  
        cookie_requests = 15
        
        # Add header testing requests
        header_requests = 13
        
        return base_requests + form_requests + cookie_requests + header_requests

    def get_smart_payloads(self, url: str, max_payloads: int = None) -> Tuple[List[str], Dict]:
        """Get smart payload selection for a URL"""
        analysis = self.analyze_url(url)
        payloads = analysis['suggested_payloads']
        
        if max_payloads is not None and len(payloads) > max_payloads:
            # Keep the most effective payloads
            payloads = payloads[:max_payloads]
        
        return payloads, analysis

    def should_test_parameter(self, param_name: str) -> bool:
        """Determine if a parameter should be tested based on name analysis"""
        param_lower = param_name.lower()
        
        # High-value parameters that should always be tested
        high_value_patterns = [
            r'\b(redirect|url|location|goto|next|return|target|dest|destination)\b',
            r'\b(forward|continue|callback|state|redirect_uri)\b',
            r'\b(success|failure|error|complete|return_to)\b'
        ]
        
        for pattern in high_value_patterns:
            if re.search(pattern, param_lower):
                return True
        
        return False

    def get_vulnerability_likelihood(self, url: str) -> Dict:
        """Assess likelihood of vulnerability based on URL structure"""
        analysis = self.analyze_url(url)
        
        likelihood = {
            'score': 0,
            'factors': [],
            'recommendation': 'standard'
        }
        
        # Score based on parameter analysis
        high_priority_params = len([p for p in analysis['parameters'] if p['priority'] <= 2])
        medium_priority_params = len([p for p in analysis['parameters'] if p['priority'] == 3])
        
        likelihood['score'] += high_priority_params * 3
        likelihood['score'] += medium_priority_params * 1
        
        if high_priority_params > 0:
            likelihood['factors'].append('High-priority redirect parameters detected')
            likelihood['recommendation'] = 'intensive'
        
        if 'oauth' in url.lower() or 'auth' in url.lower():
            likelihood['score'] += 2
            likelihood['factors'].append('Authentication-related endpoint')
        
        if 'callback' in url.lower():
            likelihood['score'] += 2
            likelihood['factors'].append('Callback endpoint detected')
        
        # Determine recommendation
        if likelihood['score'] >= 5:
            likelihood['recommendation'] = 'intensive'
        elif likelihood['score'] >= 2:
            likelihood['recommendation'] = 'moderate'
        else:
            likelihood['recommendation'] = 'basic'
        
        return likelihood