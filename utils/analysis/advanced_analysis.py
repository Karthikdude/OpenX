#!/usr/bin/env python3
"""
Advanced Analysis Module for OpenX
Implements impact assessment scoring, attack vector generation, and business logic analysis
"""

import os
import re
import json
import logging
import urllib.parse
from typing import Dict, List, Set, Tuple, Any, Optional
from pathlib import Path
import html

logger = logging.getLogger('openx.analysis.advanced')

class AdvancedAnalysis:
    """
    Implements advanced analysis features:
    - Impact assessment scoring (considers page context, user flow)
    - Attack vector generation (automatic PoC creation)
    - Business logic analysis for redirect chains
    - Risk correlation with other vulnerability types
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the advanced analysis module
        
        Args:
            config (Optional[Dict[str, Any]]): Configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        log_level = self.config.get('general', {}).get('verbose', False)
        logger.setLevel(logging.DEBUG if log_level else logging.INFO)
        
        # Analysis settings
        self.impact_assessment = self.config.get('analysis', {}).get('impact_assessment', True)
        self.attack_vector_generation = self.config.get('analysis', {}).get('attack_vector_generation', True)
        self.business_logic_analysis = self.config.get('analysis', {}).get('business_logic_analysis', True)
        self.risk_correlation = self.config.get('analysis', {}).get('risk_correlation', True)
        
        # Initialize analysis components
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize analysis components"""
        # Impact factors
        self.impact_factors = {
            'authentication': {
                'weight': 3.0,
                'description': 'Redirect occurs on authentication-related pages'
            },
            'payment': {
                'weight': 3.5,
                'description': 'Redirect occurs on payment-related pages'
            },
            'personal_data': {
                'weight': 2.5,
                'description': 'Redirect occurs on pages with personal data'
            },
            'admin': {
                'weight': 4.0,
                'description': 'Redirect occurs on admin or privileged pages'
            },
            'high_traffic': {
                'weight': 2.0,
                'description': 'Redirect occurs on high-traffic pages'
            },
            'external_domain': {
                'weight': 2.5,
                'description': 'Redirect points to external domain'
            },
            'no_confirmation': {
                'weight': 1.5,
                'description': 'Redirect occurs without user confirmation'
            },
            'automatic': {
                'weight': 2.0,
                'description': 'Redirect occurs automatically without user interaction'
            }
        }
        
        # Attack vector templates
        self.attack_vector_templates = {
            'html': """
                <html>
                <head>
                    <title>Open Redirect PoC</title>
                </head>
                <body>
                    <h1>Open Redirect Proof of Concept</h1>
                    <p>Click the link below to test the open redirect vulnerability:</p>
                    <a href="{poc_url}" target="_blank">Test Redirect</a>
                    <p>Or use the form:</p>
                    <form action="{form_url}" method="get">
                        <input type="hidden" name="{param}" value="{payload}">
                        <input type="submit" value="Submit Form">
                    </form>
                </body>
                </html>
            """,
            'curl': """
                # Test with curl
                curl -i -s -k -X GET "{poc_url}"
            """,
            'javascript': """
                // JavaScript PoC
                // Add this to the browser console or a JavaScript file
                
                function testRedirect() {
                    window.location = "{poc_url}";
                }
                
                // Alternatively, use fetch
                fetch("{poc_url}", {
                    method: "GET",
                    credentials: "include",
                    redirect: "follow"
                }).then(response => {
                    console.log("Redirect status:", response.redirected);
                    console.log("Final URL:", response.url);
                });
            """,
            'python': """
                # Python PoC
                import requests
                
                url = "{poc_url}"
                response = requests.get(url, allow_redirects=True)
                
                print(f"Initial URL: {url}")
                print(f"Final URL: {response.url}")
                print(f"Status Code: {response.status_code}")
                print(f"Redirect History: {response.history}")
            """
        }
        
        # Business logic patterns
        self.business_logic_patterns = {
            'authentication_flow': [
                r'login', r'signin', r'auth', r'oauth', r'sso'
            ],
            'payment_flow': [
                r'checkout', r'payment', r'transaction', r'billing', r'invoice'
            ],
            'registration_flow': [
                r'register', r'signup', r'join', r'create.+account'
            ],
            'account_management': [
                r'account', r'profile', r'settings', r'preferences'
            ],
            'content_management': [
                r'upload', r'edit', r'delete', r'manage', r'admin'
            ]
        }
        
        # Related vulnerability types
        self.related_vulnerabilities = {
            'xss': {
                'description': 'Cross-Site Scripting',
                'patterns': [
                    r'javascript:', r'data:', r'vbscript:', r'<script', r'onerror=', r'onload='
                ],
                'risk_multiplier': 1.5
            },
            'csrf': {
                'description': 'Cross-Site Request Forgery',
                'patterns': [
                    r'state=', r'csrf=', r'token=', r'auth='
                ],
                'risk_multiplier': 1.3
            },
            'ssrf': {
                'description': 'Server-Side Request Forgery',
                'patterns': [
                    r'localhost', r'127\.0\.0\.1', r'0\.0\.0\.0', r'internal\.'
                ],
                'risk_multiplier': 1.7
            },
            'header_injection': {
                'description': 'HTTP Header Injection',
                'patterns': [
                    r'\r\n', r'%0d%0a', r'%0D%0A', r'%0a', r'%0A'
                ],
                'risk_multiplier': 1.4
            }
        }
    
    def analyze_vulnerability(self, result: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of a vulnerability
        
        Args:
            result (Dict[str, Any]): Vulnerability result
            context (Optional[Dict[str, Any]]): Additional context information
            
        Returns:
            Dict[str, Any]: Analysis results
        """
        analysis = {
            'original_result': result,
            'impact_score': 0.0,
            'impact_factors': [],
            'attack_vectors': {},
            'business_logic': {},
            'related_vulnerabilities': [],
            'recommendations': []
        }
        
        # Perform impact assessment
        if self.impact_assessment:
            impact_score, impact_factors = self._assess_impact(result, context)
            analysis['impact_score'] = impact_score
            analysis['impact_factors'] = impact_factors
            
            # Set impact level based on score
            if impact_score >= 8.0:
                analysis['impact_level'] = 'critical'
            elif impact_score >= 6.0:
                analysis['impact_level'] = 'high'
            elif impact_score >= 4.0:
                analysis['impact_level'] = 'medium'
            elif impact_score >= 2.0:
                analysis['impact_level'] = 'low'
            else:
                analysis['impact_level'] = 'info'
        
        # Generate attack vectors
        if self.attack_vector_generation:
            attack_vectors = self._generate_attack_vectors(result)
            analysis['attack_vectors'] = attack_vectors
        
        # Perform business logic analysis
        if self.business_logic_analysis:
            business_logic = self._analyze_business_logic(result, context)
            analysis['business_logic'] = business_logic
        
        # Identify related vulnerabilities
        if self.risk_correlation:
            related_vulns = self._identify_related_vulnerabilities(result)
            analysis['related_vulnerabilities'] = related_vulns
            
            # Adjust impact score based on related vulnerabilities
            for vuln in related_vulns:
                analysis['impact_score'] *= vuln.get('risk_multiplier', 1.0)
            
            # Cap impact score at 10.0
            analysis['impact_score'] = min(analysis['impact_score'], 10.0)
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        logger.info(f"Completed advanced analysis with impact score: {analysis['impact_score']:.2f}")
        return analysis
    
    def _assess_impact(self, result: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Tuple[float, List[Dict[str, Any]]]:
        """
        Assess the impact of a vulnerability
        
        Args:
            result (Dict[str, Any]): Vulnerability result
            context (Optional[Dict[str, Any]]): Additional context information
            
        Returns:
            Tuple[float, List[Dict[str, Any]]]: Impact score and factors
        """
        impact_score = 0.0
        impact_factors = []
        
        # Get URL and content
        url = result.get('url', '')
        final_url = result.get('final_url', '')
        content = result.get('content', '')
        
        # Check for authentication-related pages
        if re.search(r'login|signin|auth|oauth|sso', url, re.IGNORECASE):
            factor = self.impact_factors['authentication']
            impact_score += factor['weight']
            impact_factors.append({
                'name': 'authentication',
                'weight': factor['weight'],
                'description': factor['description']
            })
        
        # Check for payment-related pages
        if re.search(r'checkout|payment|transaction|billing|invoice', url, re.IGNORECASE):
            factor = self.impact_factors['payment']
            impact_score += factor['weight']
            impact_factors.append({
                'name': 'payment',
                'weight': factor['weight'],
                'description': factor['description']
            })
        
        # Check for pages with personal data
        if re.search(r'account|profile|personal|user|customer', url, re.IGNORECASE):
            factor = self.impact_factors['personal_data']
            impact_score += factor['weight']
            impact_factors.append({
                'name': 'personal_data',
                'weight': factor['weight'],
                'description': factor['description']
            })
        
        # Check for admin or privileged pages
        if re.search(r'admin|manage|dashboard|control|config', url, re.IGNORECASE):
            factor = self.impact_factors['admin']
            impact_score += factor['weight']
            impact_factors.append({
                'name': 'admin',
                'weight': factor['weight'],
                'description': factor['description']
            })
        
        # Check if redirect points to external domain
        if url and final_url:
            url_domain = urllib.parse.urlparse(url).netloc
            final_domain = urllib.parse.urlparse(final_url).netloc
            
            if url_domain != final_domain:
                factor = self.impact_factors['external_domain']
                impact_score += factor['weight']
                impact_factors.append({
                    'name': 'external_domain',
                    'weight': factor['weight'],
                    'description': factor['description']
                })
        
        # Check for automatic redirects
        if content and re.search(r'<meta\s+http-equiv=["\']refresh["\']', content, re.IGNORECASE):
            factor = self.impact_factors['automatic']
            impact_score += factor['weight']
            impact_factors.append({
                'name': 'automatic',
                'weight': factor['weight'],
                'description': factor['description']
            })
        
        # Check for high-traffic pages if context is available
        if context and context.get('page_traffic') == 'high':
            factor = self.impact_factors['high_traffic']
            impact_score += factor['weight']
            impact_factors.append({
                'name': 'high_traffic',
                'weight': factor['weight'],
                'description': factor['description']
            })
        
        # Check for lack of confirmation if context is available
        if context and not context.get('has_confirmation', False):
            factor = self.impact_factors['no_confirmation']
            impact_score += factor['weight']
            impact_factors.append({
                'name': 'no_confirmation',
                'weight': factor['weight'],
                'description': factor['description']
            })
        
        logger.debug(f"Impact assessment score: {impact_score:.2f} with {len(impact_factors)} factors")
        return impact_score, impact_factors
    
    def _generate_attack_vectors(self, result: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate attack vectors (PoC) for the vulnerability
        
        Args:
            result (Dict[str, Any]): Vulnerability result
            
        Returns:
            Dict[str, str]: Attack vectors in different formats
        """
        attack_vectors = {}
        
        # Get URL and payload information
        url = result.get('url', '')
        final_url = result.get('final_url', '')
        payload = result.get('payload', '')
        
        if not url:
            return attack_vectors
        
        # Parse URL to extract parameters
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Find the vulnerable parameter
        vulnerable_param = None
        for param, values in query_params.items():
            if values and payload in values[0]:
                vulnerable_param = param
                break
        
        # If we couldn't identify the vulnerable parameter, use a default
        if not vulnerable_param and query_params:
            vulnerable_param = list(query_params.keys())[0]
        elif not vulnerable_param:
            vulnerable_param = 'url'
        
        # Create base URL without the vulnerable parameter
        base_url_parts = list(parsed_url)
        query_dict = dict(query_params)
        if vulnerable_param in query_dict:
            del query_dict[vulnerable_param]
        
        # Rebuild query string without the vulnerable parameter
        base_url_parts[4] = urllib.parse.urlencode(query_dict, doseq=True)
        base_url = urllib.parse.urlunparse(base_url_parts)
        
        # Add the parameter back with the payload for the PoC URL
        poc_url = f"{base_url}{'&' if '?' in base_url else '?'}{vulnerable_param}={urllib.parse.quote(payload)}"
        
        # Generate HTML PoC
        attack_vectors['html'] = self.attack_vector_templates['html'].format(
            poc_url=html.escape(poc_url),
            form_url=html.escape(base_url),
            param=html.escape(vulnerable_param),
            payload=html.escape(payload)
        )
        
        # Generate curl PoC
        attack_vectors['curl'] = self.attack_vector_templates['curl'].format(
            poc_url=poc_url.replace('"', '\\"')
        )
        
        # Generate JavaScript PoC
        attack_vectors['javascript'] = self.attack_vector_templates['javascript'].format(
            poc_url=poc_url.replace('"', '\\"')
        )
        
        # Generate Python PoC
        attack_vectors['python'] = self.attack_vector_templates['python'].format(
            poc_url=poc_url.replace('"', '\\"')
        )
        
        logger.debug(f"Generated {len(attack_vectors)} attack vectors")
        return attack_vectors
    
    def _analyze_business_logic(self, result: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze business logic implications of the vulnerability
        
        Args:
            result (Dict[str, Any]): Vulnerability result
            context (Optional[Dict[str, Any]]): Additional context information
            
        Returns:
            Dict[str, Any]: Business logic analysis
        """
        business_logic = {
            'flow_type': 'unknown',
            'implications': [],
            'risk_level': 'medium'
        }
        
        # Get URL and content
        url = result.get('url', '')
        content = result.get('content', '')
        
        # Identify the flow type
        for flow_type, patterns in self.business_logic_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    business_logic['flow_type'] = flow_type
                    break
            
            if business_logic['flow_type'] != 'unknown':
                break
        
        # Analyze implications based on flow type
        if business_logic['flow_type'] == 'authentication_flow':
            business_logic['implications'] = [
                'Potential for phishing attacks by redirecting users to fake login pages',
                'Credential theft through redirection to attacker-controlled sites',
                'Session hijacking by redirecting authenticated users',
                'Bypass of authentication flow through unexpected redirects'
            ]
            business_logic['risk_level'] = 'high'
        
        elif business_logic['flow_type'] == 'payment_flow':
            business_logic['implications'] = [
                'Redirection of payment information to attacker-controlled sites',
                'Financial fraud through manipulation of payment flow',
                'Bypass of payment verification steps',
                'Modification of transaction details through redirect manipulation'
            ]
            business_logic['risk_level'] = 'critical'
        
        elif business_logic['flow_type'] == 'registration_flow':
            business_logic['implications'] = [
                'Account takeover through manipulation of registration flow',
                'Creation of accounts with elevated privileges',
                'Bypass of email verification or other registration controls',
                'Identity theft through redirection of registration data'
            ]
            business_logic['risk_level'] = 'high'
        
        elif business_logic['flow_type'] == 'account_management':
            business_logic['implications'] = [
                'Unauthorized changes to account settings',
                'Privacy violations through redirection of personal information',
                'Account takeover through manipulation of account recovery flows',
                'Privilege escalation through redirection in account management'
            ]
            business_logic['risk_level'] = 'high'
        
        elif business_logic['flow_type'] == 'content_management':
            business_logic['implications'] = [
                'Unauthorized content modifications',
                'Data exfiltration through redirection of content',
                'Bypass of content access controls',
                'Injection of malicious content through redirect manipulation'
            ]
            business_logic['risk_level'] = 'medium'
        
        else:
            business_logic['implications'] = [
                'Potential for phishing attacks',
                'Redirection of user traffic to malicious sites',
                'Possible information disclosure through URL parameters',
                'Damage to brand reputation through unexpected redirects'
            ]
            business_logic['risk_level'] = 'medium'
        
        logger.debug(f"Business logic analysis: {business_logic['flow_type']} flow with {len(business_logic['implications'])} implications")
        return business_logic
    
    def _identify_related_vulnerabilities(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Identify related vulnerabilities
        
        Args:
            result (Dict[str, Any]): Vulnerability result
            
        Returns:
            List[Dict[str, Any]]: Related vulnerabilities
        """
        related_vulns = []
        
        # Get URL, payload, and content
        url = result.get('url', '')
        payload = result.get('payload', '')
        content = result.get('content', '')
        
        # Check for each related vulnerability type
        for vuln_type, vuln_info in self.related_vulnerabilities.items():
            for pattern in vuln_info['patterns']:
                # Check in URL
                if re.search(pattern, url, re.IGNORECASE):
                    related_vulns.append({
                        'type': vuln_type,
                        'description': vuln_info['description'],
                        'evidence': f"Pattern '{pattern}' found in URL",
                        'risk_multiplier': vuln_info['risk_multiplier']
                    })
                    break
                
                # Check in payload
                elif payload and re.search(pattern, payload, re.IGNORECASE):
                    related_vulns.append({
                        'type': vuln_type,
                        'description': vuln_info['description'],
                        'evidence': f"Pattern '{pattern}' found in payload",
                        'risk_multiplier': vuln_info['risk_multiplier']
                    })
                    break
                
                # Check in content
                elif content and re.search(pattern, content, re.IGNORECASE):
                    related_vulns.append({
                        'type': vuln_type,
                        'description': vuln_info['description'],
                        'evidence': f"Pattern '{pattern}' found in response content",
                        'risk_multiplier': vuln_info['risk_multiplier']
                    })
                    break
        
        logger.debug(f"Identified {len(related_vulns)} related vulnerabilities")
        return related_vulns
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """
        Generate recommendations based on analysis
        
        Args:
            analysis (Dict[str, Any]): Analysis results
            
        Returns:
            List[str]: Recommendations
        """
        recommendations = []
        
        # Basic recommendations for all open redirects
        recommendations.append("Implement a whitelist of allowed redirect URLs")
        recommendations.append("Use indirect reference maps instead of direct URLs")
        
        # Add recommendations based on impact factors
        for factor in analysis.get('impact_factors', []):
            if factor['name'] == 'authentication':
                recommendations.append("Implement additional authentication checks before redirects on login pages")
                recommendations.append("Use signed redirect tokens for authentication flows")
            
            elif factor['name'] == 'payment':
                recommendations.append("Implement strict validation for redirects in payment flows")
                recommendations.append("Add confirmation steps for redirects in financial transactions")
            
            elif factor['name'] == 'admin':
                recommendations.append("Implement role-based access controls for redirects in admin areas")
                recommendations.append("Log and monitor all redirects in privileged sections")
        
        # Add recommendations based on business logic
        business_logic = analysis.get('business_logic', {})
        flow_type = business_logic.get('flow_type', 'unknown')
        
        if flow_type == 'authentication_flow':
            recommendations.append("Implement multi-factor authentication for sensitive operations")
            recommendations.append("Add anti-phishing measures like site identification")
        
        elif flow_type == 'payment_flow':
            recommendations.append("Implement transaction signing for payment operations")
            recommendations.append("Add fraud detection mechanisms for unusual redirect patterns")
        
        # Add recommendations based on related vulnerabilities
        for vuln in analysis.get('related_vulnerabilities', []):
            if vuln['type'] == 'xss':
                recommendations.append("Implement Content Security Policy (CSP) headers")
                recommendations.append("Sanitize URL parameters to prevent script injection")
            
            elif vuln['type'] == 'csrf':
                recommendations.append("Implement anti-CSRF tokens for all forms and state-changing operations")
            
            elif vuln['type'] == 'ssrf':
                recommendations.append("Implement server-side validation of redirect targets")
                recommendations.append("Use an allowlist of permitted internal resources")
        
        # Remove duplicates while preserving order
        unique_recommendations = []
        for rec in recommendations:
            if rec not in unique_recommendations:
                unique_recommendations.append(rec)
        
        logger.debug(f"Generated {len(unique_recommendations)} recommendations")
        return unique_recommendations
    
    def get_analysis_status(self) -> Dict[str, Any]:
        """
        Get the current status of analysis features
        
        Returns:
            Dict[str, Any]: Analysis status
        """
        return {
            'impact_assessment': self.impact_assessment,
            'attack_vector_generation': self.attack_vector_generation,
            'business_logic_analysis': self.business_logic_analysis,
            'risk_correlation': self.risk_correlation,
            'impact_factors': len(self.impact_factors),
            'business_logic_patterns': {k: len(v) for k, v in self.business_logic_patterns.items()},
            'related_vulnerabilities': list(self.related_vulnerabilities.keys())
        }
