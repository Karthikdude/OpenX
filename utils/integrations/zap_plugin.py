#!/usr/bin/env python3
"""
OWASP ZAP Plugin for OpenX
Provides integration with OWASP ZAP for open redirect scanning
"""

import os
import sys
import json
import logging
import tempfile
from typing import Dict, List, Set, Tuple, Any, Optional
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import OpenX modules
from core.scanner import Scanner
from payloads.payload_manager import PayloadManager
from config.config import Config

logger = logging.getLogger('openx.integrations.zap')

class OpenXZapPlugin:
    """
    OWASP ZAP Plugin for OpenX
    
    This plugin integrates OpenX with OWASP ZAP to provide open redirect scanning capabilities.
    It can be used as a standalone script or as a ZAP extension.
    """
    
    def __init__(self):
        """Initialize the ZAP plugin"""
        self.name = "OpenX Open Redirect Scanner"
        self.description = "Scans for open redirect vulnerabilities using OpenX"
        self.author = "Karthik S Sathyan"
        self.version = "2.0"
        
        # Initialize OpenX components
        self.config = Config().load_config()
        self.payload_manager = PayloadManager(self.config)
        self.scanner = Scanner(self.config, self.payload_manager)
        
        # ZAP specific settings
        self.alert_threshold = "MEDIUM"  # LOW, MEDIUM, HIGH
        self.attack_strength = "MEDIUM"  # LOW, MEDIUM, HIGH
        
        # Initialize results
        self.results = []
    
    def scan(self, target_url, context=None, progress_callback=None):
        """
        Scan a target URL for open redirect vulnerabilities
        
        Args:
            target_url (str): URL to scan
            context (dict, optional): Scan context
            progress_callback (callable, optional): Callback for progress updates
            
        Returns:
            list: Scan results
        """
        logger.info(f"Scanning {target_url} for open redirect vulnerabilities")
        
        # Apply context-specific configuration if provided
        if context:
            self._apply_context(context)
        
        # Run scan
        try:
            # Since we can't use asyncio in ZAP, we'll use the synchronous version
            results = self._scan_url(target_url, progress_callback)
            self.results = results
            
            # Convert results to ZAP alerts
            alerts = self._convert_to_alerts(results)
            
            logger.info(f"Scan completed. Found {len(alerts)} alerts.")
            return alerts
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return []
    
    def _scan_url(self, url, progress_callback=None):
        """
        Scan a URL for open redirect vulnerabilities
        
        Args:
            url (str): URL to scan
            progress_callback (callable, optional): Callback for progress updates
            
        Returns:
            list: Scan results
        """
        # Generate payloads
        payloads = self.payload_manager.get_all_payloads()
        results = []
        
        # Track progress
        total_payloads = len(payloads)
        processed = 0
        
        for payload in payloads:
            # Update progress
            if progress_callback:
                progress = int((processed / total_payloads) * 100)
                progress_callback(progress)
            
            # Inject payload
            test_url = self.payload_manager.inject_payload(url, payload)
            
            # Test URL
            result = self._test_url(test_url)
            if result:
                results.append(result)
            
            processed += 1
        
        # Final progress update
        if progress_callback:
            progress_callback(100)
        
        return results
    
    def _test_url(self, url):
        """
        Test a URL for open redirect vulnerabilities
        
        Args:
            url (str): URL to test
            
        Returns:
            dict: Test result or None if not vulnerable
        """
        # This would normally call the scanner's test_url method
        # For ZAP integration, we'll use a synchronous version
        try:
            # Create a session
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            
            session = requests.Session()
            session.verify = False
            
            # Set user agent
            user_agent = self.scanner.get_random_user_agent()
            headers = {'User-Agent': user_agent}
            
            # Send request
            response = session.get(
                url,
                headers=headers,
                allow_redirects=True,
                timeout=self.config.get('timeout', 10)
            )
            
            # Check if vulnerable
            is_vulnerable, severity, details = self.payload_manager.is_vulnerable(
                response.url,
                response.text
            )
            
            if is_vulnerable:
                result = {
                    'url': url,
                    'final_url': response.url,
                    'status_code': response.status_code,
                    'is_vulnerable': True,
                    'severity': severity,
                    'details': details,
                    'content': response.text[:1000]  # Truncate content
                }
                return result
            
            return None
        except Exception as e:
            logger.error(f"Error testing URL {url}: {e}")
            return None
    
    def _apply_context(self, context):
        """
        Apply context-specific configuration
        
        Args:
            context (dict): Scan context
        """
        # Update attack strength
        if 'attack_strength' in context:
            self.attack_strength = context['attack_strength']
            
            # Adjust scanner settings based on attack strength
            if self.attack_strength == "LOW":
                self.config['concurrency'] = 50
                self.config['timeout'] = 5
            elif self.attack_strength == "MEDIUM":
                self.config['concurrency'] = 100
                self.config['timeout'] = 10
            elif self.attack_strength == "HIGH":
                self.config['concurrency'] = 200
                self.config['timeout'] = 15
        
        # Update alert threshold
        if 'alert_threshold' in context:
            self.alert_threshold = context['alert_threshold']
        
        # Update browser settings
        if 'browser' in context:
            if 'browser' not in self.config:
                self.config['browser'] = {}
            self.config['browser']['enabled'] = context['browser']
        
        # Reinitialize scanner with updated config
        self.scanner = Scanner(self.config, self.payload_manager)
    
    def _convert_to_alerts(self, results):
        """
        Convert scan results to ZAP alerts
        
        Args:
            results (list): Scan results
            
        Returns:
            list: ZAP alerts
        """
        alerts = []
        
        for result in results:
            if result.get('is_vulnerable', False):
                alert = {
                    'pluginId': '100001',  # Custom plugin ID for OpenX
                    'name': 'Open Redirect Vulnerability',
                    'description': result.get('details', 'An open redirect vulnerability was detected.'),
                    'risk': self._severity_to_risk(result.get('severity', 'medium')),
                    'confidence': 'Medium',
                    'url': result.get('url', ''),
                    'otherInfo': f"Final URL: {result.get('final_url', '')}",
                    'solution': self.payload_manager.get_remediation_advice(result.get('severity', 'medium')),
                    'reference': 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect',
                    'cweId': '601',  # CWE-601: URL Redirection to Untrusted Site
                    'wascId': '38'   # WASC-38: URL Redirector Abuse
                }
                alerts.append(alert)
        
        return alerts
    
    def _severity_to_risk(self, severity):
        """
        Convert severity to ZAP risk level
        
        Args:
            severity (str): Severity level
            
        Returns:
            str: ZAP risk level
        """
        severity_map = {
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Informational'
        }
        
        return severity_map.get(severity.lower(), 'Medium')
    
    def get_results(self):
        """
        Get the scan results
        
        Returns:
            list: Scan results
        """
        return self.results
    
    def get_config(self):
        """
        Get the current configuration
        
        Returns:
            dict: Configuration
        """
        return self.config
    
    def update_config(self, config):
        """
        Update the configuration
        
        Args:
            config (dict): New configuration
        """
        self.config.update(config)
        
        # Reinitialize components with new config
        self.payload_manager = PayloadManager(self.config)
        self.scanner = Scanner(self.config, self.payload_manager)

# ZAP Python API integration
class OpenXZapExtension:
    """
    ZAP Python API Extension for OpenX
    
    This class is used by ZAP to load the extension.
    """
    
    def __init__(self, zap):
        """
        Initialize the ZAP extension
        
        Args:
            zap: ZAP API client
        """
        self.zap = zap
        self.plugin = OpenXZapPlugin()
        
        # Register as an active scanner
        self.zap.ascan.add_scanner(
            id=100001,
            name=self.plugin.name,
            description=self.plugin.description,
            risk="Medium",
            confidence="Medium",
            attack_strength=self.plugin.attack_strength,
            alert_threshold=self.plugin.alert_threshold
        )
    
    def scan(self, target_url, context_id=None):
        """
        Run a scan using the ZAP API
        
        Args:
            target_url (str): URL to scan
            context_id (int, optional): ZAP context ID
            
        Returns:
            list: Scan results
        """
        # Get context if provided
        context = None
        if context_id:
            context = self.zap.context.context(context_id)
        
        # Run scan
        return self.plugin.scan(target_url, context)

# Standalone usage example
def main():
    """Standalone usage example"""
    import argparse
    
    parser = argparse.ArgumentParser(description="OpenX ZAP Plugin")
    parser.add_argument("-u", "--url", required=True, help="URL to scan")
    parser.add_argument("-b", "--browser", action="store_true", help="Use browser-based detection")
    parser.add_argument("-s", "--strength", choices=["LOW", "MEDIUM", "HIGH"], default="MEDIUM", help="Attack strength")
    parser.add_argument("-o", "--output", help="Output file for results (JSON)")
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create plugin
    plugin = OpenXZapPlugin()
    
    # Set context
    context = {
        'attack_strength': args.strength,
        'browser': args.browser
    }
    
    # Run scan
    print(f"Scanning {args.url} for open redirect vulnerabilities...")
    alerts = plugin.scan(args.url, context, progress_callback=lambda p: print(f"Progress: {p}%"))
    
    # Print results
    if alerts:
        print(f"\nFound {len(alerts)} potential vulnerabilities:")
        for i, alert in enumerate(alerts):
            print(f"\n{i+1}. {alert['name']} ({alert['risk']} risk)")
            print(f"   URL: {alert['url']}")
            print(f"   Description: {alert['description']}")
    else:
        print("\nNo vulnerabilities found.")
    
    # Save results if output file specified
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(alerts, f, indent=2)
        print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    main()
