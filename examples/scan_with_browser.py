#!/usr/bin/env python3
"""
OpenX Example: Advanced Scan with Browser Verification
This example demonstrates how to use OpenX with browser-based verification
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

async def main():
    """Main function to demonstrate OpenX with browser verification"""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="OpenX Advanced Scan Example")
    parser.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-l", "--url-list", help="File containing URLs to scan")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-f", "--format", default="html", choices=["text", "json", "html"], 
                        help="Output format (text, json, html)")
    parser.add_argument("--browser-type", default="playwright", choices=["playwright", "selenium"],
                        help="Browser type to use for verification")
    args = parser.parse_args()
    
    if not args.url and not args.url_list:
        parser.error("Either --url or --url-list is required")
    
    # Load configuration
    config = Config()
    config.load_default_config()
    
    # Configure browser settings
    config.set('browser.enabled', True)
    config.set('browser.browser_type', args.browser_type)
    config.set('browser.headless', True)
    
    # Configure other settings
    config.set('general.verbose', True)
    config.set('performance.concurrency', 5)
    config.set('user_agent.rotation', True)
    
    # Initialize payload manager with custom target domains
    payload_manager = PayloadManager(config)
    payload_manager.set_target_domains(['example.com', 'evil.com'])
    
    # Load custom payloads
    custom_payloads_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                        'payloads', 'custom_payloads.txt')
    if os.path.exists(custom_payloads_path):
        payload_manager.load_custom_payloads(custom_payloads_path)
    
    # Initialize scanner
    scanner = Scanner(config, payload_manager)
    
    # Get URLs to scan
    urls = []
    if args.url:
        urls.append(args.url)
    elif args.url_list:
        urls = read_urls_from_file(args.url_list)
    
    # Print scan information
    print(f"Starting scan with {len(urls)} URLs using {args.browser_type} browser")
    print(f"Loaded {len(payload_manager.get_payloads())} payloads")
    
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
