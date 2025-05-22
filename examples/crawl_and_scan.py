#!/usr/bin/env python3
"""
OpenX Example: Crawl and Scan
This example demonstrates how to use the crawler utility to discover potential redirect URLs
and then scan them with OpenX
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
from utils.crawler import Crawler
from utils.helpers import read_urls_from_file, save_results_to_file

async def main():
    """Main function to demonstrate crawling and scanning with OpenX"""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="OpenX Crawl and Scan Example")
    parser.add_argument("-u", "--url", required=True, help="Base URL to crawl")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Maximum crawl depth")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Maximum concurrent requests")
    parser.add_argument("-o", "--output", help="Output file for scan results")
    parser.add_argument("-f", "--format", default="html", choices=["text", "json", "html"], 
                        help="Output format (text, json, html)")
    parser.add_argument("--browser", action="store_true", help="Enable browser verification")
    parser.add_argument("--temp-file", default="discovered_urls.txt", 
                        help="Temporary file to store discovered URLs")
    args = parser.parse_args()
    
    print(f"[+] Starting crawl of {args.url} with max depth {args.depth}")
    
    # Initialize crawler
    crawler = Crawler(
        base_url=args.url,
        max_depth=args.depth,
        concurrency=args.concurrency,
        timeout=10,
        output_file=args.temp_file
    )
    
    # Start crawling
    discovered_urls = await crawler.crawl()
    
    print(f"[+] Crawling completed. Discovered {len(discovered_urls)} URLs")
    print(f"[+] Found {len(crawler.potential_redirect_urls)} potential redirect URLs")
    print(f"[+] Saved URLs to {args.temp_file}")
    
    # If no URLs were discovered, exit
    if not crawler.potential_redirect_urls:
        print("[!] No potential redirect URLs found. Exiting.")
        return
    
    # Ask user if they want to continue with scanning
    response = input("\nDo you want to scan the discovered URLs for open redirects? (y/n): ")
    if response.lower() != 'y':
        print("[!] Scan aborted by user. Exiting.")
        return
    
    # Load configuration
    config = Config()
    config.load_default_config()
    
    # Configure browser settings if enabled
    if args.browser:
        config.set('browser.enabled', True)
        config.set('browser.headless', True)
    
    # Configure other settings
    config.set('general.verbose', True)
    config.set('performance.concurrency', 5)
    config.set('user_agent.rotation', True)
    
    # Initialize payload manager with target domain from the base URL
    from urllib.parse import urlparse
    base_domain = urlparse(args.url).netloc
    
    payload_manager = PayloadManager(config)
    payload_manager.set_target_domains([base_domain, 'example.com', 'evil.com'])
    
    # Load custom payloads
    custom_payloads_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                        'payloads', 'custom_payloads.txt')
    if os.path.exists(custom_payloads_path):
        payload_manager.load_custom_payloads(custom_payloads_path)
    
    # Initialize scanner
    scanner = Scanner(config, payload_manager)
    
    # Get URLs to scan (only potential redirect URLs)
    urls_to_scan = list(crawler.potential_redirect_urls)
    
    print(f"\n[+] Starting scan with {len(urls_to_scan)} potential redirect URLs")
    print(f"[+] Loaded {len(payload_manager.get_payloads())} payloads")
    
    # Run the scan
    results = await scanner.scan_urls(urls_to_scan)
    
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
    
    # Clean up temporary file if needed
    if os.path.exists(args.temp_file) and args.temp_file.startswith('temp_'):
        os.remove(args.temp_file)
        print(f"[+] Removed temporary file: {args.temp_file}")
    
    # Return the results
    return results, stats

if __name__ == "__main__":
    # Run the main function
    asyncio.run(main())
