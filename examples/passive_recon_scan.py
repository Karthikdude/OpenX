#!/usr/bin/env python3
"""
OpenX Example: Passive Reconnaissance and Scanning
This example demonstrates how to use external tools integration for passive URL collection,
filtering, and HTTP probing before scanning for open redirect vulnerabilities
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
from utils.external_tools import ExternalToolManager
from utils.helpers import read_urls_from_file, save_results_to_file

async def main():
    """Main function to demonstrate passive reconnaissance and scanning with OpenX"""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="OpenX Passive Reconnaissance and Scanning Example")
    parser.add_argument("-d", "--domain", required=True, help="Target domain for passive URL collection")
    parser.add_argument("-o", "--output", help="Output file for scan results")
    parser.add_argument("-f", "--format", default="html", choices=["text", "json", "html"], 
                        help="Output format (text, json, html)")
    parser.add_argument("--browser", action="store_true", help="Enable browser verification")
    parser.add_argument("--skip-collection", action="store_true", help="Skip URL collection phase")
    parser.add_argument("--skip-filtering", action="store_true", help="Skip URL filtering phase")
    parser.add_argument("--skip-probing", action="store_true", help="Skip HTTP probing phase")
    parser.add_argument("--collected-urls-output", help="Output file for collected URLs")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Load configuration
    config = Config()
    config.load_default_config()
    
    # Configure settings
    config.set('general.verbose', args.verbose)
    config.set('performance.concurrency', 5)
    config.set('user_agent.rotation', True)
    
    if args.browser:
        config.set('browser.enabled', True)
        config.set('browser.headless', True)
    
    print(f"[+] Starting passive reconnaissance for domain: {args.domain}")
    
    # Initialize external tool manager
    tool_manager = ExternalToolManager(config.get_config())
    
    # Print available tools
    print("\nAvailable external tools:")
    for tool, available in tool_manager.available_tools.items():
        status = "✅ Available" if available else "❌ Not available"
        print(f"  - {tool}: {status}")
    
    # Process domain through the external tools pipeline
    urls_to_scan = []
    
    # Step 1: Collect URLs (if not skipped)
    if not args.skip_collection:
        print(f"\n[+] Collecting URLs for domain: {args.domain}")
        collected_urls = await tool_manager.collect_urls(args.domain)
        print(f"[+] Collected {len(collected_urls)} URLs")
    else:
        print("\n[+] Skipping URL collection phase")
        collected_urls = set()
    
    # Step 2: Filter URLs (if not skipped)
    if not args.skip_filtering and collected_urls:
        print("\n[+] Filtering URLs for potential redirect patterns")
        filtered_urls = tool_manager.filter_redirect_urls(collected_urls)
        print(f"[+] Filtered {len(filtered_urls)} potential redirect URLs")
    else:
        print("\n[+] Skipping URL filtering phase")
        filtered_urls = collected_urls
    
    # Step 3: Probe URLs (if not skipped)
    if not args.skip_probing and filtered_urls:
        print("\n[+] Probing URLs to check if they are live")
        live_urls = await tool_manager.probe_live_urls(filtered_urls)
        print(f"[+] Found {len(live_urls)} live URLs")
    else:
        print("\n[+] Skipping HTTP probing phase")
        live_urls = filtered_urls
    
    # Save collected URLs to file if specified
    if args.collected_urls_output and live_urls:
        with open(args.collected_urls_output, 'w') as f:
            for url in live_urls:
                f.write(f"{url}\n")
        print(f"\n[+] Saved {len(live_urls)} URLs to {args.collected_urls_output}")
    
    # Use collected URLs for scanning
    urls_to_scan = list(live_urls)
    
    # Check if we have URLs to scan
    if not urls_to_scan:
        print("\n[!] No URLs to scan. Exiting.")
        return
    
    # Ask user if they want to continue with scanning
    response = input("\nDo you want to scan the discovered URLs for open redirects? (y/n): ")
    if response.lower() != 'y':
        print("[!] Scan aborted by user. Exiting.")
        return
    
    # Initialize payload manager
    payload_manager = PayloadManager(config)
    
    # Add target domain for validation
    from urllib.parse import urlparse
    domain_parts = urlparse(args.domain).netloc.split('.')
    if len(domain_parts) >= 2:
        base_domain = '.'.join(domain_parts[-2:])
        payload_manager.add_target_domain(base_domain)
        payload_manager.add_target_domain('evil.com')  # Common target for testing
    
    # Load custom payloads
    custom_payloads_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                       'payloads', 'custom_payloads.txt')
    if os.path.exists(custom_payloads_path):
        payload_manager.load_custom_payloads(custom_payloads_path)
    
    # Initialize scanner
    scanner = Scanner(config, payload_manager)
    
    # Run scan
    print(f"\n[+] Starting scan with {len(urls_to_scan)} URLs")
    print(f"[+] Loaded {len(payload_manager.get_payloads())} payloads")
    
    from datetime import datetime
    start_time = datetime.now()
    
    results = await scanner.scan_urls(urls_to_scan)
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    # Get scan statistics
    stats = scanner.get_scan_stats()
    stats['scan_duration'] = duration
    
    # Print scan summary
    print("\nScan Summary:")
    print(f"Total URLs: {stats['total_urls']}")
    print(f"Vulnerable URLs: {stats['vulnerable_count']}")
    print(f"Scan Duration: {stats['scan_duration']:.2f} seconds")
    
    # Generate report if output file is specified
    if args.output:
        report_generator = ReportGenerator(config)
        report = report_generator.generate_report(results, stats, args.output, args.format)
        print(f"\n[+] Report saved to: {args.output}")
    
    # Return the results
    return results, stats

if __name__ == "__main__":
    # Run the main function
    asyncio.run(main())
