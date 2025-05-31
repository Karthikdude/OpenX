#!/usr/bin/env python3
"""
OpenX - Advanced Open Redirect Vulnerability Scanner
Developed by: Karthik S Sathyan
Version: 1.0
"""

import argparse
import sys
import os
import threading
import time
from pathlib import Path
from colorama import Fore, Back, Style, init

from core.scanner import OpenRedirectScanner
from core.output import OutputManager
from core.utils import display_banner, validate_url, load_urls_from_file

# Initialize colorama for cross-platform colored output
init(autoreset=True)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="OpenX - Advanced Open Redirect Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python openx.py -u https://example.com/redirect?url=
  python openx.py -l urls.txt -o results.json
  python openx.py -u https://example.com --threads 20 --timeout 15
  python openx.py -l domains.txt --headers --verbose
        """
    )
    
    # Primary arguments
    parser.add_argument('-u', '--url', help='Single target URL for scanning')
    parser.add_argument('-l', '--list', help='Path to file containing list of URLs to scan')
    parser.add_argument('-o', '--output', help='Output file path with format auto-detection')
    parser.add_argument('-c', '--callback', help='Callback URL (Burp Collaborator or custom endpoint)')
    
    # Advanced options
    parser.add_argument('--headers', action='store_true', help='Enable header-based injection testing')
    parser.add_argument('--payloads', help='Path to custom payload file')
    parser.add_argument('--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--delay', type=int, default=0, help='Delay between requests in milliseconds')
    parser.add_argument('--user-agent', help='Custom user-agent string')
    parser.add_argument('--proxy', help='HTTP/HTTPS proxy configuration')
    parser.add_argument('--follow-redirects', type=int, default=5, help='Maximum redirect chain depth to follow')
    parser.add_argument('--status-codes', action='store_true', help='Display HTTP status codes in output')
    parser.add_argument('--verbose', action='store_true', help='Enable detailed verbose logging')
    parser.add_argument('--silent', action='store_true', help='Suppress banner and non-essential output')
    
    return parser.parse_args()

def main():
    """Main function"""
    args = parse_arguments()
    
    # Display banner unless silent mode
    if not args.silent:
        display_banner()
    
    # Validate input arguments
    if not args.url and not args.list:
        print(f"{Fore.RED}[ERROR] Either -u/--url or -l/--list must be specified{Style.RESET_ALL}")
        sys.exit(1)
    
    # Prepare target URLs
    target_urls = []
    
    if args.url:
        if not validate_url(args.url):
            print(f"{Fore.RED}[ERROR] Invalid URL format: {args.url}{Style.RESET_ALL}")
            sys.exit(1)
        target_urls.append(args.url)
    
    if args.list:
        if not os.path.exists(args.list):
            print(f"{Fore.RED}[ERROR] URL list file not found: {args.list}{Style.RESET_ALL}")
            sys.exit(1)
        
        list_urls = load_urls_from_file(args.list)
        if not list_urls:
            print(f"{Fore.RED}[ERROR] No valid URLs found in file: {args.list}{Style.RESET_ALL}")
            sys.exit(1)
        target_urls.extend(list_urls)
    
    if not target_urls:
        print(f"{Fore.RED}[ERROR] No valid URLs to scan{Style.RESET_ALL}")
        sys.exit(1)
    
    # Initialize scanner with configuration
    scanner_config = {
        'threads': args.threads,
        'timeout': args.timeout,
        'delay': args.delay / 1000 if args.delay else 0,  # Convert ms to seconds
        'user_agent': args.user_agent,
        'proxy': args.proxy,
        'follow_redirects': args.follow_redirects,
        'headers_test': args.headers,
        'callback_url': args.callback,
        'custom_payloads': args.payloads,
        'verbose': args.verbose,
        'status_codes': args.status_codes
    }
    
    scanner = OpenRedirectScanner(scanner_config)
    
    # Display scan information
    if not args.silent:
        print(f"{Fore.CYAN}[INFO] Target URLs: {len(target_urls)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Threads: {args.threads}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Timeout: {args.timeout}s{Style.RESET_ALL}")
        if args.headers:
            print(f"{Fore.CYAN}[INFO] Header injection testing: Enabled{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[INFO] Starting scan...{Style.RESET_ALL}\n")
    
    # Start scanning
    start_time = time.time()
    
    try:
        results = scanner.scan_urls(target_urls)
        
        # Calculate scan statistics
        scan_time = time.time() - start_time
        total_requests = scanner.get_total_requests()
        vulnerable_count = len([r for r in results if r['vulnerable']])
        
        if not args.silent:
            print(f"\n{Fore.GREEN}[COMPLETED] Scan finished in {scan_time:.2f} seconds{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[STATS] Total requests: {total_requests}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[STATS] Vulnerable URLs: {vulnerable_count}/{len(target_urls)}{Style.RESET_ALL}")
        
        # Display results
        if results:
            vulnerable_results = [r for r in results if r['vulnerable']]
            if vulnerable_results:
                print(f"\n{Fore.RED}{'='*60}")
                print(f"{Fore.RED}VULNERABLE URLS FOUND:")
                print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")
                
                for result in vulnerable_results:
                    print(f"\n{Fore.RED}[VULNERABLE] {result['url']}{Style.RESET_ALL}")
                    print(f"  {Fore.YELLOW}Payload: {result['payload']}{Style.RESET_ALL}")
                    print(f"  {Fore.YELLOW}Method: {result['method']}{Style.RESET_ALL}")
                    if args.status_codes and 'status_code' in result:
                        print(f"  {Fore.YELLOW}Status Code: {result['status_code']}{Style.RESET_ALL}")
                    if 'redirect_chain' in result and result['redirect_chain']:
                        print(f"  {Fore.YELLOW}Redirect Chain: {' -> '.join(result['redirect_chain'])}{Style.RESET_ALL}")
                    print(f"  {Fore.YELLOW}Severity: {result.get('severity', 'Medium')}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.GREEN}[INFO] No open redirect vulnerabilities found{Style.RESET_ALL}")
        
        # Save output if specified
        if args.output:
            output_manager = OutputManager()
            success = output_manager.save_results(results, args.output)
            if success:
                print(f"\n{Fore.GREEN}[INFO] Results saved to: {args.output}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.RED}[ERROR] Failed to save results to: {args.output}{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] Unexpected error: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
