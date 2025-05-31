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
    parser.add_argument('-f', '--fast', action='store_true',
                        help='Fast mode: stop testing URL after first vulnerability found')
    
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
        
        # Display results with enhanced UI
        if results:
            vulnerable_results = [r for r in results if r['vulnerable']]
            if vulnerable_results:
                # Group results by method for better display
                results_by_method = {}
                for result in vulnerable_results:
                    method = result.get('method', 'Unknown')
                    if method not in results_by_method:
                        results_by_method[method] = []
                    results_by_method[method].append(result)
                
                print(f"\n{Fore.RED}{'='*80}")
                print(f"{Fore.RED}🔍 OPEN REDIRECT VULNERABILITIES DETECTED")
                print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
                
                # Summary by method
                print(f"\n{Fore.CYAN}📊 VULNERABILITY SUMMARY BY TYPE:")
                for method, method_results in results_by_method.items():
                    method_icon = {
                        'URL Parameter': '🌐',
                        'Meta Refresh': '🔄',
                        'JavaScript Redirect': '⚡',
                        'Header Injection': '📋',
                        'Form POST Redirect': '📝',
                        'Cookie-based Redirect': '🍪'
                    }.get(method, '🔍')
                    
                    severity_counts = {}
                    for r in method_results:
                        sev = r.get('severity', 'Medium')
                        severity_counts[sev] = severity_counts.get(sev, 0) + 1
                    
                    severity_str = ', '.join([f"{sev}: {count}" for sev, count in severity_counts.items()])
                    print(f"  {method_icon} {Fore.YELLOW}{method}: {len(method_results)} findings ({severity_str}){Style.RESET_ALL}")
                
                print(f"\n{Fore.RED}🚨 DETAILED VULNERABILITY FINDINGS:")
                print(f"{Fore.RED}{'-'*80}{Style.RESET_ALL}")
                
                for i, result in enumerate(vulnerable_results, 1):
                    # Get method icon
                    method_icon = {
                        'URL Parameter': '🌐',
                        'Meta Refresh': '🔄', 
                        'JavaScript Redirect': '⚡',
                        'Header Injection': '📋',
                        'Form POST Redirect': '📝',
                        'Cookie-based Redirect': '🍪'
                    }.get(result.get('method', 'Unknown'), '🔍')
                    
                    # Get severity color
                    severity = result.get('severity', 'Medium')
                    severity_color = {
                        'High': Fore.RED,
                        'Medium': Fore.YELLOW, 
                        'Low': Fore.CYAN
                    }.get(severity, Fore.WHITE)
                    
                    print(f"\n{Fore.RED}[{i:02d}] {method_icon} VULNERABILITY FOUND{Style.RESET_ALL}")
                    print(f"    {Fore.CYAN}URL: {result['url']}{Style.RESET_ALL}")
                    print(f"    {Fore.YELLOW}Type: {result.get('method', 'Unknown')}{Style.RESET_ALL}")
                    print(f"    {Fore.YELLOW}Payload: {result['payload']}{Style.RESET_ALL}")
                    
                    # Show parameter or header or cookie
                    if 'parameter' in result:
                        print(f"    {Fore.YELLOW}Parameter: {result['parameter']}{Style.RESET_ALL}")
                    elif 'header' in result:
                        print(f"    {Fore.YELLOW}Header: {result['header']}{Style.RESET_ALL}")
                    elif 'cookie' in result:
                        print(f"    {Fore.YELLOW}Cookie: {result['cookie']}{Style.RESET_ALL}")
                    
                    print(f"    {severity_color}Severity: {severity}{Style.RESET_ALL}")
                    
                    if args.status_codes and 'status_code' in result:
                        print(f"    {Fore.YELLOW}Status Code: {result['status_code']}{Style.RESET_ALL}")
                    
                    if 'redirect_location' in result:
                        print(f"    {Fore.YELLOW}Redirects To: {result['redirect_location']}{Style.RESET_ALL}")
                        
                    if 'redirect_chain' in result and result['redirect_chain']:
                        print(f"    {Fore.YELLOW}Redirect Chain: {' -> '.join(result['redirect_chain'])}{Style.RESET_ALL}")
                
                print(f"\n{Fore.GREEN}✅ Scan completed successfully - {len(vulnerable_results)} vulnerabilities found{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.GREEN}✅ [SECURE] No open redirect vulnerabilities detected{Style.RESET_ALL}")
                print(f"{Fore.GREEN}🛡️  The application appears to be properly protected against open redirect attacks{Style.RESET_ALL}")
        
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
