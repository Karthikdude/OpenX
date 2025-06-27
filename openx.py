#!/usr/bin/env python3
"""
OpenX - Advanced Open Redirect Vulnerability Scanner
A production-grade tool for detecting open redirect vulnerabilities
"""

import argparse
import os
import sys
import traceback
import re
from colorama import Fore, Style, init
from scanner.core import Scanner
from scanner.utils import validate_url, load_urls_from_file
from output.formatters import OutputFormatter
from scanner.external import ExternalTools

# Initialize colorama for cross-platform colored output
init(autoreset=True)

def print_banner():
    """Print OpenX banner"""
    banner = f"""
{Fore.CYAN}
 ██████╗ ██████╗ ███████╗███╗   ██╗██╗  ██╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║╚██╗██╔╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ╚███╔╝ 
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ██╔██╗ 
╚██████╔╝██║     ███████╗██║ ╚████║██╔╝ ██╗
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.YELLOW}Advanced Open Redirect Vulnerability Scanner v1.0{Style.RESET_ALL}
{Fore.GREEN}Author: Karthik S Sathyan{Style.RESET_ALL}
{Fore.BLUE}https://github.com/Karthikdude/openx{Style.RESET_ALL}
"""
    print(banner)

def create_parser():
    """Create and configure argument parser"""
    parser = argparse.ArgumentParser(
        prog='openx',
        description='Advanced Open Redirect Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  openx -u "https://example.com/redirect?url="
  openx -l urls.txt --payloads custom.txt -o results.json
  openx -e example.com --e-gau -s -f
  openx -u "https://target.com" --headers --proxy http://127.0.0.1:8080 -v
  echo "https://example.com/redirect?url=" | openx
  cat urls.txt | openx --headers -o results.json
  gau example.com | grep redirect | openx --fast
        """
    )
    
    # Target input methods (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=False)
    target_group.add_argument('-u', '--url', 
                             help='Single URL to test')
    target_group.add_argument('-l', '--list', 
                             help='File containing URLs (one per line)')
    target_group.add_argument('-e', '--external', 
                             help='Domain or file for external tool integration')
    target_group.add_argument('--stdin', action='store_true',
                             help='Read URLs from STDIN (pipe support)')
    
    # External tool options
    parser.add_argument('--e-gau', action='store_true',
                       help='Use gau for URL gathering')
    parser.add_argument('--e-wayback', action='store_true',
                       help='Use waybackurls for URL gathering')
    
    # Output options
    parser.add_argument('-o', '--output',
                       help='Output file path (format auto-detected: .txt, .json, .csv)')
    parser.add_argument('-c', '--callback',
                       help='Callback URL for payload testing')
    
    # Request options
    parser.add_argument('--headers', action='store_true',
                       help='Test header-based injection')
    parser.add_argument('--payloads',
                       help='Custom payload file')
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--delay', type=float, default=0,
                       help='Delay between requests in seconds (default: 0)')
    parser.add_argument('--user-agent',
                       default='OpenX/1.0 (Security Scanner)',
                       help='Custom User-Agent string')
    parser.add_argument('--proxy',
                       help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--follow-redirects', type=int, default=5,
                       help='Maximum redirect depth to follow (default: 5)')
    
    # Display options
    parser.add_argument('--status-codes', action='store_true',
                       help='Display HTTP status codes')
    parser.add_argument('--insecure', '-i', action='store_true',
                       help='Disable SSL certificate verification')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output with detailed information')
    parser.add_argument('--silent', action='store_true',
                       help='Silent mode (suppress banner and non-essential output)')
    
    # Performance options
    parser.add_argument('-f', '--fast', action='store_true',
                       help='Fast mode: stop after first vulnerability found per URL')
    parser.add_argument('-s', '--small', action='store_true',
                       help='Small mode: test only common redirect parameters')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Recursively test discovered parameters')
    
    # False positive reduction options
    parser.add_argument('--reduce-fp', action='store_true',
                       help='Enable enhanced false positive reduction')
    parser.add_argument('--ignore-same-domain', action='store_true',
                       help='Ignore redirects to the same domain or subdomains')
    parser.add_argument('--ignore-wp-oembed', action='store_true',
                       help='Ignore WordPress oEmbed API endpoints')
    parser.add_argument('--ignore-queue-systems', action='store_true',
                       help='Ignore queue systems with target parameters')
    
    return parser

def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Print banner unless in silent mode
    if not args.silent:
        print_banner()
    
    try:
        # Initialize scanner with configuration
        scanner = Scanner(
            threads=args.threads,
            timeout=args.timeout,
            delay=args.delay,
            user_agent=args.user_agent,
            proxy=args.proxy,
            follow_redirects=args.follow_redirects,
            verbose=args.verbose,
            silent=args.silent,
            fast_mode=args.fast,
            small_mode=args.small,
            test_headers=args.headers,
            callback_url=args.callback,
            custom_payloads=args.payloads,
            show_status_codes=args.status_codes,
            verify_ssl=not args.insecure,
            reduce_false_positives=args.reduce_fp,
            ignore_same_domain=args.ignore_same_domain,
            ignore_wp_oembed=args.ignore_wp_oembed,
            ignore_queue_systems=args.ignore_queue_systems
        )
        
        # Determine target URLs
        urls = []
        
        if args.url:
            # Single URL
            if not validate_url(args.url):
                print(f"{Fore.RED}[ERROR] Invalid URL: {args.url}{Style.RESET_ALL}")
                sys.exit(1)
            urls = [args.url]
            
        elif args.list:
            # URL list from file
            try:
                urls = load_urls_from_file(args.list)
                if not urls:
                    print(f"{Fore.RED}[ERROR] No valid URLs found in file: {args.list}{Style.RESET_ALL}")
                    sys.exit(1)
            except FileNotFoundError:
                print(f"{Fore.RED}[ERROR] File not found: {args.list}{Style.RESET_ALL}")
                sys.exit(1)
                
        elif args.external:
            # External tool integration
            external_tools = ExternalTools()
            
            # Determine which tool to use
            use_gau = args.e_gau
            use_wayback = args.e_wayback
            
            # Auto-detect if no specific tool specified
            if not use_gau and not use_wayback:
                if external_tools.check_gau_available():
                    use_gau = True
                elif external_tools.check_wayback_available():
                    use_wayback = True
                else:
                    print(f"{Fore.RED}[ERROR] No external tools available. Install 'gau' or 'waybackurls'{Style.RESET_ALL}")
                    sys.exit(1)
            
            # Gather URLs using external tools
            if use_gau:
                if not external_tools.check_gau_available():
                    print(f"{Fore.RED}[ERROR] 'gau' tool not available{Style.RESET_ALL}")
                    sys.exit(1)
                urls = external_tools.run_gau(args.external)
            elif use_wayback:
                if not external_tools.check_wayback_available():
                    print(f"{Fore.RED}[ERROR] 'waybackurls' tool not available{Style.RESET_ALL}")
                    sys.exit(1)
                urls = external_tools.run_wayback(args.external)
            
            if not urls:
                print(f"{Fore.RED}[ERROR] No URLs gathered from external tools{Style.RESET_ALL}")
                sys.exit(1)
        
        elif args.stdin:
            # Read URLs from STDIN explicitly
            try:
                import sys
                urls = []
                for line in sys.stdin:
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip empty lines and comments
                        if validate_url(line):
                            urls.append(line)
                        elif not args.silent:
                            print(f"{Fore.YELLOW}[WARNING] Skipping invalid URL: {line}{Style.RESET_ALL}")
                if not urls:
                    print(f"{Fore.RED}[ERROR] No valid URLs provided via STDIN{Style.RESET_ALL}")
                    sys.exit(1)
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[INFO] Interrupted by user{Style.RESET_ALL}")
                return 0
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Failed to read from STDIN: {e}{Style.RESET_ALL}")
                return 1
        
        else:
            # Check if data is being piped (auto-detect STDIN)
            import sys
            
            if not sys.stdin.isatty():
                # Data is being piped, read from STDIN
                try:
                    urls = []
                    for line in sys.stdin:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if validate_url(line):
                                urls.append(line)
                            elif not args.silent:
                                print(f"{Fore.YELLOW}[WARNING] Skipping invalid URL: {line}{Style.RESET_ALL}")
                    if not urls:
                        print(f"{Fore.RED}[ERROR] No valid URLs provided via pipe{Style.RESET_ALL}")
                        return 1
                except Exception as e:
                    print(f"{Fore.RED}[ERROR] Failed to read from pipe: {e}{Style.RESET_ALL}")
                    return 1
            else:
                print(f"{Fore.RED}[ERROR] No input method specified. Use -u, -l, -e, --stdin, or pipe URLs{Style.RESET_ALL}")
                parser.print_help()
                return 1
        
        # Start scanning
        if not args.silent:
            print(f"{Fore.CYAN}[INFO] Starting scan of {len(urls)} URL(s)...{Style.RESET_ALL}")
        
        results = scanner.scan_urls(urls)
        
        # Output results
        formatter = OutputFormatter(
            output_file=args.output,
            verbose=args.verbose,
            silent=args.silent
        )
        
        formatter.output_results(results)
        
        # Summary
        if not args.silent:
            total_vulnerabilities = sum(len(result.get('vulnerabilities', [])) for result in results)
            vulnerable_urls = sum(1 for result in results if result.get('vulnerabilities'))
            
            print(f"\n{Fore.CYAN}[SUMMARY]{Style.RESET_ALL}")
            print(f"URLs tested: {len(results)}")
            print(f"Vulnerable URLs: {vulnerable_urls}")
            print(f"Total vulnerabilities: {total_vulnerabilities}")
            
            if total_vulnerabilities > 0:
                print(f"{Fore.GREEN}[SUCCESS] Found {total_vulnerabilities} vulnerabilities!{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[INFO] No vulnerabilities found.{Style.RESET_ALL}")
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO] Scan interrupted by user{Style.RESET_ALL}")
        return 0
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            traceback.print_exc()
        return 1

if __name__ == '__main__':
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO] Operation cancelled by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Fatal error: {str(e)}{Style.RESET_ALL}")
        if '--verbose' in sys.argv or '-v' in sys.argv:
            traceback.print_exc()
        sys.exit(1)
