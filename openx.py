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
import shutil
import subprocess
from urllib.parse import urlparse, parse_qs

# Initialize colorama for cross-platform colored output
init(autoreset=True)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        prog='openx.py',
        description="OpenX - Advanced Open Redirect Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python openx.py -u https://example.com/redirect?url=
  python openx.py -l urls.txt -o results.json
  python openx.py -u https://example.com --threads 20 --timeout 15
  python openx.py -l domains.txt --headers --verbose
  python openx.py -e example.com -c http://mycallback.com --fast --verbose
        """
    )
    
    # Primary Target Specification (Mutually Exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-u', '--url', help='Single target URL for scanning')
    target_group.add_argument('-l', '--list', help='Path to file containing list of URLs to scan (one URL per line)')
    target_group.add_argument('-e', '--external', metavar='DOMAIN_OR_FILE', help='Domain or path to file (one domain per line) to gather URLs from using external tools (gau/waybackurls, gf, uro)')

    # External tool specifiers (optional, only relevant with -e)
    external_tool_group = parser.add_mutually_exclusive_group()
    external_tool_group.add_argument('--e-gau', action='store_true', help='Force use of GAU for URL gathering with -e')
    external_tool_group.add_argument('--e-wayback', action='store_true', help='Force use of Waybackurls for URL gathering with -e')

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
    parser.add_argument('-s', '--small', action='store_true',
                        help='Filter URLs to a small set with common redirect parameters (for -e and -l modes)')
    
    return parser.parse_args()

def filter_urls_by_common_redirect_params(urls, verbose=False, silent=False):
    """Filter URLs to keep only those with common redirect-like parameters."""
    common_params = ['redirect', 'url', 'goto', 'next', 'dest'] # Add more if needed
    filtered_urls = []
    if not urls:
        return []

    if verbose and not silent:
        print(f"{Fore.BLUE}[VERBOSE] Starting --small filter. Initial URL count: {len(urls)}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[VERBOSE] Common redirect parameters being checked: {', '.join(common_params)}{Style.RESET_ALL}")

    for url_str in urls:
        try:
            parsed_url = urlparse(url_str)
            query_params = parse_qs(parsed_url.query)
            for param_name in query_params:
                # Check if the parameter name (without '[]' if it's an array type) is in our common list
                actual_param_name = param_name.rstrip('[]')
                if actual_param_name.lower() in common_params:
                    filtered_urls.append(url_str)
                    if verbose and not silent:
                        print(f"{Fore.BLUE}[VERBOSE] --small: Kept URL '{url_str}' due to parameter '{actual_param_name}'{Style.RESET_ALL}")
                    break # Found a common param, keep URL and move to next URL
        except Exception as e:
            if verbose and not silent:
                print(f"{Fore.YELLOW}[VERBOSE] --small: Error parsing URL '{url_str}': {e}. Skipping.{Style.RESET_ALL}")
            continue
    
    if verbose and not silent:
        print(f"{Fore.BLUE}[VERBOSE] --small filter finished. Filtered URL count: {len(filtered_urls)}{Style.RESET_ALL}")
        if filtered_urls:
            print(f"{Fore.BLUE}[VERBOSE] --small: Sample of filtered URLs (first 5):{Style.RESET_ALL}")
            for i, f_url in enumerate(filtered_urls[:5]):
                print(f"{Fore.BLUE}[VERBOSE]   {i+1}: {f_url}{Style.RESET_ALL}")
            if len(filtered_urls) > 5:
                print(f"{Fore.BLUE}[VERBOSE]   ... and {len(filtered_urls) - 5} more.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[VERBOSE] --small: No URLs matched the common redirect parameter criteria.{Style.RESET_ALL}")

    return filtered_urls

def check_tool_installed(tool_name):
    """Check if a tool is installed and in PATH."""
    return shutil.which(tool_name) is not None

def run_command_and_get_output(command_parts, verbose=False):
    """Run a shell command and return its stdout lines or None on error."""
    if verbose:
            print(f"{Fore.CYAN}[INFO] Running command: {' '.join(command_parts)}{Style.RESET_ALL}")
    try:
        process = subprocess.Popen(command_parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            if verbose:
                print(f"{Fore.RED}[ERROR] Command '{' '.join(command_parts)}' failed with error:\n{stderr.strip()}{Style.RESET_ALL}")
            return None
        output_lines = stdout.strip().splitlines()
        if verbose and output_lines:
            print(f"{Fore.BLUE}[VERBOSE] Command '{' '.join(command_parts)}' STDOUT (first 5 lines):{Style.RESET_ALL}")
            for i, line in enumerate(output_lines[:5]):
                print(f"{Fore.BLUE}[VERBOSE]   {line}{Style.RESET_ALL}")
            if len(output_lines) > 5:
                print(f"{Fore.BLUE}[VERBOSE]   ... and {len(output_lines) - 5} more lines.{Style.RESET_ALL}")
        return output_lines
    except FileNotFoundError:
        if verbose:
            print(f"{Fore.RED}[ERROR] Command not found: {command_parts[0]}{Style.RESET_ALL}")
        return None
    except Exception as e:
        if verbose:
            print(f"{Fore.RED}[ERROR] Exception running command '{' '.join(command_parts)}': {e}{Style.RESET_ALL}")
        return None

def get_urls_from_external_sources(domain, force_gau=False, force_wayback=False, verbose=False, silent=False, apply_small_filter=False):
    """Fetch and process URLs using external tools."""
    urls = []
    temp_urls_file = f"{domain}_temp_external_urls.txt"

    # Check for gf and uro first as they are essential for processing
    if not check_tool_installed('gf'):
        if not silent: print(f"{Fore.RED}[ERROR] 'gf' tool not found. Please install it to use the --external feature.{Style.RESET_ALL}")
        return []
    if not check_tool_installed('uro'):
        if not silent: print(f"{Fore.RED}[ERROR] 'uro' tool not found. Please install it to use the --external feature.{Style.RESET_ALL}")
        return []

    # Step 1: Get URLs using gau or waybackurls
    source_tool_output = None
    source_tool_name = ""

    if force_wayback:
        if check_tool_installed('waybackurls'):
            if not silent: print(f"{Fore.CYAN}[INFO] Using 'waybackurls' (forced) to fetch URLs for {domain}...{Style.RESET_ALL}")
            source_tool_output = run_command_and_get_output(['waybackurls', domain], verbose=verbose)
            source_tool_name = "waybackurls"
        else:
            if not silent: print(f"{Fore.RED}[ERROR] 'waybackurls' was specified but not found. Please install it.{Style.RESET_ALL}")
            return []
    elif force_gau:
        if check_tool_installed('gau'):
            if not silent: print(f"{Fore.CYAN}[INFO] Using 'gau' (forced) to fetch URLs for {domain}...{Style.RESET_ALL}")
            source_tool_output = run_command_and_get_output(['gau', domain], verbose=verbose)
            source_tool_name = "gau"
        else:
            if not silent: print(f"{Fore.RED}[ERROR] 'gau' was specified but not found. Please install it.{Style.RESET_ALL}")
            return []
    else: # Default behavior: try waybackurls first, then gau
        if check_tool_installed('waybackurls'):
            if not silent: print(f"{Fore.CYAN}[INFO] Using 'waybackurls' (default) to fetch URLs for {domain}...{Style.RESET_ALL}")
            source_tool_output = run_command_and_get_output(['waybackurls', domain], verbose=verbose)
            source_tool_name = "waybackurls"
        elif check_tool_installed('gau'):
            if not silent: print(f"{Fore.CYAN}[INFO] 'waybackurls' not found. Using 'gau' (fallback) to fetch URLs for {domain}...{Style.RESET_ALL}")
            source_tool_output = run_command_and_get_output(['gau', domain], verbose=verbose)
            source_tool_name = "gau"
        else:
            if not silent: print(f"{Fore.RED}[ERROR] Neither 'waybackurls' nor 'gau' found. Please install one of them to use the --external feature.{Style.RESET_ALL}")
            return []

    if not source_tool_output:
        if not silent: print(f"{Fore.YELLOW}[WARNING] No URLs found by {source_tool_name or 'external source tool'} for {domain}.{Style.RESET_ALL}")
        return []
    
    if not silent: print(f"{Fore.GREEN}[INFO] {source_tool_name.capitalize()} found {len(source_tool_output)} initial URLs for {domain}.{Style.RESET_ALL}")
    if verbose and source_tool_output:
        print(f"{Fore.BLUE}[VERBOSE] Raw URLs from {source_tool_name} ({len(source_tool_output)}):{Style.RESET_ALL}")
        for i, url_ex in enumerate(source_tool_output[:5]):
            print(f"{Fore.BLUE}[VERBOSE]   {i+1}: {url_ex}{Style.RESET_ALL}")
        if len(source_tool_output) > 5:
            print(f"{Fore.BLUE}[VERBOSE]   ... and {len(source_tool_output) - 5} more.{Style.RESET_ALL}")

    if not source_tool_output:
        if not silent: print(f"{Fore.YELLOW}[WARNING] No URLs found by an external source tool for {domain}.{Style.RESET_ALL}")
        return []
    
    if not silent: print(f"{Fore.GREEN}[INFO] Found {len(source_tool_output)} initial URLs from source tool.{Style.RESET_ALL}")

    # Step 2: Filter for redirect patterns using gf redirect
    # We need to pass the output of gau/waybackurls to gf via stdin
    if not silent: print(f"{Fore.CYAN}[INFO] Filtering URLs with 'gf redirect'...{Style.RESET_ALL}")
    try:
        gf_process = subprocess.Popen(['gf', 'redirect'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        gf_stdout, gf_stderr = gf_process.communicate(input='\n'.join(source_tool_output))
        if gf_process.returncode != 0:
            if verbose:
                print(f"{Fore.RED}[ERROR] 'gf redirect' failed with error:\n{gf_stderr.strip()}{Style.RESET_ALL}")
            return []
        redirect_urls = gf_stdout.strip().splitlines()
    except FileNotFoundError:
        if verbose:
            if not silent: print(f"{Fore.RED}[ERROR] Command not found: gf{Style.RESET_ALL}")
        return [] # gf is checked above, but defensive
    except Exception as e:
        if verbose:
            if not silent: print(f"{Fore.RED}[ERROR] Exception running 'gf redirect': {e}{Style.RESET_ALL}")
        return []

    if not redirect_urls:
        if not silent: print(f"{Fore.YELLOW}[WARNING] No redirect URLs found by 'gf redirect'.{Style.RESET_ALL}")
        return []
    if not silent: print(f"{Fore.GREEN}[INFO] 'gf redirect' filtered down to {len(redirect_urls)} potential redirect URLs.{Style.RESET_ALL}")
    if verbose and redirect_urls:
        print(f"{Fore.BLUE}[VERBOSE] URLs after 'gf redirect' ({len(redirect_urls)}):{Style.RESET_ALL}")
        for i, url_ex in enumerate(redirect_urls[:5]):
            print(f"{Fore.BLUE}[VERBOSE]   {i+1}: {url_ex}{Style.RESET_ALL}")
        if len(redirect_urls) > 5:
            print(f"{Fore.BLUE}[VERBOSE]   ... and {len(redirect_urls) - 5} more.{Style.RESET_ALL}")

    # Step 3: Deduplicate using uro
    if not silent: print(f"{Fore.CYAN}[INFO] Deduplicating URLs with 'uro'...{Style.RESET_ALL}")
    try:
        uro_process = subprocess.Popen(['uro'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        uro_stdout, uro_stderr = uro_process.communicate(input='\n'.join(redirect_urls))
        if uro_process.returncode != 0:
            if verbose:
                print(f"{Fore.RED}[ERROR] 'uro' failed with error:\n{uro_stderr.strip()}{Style.RESET_ALL}")
            return [] # Return empty if uro fails, as it's part of the chain
        final_urls = uro_stdout.strip().splitlines()
    except FileNotFoundError:
        if verbose:
            if not silent: print(f"{Fore.RED}[ERROR] Command not found: uro{Style.RESET_ALL}")
        return [] # uro is checked above, but defensive
    except Exception as e:
        if verbose:
            if not silent: print(f"{Fore.RED}[ERROR] Exception running 'uro': {e}{Style.RESET_ALL}")
        return []

    if not final_urls:
        if not silent: print(f"{Fore.YELLOW}[WARNING] No URLs left after 'uro' deduplication.{Style.RESET_ALL}")
        return []
    if not silent: print(f"{Fore.GREEN}[INFO] 'uro' deduplicated to {len(final_urls)} final URLs.{Style.RESET_ALL}")
    if verbose and final_urls:
        print(f"{Fore.BLUE}[VERBOSE] URLs after 'uro' deduplication ({len(final_urls)}):{Style.RESET_ALL}")
        for i, url_ex in enumerate(final_urls[:5]):
            print(f"{Fore.BLUE}[VERBOSE]   {i+1}: {url_ex}{Style.RESET_ALL}")
        if len(final_urls) > 5:
            print(f"{Fore.BLUE}[VERBOSE]   ... and {len(final_urls) - 5} more.{Style.RESET_ALL}")
    if not silent: print(f"{Fore.CYAN}[INFO] Starting scan with {len(final_urls)} URLs for {domain}.{Style.RESET_ALL}")

    if apply_small_filter:
        if not silent:
            print(f"{Fore.CYAN}[INFO] Applying --small filter for domain {domain}...{Style.RESET_ALL}")
        final_urls = filter_urls_by_common_redirect_params(final_urls, verbose=verbose, silent=silent)
        if not final_urls:
            if not silent: print(f"{Fore.YELLOW}[WARNING] --small filter resulted in no URLs for domain {domain}. Skipping scan for this domain.{Style.RESET_ALL}")
            return [] # Return empty if filter results in no URLs
        if not silent:
            print(f"{Fore.GREEN}[INFO] --small filter applied. Proceeding with {len(final_urls)} URLs for {domain}.{Style.RESET_ALL}")

    return final_urls

def display_scan_results(results_list, args, domain_name=None):
    """Display formatted scan results for a given list of findings."""
    vulnerable_results = [r for r in results_list if r.get('vulnerable', False)]

    if domain_name:
        if not args.silent: print(f"\n{Fore.MAGENTA}{'='*20} Results for Domain: {domain_name} {'='*20}{Style.RESET_ALL}")

    if vulnerable_results:
        # Group results by method for summary
        results_by_method = {}
        for res in vulnerable_results:
            method = res.get('method', 'Unknown')
            if method not in results_by_method:
                results_by_method[method] = []
            results_by_method[method].append(res)
        
        if not args.silent: print(f"\n{Fore.RED}🔥 VULNERABILITY SUMMARY ({domain_name or 'Overall'}):{Style.RESET_ALL}")
        for method, method_results in results_by_method.items():
            # Determine overall severity for this method group (highest found)
            severities = [r.get('severity', 'Low') for r in method_results]
            highest_severity = 'Low'
            if 'High' in severities: highest_severity = 'High'
            elif 'Medium' in severities: highest_severity = 'Medium'
            
            severity_color = {
                'High': Fore.RED, 'Medium': Fore.YELLOW, 'Low': Fore.CYAN
            }.get(highest_severity, Fore.WHITE)
            severity_str = f"{severity_color}{highest_severity}{Style.RESET_ALL}"
            
            method_icon = {
                'URL Parameter': '🌐', 'Meta Refresh': '🔄', 
                'JavaScript Redirect': '⚡', 'Header Injection': '📋',
                'Form POST Redirect': '📝', 'Cookie-based Redirect': '🍪'
            }.get(method, '🔍')
            if not args.silent: print(f"  {method_icon} {Fore.YELLOW}{method}: {len(method_results)} findings ({severity_str}){Style.RESET_ALL}")
        
        if not args.silent: print(f"\n{Fore.RED}🚨 DETAILED VULNERABILITY FINDINGS ({domain_name or 'Overall'}):{Style.RESET_ALL}")
        if not args.silent: print(f"{Fore.RED}{'-'*80}{Style.RESET_ALL}")
        
        for i, result in enumerate(vulnerable_results, 1):
            method_icon = {
                'URL Parameter': '🌐', 'Meta Refresh': '🔄', 
                'JavaScript Redirect': '⚡', 'Header Injection': '📋',
                'Form POST Redirect': '📝', 'Cookie-based Redirect': '🍪'
            }.get(result.get('method', 'Unknown'), '🔍')
            
            severity = result.get('severity', 'Medium')
            severity_color = {
                'High': Fore.RED, 'Medium': Fore.YELLOW, 'Low': Fore.CYAN
            }.get(severity, Fore.WHITE)
            
            if not args.silent: print(f"\n{Fore.RED}[{i:02d}] {method_icon} VULNERABILITY FOUND{Style.RESET_ALL}")
            if not args.silent: print(f"    {Fore.CYAN}URL: {result['url']}{Style.RESET_ALL}")
            if not args.silent: print(f"    {Fore.YELLOW}Type: {result.get('method', 'Unknown')}{Style.RESET_ALL}")
            if not args.silent: print(f"    {Fore.YELLOW}Payload: {result['payload']}{Style.RESET_ALL}")
            
            if 'parameter' in result:
                if not args.silent: print(f"    {Fore.YELLOW}Parameter: {result['parameter']}{Style.RESET_ALL}")
            elif 'header' in result:
                if not args.silent: print(f"    {Fore.YELLOW}Header: {result['header']}{Style.RESET_ALL}")
            elif 'cookie' in result:
                if not args.silent: print(f"    {Fore.YELLOW}Cookie: {result['cookie']}{Style.RESET_ALL}")
            
            if not args.silent: print(f"    {severity_color}Severity: {severity}{Style.RESET_ALL}")
            
            if args.status_codes and 'status_code' in result:
                if not args.silent: print(f"    {Fore.YELLOW}Status Code: {result['status_code']}{Style.RESET_ALL}")
            
            if 'redirect_location' in result:
                if not args.silent: print(f"    {Fore.YELLOW}Redirects To: {result['redirect_location']}{Style.RESET_ALL}")
                
            if 'redirect_chain' in result and result['redirect_chain']:
                if not args.silent: print(f"    {Fore.YELLOW}Redirect Chain: {' -> '.join(result['redirect_chain'])}{Style.RESET_ALL}")
        
        if not args.silent: print(f"\n{Fore.GREEN}✅ Scan completed for {domain_name or 'target(s)'} - {len(vulnerable_results)} vulnerabilities found{Style.RESET_ALL}")
    else:
        if not args.silent: print(f"\n{Fore.GREEN}✅ [SECURE] No open redirect vulnerabilities detected for {domain_name or 'target(s)'}.{Style.RESET_ALL}")
        if domain_name: # Only show this extra line if it's for a specific domain context
             if not args.silent: print(f"{Fore.GREEN}🛡️  {domain_name} appears to be properly protected against open redirect attacks based on this scan.{Style.RESET_ALL}")

def display_final_scan_summary(all_scan_results, scanner_obj, scan_start_time, scan_end_time, cli_args):
    """Displays the overall scan summary, total requests, and time taken."""
    if not cli_args.silent:
        print(f"\n{Fore.CYAN}{'*'*20} Overall Scan Summary {'*'*20}{Style.RESET_ALL}")
        total_vulnerabilities_found = sum(1 for r in all_scan_results if r.get('vulnerable', False))
        if total_vulnerabilities_found > 0:
            print(f"{Fore.RED}🔥 Total vulnerabilities found across all targets: {total_vulnerabilities_found}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✅ No vulnerabilities found across all scanned targets.{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[INFO] Total requests made: {scanner_obj.get_total_requests()}{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}[INFO] Total scan time: {scan_end_time - scan_start_time:.2f} seconds{Style.RESET_ALL}")

def main():
    """Main function"""
    args = parse_arguments()
    exit_code = 0  # Default to success
    scanner = None # Initialize scanner to None for finally block access
    start_time = time.time() # Initialize start_time
    domains_to_process_externally = [] # Initialize for broader scope if needed by final messages

    try:
        # Display banner unless silent mode
        if not args.silent:
            display_banner()

        # Prepare target URLs (for -u and -l modes)
        target_urls = []
        if args.url:
            if not validate_url(args.url):
                if not args.silent: print(f"{Fore.RED}[ERROR] Invalid URL format: {args.url}{Style.RESET_ALL}")
                sys.exit(1)
            target_urls.append(args.url)
        
        if args.list:
            if not os.path.exists(args.list):
                if not args.silent: print(f"{Fore.RED}[ERROR] URL list file not found: {args.list}{Style.RESET_ALL}")
                sys.exit(1)
            
            list_urls = load_urls_from_file(args.list)
            if args.small and list_urls:
                if not args.silent: print(f"{Fore.CYAN}[INFO] Applying --small filter to URL list...{Style.RESET_ALL}")
                list_urls = filter_urls_by_common_redirect_params(list_urls, verbose=args.verbose, silent=args.silent)
                if not list_urls and not args.silent:
                    print(f"{Fore.YELLOW}[WARNING] --small filter resulted in no URLs from the list.{Style.RESET_ALL}")
            if not list_urls:
                if not args.silent: print(f"{Fore.RED}[ERROR] No valid URLs found in file: {args.list}{Style.RESET_ALL}")
                sys.exit(1)
            target_urls.extend(list_urls)

        all_scan_results_accumulator = []

        scanner_config = {
            'threads': args.threads,
            'timeout': args.timeout,
            'delay': args.delay / 1000 if args.delay else 0,
            'user_agent': args.user_agent,
            'proxy': args.proxy,
            'follow_redirects': args.follow_redirects,
            'headers_test': args.headers,
            'callback_url': args.callback,
            'custom_payloads': args.payloads,
            'verbose': args.verbose,
            'status_codes': args.status_codes,
            'fast': args.fast
        }
        scanner = OpenRedirectScanner(scanner_config)

        # Main processing logic based on input mode
        if args.external:
            # domains_to_process_externally is re-initialized here for this specific block
            domains_to_process_externally = [] 
            potential_target = args.external

            if os.path.exists(potential_target) and os.path.isfile(potential_target):
                if not args.silent:
                    print(f"{Fore.CYAN}[INFO] Reading domains from file for external processing: {potential_target}{Style.RESET_ALL}")
                try:
                    with open(potential_target, 'r') as f:
                        domains_from_file = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    if not domains_from_file:
                        if not args.silent: print(f"{Fore.RED}[ERROR] No domains found in file: {potential_target}. Exiting.{Style.RESET_ALL}")
                        sys.exit(1)
                    domains_to_process_externally.extend(domains_from_file)
                    if not args.silent:
                        print(f"{Fore.GREEN}[INFO] Found {len(domains_from_file)} domain(s) in {potential_target} for external processing.{Style.RESET_ALL}")
                except Exception as e:
                    if not args.silent: print(f"{Fore.RED}[ERROR] Could not read domains from file {potential_target}: {e}. Exiting.{Style.RESET_ALL}")
                    sys.exit(1)
            else:
                domains_to_process_externally.append(potential_target)
            
            if not domains_to_process_externally:
                 if not args.silent: print(f"{Fore.RED}[ERROR] No domains specified for external processing. Exiting.{Style.RESET_ALL}")
                 sys.exit(1)

            total_domains_to_process = len(domains_to_process_externally)
            for i, domain_item in enumerate(domains_to_process_externally):
                if not args.silent:
                    print(f"\n{Fore.BLUE}{'='*20} Processing Domain {i+1}/{total_domains_to_process}: {domain_item} {'='*20}{Style.RESET_ALL}")
                
                current_domain_urls = get_urls_from_external_sources(
                    domain_item, 
                    force_gau=args.e_gau, 
                    force_wayback=args.e_wayback, 
                    verbose=args.verbose, 
                    silent=args.silent,
                    apply_small_filter=args.small
                )

                if current_domain_urls:
                    if not args.silent:
                        print(f"\n{Fore.CYAN}[INFO] Starting scan for {domain_item} with {len(current_domain_urls)} URLs using {args.threads} threads...{Style.RESET_ALL}")
                    if args.verbose:
                        print(f"{Fore.CYAN}[DEBUG] Scanner Config for {domain_item}: {scanner_config}{Style.RESET_ALL}")
                    
                    domain_results = scanner.scan_urls(current_domain_urls)
                    # display_scan_results handles its own silent logic via args
                    if not args.silent: display_scan_results(domain_results, args, domain_name=domain_item)
                    if domain_results:
                        all_scan_results_accumulator.extend(domain_results)
                elif not args.silent:
                    print(f"{Fore.YELLOW}[WARNING] No URLs obtained from external tools for domain: {domain_item}. Skipping scan for this domain.{Style.RESET_ALL}")
                
                if not args.silent: # Message after each domain is processed
                    print(f"{Fore.BLUE}{'='*20} Finished Processing Domain: {domain_item} {'='*20}{Style.RESET_ALL}")

        elif args.url or args.list: # -u or -l mode (single batch scan)
            if not target_urls: 
                if not args.silent: print(f"{Fore.RED}[ERROR] No valid URLs to scan (from -u or -l). Exiting.{Style.RESET_ALL}")
                sys.exit(1)

            if not args.silent:
                print(f"\n{Fore.CYAN}[INFO] Starting scan with {len(target_urls)} URLs using {args.threads} threads...{Style.RESET_ALL}")
            if args.verbose:
                print(f"{Fore.CYAN}[DEBUG] Scanner Config: {scanner_config}{Style.RESET_ALL}")
            
            results = scanner.scan_urls(target_urls)
            # display_scan_results handles its own silent logic via args
            if not args.silent: display_scan_results(results, args)
            if results:
                all_scan_results_accumulator.extend(results)
        
        else: # No input mode specified (-u, -l, or -e)
            if not args.silent:
                print(f"{Fore.RED}[ERROR] No input specified. Use -u, -l, or -e.{Style.RESET_ALL}")
                parse_arguments().print_help() # Show help
            sys.exit(1)

        # Common post-scan logic (after all processing modes)
        end_time = time.time()

        if not args.silent:
            # Conditional messages based on findings before final summary
            if args.external and not all_scan_results_accumulator and domains_to_process_externally:
                 print(f"\n{Fore.YELLOW}[INFO] External processing completed. No vulnerabilities were found across all processed domains.{Style.RESET_ALL}")
            elif (args.url or args.list) and not all_scan_results_accumulator:
                print(f"\n{Fore.YELLOW}[INFO] Scan of provided URLs completed. No vulnerabilities were found.{Style.RESET_ALL}")
            
            # display_final_scan_summary handles its own silent logic via args
            if scanner: # Ensure scanner is initialized before passing to summary
                display_final_scan_summary(all_scan_results_accumulator, scanner, start_time, end_time, args)
            else:
                # Handle case where scanner might not be initialized if an error occurred very early
                print(f"{Fore.YELLOW}[WARNING] Scan did not fully initialize. Final summary may be incomplete.{Style.RESET_ALL}")

        if args.output:
            if all_scan_results_accumulator:
                output_manager = OutputManager() # Assuming OutputManager is defined elsewhere
                success = output_manager.save_results(all_scan_results_accumulator, args.output)
                if success and not args.silent:
                    print(f"\n{Fore.GREEN}[INFO] All results saved to: {args.output}{Style.RESET_ALL}")
                elif not success and not args.silent:
                    print(f"\n{Fore.RED}[ERROR] Failed to save all results to: {args.output}{Style.RESET_ALL}")
            elif not args.silent: # Only print if not silent and no results to save
                print(f"\n{Fore.YELLOW}[INFO] No results to save to output file.{Style.RESET_ALL}")

    except KeyboardInterrupt:
        if not args.silent:
            print(f"\n{Fore.YELLOW}[INFO] Scan interrupted by user.{Style.RESET_ALL}")
        exit_code = 1 # Indicate interruption
    except SystemExit as e: # Catch sys.exit() calls to ensure finally block runs
        exit_code = e.code if isinstance(e.code, int) else 1 # Use exit code if provided, else 1
    except Exception as e:
        if not args.silent:
            print(f"\n{Fore.RED}[CRITICAL ERROR] An unexpected error occurred: {str(e)}{Style.RESET_ALL}")
            if args.verbose:
                traceback.print_exc()
        exit_code = 1 # Indicate critical error
    finally:
        if not args.silent:
            print(f"\n{Fore.CYAN}[INFO] OpenXScanner finished.{Style.RESET_ALL}")
        sys.exit(exit_code) # Ensure script exits with appropriate code

if __name__ == "__main__":
    main()
