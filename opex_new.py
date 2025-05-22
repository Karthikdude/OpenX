#!/usr/bin/env python3
"""
OpenX - Advanced Open Redirect Vulnerability Scanner

A powerful, modular tool for detecting and verifying open redirect vulnerabilities
in web applications with advanced detection techniques and comprehensive reporting.

Author: Karthik S Sathyan
License: MIT
"""
import argparse
import logging
import os
import signal
import sys
import time
import json
import asyncio
import urllib.parse
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

# Initialize colorama for cross-platform colored terminal output
from colorama import Fore, Style, init
init(autoreset=True)

# Import modules
from config.config import Config
from payloads.payload_manager import PayloadManager
from core.scanner import Scanner
from reports.report_generator import ReportGenerator
from utils.helpers import (
    read_urls_from_file, 
    is_valid_url, 
    create_directory_if_not_exists,
    get_severity_color
)
from fake_useragent_data import UserAgentManager

# Banner function
def display_banner():
    """Display the OpenX banner"""
    banner = """
 ██████╗ ██████╗ ███████╗███╗   ██╗██╗  ██╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║╚██╗██╔╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ╚███╔╝
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ██╔██╗
╚██████╔╝██║     ███████╗██║ ╚████║██╔╝ ██╗
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝

OpenX - Advanced Open Redirect Scanner
Developed by Karthik S Sathyan
"""
    print(Fore.CYAN + banner)

# Handle keyboard interrupt
def signal_handler(sig, frame):
    """Handle keyboard interrupt (Ctrl+C)"""
    print(Fore.RED + "\nProgram terminated by user")
    for task in asyncio.all_tasks():
        task.cancel()

# Setup argument parser
def setup_argument_parser():
    """Setup command line argument parser"""
    parser = argparse.ArgumentParser(
        description="OpenX - Advanced Open Redirect Vulnerability Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Input options
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument("-l", "--url-file", help="File containing URLs to scan")
    input_group.add_argument("-u", "--single-url", help="Single URL to scan")
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument("-o", "--output", help="Output file to save results")
    output_group.add_argument("-error", "--hide-error", action="store_true", help="Hide errors from output")
    output_group.add_argument("-hide", "--hide-vuln", action="store_true", help="Only display vulnerable URLs")
    output_group.add_argument("--report-format", choices=["text", "json", "html"], default="text", help="Report format")
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument("-s", "--smart-scan", action="store_true", help="Enable smart parameter-based payload injection")
    scan_group.add_argument("-debug", "--debug-mode", action="store_true", help="Enable debug mode")
    scan_group.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    scan_group.add_argument("--dry-run", action="store_true", help="Test without scanning")
    scan_group.add_argument("--concurrency", type=int, default=100, help="Number of concurrent requests")
    scan_group.add_argument("--max-retries", type=int, default=3, help="Maximum number of retries for failed requests")
    scan_group.add_argument("--retry-delay", type=int, default=2, help="Delay between retries in seconds")
    scan_group.add_argument("--target-domains", help="Comma-separated list of target domains")
    scan_group.add_argument("--custom-payloads", help="File containing custom payloads")
    
    # Browser options
    browser_group = parser.add_argument_group('Browser Options')
    browser_group.add_argument("--browser", action="store_true", help="Use headless browser for deep verification")
    browser_group.add_argument("--browser-type", choices=["playwright", "selenium"], default="playwright", help="Browser automation type")
    browser_group.add_argument("--browser-headless", action="store_true", default=True, help="Run browser in headless mode")
    
    # Authentication options
    auth_group = parser.add_argument_group('Authentication Options')
    auth_group.add_argument("--auth-type", choices=["basic", "digest", "bearer"], help="Authentication type")
    auth_group.add_argument("--auth-username", help="Authentication username")
    auth_group.add_argument("--auth-password", help="Authentication password")
    auth_group.add_argument("--auth-token", help="Authentication token")
    
    # Proxy options
    proxy_group = parser.add_argument_group('Proxy Options')
    proxy_group.add_argument("-p", "--proxy", help="HTTP proxy URL")
    proxy_group.add_argument("--proxy-username", help="Proxy authentication username")
    proxy_group.add_argument("--proxy-password", help="Proxy authentication password")
    
    # Evasion options
    evasion_group = parser.add_argument_group('Evasion Options')
    evasion_group.add_argument("-ua", "--random-user-agent", action="store_true", help="Randomize User-Agent")
    evasion_group.add_argument("--delay", action="store_true", help="Add random delay between requests")
    evasion_group.add_argument("--min-delay", type=float, default=0.5, help="Minimum delay in seconds")
    evasion_group.add_argument("--max-delay", type=float, default=3.0, help="Maximum delay in seconds")
    evasion_group.add_argument("--waf-bypass", action="store_true", help="Enable WAF bypass techniques")
    
    # Configuration options
    config_group = parser.add_argument_group('Configuration Options')
    config_group.add_argument("--config", help="Path to configuration file")
    config_group.add_argument("--save-config", help="Save current settings to configuration file")
    config_group.add_argument("--profile", help="Use a specific scanning profile")
    config_group.add_argument("--save-profile", help="Save current settings as a profile")
    
    return parser

# Main function
async def main():
    """Main function"""
    # Display banner
    display_banner()
    
    # Setup signal handler for keyboard interrupt
    signal.signal(signal.SIGINT, signal_handler)
    
    # Parse command line arguments
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.debug_mode else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    logger = logging.getLogger("openx")
    
    # Create necessary directories
    for directory in ["reports", "config/profiles"]:
        create_directory_if_not_exists(directory)
    
    # Load configuration
    config_file = args.config
    config = Config(config_file)
    
    # Load profile if specified
    if args.profile:
        profile_config = config.get_profile(args.profile)
        if profile_config:
            config._update_nested_dict(config.config, profile_config)
            logger.info(f"Loaded profile: {args.profile}")
        else:
            logger.warning(f"Profile not found: {args.profile}")
    
    # Update configuration from command line arguments
    update_config_from_args(config, args)
    
    # Save configuration if requested
    if args.save_config:
        config.save_config(args.save_config)
        logger.info(f"Configuration saved to: {args.save_config}")
    
    # Save profile if requested
    if args.save_profile:
        config.save_profile(args.save_profile, config.config)
        logger.info(f"Profile saved: {args.save_profile}")
    
    # Check input arguments
    if not args.url_file and not args.single_url:
        logger.error("No input provided. Use -u for a single URL or -l for a file containing URLs.")
        parser.print_help()
        return
    
    # Get URLs to scan
    urls = []
    if args.url_file:
        logger.info(f"Reading URLs from file: {args.url_file}")
        urls = read_urls_from_file(args.url_file)
        logger.info(f"Loaded {len(urls)} URLs from file")
    elif args.single_url:
        if is_valid_url(args.single_url):
            logger.info(f"Scanning single URL: {args.single_url}")
            urls = [args.single_url]
        else:
            logger.error(f"Invalid URL: {args.single_url}")
            return
    
    # Initialize components
    payload_manager = PayloadManager(config.config)
    scanner = Scanner(config.config, payload_manager)
    report_generator = ReportGenerator(config.config)
    
    # Load custom payloads if provided
    if args.custom_payloads:
        payload_manager.load_custom_payloads(args.custom_payloads)
    
    # Dry run check
    if args.dry_run:
        logger.info("Dry run mode - no actual scanning will be performed")
        print(Fore.YELLOW + "[*] Dry run mode enabled - showing configuration:")
        print(json.dumps(config.config, indent=4))
        return
    
    # Start scanning
    logger.info(f"Starting scan with {len(urls)} URLs")
    results = await scanner.scan_urls(urls)
    
    # Get scan statistics
    stats = scanner.get_scan_stats()
    
    # Display scan summary
    print(Fore.CYAN + "\n[*] Scan Summary:")
    print(Fore.CYAN + f"[*] Scanned {stats['total_urls']} URLs in {stats['elapsed_time']:.2f} seconds ({stats['urls_per_sec']:.2f} URLs/sec)")
    print(Fore.CYAN + f"[*] Found {stats['vulnerable_urls']} vulnerable URLs")
    
    # Generate report if output file specified
    if args.output:
        # Set report format from args
        config.config['reporting']['output_format'] = args.report_format
        
        # Generate report
        report_file = report_generator.generate_report(results, stats, args.output)
        print(Fore.CYAN + f"[*] Report saved to: {report_file}")

def update_config_from_args(config, args):
    """
    Update configuration from command line arguments
    
    Args:
        config (Config): Configuration object
        args (Namespace): Command line arguments
    """
    # Scan settings
    if args.timeout:
        config.config['timeout'] = args.timeout
    
    if args.concurrency:
        config.config['concurrency'] = args.concurrency
    
    if args.max_retries:
        config.config['max_retries'] = args.max_retries
    
    if args.retry_delay:
        config.config['retry_delay'] = args.retry_delay
    
    if args.smart_scan:
        config.config['smart_scan'] = True
    
    if args.target_domains:
        config.config['target_domains'] = args.target_domains.split(',')
    
    if args.custom_payloads:
        config.config['custom_payload_file'] = args.custom_payloads
    
    # Browser settings
    if args.browser:
        config.config['browser']['enabled'] = True
    
    if args.browser_type:
        config.config['browser']['type'] = args.browser_type
    
    if args.browser_headless is not None:
        config.config['browser']['headless'] = args.browser_headless
    
    # Authentication settings
    if args.auth_type:
        config.config['auth']['enabled'] = True
        config.config['auth']['type'] = args.auth_type
        
        if args.auth_username:
            config.config['auth']['username'] = args.auth_username
        
        if args.auth_password:
            config.config['auth']['password'] = args.auth_password
        
        if args.auth_token:
            config.config['auth']['token'] = args.auth_token
    
    # Proxy settings
    if args.proxy:
        config.config['proxy'] = args.proxy
        
        if args.proxy_username and args.proxy_password:
            config.config['proxy_auth'] = {
                'username': args.proxy_username,
                'password': args.proxy_password
            }
    
    # Evasion settings
    if args.random_user_agent:
        config.config['user_agent_rotation'] = True
    
    if args.delay:
        config.config['evasion']['random_delay'] = True
        config.config['evasion']['min_delay'] = args.min_delay
        config.config['evasion']['max_delay'] = args.max_delay
    
    if args.waf_bypass:
        config.config['evasion']['waf_bypass'] = True
    
    # Reporting settings
    if args.report_format:
        config.config['reporting']['output_format'] = args.report_format
    
    # Output settings
    config.config['hide_error'] = args.hide_error
    config.config['hide_vuln'] = args.hide_vuln


# Entry point
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(Fore.RED + "\nProgram terminated by user")
    except Exception as e:
        print(Fore.RED + f"\nAn error occurred: {e}")
        logging.error(f"Unhandled exception: {e}", exc_info=True)
