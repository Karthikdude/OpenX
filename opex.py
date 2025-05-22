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
import sys
import argparse
import asyncio
import logging
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
from urllib.parse import urlparse

# Import modules
from core.scanner import Scanner
from payloads.payload_manager import PayloadManager
from reports.report_generator import ReportGenerator
from config.config import Config
from utils.helpers import read_urls_from_file, save_results_to_file
from utils.external_tools import ExternalToolManager
from fake_useragent_data import UserAgentManager

# Banner function
def print_banner():
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
    print(banner)

# Handle keyboard interrupt
def signal_handler(sig, frame):
    """Handle keyboard interrupt (Ctrl+C)"""
    print("\nProgram terminated by user")
    for task in asyncio.all_tasks():
        task.cancel()

# Parse command line arguments
def parse_arguments():
    """
    Parse command line arguments
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(description="OpenX - Advanced Open Redirect Scanner")
    
    # Target options
    target_group = parser.add_argument_group("Target")
    target_group.add_argument("-u", "--url", help="Single URL to scan")
    target_group.add_argument("-l", "--url-file", help="File containing URLs to scan")
    target_group.add_argument("-d", "--domain", help="Target domain for passive URL collection")
    
    # Output options
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("-o", "--output", help="Output file to save results")
    output_group.add_argument("--report-format", choices=["text", "json", "html"], default="text", help="Report format")
    output_group.add_argument("-error", "--hide-error", action="store_true", help="Hide errors from output")
    output_group.add_argument("-hide", "--hide-vuln", action="store_true", help="Only display vulnerable URLs")
    output_group.add_argument("-debug", "--debug-mode", action="store_true", help="Enable debug mode")
    
    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("-s", "--smart-scan", action="store_true", help="Enable smart parameter-based payload injection")
    scan_group.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    scan_group.add_argument("--dry-run", action="store_true", help="Test without scanning")
    scan_group.add_argument("--browser", action="store_true", help="Use headless browser for deep verification")
    scan_group.add_argument("--concurrency", type=int, default=100, help="Number of concurrent requests")
    
    # Proxy options
    proxy_group = parser.add_argument_group("Proxy")
    proxy_group.add_argument("-p", "--proxy", help="HTTP proxy URL")
    
    # User agent options
    ua_group = parser.add_argument_group("User Agent")
    ua_group.add_argument("-ua", "--random-user-agent", action="store_true", help="Randomize User-Agent")
    
    # Configuration options
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument("--config", help="Path to configuration file")
    
    # Payload options
    payload_group = parser.add_argument_group("Payload")
    payload_group.add_argument("--custom-payloads", help="File containing custom payloads")
    payload_group.add_argument("--target-domains", help="Comma-separated list of target domains")
    
    # External tools options
    tools_group = parser.add_argument_group("External Tools")
    tools_group.add_argument("--use-external-tools", action="store_true", help="Use external tools for URL collection and filtering")
    tools_group.add_argument("--skip-url-collection", action="store_true", help="Skip URL collection phase")
    tools_group.add_argument("--skip-filtering", action="store_true", help="Skip URL filtering phase")
    tools_group.add_argument("--skip-probing", action="store_true", help="Skip HTTP probing phase")
    tools_group.add_argument("--tools-output", help="Output file for collected URLs")
    
    return parser.parse_args()

# Main function
async def main():
    """
    Main function
    """
    # Parse arguments
    args = parse_arguments()
    
    # Set up logging
    log_level = logging.DEBUG if args.debug_mode else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger('openx')
    
    # Print banner
    print_banner()
    
    # Load configuration
    config = Config()
    
    if args.config:
        config.load_from_file(args.config)
    else:
        config.load_default_config()
    
    # Override configuration with command line arguments
    if args.timeout:
        config.set('performance.timeout', args.timeout)
    
    if args.concurrency:
        config.set('performance.concurrency', args.concurrency)
    
    if args.proxy:
        config.set('proxy.url', args.proxy)
    
    if args.random_user_agent:
        config.set('user_agent.rotation', True)
    
    if args.browser:
        config.set('browser.enabled', True)
    
    # Initialize payload manager
    payload_manager = PayloadManager(config)
    
    # Set target domains if specified
    if args.target_domains:
        target_domains = [domain.strip() for domain in args.target_domains.split(',')]
        payload_manager.set_target_domains(target_domains)
    
    # Load custom payloads if specified
    if args.custom_payloads:
        payload_manager.load_custom_payloads(args.custom_payloads)
    
    # Get URLs to scan
    urls = []
    
    # Use external tools for URL collection if specified
    if args.use_external_tools and args.domain:
        logger.info(f"Using external tools for URL collection from domain: {args.domain}")
        
        # Initialize external tool manager
        tool_manager = ExternalToolManager(config.get_config())
        
        # Print available tools
        logger.info("Available external tools:")
        for tool, available in tool_manager.available_tools.items():
            status = "Available" if available else "Not available"
            logger.info(f"  - {tool}: {status}")
        
        # Process domain through the external tools pipeline
        collected_urls: Set[str] = set()
        filtered_urls: Set[str] = set()
        live_urls: Set[str] = set()
        
        # Step 1: Collect URLs (if not skipped)
        if not args.skip_url_collection:
            collected_urls = await tool_manager.collect_urls(args.domain)
            logger.info(f"Collected {len(collected_urls)} URLs from external tools")
        else:
            logger.info("Skipping URL collection phase")
            # If URL collection is skipped but we have a URL file, use that
            if args.url_file:
                collected_urls = set(read_urls_from_file(args.url_file))
                logger.info(f"Loaded {len(collected_urls)} URLs from file: {args.url_file}")
        
        # Step 2: Filter URLs (if not skipped)
        if not args.skip_filtering and collected_urls:
            filtered_urls = tool_manager.filter_redirect_urls(collected_urls)
            logger.info(f"Filtered {len(filtered_urls)} potential redirect URLs")
        else:
            logger.info("Skipping URL filtering phase")
            filtered_urls = collected_urls
        
        # Step 3: Probe URLs (if not skipped)
        if not args.skip_probing and filtered_urls:
            live_urls = await tool_manager.probe_live_urls(filtered_urls)
            logger.info(f"Found {len(live_urls)} live URLs")
        else:
            logger.info("Skipping HTTP probing phase")
            live_urls = filtered_urls
        
        # Save collected URLs to file if specified
        if args.tools_output and live_urls:
            with open(args.tools_output, 'w') as f:
                for url in live_urls:
                    f.write(f"{url}\n")
            logger.info(f"Saved {len(live_urls)} URLs to {args.tools_output}")
        
        # Use collected URLs for scanning
        urls = list(live_urls)
        
        # If we're using a domain for URL collection, add it to target domains for validation
        domain_parts = urlparse(args.domain).netloc.split('.')
        if len(domain_parts) >= 2:
            base_domain = '.'.join(domain_parts[-2:])
            payload_manager.add_target_domain(base_domain)
    else:
        # Traditional URL collection from arguments
        if args.url:
            urls.append(args.url)
        elif args.url_file:
            urls = read_urls_from_file(args.url_file)
    
    # Check if we have URLs to scan
    if not urls:
        logger.error("No targets to scan. Use -u/--url, -l/--url-file, or -d/--domain with --use-external-tools")
        sys.exit(1)
    
    # Initialize scanner
    scanner = Scanner(config, payload_manager)
    
    # Dry run
    if args.dry_run:
        logger.info(f"Dry run: would scan {len(urls)} URLs")
        sys.exit(0)
    
    # Run scan
    logger.info(f"Starting scan with {len(urls)} URLs")
    start_time = datetime.now()
    
    results = await scanner.scan_urls(urls)
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    # Get scan statistics
    stats = scanner.get_scan_stats()
    stats['scan_duration'] = duration
    
    # Print results
    print_results(results, stats, args.hide_vuln)
    
    # Generate report if output file is specified
    if args.output:
        report_generator = ReportGenerator(config)
        report = report_generator.generate_report(results, stats, args.output, args.report_format)
        logger.info(f"Report saved to {args.output}")
    
    return results
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
