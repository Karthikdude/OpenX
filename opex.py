#!/usr/bin/env python3
"""
OpenX - Open Redirect Vulnerability Scanner
Version 2.0

A powerful and modular tool for detecting open redirect vulnerabilities
with support for multiple scanning methods and external tool integration.
"""

import os
import sys
import logging
import argparse
import asyncio
import yaml
from typing import List, Dict, Any, Set, Optional
from datetime import datetime

# Add the parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import OpenX modules
from core.scanner import Scanner
from utils.crawler import Crawler
from utils.reporter import Reporter
from utils.external_tools import ExternalToolManager
from utils.intelligent_analyzer import IntelligentAnalyzer
from config.config import Config
from utils.helpers import read_urls_from_file, save_results_to_file
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

OpenX - Open Redirect Scanner
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
    parser = argparse.ArgumentParser(description="OpenX - Open Redirect Scanner")
    
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
    external_tools_group = parser.add_argument_group('External Tools Options')
    external_tools_group.add_argument('--use-external-tools', action='store_true',
                        help='Use external tools for URL collection, filtering, and probing')
    external_tools_group.add_argument('--skip-url-collection', action='store_true',
                        help='Skip URL collection phase when using external tools')
    external_tools_group.add_argument('--skip-url-filtering', action='store_true',
                        help='Skip URL filtering phase when using external tools')
    external_tools_group.add_argument('--skip-url-deduplication', action='store_true',
                        help='Skip URL deduplication phase when using external tools')
    external_tools_group.add_argument('--skip-url-probing', action='store_true',
                        help='Skip URL probing phase when using external tools')
    
    # Add arguments for intelligent analysis
    intelligent_group = parser.add_argument_group('Intelligent Analysis Options')
    intelligent_group.add_argument('--intelligent-analysis', action='store_true',
                        help='Use intelligent analysis to prioritize URLs based on risk score')
    intelligent_group.add_argument('--min-risk-level', choices=['info', 'low', 'medium', 'high'],
                        default='low', help='Minimum risk level to include in scanning (default: low)')
    
    return parser.parse_args()

# Main function
async def process_with_external_tools(args, config):
    """
    Process targets using external tools for URL collection, filtering, deduplication, and probing
    
    Args:
        args: Command line arguments
        config: Configuration dictionary
    
    Returns:
        Set[str]: Set of URLs to scan
    """
    logger.info("Processing targets with external tools")
    
    # Initialize external tool manager
    external_tool_manager = ExternalToolManager(config)
    
    urls_to_scan = set()
    
    # Process each target domain
    for target in args.targets:
        # Skip URL collection if specified
        if args.skip_url_collection:
            logger.info(f"Skipping URL collection for {target}")
            continue
        
        # Process domain through external tools pipeline
        # Note: The ExternalToolManager will handle the skip flags internally
        results = await external_tool_manager.process_domain(target)
        
        # Add live URLs to the set of URLs to scan
        if 'live_urls' in results and results['live_urls']:
            urls_to_scan.update(results['live_urls'])
    
    # Add any URLs from the URL list file
    if args.url_list:
        with open(args.url_list, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls_to_scan.add(line)
    
    logger.info(f"Collected {len(urls_to_scan)} URLs to scan using external tools")
    
    return urls_to_scan

# Prioritize URLs using intelligent analysis
async def prioritize_urls_with_intelligent_analysis(urls_to_scan, args, config):
    """
    Prioritize URLs using intelligent analysis
    
    Args:
        urls_to_scan (Set[str]): Set of URLs to scan
        args: Command line arguments
        config: Configuration dictionary
    
    Returns:
        List[str]: Prioritized list of URLs to scan
    """
    logger.info("Prioritizing URLs with intelligent analysis")
    
    # Initialize intelligent analyzer
    analyzer = IntelligentAnalyzer(config)
    
    # Analyze and categorize URLs
    analysis_results = analyzer.analyze_urls(list(urls_to_scan))
    
    # Determine which risk levels to include based on min_risk_level
    risk_levels = ['high', 'medium', 'low', 'info']
    min_level_index = risk_levels.index(args.min_risk_level)
    included_levels = risk_levels[:min_level_index + 1]
    
    # Combine results in order of priority (high -> medium -> low -> info)
    prioritized_urls = []
    for level in included_levels:
        level_urls = [result['url'] for result in analysis_results[level]]
        logger.info(f"Found {len(level_urls)} URLs with {level.upper()} risk level")
        prioritized_urls.extend(level_urls)
    
    logger.info(f"Prioritized {len(prioritized_urls)} URLs for scanning (minimum risk level: {args.min_risk_level})")
    
    # Log some examples of high and medium risk URLs if available
    if analysis_results['high'] and logger.level <= logging.INFO:
        high_risk_examples = [result['url'] for result in analysis_results['high'][:3]]
        logger.info(f"High risk URL examples: {', '.join(high_risk_examples)}")
    
    if analysis_results['medium'] and logger.level <= logging.INFO:
        medium_risk_examples = [result['url'] for result in analysis_results['medium'][:3]]
        logger.info(f"Medium risk URL examples: {', '.join(medium_risk_examples)}")
    
    return prioritized_urls

async def main():
    """
    Main function
    """
    # Parse command line arguments
    args = parse_arguments()
    
    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.debug_mode else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger('openx')
    
    # Display banner
    print_banner()
    
    # Initialize configuration
    config = {}
    if hasattr(args, 'config_file') and args.config_file:
        try:
            with open(args.config_file, 'r') as f:
                config = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading configuration file: {e}")
            return 1
    
    # Setup configuration for external tools
    if args.use_external_tools:
        config['external_tools'] = {
            'enabled': True,
            'skip_url_collection': args.skip_url_collection if hasattr(args, 'skip_url_collection') else False,
            'skip_url_filtering': args.skip_url_filtering if hasattr(args, 'skip_url_filtering') else False,
            'skip_url_deduplication': args.skip_url_deduplication if hasattr(args, 'skip_url_deduplication') else False,
            'skip_url_probing': args.skip_url_probing if hasattr(args, 'skip_url_probing') else False
        }
    
    # Setup configuration for intelligent analysis
    if args.intelligent_analysis:
        config['intelligent_analysis'] = {
            'enabled': True,
            'min_risk_level': args.min_risk_level
        }
    
    # Setup other configuration options
    if hasattr(args, 'timeout'):
        config['timeout'] = args.timeout
    if hasattr(args, 'concurrency'):
        config['concurrency'] = args.concurrency
    if hasattr(args, 'proxy'):
        config['proxy'] = args.proxy
    if hasattr(args, 'browser') and args.browser:
        config['browser'] = {'enabled': True}
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
