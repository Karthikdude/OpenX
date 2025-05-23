#!/usr/bin/env python3
"""
OpenX - Open Redirect Vulnerability Scanner
Version 3.0

A powerful and modular tool for detecting open redirect vulnerabilities
with support for distributed scanning, stealth features, advanced analysis,
and interactive modes.
"""

import os
import sys
import logging
import argparse
import asyncio
import yaml
from typing import List, Dict, Any, Set, Optional
from datetime import datetime
import traceback
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Add the parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import OpenX modules
from core.scanner import Scanner
from core.detection.enhanced_detection import EnhancedDetection
from utils.crawler import Crawler
from utils.reporter import Reporter
from utils.external_tools import ExternalToolManager
from utils.intelligent_analyzer import IntelligentAnalyzer
from utils.analysis.advanced_analysis import AdvancedAnalysis
from utils.evasion.stealth_features import StealthFeatures
from utils.evasion.waf_bypass import WAFBypass
from utils.distributed.coordinator import Coordinator
from utils.resume_manager import ResumeManager
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

OpenX v3.0 - Advanced Open Redirect Scanner
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
    target_group.add_argument("--resume", help="Resume a previous scan using session ID")
    target_group.add_argument("--list-sessions", action="store_true", help="List available resume sessions")
    
    # Output options
    output_group = parser.add_argument_group("Output")
    output_group.add_argument("-o", "--output", help="Output file to save results")
    output_group.add_argument("--report-format", choices=["text", "json", "html"], default="text", help="Report format")
    output_group.add_argument("-error", "--hide-error", action="store_true", help="Hide errors from output")
    output_group.add_argument("-hide", "--hide-vuln", action="store_true", help="Only display vulnerable URLs")
    output_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    output_group.add_argument("-debug", "--debug-mode", action="store_true", help="Enable debug mode")
    
    # Scan options
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("-s", "--smart-scan", action="store_true", help="Enable smart parameter-based payload injection")
    scan_group.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    scan_group.add_argument("--dry-run", action="store_true", help="Test without scanning")
    scan_group.add_argument("--browser", action="store_true", help="Use headless browser for deep verification")
    scan_group.add_argument("--concurrency", type=int, default=100, help="Number of concurrent requests")
    scan_group.add_argument("--enhanced-detection", action="store_true", help="Enable enhanced detection capabilities")
    scan_group.add_argument("--detect-chained", action="store_true", help="Enable detection of chained redirects")
    
    # Proxy options
    proxy_group = parser.add_argument_group("Proxy")
    proxy_group.add_argument("-p", "--proxy", help="HTTP proxy URL")
    proxy_group.add_argument("--proxy-list", help="File containing proxy URLs for rotation")
    
    # User agent options
    ua_group = parser.add_argument_group("User Agent")
    
    # Distributed scanning options
    distributed_group = parser.add_argument_group("Distributed Scanning")
    distributed_group.add_argument("--distributed", action="store_true", help="Enable distributed scanning")
    distributed_group.add_argument("--coordinator", help="Coordinator URL for distributed scanning")
    distributed_group.add_argument("--worker", action="store_true", help="Run as a worker node")
    distributed_group.add_argument("--worker-name", help="Worker node name")
    
    # Stealth options
    stealth_group = parser.add_argument_group("Stealth Features")
    stealth_group.add_argument("--stealth", action="store_true", help="Enable stealth features")
    stealth_group.add_argument("--traffic-mimicking", action="store_true", help="Enable traffic mimicking")
    stealth_group.add_argument("--timing-randomization", action="store_true", help="Enable timing randomization")
    stealth_group.add_argument("--session-management", action="store_true", help="Enable session management")
    
    # Advanced analysis options
    analysis_group = parser.add_argument_group("Advanced Analysis")
    analysis_group.add_argument("--advanced-analysis", action="store_true", help="Enable advanced analysis")
    analysis_group.add_argument("--generate-poc", action="store_true", help="Generate proof of concept for vulnerabilities")
    analysis_group.add_argument("--business-logic", action="store_true", help="Perform business logic analysis")
    analysis_group.add_argument("--risk-correlation", action="store_true", help="Identify related vulnerabilities")
    
    # Interactive mode options
    interactive_group = parser.add_argument_group("Interactive Mode")
    interactive_group.add_argument("--interactive-cli", action="store_true", help="Start interactive CLI mode")
    interactive_group.add_argument("--web-dashboard", action="store_true", help="Start web dashboard")
    interactive_group.add_argument("--dashboard-port", type=int, default=8000, help="Web dashboard port")
    ua_group.add_argument("-ua", "--random-user-agent", action="store_true", help="Randomize User-Agent")
    
    # Configuration options
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument("--config", help="Path to configuration file")
    config_group.add_argument("--save-config", help="Save current configuration to file")
    config_group.add_argument("--check-config", action="store_true", help="Check configuration and environment")
    
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

def check_config():
    """Check configuration and environment for issues"""
    import shutil
    import platform
    import psutil
    from colorama import Fore, Style
    
    print(f"{Fore.CYAN}\n=== OpenX Configuration Check ==={Style.RESET_ALL}")
    
    # System information
    print(f"\n{Fore.CYAN}System Information:{Style.RESET_ALL}")
    print(f"OS: {platform.system()} {platform.release()}")
    print(f"Python: {platform.python_version()}")
    print(f"CPU: {psutil.cpu_count(logical=True)} cores")
    memory = psutil.virtual_memory()
    print(f"Memory: {memory.total / (1024 * 1024 * 1024):.2f} GB total, {memory.available / (1024 * 1024 * 1024):.2f} GB available")
    
    # Check for required dependencies
    print(f"\n{Fore.CYAN}Required Dependencies:{Style.RESET_ALL}")
    required_modules = ['aiohttp', 'colorama', 'pyyaml', 'jinja2', 'rich', 'beautifulsoup4', 'tqdm', 'psutil']
    for module in required_modules:
        try:
            __import__(module)
            print(f"{Fore.GREEN}✓ {module}{Style.RESET_ALL}")
        except ImportError:
            print(f"{Fore.RED}✗ {module} (missing){Style.RESET_ALL}")
    
    # Check for optional dependencies
    print(f"\n{Fore.CYAN}Optional Dependencies:{Style.RESET_ALL}")
    optional_modules = {
        'playwright': 'Browser automation (enhanced detection)',
        'selenium': 'Browser automation (alternative)',
        'webdriver_manager': 'WebDriver management for Selenium',
        'sklearn': 'Machine learning capabilities'
    }
    for module, description in optional_modules.items():
        try:
            __import__(module)
            print(f"{Fore.GREEN}✓ {module} - {description}{Style.RESET_ALL}")
        except ImportError:
            print(f"{Fore.YELLOW}○ {module} - {description} (not installed){Style.RESET_ALL}")
    
    # Check for external tools
    print(f"\n{Fore.CYAN}External Tools:{Style.RESET_ALL}")
    external_tools = [
        ('waybackurls', 'URL collection'),
        ('gau', 'URL collection'),
        ('urlfinder', 'URL collection'),
        ('gf', 'URL filtering'),
        ('httpx', 'HTTP probing'),
        ('httprobe', 'HTTP probing')
    ]
    for tool, description in external_tools:
        if shutil.which(tool):
            print(f"{Fore.GREEN}✓ {tool} - {description}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}○ {tool} - {description} (not found in PATH){Style.RESET_ALL}")
    
    # Check for configuration directories
    print(f"\n{Fore.CYAN}Configuration Directories:{Style.RESET_ALL}")
    config_dirs = [
        ('config', 'Configuration files'),
        ('payloads', 'Payload files'),
        ('reports', 'Report templates'),
        ('utils', 'Utility modules')
    ]
    for directory, description in config_dirs:
        if os.path.isdir(directory):
            print(f"{Fore.GREEN}✓ {directory} - {description}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ {directory} - {description} (missing){Style.RESET_ALL}")
    
    # Check for network connectivity
    print(f"\n{Fore.CYAN}Network Connectivity:{Style.RESET_ALL}")
    try:
        import socket
        socket.create_connection(("www.google.com", 80), timeout=5)
        print(f"{Fore.GREEN}✓ Internet connection available{Style.RESET_ALL}")
    except (socket.timeout, socket.error):
        print(f"{Fore.RED}✗ Internet connection unavailable{Style.RESET_ALL}")
    
    # Summary
    print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
    print(f"OpenX is ready to use. Run with -v or --debug for detailed logging.")
    print(f"For help, run: openx --help")
    print(f"{Fore.CYAN}==================================={Style.RESET_ALL}\n")

def setup_logging(args):
    """Set up logging based on command line arguments"""
    # Create logger
    logger = logging.getLogger('openx')
    
    # Set log level based on arguments
    if args.debug_mode:
        log_level = logging.DEBUG
    elif args.verbose:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING
    
    logger.setLevel(log_level)
    
    # Create console handler with appropriate formatting
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    
    # Create formatter
    if args.debug_mode:
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s() - %(message)s')
    elif args.verbose:
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    else:
        formatter = logging.Formatter('%(levelname)s: %(message)s')
    
    console_handler.setFormatter(formatter)
    
    # Add handler to logger if not already added
    if not logger.handlers:
        logger.addHandler(console_handler)
    
    return logger

async def main():
    """Main function"""
    # Set up signal handler for keyboard interrupt
    signal.signal(signal.SIGINT, signal_handler)
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Check configuration if requested
    if args.check_config:
        check_config()
        return
    
    # Set up logging
    logger = setup_logging(args)
    
    # Log startup information
    logger.info(f"OpenX v3.0 starting at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.debug(f"Command line arguments: {args}")
    
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
        logger.debug("Exiting due to no targets")
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

def apply_config_settings(config, args):
    """
    Apply configuration settings from command line arguments
    
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


# Entry point for command-line tool
def main_cli():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(Fore.RED + "\nProgram terminated by user")
    except Exception as e:
        print(Fore.RED + f"\nAn error occurred: {e}")
        logger = logging.getLogger('openx')
        logger.error(f"Unhandled exception: {e}")
        
        # Print traceback in debug mode
        if logger.level <= logging.DEBUG:
            print(Fore.RED + "\nTraceback:")
            traceback.print_exc()
        else:
            print(Fore.YELLOW + "\nRun with --debug for detailed error information")

# Entry point when run directly
if __name__ == "__main__":
    main_cli()
