#!/usr/bin/env python3
"""
Interactive CLI Mode for OpenX
Provides a command-line interface for real-time testing
"""

import os
import sys
import cmd
import json
import logging
import asyncio
import time
import shlex
from typing import Dict, List, Set, Tuple, Any, Optional
from colorama import Fore, Style, init

# Initialize colorama
init()

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import OpenX modules
from core.scanner import Scanner
from payloads.payload_manager import PayloadManager
from config.config import Config
from utils.helpers import read_urls_from_file

logger = logging.getLogger('openx.interactive.cli')

class OpenXInteractiveCLI(cmd.Cmd):
    """Interactive CLI for OpenX"""
    
    intro = f"""
{Fore.CYAN}
 ██████╗ ██████╗ ███████╗███╗   ██╗██╗  ██╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║╚██╗██╔╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ╚███╔╝
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ██╔██╗
╚██████╔╝██║     ███████╗██║ ╚████║██╔╝ ██╗
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝
{Style.RESET_ALL}
{Fore.GREEN}OpenX Interactive CLI Mode{Style.RESET_ALL}
Type {Fore.YELLOW}help{Style.RESET_ALL} or {Fore.YELLOW}?{Style.RESET_ALL} to list commands.
Type {Fore.YELLOW}exit{Style.RESET_ALL} to exit.
"""
    prompt = f"{Fore.CYAN}openx> {Style.RESET_ALL}"
    
    def __init__(self):
        """Initialize the interactive CLI"""
        super().__init__()
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Load configuration
        self.config = Config().load_config()
        
        # Initialize payload manager
        self.payload_manager = PayloadManager(self.config)
        
        # Initialize scanner
        self.scanner = Scanner(self.config, self.payload_manager)
        
        # State variables
        self.current_urls = []
        self.last_results = []
        self.scan_history = []
        self.scan_in_progress = False
        self.start_time = 0
        
        # Event loop
        self.loop = asyncio.get_event_loop()
    
    def do_scan(self, arg):
        """
        Scan a URL or multiple URLs for open redirect vulnerabilities
        Usage: scan <url> | -f <file>
        """
        args = shlex.split(arg)
        
        if not args:
            print(f"{Fore.RED}Error: URL or file required{Style.RESET_ALL}")
            print("Usage: scan <url> | -f <file>")
            return
        
        urls = []
        
        if args[0] == '-f':
            if len(args) < 2:
                print(f"{Fore.RED}Error: File path required{Style.RESET_ALL}")
                return
            
            try:
                urls = read_urls_from_file(args[1])
                print(f"{Fore.GREEN}Loaded {len(urls)} URLs from {args[1]}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error loading URLs from file: {e}{Style.RESET_ALL}")
                return
        else:
            urls = [args[0]]
        
        self.current_urls = urls
        self._run_scan(urls)
    
    def _run_scan(self, urls):
        """Run a scan on the specified URLs"""
        if self.scan_in_progress:
            print(f"{Fore.YELLOW}A scan is already in progress{Style.RESET_ALL}")
            return
        
        self.scan_in_progress = True
        self.start_time = time.time()
        
        print(f"{Fore.GREEN}Starting scan of {len(urls)} URLs...{Style.RESET_ALL}")
        
        try:
            # Run the scan asynchronously
            self.last_results = self.loop.run_until_complete(self.scanner.scan_urls(urls))
            
            # Add to history
            scan_duration = time.time() - self.start_time
            self.scan_history.append({
                'timestamp': time.time(),
                'urls': len(urls),
                'results': len(self.last_results),
                'vulnerable': sum(1 for r in self.last_results if r.get('is_vulnerable', False)),
                'duration': scan_duration
            })
            
            # Print summary
            self._print_scan_summary(self.last_results, scan_duration)
        except Exception as e:
            print(f"{Fore.RED}Error during scan: {e}{Style.RESET_ALL}")
        finally:
            self.scan_in_progress = False
    
    def _print_scan_summary(self, results, duration):
        """Print a summary of scan results"""
        vulnerable_count = sum(1 for r in results if r.get('is_vulnerable', False))
        
        print(f"\n{Fore.GREEN}Scan completed in {duration:.2f} seconds{Style.RESET_ALL}")
        print(f"Total URLs scanned: {len(self.current_urls)}")
        print(f"Vulnerable URLs found: {vulnerable_count}")
        
        if vulnerable_count > 0:
            print(f"\n{Fore.RED}Vulnerable URLs:{Style.RESET_ALL}")
            for result in results:
                if result.get('is_vulnerable', False):
                    url = result.get('url', 'Unknown')
                    severity = result.get('severity', 'Unknown')
                    print(f"  - {url} (Severity: {severity})")
    
    def do_config(self, arg):
        """
        View or modify configuration settings
        Usage: config [setting] [value] | list
        """
        args = shlex.split(arg)
        
        if not args or args[0] == 'list':
            print(f"{Fore.GREEN}Current Configuration:{Style.RESET_ALL}")
            for key, value in self.config.items():
                if isinstance(value, dict):
                    print(f"{key}:")
                    for subkey, subvalue in value.items():
                        print(f"  {subkey}: {subvalue}")
                else:
                    print(f"{key}: {value}")
            return
        
        if len(args) < 2:
            print(f"{Fore.RED}Error: Both setting and value required{Style.RESET_ALL}")
            return
        
        setting = args[0]
        value = args[1]
        
        # Handle nested settings
        if '.' in setting:
            main_key, sub_key = setting.split('.', 1)
            if main_key not in self.config:
                self.config[main_key] = {}
            
            # Convert value to appropriate type
            if value.lower() == 'true':
                value = True
            elif value.lower() == 'false':
                value = False
            elif value.isdigit():
                value = int(value)
            
            self.config[main_key][sub_key] = value
            print(f"{Fore.GREEN}Set {main_key}.{sub_key} to {value}{Style.RESET_ALL}")
        else:
            # Convert value to appropriate type
            if value.lower() == 'true':
                value = True
            elif value.lower() == 'false':
                value = False
            elif value.isdigit():
                value = int(value)
            
            self.config[setting] = value
            print(f"{Fore.GREEN}Set {setting} to {value}{Style.RESET_ALL}")
        
        # Reinitialize scanner with new config
        self.scanner = Scanner(self.config, self.payload_manager)
    
    def do_payloads(self, arg):
        """
        View or add custom payloads
        Usage: payloads [list | add <payload>]
        """
        args = shlex.split(arg)
        
        if not args or args[0] == 'list':
            payloads = self.payload_manager.get_all_payloads()
            print(f"{Fore.GREEN}Available Payloads ({len(payloads)}):{Style.RESET_ALL}")
            for i, payload in enumerate(payloads):
                print(f"{i+1}. {payload}")
            return
        
        if args[0] == 'add' and len(args) > 1:
            payload = args[1]
            self.payload_manager.custom_payloads.append(payload)
            print(f"{Fore.GREEN}Added custom payload: {payload}{Style.RESET_ALL}")
            return
        
        print(f"{Fore.RED}Invalid command. Usage: payloads [list | add <payload>]{Style.RESET_ALL}")
    
    def do_history(self, arg):
        """
        View scan history
        Usage: history
        """
        if not self.scan_history:
            print(f"{Fore.YELLOW}No scan history available{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}Scan History:{Style.RESET_ALL}")
        for i, entry in enumerate(self.scan_history):
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry['timestamp']))
            print(f"{i+1}. {timestamp} - {entry['urls']} URLs, {entry['vulnerable']} vulnerable, {entry['duration']:.2f}s")
    
    def do_results(self, arg):
        """
        View detailed results from the last scan
        Usage: results [all | vulnerable | <index>]
        """
        if not self.last_results:
            print(f"{Fore.YELLOW}No scan results available{Style.RESET_ALL}")
            return
        
        args = shlex.split(arg)
        
        if not args or args[0] == 'all':
            # Show all results
            for i, result in enumerate(self.last_results):
                self._print_result(i, result)
            return
        
        if args[0] == 'vulnerable':
            # Show only vulnerable results
            vulnerable_results = [r for r in self.last_results if r.get('is_vulnerable', False)]
            if not vulnerable_results:
                print(f"{Fore.YELLOW}No vulnerable URLs found{Style.RESET_ALL}")
                return
            
            for i, result in enumerate(vulnerable_results):
                self._print_result(i, result)
            return
        
        try:
            # Show specific result by index
            index = int(args[0]) - 1
            if 0 <= index < len(self.last_results):
                self._print_result(index, self.last_results[index], detailed=True)
            else:
                print(f"{Fore.RED}Invalid index. Range: 1-{len(self.last_results)}{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Invalid argument. Usage: results [all | vulnerable | <index>]{Style.RESET_ALL}")
    
    def _print_result(self, index, result, detailed=False):
        """Print a scan result"""
        url = result.get('url', 'Unknown')
        is_vulnerable = result.get('is_vulnerable', False)
        severity = result.get('severity', 'None')
        
        if is_vulnerable:
            status = f"{Fore.RED}VULNERABLE{Style.RESET_ALL}"
        else:
            status = f"{Fore.GREEN}SAFE{Style.RESET_ALL}"
        
        print(f"{index+1}. {url} - {status} (Severity: {severity})")
        
        if detailed:
            print(f"\n{Fore.CYAN}Detailed Information:{Style.RESET_ALL}")
            for key, value in result.items():
                if key not in ['url', 'is_vulnerable', 'severity']:
                    print(f"  {key}: {value}")
    
    def do_test(self, arg):
        """
        Test a single URL with specific payload
        Usage: test <url> <payload>
        """
        args = shlex.split(arg)
        
        if len(args) < 2:
            print(f"{Fore.RED}Error: URL and payload required{Style.RESET_ALL}")
            print("Usage: test <url> <payload>")
            return
        
        url = args[0]
        payload = args[1]
        
        print(f"{Fore.GREEN}Testing {url} with payload: {payload}{Style.RESET_ALL}")
        
        # Create a test URL with the payload
        test_url = self.payload_manager.inject_payload(url, payload)
        
        # Run the test
        self.scan_in_progress = True
        try:
            results = self.loop.run_until_complete(self.scanner.scan_urls([test_url]))
            self.last_results = results
            
            # Print results
            if results:
                self._print_result(0, results[0], detailed=True)
            else:
                print(f"{Fore.YELLOW}No results returned{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error during test: {e}{Style.RESET_ALL}")
        finally:
            self.scan_in_progress = False
    
    def do_browser(self, arg):
        """
        Test a URL using headless browser
        Usage: browser <url>
        """
        if not arg:
            print(f"{Fore.RED}Error: URL required{Style.RESET_ALL}")
            print("Usage: browser <url>")
            return
        
        url = arg.strip()
        
        # Enable browser testing
        old_browser_enabled = self.config.get('browser', {}).get('enabled', False)
        if 'browser' not in self.config:
            self.config['browser'] = {}
        self.config['browser']['enabled'] = True
        
        # Reinitialize scanner with new config
        self.scanner = Scanner(self.config, self.payload_manager)
        
        print(f"{Fore.GREEN}Testing {url} with headless browser...{Style.RESET_ALL}")
        
        # Run the test
        self.scan_in_progress = True
        try:
            results = self.loop.run_until_complete(self.scanner.scan_urls([url]))
            self.last_results = results
            
            # Print results
            if results:
                self._print_result(0, results[0], detailed=True)
            else:
                print(f"{Fore.YELLOW}No results returned{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error during browser test: {e}{Style.RESET_ALL}")
        finally:
            self.scan_in_progress = False
            
            # Restore previous browser setting
            self.config['browser']['enabled'] = old_browser_enabled
            self.scanner = Scanner(self.config, self.payload_manager)
    
    def do_exit(self, arg):
        """Exit the interactive CLI"""
        print(f"{Fore.GREEN}Exiting OpenX Interactive CLI. Goodbye!{Style.RESET_ALL}")
        return True
    
    def do_quit(self, arg):
        """Exit the interactive CLI"""
        return self.do_exit(arg)
    
    def do_help(self, arg):
        """Show help information"""
        if arg:
            # Show help for specific command
            super().do_help(arg)
        else:
            # Show general help
            print(f"\n{Fore.GREEN}OpenX Interactive CLI Commands:{Style.RESET_ALL}")
            print(f"  {Fore.YELLOW}scan <url> | -f <file>{Style.RESET_ALL} - Scan URL(s) for open redirect vulnerabilities")
            print(f"  {Fore.YELLOW}test <url> <payload>{Style.RESET_ALL} - Test a specific URL with a specific payload")
            print(f"  {Fore.YELLOW}browser <url>{Style.RESET_ALL} - Test a URL using headless browser")
            print(f"  {Fore.YELLOW}config [setting] [value] | list{Style.RESET_ALL} - View or modify configuration")
            print(f"  {Fore.YELLOW}payloads [list | add <payload>]{Style.RESET_ALL} - View or add custom payloads")
            print(f"  {Fore.YELLOW}results [all | vulnerable | <index>]{Style.RESET_ALL} - View scan results")
            print(f"  {Fore.YELLOW}history{Style.RESET_ALL} - View scan history")
            print(f"  {Fore.YELLOW}help{Style.RESET_ALL} - Show this help message")
            print(f"  {Fore.YELLOW}exit{Style.RESET_ALL} - Exit the interactive CLI")

def main():
    """Main entry point for the interactive CLI"""
    try:
        cli = OpenXInteractiveCLI()
        cli.cmdloop()
    except KeyboardInterrupt:
        print(f"\n{Fore.GREEN}Exiting OpenX Interactive CLI. Goodbye!{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

def main_cli():
    """Entry point for the command-line tool"""
    cli = InteractiveCLI()
    cli.start()

if __name__ == "__main__":
    main()
