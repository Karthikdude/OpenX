#!/usr/bin/env python3
"""
External Tools Integration Module for OpenX
Provides integration with popular external security tools for URL collection,
filtering, and HTTP probing.
"""

import os
import sys
import json
import logging
import subprocess
import shutil
import re
from typing import List, Dict, Set, Optional, Tuple, Any, Union
from pathlib import Path
import tempfile
import asyncio
from urllib.parse import urlparse

logger = logging.getLogger('openx.external_tools')

class ExternalToolManager:
    """
    Manages the integration with external security tools for OpenX
    
    Supported tools:
    - URL Collection: waybackurls, gau, urlfinder
    - URL Filtering: gf
    - HTTP Probing: httpx, httprobe
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the external tool manager
        
        Args:
            config (Optional[Dict[str, Any]]): Configuration dictionary
        """
        self.config = config or {}
        self.available_tools = self._detect_available_tools()
        
        # Set up logging
        log_level = self.config.get('general', {}).get('verbose', False)
        logger.setLevel(logging.DEBUG if log_level else logging.INFO)
        
        # Temporary directory for storing intermediate results
        self.temp_dir = tempfile.mkdtemp(prefix="openx_")
        logger.debug(f"Created temporary directory: {self.temp_dir}")
        
        # GF patterns directory
        self.gf_patterns_dir = self._get_gf_patterns_dir()
        
        # Initialize results
        self.results = {
            'collected_urls': set(),
            'filtered_urls': set(),
            'live_urls': set()
        }
    
    def __del__(self):
        """Cleanup temporary files on destruction"""
        try:
            if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
                import shutil
                shutil.rmtree(self.temp_dir)
                logger.debug(f"Removed temporary directory: {self.temp_dir}")
        except Exception as e:
            logger.error(f"Error cleaning up temporary directory: {e}")
    
    def _detect_available_tools(self) -> Dict[str, bool]:
        """
        Detect which external tools are available in the system
        
        Returns:
            Dict[str, bool]: Dictionary of tool availability
        """
        tools = {
            # URL Collection
            'waybackurls': False,
            'gau': False,
            'urlfinder': False,
            
            # URL Filtering
            'gf': False,
            
            # URL Deduplication
            'uro': False,
            
            # HTTP Probing
            'httpx': False,
            'httprobe': False
        }
        
        for tool in tools:
            if shutil.which(tool):
                tools[tool] = True
                logger.info(f"Detected {tool} in system PATH")
        
        return tools
    
    def _get_gf_patterns_dir(self) -> Optional[str]:
        """
        Get the GF patterns directory
        
        Returns:
            Optional[str]: Path to GF patterns directory
        """
        if not self.available_tools['gf']:
            return None
        
        # Check common locations for GF patterns
        home_dir = os.path.expanduser("~")
        common_locations = [
            os.path.join(home_dir, ".gf"),
            os.path.join(home_dir, "go", "src", "github.com", "tomnomnom", "gf", "examples")
        ]
        
        for location in common_locations:
            if os.path.exists(location) and os.path.isdir(location):
                logger.info(f"Found GF patterns directory: {location}")
                return location
        
        return None
    
    def _run_command(self, command: List[str], input_data: Optional[str] = None) -> Tuple[bool, str, str]:
        """
        Run a command and return its output
        
        Args:
            command (List[str]): Command to run
            input_data (Optional[str]): Input data to pass to the command
            
        Returns:
            Tuple[bool, str, str]: Success status, stdout, stderr
        """
        try:
            logger.debug(f"Running command: {' '.join(command)}")
            
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if input_data else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(input=input_data)
            success = process.returncode == 0
            
            if not success:
                logger.warning(f"Command failed with exit code {process.returncode}: {stderr}")
            
            return success, stdout, stderr
        
        except Exception as e:
            logger.error(f"Error running command: {e}")
            return False, "", str(e)
    
    async def collect_urls(self, domain: str) -> Set[str]:
        """
        Collect URLs from various sources using available tools
        
        Args:
            domain (str): Target domain
            
        Returns:
            Set[str]: Set of collected URLs
        """
        collected_urls = set()
        collection_tasks = []
        
        # Check if any URL collection tools are available
        if not any(self.available_tools[tool] for tool in ['waybackurls', 'gau', 'urlfinder']):
            logger.warning("No URL collection tools available. Skipping URL collection phase.")
            return collected_urls
        
        logger.info(f"Starting URL collection for domain: {domain}")
        
        # Create tasks for each available tool
        if self.available_tools['waybackurls']:
            collection_tasks.append(self._collect_with_waybackurls(domain))
        
        if self.available_tools['gau']:
            collection_tasks.append(self._collect_with_gau(domain))
        
        if self.available_tools['urlfinder']:
            collection_tasks.append(self._collect_with_urlfinder(domain))
        
        # Run all tasks concurrently
        results = await asyncio.gather(*collection_tasks)
        
        # Combine results
        for urls in results:
            collected_urls.update(urls)
        
        logger.info(f"Collected {len(collected_urls)} unique URLs from all sources")
        self.results['collected_urls'] = collected_urls
        
        return collected_urls
    
    async def _collect_with_waybackurls(self, domain: str) -> Set[str]:
        """
        Collect URLs using waybackurls
        
        Args:
            domain (str): Target domain
            
        Returns:
            Set[str]: Set of collected URLs
        """
        urls = set()
        
        # Run waybackurls
        command = ["waybackurls", domain]
        success, stdout, stderr = self._run_command(command)
        
        if success:
            # Parse output
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    urls.add(line)
            
            logger.info(f"Collected {len(urls)} URLs using waybackurls")
        else:
            logger.error(f"Failed to run waybackurls: {stderr}")
        
        return urls
    
    async def _collect_with_gau(self, domain: str) -> Set[str]:
        """
        Collect URLs using gau (GetAllUrls)
        
        Args:
            domain (str): Target domain
            
        Returns:
            Set[str]: Set of collected URLs
        """
        urls = set()
        
        # Run gau
        command = ["gau", domain]
        success, stdout, stderr = self._run_command(command)
        
        if success:
            # Parse output
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    urls.add(line)
            
            logger.info(f"Collected {len(urls)} URLs using gau")
        else:
            logger.error(f"Failed to run gau: {stderr}")
        
        return urls
    
    async def _collect_with_urlfinder(self, domain: str) -> Set[str]:
        """
        Collect URLs using urlfinder
        
        Args:
            domain (str): Target domain
            
        Returns:
            Set[str]: Set of collected URLs
        """
        urls = set()
        
        # Run urlfinder
        command = ["urlfinder", "-d", domain]
        success, stdout, stderr = self._run_command(command)
        
        if success:
            # Parse output
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    urls.add(line)
            
            logger.info(f"Collected {len(urls)} URLs using urlfinder")
        else:
            logger.error(f"Failed to run urlfinder: {stderr}")
        
        return urls
    
    def filter_redirect_urls(self, urls: Set[str]) -> Set[str]:
        """
        Filter URLs that are likely to involve redirection behavior
        
        Args:
            urls (Set[str]): Set of URLs to filter
            
        Returns:
            Set[str]: Set of filtered URLs
        """
        filtered_urls = set()
        
        # Check if GF is available
        if self.available_tools['gf'] and self.gf_patterns_dir:
            logger.info("Using GF to filter redirect URLs")
            filtered_urls = self._filter_with_gf(urls)
        else:
            logger.info("GF not available, using built-in filtering")
            filtered_urls = self._filter_with_builtin(urls)
        
        logger.info(f"Filtered {len(filtered_urls)} potential redirect URLs")
        self.results['filtered_urls'] = filtered_urls
        
        return filtered_urls
    
    def _filter_with_gf(self, urls: Set[str]) -> Set[str]:
        """
        Filter URLs using GF with redirect pattern
        
        Args:
            urls (Set[str]): Set of URLs to filter
            
        Returns:
            Set[str]: Set of filtered URLs
        """
        filtered_urls = set()
        
        # Create temporary file with URLs
        urls_file = os.path.join(self.temp_dir, "urls.txt")
        with open(urls_file, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")
        
        # Run GF with redirect pattern
        command = ["gf", "redirect", urls_file]
        success, stdout, stderr = self._run_command(command)
        
        if success:
            # Parse output
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    filtered_urls.add(line)
            
            logger.info(f"Filtered {len(filtered_urls)} URLs using GF redirect pattern")
        else:
            logger.error(f"Failed to run GF: {stderr}")
            # Fall back to built-in filtering
            filtered_urls = self._filter_with_builtin(urls)
        
        return filtered_urls
    
    def _filter_with_builtin(self, urls: Set[str]) -> Set[str]:
        """
        Filter URLs using built-in patterns for redirect parameters
        
        Args:
            urls (Set[str]): Set of URLs to filter
            
        Returns:
            Set[str]: Set of filtered URLs
        """
        filtered_urls = set()
        
        # Common redirect parameter patterns
        redirect_params = [
            'url', 'link', 'redirect', 'redir', 'next', 'goto', 'target',
            'destination', 'return', 'returnto', 'return_to', 'returnurl',
            'return_url', 'continue', 'forward', 'forward_url', 'location',
            'redirect_to', 'redirect_uri', 'redirecturl', 'redirect_url',
            'u', 'uri', 'path', 'r', 'ref', 'q', 'to', 'out', 'view', 'dir'
        ]
        
        # Create regex pattern for redirect parameters
        pattern = re.compile(r'[?&](' + '|'.join(redirect_params) + r')=', re.IGNORECASE)
        
        # Filter URLs
        for url in urls:
            if pattern.search(url):
                filtered_urls.add(url)
        
        logger.info(f"Filtered {len(filtered_urls)} URLs using built-in patterns")
        
        return filtered_urls
    
    def deduplicate_urls(self, urls: Set[str]) -> Set[str]:
        """
        Deduplicate and normalize URLs using uro if available
        
        Args:
            urls (Set[str]): Set of URLs to deduplicate
            
        Returns:
            Set[str]: Set of deduplicated URLs
        """
        if not urls:
            return set()
            
        # Check if uro is available
        if not self.available_tools['uro']:
            logger.warning("Uro is not available. Skipping URL deduplication phase.")
            return urls  # Return original URLs if uro is not available
        
        logger.info(f"Starting URL deduplication for {len(urls)} URLs using uro")
        
        # Create temporary file with URLs
        urls_file = os.path.join(self.temp_dir, "urls_to_deduplicate.txt")
        with open(urls_file, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")
        
        # Run uro for deduplication
        output_file = os.path.join(self.temp_dir, "deduplicated_urls.txt")
        command = ["uro", "-i", urls_file, "-o", output_file]
        success, stdout, stderr = self._run_command(command)
        
        deduplicated_urls = set()
        
        if success:
            # Read deduplicated URLs from output file
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            deduplicated_urls.add(line)
            
            logger.info(f"Deduplicated {len(urls)} URLs to {len(deduplicated_urls)} unique URLs using uro")
        else:
            logger.error(f"Failed to run uro: {stderr}")
            deduplicated_urls = urls  # Return original URLs if uro fails
        
        self.results['deduplicated_urls'] = deduplicated_urls
        return deduplicated_urls
    
    async def probe_live_urls(self, urls: Set[str]) -> Set[str]:
        """
        Probe URLs to check if they are live
        
        Args:
            urls (Set[str]): Set of URLs to probe
            
        Returns:
            Set[str]: Set of live URLs
        """
        live_urls = set()
        
        # Check if any HTTP probing tools are available
        if not any(self.available_tools[tool] for tool in ['httpx', 'httprobe']):
            logger.warning("No HTTP probing tools available. Skipping probing phase.")
            return urls  # Return all URLs if no probing tools available
        
        logger.info(f"Starting HTTP probing for {len(urls)} URLs")
        
        # Create temporary file with URLs
        urls_file = os.path.join(self.temp_dir, "urls_to_probe.txt")
        with open(urls_file, 'w') as f:
            for url in urls:
                f.write(f"{url}\n")
        
        # Prefer httpx over httprobe if both are available
        if self.available_tools['httpx']:
            live_urls = await self._probe_with_httpx(urls_file)
        elif self.available_tools['httprobe']:
            live_urls = await self._probe_with_httprobe(urls_file)
        
        logger.info(f"Found {len(live_urls)} live URLs")
        self.results['live_urls'] = live_urls
        
        return live_urls
    
    async def _probe_with_httpx(self, urls_file: str) -> Set[str]:
        """
        Probe URLs using httpx
        
        Args:
            urls_file (str): Path to file containing URLs
            
        Returns:
            Set[str]: Set of live URLs
        """
        live_urls = set()
        
        # Run httpx
        command = [
            "httpx", 
            "-l", urls_file,
            "-silent",
            "-follow-redirects",
            "-status-code",
            "-timeout", "10"
        ]
        
        success, stdout, stderr = self._run_command(command)
        
        if success:
            # Parse output (format: url [status_code])
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    parts = line.split()
                    if len(parts) >= 2:
                        url = parts[0]
                        status_code = parts[1].strip('[]')
                        
                        # Consider 2xx and 3xx as live
                        if status_code.startswith(('2', '3')):
                            live_urls.add(url)
            
            logger.info(f"Found {len(live_urls)} live URLs using httpx")
        else:
            logger.error(f"Failed to run httpx: {stderr}")
        
        return live_urls
    
    async def _probe_with_httprobe(self, urls_file: str) -> Set[str]:
        """
        Probe URLs using httprobe
        
        Args:
            urls_file (str): Path to file containing URLs
            
        Returns:
            Set[str]: Set of live URLs
        """
        live_urls = set()
        
        # Run httprobe
        with open(urls_file, 'r') as f:
            urls_content = f.read()
        
        command = ["httprobe", "-t", "10000"]
        success, stdout, stderr = self._run_command(command, input_data=urls_content)
        
        if success:
            # Parse output
            for line in stdout.splitlines():
                line = line.strip()
                if line:
                    live_urls.add(line)
            
            logger.info(f"Found {len(live_urls)} live URLs using httprobe")
        else:
            logger.error(f"Failed to run httprobe: {stderr}")
        
        return live_urls
    
    async def process_domain(self, domain: str) -> Dict[str, Set[str]]:
        """
        Process a domain through the entire pipeline:
        1. Collect URLs
        2. Filter for redirect patterns
        3. Deduplicate URLs
        4. Probe for live URLs
        
        Args:
            domain (str): Target domain
            
        Returns:
            Dict[str, Set[str]]: Dictionary with results from each stage
        """
        logger.info(f"Starting external tools pipeline for domain: {domain}")
        
        # Step 1: Collect URLs
        collected_urls = await self.collect_urls(domain)
        
        # Step 2: Filter for redirect patterns
        filtered_urls = self.filter_redirect_urls(collected_urls)
        
        # Step 3: Deduplicate URLs
        deduplicated_urls = self.deduplicate_urls(filtered_urls)
        
        # Step 4: Probe for live URLs
        live_urls = await self.probe_live_urls(deduplicated_urls)
        
        logger.info(f"External tools pipeline completed for domain: {domain}")
        logger.info(f"Results: {len(collected_urls)} collected, {len(filtered_urls)} filtered, "
                  f"{len(deduplicated_urls)} deduplicated, {len(live_urls)} live")
        
        return self.results
    
    def create_redirect_pattern(self) -> bool:
        """
        Create a custom redirect pattern for GF if it doesn't exist
        
        Returns:
            bool: True if pattern was created or already exists, False otherwise
        """
        if not self.available_tools['gf'] or not self.gf_patterns_dir:
            logger.warning("GF not available. Cannot create redirect pattern.")
            return False
        
        pattern_file = os.path.join(self.gf_patterns_dir, "redirect.json")
        
        # Check if pattern already exists
        if os.path.exists(pattern_file):
            logger.info("GF redirect pattern already exists")
            return True
        
        # Create pattern file
        pattern = {
            "flags": "-iE",
            "pattern": "([?&](url|redirect|next|goto|target|destination|return|returnto|return_to|returnurl|return_url|continue|forward|forward_url|location|redirect_to|redirect_uri|redirecturl|redirect_url|u|uri|path|r|ref|q|to|out|view|dir)=)",
            "description": "Open redirect parameters"
        }
        
        try:
            with open(pattern_file, 'w') as f:
                json.dump(pattern, f, indent=4)
            
            logger.info(f"Created GF redirect pattern: {pattern_file}")
            return True
        
        except Exception as e:
            logger.error(f"Error creating GF redirect pattern: {e}")
            return False
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the external tools integration
        
        Returns:
            Dict[str, Any]: Summary information
        """
        return {
            'available_tools': self.available_tools,
            'gf_patterns_dir': self.gf_patterns_dir,
            'results': {
                'collected_urls': len(self.results['collected_urls']),
                'filtered_urls': len(self.results['filtered_urls']),
                'live_urls': len(self.results['live_urls'])
            }
        }


# Example usage
async def main():
    """Example usage of ExternalToolManager"""
    import argparse
    
    parser = argparse.ArgumentParser(description="OpenX External Tools Integration")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize tool manager
    config = {
        'general': {
            'verbose': args.verbose
        }
    }
    
    tool_manager = ExternalToolManager(config)
    
    # Print available tools
    print("Available tools:")
    for tool, available in tool_manager.available_tools.items():
        status = "✅ Available" if available else "❌ Not available"
        print(f"  - {tool}: {status}")
    
    # Process domain
    results = await tool_manager.process_domain(args.domain)
    
    # Print results
    print("\nResults:")
    print(f"  - Collected URLs: {len(results['collected_urls'])}")
    print(f"  - Filtered URLs: {len(results['filtered_urls'])}")
    print(f"  - Live URLs: {len(results['live_urls'])}")
    
    # Save results to file if specified
    if args.output:
        with open(args.output, 'w') as f:
            for url in results['live_urls']:
                f.write(f"{url}\n")
        
        print(f"\nSaved {len(results['live_urls'])} URLs to {args.output}")

if __name__ == "__main__":
    asyncio.run(main())
