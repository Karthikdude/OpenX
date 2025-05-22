#!/usr/bin/env python3
"""
Example script demonstrating how to use OpenX with intelligent analysis
to prioritize high-risk URLs for scanning.

This script shows how to:
1. Collect URLs using external tools
2. Use intelligent analysis to prioritize high-risk URLs
3. Scan only URLs with medium or higher risk level
"""

import os
import sys
import asyncio
import logging
from typing import List, Dict, Any, Set

# Add the parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import OpenX modules
from core.scanner import Scanner
from utils.external_tools import ExternalToolManager
from utils.intelligent_analyzer import IntelligentAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('openx.examples.intelligent_analysis')

async def main():
    """
    Main function demonstrating intelligent analysis with OpenX
    """
    # Check if domain is provided
    if len(sys.argv) < 2:
        print("Usage: python intelligent_analysis_scan.py <domain>")
        return 1
    
    domain = sys.argv[1]
    logger.info(f"Starting intelligent analysis scan for domain: {domain}")
    
    # Configuration
    config = {
        'concurrency': 50,
        'timeout': 10,
        'external_tools': {
            'enabled': True
        },
        'intelligent_analysis': {
            'enabled': True,
            'min_risk_level': 'medium'  # Only scan URLs with medium or higher risk
        }
    }
    
    # Step 1: Collect URLs using external tools
    logger.info("Step 1: Collecting URLs using external tools")
    external_tool_manager = ExternalToolManager(config)
    results = await external_tool_manager.process_domain(domain)
    
    # Get the collected URLs
    urls_to_analyze = set()
    if 'live_urls' in results and results['live_urls']:
        urls_to_analyze = results['live_urls']
    elif 'deduplicated_urls' in results and results['deduplicated_urls']:
        urls_to_analyze = results['deduplicated_urls']
    elif 'filtered_urls' in results and results['filtered_urls']:
        urls_to_analyze = results['filtered_urls']
    elif 'collected_urls' in results and results['collected_urls']:
        urls_to_analyze = results['collected_urls']
    
    if not urls_to_analyze:
        logger.error("No URLs collected. Try a different domain or check if external tools are installed.")
        return 1
    
    logger.info(f"Collected {len(urls_to_analyze)} URLs for analysis")
    
    # Step 2: Use intelligent analysis to prioritize URLs
    logger.info("Step 2: Using intelligent analysis to prioritize URLs")
    analyzer = IntelligentAnalyzer(config)
    analysis_results = analyzer.analyze_urls(list(urls_to_analyze))
    
    # Print analysis summary
    logger.info("Analysis results:")
    for level in ['high', 'medium', 'low', 'info']:
        logger.info(f"  - {level.upper()} risk: {len(analysis_results[level])} URLs")
    
    # Get URLs to scan (medium and high risk only)
    urls_to_scan = []
    for level in ['high', 'medium']:
        level_urls = [result['url'] for result in analysis_results[level]]
        urls_to_scan.extend(level_urls)
    
    if not urls_to_scan:
        logger.warning("No medium or high risk URLs found. Try lowering the minimum risk level.")
        return 0
    
    logger.info(f"Selected {len(urls_to_scan)} URLs for scanning (medium and high risk only)")
    
    # Print some examples of high risk URLs
    if analysis_results['high']:
        logger.info("Examples of high risk URLs:")
        for i, result in enumerate(analysis_results['high'][:3]):
            logger.info(f"  {i+1}. {result['url']} (Score: {result['score']})")
            logger.info("     Matched rules:")
            for rule in result['matched_rules']:
                logger.info(f"     - {rule['description']} (+{rule['score']})")
    
    # Step 3: Scan prioritized URLs
    logger.info("Step 3: Scanning prioritized URLs")
    scanner = Scanner(config)
    scan_results = await scanner.scan_urls(urls_to_scan)
    
    # Print scan results
    vulnerable_count = sum(1 for result in scan_results if result.get('vulnerable', False))
    logger.info(f"Scan completed. Found {vulnerable_count} vulnerable URLs out of {len(scan_results)} scanned.")
    
    if vulnerable_count > 0:
        logger.info("Vulnerable URLs:")
        for i, result in enumerate(scan_results):
            if result.get('vulnerable', False):
                logger.info(f"  {i+1}. {result['url']} -> {result['redirect_url']}")
    
    return 0

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProgram terminated by user")
    except Exception as e:
        print(f"\nAn error occurred: {e}")
        logging.error(f"Unhandled exception: {e}", exc_info=True)
