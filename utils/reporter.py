#!/usr/bin/env python3
"""
Reporter Module for OpenX
Handles report generation in various formats (text, JSON, HTML)
"""

import os
import json
import logging
import datetime
from typing import Dict, List, Any, Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger('openx.reporter')

class Reporter:
    """
    Reporter class for generating scan reports in various formats
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the reporter
        
        Args:
            config (Optional[Dict[str, Any]]): Configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        log_level = self.config.get('general', {}).get('verbose', False)
        logger.setLevel(logging.DEBUG if log_level else logging.INFO)
        
        # Default templates directory
        self.templates_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'templates'
        )
        
        # Initialize Jinja2 environment for HTML reports
        try:
            self.jinja_env = Environment(
                loader=FileSystemLoader(self.templates_dir),
                autoescape=select_autoescape(['html', 'xml'])
            )
            logger.debug(f"Initialized Jinja2 environment with templates from {self.templates_dir}")
        except Exception as e:
            logger.warning(f"Could not initialize Jinja2 environment: {e}")
            self.jinja_env = None
    
    def generate_report(self, results: List[Dict[str, Any]], stats: Dict[str, Any], 
                        output_file: str, format_type: str = 'text') -> bool:
        """
        Generate a report in the specified format
        
        Args:
            results (List[Dict[str, Any]]): Scan results
            stats (Dict[str, Any]): Scan statistics
            output_file (str): Output file path
            format_type (str): Report format (text, json, html)
            
        Returns:
            bool: True if report was generated successfully, False otherwise
        """
        if format_type.lower() == 'text':
            return self._generate_text_report(results, stats, output_file)
        elif format_type.lower() == 'json':
            return self._generate_json_report(results, stats, output_file)
        elif format_type.lower() == 'html':
            return self._generate_html_report(results, stats, output_file)
        else:
            logger.error(f"Unsupported report format: {format_type}")
            return False
    
    def _generate_text_report(self, results: List[Dict[str, Any]], stats: Dict[str, Any], 
                             output_file: str) -> bool:
        """
        Generate a text report
        
        Args:
            results (List[Dict[str, Any]]): Scan results
            stats (Dict[str, Any]): Scan statistics
            output_file (str): Output file path
            
        Returns:
            bool: True if report was generated successfully, False otherwise
        """
        try:
            with open(output_file, 'w') as f:
                # Write header
                f.write("OpenX - Open Redirect Vulnerability Scanner\n")
                f.write("=" * 50 + "\n\n")
                
                # Write scan information
                f.write("Scan Information:\n")
                f.write("-" * 20 + "\n")
                f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Duration: {stats.get('scan_duration', 0):.2f} seconds\n")
                f.write(f"Total URLs Scanned: {stats.get('total_urls', 0)}\n")
                f.write(f"Vulnerable URLs: {stats.get('vulnerable_urls', 0)}\n")
                f.write(f"Error URLs: {stats.get('error_urls', 0)}\n\n")
                
                # Write results
                f.write("Scan Results:\n")
                f.write("-" * 20 + "\n")
                
                for i, result in enumerate(results, 1):
                    f.write(f"[{i}] {result.get('url', 'Unknown URL')}\n")
                    f.write(f"    Status: {result.get('status', 'Unknown')}\n")
                    
                    if result.get('vulnerable', False):
                        f.write(f"    Vulnerable: Yes\n")
                        f.write(f"    Payload: {result.get('payload', 'N/A')}\n")
                        f.write(f"    Redirect URL: {result.get('redirect_url', 'N/A')}\n")
                    else:
                        f.write(f"    Vulnerable: No\n")
                    
                    if result.get('error'):
                        f.write(f"    Error: {result.get('error')}\n")
                    
                    f.write("\n")
            
            logger.info(f"Generated text report: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating text report: {e}")
            return False
    
    def _generate_json_report(self, results: List[Dict[str, Any]], stats: Dict[str, Any], 
                             output_file: str) -> bool:
        """
        Generate a JSON report
        
        Args:
            results (List[Dict[str, Any]]): Scan results
            stats (Dict[str, Any]): Scan statistics
            output_file (str): Output file path
            
        Returns:
            bool: True if report was generated successfully, False otherwise
        """
        try:
            report_data = {
                'scan_info': {
                    'date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'duration': stats.get('scan_duration', 0),
                    'total_urls': stats.get('total_urls', 0),
                    'vulnerable_urls': stats.get('vulnerable_urls', 0),
                    'error_urls': stats.get('error_urls', 0)
                },
                'results': results
            }
            
            with open(output_file, 'w') as f:
                json.dump(report_data, f, indent=4)
            
            logger.info(f"Generated JSON report: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            return False
    
    def _generate_html_report(self, results: List[Dict[str, Any]], stats: Dict[str, Any], 
                             output_file: str) -> bool:
        """
        Generate an HTML report
        
        Args:
            results (List[Dict[str, Any]]): Scan results
            stats (Dict[str, Any]): Scan statistics
            output_file (str): Output file path
            
        Returns:
            bool: True if report was generated successfully, False otherwise
        """
        if not self.jinja_env:
            logger.error("Jinja2 environment not initialized. Cannot generate HTML report.")
            return False
        
        try:
            # Check if template exists
            try:
                template = self.jinja_env.get_template('report.html')
            except Exception as e:
                logger.warning(f"Could not load HTML template: {e}")
                # Create a basic template if not found
                template_str = """<!DOCTYPE html>
<html>
<head>
    <title>OpenX Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2c3e50; }
        h2 { color: #3498db; }
        .info { background-color: #f8f9fa; padding: 15px; border-radius: 5px; }
        .vulnerable { color: #e74c3c; font-weight: bold; }
        .safe { color: #27ae60; }
        .result { margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        .error { color: #e74c3c; }
    </style>
</head>
<body>
    <h1>OpenX - Open Redirect Vulnerability Scanner</h1>
    
    <div class="info">
        <h2>Scan Information</h2>
        <p><strong>Date:</strong> {{ scan_info.date }}</p>
        <p><strong>Duration:</strong> {{ scan_info.duration|round(2) }} seconds</p>
        <p><strong>Total URLs Scanned:</strong> {{ scan_info.total_urls }}</p>
        <p><strong>Vulnerable URLs:</strong> {{ scan_info.vulnerable_urls }}</p>
        <p><strong>Error URLs:</strong> {{ scan_info.error_urls }}</p>
    </div>
    
    <h2>Scan Results</h2>
    
    {% for result in results %}
    <div class="result">
        <h3>{{ result.url }}</h3>
        <p><strong>Status:</strong> {{ result.status }}</p>
        
        {% if result.vulnerable %}
        <p class="vulnerable"><strong>Vulnerable: Yes</strong></p>
        <p><strong>Payload:</strong> {{ result.payload }}</p>
        <p><strong>Redirect URL:</strong> {{ result.redirect_url }}</p>
        {% else %}
        <p class="safe"><strong>Vulnerable: No</strong></p>
        {% endif %}
        
        {% if result.error %}
        <p class="error"><strong>Error:</strong> {{ result.error }}</p>
        {% endif %}
    </div>
    {% endfor %}
</body>
</html>"""
                template = self.jinja_env.from_string(template_str)
            
            # Prepare template data
            template_data = {
                'scan_info': {
                    'date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'duration': stats.get('scan_duration', 0),
                    'total_urls': stats.get('total_urls', 0),
                    'vulnerable_urls': stats.get('vulnerable_urls', 0),
                    'error_urls': stats.get('error_urls', 0)
                },
                'results': results
            }
            
            # Render template and write to file
            html_content = template.render(**template_data)
            
            with open(output_file, 'w') as f:
                f.write(html_content)
            
            logger.info(f"Generated HTML report: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            return False
    
    def print_results(self, results: List[Dict[str, Any]], stats: Dict[str, Any], 
                     hide_non_vulnerable: bool = False) -> None:
        """
        Print scan results to console
        
        Args:
            results (List[Dict[str, Any]]): Scan results
            stats (Dict[str, Any]): Scan statistics
            hide_non_vulnerable (bool): Whether to hide non-vulnerable URLs
        """
        from colorama import Fore, Style, init
        
        # Initialize colorama
        init(autoreset=True)
        
        # Print scan statistics
        print("\n" + "=" * 60)
        print(f"{Fore.CYAN}OpenX Scan Results{Style.RESET_ALL}")
        print("=" * 60)
        
        print(f"\n{Fore.CYAN}Scan Statistics:{Style.RESET_ALL}")
        print(f"Duration: {stats.get('scan_duration', 0):.2f} seconds")
        print(f"Total URLs Scanned: {stats.get('total_urls', 0)}")
        print(f"Vulnerable URLs: {Fore.RED}{stats.get('vulnerable_urls', 0)}{Style.RESET_ALL}")
        print(f"Error URLs: {stats.get('error_urls', 0)}")
        
        # Print results
        print(f"\n{Fore.CYAN}Detailed Results:{Style.RESET_ALL}")
        
        for i, result in enumerate(results, 1):
            # Skip non-vulnerable URLs if hide_non_vulnerable is True
            if hide_non_vulnerable and not result.get('vulnerable', False):
                continue
                
            print(f"\n[{i}] {Fore.YELLOW}{result.get('url', 'Unknown URL')}{Style.RESET_ALL}")
            print(f"    Status: {result.get('status', 'Unknown')}")
            
            if result.get('vulnerable', False):
                print(f"    Vulnerable: {Fore.RED}Yes{Style.RESET_ALL}")
                print(f"    Payload: {result.get('payload', 'N/A')}")
                print(f"    Redirect URL: {result.get('redirect_url', 'N/A')}")
            else:
                print(f"    Vulnerable: {Fore.GREEN}No{Style.RESET_ALL}")
            
            if result.get('error'):
                print(f"    Error: {Fore.RED}{result.get('error')}{Style.RESET_ALL}")
        
        print("\n" + "=" * 60)


# Example usage
def main():
    """Example usage of Reporter"""
    import argparse
    
    parser = argparse.ArgumentParser(description="OpenX Reporter")
    parser.add_argument("-o", "--output", required=True, help="Output file path")
    parser.add_argument("-f", "--format", choices=["text", "json", "html"], default="text", help="Report format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize reporter
    config = {
        'general': {
            'verbose': args.verbose
        }
    }
    
    reporter = Reporter(config)
    
    # Example results and stats
    results = [
        {
            'url': 'https://example.com/redirect?url=https://evil.com',
            'status': 'Completed',
            'vulnerable': True,
            'payload': 'https://evil.com',
            'redirect_url': 'https://evil.com'
        },
        {
            'url': 'https://example.com/goto?next=https://example.org',
            'status': 'Completed',
            'vulnerable': True,
            'payload': 'https://example.org',
            'redirect_url': 'https://example.org'
        },
        {
            'url': 'https://example.com/page?param=value',
            'status': 'Completed',
            'vulnerable': False
        },
        {
            'url': 'https://example.com/error',
            'status': 'Error',
            'vulnerable': False,
            'error': 'Connection timeout'
        }
    ]
    
    stats = {
        'scan_duration': 10.5,
        'total_urls': 4,
        'vulnerable_urls': 2,
        'error_urls': 1
    }
    
    # Generate report
    reporter.generate_report(results, stats, args.output, args.format)
    
    # Print results to console
    reporter.print_results(results, stats)

if __name__ == "__main__":
    main()
