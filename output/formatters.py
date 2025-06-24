"""
Output formatting for OpenX scanner results
"""

import json
import csv
import os
import time
from datetime import datetime
from colorama import Fore, Style

class OutputFormatter:
    """Handles output formatting for scan results"""
    
    def __init__(self, output_file=None, verbose=False, silent=False):
        """Initialize output formatter"""
        self.output_file = output_file
        self.verbose = verbose
        self.silent = silent
    
    def format_vulnerability_console(self, vuln):
        """Format vulnerability for console output"""
        lines = []
        
        # Header with URL and vulnerability type
        lines.append(f"{Fore.GREEN}[VULNERABILITY FOUND]{Style.RESET_ALL}")
        lines.append(f"URL: {vuln['url']}")
        lines.append(f"Parameter: {vuln['parameter']}")
        lines.append(f"Method: {vuln['method']}")
        lines.append(f"Payload: {vuln['payload']}")
        lines.append(f"Redirect To: {vuln.get('final_location', 'N/A')}")
        lines.append(f"Status Code: {vuln['status_code']}")
        lines.append(f"Severity: {vuln['severity']}")
        
        if self.verbose:
            lines.append(f"Description: {vuln['description']}")
        
        lines.append("-" * 60)
        
        return '\n'.join(lines)
    
    def output_console(self, results):
        """Output results to console"""
        if self.silent:
            # In silent mode, only output vulnerabilities
            for result in results:
                for vuln in result.get('vulnerabilities', []):
                    print(self.format_vulnerability_console(vuln))
        else:
            # Full console output
            for result in results:
                url = result['url']
                vulnerabilities = result.get('vulnerabilities', [])
                error = result.get('error')
                
                if error:
                    print(f"{Fore.RED}[ERROR] {url}: {error}{Style.RESET_ALL}")
                elif vulnerabilities:
                    print(f"{Fore.GREEN}[VULNERABLE] {url} - {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}")
                    for vuln in vulnerabilities:
                        print(self.format_vulnerability_console(vuln))
                else:
                    if self.verbose:
                        print(f"{Fore.YELLOW}[CLEAN] {url}{Style.RESET_ALL}")
    
    def format_results_json(self, results):
        """Format results as JSON"""
        output_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_urls': len(results),
                'total_vulnerabilities': sum(len(r.get('vulnerabilities', [])) for r in results)
            },
            'results': []
        }
        
        for result in results:
            formatted_result = {
                'url': result['url'],
                'timestamp': datetime.fromtimestamp(result.get('timestamp', time.time())).isoformat(),
                'total_requests': result.get('total_requests', 0),
                'vulnerabilities': result.get('vulnerabilities', []),
                'error': result.get('error')
            }
            output_data['results'].append(formatted_result)
        
        return json.dumps(output_data, indent=2, ensure_ascii=False)
    
    def format_results_csv(self, results):
        """Format results as CSV"""
        rows = []
        
        # Header row
        headers = [
            'URL', 'Parameter', 'Method', 'Payload', 'Redirect_To',
            'Status_Code', 'Severity', 'Description', 'Timestamp'
        ]
        rows.append(headers)
        
        # Data rows
        for result in results:
            url = result['url']
            timestamp = datetime.fromtimestamp(result.get('timestamp', time.time())).isoformat()
            
            vulnerabilities = result.get('vulnerabilities', [])
            if vulnerabilities:
                for vuln in vulnerabilities:
                    row = [
                        url,
                        vuln.get('parameter', ''),
                        vuln.get('method', ''),
                        vuln.get('payload', ''),
                        vuln.get('location_header', ''),
                        vuln.get('status_code', ''),
                        vuln.get('severity', ''),
                        vuln.get('description', ''),
                        timestamp
                    ]
                    rows.append(row)
            else:
                # Add row for URLs with no vulnerabilities
                row = [url, '', '', '', '', '', 'CLEAN', 'No vulnerabilities found', timestamp]
                rows.append(row)
        
        return rows
    
    def format_results_txt(self, results):
        """Format results as plain text"""
        lines = []
        
        # Header
        lines.append("OpenX Vulnerability Scanner Results")
        lines.append("=" * 50)
        lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total URLs Scanned: {len(results)}")
        
        total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results)
        lines.append(f"Total Vulnerabilities: {total_vulns}")
        lines.append("")
        
        # Results
        for result in results:
            url = result['url']
            vulnerabilities = result.get('vulnerabilities', [])
            error = result.get('error')
            
            lines.append(f"URL: {url}")
            lines.append("-" * len(f"URL: {url}"))
            
            if error:
                lines.append(f"ERROR: {error}")
            elif vulnerabilities:
                lines.append(f"VULNERABILITIES FOUND: {len(vulnerabilities)}")
                lines.append("")
                
                for i, vuln in enumerate(vulnerabilities, 1):
                    lines.append(f"  {i}. Parameter: {vuln.get('parameter', 'N/A')}")
                    lines.append(f"     Method: {vuln.get('method', 'N/A')}")
                    lines.append(f"     Payload: {vuln.get('payload', 'N/A')}")
                    lines.append(f"     Redirect To: {vuln.get('location_header', 'N/A')}")
                    lines.append(f"     Status Code: {vuln.get('status_code', 'N/A')}")
                    lines.append(f"     Severity: {vuln.get('severity', 'N/A')}")
                    lines.append(f"     Description: {vuln.get('description', 'N/A')}")
                    lines.append("")
            else:
                lines.append("RESULT: No vulnerabilities found")
            
            lines.append("")
        
        return '\n'.join(lines)
    
    def save_to_file(self, content, filepath, file_format):
        """Save content to file"""
        try:
            if file_format == 'csv':
                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerows(content)
            else:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            if not self.silent:
                print(f"{Fore.CYAN}[INFO] Results saved to: {filepath}{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to save results: {str(e)}{Style.RESET_ALL}")
    
    def detect_output_format(self, filepath):
        """Detect output format from file extension"""
        if not filepath:
            return None
        
        ext = os.path.splitext(filepath)[1].lower()
        
        if ext == '.json':
            return 'json'
        elif ext == '.csv':
            return 'csv'
        elif ext in ['.txt', '.log']:
            return 'txt'
        else:
            # Default to txt for unknown extensions
            return 'txt'
    
    def output_results(self, results):
        """Output results in all requested formats"""
        # Console output
        self.output_console(results)
        
        # File output if specified
        if self.output_file:
            output_format = self.detect_output_format(self.output_file)
            
            if output_format == 'json':
                content = self.format_results_json(results)
                self.save_to_file(content, self.output_file, 'json')
            
            elif output_format == 'csv':
                content = self.format_results_csv(results)
                self.save_to_file(content, self.output_file, 'csv')
            
            elif output_format == 'txt':
                content = self.format_results_txt(results)
                self.save_to_file(content, self.output_file, 'txt')
