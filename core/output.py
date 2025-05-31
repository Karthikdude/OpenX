"""
OpenX Output Manager
Handles output formatting and file generation
"""

import json
import csv
import os
from pathlib import Path
from datetime import datetime
from colorama import Fore, Style

class OutputManager:
    """Manages output formatting and file operations"""
    
    def __init__(self):
        self.supported_formats = ['json', 'csv', 'txt', 'xml']
    
    def detect_format(self, file_path):
        """Detect output format from file extension"""
        extension = Path(file_path).suffix.lower().lstrip('.')
        return extension if extension in self.supported_formats else 'txt'
    
    def save_results(self, results, file_path):
        """Save results to file in the appropriate format"""
        try:
            format_type = self.detect_format(file_path)
            
            if format_type == 'json':
                return self._save_json(results, file_path)
            elif format_type == 'csv':
                return self._save_csv(results, file_path)
            elif format_type == 'xml':
                return self._save_xml(results, file_path)
            else:
                return self._save_txt(results, file_path)
                
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to save results: {str(e)}{Style.RESET_ALL}")
            return False
    
    def _save_json(self, results, file_path):
        """Save results in JSON format"""
        output_data = {
            'scan_info': {
                'tool': 'OpenX',
                'version': '1.0',
                'scan_date': datetime.now().isoformat(),
                'total_urls': len(set(r.get('original_url', r.get('url', '')) for r in results)),
                'total_tests': len(results),
                'vulnerable_count': len([r for r in results if r.get('vulnerable', False)])
            },
            'results': results
        }
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        return True
    
    def _save_csv(self, results, file_path):
        """Save results in CSV format"""
        if not results:
            return True
        
        # Define CSV headers
        headers = [
            'url', 'original_url', 'vulnerable', 'method', 'parameter', 'header',
            'payload', 'status_code', 'redirect_location', 'severity'
        ]
        
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            
            for result in results:
                # Prepare row data
                row = {}
                for header in headers:
                    row[header] = result.get(header, '')
                writer.writerow(row)
        
        return True
    
    def _save_txt(self, results, file_path):
        """Save results in human-readable text format"""
        with open(file_path, 'w', encoding='utf-8') as f:
            # Write header
            f.write("OpenX - Open Redirect Scanner Results\n")
            f.write("=" * 50 + "\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total URLs Tested: {len(set(r.get('original_url', r.get('url', '')) for r in results))}\n")
            f.write(f"Total Tests: {len(results)}\n")
            f.write(f"Vulnerable URLs: {len([r for r in results if r.get('vulnerable', False)])}\n\n")
            
            # Group results by vulnerability status
            vulnerable_results = [r for r in results if r.get('vulnerable', False)]
            
            if vulnerable_results:
                f.write("VULNERABLE URLS:\n")
                f.write("-" * 30 + "\n\n")
                
                for i, result in enumerate(vulnerable_results, 1):
                    f.write(f"{i}. URL: {result.get('url', 'N/A')}\n")
                    f.write(f"   Original URL: {result.get('original_url', 'N/A')}\n")
                    f.write(f"   Method: {result.get('method', 'N/A')}\n")
                    f.write(f"   Payload: {result.get('payload', 'N/A')}\n")
                    
                    if 'parameter' in result:
                        f.write(f"   Parameter: {result['parameter']}\n")
                    if 'header' in result:
                        f.write(f"   Header: {result['header']}\n")
                    
                    f.write(f"   Status Code: {result.get('status_code', 'N/A')}\n")
                    f.write(f"   Redirect Location: {result.get('redirect_location', 'N/A')}\n")
                    f.write(f"   Severity: {result.get('severity', 'Medium')}\n")
                    f.write("\n")
            else:
                f.write("No open redirect vulnerabilities found.\n")
        
        return True
    
    def _save_xml(self, results, file_path):
        """Save results in XML format"""
        from xml.etree.ElementTree import Element, SubElement, tostring
        from xml.dom import minidom
        
        # Create root element
        root = Element('openx_scan_results')
        
        # Add scan info
        scan_info = SubElement(root, 'scan_info')
        SubElement(scan_info, 'tool').text = 'OpenX'
        SubElement(scan_info, 'version').text = '1.0'
        SubElement(scan_info, 'scan_date').text = datetime.now().isoformat()
        SubElement(scan_info, 'total_urls').text = str(len(set(r.get('original_url', r.get('url', '')) for r in results)))
        SubElement(scan_info, 'total_tests').text = str(len(results))
        SubElement(scan_info, 'vulnerable_count').text = str(len([r for r in results if r.get('vulnerable', False)]))
        
        # Add results
        results_element = SubElement(root, 'results')
        
        for result in results:
            result_element = SubElement(results_element, 'result')
            
            for key, value in result.items():
                if value is not None:
                    elem = SubElement(result_element, key)
                    elem.text = str(value)
        
        # Pretty print and save
        rough_string = tostring(root, 'utf-8')
        reparsed = minidom.parseString(rough_string)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(reparsed.toprettyxml(indent="  "))
        
        return True
    
    def print_summary(self, results):
        """Print a summary of the scan results"""
        if not results:
            print(f"{Fore.YELLOW}[INFO] No results to display{Style.RESET_ALL}")
            return
        
        total_urls = len(set(r.get('original_url', r.get('url', '')) for r in results))
        vulnerable_count = len([r for r in results if r.get('vulnerable', False)])
        
        print(f"\n{Fore.CYAN}SCAN SUMMARY:")
        print(f"{Fore.CYAN}=" * 40)
        print(f"{Fore.CYAN}Total URLs Scanned: {total_urls}")
        print(f"{Fore.CYAN}Total Tests Performed: {len(results)}")
        print(f"{Fore.CYAN}Vulnerable URLs Found: {vulnerable_count}")
        
        if vulnerable_count > 0:
            print(f"{Fore.RED}Vulnerabilities detected! Review the results above.{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}No vulnerabilities found.{Style.RESET_ALL}")
