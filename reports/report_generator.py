#!/usr/bin/env python3
"""
Report Generator for OpenX
Handles different report formats and output
"""
import os
import json
import logging
import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

class ReportGenerator:
    """Generates reports in different formats for OpenX scan results"""
    
    def __init__(self, config=None):
        """
        Initialize the report generator
        
        Args:
            config (dict, optional): Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger("openx.reports")
        
        # Report settings
        self.output_format = self.config.get('reporting', {}).get('output_format', 'text')
        self.include_remediation = self.config.get('reporting', {}).get('include_remediation', True)
        self.include_evidence = self.config.get('reporting', {}).get('include_evidence', True)
        
        # Create reports directory if it doesn't exist
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
    
    def generate_report(self, results: List[Dict[str, Any]], stats: Dict[str, Any], output_file: Optional[str] = None) -> str:
        """
        Generate a report based on scan results
        
        Args:
            results (List[Dict[str, Any]]): Scan results
            stats (Dict[str, Any]): Scan statistics
            output_file (str, optional): Output file path
            
        Returns:
            str: Path to the generated report file
        """
        if self.output_format == 'json':
            return self._generate_json_report(results, stats, output_file)
        elif self.output_format == 'html':
            return self._generate_html_report(results, stats, output_file)
        else:
            return self._generate_text_report(results, stats, output_file)
    
    def _generate_text_report(self, results: List[Dict[str, Any]], stats: Dict[str, Any]], output_file: Optional[str] = None) -> str:
        """
        Generate a text report
        
        Args:
            results (List[Dict[str, Any]]): Scan results
            stats (Dict[str, Any]): Scan statistics
            output_file (str, optional): Output file path
            
        Returns:
            str: Path to the generated report file
        """
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"reports/openx_report_{timestamp}.txt"
        
        with open(output_file, 'w') as f:
            # Write header
            f.write("=" * 80 + "\n")
            f.write("OpenX Scan Report\n")
            f.write("=" * 80 + "\n\n")
            
            # Write scan statistics
            f.write("Scan Statistics:\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total URLs scanned: {stats['total_urls']}\n")
            f.write(f"Vulnerable URLs found: {stats['vulnerable_urls']}\n")
            f.write(f"Scan duration: {stats['elapsed_time']:.2f} seconds\n")
            f.write(f"Scan speed: {stats['urls_per_sec']:.2f} URLs/second\n\n")
            
            # Group vulnerabilities by severity
            vulnerabilities = {
                "high": [],
                "medium": [],
                "low": []
            }
            
            for result in results:
                severity = result.get('severity', 'low')
                if severity in vulnerabilities:
                    vulnerabilities[severity].append(result)
            
            # Write vulnerabilities by severity
            f.write("Vulnerabilities by Severity:\n")
            f.write("-" * 80 + "\n")
            
            for severity in ["high", "medium", "low"]:
                vuln_count = len(vulnerabilities[severity])
                f.write(f"{severity.upper()} severity vulnerabilities: {vuln_count}\n")
            
            f.write("\n")
            
            # Write detailed findings
            f.write("Detailed Findings:\n")
            f.write("-" * 80 + "\n\n")
            
            for severity in ["high", "medium", "low"]:
                if vulnerabilities[severity]:
                    f.write(f"{severity.upper()} Severity Vulnerabilities:\n")
                    f.write("-" * 80 + "\n")
                    
                    for i, vuln in enumerate(vulnerabilities[severity], 1):
                        f.write(f"[{i}] {vuln['url']}\n")
                        f.write(f"    Status Code: {vuln['status_code']}\n")
                        f.write(f"    Payload URL: {vuln['payload_url']}\n")
                        f.write(f"    Final URL: {vuln['final_url']}\n")
                        f.write(f"    Type: {vuln['type']}\n")
                        f.write(f"    Details: {vuln['details']}\n")
                        
                        if self.include_evidence and 'evidence' in vuln:
                            f.write(f"    Evidence: {vuln['evidence']}\n")
                        
                        f.write("\n")
                    
                    # Add remediation advice if enabled
                    if self.include_remediation:
                        f.write(f"Remediation for {severity.upper()} severity vulnerabilities:\n")
                        if severity == "high":
                            f.write("1. Implement a whitelist of allowed redirect URLs\n")
                            f.write("2. Use relative URLs for internal redirects\n")
                            f.write("3. Validate the full URL including protocol and domain\n")
                            f.write("4. Consider using indirect reference maps instead of direct URLs\n")
                            f.write("5. Implement CSRF protection for all redirect functionality\n")
                        elif severity == "medium":
                            f.write("1. Validate redirect URLs against a whitelist\n")
                            f.write("2. Ensure proper URL validation includes checking the domain\n")
                            f.write("3. Consider implementing URL signing for redirects\n")
                            f.write("4. Add warnings to users when redirecting to external sites\n")
                        elif severity == "low":
                            f.write("1. Add user confirmation for external redirects\n")
                            f.write("2. Implement proper URL validation\n")
                            f.write("3. Consider using a redirect warning page\n")
                        
                        f.write("\n")
            
            # Write footer
            f.write("=" * 80 + "\n")
            f.write(f"Report generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n")
        
        self.logger.info(f"Text report generated: {output_file}")
        return output_file
    
    def _generate_json_report(self, results: List[Dict[str, Any]], stats: Dict[str, Any], output_file: Optional[str] = None) -> str:
        """
        Generate a JSON report
        
        Args:
            results (List[Dict[str, Any]]): Scan results
            stats (Dict[str, Any]): Scan statistics
            output_file (str, optional): Output file path
            
        Returns:
            str: Path to the generated report file
        """
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"reports/openx_report_{timestamp}.json"
        
        # Prepare report data
        report_data = {
            "scan_date": datetime.datetime.now().isoformat(),
            "statistics": stats,
            "vulnerabilities": results
        }
        
        # Add remediation if enabled
        if self.include_remediation:
            report_data["remediation"] = {
                "high": [
                    "Implement a whitelist of allowed redirect URLs",
                    "Use relative URLs for internal redirects",
                    "Validate the full URL including protocol and domain",
                    "Consider using indirect reference maps instead of direct URLs",
                    "Implement CSRF protection for all redirect functionality"
                ],
                "medium": [
                    "Validate redirect URLs against a whitelist",
                    "Ensure proper URL validation includes checking the domain",
                    "Consider implementing URL signing for redirects",
                    "Add warnings to users when redirecting to external sites"
                ],
                "low": [
                    "Add user confirmation for external redirects",
                    "Implement proper URL validation",
                    "Consider using a redirect warning page"
                ]
            }
        
        # Write to file
        with open(output_file, 'w') as f:
            json.dump(report_data, f, indent=4)
        
        self.logger.info(f"JSON report generated: {output_file}")
        return output_file
    
    def _generate_html_report(self, results: List[Dict[str, Any]], stats: Dict[str, Any], output_file: Optional[str] = None) -> str:
        """
        Generate an HTML report
        
        Args:
            results (List[Dict[str, Any]]): Scan results
            stats (Dict[str, Any]): Scan statistics
            output_file (str, optional): Output file path
            
        Returns:
            str: Path to the generated report file
        """
        if not output_file:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"reports/openx_report_{timestamp}.html"
        
        # Group vulnerabilities by severity
        vulnerabilities = {
            "high": [],
            "medium": [],
            "low": []
        }
        
        for result in results:
            severity = result.get('severity', 'low')
            if severity in vulnerabilities:
                vulnerabilities[severity].append(result)
        
        # Generate HTML content
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenX Scan Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        h1, h2, h3 {{
            margin-top: 0;
        }}
        .stats {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            flex: 1;
            min-width: 200px;
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .stat-value {{
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-label {{
            color: #666;
        }}
        .severity-high {{
            color: #e74c3c;
        }}
        .severity-medium {{
            color: #f39c12;
        }}
        .severity-low {{
            color: #3498db;
        }}
        .vulnerability-section {{
            margin-bottom: 30px;
        }}
        .vulnerability-card {{
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .vulnerability-card h4 {{
            margin-top: 0;
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
        }}
        .vulnerability-card .details {{
            display: grid;
            grid-template-columns: 150px auto;
            gap: 10px;
        }}
        .vulnerability-card .label {{
            font-weight: bold;
        }}
        .remediation {{
            background-color: #e8f4f8;
            border-radius: 5px;
            padding: 20px;
            margin-top: 20px;
        }}
        .remediation h3 {{
            margin-top: 0;
        }}
        .remediation ul {{
            margin-bottom: 0;
        }}
        footer {{
            margin-top: 50px;
            text-align: center;
            color: #666;
            font-size: 14px;
        }}
        .evidence {{
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
            font-family: monospace;
            white-space: pre-wrap;
            overflow-x: auto;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            margin-right: 10px;
        }}
        .badge-high {{
            background-color: #e74c3c;
        }}
        .badge-medium {{
            background-color: #f39c12;
        }}
        .badge-low {{
            background-color: #3498db;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>OpenX Scan Report</h1>
            <p>Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <section>
            <h2>Scan Statistics</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value">{stats['total_urls']}</div>
                    <div class="stat-label">Total URLs Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['vulnerable_urls']}</div>
                    <div class="stat-label">Vulnerable URLs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['elapsed_time']:.2f}s</div>
                    <div class="stat-label">Scan Duration</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['urls_per_sec']:.2f}</div>
                    <div class="stat-label">URLs/Second</div>
                </div>
            </div>
        </section>
        
        <section>
            <h2>Vulnerabilities Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value severity-high">{len(vulnerabilities['high'])}</div>
                    <div class="stat-label">High Severity</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value severity-medium">{len(vulnerabilities['medium'])}</div>
                    <div class="stat-label">Medium Severity</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value severity-low">{len(vulnerabilities['low'])}</div>
                    <div class="stat-label">Low Severity</div>
                </div>
            </div>
        </section>
"""
        
        # Add vulnerability details by severity
        for severity in ["high", "medium", "low"]:
            if vulnerabilities[severity]:
                html_content += f"""
        <section class="vulnerability-section">
            <h2 class="severity-{severity}">{severity.capitalize()} Severity Vulnerabilities</h2>
"""
                
                for i, vuln in enumerate(vulnerabilities[severity], 1):
                    html_content += f"""
            <div class="vulnerability-card">
                <h4>
                    <span class="severity-badge badge-{severity}">{severity.upper()}</span>
                    {vuln['url']}
                </h4>
                <div class="details">
                    <div class="label">Status Code:</div>
                    <div>{vuln['status_code']}</div>
                    
                    <div class="label">Payload URL:</div>
                    <div>{vuln['payload_url']}</div>
                    
                    <div class="label">Final URL:</div>
                    <div>{vuln['final_url']}</div>
                    
                    <div class="label">Type:</div>
                    <div>{vuln['type']}</div>
                    
                    <div class="label">Details:</div>
                    <div>{vuln['details']}</div>
"""
                    
                    if self.include_evidence and 'evidence' in vuln:
                        html_content += f"""
                    <div class="label">Evidence:</div>
                    <div class="evidence">{vuln['evidence']}</div>
"""
                    
                    html_content += """
                </div>
            </div>
"""
                
                # Add remediation advice if enabled
                if self.include_remediation:
                    html_content += f"""
            <div class="remediation">
                <h3>Remediation for {severity.capitalize()} Severity Vulnerabilities</h3>
                <ul>
"""
                    
                    if severity == "high":
                        remediation_items = [
                            "Implement a whitelist of allowed redirect URLs",
                            "Use relative URLs for internal redirects",
                            "Validate the full URL including protocol and domain",
                            "Consider using indirect reference maps instead of direct URLs",
                            "Implement CSRF protection for all redirect functionality"
                        ]
                    elif severity == "medium":
                        remediation_items = [
                            "Validate redirect URLs against a whitelist",
                            "Ensure proper URL validation includes checking the domain",
                            "Consider implementing URL signing for redirects",
                            "Add warnings to users when redirecting to external sites"
                        ]
                    else:  # low
                        remediation_items = [
                            "Add user confirmation for external redirects",
                            "Implement proper URL validation",
                            "Consider using a redirect warning page"
                        ]
                    
                    for item in remediation_items:
                        html_content += f"                    <li>{item}</li>\n"
                    
                    html_content += """
                </ul>
            </div>
"""
                
                html_content += """
        </section>
"""
        
        # Add footer and close HTML
        html_content += """
        <footer>
            <p>Generated by OpenX - Open Redirect Scanner</p>
        </footer>
    </div>
</body>
</html>
"""
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        self.logger.info(f"HTML report generated: {output_file}")
        return output_file
