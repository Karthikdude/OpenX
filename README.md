# OpenX v3.0 - Advanced Open Redirect Vulnerability Scanner

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-3.0-orange.svg)](https://github.com/username/openx/releases/tag/v3.0)

OpenX is a powerful, modular, and feature-rich open redirect vulnerability scanner designed for security professionals and penetration testers. It helps identify and verify open redirect vulnerabilities in web applications with advanced detection techniques and comprehensive reporting.

Version 3.0 introduces major enhancements including distributed scanning architecture, stealth features, advanced analysis capabilities, and interactive modes. Version 2.0 introduced external tools integration, improved browser-based detection, and a more comprehensive scanning pipeline.

## Features

### Core Features (v1.0)

- **Advanced Payload Detection**
  - Configurable target domains for validation
  - Sophisticated regex-based pattern detection
  - Support for custom payloads via file input

- **Comprehensive Reporting**
  - Multiple output formats (text, JSON, HTML)
  - Vulnerability categorization by severity
  - Detailed remediation suggestions

- **Authentication Support**
  - Basic, digest, and token-based authentication
  - Session handling for authenticated scanning

- **Enhanced Scanning Capabilities**
  - Headless browser support using Playwright or Selenium
  - DOM-based redirect detection
  - Path-based payload injection
  - Smart parameter detection

- **Performance Optimizations**
  - Retry mechanisms for failed requests
  - Smart throttling based on server response
  - Configurable concurrency

- **Security Enhancements**
  - Proxy support with authentication
  - WAF evasion techniques
  - Configurable delay options
  - False positive reduction

### New in Version 2.0

- **External Tools Integration**
  - Passive URL collection using tools like waybackurls, gau, urlfinder, and uro
  - URL filtering with gf patterns for redirect parameters
  - HTTP probing with httpx and httprobe
  - Environment-aware detection of available tools

- **Enhanced Browser-Based Detection**
  - Improved Selenium implementation matching Playwright capabilities
  - Support for multiple browser types (Chrome, Firefox)
  - Detection of DOM-based, meta refresh, and form-based redirects
  - JavaScript redirect interception

- **Advanced User Agent Management**
  - Categorized user agents by browser type and device
  - WAF evasion user agents
  - User agent rotation with memory to avoid detection

- **Improved Reporting**
  - Interactive HTML reports with charts and visualizations
  - Detailed evidence and remediation recommendations
  - Severity-based vulnerability categorization

- **Modular Scanning Pipeline**
  - Passive reconnaissance → Filtering → Probing → Active Scanning
  - Each phase can be enabled or disabled independently
  - Graceful fallbacks when external tools aren't available

- **Intelligent Analysis**
  - Uses rule-based scoring heuristics to prioritize high-risk URLs
  - Assigns scores based on various factors like common redirect parameters, URL in parameter value, protocol-relative URLs, etc.

### New in Version 3.0

- **Stealth Features Module**
  - Traffic mimicking to simulate normal user behavior
  - Request timing randomization based on human patterns
  - Session management with realistic user flows
  - Distributed request sourcing through proxy rotation

- **Advanced Analysis Module**
  - Impact assessment scoring based on page context
  - Attack vector generation (PoCs) in multiple formats (HTML, curl, JavaScript, Python)
  - Business logic analysis for redirect chains
  - Related vulnerability identification and risk correlation

- **Distributed Scanning Architecture**
  - Master/worker architecture for distributed scanning
  - Task queuing, load balancing, and result aggregation
  - Fault tolerance and worker monitoring
  - REST API for management and status reporting

- **Interactive Modes**
  - Command-line interactive interface for real-time testing
  - Web-based dashboard for scan management
  - Real-time scan monitoring and result visualization
  - Configuration management through UI

- **Enhanced Detection Capabilities**
  - Detection of various redirect types (meta refresh, iframe redirects, history.pushState)
  - WebSocket and POST-based redirect detection
  - Chained redirect detection (A→B→C scenarios)
  - WAF bypass techniques for evasion

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

### Basic Installation

```bash
# Clone the repository
git clone https://github.com/username/openx.git
cd openx

# Install required dependencies
pip install -r requirements.txt
```

### Optional Dependencies

For headless browser support:

```bash
# For Playwright support
pip install playwright
python -m playwright install

# For Selenium support
pip install selenium webdriver-manager
```

### External Tools (Optional)

OpenX v2.0 can integrate with these external tools if they're available in your system:

```bash
# URL Collection Tools
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/mr-pmillz/urlfinder@latest
go install github.com/sensepost/uro@latest

# URL Filtering
go install github.com/tomnomnom/gf@latest

# HTTP Probing
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/httprobe@latest
```

Note: These tools are optional. OpenX will detect which tools are available and adapt accordingly.

## Usage

### Basic Usage

```bash
# Scan a single URL
python opex.py -u https://example.com/redirect?url=FUZZ

# Scan multiple URLs from a file
python opex.py -l urls.txt

# Save results to a file
python opex.py -l urls.txt -o results.txt
```

### Advanced Options

```bash
# Enable smart parameter-based payload injection
python opex.py -l urls.txt -s

# Use headless browser for deep verification
python opex.py -l urls.txt --browser

# Hide errors from output
python opex.py -l urls.txt -error

# Only display vulnerable URLs
python opex.py -l urls.txt -hide

# Set request timeout
python opex.py -l urls.txt -t 15

# Use a proxy
python opex.py -l urls.txt -p http://127.0.0.1:8080

# Randomize User-Agent
python opex.py -l urls.txt -ua

# Set concurrency level
python opex.py -l urls.txt --concurrency 50

# Generate HTML report
python opex.py -l urls.txt --report-format html

# Use intelligent analysis to prioritize high-risk URLs
python opex.py -d example.com --use-external-tools --intelligent-analysis

# Set minimum risk level for intelligent analysis
python opex.py -d example.com --use-external-tools --intelligent-analysis --min-risk-level medium
```

### External Tools Integration (v2.0)

```bash
# Use external tools for passive URL collection from a domain
python opex.py -d example.com --use-external-tools -o report.html

# Skip specific phases of the external tools pipeline
python opex.py -d example.com --use-external-tools --skip-probing

# Save collected URLs to a file
python opex.py -d example.com --use-external-tools --tools-output urls.txt

# Use collected URLs with browser verification
python opex.py -d example.com --use-external-tools --browser
```

### Configuration File

You can use a configuration file to set default options:

```bash
python opex.py --config config.json
```

Example configuration file (config.json):

```json
{
  "timeout": 10,
  "concurrency": 100,
  "user_agent_rotation": true,
  "verify_ssl": false,
  "max_retries": 3,
  "target_domains": ["example.com", "evil.com"],
  "browser": {
    "enabled": true,
    "type": "playwright",
    "headless": true
  },
  "reporting": {
    "output_format": "html",
    "include_remediation": true
  }
}
```

## Command Line Arguments

### Core Arguments

| Argument | Description |
|----------|-------------|
| `-l`, `--url-file` | File containing URLs to scan |
| `-u`, `--single-url` | Single URL to scan |
| `-o`, `--output` | Output file to save results |
| `-error`, `--hide-error` | Hide errors from output |
| `-hide`, `--hide-vuln` | Only display vulnerable URLs |
| `-s`, `--smart-scan` | Enable smart parameter-based payload injection |
| `-debug`, `--debug-mode` | Enable debug mode |
| `-t`, `--timeout` | Request timeout in seconds (default: 10) |
| `--dry-run` | Test without scanning |
| `--browser` | Use headless browser for deep verification |
| `--concurrency` | Number of concurrent requests (default: 100) |
| `-p`, `--proxy` | HTTP proxy URL |
| `-ua`, `--random-user-agent` | Randomize User-Agent |
| `--config` | Path to configuration file |
| `--report-format` | Report format (text, json, html) |
| `--custom-payloads` | File containing custom payloads |
| `--target-domains` | Comma-separated list of target domains |

### External Tools Arguments (v2.0)

| Argument | Description |
|----------|-------------|
| `-d`, `--domain` | Target domain for passive URL collection |
| `--use-external-tools` | Use external tools for URL collection and filtering |
| `--skip-url-collection` | Skip URL collection phase |
| `--skip-filtering` | Skip URL filtering phase |
| `--skip-probing` | Skip HTTP probing phase |
| `--tools-output` | Output file for collected URLs |

### Intelligent Analysis Arguments

| Argument | Description |
|----------|-------------|
| `--intelligent-analysis` | Use intelligent analysis to prioritize high-risk URLs |
| `--min-risk-level` | Minimum risk level to include in scanning (info, low, medium, high) |

## Intelligent Analysis

OpenX includes an intelligent analysis module that uses rule-based scoring heuristics to prioritize URLs for scanning. This helps focus on high-risk URLs first and reduces false positives.

### Risk Scoring

The intelligent analyzer assigns scores to URLs based on various factors:

- **Common Redirect Parameters**: URLs containing parameters like `url`, `redirect`, `next`, etc.
- **URL in Parameter Value**: Parameter values starting with `http://` or `https://`
- **Protocol-Relative URLs**: Parameter values starting with `//`
- **Blacklisted Domains**: Parameter values containing known malicious domains
- **Encoded Characters**: Parameter values containing URL-encoded characters
- **Base64-Encoded Content**: Parameter values containing possible base64-encoded URLs
- **Multiple Redirect Parameters**: URLs with multiple potential redirect parameters
- **Path Traversal Sequences**: Parameter values containing `../` or similar
- **JavaScript Protocol**: Parameter values containing `javascript:` protocol
- **Data URI Scheme**: Parameter values containing `data:` URI scheme

### Risk Levels

URLs are categorized into four risk levels based on their total score:

- **High Risk**: Score >= 8
- **Medium Risk**: Score >= 5 and < 8
- **Low Risk**: Score >= 3 and < 5
- **Info**: Score < 3

## Examples

### Testing a Specific Parameter

```bash
python opex.py -u "https://example.com/redirect?url=FUZZ"
```

The `FUZZ` keyword will be replaced with various payloads during testing.

### Using Custom Payloads

```bash
python opex.py -l urls.txt --custom-payloads my_payloads.txt
```

Example custom payloads file (my_payloads.txt):
```
https://evil.com/
//evil.com/
/\evil.com/
```

### Testing with Authentication

```bash
python opex.py -l urls.txt --auth-type basic --auth-username user --auth-password pass
```

### Generating an HTML Report

```bash
python opex.py -l urls.txt --report-format html -o report.html
```

### Using External Tools for Passive Reconnaissance (v2.0)

```bash
# Collect URLs from a domain and scan them
python opex.py -d example.com --use-external-tools -o report.html

# Use the example script for more control
python examples/passive_recon_scan.py -d example.com -o report.html --browser
```

### Distributed Scanning (v3.0)

```bash
# Start the coordinator
python utils/distributed/coordinator.py --host 0.0.0.0 --port 8080

# Start worker nodes
python utils/distributed/worker.py --coordinator http://coordinator-ip:8080

# Distribute a scan using the coordinator
python opex.py -l urls.txt --distributed --coordinator http://coordinator-ip:8080
```

### Using Stealth Mode (v3.0)

```bash
# Enable stealth mode with traffic mimicking
python opex.py -l urls.txt --stealth --traffic-mimicking

# Use timing randomization to avoid detection
python opex.py -l urls.txt --stealth --timing-randomization
```

### Advanced Analysis (v3.0)

```bash
# Generate impact assessment and attack vectors
python opex.py -l urls.txt --advanced-analysis --generate-poc

# Perform business logic analysis
python opex.py -l urls.txt --advanced-analysis --business-logic
```

### Interactive Mode (v3.0)

```bash
# Start the interactive CLI
python utils/interactive/cli_interactive.py

# Start the web dashboard
python utils/interactive/web_dashboard.py --port 8000
```

### Crawling and Scanning (v2.0)

```bash
# Use the crawler utility to discover URLs and scan them
python examples/crawl_and_scan.py -u https://example.com -d 2 -o report.html
```

### WAF Evasion Techniques (v2.0)

```bash
# Use WAF evasion techniques with specialized user agents
python examples/waf_evasion_scan.py -u https://example.com/redirect?url= -o report.html --proxy http://127.0.0.1:8080
```

## Project Structure

```
OpenX/
├── config/                # Configuration files
│   └── default_config.yaml # Default configuration
├── core/                  # Core scanner functionality
│   └── scanner.py         # Scanner implementation
├── examples/              # Example scripts
│   ├── crawl_and_scan.py  # Crawler example
│   ├── passive_recon_scan.py # External tools example
│   └── waf_evasion_scan.py # WAF evasion example
├── payloads/              # Payload management
│   ├── payload_manager.py # Payload handling
│   └── custom_payloads.txt # Sample payloads
├── reports/               # Report generation
│   └── report_generator.py # Report templates
├── utils/                 # Utility functions
│   ├── analysis/          # Analysis modules
│   │   └── advanced_analysis.py # Impact assessment and attack vectors
│   ├── crawler.py         # Web crawler
│   ├── distributed/       # Distributed scanning
│   │   ├── coordinator.py # Master node implementation
│   │   └── worker.py      # Worker node implementation
│   ├── evasion/           # Evasion techniques
│   │   ├── stealth_features.py # Stealth scanning features
│   │   └── waf_bypass.py  # WAF bypass techniques
│   ├── external_tools.py  # External tools integration
│   ├── helpers.py         # Helper functions
│   ├── interactive/       # Interactive interfaces
│   │   ├── cli_interactive.py # Command-line interface
│   │   └── web_dashboard.py # Web-based dashboard
│   ├── integrations/      # Third-party integrations
│   │   ├── burp_extension.py # Burp Suite extension
│   │   └── zap_plugin.py  # OWASP ZAP plugin
│   ├── resume_manager.py  # Scan resumption functionality
│   └── fake_useragent_data.py # User agent management
├── fake_useragent_data.py # User agent database
├── opex.py                # Main script
├── requirements.txt       # Dependencies
└── README.md              # Documentation
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

### Version 3.0 (July 2025)
- Added distributed scanning architecture with coordinator and worker nodes
- Implemented stealth features for evasion (traffic mimicking, timing randomization)
- Added advanced analysis module with impact assessment and attack vector generation
- Implemented interactive CLI and web dashboard interfaces
- Enhanced detection capabilities for various redirect types
- Added resume functionality for interrupted scans
- Implemented WAF bypass techniques for improved evasion
- Added integration with Burp Suite and OWASP ZAP
- Implemented business logic analysis for redirect chains
- Added related vulnerability identification and risk correlation

### Version 2.0 (May 2025)
- Added external tools integration for passive URL collection
- Enhanced browser-based detection with improved Selenium implementation
- Implemented advanced user agent management system
- Added interactive HTML reports with charts and visualizations
- Created modular scanning pipeline with graceful fallbacks
- Added example scripts for different use cases
- Improved documentation and project structure
- Added uro tool integration for URL deduplication
- Added intelligent analysis with rule-based scoring heuristics

### Version 1.0 (Initial Release)
- Core scanning functionality
- Headless browser support
- Custom payload management
- Multiple report formats
- Authentication and proxy support

## Acknowledgments

- Developed by Karthik S Sathyan
- Inspired by various open redirect testing techniques
- Thanks to all contributors
- Special thanks to the developers of the integrated tools:
  - waybackurls, gau, urlfinder (URL collection)
  - gf (URL filtering)
  - httpx, httprobe (HTTP probing)

## Disclaimer

This tool is intended for security professionals and penetration testers. Always obtain proper authorization before testing any systems. The authors are not responsible for any misuse or damage caused by this tool.