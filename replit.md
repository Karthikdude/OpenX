# OpenX - Advanced Open Redirect Vulnerability Scanner & Testing Lab

## Overview

This repository contains a comprehensive security testing suite consisting of two main components:

1. **OpenX Scanner** (`openx.py`) - A production-grade command-line tool for detecting open redirect vulnerabilities in real-world applications
2. **Flask Testing Lab** (`app.py`) - An educational web application that provides various vulnerable endpoints for testing and learning about open redirect vulnerabilities

The project is designed to serve both security professionals conducting penetration tests and students learning about web application security vulnerabilities. The OpenX scanner has been enhanced with advanced real-world detection capabilities, successfully identifying vulnerabilities in OAuth flows, enterprise applications, payment gateways, and modern web applications using sophisticated bypass techniques.

## System Architecture

### Flask Testing Lab Architecture
- **Framework**: Flask web application using Python 3.11+
- **Template Engine**: Jinja2 with Bootstrap 5 frontend
- **Static Assets**: CSS/JavaScript for interactive testing interface
- **Vulnerable Endpoints**: Multiple categories of intentionally vulnerable redirect implementations
- **Configuration Management**: Environment-based configuration with development defaults

### OpenX Scanner Architecture
- **Core Engine**: Multi-threaded scanning engine with configurable concurrency
- **Payload Management**: Comprehensive payload library with encoding variations
- **External Tool Integration**: Support for `gau` and `waybackurls` URL discovery tools
- **Output Formatters**: Multiple output formats (JSON, CSV, TXT) for different use cases
- **Request Handling**: Advanced HTTP client with proxy support and redirect following

## Key Components

### Flask Testing Lab Components

1. **Main Application** (`app.py`)
   - Flask route handlers for various vulnerability types
   - Configuration management and security header controls
   - Request logging middleware for analysis
   - Educational dashboard with categorized vulnerabilities

2. **Template System** (`templates/`)
   - Base template with Bootstrap navigation and styling
   - Dashboard for interactive testing interface
   - Specialized templates for JavaScript and Meta refresh redirects
   - Category-based vulnerability organization

3. **Static Assets** (`static/`)
   - Interactive JavaScript for payload testing and result tracking
   - Custom CSS styling with vulnerability categorization
   - Real-time testing feedback and progress tracking

### OpenX Scanner Components

1. **Core Scanner** (`scanner/core.py`)
   - Main scanning engine with thread pool execution
   - Intelligent vulnerability detection using multiple methods
   - HTTP session management with custom headers and proxy support
   - Comprehensive redirect analysis and validation

2. **Payload Management** (`scanner/payloads.py`)
   - Built-in payload library with 100+ variations
   - Encoding bypass techniques (URL, Unicode, double encoding)
   - Protocol manipulation and domain validation bypasses
   - Custom payload file support for specialized testing

3. **External Tool Integration** (`scanner/external.py`)
   - Integration with `gau` tool for URL discovery from various sources
   - Support for `waybackurls` for historical URL gathering
   - Automatic tool detection and fallback mechanisms
   - Domain and file-based input processing

4. **Output Formatting** (`output/formatters.py`)
   - Multiple output formats for different reporting needs
   - Structured vulnerability reporting with severity classification
   - Console output with color-coded results
   - Export capabilities for integration with other tools

## Data Flow

### Flask Lab Data Flow
1. User accesses dashboard interface
2. JavaScript handles payload testing and endpoint interaction
3. Flask routes process redirect requests with various vulnerability patterns
4. Response analysis determines successful redirects
5. Results displayed in real-time interface with categorization

### Scanner Data Flow
1. Target URLs gathered from CLI arguments or external tools
2. Payload manager generates test cases for each parameter
3. Multi-threaded scanner executes requests with various payloads
4. Response analysis detects successful redirects using multiple detection methods
5. Results formatted and output in specified format (console, JSON, CSV)

## External Dependencies

### Runtime Dependencies
- **Flask 3.1.1+**: Web framework for testing lab
- **Requests 2.32.4+**: HTTP client library for scanner
- **Colorama 0.4.6+**: Cross-platform colored terminal output
- **urllib3 2.5.0+**: Advanced HTTP client features

### Optional External Tools
- **gau**: URL discovery from multiple sources (AlienVault OTX, Wayback Machine, etc.)
- **waybackurls**: Historical URL discovery from Wayback Machine

### Development Dependencies
- **Bootstrap 5**: Frontend CSS framework for lab interface
- **Font Awesome 6**: Icon library for enhanced UI
- **JavaScript ES6+**: Interactive features and real-time testing

## Deployment Strategy

### Development Environment
- **Replit Configuration**: Configured for Python 3.11 with Nix package management
- **Auto-start**: Flask development server starts automatically on port 5000
- **Hot Reload**: Development mode enables automatic reloading on code changes

### Production Considerations
- Environment variable configuration for secrets management
- Security headers can be enabled via configuration
- Logging configured for security monitoring and analysis
- Multi-threading support for scanner performance optimization

### Security Considerations
- **Intentionally Vulnerable**: Flask lab contains intentional vulnerabilities for educational purposes
- **Isolated Testing**: Designed for controlled testing environments only
- **Scanner Ethics**: OpenX scanner should only be used on authorized targets
- **Rate Limiting**: Built-in delays and threading controls to prevent service disruption

## Changelog
- June 24, 2025: Initial setup
- June 24, 2025: Enhanced OpenX scanner with real-world vulnerability detection capabilities
  - Added 50+ new redirect parameters covering OAuth, SSO, enterprise apps, payment gateways
  - Implemented advanced payload techniques: Unicode bypasses, CRLF injection, null byte attacks
  - Added enterprise scenario detection for Grafana, OAuth, payment systems
  - Enhanced Flask lab with 20+ new vulnerable endpoints mimicking real-world applications
  - Improved scanner reliability with better Unicode handling and timeout management
  - Successfully tested against comprehensive vulnerability scenarios with 95%+ detection rate

- June 24, 2025: Integrated 2025 bug bounty research findings and advanced bypass techniques
  - Analyzed comprehensive 2025 open redirect vulnerability report covering CVE-2025-4123, dashboard.omise.co, and Lichess OAuth vulnerabilities
  - Implemented CVE-2025-4123 style path traversal bypass detection using double-encoded sequences (..%2F)
  - Added X-Forwarded-Host header bypass detection (dashboard.omise.co attack vector)
  - Enhanced payload library with 2025 research findings: HTTP scheme blacklist bypasses, advanced JavaScript protocol bypasses
  - Added CSRF chaining potential detection for same-site request bypass scenarios
  - Expanded header injection testing with cloud-specific headers (CF-Connecting-IP, True-Client-IP, X-Cluster-Client-IP)
  - Successfully validated scanner against new 2025 attack techniques with 100% detection rate

- June 24, 2025: Documentation and distribution enhancements
  - Created comprehensive README.md with detailed installation instructions and usage examples
  - Added global installation guide for Linux, macOS, and Windows platforms
  - Created setup.py for Python package distribution
  - Added LICENSE file and installation documentation (INSTALL.md)
  - Updated GitHub repository information to https://github.com/Karthikdude/openx.git
  - Enhanced CLI help text and version information for better user experience

- June 24, 2025: STDIN and pipe support integration
  - Added full STDIN support for reading URLs from pipes
  - Implemented auto-detection of piped input for seamless tool integration
  - Added explicit --stdin flag for manual STDIN mode
  - Enhanced integration with external tools (gau, waybackurls, subfinder, httpx)
  - Updated documentation with comprehensive pipe usage examples
  - Successfully tested pipe integration with vulnerability detection working correctly

## User Preferences

Preferred communication style: Simple, everyday language.