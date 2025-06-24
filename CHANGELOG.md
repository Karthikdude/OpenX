# Changelog

All notable changes to OpenX will be documented in this file.

## [1.0.0] - 2025-06-24

### Added
- Initial release of OpenX Advanced Open Redirect Vulnerability Scanner
- Comprehensive Flask testing lab with 35+ vulnerable endpoints
- 100+ sophisticated payload variations including 2025 research findings
- Multi-threaded scanning with configurable concurrency
- Real-world scenario detection (OAuth, enterprise apps, payment gateways)
- Advanced bypass techniques: path traversal, header injection, encoding bypasses
- CSRF chaining potential detection
- Multiple output formats (JSON, CSV, TXT)
- External tool integration (gau, waybackurls)
- Interactive web dashboard for educational testing
- CVE-2025-4123 style path traversal bypass detection
- X-Forwarded-Host header bypass detection (dashboard.omise.co style)
- Cloud-specific header injection testing
- Global installation scripts for Linux, macOS, and Windows
- Comprehensive documentation and installation guides

### Security Enhancements
- Implemented 2025 bug bounty research findings
- Added detection for real-world attack vectors from recent CVEs
- Enhanced payload library with advanced encoding techniques
- Improved Unicode handling and error management

### Documentation
- Created comprehensive README.md with installation instructions
- Added INSTALL.md with platform-specific setup guides
- Included CONTRIBUTING.md for development guidelines
- Added LICENSE file and proper project structure

### Technical Improvements
- Enhanced scanner reliability with better error handling
- Improved payload generation and management
- Optimized performance for large-scale scanning
- Added support for custom callback URLs and payloads
- Full STDIN and pipe support for seamless tool integration
- Auto-detection of piped input for workflow automation
- Enhanced external tool compatibility (gau, waybackurls, subfinder, httpx)

## Development Roadmap

### Planned for v1.1.0
- Machine learning-based payload generation
- Enhanced API endpoint detection
- Integration with more external tools
- Performance optimizations for enterprise environments

### Planned for v1.2.0
- Web-based scanner interface
- Collaborative testing features
- Advanced reporting and analytics
- Plugin architecture for extensibility

### Long-term Goals
- AI-powered vulnerability pattern recognition
- Cloud-native deployment options
- Enterprise-grade reporting and compliance
- Integration with CI/CD pipelines