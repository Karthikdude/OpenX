# OpenX - Advanced Open Redirect Vulnerability Scanner & Testing Lab

A comprehensive production-grade security testing suite consisting of:

1. **OpenX Scanner** - Advanced open redirect vulnerability scanner for real-world penetration testing
2. **Flask Testing Lab** - Educational environment for testing and validating open redirect vulnerabilities

## 🚀 Features

### OpenX Scanner
- **Advanced Payload Management** - 100+ built-in payloads with encoding variations
- **Multi-threaded Scanning** - Configurable concurrent testing
- **External Tool Integration** - Support for `gau` and `waybackurls`
- **Intelligent Detection** - Multiple detection methods (HTTP redirects, JavaScript, Meta refresh)
- **Bypass Techniques** - Domain validation bypasses, protocol manipulation, encoding variations
- **Comprehensive Reporting** - JSON, CSV, and TXT output formats
- **Header Injection Testing** - Test for header-based redirect vulnerabilities
- **Real-world Evasion** - Unicode bypasses, CRLF injection, subdomain confusion

### Flask Testing Lab
- **13 Vulnerability Categories** - Basic, Encoding, Protocol, Bypass, Header, Client-side
- **Interactive Testing Interface** - Real-time vulnerability testing with visual feedback
- **Educational Content** - Detailed explanations of each vulnerability type
- **Realistic Scenarios** - Mimics real-world application patterns
- **Comprehensive Coverage** - Multiple parameter variations and bypass techniques
- **API Integration** - RESTful API for automated testing

## 📋 Requirements

### OpenX Scanner
```bash
pip install requests colorama urllib3
