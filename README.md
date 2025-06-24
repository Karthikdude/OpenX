
# 🔓 OpenX - Advanced Open Redirect Vulnerability Scanner & Testing Lab

<div align="center">

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Vulnerabilities Detected](https://img.shields.io/badge/vulnerabilities-100%2B-red.svg)](https://github.com/Karthikdude/openx)
[![Security Research](https://img.shields.io/badge/research-2025%20findings-orange.svg)](CHANGELOG.md)
[![Flask Lab](https://img.shields.io/badge/testing%20lab-35%2B%20endpoints-purple.svg)](app.py)

**🚀 A cutting-edge, production-grade cybersecurity tool for detecting open redirect vulnerabilities**

*Built with insights from 2025 bug bounty research and real-world attack scenarios*

</div>

---

## 📋 Table of Contents

- [🎯 Project Overview](#-project-overview)
- [✨ Key Features](#-key-features)
- [🚀 Quick Start](#-quick-start)
- [📖 Documentation](#-documentation)
- [🛠️ Installation](#️-installation)
- [💻 Usage Examples](#-usage-examples)
- [🧪 Testing Lab](#-testing-lab)
- [🔧 Advanced Configuration](#-advanced-configuration)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🆘 Support](#-support)

---

## 🎯 Project Overview

**OpenX** combines sophisticated vulnerability detection with educational security testing in a comprehensive package designed for both security professionals and students. The project serves as both a powerful penetration testing tool and an interactive learning environment for understanding open redirect vulnerabilities.

### 🔬 What's Inside

| Component | Description | Features |
|-----------|-------------|----------|
| **🔍 OpenX Scanner** | Advanced CLI vulnerability scanner | 100+ payloads, multi-threading, bypass techniques |
| **🧪 Flask Testing Lab** | Educational web application | 35+ vulnerable endpoints, interactive dashboard |

---

## ✨ Key Features

### 🔍 OpenX Scanner Capabilities

<table>
<tr>
<td width="50%">

**🚀 Performance & Detection**
- ⚡ Multi-threaded scanning with configurable concurrency
- 🔍 100+ sophisticated payload variations
- 🎯 Real-world scenario detection (OAuth, enterprise apps)
- 🛡️ Advanced bypass techniques (2025 research findings)

</td>
<td width="50%">

**🔗 Integration & Output**
- 📥 Full STDIN/pipe support for tool chaining
- 🔧 External tool integration (`gau`, `waybackurls`)
- 📊 Multiple output formats (JSON, CSV, TXT)
- 🎛️ Comprehensive configuration options

</td>
</tr>
</table>

### 🧪 Flask Testing Lab Features

<table>
<tr>
<td width="50%">

**📚 Educational Platform**
- 🌐 Interactive web dashboard
- 📱 Responsive Bootstrap interface
- 🔄 Real-time payload testing
- 📊 Live result tracking

</td>
<td width="50%">

**🎓 Vulnerability Categories**
- 🔰 Basic redirect vulnerabilities
- 🔥 Advanced bypass techniques
- 🔐 OAuth implementation flaws
- 🏢 Enterprise application scenarios

</td>
</tr>
</table>

---

## 🚀 Quick Start

### ⚡ 30-Second Setup

```bash
# 1. Clone the repository
git clone https://github.com/Karthikdude/openx.git
cd openx

# 2. Install dependencies
pip install flask colorama requests urllib3

# 3. Test the scanner
python openx.py --help

# 4. Start the testing lab
python app.py
```

> 🌐 **Testing Lab**: Open `http://localhost:5000` in your browser

---

## 📖 Documentation

<div align="center">

| 📋 Document | 📝 Description | 🔗 Link |
|-------------|----------------|---------|
| **📦 Installation Guide** | Detailed setup instructions for all platforms | [INSTALL.md](INSTALL.md) |
| **📝 Changelog** | Version history and feature updates | [CHANGELOG.md](CHANGELOG.md) |
| **🤝 Contributing** | Guidelines for contributing to the project | [CONTRIBUTING.md](CONTRIBUTING.md) |
| **⚖️ License** | MIT License terms and conditions | [LICENSE](LICENSE) |

</div>

---

## 🛠️ Installation

### 📋 System Requirements

- **Python**: 3.8 or higher
- **Operating System**: Linux, macOS, Windows
- **Memory**: Minimum 512MB RAM
- **Storage**: 50MB free space

### 🔧 Installation Methods

<details>
<summary><b>🎯 Method 1: Quick Installation (Recommended)</b></summary>

```bash
git clone https://github.com/Karthikdude/openx.git
cd openx
pip install flask colorama requests urllib3
python openx.py --help
```

</details>

<details>
<summary><b>🐍 Method 2: Virtual Environment</b></summary>

```bash
git clone https://github.com/Karthikdude/openx.git
cd openx
python -m venv openx-env
source openx-env/bin/activate  # Linux/Mac
pip install -r requirements.txt
```

</details>

<details>
<summary><b>🌍 Method 3: Global Installation</b></summary>

```bash
git clone https://github.com/Karthikdude/openx.git
cd openx
pip install -e .
openx --help
```

</details>

> 📚 **Need help?** Check our comprehensive [Installation Guide](INSTALL.md) for platform-specific instructions and troubleshooting.

---

## 💻 Usage Examples

### 🔍 Scanner Usage

<table>
<tr>
<th width="50%">🎯 Basic Scanning</th>
<th width="50%">🔗 Tool Integration</th>
</tr>
<tr>
<td>

```bash
# Single URL scan
python openx.py -u "https://example.com/redirect?url="

# Batch scanning
python openx.py -l urls.txt -o results.json

# Fast mode scanning
python openx.py -u "https://target.com" -f -v
```

</td>
<td>

```bash
# Pipe integration
echo "https://example.com/redirect?url=" | python openx.py

# External tool integration
python openx.py -e example.com --e-gau -s

# Chain with other tools
gau example.com | grep redirect | python openx.py
```

</td>
</tr>
</table>

### 🧪 Testing Lab Usage

```bash
# Start the educational lab
python app.py

# Access dashboard at: http://localhost:5000
# Test various vulnerability categories interactively
```

---

## 🧪 Testing Lab

### 🎯 Vulnerability Categories

<div align="center">

| 🔰 Category | 📊 Endpoints | 🎯 Purpose |
|-------------|--------------|------------|
| **Basic Redirects** | 8 endpoints | Fundamental redirect vulnerabilities |
| **Advanced Bypasses** | 12 endpoints | Sophisticated evasion techniques |
| **OAuth Scenarios** | 6 endpoints | OAuth implementation flaws |
| **Enterprise Patterns** | 9 endpoints | Real-world application scenarios |

</div>

### 🌐 Interactive Features

- **📊 Real-time Dashboard**: Monitor testing progress and results
- **🔄 Live Testing**: JavaScript-powered payload testing
- **📱 Responsive Design**: Works on desktop, tablet, and mobile
- **📈 Progress Tracking**: Visual indicators for test completion

---

## 🔧 Advanced Configuration

### ⚙️ Scanner Configuration

```bash
# Custom threading and timeouts
python openx.py -u "https://target.com" --threads 20 --timeout 15

# Proxy and headers
python openx.py -u "https://target.com" --proxy http://127.0.0.1:8080 --headers

# Custom payloads
python openx.py -u "https://target.com" --payloads custom.txt --callback https://evil.com
```

### 🎛️ Output Formats

| Format | Description | Usage |
|--------|-------------|--------|
| **JSON** | Structured data for tools | `-o results.json` |
| **CSV** | Spreadsheet compatible | `-o results.csv` |
| **TXT** | Human readable | `-o results.txt` |

---

## 🤝 Contributing

We welcome contributions to OpenX! Whether you're fixing bugs, adding features, or improving documentation, your help is appreciated.

### 🚀 Quick Contribution Guide

1. **🍴 Fork the repository**
2. **🌿 Create a feature branch**
3. **💻 Make your changes**
4. **✅ Test thoroughly**
5. **📝 Submit a pull request**

> 📋 **Detailed Guidelines**: Read our [Contributing Guide](CONTRIBUTING.md) for comprehensive instructions, coding standards, and development setup.

### 🎯 Areas for Contribution

<div align="center">

| 🔥 High Priority | 🟡 Medium Priority | 🔵 Low Priority |
|------------------|-------------------|-----------------|
| New bypass payloads | UI/UX improvements | Additional test cases |
| Performance optimizations | Documentation enhancements | Configuration file support |
| External tool integration | Error handling improvements | Plugin architecture |
| Output format additions | Code refactoring | Alternative language bindings |

</div>

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License - Copyright (c) 2025 OpenX Security Research Team
Permission is hereby granted, free of charge, to any person obtaining a copy...
```

---

## 🆘 Support

### 🔗 Quick Links

<div align="center">

| 📋 Resource | 🔗 Link | 📝 Description |
|-------------|---------|----------------|
| **🐛 Bug Reports** | [GitHub Issues](https://github.com/Karthikdude/openx/issues) | Report bugs and request features |
| **💬 Discussions** | [GitHub Discussions](https://github.com/Karthikdude/openx/discussions) | Community support and questions |
| **📚 Documentation** | [Project Wiki](https://github.com/Karthikdude/openx/wiki) | Comprehensive guides and tutorials |
| **🔄 Updates** | [Release Notes](CHANGELOG.md) | Latest changes and version history |

</div>

### 🚨 Getting Help

<details>
<summary><b>🐛 Found a Bug?</b></summary>

1. Check existing [GitHub Issues](https://github.com/Karthikdude/openx/issues)
2. Create a new issue with:
   - Operating system and version
   - Python version
   - Full error message
   - Steps to reproduce

</details>

<details>
<summary><b>💡 Have a Feature Request?</b></summary>

1. Search existing [feature requests](https://github.com/Karthikdude/openx/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement)
2. Open a new issue with:
   - Clear description of the feature
   - Use cases and examples
   - Security impact explanation

</details>

<details>
<summary><b>🤔 Need Help Getting Started?</b></summary>

1. Read the [Installation Guide](INSTALL.md)
2. Check the [Contributing Guidelines](CONTRIBUTING.md)
3. Join [GitHub Discussions](https://github.com/Karthikdude/openx/discussions)

</details>

---

<div align="center">

### 🎉 Thank You for Using OpenX!

**⭐ If you find OpenX useful, please consider giving it a star on GitHub!**

---

**🔐 Built with ❤️ by the Security Research Community**

*For educational and authorized security testing purposes only*

[![GitHub Stars](https://img.shields.io/github/stars/Karthikdude/openx?style=social)](https://github.com/Karthikdude/openx)
[![GitHub Forks](https://img.shields.io/github/forks/Karthikdude/openx?style=social)](https://github.com/Karthikdude/openx)

</div>
