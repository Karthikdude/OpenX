# OpenX - Advanced Open Redirect Vulnerability Scanner & Testing Lab

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Vulnerabilities Detected](https://img.shields.io/badge/vulnerabilities-100%2B-red.svg)](https://github.com/Karthikdude/openx)

**OpenX** is a cutting-edge, production-grade cybersecurity tool designed for detecting open redirect vulnerabilities in web applications. Built with insights from 2025 bug bounty research and real-world attack scenarios, OpenX combines sophisticated bypass techniques with an educational testing environment to provide comprehensive security assessment capabilities.

## 🎯 Project Overview

This repository contains two main components:

1. **OpenX Scanner** - A powerful command-line vulnerability scanner
2. **Flask Testing Lab** - An educational web application with intentionally vulnerable endpoints

The project serves both security professionals conducting penetration tests and students learning about web application security vulnerabilities.

## ✨ Key Features

### OpenX Scanner
- **🚀 Advanced Detection**: 100+ sophisticated payload variations including 2025 research findings
- **⚡ Multi-threaded Performance**: Configurable concurrency for optimal scanning speed
- **🔍 Real-World Scenarios**: Detects OAuth, enterprise applications, payment gateway vulnerabilities
- **🛡️ Bypass Techniques**: Path traversal, header injection, encoding bypasses, CSRF chaining
- **📊 Multiple Outputs**: JSON, CSV, TXT reporting formats
- **🔗 External Integration**: Support for `gau` and `waybackurls` URL discovery tools
- **📥 STDIN Support**: Full pipe support for integration with other security tools
- **🎯 Smart Detection**: Automatic recognition of CVE-2025-4123 style vulnerabilities

### Flask Testing Lab
- **📚 Educational Platform**: 35+ vulnerable endpoints across multiple categories
- **🌐 Interactive Dashboard**: Web-based testing interface with real-time results
- **🔄 Live Testing**: JavaScript-powered payload testing and result tracking
- **📱 Responsive Design**: Bootstrap-based interface for all devices
- **🎓 Learning Categories**: Basic, Advanced, OAuth, Enterprise, and Bypass techniques

## 🛠️ Installation Guide

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Git (for cloning repository)

### Method 1: Quick Installation
```bash
# Clone the repository
git clone https://github.com/Karthikdude/openx.git
cd openx

# Install dependencies
pip install flask colorama requests urllib3

# Run OpenX scanner
python openx.py --help
