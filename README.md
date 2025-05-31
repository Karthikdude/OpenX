# 🔍 OpenX - Advanced Open Redirect Vulnerability Scanner

<div align="center">

![Version](https://img.shields.io/badge/Version-1.0-blue)
![Python](https://img.shields.io/badge/Python-3.6%2B-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

</div>

## 📋 Overview

OpenX is an advanced open redirect vulnerability scanner developed by Karthik S Sathyan. It's designed to detect various types of open redirect vulnerabilities in web applications, including URL parameter-based redirects, meta refresh redirects, JavaScript redirects, header injections, form POST redirects, and cookie-based redirects.

The tool offers comprehensive scanning capabilities with multi-threading support, customizable payloads, and detailed reporting options.

## ✨ Features

- 🚀 **High-Performance Scanning**: Multi-threaded architecture for fast scanning
- 🔄 **Multiple Redirect Detection Methods**: Detects various types of open redirect vulnerabilities
- 📊 **Detailed Reporting**: Comprehensive vulnerability reports with severity ratings
- 🛠️ **Customizable**: Configurable threads, timeouts, user agents, and proxies
- 📝 **Multiple Output Formats**: Export results in JSON, CSV, TXT, or XML
- 🔍 **Header Injection Testing**: Detect header-based open redirect vulnerabilities
- 🧪 **Built-in Test Labs**: Includes vulnerable test applications for practice

## 📥 Installation

### Requirements

- Python 3.6+
- Required packages (install using `pip install -r requirements.txt`):
  - colorama
  - requests
  - tqdm
  - urllib3
  - python-dateutil

### Setup

```bash
# Clone the repository (or download and extract)
# Install dependencies
pip install -r requirements.txt
```

## 🌐 Global Installation

You can make OpenX globally accessible from your terminal by following these steps:

### For Windows

1. **Create a batch file** named `openx.bat` in a directory that's in your PATH (e.g., `C:\Windows` or create a custom directory and add it to PATH)

   ```batch
   @echo off
   python "%~dp0openx.py" %*
   ```

2. **Alternative: Using pip to install locally**

   Create a `setup.py` file in the project root:

   ```python
   from setuptools import setup, find_packages

   setup(
       name="openx",
       version="1.0",
       packages=find_packages(),
       entry_points={
           'console_scripts': [
               'openx=openx:main',
           ],
       },
       install_requires=[
           'colorama',
           'requests',
           'tqdm',
           'urllib3',
           'python-dateutil',
       ],
   )
   ```

   Then install it:

   ```bash
   pip install -e .
   ```

### For Linux/macOS

1. **Create a symbolic link**

   ```bash
   # Make the script executable
   chmod +x openx.py
   
   # Create a symbolic link in /usr/local/bin
   sudo ln -s "$(pwd)/openx.py" /usr/local/bin/openx
   ```

2. **Alternative: Using an alias**

   Add this line to your `.bashrc` or `.zshrc`:

   ```bash
   alias openx='python /path/to/OpenXScanner/openx.py'
   ```

   Then reload your shell configuration:

   ```bash
   source ~/.bashrc  # or source ~/.zshrc
   ```

3. **Alternative: Using pip to install locally**

   Same as Windows method above.

After installation, you can use OpenX directly from any directory:

```bash
# Instead of
python /path/to/openx.py -u https://example.com

# You can now use
openx -u https://example.com
```

## 🚀 Usage

OpenX provides a comprehensive command-line interface with various options:

```
usage: openx.py [-h] [-u URL] [-l LIST] [-o OUTPUT] [-c CALLBACK] [--headers]
                [--payloads PAYLOADS] [--threads THREADS] [--timeout TIMEOUT]
                [--delay DELAY] [--user-agent USER_AGENT] [--proxy PROXY]
                [--follow-redirects FOLLOW_REDIRECTS] [--status-codes] [--verbose]
                [--silent] [-f]
                                                                                           
OpenX - Advanced Open Redirect Vulnerability Scanner

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Single target URL for scanning
  -l LIST, --list LIST  Path to file containing list of URLs to scan
  -o OUTPUT, --output OUTPUT
                        Output file path with format auto-detection
  -c CALLBACK, --callback CALLBACK
                        Callback URL (Burp Collaborator or custom endpoint)
  --headers             Enable header-based injection testing
  --payloads PAYLOADS   Path to custom payload file
  --threads THREADS     Number of concurrent threads (default: 10)
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  --delay DELAY         Delay between requests in milliseconds
  --user-agent USER_AGENT
                        Custom user-agent string
  --proxy PROXY         HTTP/HTTPS proxy configuration
  --follow-redirects FOLLOW_REDIRECTS
                        Maximum redirect chain depth to follow
  --status-codes        Display HTTP status codes in output
  --verbose             Enable detailed verbose logging
  --silent              Suppress banner and non-essential output
  -f, --fast            Fast mode: stop testing URL after first vulnerability found
```

### Examples

```bash
# Scan a single URL
openx -u https://example.com/redirect?url=

# Scan multiple URLs from a file
openx -l urls.txt -o results.json

# Advanced scanning with custom options
openx -u https://example.com --threads 20 --timeout 15

# Enable header injection testing with verbose output
openx -l domains.txt --headers --verbose
```

> Note: If you haven't set up global access, use `python openx.py` instead of just `openx`

## 🧪 Testing with Built-in Labs

OpenX includes two vulnerable Flask applications for testing and learning purposes:

### Basic Vulnerable App

Run the basic vulnerable application with:

```bash
python vulnerable_app.py
```

This starts a Flask server on http://localhost:5000 with 20+ different open redirect vulnerability patterns.

### Advanced Vulnerable Labs

Run the advanced vulnerable application with:

```bash
python advanced_labs.py
```

This starts a Flask server on http://localhost:5001 with complex, real-world open redirect scenarios.

### Test URL Lists

OpenX includes several pre-configured URL lists for testing:

- `all_labs.txt` - All vulnerable endpoints from both test applications
- `quick_test.txt` - A small subset of basic vulnerable endpoints for quick testing
- `comprehensive_test.txt` - A comprehensive set of test cases
- `advanced_urls.txt` - Complex vulnerability patterns from the advanced labs

### Example Test Command

```bash
# Test against the basic vulnerable app
openx -l all_labs.txt --verbose
```

## 📊 Output Formats

OpenX supports multiple output formats:

- JSON (default for programmatic use)
- CSV (for spreadsheet analysis)
- TXT (for simple text reports)
- XML (for integration with other tools)

```bash
# Example with JSON output
openx -u https://example.com/redirect?url= -o results.json

# Example with CSV output
openx -l urls.txt -o results.csv
```

## 🛡️ Security Considerations

- Only use the tool against applications you have permission to test
- The included vulnerable applications are for educational purposes only
- Never use the tool against production systems without proper authorization

## 🤝 Contributing

Contributions are welcome! Feel free to submit issues or pull requests.

## 📄 License

This project is licensed under the MIT License.

---

<div align="center">

**Developed by Karthik S Sathyan**

</div>
