# OpenX Installation Guide

This guide provides detailed installation instructions for the OpenX scanner and testing lab on different operating systems.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Installation Methods](#installation-methods)
3. [Platform-Specific Instructions](#platform-specific-instructions)
4. [Global Installation](#global-installation)
5. [Verification](#verification)
6. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements
- **Python**: 3.8 or higher
- **Operating System**: Linux, macOS, Windows
- **Memory**: Minimum 512MB RAM
- **Storage**: 50MB free space
- **Network**: Internet connection for dependency installation

### Required Tools
- `python3` and `pip` package manager
- `git` for repository cloning
- Terminal/Command Prompt access

## Installation Methods

### Method 1: Quick Start (Recommended for Testing)

```bash
# Clone the repository
git clone https://github.com/Karthikdude/openx.git
cd openx

# Install dependencies
pip install flask colorama requests urllib3

# Test installation
python openx.py --help
```

### Method 2: Virtual Environment (Recommended for Development)

```bash
# Clone repository
git clone https://github.com/Karthikdude/openx.git
cd openx

# Create virtual environment
python -m venv openx-env

# Activate virtual environment
source openx-env/bin/activate  # Linux/Mac
# OR
openx-env\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Verify installation
python openx.py --version
```

### Method 3: Python Package Installation

```bash
# Clone and install as package
git clone https://github.com/Karthikdude/openx.git
cd openx

# Install in development mode
pip install -e .

# Use globally
openx --help
```

## Platform-Specific Instructions

### Linux (Ubuntu/Debian)

```bash
# Update package manager
sudo apt update

# Install Python and pip
sudo apt install python3 python3-pip git

# Clone repository
git clone https://github.com/Karthikdude/openx.git
cd openx

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x openx.py

# Test installation
python3 openx.py --help
```

### Linux (CentOS/RHEL/Fedora)

```bash
# Install Python and pip
sudo dnf install python3 python3-pip git  # Fedora
# OR
sudo yum install python3 python3-pip git  # CentOS/RHEL

# Clone repository
git clone https://github.com/Karthikdude/openx.git
cd openx

# Install dependencies
pip3 install -r requirements.txt

# Test installation
python3 openx.py --help
```

### macOS

```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and Git
brew install python git

# Clone repository
git clone https://github.com/Karthikdude/openx.git
cd openx

# Install dependencies
pip3 install -r requirements.txt

# Test installation
python3 openx.py --help
```

### Windows

#### Using Command Prompt
```batch
# Install Python from python.org (ensure pip is included)
# Install Git from git-scm.com

# Clone repository
git clone https://github.com/Karthikdude/openx.git
cd openx

# Install dependencies
pip install -r requirements.txt

# Test installation
python openx.py --help
```

#### Using PowerShell
```powershell
# Enable execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Clone repository
git clone https://github.com/Karthikdude/openx.git
Set-Location openx

# Install dependencies
pip install -r requirements.txt

# Test installation
python openx.py --help
```

## Global Installation

### Linux/macOS Global Access

```bash
# Navigate to OpenX directory
cd /path/to/openx

# Method 1: Symbolic Link
sudo ln -s $(pwd)/openx.py /usr/local/bin/openx
sudo chmod +x /usr/local/bin/openx

# Method 2: Copy to bin directory
sudo cp openx.py /usr/local/bin/openx
sudo chmod +x /usr/local/bin/openx

# Method 3: Add to PATH
echo 'export PATH="$PATH:/path/to/openx"' >> ~/.bashrc
source ~/.bashrc

# Verify global access
openx --help
```

### Windows Global Access

#### Method 1: Add to PATH
1. Right-click "This PC" → Properties
2. Click "Advanced system settings"
3. Click "Environment Variables"
4. Under "System Variables", find and select "Path"
5. Click "Edit" → "New"
6. Add the full path to your OpenX directory
7. Click "OK" to save

#### Method 2: Create Batch File
```batch
# Navigate to OpenX directory
cd C:\path\to\openx

# Create batch wrapper
echo @python "%%~dp0openx.py" %%* > openx.bat

# Copy to Windows directory (requires admin)
copy openx.bat C:\Windows\System32\

# Test global access
openx --help
```

#### Method 3: PowerShell Profile
```powershell
# Edit PowerShell profile
notepad $PROFILE

# Add this line to the profile:
function openx { python C:\path\to\openx\openx.py $args }

# Reload profile
. $PROFILE

# Test global access
openx --help
```

## Verification

### Test Scanner Functionality
```bash
# Basic functionality test
openx --help

# Version check
openx --version

# Quick scan test (use your own test server)
openx -u "http://httpbin.org/redirect-to?url=http://example.com" -v
```

### Test Flask Lab
```bash
# Start the testing lab
python app.py

# Verify in browser
# Navigate to: http://localhost:5000
```

### Test Dependencies
```python
# Test in Python shell
python -c "import flask, colorama, requests, urllib3; print('All dependencies installed successfully!')"
```

## Troubleshooting

### Common Issues

#### Permission Denied (Linux/macOS)
```bash
# Fix script permissions
chmod +x openx.py

# Fix directory permissions
chmod 755 /path/to/openx
```

#### Python Not Found
```bash
# Check Python installation
python --version
python3 --version

# Check PATH
echo $PATH  # Linux/macOS
echo %PATH% # Windows
```

#### Module Not Found Errors
```bash
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt

# Check pip version
pip --version

# Update pip
python -m pip install --upgrade pip
```

#### Port Already in Use (Flask Lab)
```bash
# Check what's using port 5000
lsof -i :5000  # Linux/macOS
netstat -ano | findstr :5000  # Windows

# Use different port
python app.py --port 8080
```

#### Firewall Issues
- **Linux**: `sudo ufw allow 5000`
- **Windows**: Add exception in Windows Defender Firewall
- **macOS**: System Preferences → Security & Privacy → Firewall

### Getting Help

If you encounter issues not covered here:

1. **Check the GitHub Issues**: [https://github.com/Karthikdude/openx/issues](https://github.com/Karthikdude/openx/issues)
2. **Create a new issue** with:
   - Operating system and version
   - Python version
   - Full error message
   - Steps to reproduce
3. **Check system logs** for additional error details

### Advanced Configuration

#### Custom Configuration File
```bash
# Create config file
cat > ~/.openxrc << EOF
OPENX_THREADS=20
OPENX_TIMEOUT=15
OPENX_USER_AGENT="OpenX-Scanner/1.0"
OPENX_DELAY=0.5
EOF

# Source in shell profile
echo 'source ~/.openxrc' >> ~/.bashrc
```

#### Proxy Configuration
```bash
# Set proxy environment variables
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080

# Use with OpenX
openx -u "http://example.com" --proxy $HTTP_PROXY
```

---

For additional support, visit the [OpenX GitHub repository](https://github.com/Karthikdude/openx).