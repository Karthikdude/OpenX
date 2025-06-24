#!/bin/bash
# OpenX Global Installation Script for Linux/macOS

set -e

echo "🚀 OpenX Global Installation Script"
echo "===================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8+ first."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.8"

if [[ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]]; then
    echo "❌ Python $PYTHON_VERSION detected. Please upgrade to Python 3.8 or higher."
    exit 1
fi

echo "✅ Python $PYTHON_VERSION detected"

# Install dependencies
echo "📦 Installing dependencies..."
pip3 install flask colorama requests urllib3

# Make script executable
chmod +x openx.py

# Determine installation method
echo "🔧 Setting up global access..."

if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    INSTALL_PATH="/usr/local/bin/openx"
else
    # Linux
    INSTALL_PATH="/usr/local/bin/openx"
fi

# Create symbolic link
if sudo ln -sf "$(pwd)/openx.py" "$INSTALL_PATH" 2>/dev/null; then
    echo "✅ OpenX installed globally at $INSTALL_PATH"
    echo "🎉 Installation complete! You can now use 'openx' from anywhere."
    echo ""
    echo "Usage examples:"
    echo "  openx --help"
    echo "  openx -u 'http://example.com/redirect?url=' -v"
    echo "  openx -f urls.txt --headers"
else
    echo "⚠️  Could not install globally (permission denied)."
    echo "💡 You can still use OpenX with: python3 $(pwd)/openx.py"
    echo ""
    echo "To install globally manually:"
    echo "  sudo ln -sf $(pwd)/openx.py /usr/local/bin/openx"
fi

# Test installation
echo ""
echo "🧪 Testing installation..."
if command -v openx &> /dev/null; then
    openx --version
else
    python3 openx.py --version
fi

echo ""
echo "🎓 To start the Flask testing lab:"
echo "  python3 app.py"
echo "  Then visit: http://localhost:5000"