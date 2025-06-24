@echo off
REM OpenX Global Installation Script for Windows

echo 🚀 OpenX Global Installation Script
echo ====================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed. Please install Python 3.8+ first.
    echo Download from: https://python.org/downloads/
    pause
    exit /b 1
)

echo ✅ Python detected

REM Install dependencies
echo 📦 Installing dependencies...
pip install flask colorama requests urllib3

REM Create batch wrapper for global access
echo @python "%%~dp0openx.py" %%* > openx.bat

REM Try to copy to System32 (requires admin)
echo 🔧 Setting up global access...
copy openx.bat "%WINDIR%\System32\" >nul 2>&1
if errorlevel 1 (
    echo ⚠️  Could not install globally ^(admin privileges required^).
    echo 💡 You can still use OpenX with: python openx.py
    echo.
    echo To install globally manually ^(as administrator^):
    echo   copy openx.bat C:\Windows\System32\
    echo.
    echo Or add this directory to your PATH environment variable.
) else (
    echo ✅ OpenX installed globally
    echo 🎉 Installation complete! You can now use 'openx' from anywhere.
)

echo.
echo Usage examples:
echo   openx --help
echo   openx -u "http://example.com/redirect?url=" -v
echo   openx -f urls.txt --headers

REM Test installation
echo.
echo 🧪 Testing installation...
if exist "%WINDIR%\System32\openx.bat" (
    openx --version
) else (
    python openx.py --version
)

echo.
echo 🎓 To start the Flask testing lab:
echo   python app.py
echo   Then visit: http://localhost:5000

pause