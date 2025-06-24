#!/usr/bin/env python3
"""
Setup script for OpenX - Advanced Open Redirect Vulnerability Scanner
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    requirements = []
    if os.path.exists("requirements.txt"):
        with open("requirements.txt", "r", encoding="utf-8") as fh:
            requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    return requirements

setup(
    name="openx-scanner",
    version="1.0.0",
    author="Karthik",
    author_email="karthik@example.com",
    description="Advanced Open Redirect Vulnerability Scanner & Testing Lab",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/Karthikdude/openx",
    project_urls={
        "Bug Reports": "https://github.com/Karthikdude/openx/issues",
        "Source": "https://github.com/Karthikdude/openx",
        "Documentation": "https://github.com/Karthikdude/openx/blob/main/README.md",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Testing",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "openx=openx:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.txt", "*.md", "*.json", "*.csv"],
    },
    keywords=[
        "security", "vulnerability", "scanner", "open-redirect", 
        "penetration-testing", "bug-bounty", "web-security", 
        "cybersecurity", "ethical-hacking"
    ],
    zip_safe=False,
)