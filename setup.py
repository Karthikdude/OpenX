#!/usr/bin/env python3
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="openx",
    version="3.0.0",
    author="Karthik S Sathyan",
    author_email="karthik@example.com",
    description="Advanced Open Redirect Vulnerability Scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Karthikdude/OpenX",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "aiohttp",
        "colorama",
        "pyyaml",
        "jinja2",
        "rich",
        "beautifulsoup4",
        "tqdm",
        "psutil",
    ],
    entry_points={
        "console_scripts": [
            "openx=opex:main_cli",
            "openx-coordinator=utils.distributed.coordinator:main_cli",
            "openx-worker=utils.distributed.worker:main_cli",
            "openx-cli=utils.interactive.cli_interactive:main_cli",
            "openx-dashboard=utils.interactive.web_dashboard:main_cli",
            "openx-crawler=examples.crawl_and_scan:main_cli",
            "openx-waf-bypass=examples.waf_evasion_scan:main_cli",
        ],
    },
)
