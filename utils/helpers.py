#!/usr/bin/env python3
"""
Helper utilities for OpenX
Contains common functions used across modules
"""
import os
import re
import logging
import urllib.parse
import random
import time
import json
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid
    
    Args:
        url (str): URL to check
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def read_urls_from_file(filename: str) -> List[str]:
    """
    Read URLs from a file
    
    Args:
        filename (str): Path to file containing URLs
        
    Returns:
        List[str]: List of valid URLs
    """
    urls = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                url = line.strip()
                if url and is_valid_url(url):
                    urls.append(url)
    except Exception as e:
        logging.error(f"Error reading URLs from file {filename}: {e}")
    
    return list(set(urls))  # Remove duplicates

def save_results_to_file(results: List[Dict[str, Any]], output_file: str) -> bool:
    """
    Save results to a file
    
    Args:
        results (List[Dict[str, Any]]): Results to save
        output_file (str): Output file path
        
    Returns:
        bool: True if saved successfully, False otherwise
    """
    try:
        with open(output_file, 'w') as file:
            for result in results:
                file.write(json.dumps(result) + "\n")
        return True
    except Exception as e:
        logging.error(f"Error saving results to {output_file}: {e}")
        return False

def parse_domain(url: str) -> str:
    """
    Parse domain from URL
    
    Args:
        url (str): URL to parse
        
    Returns:
        str: Domain name
    """
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc
    except Exception:
        return ""

def random_delay(min_delay: float = 0.5, max_delay: float = 3.0) -> None:
    """
    Sleep for a random time between min and max delay
    
    Args:
        min_delay (float): Minimum delay in seconds
        max_delay (float): Maximum delay in seconds
    """
    delay = random.uniform(min_delay, max_delay)
    time.sleep(delay)

def extract_redirect_params(url: str) -> List[str]:
    """
    Extract potential redirect parameters from a URL
    
    Args:
        url (str): URL to analyze
        
    Returns:
        List[str]: List of potential redirect parameters
    """
    redirect_params = []
    try:
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        
        # Common redirect parameter names
        redirect_keywords = [
            "redirect", "url", "next", "dest", "goto", "return", 
            "target", "link", "site", "location", "path"
        ]
        
        for param in query_params:
            if any(keyword in param.lower() for keyword in redirect_keywords):
                redirect_params.append(param)
    except Exception as e:
        logging.error(f"Error extracting redirect parameters from {url}: {e}")
    
    return redirect_params

def detect_waf(response_headers: Dict[str, str], response_body: str) -> Tuple[bool, str]:
    """
    Detect if a WAF is present based on response headers and body
    
    Args:
        response_headers (Dict[str, str]): Response headers
        response_body (str): Response body
        
    Returns:
        Tuple[bool, str]: (is_waf_detected, waf_type)
    """
    waf_signatures = {
        "Cloudflare": [
            ("server", "cloudflare"),
            ("cf-ray", ".*")
        ],
        "AWS WAF": [
            ("x-amzn-requestid", ".*")
        ],
        "Akamai": [
            ("server", "AkamaiGHost")
        ],
        "Imperva": [
            ("x-iinfo", ".*")
        ],
        "F5 BIG-IP ASM": [
            ("server", "BigIP")
        ],
        "Sucuri": [
            ("x-sucuri-id", ".*")
        ]
    }
    
    # Check headers for WAF signatures
    for waf_name, signatures in waf_signatures.items():
        for header_name, pattern in signatures:
            if header_name.lower() in [h.lower() for h in response_headers]:
                header_value = response_headers.get(header_name, "")
                if re.search(pattern, header_value, re.IGNORECASE):
                    return True, waf_name
    
    # Check body for WAF block messages
    waf_body_patterns = [
        (r"cloudflare", "Cloudflare"),
        (r"security check", "Generic WAF"),
        (r"access denied", "Generic WAF"),
        (r"blocked", "Generic WAF"),
        (r"forbidden", "Generic WAF"),
        (r"your IP", "Generic WAF"),
        (r"captcha", "Generic WAF")
    ]
    
    for pattern, waf_name in waf_body_patterns:
        if re.search(pattern, response_body, re.IGNORECASE):
            return True, waf_name
    
    return False, ""

def create_directory_if_not_exists(directory: str) -> bool:
    """
    Create a directory if it doesn't exist
    
    Args:
        directory (str): Directory path
        
    Returns:
        bool: True if directory exists or was created, False otherwise
    """
    try:
        os.makedirs(directory, exist_ok=True)
        return True
    except Exception as e:
        logging.error(f"Error creating directory {directory}: {e}")
        return False

def get_severity_color(severity: str) -> str:
    """
    Get color code for severity level
    
    Args:
        severity (str): Severity level
        
    Returns:
        str: ANSI color code
    """
    severity_colors = {
        "high": "\033[91m",  # Red
        "medium": "\033[93m",  # Yellow
        "low": "\033[94m",  # Blue
        "info": "\033[92m",  # Green
        "none": "\033[0m"   # Reset
    }
    
    return severity_colors.get(severity.lower(), "\033[0m")

def format_url_for_display(url: str, max_length: int = 80) -> str:
    """
    Format URL for display, truncating if necessary
    
    Args:
        url (str): URL to format
        max_length (int): Maximum length
        
    Returns:
        str: Formatted URL
    """
    if len(url) <= max_length:
        return url
    
    parsed = urllib.parse.urlparse(url)
    scheme_and_netloc = f"{parsed.scheme}://{parsed.netloc}"
    
    if len(scheme_and_netloc) >= max_length - 3:
        # If even the domain is too long, truncate it
        return scheme_and_netloc[:max_length-3] + "..."
    
    # Calculate how much of the path we can show
    remaining_length = max_length - len(scheme_and_netloc) - 3  # 3 for "..."
    
    path_query = f"{parsed.path}"
    if parsed.query:
        path_query += f"?{parsed.query}"
    
    if len(path_query) <= remaining_length:
        return f"{scheme_and_netloc}{path_query}"
    
    return f"{scheme_and_netloc}{path_query[:remaining_length]}..."
