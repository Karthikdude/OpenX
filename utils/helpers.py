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
from typing import List, Dict, Any, Optional, Tuple, Set
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

def normalize_url(url: str) -> str:
    """
    Normalize a URL by handling common issues
    
    Args:
        url (str): URL to normalize
        
    Returns:
        str: Normalized URL
    """
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Parse the URL
    parsed = urllib.parse.urlparse(url)
    
    # Normalize the path
    path = parsed.path or '/'
    
    # Rebuild the URL
    normalized = urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        path,
        parsed.params,
        parsed.query,
        parsed.fragment
    ))
    
    return normalized

def detect_redirect_params(url: str) -> List[str]:
    """
    Detect potential redirection parameters in a URL
    
    Args:
        url (str): URL to analyze
        
    Returns:
        List[str]: List of potential redirection parameters
    """
    # Common redirect parameter names
    redirect_params = [
        'redirect', 'url', 'next', 'target', 'redir', 'destination',
        'dest', 'return', 'return_url', 'return_to', 'goto', 'link',
        'to', 'out', 'view', 'dir', 'path', 'uri', 'location', 'forward',
        'forward_url', 'go', 'site', 'page', 'file', 'val', 'validate', 'domain',
        'callback', 'return_path', 'returnTo', 'continue', 'continue_to',
        'redirect_to', 'redirectUrl', 'redirect_uri', 'redirectUri', 'u', 'r'
    ]
    
    redirect_found = []
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    
    for param in query_params:
        if param.lower() in redirect_params:
            redirect_found.append(param)
    
    return redirect_found

def analyze_url_for_vulnerabilities(url: str) -> Dict[str, Any]:
    """
    Analyze a URL for potential vulnerability indicators
    
    Args:
        url (str): URL to analyze
        
    Returns:
        Dict[str, Any]: Analysis results
    """
    analysis = {
        'has_redirect_params': False,
        'redirect_params': [],
        'has_open_redirects': False,
        'risk_score': 0,
        'notes': []
    }
    
    # Check for redirect parameters
    redirect_params = detect_redirect_params(url)
    if redirect_params:
        analysis['has_redirect_params'] = True
        analysis['redirect_params'] = redirect_params
        analysis['risk_score'] += 5
        analysis['notes'].append(f"Found potential redirect parameters: {', '.join(redirect_params)}")
    
    # Check for URLs in query parameters (potential open redirects)
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    
    for param, values in query_params.items():
        for value in values:
            if value.startswith(('http://', 'https://', '//', 'www.')):
                analysis['has_open_redirects'] = True
                analysis['risk_score'] += 8
                analysis['notes'].append(f"Parameter '{param}' contains a URL: {value}")
    
    # Check for suspicious path segments
    path_segments = parsed.path.split('/')
    for segment in path_segments:
        if segment.lower() in ['redirect', 'redir', 'go', 'out', 'goto', 'return']:
            analysis['risk_score'] += 3
            analysis['notes'].append(f"Suspicious path segment: {segment}")
    
    # Categorize risk
    if analysis['risk_score'] >= 10:
        analysis['risk_level'] = 'high'
    elif analysis['risk_score'] >= 5:
        analysis['risk_level'] = 'medium'
    else:
        analysis['risk_level'] = 'low'
    
    return analysis

def read_urls_from_file(filename: str, analyze: bool = True, normalize: bool = True) -> List[Dict[str, Any]]:
    """
    Read URLs from a file with enhanced handling
    
    Args:
        filename (str): Path to file containing URLs
        analyze (bool): Whether to analyze URLs for vulnerabilities
        normalize (bool): Whether to normalize URLs
        
    Returns:
        List[Dict[str, Any]]: List of URL objects with metadata
    """
    url_objects = []
    seen_urls = set()  # For duplicate detection
    seen_normalized = set()  # For normalized duplicate detection
    logger = logging.getLogger('openx.helpers')
    
    try:
        # Determine file type from extension
        file_ext = Path(filename).suffix.lower()
        
        if file_ext == '.json':
            # Handle JSON file
            with open(filename, 'r') as file:
                data = json.load(file)
                # Handle different JSON formats
                if isinstance(data, list):
                    # List of strings or objects
                    for item in data:
                        if isinstance(item, str):
                            url = item.strip()
                        elif isinstance(item, dict) and 'url' in item:
                            url = item['url'].strip()
                        else:
                            continue
                        
                        if url and is_valid_url(url):
                            _process_url(url, url_objects, seen_urls, seen_normalized, analyze, normalize)
                elif isinstance(data, dict):
                    # Dictionary with URLs as values or in nested structure
                    for key, value in data.items():
                        if isinstance(value, str) and is_valid_url(value):
                            _process_url(value, url_objects, seen_urls, seen_normalized, analyze, normalize)
        elif file_ext == '.csv':
            # Handle CSV file
            import csv
            with open(filename, 'r') as file:
                reader = csv.reader(file)
                for row in reader:
                    for item in row:
                        url = item.strip()
                        if url and is_valid_url(url):
                            _process_url(url, url_objects, seen_urls, seen_normalized, analyze, normalize)
        else:
            # Handle text file (default)
            with open(filename, 'r') as file:
                for line in file:
                    url = line.strip()
                    # Skip comments and empty lines
                    if not url or url.startswith('#'):
                        continue
                    
                    if is_valid_url(url):
                        _process_url(url, url_objects, seen_urls, seen_normalized, analyze, normalize)
        
        logger.info(f"Loaded {len(url_objects)} unique URLs from {filename}")
        
        # Sort URLs by risk score if analyzed
        if analyze:
            url_objects.sort(key=lambda x: x.get('analysis', {}).get('risk_score', 0), reverse=True)
            
            # Log high-risk URLs
            high_risk_urls = [u for u in url_objects if u.get('analysis', {}).get('risk_level') == 'high']
            if high_risk_urls:
                logger.info(f"Found {len(high_risk_urls)} high-risk URLs")
                
    except Exception as e:
        logger.error(f"Error reading URLs from file {filename}: {e}")
    
    return url_objects

def _process_url(url: str, url_objects: List[Dict[str, Any]], seen_urls: Set[str], 
                seen_normalized: Set[str], analyze: bool, normalize: bool) -> None:
    """
    Process a URL and add it to the URL objects list if it's unique
    
    Args:
        url (str): URL to process
        url_objects (List[Dict[str, Any]]): List to add the URL object to
        seen_urls (Set[str]): Set of seen URLs
        seen_normalized (Set[str]): Set of seen normalized URLs
        analyze (bool): Whether to analyze the URL
        normalize (bool): Whether to normalize the URL
    """
    # Skip if we've seen this exact URL
    if url in seen_urls:
        return
    
    # Create URL object
    url_object = {'url': url}
    
    # Normalize if requested
    if normalize:
        normalized_url = normalize_url(url)
        url_object['normalized_url'] = normalized_url
        
        # Skip if we've seen this normalized URL
        if normalized_url in seen_normalized:
            return
        
        seen_normalized.add(normalized_url)
    
    # Analyze if requested
    if analyze:
        url_object['analysis'] = analyze_url_for_vulnerabilities(url)
    
    # Add to our collections
    url_objects.append(url_object)
    seen_urls.add(url)

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
