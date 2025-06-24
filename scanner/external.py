"""
External tool integration for OpenX scanner
"""

import subprocess
import os
import tempfile
from .utils import validate_url, is_valid_domain

class ExternalTools:
    """Integration with external URL gathering tools"""
    
    def __init__(self):
        """Initialize external tools manager"""
        pass
    
    def check_gau_available(self):
        """Check if gau tool is available"""
        try:
            result = subprocess.run(['gau', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return False
    
    def check_wayback_available(self):
        """Check if waybackurls tool is available"""
        try:
            result = subprocess.run(['waybackurls', '--help'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return False
    
    def run_gau(self, target):
        """Run gau tool to gather URLs"""
        urls = []
        
        try:
            # Determine if target is a domain or file
            if os.path.isfile(target):
                # Read domains from file
                with open(target, 'r') as f:
                    domains = [line.strip() for line in f.readlines() 
                              if line.strip() and is_valid_domain(line.strip())]
            else:
                # Single domain
                if not is_valid_domain(target):
                    raise ValueError(f"Invalid domain: {target}")
                domains = [target]
            
            # Run gau for each domain
            for domain in domains:
                try:
                    # Run gau with timeout
                    result = subprocess.run(
                        ['gau', domain],
                        capture_output=True,
                        text=True,
                        timeout=300  # 5 minute timeout
                    )
                    
                    if result.returncode == 0:
                        # Parse URLs from output
                        domain_urls = [url.strip() for url in result.stdout.split('\n') 
                                     if url.strip() and validate_url(url.strip())]
                        urls.extend(domain_urls)
                    else:
                        print(f"Warning: gau failed for domain {domain}: {result.stderr}")
                
                except subprocess.TimeoutExpired:
                    print(f"Warning: gau timeout for domain {domain}")
                except Exception as e:
                    print(f"Warning: gau error for domain {domain}: {str(e)}")
        
        except Exception as e:
            raise Exception(f"Error running gau: {str(e)}")
        
        # Filter URLs that might contain redirect parameters
        filtered_urls = self.filter_potential_redirect_urls(urls)
        
        return filtered_urls
    
    def run_wayback(self, target):
        """Run waybackurls tool to gather URLs"""
        urls = []
        
        try:
            # Determine if target is a domain or file
            if os.path.isfile(target):
                # Read domains from file
                with open(target, 'r') as f:
                    domains = [line.strip() for line in f.readlines() 
                              if line.strip() and is_valid_domain(line.strip())]
            else:
                # Single domain
                if not is_valid_domain(target):
                    raise ValueError(f"Invalid domain: {target}")
                domains = [target]
            
            # Run waybackurls for each domain
            for domain in domains:
                try:
                    # Run waybackurls with timeout
                    result = subprocess.run(
                        ['waybackurls', domain],
                        capture_output=True,
                        text=True,
                        timeout=300  # 5 minute timeout
                    )
                    
                    if result.returncode == 0:
                        # Parse URLs from output
                        domain_urls = [url.strip() for url in result.stdout.split('\n') 
                                     if url.strip() and validate_url(url.strip())]
                        urls.extend(domain_urls)
                    else:
                        print(f"Warning: waybackurls failed for domain {domain}: {result.stderr}")
                
                except subprocess.TimeoutExpired:
                    print(f"Warning: waybackurls timeout for domain {domain}")
                except Exception as e:
                    print(f"Warning: waybackurls error for domain {domain}: {str(e)}")
        
        except Exception as e:
            raise Exception(f"Error running waybackurls: {str(e)}")
        
        # Filter URLs that might contain redirect parameters
        filtered_urls = self.filter_potential_redirect_urls(urls)
        
        return filtered_urls
    
    def filter_potential_redirect_urls(self, urls):
        """Filter URLs that potentially contain redirect parameters"""
        redirect_keywords = [
            'redirect', 'url', 'return', 'next', 'goto', 'target',
            'destination', 'forward', 'location', 'site', 'callback',
            'success', 'continue', 'r', 'u', 'link', 'path', 'ref'
        ]
        
        potential_urls = []
        
        for url in urls:
            # Check if URL contains potential redirect parameters
            url_lower = url.lower()
            
            # Look for redirect keywords in query parameters
            if '?' in url:
                query_part = url.split('?', 1)[1]
                if any(keyword in query_part for keyword in redirect_keywords):
                    potential_urls.append(url)
                    continue
            
            # Look for redirect keywords in path
            if any(keyword in url_lower for keyword in redirect_keywords):
                potential_urls.append(url)
                continue
            
            # Include URLs with query parameters even if they don't match keywords
            # (for comprehensive testing)
            if '?' in url and '=' in url:
                potential_urls.append(url)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_urls = []
        for url in potential_urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)
        
        return unique_urls
    
    def save_urls_to_temp_file(self, urls):
        """Save URLs to temporary file for processing"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for url in urls:
                    f.write(url + '\n')
                return f.name
        except Exception as e:
            raise Exception(f"Error saving URLs to temp file: {str(e)}")
    
    def cleanup_temp_file(self, filepath):
        """Clean up temporary file"""
        try:
            if os.path.exists(filepath):
                os.unlink(filepath)
        except Exception:
            pass  # Ignore cleanup errors
