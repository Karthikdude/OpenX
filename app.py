"""
Flask Open Redirect Vulnerability Testing Lab
Educational environment for testing open redirect vulnerabilities
"""

import os
import urllib.parse
from flask import Flask, request, redirect, render_template, jsonify, url_for, flash
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

# Configuration
class Config:
    ENABLE_BASIC_REDIRECTS = True
    ENABLE_HEADER_REDIRECTS = True
    ENABLE_JS_REDIRECTS = True
    SECURITY_HEADERS_DISABLED = True
    DEBUG = True
    CALLBACK_URL = "http://callback.example.com"
    VALID_APP_DOMAIN = "legitapp.com"
    OAUTH_CLIENT_ID = "mock-client-id-123"
    OAUTH_AUTHORIZE_URL = "/oauth/authorize"

app.config.from_object(Config)

# Logging middleware
@app.before_request
def log_requests():
    """Log redirect attempts for analysis"""
    if request.endpoint and 'redirect' in str(request.endpoint):
        app.logger.info(f"Redirect attempt: {request.url} - Args: {request.args}")

@app.after_request
def after_request(response):
    """Configure security headers"""
    if not app.config.get('SECURITY_HEADERS_DISABLED'):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
    return response

# Main dashboard
@app.route('/')
def dashboard():
    """Main testing dashboard"""
    endpoints = [
        {
            'name': 'Basic Redirect',
            'url': '/redirect?url=',
            'description': 'Direct parameter redirect without validation',
            'payloads': ['http://evil.com', '//evil.com', 'https://evil.com'],
            'category': 'Basic'
        },
        {
            'name': 'Login Redirect',
            'url': '/login?return_url=',
            'description': 'Login form with return URL parameter',
            'payloads': ['http://evil.com', 'https://evil.com/login'],
            'category': 'Basic'
        },
        {
            'name': 'Encoded Redirect',
            'url': '/encoded-redirect?target=',
            'description': 'URL decoding before redirect',
            'payloads': ['http%3A%2F%2Fevil.com', '%2F%2Fevil.com'],
            'category': 'Encoding'
        },
        {
            'name': 'Double Encoded',
            'url': '/double-encoded?url=',
            'description': 'Double URL decoding vulnerability',
            'payloads': ['%252F%252Fevil.com', 'http%253A%252F%252Fevil.com'],
            'category': 'Encoding'
        },
        {
            'name': 'Protocol Redirect',
            'url': '/protocol-redirect?url=',
            'description': 'Protocol confusion vulnerability',
            'payloads': ['javascript:alert(1)', '//evil.com', 'data:text/html,<script>alert(1)</script>'],
            'category': 'Protocol'
        },
        {
            'name': 'Relative Redirect',
            'url': '/relative-redirect?path=',
            'description': 'Relative URL handling vulnerability',
            'payloads': ['//evil.com', '///evil.com', '\\\\evil.com'],
            'category': 'Protocol'
        },
        {
            'name': 'Whitelist Bypass',
            'url': '/whitelist-bypass?url=',
            'description': 'Weak domain validation bypass',
            'payloads': ['http://evil.com/yoursite.com', 'http://yoursite.com.evil.com'],
            'category': 'Bypass'
        },
        {
            'name': 'Subdomain Bypass',
            'url': '/subdomain-bypass?url=',
            'description': 'Subdomain confusion vulnerability',
            'payloads': ['https://yoursite.com.evil.com', 'https://yoursite.com@evil.com'],
            'category': 'Bypass'
        },
        {
            'name': 'Blacklist Bypass',
            'url': '/blacklist-bypass?url=',
            'description': 'Basic blacklist bypass techniques',
            'payloads': ['http://eviI.com', 'http://evil.com.example.com'],
            'category': 'Bypass'
        },
        {
            'name': 'Host Header Redirect',
            'url': '/host-redirect',
            'description': 'Host header injection vulnerability',
            'payloads': ['Set Host header to evil.com'],
            'category': 'Header'
        },
        {
            'name': 'Header Redirect',
            'url': '/header-redirect',
            'description': 'Custom header redirect vulnerability',
            'payloads': ['Set X-Redirect-To header to http://evil.com'],
            'category': 'Header'
        },
        {
            'name': 'JavaScript Redirect',
            'url': '/js-redirect?url=',
            'description': 'JavaScript-based redirect vulnerability',
            'payloads': ['http://evil.com', 'javascript:alert(1)'],
            'category': 'Client-Side'
        },
        {
            'name': 'Meta Refresh Redirect',
            'url': '/meta-redirect?url=',
            'description': 'Meta refresh tag vulnerability',
            'payloads': ['http://evil.com', 'javascript:alert(1)'],
            'category': 'Client-Side'
        },
        {
            'name': 'OAuth Authorize',
            'url': '/oauth/authorize?client_id=mock-client-id-123&redirect_uri=',
            'description': 'OAuth authorization endpoint vulnerability',
            'payloads': ['http://evil.com/callback', 'http://legitapp.com.evil.com/callback'],
            'category': 'OAuth'
        },
        {
            'name': 'Grafana Login',
            'url': '/grafana-login?returnTo=',
            'description': 'Grafana-style login redirect vulnerability',
            'payloads': ['//evil.com/dashboard', 'javascript:alert(1)'],
            'category': 'Enterprise'
        },
        {
            'name': 'Payment Success',
            'url': '/payment-success?success_url=',
            'description': 'Payment gateway callback vulnerability',
            'payloads': ['http://evil.com', 'https://evil.com/payment'],
            'category': 'Enterprise'
        },
        {
            'name': 'Email Confirm',
            'url': '/email-confirm?return_to=',
            'description': 'Email confirmation redirect vulnerability',
            'payloads': ['//evil.com', 'http://evil.com/confirmed'],
            'category': 'Enterprise'
        },
        {
            'name': 'Advanced Whitelist',
            'url': '/advanced-whitelist?url=',
            'description': 'Advanced regex-based whitelist bypass',
            'payloads': ['http://legitapp.com@evil.com', 'http://evil.com/legitapp.com'],
            'category': 'Advanced'
        },
        {
            'name': 'Chain Redirect',
            'url': '/chain-redirect?first=',
            'description': 'Multi-hop redirect chain vulnerability',
            'payloads': ['http://evil.com', '//evil.com'],
            'category': 'Advanced'
        }
    ]
    return render_template('dashboard.html', endpoints=endpoints)

# Basic redirect vulnerabilities
@app.route('/redirect')
def basic_redirect():
    """Level 1: Direct parameter redirect (most basic)"""
    url = request.args.get('url')
    if url:
        return redirect(url)
    return "No URL parameter provided"

@app.route('/login')
def login_redirect():
    """Login form with return URL"""
    return_url = request.args.get('return_url', '/')
    # Simulate login process
    flash('Login successful!')
    return redirect(return_url)

# Parameter variation endpoints
@app.route('/return-url')
def return_url_redirect():
    """Return URL parameter variant"""
    url = request.args.get('returnurl') or request.args.get('returnUrl')
    if url:
        return redirect(url)
    return "No return URL provided"

@app.route('/next-redirect')
def next_redirect():
    """Next parameter redirect"""
    url = request.args.get('next')
    if url:
        return redirect(url)
    return "No next URL provided"

@app.route('/goto-redirect')
def goto_redirect():
    """Goto parameter redirect"""
    url = request.args.get('goto')
    if url:
        return redirect(url)
    return "No goto URL provided"

@app.route('/target-redirect')
def target_redirect():
    """Target parameter redirect"""
    url = request.args.get('target') or request.args.get('destination')
    if url:
        return redirect(url)
    return "No target URL provided"

@app.route('/callback-redirect')
def callback_redirect():
    """Callback parameter redirect"""
    url = request.args.get('callback') or request.args.get('redirect_uri')
    if url:
        return redirect(url)
    return "No callback URL provided"

# Encoding bypass scenarios
@app.route('/encoded-redirect')
def encoded_redirect():
    """URL encoding variation"""
    url = request.args.get('target')
    if url:
        # Simulate basic URL decoding
        decoded_url = urllib.parse.unquote(url)
        return redirect(decoded_url)
    return "No target URL provided"

@app.route('/double-encoded')
def double_encoded_redirect():
    """Double encoding scenario"""
    url = request.args.get('url')
    if url:
        # Double decode
        decoded = urllib.parse.unquote(urllib.parse.unquote(url))
        return redirect(decoded)
    return "No URL provided"

# Protocol-based bypasses
@app.route('/protocol-redirect')
def protocol_redirect():
    """Protocol confusion"""
    url = request.args.get('url')
    if url:
        # Vulnerable: allows javascript:, data:, etc.
        return redirect(url)
    return "No URL provided"

@app.route('/relative-redirect')
def relative_redirect():
    """Relative URL handling"""
    path = request.args.get('path', '/')
    # Vulnerable to //evil.com bypasses
    return redirect(path)

# Filtering bypass scenarios
@app.route('/whitelist-bypass')
def whitelist_bypass():
    """Weak domain validation"""
    url = request.args.get('url')
    if url and 'yoursite.com' in url:
        # Vulnerable: allows evil.com/yoursite.com
        return redirect(url)
    return "Invalid redirect URL - must contain yoursite.com"

@app.route('/subdomain-bypass')
def subdomain_bypass():
    """Subdomain confusion"""
    url = request.args.get('url')
    if url and url.startswith('https://yoursite.com'):
        # Vulnerable: allows https://yoursite.com.evil.com
        return redirect(url)
    return "Invalid redirect URL - must start with https://yoursite.com"

@app.route('/blacklist-bypass')
def blacklist_bypass():
    """Basic blacklist"""
    url = request.args.get('url')
    blocked = ['evil.com', 'malicious.com', 'attacker.com']
    
    if url and not any(blocked_domain in url.lower() for blocked_domain in blocked):
        # Vulnerable to encoding, subdomains, case variations etc.
        return redirect(url)
    return "Blocked URL detected"

# Advanced vulnerability scenarios
@app.route('/host-redirect')
def host_redirect():
    """Host header injection"""
    host = request.headers.get('Host', 'localhost:5000')
    return redirect(f'https://{host}/success')

@app.route('/referer-redirect')
def referer_redirect():
    """Referer-based redirect"""
    referer = request.headers.get('Referer', '/')
    return redirect(referer)

@app.route('/header-redirect')
def header_redirect():
    """Custom header redirect"""
    custom_redirect = request.headers.get('X-Redirect-To')
    if custom_redirect:
        return redirect(custom_redirect)
    return "No X-Redirect-To header found"

# JavaScript-based redirects
@app.route('/js-redirect')
def js_redirect():
    """JavaScript redirect injection"""
    url = request.args.get('url', '/')
    return render_template('js_redirect.html', redirect_url=url)

# Meta refresh redirects
@app.route('/meta-redirect')
def meta_redirect():
    """Meta refresh redirect"""
    url = request.args.get('url', '/')
    return render_template('meta_redirect.html', redirect_url=url)

# Success page
@app.route('/success')
def success():
    """Success page for legitimate redirects"""
    return render_template('success.html')

# API endpoints for automation
@app.route('/api/test-redirect', methods=['POST'])
def api_test_redirect():
    """API endpoint for automated testing"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    endpoint = data.get('endpoint')
    payload = data.get('payload')
    
    if not endpoint or not payload:
        return jsonify({'error': 'endpoint and payload required'}), 400
    
    # Return structured response for automated testing
    return jsonify({
        'endpoint': endpoint,
        'payload': payload,
        'vulnerable': True,  # This would be determined by actual testing
        'redirect_location': payload,
        'timestamp': '2025-06-24T00:00:00Z'
    })

# Test multiple parameters at once
@app.route('/multi-param')
def multi_param_redirect():
    """Test multiple redirect parameters"""
    redirect_params = ['url', 'redirect', 'return', 'next', 'goto', 'target']
    
    for param in redirect_params:
        value = request.args.get(param)
        if value:
            return redirect(value)
    
    return "No redirect parameter found"

# Path-based redirect
@app.route('/path-redirect/<path:redirect_path>')
def path_redirect(redirect_path):
    """Path-based redirect vulnerability"""
    # Vulnerable: directly redirects to path parameter
    return redirect(f'http://{redirect_path}')

# OAuth-like Authorization Endpoint (Vulnerable)
@app.route('/oauth/authorize')
def oauth_authorize():
    """OAuth authorization endpoint vulnerability"""
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope')
    state = request.args.get('state')

    if not all([client_id, redirect_uri]):
        return "Missing OAuth parameters", 400

    # Simulate basic client_id check
    if client_id != app.config['OAUTH_CLIENT_ID']:
        return "Invalid client_id", 401

    # VULNERABLE: Direct redirect_uri usage without strict validation
    mock_auth_code = "mock-auth-code-xyz"
    final_redirect_url = f"{redirect_uri}?code={mock_auth_code}&state={state}"
    app.logger.info(f"OAuth redirecting to: {final_redirect_url}")
    return redirect(final_redirect_url)

# Grafana-like Login Redirect
@app.route('/grafana-login', methods=['GET', 'POST'])
def grafana_login():
    """Grafana-style login redirect vulnerability"""
    return_to = request.args.get('returnTo') or request.form.get('returnTo', '/')
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Simulate successful login
        if username == "admin" and password == "password":
            flash("Logged into Grafana (mock) successfully!")
            app.logger.info(f"Grafana login redirecting to: {return_to}")
            return redirect(return_to)
        else:
            flash("Invalid credentials for Grafana (mock).")
            return render_template('login.html', return_to=return_to)
    
    return render_template('login.html', return_to=return_to)

# Payment Gateway Success Redirect
@app.route('/payment-success')
def payment_success():
    """Payment gateway callback vulnerability"""
    success_url = request.args.get('success_url') or request.args.get('return_url')
    if success_url:
        flash("Payment processed successfully!")
        return redirect(success_url)
    return "No success URL provided"

# Email Confirmation Redirect
@app.route('/email-confirm')
def email_confirm():
    """Email confirmation redirect vulnerability"""
    return_to = request.args.get('return_to') or request.args.get('next')
    token = request.args.get('token', 'mock-token')
    
    # Simulate email confirmation
    if token:
        flash("Email confirmed successfully!")
        if return_to:
            return redirect(return_to)
    return redirect(url_for('dashboard'))

# Advanced Whitelist Bypass
@app.route('/advanced-whitelist')
def advanced_whitelist():
    """Advanced regex-based whitelist bypass"""
    url = request.args.get('url')
    if not url:
        return "No URL parameter provided"
    
    # Advanced but still bypassable whitelist
    import re
    pattern = r'^https?://([\w-]+\.)?legitapp\.com(/.*)?$'
    
    if re.match(pattern, url):
        return redirect(url)
    
    # Try to be "smart" but still vulnerable
    if 'legitapp.com' in url and url.startswith('http'):
        return redirect(url)
    
    return "URL not in whitelist"

# Chain Redirect Vulnerability
@app.route('/chain-redirect')
def chain_redirect():
    """Multi-hop redirect chain vulnerability"""
    first = request.args.get('first')
    if first:
        # First hop - redirect to our "trusted" intermediate
        intermediate_url = url_for('chain_intermediate', next=first, _external=True)
        return redirect(intermediate_url)
    return "No first URL provided"

@app.route('/chain-intermediate')
def chain_intermediate():
    """Intermediate redirect in chain"""
    next_url = request.args.get('next')
    if next_url:
        # Second hop - now redirect to final destination (vulnerable)
        return redirect(next_url)
    return redirect(url_for('success'))

# Case Sensitivity Bypass
@app.route('/case-bypass')
def case_bypass():
    """Case sensitivity bypass vulnerability"""
    url = request.args.get('url')
    blocked = ['evil.com', 'malicious.com', 'attacker.com']
    
    if url and not any(blocked_domain in url for blocked_domain in blocked):
        # Vulnerable to case variations like Evil.com, EVIL.COM
        return redirect(url)
    return "Blocked URL detected"

# Null Byte Injection
@app.route('/null-byte-redirect')
def null_byte_redirect():
    """Null byte injection vulnerability"""
    url = request.args.get('url')
    if url:
        # Vulnerable to null byte truncation
        if '\x00' in url:
            url = url.split('\x00')[0]  # Simulate truncation
        return redirect(url)
    return "No URL provided"

# CRLF Injection
@app.route('/crlf-redirect')
def crlf_redirect():
    """CRLF injection vulnerability"""
    url = request.args.get('url')
    if url:
        # Vulnerable to CRLF injection for response splitting
        return redirect(url)
    return "No URL provided"

# Proxy Header Vulnerability
@app.route('/proxy-redirect')
def proxy_redirect():
    """Reverse proxy header vulnerability"""
    # Vulnerable when X-Forwarded-Host is trusted
    forwarded_host = request.headers.get('X-Forwarded-Host', request.host)
    return redirect(f'https://{forwarded_host}/success')

# Unicode Bypass
@app.route('/unicode-bypass')
def unicode_bypass():
    """Unicode bypass vulnerability"""
    url = request.args.get('url')
    blocked = ['evil.com', 'malicious.com']
    
    if url:
        # Simple ASCII check that misses Unicode variants
        if not any(blocked in url for blocked in blocked):
            return redirect(url)
    return "Blocked URL"

# File Upload Success Redirect
@app.route('/upload-success')
def upload_success():
    """File upload success redirect"""
    next_url = request.args.get('next_url') or request.args.get('continue')
    if next_url:
        flash("File uploaded successfully!")
        return redirect(next_url)
    return "Upload completed"

# Error handler
@app.route('/path-traversal-bypass')
def path_traversal_bypass():
    """CVE-2025-4123 style path traversal bypass vulnerability"""
    url_param = request.args.get('url', '/dashboard')
    
    # Weak sanitization that can be bypassed with double encoding
    if '../../' in url_param:
        return "Path traversal detected", 400
    
    # This can be bypassed with ..%2F (double encoded)
    if url_param.startswith('http://') or url_param.startswith('https://'):
        return redirect(url_param, code=302)
    
    # Simulate internal redirect that could be exploited
    if '..%2F' in url_param:
        # Decode the path traversal
        decoded_url = url_param.replace('..%2F', '../')
        if decoded_url.startswith('../') and 'http' in decoded_url:
            # Extract the malicious URL
            malicious_url = decoded_url.split('../')[-1]
            if malicious_url.startswith('http'):
                return redirect(malicious_url, code=302)
    
    return redirect(url_param, code=302)

@app.route('/x-forwarded-host-bypass')
def x_forwarded_host_bypass():
    """Dashboard.omise.co style X-Forwarded-Host header bypass"""
    forwarded_host = request.headers.get('X-Forwarded-Host')
    
    if forwarded_host:
        # Vulnerable: trusting X-Forwarded-Host header
        redirect_url = f"http://{forwarded_host}/callback"
        return redirect(redirect_url, code=302)
    
    # Normal redirect parameter
    return_url = request.args.get('return_url', '/dashboard')
    return redirect(return_url, code=302)

@app.errorhandler(404)
def not_found(error):
    """Custom 404 handler"""
    return "Page not found", 404

if __name__ == '__main__':
    # Run Flask app on port 5000 for external access
    app.run(host='0.0.0.0', port=5000, debug=True)
