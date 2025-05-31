#!/usr/bin/env python3
"""
Vulnerable Flask Application for Testing OpenX Scanner
Contains 20+ different open redirect vulnerability patterns
"""

from flask import Flask, request, redirect, render_template_string, make_response, url_for, jsonify
import urllib.parse
import base64
import json

app = Flask(__name__)

# HTML template for the main page
MAIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>OpenX Test Lab - Open Redirect Vulnerabilities</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .lab { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .vulnerable { background-color: #ffebee; }
        .safe { background-color: #e8f5e8; }
        h1 { color: #d32f2f; }
        h2 { color: #1976d2; }
        a { color: #1976d2; text-decoration: none; }
        a:hover { text-decoration: underline; }
        code { background-color: #f5f5f5; padding: 2px 4px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>🔐 OpenX Test Lab - Open Redirect Vulnerabilities</h1>
    <p>This application contains various open redirect vulnerability patterns for testing security scanners.</p>
    
    <div class="lab vulnerable">
        <h2>Lab 1: Basic URL Parameter Redirect</h2>
        <p>Simple redirect using 'url' parameter:</p>
        <a href="/redirect1?url=https://google.com">Test: /redirect1?url=https://google.com</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 2: Return Parameter Redirect</h2>
        <p>Redirect using 'return' parameter:</p>
        <a href="/redirect2?return=https://example.com">Test: /redirect2?return=https://example.com</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 3: Next Parameter Redirect</h2>
        <p>Redirect using 'next' parameter:</p>
        <a href="/redirect3?next=//evil.com">Test: /redirect3?next=//evil.com</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 4: Callback Parameter Redirect</h2>
        <p>Redirect using 'callback' parameter:</p>
        <a href="/redirect4?callback=http://attacker.com">Test: /redirect4?callback=http://attacker.com</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 5: Goto Parameter Redirect</h2>
        <p>Redirect using 'goto' parameter:</p>
        <a href="/redirect5?goto=https://malicious.com">Test: /redirect5?goto=https://malicious.com</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 6: Target Parameter Redirect</h2>
        <p>Redirect using 'target' parameter:</p>
        <a href="/redirect6?target=javascript:alert(1)">Test: /redirect6?target=javascript:alert(1)</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 7: Meta Refresh Redirect</h2>
        <p>Meta refresh based redirect:</p>
        <a href="/meta_redirect?url=https://evil.com">Test: /meta_redirect?url=https://evil.com</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 8: JavaScript Redirect</h2>
        <p>JavaScript window.location redirect:</p>
        <a href="/js_redirect?destination=https://attacker.com">Test: /js_redirect?destination=https://attacker.com</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 9: Base64 Encoded Redirect</h2>
        <p>Base64 encoded redirect parameter:</p>
        <a href="/b64_redirect?data=aHR0cHM6Ly9ldmlsLmNvbQ==">Test: /b64_redirect?data=aHR0cHM6Ly9ldmlsLmNvbQ==</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 10: JSON Parameter Redirect</h2>
        <p>JSON-based redirect parameter:</p>
        <a href='/json_redirect?config={"redirect_url":"https://malicious.com"}'>Test: JSON redirect</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 11: Header-based Redirect (Host)</h2>
        <p>Redirect based on Host header manipulation:</p>
        <a href="/host_redirect">Test: /host_redirect (requires Host header)</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 12: Referer-based Redirect</h2>
        <p>Redirect based on Referer header:</p>
        <a href="/referer_redirect">Test: /referer_redirect (requires Referer header)</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 13: Double URL Encoding</h2>
        <p>Double URL encoded redirect:</p>
        <a href="/double_encoded?url=%25%36%38%25%37%34%25%37%34%25%37%30%25%33%61%25%32%66%25%32%66%25%36%35%25%37%36%25%36%39%25%36%63%25%32%65%25%36%33%25%36%66%25%36%64">Test: Double encoded</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 14: CRLF Injection Redirect</h2>
        <p>CRLF injection in redirect:</p>
        <a href="/crlf_redirect?url=https://example.com%0d%0aLocation:https://evil.com">Test: CRLF injection</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 15: Fragment-based Bypass</h2>
        <p>Fragment-based domain bypass:</p>
        <a href="/fragment_redirect?url=https://evil.com#.example.com">Test: Fragment bypass</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 16: Path Traversal Redirect</h2>
        <p>Path traversal in redirect:</p>
        <a href="/path_redirect?path=../../../evil.com">Test: Path traversal</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 17: IP Address Redirect</h2>
        <p>IP address based redirect:</p>
        <a href="/ip_redirect?target=http://192.168.1.1">Test: IP redirect</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 18: Data URI Redirect</h2>
        <p>Data URI based redirect:</p>
        <a href="/data_redirect?uri=data:text/html,<script>alert(1)</script>">Test: Data URI</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 19: Multiple Parameter Pollution</h2>
        <p>Parameter pollution vulnerability:</p>
        <a href="/pollution_redirect?url=safe.com&url=evil.com">Test: Parameter pollution</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 20: Case Insensitive Redirect</h2>
        <p>Case insensitive parameter:</p>
        <a href="/case_redirect?URL=https://evil.com">Test: Case insensitive</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 21: Whitespace Bypass</h2>
        <p>Whitespace character bypass:</p>
        <a href="/whitespace_redirect?url=%20https://evil.com">Test: Whitespace bypass</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 22: Protocol Relative URL</h2>
        <p>Protocol relative URL redirect:</p>
        <a href="/protocol_redirect?link=//evil.com/malicious">Test: Protocol relative</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 23: Subdomain Bypass</h2>
        <p>Subdomain-based bypass attempt:</p>
        <a href="/subdomain_redirect?domain=evil.example.com">Test: Subdomain bypass</a>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 24: Form-based Redirect</h2>
        <p>POST form redirect:</p>
        <form method="POST" action="/form_redirect">
            <input type="hidden" name="redirect_to" value="https://evil.com">
            <button type="submit">Test Form Redirect</button>
        </form>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 25: Cookie-based Redirect</h2>
        <p>Cookie-based redirect vulnerability:</p>
        <a href="/cookie_redirect">Test: Cookie redirect (set cookie first)</a>
        <br><a href="/set_cookie?redirect_url=https://evil.com">Set malicious cookie</a>
    </div>
    
    <h2>🧪 Test with OpenX Scanner</h2>
    <p>To test with OpenX scanner, create a file with these URLs and run:</p>
    <code>python openx.py -l test_urls.txt --verbose --headers</code>
</body>
</html>
"""

@app.route('/')
def index():
    return MAIN_TEMPLATE

# Lab 1: Basic URL parameter redirect
@app.route('/redirect1')
def redirect1():
    url = request.args.get('url', '/')
    return redirect(url)

# Lab 2: Return parameter redirect
@app.route('/redirect2')
def redirect2():
    return_url = request.args.get('return', '/')
    return redirect(return_url)

# Lab 3: Next parameter redirect
@app.route('/redirect3')
def redirect3():
    next_url = request.args.get('next', '/')
    return redirect(next_url)

# Lab 4: Callback parameter redirect
@app.route('/redirect4')
def redirect4():
    callback = request.args.get('callback', '/')
    return redirect(callback)

# Lab 5: Goto parameter redirect
@app.route('/redirect5')
def redirect5():
    goto = request.args.get('goto', '/')
    return redirect(goto)

# Lab 6: Target parameter redirect
@app.route('/redirect6')
def redirect6():
    target = request.args.get('target', '/')
    return redirect(target)

# Lab 7: Meta refresh redirect
@app.route('/meta_redirect')
def meta_redirect():
    url = request.args.get('url', '/')
    html = f'''
    <html>
    <head>
        <meta http-equiv="refresh" content="0; url={url}">
    </head>
    <body>
        <p>Redirecting to {url}...</p>
    </body>
    </html>
    '''
    return html

# Lab 8: JavaScript redirect
@app.route('/js_redirect')
def js_redirect():
    destination = request.args.get('destination', '/')
    html = f'''
    <html>
    <head>
        <script>
            window.location = "{destination}";
        </script>
    </head>
    <body>
        <p>Redirecting via JavaScript...</p>
    </body>
    </html>
    '''
    return html

# Lab 9: Base64 encoded redirect
@app.route('/b64_redirect')
def b64_redirect():
    data = request.args.get('data', '')
    try:
        decoded_url = base64.b64decode(data).decode('utf-8')
        return redirect(decoded_url)
    except:
        return redirect('/')

# Lab 10: JSON parameter redirect
@app.route('/json_redirect')
def json_redirect():
    config = request.args.get('config', '{}')
    try:
        config_data = json.loads(config)
        redirect_url = config_data.get('redirect_url', '/')
        return redirect(redirect_url)
    except:
        return redirect('/')

# Lab 11: Host header redirect
@app.route('/host_redirect')
def host_redirect():
    host = request.headers.get('Host', 'localhost:5000')
    if 'evil.com' in host or 'attacker.com' in host:
        return redirect(f'http://{host}/malicious')
    return "Host header redirect test"

# Lab 12: Referer header redirect
@app.route('/referer_redirect')
def referer_redirect():
    referer = request.headers.get('Referer', '')
    if referer:
        return redirect(referer)
    return "Referer redirect test"

# Lab 13: Double URL encoding
@app.route('/double_encoded')
def double_encoded():
    url = request.args.get('url', '/')
    # Double decode
    try:
        decoded_once = urllib.parse.unquote(url)
        decoded_twice = urllib.parse.unquote(decoded_once)
        return redirect(decoded_twice)
    except:
        return redirect('/')

# Lab 14: CRLF injection
@app.route('/crlf_redirect')
def crlf_redirect():
    url = request.args.get('url', '/')
    response = make_response(f"Redirecting to {url}")
    # This would be vulnerable to CRLF injection
    if '\r\n' in url or '%0d%0a' in url:
        return redirect(url.split('\r\n')[0].split('%0d%0a')[0])
    return redirect(url)

# Lab 15: Fragment bypass
@app.route('/fragment_redirect')
def fragment_redirect():
    url = request.args.get('url', '/')
    # Simple check that can be bypassed with fragments
    if 'example.com' not in url:
        return redirect(url)
    return "Fragment bypass test"

# Lab 16: Path traversal
@app.route('/path_redirect')
def path_redirect():
    path = request.args.get('path', '/')
    base_url = "https://safe.com/"
    full_url = base_url + path
    return redirect(full_url)

# Lab 17: IP address redirect
@app.route('/ip_redirect')
def ip_redirect():
    target = request.args.get('target', '/')
    return redirect(target)

# Lab 18: Data URI redirect
@app.route('/data_redirect')
def data_redirect():
    uri = request.args.get('uri', '/')
    return redirect(uri)

# Lab 19: Parameter pollution
@app.route('/pollution_redirect')
def pollution_redirect():
    # Flask automatically handles multiple parameters
    urls = request.args.getlist('url')
    if len(urls) > 1:
        return redirect(urls[-1])  # Use last value
    elif len(urls) == 1:
        return redirect(urls[0])
    return redirect('/')

# Lab 20: Case insensitive
@app.route('/case_redirect')
def case_redirect():
    # Check both cases
    url = request.args.get('url') or request.args.get('URL') or '/'
    return redirect(url)

# Lab 21: Whitespace bypass
@app.route('/whitespace_redirect')
def whitespace_redirect():
    url = request.args.get('url', '/').strip()
    return redirect(url)

# Lab 22: Protocol relative
@app.route('/protocol_redirect')
def protocol_redirect():
    link = request.args.get('link', '/')
    return redirect(link)

# Lab 23: Subdomain bypass
@app.route('/subdomain_redirect')
def subdomain_redirect():
    domain = request.args.get('domain', '/')
    return redirect(f'https://{domain}')

# Lab 24: Form redirect
@app.route('/form_redirect', methods=['POST'])
def form_redirect():
    redirect_to = request.form.get('redirect_to', '/')
    return redirect(redirect_to)

# Lab 25: Cookie redirect
@app.route('/cookie_redirect')
def cookie_redirect():
    redirect_url = request.cookies.get('redirect_url', '/')
    return redirect(redirect_url)

@app.route('/set_cookie')
def set_cookie():
    redirect_url = request.args.get('redirect_url', '/')
    response = make_response("Cookie set!")
    response.set_cookie('redirect_url', redirect_url)
    return response

# Advanced Labs Integration
@app.route('/oauth/callback')
def oauth_redirect():
    """OAuth callback with state parameter redirect vulnerability"""
    state = request.args.get('state', '')
    code = request.args.get('code', 'dummy_code')
    
    if state:
        return redirect(state)
    return "OAuth callback processed"

@app.route('/multi-hop/<int:step>')
def multi_hop(step):
    """Multi-hop redirect chain vulnerability"""
    target = request.args.get('next', '')
    if step > 1:
        return redirect(f'/multi-hop/{step-1}?next={target}')
    elif target:
        return redirect(target)
    return "Final destination"

@app.route('/saml/acs', methods=['POST', 'GET'])
def saml_acs():
    """SAML ACS RelayState parameter vulnerability"""
    relay_state = request.args.get('RelayState') or request.form.get('RelayState')
    saml_response = request.args.get('SAMLResponse') or request.form.get('SAMLResponse')
    
    if relay_state:
        return redirect(relay_state)
    return "SAML authentication processed"

@app.route('/jwt/redirect')
def jwt_redirect():
    """JWT token redirect vulnerability"""
    token = request.args.get('token', '')
    try:
        import base64
        # Decode JWT payload (simplified)
        parts = token.split('.')
        if len(parts) >= 2:
            payload = base64.b64decode(parts[1] + '==').decode()
            if 'redirect_uri' in payload:
                import json
                data = json.loads(payload)
                return redirect(data.get('redirect_uri', '/'))
    except:
        pass
    
    redirect_uri = request.args.get('redirect_uri', '')
    if redirect_uri:
        return redirect(redirect_uri)
    return "JWT processed"

@app.route('/graphql', methods=['POST'])
def graphql_redirect():
    """GraphQL mutation redirect vulnerability"""
    try:
        data = request.get_json()
        if data and 'query' in data:
            query = data['query']
            if 'redirect' in query.lower():
                # Extract URL from GraphQL mutation
                import re
                url_match = re.search(r'url:\s*"([^"]+)"', query)
                if url_match:
                    return redirect(url_match.group(1))
    except:
        pass
    
    return jsonify({"data": {"redirect": {"success": True}}})

@app.route('/upload/redirect')
def upload_redirect():
    """File upload redirect vulnerability"""
    file_url = request.args.get('file_url', '')
    success_url = request.args.get('success_url', '')
    
    if success_url:
        return redirect(success_url)
    return "Upload processed"

@app.route('/api/redirect')
def api_redirect():
    """API endpoint redirect vulnerability"""
    callback = request.args.get('callback', '')
    redirect_to = request.args.get('redirect_to', '')
    
    if redirect_to:
        return redirect(redirect_to)
    
    if callback:
        return f"{callback}({{\"status\": \"success\", \"redirect\": \"{callback}\"}})"
    
    return jsonify({"status": "success"})

@app.route('/cached/redirect')
def cached_redirect():
    """Cache-based redirect vulnerability"""
    cache_key = request.args.get('cache_key', '')
    redirect_url = request.args.get('url', '')
    
    # Simulate cache behavior
    if cache_key and redirect_url:
        return redirect(redirect_url)
    return "Cached response"

@app.route('/unicode/redirect')
def unicode_redirect():
    """Unicode normalization redirect vulnerability"""
    url = request.args.get('url', '')
    
    # Various unicode normalizations that could bypass filters
    if url:
        import urllib.parse
        decoded_url = urllib.parse.unquote(url)
        return redirect(decoded_url)
    return "Unicode processed"

@app.route('/template/redirect')
def template_redirect():
    """Template injection redirect vulnerability"""
    template = request.args.get('template', '')
    redirect_url = request.args.get('url', '')
    
    if redirect_url and 'redirect' in template.lower():
        return redirect(redirect_url)
    return "Template processed"

@app.route('/dns/redirect')
def dns_redirect():
    """DNS rebinding redirect vulnerability"""
    host = request.args.get('host', '')
    port = request.args.get('port', '80')
    path = request.args.get('path', '/')
    
    if host:
        target_url = f"http://{host}:{port}{path}"
        return redirect(target_url)
    return "DNS lookup processed"

@app.route('/rate-limited/redirect')
def rate_limited_redirect():
    """Rate-limited redirect vulnerability"""
    import time
    time.sleep(0.1)  # Simulate rate limiting
    
    url = request.args.get('url', '')
    if url:
        return redirect(url)
    return "Rate limited response"

@app.route('/advanced')
def advanced_labs():
    """Advanced labs directory"""
    return '''
    <h1>🔬 Advanced OpenX Labs</h1>
    <h2>OAuth & Authentication Labs:</h2>
    <a href="/oauth/callback?state=http://evil.com">OAuth Redirect</a><br>
    <a href="/jwt/redirect?redirect_uri=http://evil.com">JWT Redirect</a><br>
    <a href="/saml/acs?RelayState=http://evil.com">SAML RelayState</a><br>
    
    <h2>Multi-Step & Chain Labs:</h2>
    <a href="/multi-hop/3?next=http://evil.com">Multi-hop Redirect</a><br>
    
    <h2>API & Modern Labs:</h2>
    <a href="/graphql">GraphQL Mutation</a><br>
    <a href="/api/redirect?redirect_to=http://evil.com">API Redirect</a><br>
    
    <h2>Advanced Evasion Labs:</h2>
    <a href="/unicode/redirect?url=http://evil.com">Unicode Redirect</a><br>
    <a href="/cached/redirect?url=http://evil.com">Cached Redirect</a><br>
    <a href="/template/redirect?template=redirect&url=http://evil.com">Template Redirect</a><br>
    <a href="/dns/redirect?host=evil.com">DNS Redirect</a><br>
    <a href="/upload/redirect?success_url=http://evil.com">Upload Redirect</a><br>
    <a href="/rate-limited/redirect?url=http://evil.com">Rate Limited Redirect</a><br>
    '''

if __name__ == '__main__':
    print("🔐 Starting Comprehensive Vulnerable Test Application")
    print("Access the basic labs at: http://localhost:5000")
    print("Access the advanced labs at: http://localhost:5000/advanced")
    print("Use this for testing OpenX scanner")
    app.run(host='0.0.0.0', port=5000, debug=True)