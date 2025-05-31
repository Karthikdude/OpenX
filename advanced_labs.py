#!/usr/bin/env python3
"""
Advanced Open Redirect Labs - Real-world Complex Scenarios
Extension to the vulnerable app with advanced attack vectors
"""

from flask import Flask, request, redirect, render_template_string, make_response, url_for, session
import urllib.parse
import base64
import json
import hashlib
import time
import re

app = Flask(__name__)
app.secret_key = 'openx_test_key_12345'

# Advanced HTML template for complex labs
ADVANCED_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>OpenX Advanced Labs - Complex Open Redirect Scenarios</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .lab { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background-color: white; }
        .vulnerable { border-left: 5px solid #e74c3c; }
        .complex { border-left: 5px solid #f39c12; }
        .advanced { border-left: 5px solid #9b59b6; }
        h1 { color: #2c3e50; }
        h2 { color: #34495e; }
        .difficulty { font-weight: bold; padding: 5px 10px; border-radius: 3px; color: white; }
        .hard { background-color: #e74c3c; }
        .medium { background-color: #f39c12; }
        .easy { background-color: #27ae60; }
        code { background-color: #ecf0f1; padding: 2px 4px; border-radius: 3px; font-family: 'Courier New', monospace; }
        .test-form { margin: 10px 0; padding: 15px; background-color: #ecf0f1; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>🔬 OpenX Advanced Labs - Complex Open Redirect Scenarios</h1>
    <p>Advanced vulnerability patterns designed to test sophisticated scanners and manual testing techniques.</p>
    
    <div class="lab vulnerable">
        <h2>Lab 26: OAuth State Parameter Bypass <span class="difficulty hard">HARD</span></h2>
        <p>OAuth flow with state parameter manipulation leading to open redirect</p>
        <a href="/oauth_redirect?state=trusted&redirect_uri=https://app.example.com/callback">OAuth Flow</a>
        <br><small>Try manipulating the redirect_uri or state parameters</small>
    </div>
    
    <div class="lab complex">
        <h2>Lab 27: Multiple Hop Redirect Chain <span class="difficulty hard">HARD</span></h2>
        <p>Multi-step redirect with validation bypass through intermediate hops</p>
        <a href="/multi_hop?step1=https://trusted.com&step2=https://evil.com">Multi-hop Chain</a>
        <br><small>Complex redirect chain requiring multiple payloads</small>
    </div>
    
    <div class="lab advanced">
        <h2>Lab 28: SAML Response Redirect <span class="difficulty hard">HARD</span></h2>
        <p>SAML authentication flow with RelayState parameter manipulation</p>
        <a href="/saml_acs?RelayState=L2Rhc2hib2FyZA%3D%3D&SAMLResponse=dummy">SAML ACS</a>
        <br><small>Base64 encoded RelayState parameter bypass</small>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 29: JSON Web Token (JWT) Redirect <span class="difficulty medium">MEDIUM</span></h2>
        <p>JWT token containing redirect URL in claims</p>
        <a href="/jwt_redirect?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJyZWRpcmVjdF91cmwiOiJodHRwczovL2V4YW1wbGUuY29tIn0.">JWT Flow</a>
        <br><small>Manipulate JWT payload to change redirect destination</small>
    </div>
    
    <div class="lab complex">
        <h2>Lab 30: GraphQL Mutation Redirect <span class="difficulty hard">HARD</span></h2>
        <p>GraphQL mutation with redirect URL in variables</p>
        <div class="test-form">
            <form method="POST" action="/graphql">
                <textarea name="query" rows="4" cols="60">
mutation { 
  updateProfile(redirectUrl: "https://evil.com") { 
    success 
    redirectUrl 
  } 
}</textarea><br>
                <button type="submit">Execute GraphQL</button>
            </form>
        </div>
    </div>
    
    <div class="lab advanced">
        <h2>Lab 31: WebSocket Message Redirect <span class="difficulty hard">HARD</span></h2>
        <p>WebSocket message containing redirect instructions</p>
        <a href="/websocket_redirect">WebSocket Redirect Test</a>
        <br><small>Requires WebSocket connection and message analysis</small>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 32: Server-Side Request Forgery (SSRF) + Redirect <span class="difficulty hard">HARD</span></h2>
        <p>SSRF vulnerability leading to internal redirect manipulation</p>
        <a href="/ssrf_redirect?url=http://internal.service/redirect?target=https://evil.com">SSRF Chain</a>
        <br><small>Internal service redirect manipulation</small>
    </div>
    
    <div class="lab complex">
        <h2>Lab 33: Template Injection + Redirect <span class="difficulty hard">HARD</span></h2>
        <p>Server-side template injection leading to redirect</p>
        <a href="/template_redirect?name={{request.args.get('redirect','/')}}&redirect=https://evil.com">Template Injection</a>
        <br><small>SSTI payload in template rendering</small>
    </div>
    
    <div class="lab advanced">
        <h2>Lab 34: DNS Rebinding + Redirect <span class="difficulty hard">HARD</span></h2>
        <p>DNS rebinding attack combined with open redirect</p>
        <a href="/dns_redirect?target=http://rebind.attacker.com">DNS Rebinding</a>
        <br><small>Requires DNS manipulation and timing attacks</small>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 35: File Upload + Redirect <span class="difficulty medium">MEDIUM</span></h2>
        <p>File upload functionality with redirect after processing</p>
        <div class="test-form">
            <form method="POST" action="/upload_redirect" enctype="multipart/form-data">
                <input type="file" name="file" required><br>
                <input type="hidden" name="success_url" value="https://evil.com">
                <button type="submit">Upload & Redirect</button>
            </form>
        </div>
    </div>
    
    <div class="lab complex">
        <h2>Lab 36: Rate Limiting Bypass + Redirect <span class="difficulty medium">MEDIUM</span></h2>
        <p>Rate limiting bypass leading to redirect vulnerability</p>
        <a href="/rate_limited_redirect?url=https://evil.com">Rate Limited Endpoint</a>
        <br><small>Requires multiple requests to bypass rate limiting</small>
    </div>
    
    <div class="lab advanced">
        <h2>Lab 37: Unicode Normalization Bypass <span class="difficulty hard">HARD</span></h2>
        <p>Unicode normalization leading to domain validation bypass</p>
        <a href="/unicode_redirect?url=https://еxample.com">Unicode Domain</a>
        <br><small>Unicode characters that normalize to different domains</small>
    </div>
    
    <div class="lab vulnerable">
        <h2>Lab 38: Cache Poisoning + Redirect <span class="difficulty hard">HARD</span></h2>
        <p>HTTP cache poisoning leading to redirect manipulation</p>
        <a href="/cached_redirect?version=1.0">Cached Redirect</a>
        <br><small>Requires cache poisoning with Host header manipulation</small>
    </div>
    
    <div class="lab complex">
        <h2>Lab 39: Machine Learning Model Bypass <span class="difficulty hard">HARD</span></h2>
        <p>ML-based URL filtering bypass using adversarial inputs</p>
        <a href="/ml_protected_redirect?url=https://evil.com">ML Protected</a>
        <br><small>Adversarial examples to fool ML-based protection</small>
    </div>
    
    <div class="lab advanced">
        <h2>Lab 40: Blockchain Smart Contract Redirect <span class="difficulty hard">HARD</span></h2>
        <p>Smart contract interaction leading to redirect</p>
        <a href="/blockchain_redirect?contract=0x123&redirect=https://evil.com">Smart Contract</a>
        <br><small>Blockchain transaction result redirect manipulation</small>
    </div>
    
    <h2>🧪 Advanced Testing Instructions</h2>
    <p>These labs require sophisticated testing techniques:</p>
    <ul>
        <li><strong>Manual Analysis:</strong> Many require understanding of the application logic</li>
        <li><strong>Multi-step Attacks:</strong> Some vulnerabilities require multiple requests</li>
        <li><strong>Protocol Understanding:</strong> OAuth, SAML, JWT, GraphQL knowledge needed</li>
        <li><strong>Advanced Payloads:</strong> Unicode, timing, cache poisoning techniques</li>
    </ul>
    
    <p><code>python openx.py -l advanced_urls.txt --verbose --headers --threads 5</code></p>
</body>
</html>
"""

@app.route('/advanced')
def advanced_labs():
    return ADVANCED_TEMPLATE

# Lab 26: OAuth State Parameter Bypass
@app.route('/oauth_redirect')
def oauth_redirect():
    state = request.args.get('state', '')
    redirect_uri = request.args.get('redirect_uri', '/')
    
    # Weak validation - only checks if state contains "trusted"
    if 'trusted' in state:
        return redirect(redirect_uri)
    else:
        return "Invalid OAuth state parameter", 400

# Lab 27: Multiple Hop Redirect Chain
@app.route('/multi_hop')
def multi_hop():
    step1 = request.args.get('step1', '/')
    step2 = request.args.get('step2', '/')
    
    # First hop validation
    if 'trusted.com' in step1:
        # Redirect to intermediate endpoint
        return redirect(f'/hop_intermediate?next={step2}')
    return "Invalid first hop", 400

@app.route('/hop_intermediate')
def hop_intermediate():
    next_url = request.args.get('next', '/')
    # Weak second hop validation
    return redirect(next_url)

# Lab 28: SAML Response Redirect
@app.route('/saml_acs')
def saml_acs():
    relay_state = request.args.get('RelayState', '')
    saml_response = request.args.get('SAMLResponse', '')
    
    if relay_state:
        try:
            # Decode base64 RelayState
            decoded = base64.b64decode(relay_state + '==').decode('utf-8')
            return redirect(decoded)
        except:
            pass
    
    return redirect('/')

# Lab 29: JWT Redirect
@app.route('/jwt_redirect')
def jwt_redirect():
    token = request.args.get('token', '')
    
    if token:
        try:
            # Simple JWT parsing (no signature verification for demo)
            parts = token.split('.')
            if len(parts) >= 2:
                payload = parts[1] + '=='  # Add padding
                decoded = base64.b64decode(payload).decode('utf-8')
                data = json.loads(decoded)
                redirect_url = data.get('redirect_url', '/')
                return redirect(redirect_url)
        except:
            pass
    
    return redirect('/')

# Lab 30: GraphQL Mutation Redirect
@app.route('/graphql', methods=['POST'])
def graphql_redirect():
    query = request.form.get('query', '')
    
    # Simple GraphQL parsing for demo
    if 'updateProfile' in query and 'redirectUrl' in query:
        # Extract redirect URL from query
        match = re.search(r'redirectUrl:\s*"([^"]+)"', query)
        if match:
            redirect_url = match.group(1)
            return redirect(redirect_url)
    
    return "GraphQL executed", 200

# Lab 31: WebSocket Message Redirect
@app.route('/websocket_redirect')
def websocket_redirect():
    # Simulate WebSocket redirect via query parameter
    ws_message = request.args.get('message', '')
    if ws_message:
        try:
            data = json.loads(ws_message)
            if data.get('type') == 'redirect':
                return redirect(data.get('url', '/'))
        except:
            pass
    
    return """
    <html>
    <body>
        <h3>WebSocket Redirect Test</h3>
        <p>Try: ?message={"type":"redirect","url":"https://evil.com"}</p>
    </body>
    </html>
    """

# Lab 32: SSRF + Redirect
@app.route('/ssrf_redirect')
def ssrf_redirect():
    url = request.args.get('url', '')
    
    # Simulate SSRF - in real scenario, this would make internal request
    if url.startswith('http://internal.'):
        # Extract target from internal URL
        if 'target=' in url:
            target = url.split('target=')[1]
            return redirect(target)
    
    return "SSRF endpoint", 200

# Lab 33: Template Injection + Redirect
@app.route('/template_redirect')
def template_redirect():
    name = request.args.get('name', 'User')
    redirect_param = request.args.get('redirect', '/')
    
    # Vulnerable template rendering
    template = f"""
    <html>
    <body>
        <h3>Hello {name}!</h3>
        <script>
            setTimeout(function() {{
                window.location = "{redirect_param}";
            }}, 2000);
        </script>
    </body>
    </html>
    """
    
    return template

# Lab 34: DNS Rebinding + Redirect
@app.route('/dns_redirect')
def dns_redirect():
    target = request.args.get('target', '')
    
    # Simulate DNS rebinding check
    if 'rebind.' in target:
        return redirect(target)
    
    return "DNS rebinding protection", 403

# Lab 35: File Upload + Redirect
@app.route('/upload_redirect', methods=['POST'])
def upload_redirect():
    success_url = request.form.get('success_url', '/')
    file = request.files.get('file')
    
    if file:
        # Simulate file processing
        return redirect(success_url)
    
    return "Upload failed", 400

# Lab 36: Rate Limited Redirect
request_counts = {}

@app.route('/rate_limited_redirect')
def rate_limited_redirect():
    client_ip = request.remote_addr
    current_time = time.time()
    
    # Simple rate limiting
    if client_ip not in request_counts:
        request_counts[client_ip] = []
    
    # Clean old requests (older than 60 seconds)
    request_counts[client_ip] = [t for t in request_counts[client_ip] if current_time - t < 60]
    
    if len(request_counts[client_ip]) < 5:  # Allow 5 requests per minute
        request_counts[client_ip].append(current_time)
        url = request.args.get('url', '/')
        return redirect(url)
    else:
        return "Rate limit exceeded", 429

# Lab 37: Unicode Normalization Bypass
@app.route('/unicode_redirect')
def unicode_redirect():
    url = request.args.get('url', '')
    
    # Weak domain validation
    if 'example.com' in url:
        return redirect(url)
    
    return "Domain not allowed", 403

# Lab 38: Cache Poisoning + Redirect
@app.route('/cached_redirect')
def cached_redirect():
    version = request.args.get('version', '1.0')
    host = request.headers.get('Host', 'localhost')
    
    # Vulnerable to host header injection
    redirect_url = f"https://{host}/success?v={version}"
    return redirect(redirect_url)

# Lab 39: ML Protected Redirect
@app.route('/ml_protected_redirect')
def ml_protected_redirect():
    url = request.args.get('url', '')
    
    # Simulate ML-based filtering (very basic)
    malicious_indicators = ['evil', 'malicious', 'attacker', 'hack']
    
    # Simple bypass: if URL contains numbers, allow it
    if any(char.isdigit() for char in url):
        return redirect(url)
    
    if not any(indicator in url.lower() for indicator in malicious_indicators):
        return redirect(url)
    
    return "ML filter blocked request", 403

# Lab 40: Blockchain Smart Contract Redirect
@app.route('/blockchain_redirect')
def blockchain_redirect():
    contract = request.args.get('contract', '')
    redirect_url = request.args.get('redirect', '/')
    
    # Simulate blockchain interaction
    if contract.startswith('0x') and len(contract) > 10:
        return redirect(redirect_url)
    
    return "Invalid contract address", 400

if __name__ == '__main__':
    print("🔬 Starting Advanced OpenX Labs")
    print("Access advanced labs at: http://localhost:5001/advanced")
    app.run(host='0.0.0.0', port=5001, debug=True)