#!/usr/bin/env python3
"""
Web Dashboard for OpenX
Provides a web-based interface for scan management
"""

import os
import sys
import json
import logging
import asyncio
import time
import uuid
from typing import Dict, List, Set, Tuple, Any, Optional
from pathlib import Path
import aiohttp
from aiohttp import web
import jinja2
import aiohttp_jinja2

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import OpenX modules
from core.scanner import Scanner
from payloads.payload_manager import PayloadManager
from config.config import Config
from utils.helpers import read_urls_from_file
from utils.resume_manager import ResumeManager

logger = logging.getLogger('openx.interactive.web_dashboard')

class WebDashboard:
    """Web-based dashboard for OpenX"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the web dashboard
        
        Args:
            config (Optional[Dict[str, Any]]): Configuration dictionary
        """
        self.config = config or Config().load_config()
        
        # Dashboard settings
        self.host = self.config.get('dashboard', {}).get('host', '127.0.0.1')
        self.port = self.config.get('dashboard', {}).get('port', 8888)
        self.debug = self.config.get('dashboard', {}).get('debug', False)
        
        # Set up logging
        log_level = logging.DEBUG if self.debug else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Initialize payload manager
        self.payload_manager = PayloadManager(self.config)
        
        # Initialize scanner
        self.scanner = Scanner(self.config, self.payload_manager)
        
        # Initialize resume manager
        self.resume_manager = ResumeManager(self.config)
        
        # State variables
        self.active_scans = {}
        self.scan_results = {}
        self.scan_history = []
        
        # Web application
        self.app = web.Application()
        self.setup_routes()
        self.setup_templates()
    
    def setup_routes(self):
        """Set up web application routes"""
        self.app.add_routes([
            web.get('/', self.handle_index),
            web.get('/dashboard', self.handle_dashboard),
            web.get('/scans', self.handle_scans),
            web.post('/scan/start', self.handle_start_scan),
            web.get('/scan/{scan_id}', self.handle_scan_detail),
            web.post('/scan/{scan_id}/stop', self.handle_stop_scan),
            web.get('/results', self.handle_results),
            web.get('/result/{result_id}', self.handle_result_detail),
            web.get('/config', self.handle_config),
            web.post('/config/update', self.handle_config_update),
            web.get('/payloads', self.handle_payloads),
            web.post('/payloads/add', self.handle_add_payload),
            web.get('/api/scan/{scan_id}/status', self.handle_scan_status),
            web.get('/api/scans', self.handle_api_scans),
            web.get('/api/results', self.handle_api_results),
            web.static('/static', os.path.join(os.path.dirname(__file__), 'static'))
        ])
    
    def setup_templates(self):
        """Set up Jinja2 templates"""
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        
        # Create templates directory if it doesn't exist
        os.makedirs(template_dir, exist_ok=True)
        
        # Create default templates if they don't exist
        self.create_default_templates(template_dir)
        
        # Set up Jinja2
        aiohttp_jinja2.setup(
            self.app,
            loader=jinja2.FileSystemLoader(template_dir)
        )
    
    def create_default_templates(self, template_dir):
        """Create default templates if they don't exist"""
        # Base template
        base_template = os.path.join(template_dir, 'base.html')
        if not os.path.exists(base_template):
            with open(base_template, 'w') as f:
                f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}OpenX Dashboard{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { padding-top: 60px; }
        .sidebar { position: fixed; top: 56px; bottom: 0; left: 0; z-index: 100; padding: 48px 0 0; box-shadow: inset -1px 0 0 rgba(0, 0, 0, .1); }
        .sidebar-sticky { position: relative; top: 0; height: calc(100vh - 48px); padding-top: .5rem; overflow-x: hidden; overflow-y: auto; }
        .nav-link { font-weight: 500; color: #333; }
        .nav-link.active { color: #007bff; }
    </style>
    {% block head %}{% endblock %}
</head>
<body>
    <nav class="navbar navbar-expand-md navbar-dark bg-dark fixed-top">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">OpenX Dashboard</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarCollapse">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarCollapse">
                <ul class="navbar-nav me-auto mb-2 mb-md-0">
                    <li class="nav-item">
                        <a class="nav-link" href="/dashboard">Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/scans">Scans</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/results">Results</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/config">Configuration</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/payloads">Payloads</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container-fluid">
        <div class="row">
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                {% block content %}{% endblock %}
            </main>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>""")
        
        # Dashboard template
        dashboard_template = os.path.join(template_dir, 'dashboard.html')
        if not os.path.exists(dashboard_template):
            with open(dashboard_template, 'w') as f:
                f.write("""{% extends "base.html" %}

{% block title %}OpenX Dashboard{% endblock %}

{% block content %}
<div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
    <h1 class="h2">Dashboard</h1>
    <div class="btn-toolbar mb-2 mb-md-0">
        <div class="btn-group me-2">
            <a href="/scans" class="btn btn-sm btn-outline-secondary">View All Scans</a>
            <a href="/results" class="btn btn-sm btn-outline-secondary">View All Results</a>
        </div>
        <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#newScanModal">
            New Scan
        </button>
    </div>
</div>

<div class="row">
    <div class="col-md-4">
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="card-title">Active Scans</h5>
            </div>
            <div class="card-body">
                <h1 class="display-4 text-center">{{ active_scans }}</h1>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="card-title">Total Scans</h5>
            </div>
            <div class="card-body">
                <h1 class="display-4 text-center">{{ total_scans }}</h1>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="card-title">Vulnerabilities Found</h5>
            </div>
            <div class="card-body">
                <h1 class="display-4 text-center">{{ total_vulnerabilities }}</h1>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="card-title">Recent Scans</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped table-sm">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Date</th>
                                <th>URLs</th>
                                <th>Status</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for scan in recent_scans %}
                            <tr>
                                <td>{{ scan.id[:8] }}</td>
                                <td>{{ scan.start_time }}</td>
                                <td>{{ scan.total_urls }}</td>
                                <td>
                                    {% if scan.status == 'running' %}
                                    <span class="badge bg-primary">Running</span>
                                    {% elif scan.status == 'completed' %}
                                    <span class="badge bg-success">Completed</span>
                                    {% elif scan.status == 'stopped' %}
                                    <span class="badge bg-warning">Stopped</span>
                                    {% else %}
                                    <span class="badge bg-secondary">{{ scan.status }}</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <a href="/scan/{{ scan.id }}" class="btn btn-sm btn-info">View</a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="card-title">Recent Vulnerabilities</h5>
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-striped table-sm">
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>Type</th>
                                <th>Severity</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for vuln in recent_vulnerabilities %}
                            <tr>
                                <td>{{ vuln.url[:30] }}...</td>
                                <td>{{ vuln.type }}</td>
                                <td>
                                    {% if vuln.severity == 'high' %}
                                    <span class="badge bg-danger">High</span>
                                    {% elif vuln.severity == 'medium' %}
                                    <span class="badge bg-warning">Medium</span>
                                    {% elif vuln.severity == 'low' %}
                                    <span class="badge bg-info">Low</span>
                                    {% else %}
                                    <span class="badge bg-secondary">{{ vuln.severity }}</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <a href="/result/{{ vuln.id }}" class="btn btn-sm btn-info">View</a>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- New Scan Modal -->
<div class="modal fade" id="newScanModal" tabindex="-1" aria-labelledby="newScanModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="newScanModalLabel">Start New Scan</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <form id="newScanForm" action="/scan/start" method="post">
                    <div class="mb-3">
                        <label for="scanType" class="form-label">Scan Type</label>
                        <select class="form-select" id="scanType" name="scan_type">
                            <option value="url">Single URL</option>
                            <option value="file">URL File</option>
                            <option value="domain">Domain</option>
                        </select>
                    </div>
                    <div class="mb-3" id="urlInput">
                        <label for="url" class="form-label">URL</label>
                        <input type="text" class="form-control" id="url" name="url" placeholder="https://example.com/redirect?url=">
                    </div>
                    <div class="mb-3 d-none" id="fileInput">
                        <label for="urlFile" class="form-label">URL File</label>
                        <input type="file" class="form-control" id="urlFile" name="url_file">
                    </div>
                    <div class="mb-3 d-none" id="domainInput">
                        <label for="domain" class="form-label">Domain</label>
                        <input type="text" class="form-control" id="domain" name="domain" placeholder="example.com">
                    </div>
                    <div class="mb-3">
                        <label for="concurrency" class="form-label">Concurrency</label>
                        <input type="number" class="form-control" id="concurrency" name="concurrency" value="100" min="1" max="1000">
                    </div>
                    <div class="mb-3">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="browserCheck" name="browser">
                            <label class="form-check-label" for="browserCheck">
                                Use Browser-based Detection
                            </label>
                        </div>
                    </div>
                    <div class="mb-3">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="smartScanCheck" name="smart_scan">
                            <label class="form-check-label" for="smartScanCheck">
                                Enable Smart Scan
                            </label>
                        </div>
                    </div>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="submit" form="newScanForm" class="btn btn-primary">Start Scan</button>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
    document.addEventListener('DOMContentLoaded', function() {
        const scanType = document.getElementById('scanType');
        const urlInput = document.getElementById('urlInput');
        const fileInput = document.getElementById('fileInput');
        const domainInput = document.getElementById('domainInput');
        
        scanType.addEventListener('change', function() {
            urlInput.classList.add('d-none');
            fileInput.classList.add('d-none');
            domainInput.classList.add('d-none');
            
            if (this.value === 'url') {
                urlInput.classList.remove('d-none');
            } else if (this.value === 'file') {
                fileInput.classList.remove('d-none');
            } else if (this.value === 'domain') {
                domainInput.classList.remove('d-none');
            }
        });
    });
</script>
{% endblock %}""")
    
    async def start(self):
        """Start the web dashboard"""
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        
        logger.info(f"Web dashboard started at http://{self.host}:{self.port}")
        
        return runner
    
    @aiohttp_jinja2.template('dashboard.html')
    async def handle_index(self, request):
        """Handle index page request"""
        return await self.handle_dashboard(request)
    
    @aiohttp_jinja2.template('dashboard.html')
    async def handle_dashboard(self, request):
        """Handle dashboard page request"""
        # Get dashboard data
        active_scans = len([s for s in self.active_scans.values() if s['status'] == 'running'])
        total_scans = len(self.scan_history)
        
        # Count vulnerabilities
        total_vulnerabilities = 0
        for results in self.scan_results.values():
            for result in results:
                if result.get('is_vulnerable', False):
                    total_vulnerabilities += 1
        
        # Get recent scans
        recent_scans = sorted(
            self.scan_history,
            key=lambda x: x.get('start_time', 0),
            reverse=True
        )[:5]
        
        # Get recent vulnerabilities
        recent_vulnerabilities = []
        for scan_id, results in self.scan_results.items():
            for result in results:
                if result.get('is_vulnerable', False):
                    vuln = {
                        'id': result.get('id', ''),
                        'url': result.get('url', ''),
                        'type': result.get('type', 'Unknown'),
                        'severity': result.get('severity', 'Unknown'),
                        'scan_id': scan_id
                    }
                    recent_vulnerabilities.append(vuln)
        
        # Sort by severity (high first)
        severity_order = {'high': 0, 'medium': 1, 'low': 2}
        recent_vulnerabilities.sort(
            key=lambda x: severity_order.get(x['severity'].lower(), 99)
        )
        recent_vulnerabilities = recent_vulnerabilities[:5]
        
        return {
            'active_scans': active_scans,
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulnerabilities,
            'recent_scans': recent_scans,
            'recent_vulnerabilities': recent_vulnerabilities
        }
    
    @aiohttp_jinja2.template('scans.html')
    async def handle_scans(self, request):
        """Handle scans page request"""
        return {
            'active_scans': self.active_scans,
            'scan_history': sorted(
                self.scan_history,
                key=lambda x: x.get('start_time', 0),
                reverse=True
            )
        }
    
    async def handle_start_scan(self, request):
        """Handle start scan request"""
        data = await request.post()
        scan_type = data.get('scan_type')
        
        urls = []
        
        if scan_type == 'url':
            url = data.get('url')
            if url:
                urls = [url]
        elif scan_type == 'file':
            file_field = data.get('url_file')
            if file_field and hasattr(file_field, 'file'):
                content = await file_field.read()
                urls = [line.strip() for line in content.decode('utf-8').splitlines() if line.strip()]
        elif scan_type == 'domain':
            domain = data.get('domain')
            if domain:
                # This would normally use external tools to collect URLs
                urls = [f"https://{domain}"]
        
        if not urls:
            return web.HTTPBadRequest(text="No URLs provided")
        
        # Create scan
        scan_id = str(uuid.uuid4())
        scan = {
            'id': scan_id,
            'urls': urls,
            'total_urls': len(urls),
            'scanned_urls': 0,
            'status': 'pending',
            'start_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': None,
            'progress': 0.0,
            'config': {
                'concurrency': int(data.get('concurrency', 100)),
                'browser': 'browser' in data,
                'smart_scan': 'smart_scan' in data
            }
        }
        
        self.active_scans[scan_id] = scan
        self.scan_history.append(scan)
        
        # Start scan in background
        asyncio.create_task(self.run_scan(scan_id, urls, scan['config']))
        
        # Redirect to scan detail page
        return web.HTTPFound(f"/scan/{scan_id}")
    
    @aiohttp_jinja2.template('scan_detail.html')
    async def handle_scan_detail(self, request):
        """Handle scan detail page request"""
        scan_id = request.match_info['scan_id']
        
        if scan_id not in self.active_scans:
            return web.HTTPNotFound(text=f"Scan {scan_id} not found")
        
        scan = self.active_scans[scan_id]
        results = self.scan_results.get(scan_id, [])
        
        return {
            'scan': scan,
            'results': results,
            'vulnerable_count': sum(1 for r in results if r.get('is_vulnerable', False))
        }
    
    async def handle_stop_scan(self, request):
        """Handle stop scan request"""
        scan_id = request.match_info['scan_id']
        
        if scan_id not in self.active_scans:
            return web.HTTPNotFound(text=f"Scan {scan_id} not found")
        
        scan = self.active_scans[scan_id]
        
        if scan['status'] == 'running':
            scan['status'] = 'stopping'
            # The actual stopping logic would be implemented in run_scan
        
        return web.HTTPFound(f"/scan/{scan_id}")
    
    @aiohttp_jinja2.template('results.html')
    async def handle_results(self, request):
        """Handle results page request"""
        all_results = []
        
        for scan_id, results in self.scan_results.items():
            for result in results:
                result['scan_id'] = scan_id
                all_results.append(result)
        
        return {
            'results': all_results,
            'vulnerable_results': [r for r in all_results if r.get('is_vulnerable', False)]
        }
    
    @aiohttp_jinja2.template('result_detail.html')
    async def handle_result_detail(self, request):
        """Handle result detail page request"""
        result_id = request.match_info['result_id']
        
        # Find result
        for results in self.scan_results.values():
            for result in results:
                if result.get('id') == result_id:
                    return {'result': result}
        
        return web.HTTPNotFound(text=f"Result {result_id} not found")
    
    @aiohttp_jinja2.template('config.html')
    async def handle_config(self, request):
        """Handle config page request"""
        return {'config': self.config}
    
    async def handle_config_update(self, request):
        """Handle config update request"""
        data = await request.post()
        
        # Update config
        # This would normally update the config file
        
        return web.HTTPFound("/config")
    
    @aiohttp_jinja2.template('payloads.html')
    async def handle_payloads(self, request):
        """Handle payloads page request"""
        return {
            'payloads': self.payload_manager.get_all_payloads(),
            'param_payloads': self.payload_manager.get_param_payloads(),
            'path_payloads': self.payload_manager.get_path_payloads()
        }
    
    async def handle_add_payload(self, request):
        """Handle add payload request"""
        data = await request.post()
        payload = data.get('payload')
        
        if payload:
            self.payload_manager.custom_payloads.append(payload)
        
        return web.HTTPFound("/payloads")
    
    async def handle_scan_status(self, request):
        """Handle scan status API request"""
        scan_id = request.match_info['scan_id']
        
        if scan_id not in self.active_scans:
            return web.json_response({'error': 'Scan not found'}, status=404)
        
        return web.json_response(self.active_scans[scan_id])
    
    async def handle_api_scans(self, request):
        """Handle scans API request"""
        return web.json_response({
            'active_scans': self.active_scans,
            'scan_history': self.scan_history
        })
    
    async def handle_api_results(self, request):
        """Handle results API request"""
        return web.json_response(self.scan_results)
    
    async def run_scan(self, scan_id, urls, config):
        """Run a scan in the background"""
        scan = self.active_scans[scan_id]
        scan['status'] = 'running'
        
        # Apply scan configuration
        old_config = {}
        for key, value in config.items():
            if key in self.config:
                old_config[key] = self.config[key]
                self.config[key] = value
        
        # Reinitialize scanner with new config
        self.scanner = Scanner(self.config, self.payload_manager)
        
        try:
            # Run scan
            results = await self.scanner.scan_urls(urls)
            
            # Store results
            for result in results:
                result['id'] = str(uuid.uuid4())
            
            self.scan_results[scan_id] = results
            
            # Update scan status
            scan['status'] = 'completed'
            scan['end_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
            scan['progress'] = 100.0
            scan['scanned_urls'] = len(urls)
            
            logger.info(f"Scan {scan_id} completed")
        except Exception as e:
            logger.error(f"Error in scan {scan_id}: {e}")
            scan['status'] = 'error'
            scan['error'] = str(e)
        finally:
            # Restore original config
            for key, value in old_config.items():
                self.config[key] = value
            
            # Reinitialize scanner with original config
            self.scanner = Scanner(self.config, self.payload_manager)

async def main():
    """Main entry point for the web dashboard"""
    dashboard = WebDashboard()
    runner = await dashboard.start()
    
    try:
        # Keep the server running
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        logger.info("Shutting down web dashboard")
    finally:
        await runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
