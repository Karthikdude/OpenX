/**
 * Main JavaScript for Flask Open Redirect Lab
 * Handles interactive testing and UI functionality
 */

// Global state management
const LabState = {
    testResults: {
        total: 0,
        successful: 0,
        failed: 0,
        errors: 0
    },
    currentTests: new Set(),
    testHistory: []
};

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

/**
 * Initialize the application
 */
function initializeApp() {
    setupEventListeners();
    setupPayloadHandlers();
    loadTestHistory();
    updateResultsSummary();
}

/**
 * Setup event listeners for interactive elements
 */
function setupEventListeners() {
    // Category filter buttons
    document.querySelectorAll('.btn-group .btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const category = this.textContent.trim();
            filterCategory(category);
        });
    });

    // Test all button
    const testAllBtn = document.querySelector('[onclick="testAllEndpoints()"]');
    if (testAllBtn) {
        testAllBtn.addEventListener('click', function(e) {
            e.preventDefault();
            testAllEndpoints();
        });
    }

    // Export results button
    const exportBtn = document.querySelector('[onclick="exportResults()"]');
    if (exportBtn) {
        exportBtn.addEventListener('click', function(e) {
            e.preventDefault();
            exportResults();
        });
    }

    // Help button
    document.querySelectorAll('[onclick="showHelp()"]').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            showHelp();
        });
    });
}

/**
 * Setup payload selection handlers
 */
function setupPayloadHandlers() {
    document.querySelectorAll('.payload-select').forEach(select => {
        select.addEventListener('change', function() {
            const customInput = this.parentNode.querySelector('.custom-payload');
            if (this.value === 'custom') {
                customInput.style.display = 'block';
                customInput.focus();
            } else {
                customInput.style.display = 'none';
            }
        });
    });
}

/**
 * Filter endpoints by category
 */
function filterCategory(category) {
    const cards = document.querySelectorAll('.endpoint-card');
    const buttons = document.querySelectorAll('.btn-group .btn');
    
    // Update active button
    buttons.forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    
    // Show/hide cards
    cards.forEach(card => {
        const cardCategory = card.dataset.category;
        if (category.toLowerCase() === 'all' || cardCategory === category) {
            card.style.display = 'block';
            card.classList.add('fade-in');
        } else {
            card.style.display = 'none';
            card.classList.remove('fade-in');
        }
    });

    // Update visible count
    const visibleCount = document.querySelectorAll('.endpoint-card[style*="display: block"]').length;
    showToast(`Showing ${visibleCount} endpoints in ${category} category`, 'info');
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(input) {
    if (input && input.select) {
        input.select();
        input.setSelectionRange(0, 99999); // For mobile devices
        
        try {
            const successful = document.execCommand('copy');
            if (successful) {
                const button = input.nextElementSibling;
                const originalHTML = button.innerHTML;
                button.innerHTML = '<i class="fas fa-check text-success"></i>';
                button.classList.add('btn-success');
                
                setTimeout(() => {
                    button.innerHTML = originalHTML;
                    button.classList.remove('btn-success');
                }, 1500);
                
                showToast('URL copied to clipboard!', 'success');
            }
        } catch (err) {
            // Fallback for modern browsers
            if (navigator.clipboard) {
                navigator.clipboard.writeText(input.value).then(() => {
                    showToast('URL copied to clipboard!', 'success');
                }).catch(() => {
                    showToast('Failed to copy URL', 'error');
                });
            } else {
                showToast('Copy not supported in this browser', 'warning');
            }
        }
    }
}

/**
 * Test individual endpoint
 */
async function testEndpoint(baseUrl, button) {
    const card = button.closest('.card');
    const payloadSelect = card.querySelector('.payload-select');
    const customPayload = card.querySelector('.custom-payload');
    const resultDiv = card.querySelector('.test-result');
    const endpointName = card.querySelector('.card-header h6').textContent;
    
    // Get payload
    let payload = payloadSelect.value === 'custom' ? customPayload.value : payloadSelect.value;
    
    if (!payload) {
        showToast('Please select or enter a payload', 'warning');
        return;
    }
    
    // Prevent multiple simultaneous tests
    if (LabState.currentTests.has(endpointName)) {
        showToast('Test already in progress for this endpoint', 'info');
        return;
    }
    
    LabState.currentTests.add(endpointName);
    
    // Build test URL
    const testUrl = constructTestUrl(baseUrl, payload);
    
    // Update UI
    setButtonLoading(button, true);
    resultDiv.style.display = 'none';
    
    const testStartTime = Date.now();
    
    try {
        const result = await performVulnerabilityTest(testUrl, payload);
        const testDuration = Date.now() - testStartTime;
        
        // Update statistics
        LabState.testResults.total++;
        
        // Display result
        displayTestResult(resultDiv, result, testDuration);
        
        // Update statistics based on result
        if (result.vulnerable) {
            LabState.testResults.successful++;
        } else {
            LabState.testResults.failed++;
        }
        
        // Save to history
        saveTestToHistory({
            endpoint: endpointName,
            url: testUrl,
            payload: payload,
            result: result,
            timestamp: new Date().toISOString(),
            duration: testDuration
        });
        
    } catch (error) {
        LabState.testResults.total++;
        LabState.testResults.errors++;
        
        displayTestResult(resultDiv, {
            vulnerable: false,
            error: true,
            message: error.message,
            status: 'Error'
        });
        
        console.error('Test error:', error);
    } finally {
        setButtonLoading(button, false);
        LabState.currentTests.delete(endpointName);
        updateResultsSummary();
    }
}

/**
 * Construct test URL with proper encoding
 */
function constructTestUrl(baseUrl, payload) {
    const baseURL = window.location.origin + baseUrl;
    
    // Handle different URL patterns
    if (baseUrl.includes('?')) {
        return baseURL + encodeURIComponent(payload);
    } else {
        return baseURL + '?url=' + encodeURIComponent(payload);
    }
}

/**
 * Perform vulnerability test using multiple detection methods
 */
async function performVulnerabilityTest(testUrl, payload) {
    const testMethods = [
        testRedirectResponse,
        testJavaScriptRedirect,
        testMetaRefresh,
        testLocationHeader
    ];
    
    const results = [];
    
    for (const testMethod of testMethods) {
        try {
            const result = await testMethod(testUrl, payload);
            results.push(result);
        } catch (error) {
            results.push({
                vulnerable: false,
                error: true,
                message: error.message,
                method: testMethod.name
            });
        }
    }
    
    // Determine overall vulnerability status
    const vulnerable = results.some(r => r.vulnerable);
    const methods = results.filter(r => r.vulnerable).map(r => r.method);
    
    return {
        vulnerable: vulnerable,
        methods: methods,
        status: vulnerable ? 'Vulnerable' : 'Protected',
        details: results,
        confidence: calculateConfidence(results)
    };
}

/**
 * Test for HTTP redirect response
 */
async function testRedirectResponse(testUrl, payload) {
    try {
        const response = await fetch(testUrl, { 
            method: 'HEAD',
            redirect: 'manual',
            mode: 'cors'
        });
        
        const isRedirect = response.status >= 300 && response.status < 400;
        const location = response.headers.get('Location');
        
        return {
            vulnerable: isRedirect && location && isExternalRedirect(testUrl, location, payload),
            method: 'HTTP Redirect',
            status: response.status,
            location: location,
            type: 'redirect_response'
        };
    } catch (error) {
        // Handle CORS and other network errors
        if (error.name === 'TypeError' && error.message.includes('cors')) {
            // CORS error might indicate redirect occurred
            return {
                vulnerable: true,
                method: 'HTTP Redirect (CORS)',
                status: 'CORS_ERROR',
                location: 'Unknown (CORS blocked)',
                type: 'cors_redirect'
            };
        }
        throw error;
    }
}

/**
 * Test for JavaScript-based redirects
 */
async function testJavaScriptRedirect(testUrl, payload) {
    try {
        const response = await fetch(testUrl, { 
            method: 'GET',
            redirect: 'follow'
        });
        
        const text = await response.text();
        const jsRedirectPatterns = [
            /window\.location\s*=\s*['"](.*?)['"]/gi,
            /window\.location\.href\s*=\s*['"](.*?)['"]/gi,
            /location\.href\s*=\s*['"](.*?)['"]/gi,
            /document\.location\s*=\s*['"](.*?)['"]/gi
        ];
        
        for (const pattern of jsRedirectPatterns) {
            const matches = text.matchAll(pattern);
            for (const match of matches) {
                if (match[1] && match[1].includes(payload)) {
                    return {
                        vulnerable: true,
                        method: 'JavaScript Redirect',
                        location: match[1],
                        type: 'js_redirect'
                    };
                }
            }
        }
        
        return {
            vulnerable: false,
            method: 'JavaScript Redirect',
            type: 'js_redirect'
        };
    } catch (error) {
        throw error;
    }
}

/**
 * Test for meta refresh redirects
 */
async function testMetaRefresh(testUrl, payload) {
    try {
        const response = await fetch(testUrl);
        const text = await response.text();
        
        const metaPattern = /<meta[^>]+http-equiv\s*=\s*['"]\s*refresh\s*['"][^>]+content\s*=\s*['"]\s*\d+\s*;\s*url\s*=\s*([^'"]+)['"]/gi;
        const matches = text.matchAll(metaPattern);
        
        for (const match of matches) {
            if (match[1] && match[1].includes(payload)) {
                return {
                    vulnerable: true,
                    method: 'Meta Refresh',
                    location: match[1],
                    type: 'meta_refresh'
                };
            }
        }
        
        return {
            vulnerable: false,
            method: 'Meta Refresh',
            type: 'meta_refresh'
        };
    } catch (error) {
        throw error;
    }
}

/**
 * Test for location header manipulation
 */
async function testLocationHeader(testUrl, payload) {
    try {
        const response = await fetch(testUrl, { redirect: 'manual' });
        const location = response.headers.get('Location');
        
        if (location && payload && location.includes(payload)) {
            return {
                vulnerable: isExternalRedirect(testUrl, location, payload),
                method: 'Location Header',
                location: location,
                status: response.status,
                type: 'location_header'
            };
        }
        
        return {
            vulnerable: false,
            method: 'Location Header',
            type: 'location_header'
        };
    } catch (error) {
        throw error;
    }
}

/**
 * Check if redirect is to external domain
 */
function isExternalRedirect(originalUrl, redirectUrl, payload) {
    if (!redirectUrl) return false;
    
    try {
        const originalDomain = new URL(originalUrl).hostname;
        
        // Handle relative URLs
        if (redirectUrl.startsWith('/')) {
            return false;
        }
        
        // Handle protocol-relative URLs
        if (redirectUrl.startsWith('//')) {
            redirectUrl = 'http:' + redirectUrl;
        }
        
        // Handle URLs without protocol
        if (!redirectUrl.startsWith('http')) {
            // Check for dangerous protocols
            if (redirectUrl.startsWith('javascript:') || redirectUrl.startsWith('data:')) {
                return true;
            }
            redirectUrl = 'http://' + redirectUrl;
        }
        
        const redirectDomain = new URL(redirectUrl).hostname;
        
        // Different domains indicate external redirect
        return originalDomain !== redirectDomain;
    } catch (error) {
        // If URL parsing fails, assume it's external if it contains payload
        return redirectUrl.includes(payload);
    }
}

/**
 * Calculate confidence level of vulnerability detection
 */
function calculateConfidence(results) {
    const vulnerableCount = results.filter(r => r.vulnerable).length;
    const totalCount = results.length;
    
    if (vulnerableCount === 0) return 'None';
    if (vulnerableCount === totalCount) return 'High';
    if (vulnerableCount >= totalCount * 0.5) return 'Medium';
    return 'Low';
}

/**
 * Display test result in UI
 */
function displayTestResult(resultDiv, result, duration = 0) {
    let alertClass = 'alert-success';
    let iconClass = 'fas fa-check-circle';
    let message = '';
    
    if (result.error) {
        alertClass = 'alert-danger';
        iconClass = 'fas fa-exclamation-triangle';
        message = `Error: ${result.message}`;
    } else if (result.vulnerable) {
        alertClass = 'alert-success';
        iconClass = 'fas fa-bug';
        message = `Vulnerable! ${result.status}`;
        
        if (result.methods && result.methods.length > 0) {
            message += ` (${result.methods.join(', ')})`;
        }
        
        if (result.confidence) {
            message += ` - Confidence: ${result.confidence}`;
        }
    } else {
        alertClass = 'alert-warning';
        iconClass = 'fas fa-shield-alt';
        message = `Protected - ${result.status || 'No vulnerability detected'}`;
    }
    
    // Add duration if available
    if (duration > 0) {
        message += ` (${duration}ms)`;
    }
    
    resultDiv.innerHTML = `
        <div class="alert ${alertClass} alert-sm mb-0">
            <i class="${iconClass}"></i> ${message}
        </div>
    `;
    resultDiv.style.display = 'block';
    
    // Add animation
    resultDiv.classList.add('fade-in');
}

/**
 * Set button loading state
 */
function setButtonLoading(button, loading) {
    if (loading) {
        button.disabled = true;
        button.dataset.originalContent = button.innerHTML;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing...';
    } else {
        button.disabled = false;
        button.innerHTML = button.dataset.originalContent || '<i class="fas fa-play"></i> Test';
    }
}

/**
 * Open endpoint in new tab
 */
function openInNewTab(baseUrl, button) {
    const card = button.closest('.card');
    const payloadSelect = card.querySelector('.payload-select');
    const customPayload = card.querySelector('.custom-payload');
    
    let payload = payloadSelect.value === 'custom' ? customPayload.value : payloadSelect.value;
    
    if (!payload) {
        showToast('Please select or enter a payload', 'warning');
        return;
    }
    
    const testUrl = constructTestUrl(baseUrl, payload);
    window.open(testUrl, '_blank', 'noopener,noreferrer');
    
    showToast('Opened in new tab', 'info');
}

/**
 * Test all visible endpoints
 */
async function testAllEndpoints() {
    const visibleCards = document.querySelectorAll('.endpoint-card:not([style*="display: none"])');
    
    if (visibleCards.length === 0) {
        showToast('No endpoints visible to test', 'warning');
        return;
    }
    
    const confirmed = confirm(`This will test ${visibleCards.length} endpoints. This may take a while. Continue?`);
    if (!confirmed) return;
    
    // Disable test all button
    const testAllBtn = document.querySelector('[onclick="testAllEndpoints()"]');
    if (testAllBtn) {
        testAllBtn.disabled = true;
        testAllBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing All...';
    }
    
    const startTime = Date.now();
    let completed = 0;
    
    // Test endpoints with controlled concurrency
    const maxConcurrent = 3;
    const chunks = chunkArray(Array.from(visibleCards), maxConcurrent);
    
    for (const chunk of chunks) {
        const promises = chunk.map(async (card) => {
            const testButton = card.querySelector('.btn-primary');
            const baseUrl = extractBaseUrl(testButton);
            
            if (baseUrl) {
                await testEndpoint(baseUrl, testButton);
            }
            
            completed++;
            updateProgress(completed, visibleCards.length);
        });
        
        await Promise.all(promises);
        
        // Add delay between chunks to be respectful
        if (chunks.indexOf(chunk) < chunks.length - 1) {
            await sleep(1000);
        }
    }
    
    const duration = Date.now() - startTime;
    
    // Re-enable test all button
    if (testAllBtn) {
        testAllBtn.disabled = false;
        testAllBtn.innerHTML = '<i class="fas fa-play"></i> Test All';
    }
    
    showToast(`Completed testing ${visibleCards.length} endpoints in ${(duration/1000).toFixed(1)}s`, 'success');
}

/**
 * Extract base URL from test button
 */
function extractBaseUrl(button) {
    const onclickAttr = button.getAttribute('onclick');
    if (onclickAttr) {
        const match = onclickAttr.match(/'([^']+)'/);
        return match ? match[1] : null;
    }
    return null;
}

/**
 * Update progress during batch testing
 */
function updateProgress(completed, total) {
    const percentage = Math.round((completed / total) * 100);
    // You could add a progress bar here if needed
    console.log(`Progress: ${completed}/${total} (${percentage}%)`);
}

/**
 * Chunk array into smaller arrays
 */
function chunkArray(array, size) {
    const chunks = [];
    for (let i = 0; i < array.length; i += size) {
        chunks.push(array.slice(i, i + size));
    }
    return chunks;
}

/**
 * Sleep utility function
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Update results summary display
 */
function updateResultsSummary() {
    const elements = {
        total: document.getElementById('total-tests'),
        successful: document.getElementById('successful-tests'),
        failed: document.getElementById('failed-tests'),
        errors: document.getElementById('error-tests')
    };
    
    Object.keys(elements).forEach(key => {
        const element = elements[key];
        if (element) {
            element.textContent = LabState.testResults[key];
            
            // Add animation for updates
            element.classList.add('pulse');
            setTimeout(() => element.classList.remove('pulse'), 1000);
        }
    });
}

/**
 * Export test results
 */
function exportResults() {
    const results = {
        metadata: {
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent,
            testLabVersion: '1.0.0',
            totalEndpoints: document.querySelectorAll('.endpoint-card').length
        },
        summary: { ...LabState.testResults },
        testHistory: LabState.testHistory,
        detailedResults: collectDetailedResults()
    };
    
    // Create and download file
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `redirect-lab-results-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showToast('Results exported successfully', 'success');
}

/**
 * Collect detailed results from UI
 */
function collectDetailedResults() {
    const results = [];
    
    document.querySelectorAll('.endpoint-card').forEach(card => {
        const name = card.querySelector('.card-header h6').textContent.trim();
        const category = card.dataset.category;
        const result = card.querySelector('.test-result');
        
        if (result && result.style.display !== 'none') {
            const alertDiv = result.querySelector('.alert');
            if (alertDiv) {
                results.push({
                    endpoint: name,
                    category: category,
                    result: alertDiv.textContent.trim(),
                    vulnerable: alertDiv.classList.contains('alert-success'),
                    protected: alertDiv.classList.contains('alert-warning'),
                    error: alertDiv.classList.contains('alert-danger')
                });
            }
        }
    });
    
    return results;
}

/**
 * Save test to history
 */
function saveTestToHistory(testData) {
    LabState.testHistory.push(testData);
    
    // Limit history size
    if (LabState.testHistory.length > 100) {
        LabState.testHistory = LabState.testHistory.slice(-100);
    }
    
    // Save to localStorage
    try {
        localStorage.setItem('lab-test-history', JSON.stringify(LabState.testHistory));
    } catch (error) {
        console.warn('Failed to save test history:', error);
    }
}

/**
 * Load test history from localStorage
 */
function loadTestHistory() {
    try {
        const saved = localStorage.getItem('lab-test-history');
        if (saved) {
            LabState.testHistory = JSON.parse(saved);
        }
    } catch (error) {
        console.warn('Failed to load test history:', error);
        LabState.testHistory = [];
    }
}

/**
 * Show help modal
 */
function showHelp() {
    const helpModal = document.getElementById('helpModal');
    if (helpModal) {
        new bootstrap.Modal(helpModal).show();
    }
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    const toastContainer = getOrCreateToastContainer();
    
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${getBootstrapColor(type)} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <i class="fas ${getToastIcon(type)}"></i> ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    
    const bsToast = new bootstrap.Toast(toast, {
        delay: type === 'error' ? 5000 : 3000
    });
    
    bsToast.show();
    
    // Remove toast element after it's hidden
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

/**
 * Get or create toast container
 */
function getOrCreateToastContainer() {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container position-fixed top-0 end-0 p-3';
        container.style.zIndex = '9999';
        document.body.appendChild(container);
    }
    return container;
}

/**
 * Get Bootstrap color class for toast type
 */
function getBootstrapColor(type) {
    const colors = {
        success: 'success',
        error: 'danger',
        warning: 'warning',
        info: 'primary'
    };
    return colors[type] || 'primary';
}

/**
 * Get icon for toast type
 */
function getToastIcon(type) {
    const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-triangle',
        warning: 'fa-exclamation-circle',
        info: 'fa-info-circle'
    };
    return icons[type] || 'fa-info-circle';
}

/**
 * Reset all test results
 */
function resetResults() {
    if (confirm('Are you sure you want to reset all test results?')) {
        LabState.testResults = {
            total: 0,
            successful: 0,
            failed: 0,
            errors: 0
        };
        
        LabState.testHistory = [];
        
        // Clear UI results
        document.querySelectorAll('.test-result').forEach(result => {
            result.style.display = 'none';
        });
        
        updateResultsSummary();
        
        try {
            localStorage.removeItem('lab-test-history');
        } catch (error) {
            console.warn('Failed to clear test history:', error);
        }
        
        showToast('All results have been reset', 'info');
    }
}

// Expose global functions that might be called from HTML
window.testEndpoint = testEndpoint;
window.openInNewTab = openInNewTab;
window.copyToClipboard = copyToClipboard;
window.testAllEndpoints = testAllEndpoints;
window.exportResults = exportResults;
window.showHelp = showHelp;
window.filterCategory = filterCategory;
window.resetResults = resetResults;
