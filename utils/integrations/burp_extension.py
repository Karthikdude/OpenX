#!/usr/bin/env python3
"""
Burp Suite Extension for OpenX
Provides integration with Burp Suite for open redirect scanning
"""

import os
import sys
import json
import logging
import tempfile
from typing import Dict, List, Set, Tuple, Any, Optional
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import OpenX modules
from core.scanner import Scanner
from payloads.payload_manager import PayloadManager
from config.config import Config

# Burp Suite extension imports
try:
    from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpListener
    from burp import IMessageEditorController, IContextMenuInvocation
    from javax.swing import JPanel, JButton, JTextField, JLabel, JCheckBox, JScrollPane, JTable
    from javax.swing import JTabbedPane, JComboBox, BoxLayout, Box, BorderFactory, JMenuItem
    from javax.swing.table import AbstractTableModel
    from java.awt import BorderLayout, FlowLayout, GridLayout, Dimension
    from java.util import ArrayList
    from java.lang import Thread
    BURP_AVAILABLE = True
except ImportError:
    BURP_AVAILABLE = False
    # Create dummy classes for IDE support
    class IBurpExtender: pass
    class ITab: pass
    class IContextMenuFactory: pass
    class IHttpListener: pass
    class IMessageEditorController: pass
    class IContextMenuInvocation: pass

logger = logging.getLogger('openx.integrations.burp')

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener):
    """
    Burp Suite extension for OpenX
    """
    
    def registerExtenderCallbacks(self, callbacks):
        """
        Register extension callbacks
        
        Args:
            callbacks: Burp Suite callbacks
        """
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("OpenX - Open Redirect Scanner")
        
        # Initialize OpenX components
        self.config = Config().load_config()
        self.payload_manager = PayloadManager(self.config)
        
        # Create UI
        self.tab = self.createTab()
        callbacks.addSuiteTab(self)
        
        # Register context menu
        callbacks.registerContextMenuFactory(self)
        
        # Register HTTP listener
        callbacks.registerHttpListener(self)
        
        # Print banner
        print("OpenX Burp Extension loaded")
        print("Version: 2.0")
        print("Author: Karthik S Sathyan")
    
    def createTab(self):
        """
        Create the extension tab UI
        
        Returns:
            JPanel: Main panel for the extension tab
        """
        panel = JPanel(BorderLayout())
        
        # Create tabbed pane
        tabbedPane = JTabbedPane()
        
        # Scanner tab
        scannerPanel = JPanel()
        scannerPanel.setLayout(BoxLayout(scannerPanel, BoxLayout.Y_AXIS))
        
        # URL input
        urlPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        urlPanel.add(JLabel("URL to scan:"))
        self.urlField = JTextField("", 40)
        urlPanel.add(self.urlField)
        scannerPanel.add(urlPanel)
        
        # Options
        optionsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.browserCheck = JCheckBox("Use browser-based detection", False)
        self.smartScanCheck = JCheckBox("Enable smart scan", True)
        optionsPanel.add(self.browserCheck)
        optionsPanel.add(self.smartScanCheck)
        scannerPanel.add(optionsPanel)
        
        # Buttons
        buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        scanButton = JButton("Scan URL", actionPerformed=self.scanURL)
        scanSiteButton = JButton("Scan Selected Site", actionPerformed=self.scanSite)
        buttonPanel.add(scanButton)
        buttonPanel.add(scanSiteButton)
        scannerPanel.add(buttonPanel)
        
        # Results table
        self.resultsModel = ResultsTableModel()
        resultsTable = JTable(self.resultsModel)
        scrollPane = JScrollPane(resultsTable)
        scannerPanel.add(JLabel("Scan Results:"))
        scannerPanel.add(scrollPane)
        
        # Configuration tab
        configPanel = JPanel()
        configPanel.setLayout(BoxLayout(configPanel, BoxLayout.Y_AXIS))
        
        # Payload configuration
        payloadPanel = JPanel(GridLayout(0, 2))
        payloadPanel.setBorder(BorderFactory.createTitledBorder("Payload Configuration"))
        
        payloadPanel.add(JLabel("Target Domain:"))
        self.targetDomainField = JTextField(self.config.get('target_domains', ['example.com'])[0], 20)
        payloadPanel.add(self.targetDomainField)
        
        payloadPanel.add(JLabel("Custom Payloads File:"))
        self.customPayloadsField = JTextField(self.config.get('custom_payload_file', ''), 20)
        payloadPanel.add(self.customPayloadsField)
        
        configPanel.add(payloadPanel)
        
        # Scanner configuration
        scannerConfigPanel = JPanel(GridLayout(0, 2))
        scannerConfigPanel.setBorder(BorderFactory.createTitledBorder("Scanner Configuration"))
        
        scannerConfigPanel.add(JLabel("Concurrency:"))
        self.concurrencyField = JTextField(str(self.config.get('concurrency', 100)), 5)
        scannerConfigPanel.add(self.concurrencyField)
        
        scannerConfigPanel.add(JLabel("Timeout (seconds):"))
        self.timeoutField = JTextField(str(self.config.get('timeout', 10)), 5)
        scannerConfigPanel.add(self.timeoutField)
        
        scannerConfigPanel.add(JLabel("Browser Type:"))
        self.browserTypeCombo = JComboBox(["playwright", "selenium"])
        self.browserTypeCombo.setSelectedItem(self.config.get('browser', {}).get('type', 'playwright'))
        scannerConfigPanel.add(self.browserTypeCombo)
        
        configPanel.add(scannerConfigPanel)
        
        # Save button
        savePanel = JPanel(FlowLayout(FlowLayout.RIGHT))
        saveButton = JButton("Save Configuration", actionPerformed=self.saveConfig)
        savePanel.add(saveButton)
        configPanel.add(savePanel)
        
        # Add tabs
        tabbedPane.addTab("Scanner", scannerPanel)
        tabbedPane.addTab("Configuration", configPanel)
        
        panel.add(tabbedPane, BorderLayout.CENTER)
        return panel
    
    def scanURL(self, event):
        """
        Scan a single URL
        
        Args:
            event: Button click event
        """
        url = self.urlField.getText()
        if not url:
            self.callbacks.printOutput("Error: URL is required")
            return
        
        # Update configuration
        self.updateConfig()
        
        # Create scanner
        scanner = Scanner(self.config, self.payload_manager)
        
        # Run scan in a separate thread
        thread = Thread(target=self.runScan, args=(scanner, [url]))
        thread.start()
    
    def scanSite(self, event):
        """
        Scan a selected site from the site map
        
        Args:
            event: Button click event
        """
        # Get selected site map items
        siteMapData = self.callbacks.getSiteMap(None)
        if not siteMapData:
            self.callbacks.printOutput("Error: No sites in site map")
            return
        
        # Extract URLs
        urls = []
        for item in siteMapData:
            request = item.getRequest()
            if request:
                requestInfo = self.helpers.analyzeRequest(request)
                url = requestInfo.getUrl().toString()
                urls.append(url)
        
        # Update configuration
        self.updateConfig()
        
        # Create scanner
        scanner = Scanner(self.config, self.payload_manager)
        
        # Run scan in a separate thread
        thread = Thread(target=self.runScan, args=(scanner, urls))
        thread.start()
    
    def runScan(self, scanner, urls):
        """
        Run a scan with the given scanner and URLs
        
        Args:
            scanner: Scanner instance
            urls: List of URLs to scan
        """
        try:
            self.callbacks.printOutput(f"Starting scan of {len(urls)} URLs...")
            
            # Clear results
            self.resultsModel.clearResults()
            
            # Run scan
            results = []
            for url in urls:
                # Since we can't use asyncio in Jython, we'll call the synchronous version
                result = scanner.test_url_sync(url)
                if result:
                    results.append(result)
                    
                    # Add to results table
                    if result.get('is_vulnerable', False):
                        self.resultsModel.addResult(result)
            
            self.callbacks.printOutput(f"Scan completed. Found {len(results)} results.")
        except Exception as e:
            self.callbacks.printError(f"Error during scan: {e}")
    
    def updateConfig(self):
        """Update configuration from UI fields"""
        # Update target domain
        target_domain = self.targetDomainField.getText()
        if target_domain:
            self.config['target_domains'] = [target_domain]
        
        # Update custom payloads file
        custom_payloads = self.customPayloadsField.getText()
        if custom_payloads:
            self.config['custom_payload_file'] = custom_payloads
        
        # Update scanner settings
        try:
            self.config['concurrency'] = int(self.concurrencyField.getText())
        except:
            pass
        
        try:
            self.config['timeout'] = int(self.timeoutField.getText())
        except:
            pass
        
        # Update browser settings
        if 'browser' not in self.config:
            self.config['browser'] = {}
        
        self.config['browser']['enabled'] = self.browserCheck.isSelected()
        self.config['browser']['type'] = self.browserTypeCombo.getSelectedItem()
        
        # Update smart scan
        self.config['smart_scan'] = self.smartScanCheck.isSelected()
        
        # Reinitialize payload manager
        self.payload_manager = PayloadManager(self.config)
    
    def saveConfig(self, event):
        """
        Save configuration
        
        Args:
            event: Button click event
        """
        self.updateConfig()
        self.callbacks.printOutput("Configuration saved")
    
    # ITab implementation
    
    def getTabCaption(self):
        """Get the tab caption"""
        return "OpenX"
    
    def getUiComponent(self):
        """Get the UI component"""
        return self.tab
    
    # IContextMenuFactory implementation
    
    def createMenuItems(self, invocation):
        """
        Create context menu items
        
        Args:
            invocation: Context menu invocation
        
        Returns:
            List: List of menu items
        """
        menuItems = ArrayList()
        
        # Add menu item for scanning selected URL
        menuItems.add(JMenuItem("Scan with OpenX", actionPerformed=lambda event: self.scanSelectedURL(invocation)))
        
        return menuItems
    
    def scanSelectedURL(self, invocation):
        """
        Scan the selected URL from context menu
        
        Args:
            invocation: Context menu invocation
        """
        # Get selected message
        selectedMessages = invocation.getSelectedMessages()
        if not selectedMessages or len(selectedMessages) == 0:
            return
        
        # Get URL from first selected message
        requestInfo = self.helpers.analyzeRequest(selectedMessages[0])
        url = requestInfo.getUrl().toString()
        
        # Set URL in field
        self.urlField.setText(url)
        
        # Trigger scan
        self.scanURL(None)
    
    # IHttpListener implementation
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        Process HTTP messages
        
        Args:
            toolFlag: Tool flag
            messageIsRequest: True if message is a request, False if response
            messageInfo: Message information
        """
        # Only process responses from the proxy tool
        if toolFlag == self.callbacks.TOOL_PROXY and not messageIsRequest:
            # Analyze response for potential open redirects
            response = messageInfo.getResponse()
            responseInfo = self.helpers.analyzeResponse(response)
            
            # Get response body
            bodyOffset = responseInfo.getBodyOffset()
            body = self.helpers.bytesToString(response)[bodyOffset:]
            
            # Check for potential redirect indicators
            if "window.location" in body or "location.href" in body or '<meta http-equiv="refresh"' in body:
                # Get request details
                requestInfo = self.helpers.analyzeRequest(messageInfo.getRequest())
                url = requestInfo.getUrl().toString()
                
                # Add comment to highlight potential redirect
                messageInfo.setComment("Potential redirect detected by OpenX")
                
                # Log the finding
                self.callbacks.printOutput(f"Potential redirect detected in: {url}")

class ResultsTableModel(AbstractTableModel):
    """Table model for scan results"""
    
    def __init__(self):
        """Initialize the results table model"""
        self.columnNames = ["URL", "Type", "Severity", "Details"]
        self.data = ArrayList()
    
    def getColumnCount(self):
        """Get the number of columns"""
        return len(self.columnNames)
    
    def getRowCount(self):
        """Get the number of rows"""
        return self.data.size()
    
    def getColumnName(self, column):
        """Get the column name"""
        return self.columnNames[column]
    
    def getValueAt(self, row, column):
        """Get the value at a specific row and column"""
        result = self.data.get(row)
        
        if column == 0:
            return result.get("url", "")
        elif column == 1:
            return result.get("type", "")
        elif column == 2:
            return result.get("severity", "")
        elif column == 3:
            return result.get("details", "")
        
        return ""
    
    def addResult(self, result):
        """
        Add a result to the table
        
        Args:
            result: Result to add
        """
        self.data.add(result)
        self.fireTableDataChanged()
    
    def clearResults(self):
        """Clear all results"""
        self.data.clear()
        self.fireTableDataChanged()

# For standalone testing
if __name__ == "__main__":
    print("This is a Burp Suite extension. Load it through Burp's Extender interface.")
