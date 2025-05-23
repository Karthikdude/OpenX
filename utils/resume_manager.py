#!/usr/bin/env python3
"""
Resume Manager Module for OpenX
Implements functionality to resume interrupted scans
"""

import os
import json
import logging
import time
import hashlib
from typing import Dict, List, Set, Tuple, Any, Optional
from pathlib import Path

logger = logging.getLogger('openx.resume_manager')

class ResumeManager:
    """
    Manages scan state persistence for resuming interrupted scans
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the resume manager
        
        Args:
            config (Optional[Dict[str, Any]]): Configuration dictionary
        """
        self.config = config or {}
        
        # Set up logging
        log_level = self.config.get('general', {}).get('verbose', False)
        logger.setLevel(logging.DEBUG if log_level else logging.INFO)
        
        # Resume settings
        self.resume_enabled = self.config.get('resume', {}).get('enabled', True)
        self.resume_dir = self.config.get('resume', {}).get('directory', os.path.join(os.path.expanduser('~'), '.openx', 'resume'))
        self.max_age_days = self.config.get('resume', {}).get('max_age_days', 7)
        
        # Ensure resume directory exists
        if self.resume_enabled:
            os.makedirs(self.resume_dir, exist_ok=True)
    
    def generate_session_id(self, urls: List[str], args: Any) -> str:
        """
        Generate a unique session ID based on scan parameters
        
        Args:
            urls (List[str]): List of URLs to scan
            args (Any): Command line arguments or configuration
            
        Returns:
            str: Unique session ID
        """
        # Create a hash of the URLs and key arguments
        hasher = hashlib.sha256()
        
        # Add URLs to hash
        for url in sorted(urls):
            hasher.update(url.encode('utf-8'))
        
        # Add key arguments to hash
        if hasattr(args, 'smart_scan') and args.smart_scan:
            hasher.update(b'smart_scan')
        
        if hasattr(args, 'browser') and args.browser:
            hasher.update(b'browser')
        
        if hasattr(args, 'proxy') and args.proxy:
            hasher.update(args.proxy.encode('utf-8'))
        
        # Generate session ID
        session_id = hasher.hexdigest()[:16]
        return session_id
    
    def get_resume_file_path(self, session_id: str) -> str:
        """
        Get the path to the resume file for a session
        
        Args:
            session_id (str): Session ID
            
        Returns:
            str: Path to resume file
        """
        return os.path.join(self.resume_dir, f"openx_resume_{session_id}.json")
    
    def save_scan_state(self, session_id: str, state: Dict[str, Any]) -> bool:
        """
        Save the current scan state to disk
        
        Args:
            session_id (str): Session ID
            state (Dict[str, Any]): Scan state to save
            
        Returns:
            bool: True if state was saved successfully, False otherwise
        """
        if not self.resume_enabled:
            logger.debug("Resume functionality is disabled")
            return False
        
        try:
            # Add timestamp
            state['timestamp'] = time.time()
            
            # Save to file
            resume_file = self.get_resume_file_path(session_id)
            with open(resume_file, 'w') as f:
                json.dump(state, f, indent=2)
            
            logger.info(f"Saved scan state to {resume_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving scan state: {e}")
            return False
    
    def load_scan_state(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Load a saved scan state from disk
        
        Args:
            session_id (str): Session ID
            
        Returns:
            Optional[Dict[str, Any]]: Loaded scan state or None if not found
        """
        if not self.resume_enabled:
            logger.debug("Resume functionality is disabled")
            return None
        
        try:
            resume_file = self.get_resume_file_path(session_id)
            
            if not os.path.exists(resume_file):
                logger.debug(f"No resume file found for session {session_id}")
                return None
            
            # Load from file
            with open(resume_file, 'r') as f:
                state = json.load(f)
            
            # Check if state is too old
            if 'timestamp' in state:
                age_days = (time.time() - state['timestamp']) / (24 * 60 * 60)
                if age_days > self.max_age_days:
                    logger.warning(f"Resume file is {age_days:.1f} days old, exceeding max age of {self.max_age_days} days")
                    return None
            
            logger.info(f"Loaded scan state from {resume_file}")
            return state
        except Exception as e:
            logger.error(f"Error loading scan state: {e}")
            return None
    
    def clean_old_resume_files(self) -> int:
        """
        Clean up old resume files
        
        Returns:
            int: Number of files removed
        """
        if not self.resume_enabled:
            return 0
        
        try:
            count = 0
            now = time.time()
            max_age_seconds = self.max_age_days * 24 * 60 * 60
            
            for file in os.listdir(self.resume_dir):
                if file.startswith("openx_resume_") and file.endswith(".json"):
                    file_path = os.path.join(self.resume_dir, file)
                    file_age = now - os.path.getmtime(file_path)
                    
                    if file_age > max_age_seconds:
                        os.remove(file_path)
                        count += 1
                        logger.debug(f"Removed old resume file: {file}")
            
            if count > 0:
                logger.info(f"Cleaned up {count} old resume files")
            
            return count
        except Exception as e:
            logger.error(f"Error cleaning old resume files: {e}")
            return 0
    
    def list_available_sessions(self) -> List[Dict[str, Any]]:
        """
        List all available resume sessions
        
        Returns:
            List[Dict[str, Any]]: List of available sessions with metadata
        """
        if not self.resume_enabled:
            return []
        
        try:
            sessions = []
            
            for file in os.listdir(self.resume_dir):
                if file.startswith("openx_resume_") and file.endswith(".json"):
                    file_path = os.path.join(self.resume_dir, file)
                    
                    try:
                        with open(file_path, 'r') as f:
                            state = json.load(f)
                        
                        # Extract session ID from filename
                        session_id = file.replace("openx_resume_", "").replace(".json", "")
                        
                        # Create session info
                        session_info = {
                            'session_id': session_id,
                            'timestamp': state.get('timestamp', 0),
                            'date': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(state.get('timestamp', 0))),
                            'total_urls': len(state.get('urls', [])),
                            'scanned_urls': len(state.get('scanned_urls', [])),
                            'remaining_urls': len(state.get('urls', [])) - len(state.get('scanned_urls', [])),
                            'file_path': file_path
                        }
                        
                        sessions.append(session_info)
                    except Exception as e:
                        logger.error(f"Error reading resume file {file}: {e}")
            
            # Sort by timestamp (newest first)
            sessions.sort(key=lambda x: x['timestamp'], reverse=True)
            
            return sessions
        except Exception as e:
            logger.error(f"Error listing available sessions: {e}")
            return []
    
    def delete_session(self, session_id: str) -> bool:
        """
        Delete a saved session
        
        Args:
            session_id (str): Session ID to delete
            
        Returns:
            bool: True if session was deleted successfully, False otherwise
        """
        if not self.resume_enabled:
            return False
        
        try:
            resume_file = self.get_resume_file_path(session_id)
            
            if os.path.exists(resume_file):
                os.remove(resume_file)
                logger.info(f"Deleted session {session_id}")
                return True
            else:
                logger.warning(f"Session {session_id} not found")
                return False
        except Exception as e:
            logger.error(f"Error deleting session {session_id}: {e}")
            return False
    
    def create_scan_state(self, urls: List[str], args: Any) -> Dict[str, Any]:
        """
        Create an initial scan state
        
        Args:
            urls (List[str]): List of URLs to scan
            args (Any): Command line arguments or configuration
            
        Returns:
            Dict[str, Any]: Initial scan state
        """
        return {
            'timestamp': time.time(),
            'urls': urls,
            'scanned_urls': [],
            'results': [],
            'args': vars(args) if hasattr(args, '__dict__') else {},
            'progress': 0.0
        }
    
    def update_scan_progress(self, session_id: str, scanned_url: str, result: Optional[Dict[str, Any]] = None) -> bool:
        """
        Update scan progress for a session
        
        Args:
            session_id (str): Session ID
            scanned_url (str): URL that was scanned
            result (Optional[Dict[str, Any]]): Scan result for the URL
            
        Returns:
            bool: True if state was updated successfully, False otherwise
        """
        if not self.resume_enabled:
            return False
        
        try:
            # Load current state
            state = self.load_scan_state(session_id)
            
            if not state:
                logger.warning(f"No state found for session {session_id}")
                return False
            
            # Update scanned URLs
            if scanned_url not in state['scanned_urls']:
                state['scanned_urls'].append(scanned_url)
            
            # Add result if provided
            if result:
                state['results'].append(result)
            
            # Update progress
            total_urls = len(state['urls'])
            scanned_urls = len(state['scanned_urls'])
            state['progress'] = (scanned_urls / total_urls) * 100 if total_urls > 0 else 0
            
            # Save updated state
            return self.save_scan_state(session_id, state)
        except Exception as e:
            logger.error(f"Error updating scan progress: {e}")
            return False
