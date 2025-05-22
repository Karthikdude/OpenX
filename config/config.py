#!/usr/bin/env python3
"""
Configuration module for OpenX
Contains default settings and configuration loading functionality
"""
import os
import json
import logging
from pathlib import Path

class Config:
    """Configuration class for OpenX tool"""
    
    def __init__(self, config_file=None):
        """
        Initialize configuration with default values
        
        Args:
            config_file (str, optional): Path to configuration file
        """
        # Default configuration
        self.default_config = {
            "timeout": 10,
            "concurrency": 100,
            "user_agent_rotation": True,
            "verify_ssl": False,
            "max_retries": 3,
            "retry_delay": 2,
            "target_domains": ["example.com"],
            "severity_levels": {
                "high": ["Open redirect with no validation"],
                "medium": ["Open redirect with partial validation"],
                "low": ["Potential redirect requiring user interaction"]
            },
            "proxy": None,
            "proxy_auth": None,
            "auth": {
                "enabled": False,
                "type": None,  # basic, digest, oauth
                "username": None,
                "password": None,
                "token": None
            },
            "browser": {
                "enabled": False,
                "type": "playwright",  # playwright or selenium
                "headless": True,
                "timeout": 30
            },
            "smart_scan": False,
            "evasion": {
                "random_delay": False,
                "min_delay": 0.5,
                "max_delay": 3.0,
                "waf_bypass": False
            },
            "reporting": {
                "output_format": "text",  # text, json, html
                "include_remediation": True,
                "include_evidence": True
            },
            "distributed": {
                "enabled": False,
                "workers": 1
            }
        }
        
        self.config = self.default_config.copy()
        
        # Load configuration from file if provided
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
    
    def load_config(self, config_file):
        """
        Load configuration from a JSON file
        
        Args:
            config_file (str): Path to configuration file
        """
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                # Update default config with user config
                self._update_nested_dict(self.config, user_config)
            logging.info(f"Configuration loaded from {config_file}")
        except Exception as e:
            logging.error(f"Error loading configuration: {e}")
    
    def save_config(self, config_file):
        """
        Save current configuration to a JSON file
        
        Args:
            config_file (str): Path to save configuration
        """
        try:
            with open(config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            logging.info(f"Configuration saved to {config_file}")
            return True
        except Exception as e:
            logging.error(f"Error saving configuration: {e}")
            return False
    
    def _update_nested_dict(self, d, u):
        """
        Update nested dictionary with another dictionary
        
        Args:
            d (dict): Dictionary to update
            u (dict): Dictionary with updates
        """
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                self._update_nested_dict(d[k], v)
            else:
                d[k] = v
    
    def get_profile(self, profile_name):
        """
        Get a specific scanning profile
        
        Args:
            profile_name (str): Name of the profile
            
        Returns:
            dict: Profile configuration or None if not found
        """
        profiles_dir = Path(__file__).parent / "profiles"
        profile_file = profiles_dir / f"{profile_name}.json"
        
        if profile_file.exists():
            try:
                with open(profile_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logging.error(f"Error loading profile {profile_name}: {e}")
        
        return None
    
    def save_profile(self, profile_name, profile_config):
        """
        Save a scanning profile
        
        Args:
            profile_name (str): Name of the profile
            profile_config (dict): Profile configuration
            
        Returns:
            bool: True if saved successfully, False otherwise
        """
        profiles_dir = Path(__file__).parent / "profiles"
        profiles_dir.mkdir(exist_ok=True)
        
        profile_file = profiles_dir / f"{profile_name}.json"
        
        try:
            with open(profile_file, 'w') as f:
                json.dump(profile_config, f, indent=4)
            logging.info(f"Profile {profile_name} saved")
            return True
        except Exception as e:
            logging.error(f"Error saving profile {profile_name}: {e}")
            return False
