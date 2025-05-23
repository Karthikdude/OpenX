#!/usr/bin/env python3
"""
Fake User Agent data module for OpenX
Contains user agent strings for browser emulation
"""
from typing import List, Dict, Optional, Union
import random
import json
import os
import logging
from datetime import datetime

logger = logging.getLogger('openx.useragent')

class UserAgentManager:
    """Manages user agent strings for HTTP requests"""
    
    def __init__(self, custom_ua_file: Optional[str] = None):
        """
        Initialize the user agent manager
        
        Args:
            custom_ua_file (Optional[str]): Path to custom user agent file
        """
        self.user_agents: Dict[str, List[str]] = {}
        self.load_default_user_agents()
        
        if custom_ua_file and os.path.exists(custom_ua_file):
            self.load_from_file(custom_ua_file)
            
        self.last_used: Dict[str, str] = {}
    
    def load_default_user_agents(self) -> None:
        """
        Load default user agents organized by browser type and device category
        """
        # Chrome Desktop User Agents
        self.user_agents['chrome_desktop'] = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.81 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.61 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36"
        ]
        
        # Chrome Mobile User Agents
        self.user_agents['chrome_mobile'] = [
            "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.61 Mobile Safari/537.36",
            "Mozilla/5.0 (Linux; Android 12; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.78 Mobile Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/100.0.4896.85 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/101.0.4951.58 Mobile/15E148 Safari/604.1"
        ]
        
        # Firefox Desktop User Agents
        self.user_agents['firefox_desktop'] = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:101.0) Gecko/20100101 Firefox/101.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:100.0) Gecko/20100101 Firefox/100.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:101.0) Gecko/20100101 Firefox/101.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:101.0) Gecko/20100101 Firefox/101.0"
        ]
        
        # Firefox Mobile User Agents
        self.user_agents['firefox_mobile'] = [
            "Mozilla/5.0 (Android 12; Mobile; rv:100.0) Gecko/100.0 Firefox/100.0",
            "Mozilla/5.0 (Android 12; Mobile; rv:101.0) Gecko/101.0 Firefox/101.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/100.0 Mobile/15E148 Safari/605.1.15"
        ]
        
        # Safari User Agents
        self.user_agents['safari'] = [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 15_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1"
        ]
        
        # Edge User Agents
        self.user_agents['edge'] = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 Edg/100.0.1185.50",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edg/101.0.1210.53",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36 Edg/102.0.1245.33",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 Edg/100.0.1185.50"
        ]
        
        # Opera User Agents
        self.user_agents['opera'] = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 OPR/86.0.4363.59",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 OPR/87.0.4390.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 OPR/86.0.4363.59",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 OPR/86.0.4363.59"
        ]
        
        # Bots and Crawlers
        self.user_agents['bots'] = [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
            "Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)"
        ]
        
        # WAF Evasion User Agents (less common or modified to bypass WAFs)
        self.user_agents['waf_evasion'] = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 Unique/1.0.0.0",
            "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",  # Old IE
            "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)",  # Very old IE
            "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",  # IE 11
            "Opera/9.80 (Windows NT 6.1; U; en) Presto/2.8.131 Version/11.11",  # Old Opera
            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.53 Safari/525.19"  # Very old Chrome
        ]
        
        # Create a combined list for easy random selection
        self.user_agents['all'] = []
        for category in self.user_agents:
            if category != 'all':
                self.user_agents['all'].extend(self.user_agents[category])
        
        logger.info(f"Loaded {len(self.user_agents['all'])} user agents in {len(self.user_agents) - 1} categories")
    
    def load_from_file(self, file_path: str) -> bool:
        """
        Load user agents from a file. The file can be a simple text file with one user agent per line,
        or a JSON file with categories.
        
        Args:
            file_path (str): Path to file containing user agents
            
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        try:
            file_ext = os.path.splitext(file_path)[1].lower()
            
            if file_ext == '.json':
                # Load from JSON file with categories
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                if isinstance(data, dict):
                    # Add to existing categories or create new ones
                    for category, agents in data.items():
                        if isinstance(agents, list) and agents:
                            if category in self.user_agents:
                                self.user_agents[category].extend(agents)
                            else:
                                self.user_agents[category] = agents
                    
                    # Update the 'all' category
                    self.user_agents['all'] = []
                    for category in self.user_agents:
                        if category != 'all':
                            self.user_agents['all'].extend(self.user_agents[category])
                    
                    logger.info(f"Loaded user agents from JSON file: {file_path}")
                    return True
                return False
            else:
                # Load from text file (one agent per line)
                with open(file_path, 'r') as f:
                    agents = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                if agents:
                    # Add to 'custom' category
                    if 'custom' in self.user_agents:
                        self.user_agents['custom'].extend(agents)
                    else:
                        self.user_agents['custom'] = agents
                    
                    # Update the 'all' category
                    self.user_agents['all'].extend(agents)
                    
                    logger.info(f"Loaded {len(agents)} user agents from text file: {file_path}")
                    return True
                return False
        except Exception as e:
            logger.error(f"Error loading user agents from file: {e}")
            return False
    
    def get_random(self) -> str:
        """
        Get a random user agent from all available user agents
        
        Returns:
            str: Random user agent string
        """
        if not self.user_agents.get('all'):
            return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36"
        return random.choice(self.user_agents['all'])
    
    def get_chrome(self, mobile: bool = False) -> str:
        """
        Get a Chrome user agent
        
        Args:
            mobile (bool): Whether to get a mobile user agent
            
        Returns:
            str: Chrome user agent string
        """
        category = 'chrome_mobile' if mobile else 'chrome_desktop'
        if category in self.user_agents and self.user_agents[category]:
            return random.choice(self.user_agents[category])
        return self.get_random()
    
    def get_firefox(self, mobile: bool = False) -> str:
        """
        Get a Firefox user agent
        
        Args:
            mobile (bool): Whether to get a mobile user agent
            
        Returns:
            str: Firefox user agent string
        """
        category = 'firefox_mobile' if mobile else 'firefox_desktop'
        if category in self.user_agents and self.user_agents[category]:
            return random.choice(self.user_agents[category])
        return self.get_random()
    
    def get_safari(self, mobile: bool = False) -> str:
        """
        Get a Safari user agent
        
        Args:
            mobile (bool): Whether to get a mobile user agent
            
        Returns:
            str: Safari user agent string
        """
        if 'safari' in self.user_agents and self.user_agents['safari']:
            if mobile:
                mobile_agents = [ua for ua in self.user_agents['safari'] if 'Mobile' in ua]
                if mobile_agents:
                    return random.choice(mobile_agents)
            else:
                desktop_agents = [ua for ua in self.user_agents['safari'] if 'Mobile' not in ua]
                if desktop_agents:
                    return random.choice(desktop_agents)
            return random.choice(self.user_agents['safari'])
        return self.get_random()
    
    def get_edge(self) -> str:
        """
        Get an Edge user agent
        
        Returns:
            str: Edge user agent string
        """
        if 'edge' in self.user_agents and self.user_agents['edge']:
            return random.choice(self.user_agents['edge'])
        return self.get_random()
    
    def get_opera(self) -> str:
        """
        Get an Opera user agent
        
        Returns:
            str: Opera user agent string
        """
        if 'opera' in self.user_agents and self.user_agents['opera']:
            return random.choice(self.user_agents['opera'])
        return self.get_random()
    
    def get_bot(self) -> str:
        """
        Get a bot user agent
        
        Returns:
            str: Bot user agent string
        """
        if 'bots' in self.user_agents and self.user_agents['bots']:
            return random.choice(self.user_agents['bots'])
        return self.get_random()
    
    def get_waf_evasion(self) -> str:
        """
        Get a user agent designed for WAF evasion
        
        Returns:
            str: WAF evasion user agent string
        """
        if 'waf_evasion' in self.user_agents and self.user_agents['waf_evasion']:
            return random.choice(self.user_agents['waf_evasion'])
        return self.get_random()
    
    def get_by_category(self, category: str) -> str:
        """
        Get a user agent from a specific category
        
        Args:
            category (str): Category name
            
        Returns:
            str: User agent string from the specified category
        """
        if category in self.user_agents and self.user_agents[category]:
            return random.choice(self.user_agents[category])
        return self.get_random()
    
    def get_random_with_rotation(self, last_key: str = None) -> str:
        """
        Get a random user agent with rotation to avoid using the same one twice in a row
        
        Args:
            last_key (str): Key to identify the last context where a user agent was used
            
        Returns:
            str: Random user agent string
        """
        if not last_key:
            last_key = 'default'
            
        if last_key in self.last_used:
            # Get a different user agent than the last one used for this key
            last_ua = self.last_used[last_key]
            all_agents = self.user_agents.get('all', [])
            if len(all_agents) > 1:
                while True:
                    ua = random.choice(all_agents)
                    if ua != last_ua:
                        self.last_used[last_key] = ua
                        return ua
            
        # If no last user agent or only one available, just get a random one
        ua = self.get_random()
        self.last_used[last_key] = ua
        return ua
    
    def export_to_file(self, file_path: str, format: str = 'json') -> bool:
        """
        Export user agents to a file
        
        Args:
            file_path (str): Path to save the user agents
            format (str): Format to save in ('json' or 'txt')
            
        Returns:
            bool: True if exported successfully, False otherwise
        """
        try:
            if format.lower() == 'json':
                with open(file_path, 'w') as f:
                    json.dump(self.user_agents, f, indent=2)
            else:
                with open(file_path, 'w') as f:
                    f.write(f"# OpenX User Agents - Exported on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Total: {len(self.user_agents.get('all', []))}\n\n")
                    
                    for ua in self.user_agents.get('all', []):
                        f.write(f"{ua}\n")
            
            logger.info(f"Exported user agents to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error exporting user agents: {e}")
            return False
