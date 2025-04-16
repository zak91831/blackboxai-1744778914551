"""
Proxy Integration Module

This module handles proxy server integration, allowing HTTP requests to be routed
through various proxy servers for enhanced anonymity and testing capabilities.
"""

import logging
import random
import time
import socket
from urllib.parse import urlparse
import requests

class ProxyIntegration:
    """
    A class to manage proxy servers for HTTP requests.
    
    Features:
    - Support for HTTP, HTTPS, and SOCKS proxies
    - Proxy rotation
    - Health checks
    - Failover mechanisms
    - Authentication support
    """
    
    def __init__(self, config):
        """
        Initialize the Proxy Integration.
        
        Args:
            config (dict): Configuration settings for proxy integration.
        """
        self.logger = logging.getLogger('cachexssdetector.proxy_integration')
        self.config = config.get('proxy', {})
        
        # Initialize proxy list
        self.proxies = []
        self._load_proxies()
        
        # Current proxy index
        self.current_index = 0
        
        # Proxy health status
        self.health_status = {}
        
        # Rotation strategy
        self.rotation_strategy = self.config.get('rotation_strategy', 'round_robin')
        
        self.logger.info("Proxy Integration initialized")
        
        # Perform initial health check
        if self.config.get('health_check_on_start', False):
            self.check_proxy_health()
    
    def _load_proxies(self):
        """
        Load proxy configurations from the config.
        """
        # Load single proxy if enabled
        if self.config.get('enabled', False):
            proxy_url = self.config.get('url', '')
            if proxy_url:
                # Parse authentication if available
                auth_config = self.config.get('auth', {})
                username = auth_config.get('username', '')
                password = auth_config.get('password', '')
                
                # Add authentication to proxy URL if provided
                if username and password:
                    parsed_url = urlparse(proxy_url)
                    auth_url = f"{parsed_url.scheme}://{username}:{password}@{parsed_url.netloc}{parsed_url.path}"
                    proxy_url = auth_url
                
                self.proxies.append({
                    'url': proxy_url,
                    'type': self._determine_proxy_type(proxy_url),
                    'enabled': True
                })
                
                self.logger.info(f"Loaded proxy: {proxy_url}")
        
        # Load multiple proxies if defined
        proxy_list = self.config.get('proxy_list', [])
        for proxy in proxy_list:
            if isinstance(proxy, str):
                # Simple string format
                self.proxies.append({
                    'url': proxy,
                    'type': self._determine_proxy_type(proxy),
                    'enabled': True
                })
            elif isinstance(proxy, dict):
                # Dictionary format with additional settings
                proxy_url = proxy.get('url', '')
                if proxy_url:
                    self.proxies.append({
                        'url': proxy_url,
                        'type': proxy.get('type', self._determine_proxy_type(proxy_url)),
                        'enabled': proxy.get('enabled', True),
                        'priority': proxy.get('priority', 0),
                        'country': proxy.get('country', ''),
                        'tags': proxy.get('tags', [])
                    })
        
        # Sort proxies by priority if available
        self.proxies.sort(key=lambda x: x.get('priority', 0), reverse=True)
        
        self.logger.info(f"Loaded {len(self.proxies)} proxies")
    
    def _determine_proxy_type(self, proxy_url):
        """
        Determine the type of proxy from its URL.
        
        Args:
            proxy_url (str): The proxy URL.
            
        Returns:
            str: The proxy type (http, https, socks4, socks5).
        """
        if not proxy_url:
            return None
            
        parsed = urlparse(proxy_url)
        scheme = parsed.scheme.lower()
        
        if scheme == 'http':
            return 'http'
        elif scheme == 'https':
            return 'https'
        elif scheme == 'socks4':
            return 'socks4'
        elif scheme == 'socks5':
            return 'socks5'
        else:
            self.logger.warning(f"Unknown proxy type: {scheme}, assuming http")
            return 'http'
    
    def get_proxy(self, rotate=False):
        """
        Get the current proxy configuration.
        
        Args:
            rotate (bool): Whether to rotate to the next proxy.
            
        Returns:
            dict: A dictionary containing proxy settings, or None if no proxy is available.
        """
        if not self.proxies:
            return None
            
        if rotate:
            self.rotate_proxy()
            
        # Find the first enabled proxy
        for i in range(len(self.proxies)):
            index = (self.current_index + i) % len(self.proxies)
            proxy = self.proxies[index]
            
            if proxy.get('enabled', True):
                self.current_index = index
                return self._format_proxy(proxy)
        
        self.logger.warning("No enabled proxies available")
        return None
    
    def _format_proxy(self, proxy):
        """
        Format a proxy configuration for use with requests.
        
        Args:
            proxy (dict): The proxy configuration.
            
        Returns:
            dict: Formatted proxy configuration for the requests library.
        """
        proxy_url = proxy.get('url', '')
        proxy_type = proxy.get('type', 'http')
        
        if not proxy_url:
            return None
            
        # Format for requests library
        if proxy_type in ['http', 'https']:
            return {
                'http': proxy_url if proxy_type == 'http' else None,
                'https': proxy_url if proxy_type == 'https' else None
            }
        elif proxy_type in ['socks4', 'socks5']:
            # For SOCKS proxies, both HTTP and HTTPS use the same proxy
            return {
                'http': proxy_url,
                'https': proxy_url
            }
        else:
            return None
    
    def rotate_proxy(self):
        """
        Rotate to the next available proxy according to the strategy.
        
        Returns:
            dict: The new proxy configuration, or None if no proxy is available.
        """
        if not self.proxies:
            return None
            
        if self.rotation_strategy == 'round_robin':
            # Simple round-robin rotation
            self.current_index = (self.current_index + 1) % len(self.proxies)
        elif self.rotation_strategy == 'random':
            # Random selection
            self.current_index = random.randint(0, len(self.proxies) - 1)
        elif self.rotation_strategy == 'health_based':
            # Select the healthiest proxy
            healthiest_index = self._find_healthiest_proxy()
            if healthiest_index is not None:
                self.current_index = healthiest_index
                
        # Ensure the selected proxy is enabled
        attempts = 0
        while attempts < len(self.proxies) and not self.proxies[self.current_index].get('enabled', True):
            self.current_index = (self.current_index + 1) % len(self.proxies)
            attempts += 1
            
        if attempts >= len(self.proxies):
            self.logger.warning("No enabled proxies found")
            return None
            
        proxy = self.proxies[self.current_index]
        self.logger.debug(f"Rotated to proxy: {proxy['url']}")
        
        return self._format_proxy(proxy)
    
    def check_proxy_health(self, test_url=None):
        """
        Check the health of all proxies.
        
        Args:
            test_url (str, optional): URL to use for health checks.
            
        Returns:
            dict: A dictionary mapping proxy URLs to their health status.
        """
        if not self.proxies:
            return {}
            
        # Use default test URL if none provided
        if not test_url:
            test_url = self.config.get('health_check_url', 'https://www.example.com')
            
        timeout = self.config.get('health_check_timeout', 10)
        
        self.logger.info(f"Checking health of {len(self.proxies)} proxies")
        
        for i, proxy in enumerate(self.proxies):
            proxy_url = proxy.get('url', '')
            if not proxy_url:
                continue
                
            proxy_formatted = self._format_proxy(proxy)
            
            try:
                start_time = time.time()
                response = requests.get(test_url, proxies=proxy_formatted, timeout=timeout)
                elapsed = time.time() - start_time
                
                # Check if response is successful
                if response.status_code < 400:
                    status = {
                        'status': 'healthy',
                        'latency': elapsed,
                        'last_check': time.time(),
                        'status_code': response.status_code
                    }
                else:
                    status = {
                        'status': 'unhealthy',
                        'latency': elapsed,
                        'last_check': time.time(),
                        'status_code': response.status_code,
                        'reason': f"HTTP error: {response.status_code}"
                    }
            except (requests.exceptions.RequestException, socket.error) as e:
                status = {
                    'status': 'unhealthy',
                    'last_check': time.time(),
                    'reason': str(e)
                }
                proxy['enabled'] = self.config.get('disable_unhealthy_proxies', True)
                
            self.health_status[proxy_url] = status
            
            self.logger.debug(f"Proxy {proxy_url} health: {status['status']}")
            
        return self.health_status
    
    def _find_healthiest_proxy(self):
        """
        Find the index of the healthiest proxy based on latency and status.
        
        Returns:
            int or None: The index of the healthiest proxy, or None if no healthy proxy exists.
        """
        best_index = None
        best_latency = float('inf')
        
        for i, proxy in enumerate(self.proxies):
            proxy_url = proxy.get('url', '')
            if not proxy_url or not proxy.get('enabled', True):
                continue
                
            health = self.health_status.get(proxy_url, {})
            if health.get('status') == 'healthy':
                latency = health.get('latency', float('inf'))
                if latency < best_latency:
                    best_latency = latency
                    best_index = i
                    
        return best_index
    
    def disable_proxy(self, index=None):
        """
        Disable a proxy by index.
        
        Args:
            index (int, optional): The index of the proxy to disable, or current if None.
        """
        if not self.proxies:
            return
            
        if index is None:
            index = self.current_index
            
        if 0 <= index < len(self.proxies):
            proxy = self.proxies[index]
            proxy['enabled'] = False
            self.logger.info(f"Disabled proxy: {proxy.get('url', '')}")
            
            # Rotate to next proxy
            self.rotate_proxy()
    
    def enable_proxy(self, index):
        """
        Enable a previously disabled proxy.
        
        Args:
            index (int): The index of the proxy to enable.
        """
        if not self.proxies or not (0 <= index < len(self.proxies)):
            return
            
        proxy = self.proxies[index]
        proxy['enabled'] = True
        self.logger.info(f"Enabled proxy: {proxy.get('url', '')}")
    
    def enable_all_proxies(self):
        """
        Enable all proxies.
        """
        for proxy in self.proxies:
            proxy['enabled'] = True
            
        self.logger.info("Enabled all proxies")
    
    def add_proxy(self, proxy_url, proxy_type=None, enabled=True, priority=0):
        """
        Add a new proxy to the list.
        
        Args:
            proxy_url (str): The proxy URL.
            proxy_type (str, optional): The proxy type, or auto-detect if None.
            enabled (bool, optional): Whether the proxy is enabled.
            priority (int, optional): Priority level for this proxy.
            
        Returns:
            int: The index of the newly added proxy.
        """
        if not proxy_url:
            return -1
            
        # Determine proxy type if not provided
        if proxy_type is None:
            proxy_type = self._determine_proxy_type(proxy_url)
            
        # Add to the list
        self.proxies.append({
            'url': proxy_url,
            'type': proxy_type,
            'enabled': enabled,
            'priority': priority
        })
        
        # Sort by priority
        self.proxies.sort(key=lambda x: x.get('priority', 0), reverse=True)
        
        # Find the index of the newly added proxy
        for i, proxy in enumerate(self.proxies):
            if proxy['url'] == proxy_url:
                self.logger.info(f"Added proxy: {proxy_url}")
                return i
                
        return -1
    
    def remove_proxy(self, index):
        """
        Remove a proxy from the list.
        
        Args:
            index (int): The index of the proxy to remove.
            
        Returns:
            bool: True if successful, False otherwise.
        """
        if not self.proxies or not (0 <= index < len(self.proxies)):
            return False
            
        proxy = self.proxies.pop(index)
        self.logger.info(f"Removed proxy: {proxy.get('url', '')}")
        
        # Adjust current index if needed
        if self.current_index >= len(self.proxies) and self.proxies:
            self.current_index = 0
            
        return True
    
    def get_proxies_info(self):
        """
        Get information about all configured proxies.
        
        Returns:
            list: List of proxy information dictionaries.
        """
        info = []
        
        for i, proxy in enumerate(self.proxies):
            proxy_url = proxy.get('url', '')
            proxy_info = {
                'index': i,
                'url': proxy_url,
                'type': proxy.get('type', 'unknown'),
                'enabled': proxy.get('enabled', True),
                'priority': proxy.get('priority', 0),
                'current': (i == self.current_index),
                'health': self.health_status.get(proxy_url, {'status': 'unknown'})
            }
            
            info.append(proxy_info)
            
        return info
    
    def apply_proxy_to_client(self, http_client):
        """
        Apply the current proxy configuration to an HTTP client.
        
        Args:
            http_client: The HTTP client to configure.
            
        Returns:
            bool: True if successful, False if no proxy available.
        """
        proxy = self.get_proxy()
        if not proxy:
            return False
            
        http_client.session.proxies.update(proxy)
        self.logger.debug(f"Applied proxy to HTTP client: {list(proxy.values())[0]}")
        
        return True
