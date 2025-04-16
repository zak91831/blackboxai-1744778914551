"""
Header Manipulation Module

This module handles HTTP header manipulation for cache-based XSS testing,
focusing on cache-control headers and cache-related behavior.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
import time
import random
import string
from collections import defaultdict

class HeaderManipulator:
    """
    A class to manipulate HTTP headers for cache-based testing.
    """
    
    def __init__(self, config):
        """
        Initialize the Header Manipulator.
        
        Args:
            config (dict): Configuration settings for header manipulation.
        """
        self.logger = logging.getLogger('cachexssdetector.header_manipulator')
        self.config = config
        
        # Configuration
        self.max_header_length = config.get('max_header_length', 4096)
        self.enable_custom_headers = config.get('enable_custom_headers', True)
        self.enable_cache_headers = config.get('enable_cache_headers', True)
        
        # Initialize header templates
        self._init_templates()
        
        self.logger.info("Header Manipulator initialized")
    
    def _init_templates(self):
        """Initialize header manipulation templates."""
        # Cache control headers
        self.cache_headers = {
            'control': {
                'Cache-Control': [
                    'no-cache',
                    'no-store',
                    'max-age=0',
                    'max-age=3600',
                    'public',
                    'private',
                    'must-revalidate'
                ],
                'Pragma': ['no-cache'],
                'Expires': ['-1', '0', 'Thu, 01 Jan 1970 00:00:00 GMT']
            },
            'validation': {
                'If-None-Match': ['*', 'W/"random"'],
                'If-Modified-Since': ['Thu, 01 Jan 1970 00:00:00 GMT']
            },
            'vary': {
                'Vary': ['*', 'Accept-Encoding', 'User-Agent', 'Cookie']
            }
        }
        
        # Custom headers
        self.custom_headers = {
            'client': {
                'X-Forwarded-For': ['127.0.0.1', '192.168.1.1'],
                'X-Real-IP': ['127.0.0.1', '192.168.1.1'],
                'X-Client-IP': ['127.0.0.1', '192.168.1.1']
            },
            'cache': {
                'X-Cache-Control': ['bypass', 'force-cache'],
                'X-Cache-Tags': ['test', 'xss'],
                'X-Cache-Vary': ['custom']
            },
            'security': {
                'X-XSS-Protection': ['0', '1', '1; mode=block'],
                'X-Content-Type-Options': ['nosniff'],
                'X-Frame-Options': ['DENY', 'SAMEORIGIN']
            }
        }
    
    def modify_headers(
        self,
        headers: Dict[str, str],
        modifications: Optional[Dict] = None
    ) -> Dict[str, str]:
        """
        Modify HTTP headers based on specified modifications.
        
        Args:
            headers (dict): Original headers.
            modifications (dict, optional): Specific modifications to apply.
            
        Returns:
            dict: Modified headers.
        """
        modified = headers.copy()
        
        try:
            # Apply specific modifications if provided
            if modifications:
                for header, value in modifications.items():
                    if self._validate_header(header, value):
                        modified[header] = value
            
            # Apply custom headers if enabled
            if self.enable_custom_headers:
                custom_headers = self._generate_custom_headers()
                modified.update(custom_headers)
            
            # Apply cache headers if enabled
            if self.enable_cache_headers:
                cache_headers = self._generate_cache_headers()
                modified.update(cache_headers)
            
        except Exception as e:
            self.logger.error(f"Error modifying headers: {str(e)}")
        
        return modified
    
    def generate_header_variations(
        self,
        base_headers: Dict[str, str],
        context: Optional[Dict] = None
    ) -> List[Dict[str, str]]:
        """
        Generate variations of headers for testing.
        
        Args:
            base_headers (dict): Base headers to vary.
            context (dict, optional): Context for variation generation.
            
        Returns:
            list: Header variations.
        """
        variations = []
        
        try:
            # Add base headers
            variations.append(base_headers)
            
            # Generate cache control variations
            cache_variations = self._generate_cache_variations(base_headers)
            variations.extend(cache_variations)
            
            # Generate custom header variations
            if self.enable_custom_headers:
                custom_variations = self._generate_custom_variations(base_headers)
                variations.extend(custom_variations)
            
            # Generate combination variations
            combined_variations = self._generate_combined_variations(
                cache_variations,
                custom_variations if self.enable_custom_headers else []
            )
            variations.extend(combined_variations)
            
        except Exception as e:
            self.logger.error(f"Error generating header variations: {str(e)}")
        
        return variations
    
    def generate_cache_headers(
        self,
        cache_policy: str = 'default'
    ) -> Dict[str, str]:
        """
        Generate cache-specific headers.
        
        Args:
            cache_policy (str): Cache policy to apply.
            
        Returns:
            dict: Generated cache headers.
        """
        headers = {}
        
        try:
            if cache_policy == 'no-cache':
                headers.update({
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                })
            elif cache_policy == 'force-cache':
                headers.update({
                    'Cache-Control': 'public, max-age=31536000',
                    'Expires': self._generate_future_date(365)  # 1 year
                })
            elif cache_policy == 'validate':
                headers.update({
                    'Cache-Control': 'no-cache',
                    'If-None-Match': f'W/"{self._generate_etag()}"',
                    'If-Modified-Since': self._generate_past_date(1)  # 1 day ago
                })
            else:  # default
                headers.update({
                    'Cache-Control': 'public, max-age=3600',
                    'Expires': self._generate_future_date(1)  # 1 day
                })
            
        except Exception as e:
            self.logger.error(f"Error generating cache headers: {str(e)}")
        
        return headers
    
    def _generate_custom_headers(self) -> Dict[str, str]:
        """Generate custom headers for testing."""
        headers = {}
        
        try:
            # Add random client headers
            for header, values in self.custom_headers['client'].items():
                headers[header] = random.choice(values)
            
            # Add cache-related custom headers
            for header, values in self.custom_headers['cache'].items():
                headers[header] = random.choice(values)
            
            # Add security headers
            for header, values in self.custom_headers['security'].items():
                headers[header] = random.choice(values)
            
        except Exception as e:
            self.logger.error(f"Error generating custom headers: {str(e)}")
        
        return headers
    
    def _generate_cache_headers(self) -> Dict[str, str]:
        """Generate cache-control headers."""
        headers = {}
        
        try:
            # Add random cache control directive
            headers['Cache-Control'] = random.choice(
                self.cache_headers['control']['Cache-Control']
            )
            
            # Add validation headers
            if random.random() < 0.5:
                for header, values in self.cache_headers['validation'].items():
                    headers[header] = random.choice(values)
            
            # Add vary header
            if random.random() < 0.3:
                headers['Vary'] = random.choice(
                    self.cache_headers['vary']['Vary']
                )
            
        except Exception as e:
            self.logger.error(f"Error generating cache headers: {str(e)}")
        
        return headers
    
    def _generate_cache_variations(
        self,
        base_headers: Dict[str, str]
    ) -> List[Dict[str, str]]:
        """Generate cache header variations."""
        variations = []
        
        try:
            # Generate variations for each cache control directive
            for directive in self.cache_headers['control']['Cache-Control']:
                variation = base_headers.copy()
                variation['Cache-Control'] = directive
                variations.append(variation)
            
            # Generate variations with validation headers
            for etag in ['*', f'W/"{self._generate_etag()}"']:
                variation = base_headers.copy()
                variation['If-None-Match'] = etag
                variations.append(variation)
            
            # Generate variations with vary headers
            for vary in self.cache_headers['vary']['Vary']:
                variation = base_headers.copy()
                variation['Vary'] = vary
                variations.append(variation)
            
        except Exception as e:
            self.logger.error(f"Error generating cache variations: {str(e)}")
        
        return variations
    
    def _generate_custom_variations(
        self,
        base_headers: Dict[str, str]
    ) -> List[Dict[str, str]]:
        """Generate custom header variations."""
        variations = []
        
        try:
            # Generate variations for client headers
            for header, values in self.custom_headers['client'].items():
                for value in values:
                    variation = base_headers.copy()
                    variation[header] = value
                    variations.append(variation)
            
            # Generate variations for cache custom headers
            for header, values in self.custom_headers['cache'].items():
                for value in values:
                    variation = base_headers.copy()
                    variation[header] = value
                    variations.append(variation)
            
        except Exception as e:
            self.logger.error(f"Error generating custom variations: {str(e)}")
        
        return variations
    
    def _generate_combined_variations(
        self,
        cache_variations: List[Dict[str, str]],
        custom_variations: List[Dict[str, str]]
    ) -> List[Dict[str, str]]:
        """Generate combinations of variations."""
        combined = []
        
        try:
            # Combine cache and custom variations
            for cache_var in cache_variations:
                for custom_var in custom_variations:
                    variation = cache_var.copy()
                    variation.update(custom_var)
                    combined.append(variation)
            
        except Exception as e:
            self.logger.error(f"Error generating combined variations: {str(e)}")
        
        return combined
    
    def _validate_header(self, header: str, value: str) -> bool:
        """
        Validate header name and value.
        
        Args:
            header (str): Header name.
            value (str): Header value.
            
        Returns:
            bool: True if header is valid.
        """
        try:
            # Check header name format
            if not re.match(r'^[A-Za-z0-9-]+$', header):
                return False
            
            # Check value length
            if len(value) > self.max_header_length:
                return False
            
            # Check for invalid characters
            if re.search(r'[\x00-\x1F\x7F]', value):
                return False
            
            return True
            
        except Exception:
            return False
    
    def _generate_etag(self, length: int = 16) -> str:
        """Generate random ETag value."""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _generate_future_date(self, days: int) -> str:
        """Generate future date string."""
        future = time.time() + (days * 86400)
        return time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(future))
    
    def _generate_past_date(self, days: int) -> str:
        """Generate past date string."""
        past = time.time() - (days * 86400)
        return time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(past))
