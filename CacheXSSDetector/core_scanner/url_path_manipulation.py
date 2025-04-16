"""
URL Path Manipulation Module

This module handles URL path manipulation for testing cache-based XSS vulnerabilities,
including path traversal, parameter manipulation, and cache key variations.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re
import random
import string
import itertools

class URLPathManipulator:
    """
    A class to manipulate URL paths for cache-based XSS testing.
    """
    
    def __init__(self, config):
        """
        Initialize the URL Path Manipulator.
        
        Args:
            config (dict): Configuration settings for URL manipulation.
        """
        self.logger = logging.getLogger('cachexssdetector.url_path_manipulator')
        self.config = config
        
        # Configuration
        self.max_path_depth = config.get('max_path_depth', 5)
        self.max_params = config.get('max_params', 10)
        self.max_variations = config.get('max_variations', 100)
        
        # Initialize manipulation patterns
        self._init_patterns()
        
        self.logger.info("URL Path Manipulator initialized")
    
    def _init_patterns(self):
        """Initialize URL manipulation patterns."""
        # Path traversal patterns
        self.path_patterns = {
            'directory_traversal': ['../', './'],
            'path_normalization': ['/./', '/../', '/.//', '//'],
            'encoding_variations': ['%2e%2e%2f', '%2e%2f', '%2f'],
            'case_variations': ['/PATH/', '/path/', '/Path/']
        }
        
        # Parameter manipulation patterns
        self.param_patterns = {
            'common_params': ['id', 'page', 'file', 'path', 'url', 'action'],
            'cache_params': ['cache', 'nocache', 'refresh', 'version'],
            'special_chars': ['<', '>', '"', "'", ';', '|', '&'],
            'encodings': ['utf-8', 'utf-16', 'ascii']
        }
        
        # Cache buster patterns
        self.cache_buster_patterns = {
            'timestamp': lambda: str(int(time.time())),
            'random': lambda: ''.join(random.choices(string.ascii_letters + string.digits, k=8)),
            'counter': lambda: str(next(self.counter)),
            'guid': lambda: str(uuid.uuid4())
        }
        
        # Initialize counter for cache busting
        self.counter = itertools.count()
    
    def generate_path_variations(self, url: str) -> List[str]:
        """
        Generate variations of the URL path.
        
        Args:
            url (str): Original URL.
            
        Returns:
            list: List of URL variations.
        """
        variations = []
        parsed = urlparse(url)
        
        try:
            # Generate path variations
            path_variations = self._generate_path_variations(parsed.path)
            
            # Generate query variations
            query_variations = self._generate_query_variations(parsed.query)
            
            # Combine variations
            for path in path_variations:
                for query in query_variations:
                    new_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        path,
                        parsed.params,
                        query,
                        parsed.fragment
                    ))
                    variations.append(new_url)
            
            # Limit number of variations
            variations = variations[:self.max_variations]
            
        except Exception as e:
            self.logger.error(f"Error generating URL variations: {str(e)}")
        
        return variations
    
    def generate_cache_variations(self, url: str) -> List[str]:
        """
        Generate URL variations specifically for cache testing.
        
        Args:
            url (str): Original URL.
            
        Returns:
            list: List of cache-focused URL variations.
        """
        variations = []
        parsed = urlparse(url)
        
        try:
            # Generate cache buster variations
            cache_variations = self._generate_cache_variations(parsed)
            variations.extend(cache_variations)
            
            # Generate cache key variations
            key_variations = self._generate_cache_key_variations(parsed)
            variations.extend(key_variations)
            
            # Limit number of variations
            variations = variations[:self.max_variations]
            
        except Exception as e:
            self.logger.error(f"Error generating cache variations: {str(e)}")
        
        return variations
    
    def _generate_path_variations(self, path: str) -> List[str]:
        """
        Generate variations of the URL path component.
        
        Args:
            path (str): Original path.
            
        Returns:
            list: Path variations.
        """
        variations = set([path])
        path_parts = path.split('/')
        
        # Generate directory traversal variations
        for i in range(len(path_parts)):
            for pattern in self.path_patterns['directory_traversal']:
                new_path = '/'.join(path_parts[:i] + [pattern] + path_parts[i:])
                variations.add(new_path)
        
        # Generate path normalization variations
        for pattern in self.path_patterns['path_normalization']:
            variations.add(path.replace('/', pattern))
        
        # Generate encoding variations
        for pattern in self.path_patterns['encoding_variations']:
            variations.add(path.replace('/', pattern))
        
        # Generate case variations
        for part in path_parts:
            if part:
                for pattern in self.path_patterns['case_variations']:
                    variations.add(path.replace(f'/{part}/', pattern))
        
        return list(variations)
    
    def _generate_query_variations(self, query: str) -> List[str]:
        """
        Generate variations of the URL query component.
        
        Args:
            query (str): Original query string.
            
        Returns:
            list: Query variations.
        """
        variations = set([query])
        params = parse_qs(query, keep_blank_values=True)
        
        # Generate parameter variations
        for param in params:
            # Add common parameter variations
            for common_param in self.param_patterns['common_params']:
                new_params = params.copy()
                new_params[common_param] = params[param]
                variations.add(urlencode(new_params, doseq=True))
            
            # Add cache parameter variations
            for cache_param in self.param_patterns['cache_params']:
                new_params = params.copy()
                new_params[cache_param] = ['1']
                variations.add(urlencode(new_params, doseq=True))
            
            # Add special character variations
            for char in self.param_patterns['special_chars']:
                new_params = params.copy()
                new_params[param] = [f"{params[param][0]}{char}"]
                variations.add(urlencode(new_params, doseq=True))
        
        return list(variations)
    
    def _generate_cache_variations(self, parsed_url: urlparse) -> List[str]:
        """
        Generate cache-specific URL variations.
        
        Args:
            parsed_url: Parsed URL object.
            
        Returns:
            list: Cache-focused URL variations.
        """
        variations = []
        params = parse_qs(parsed_url.query, keep_blank_values=True)
        
        # Add cache buster parameters
        for buster_type, buster_func in self.cache_buster_patterns.items():
            new_params = params.copy()
            new_params[f'_cb_{buster_type}'] = [buster_func()]
            query = urlencode(new_params, doseq=True)
            
            variations.append(urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                query,
                parsed_url.fragment
            )))
        
        # Add cache control parameters
        cache_controls = ['no-cache', 'no-store', 'must-revalidate']
        for control in cache_controls:
            new_params = params.copy()
            new_params['cache_control'] = [control]
            query = urlencode(new_params, doseq=True)
            
            variations.append(urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                query,
                parsed_url.fragment
            )))
        
        return variations
    
    def _generate_cache_key_variations(self, parsed_url: urlparse) -> List[str]:
        """
        Generate variations that might affect cache keys.
        
        Args:
            parsed_url: Parsed URL object.
            
        Returns:
            list: Cache key variations.
        """
        variations = []
        params = parse_qs(parsed_url.query, keep_blank_values=True)
        
        # Vary parameter order
        param_items = list(params.items())
        for _ in range(min(len(param_items), 5)):  # Limit permutations
            random.shuffle(param_items)
            new_params = dict(param_items)
            query = urlencode(new_params, doseq=True)
            
            variations.append(urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                query,
                parsed_url.fragment
            )))
        
        # Add/modify cache-related parameters
        cache_params = {
            'v': ['1', '2', 'latest'],
            'version': ['1.0', '2.0'],
            'rev': ['a', 'b', 'c']
        }
        
        for param, values in cache_params.items():
            for value in values:
                new_params = params.copy()
                new_params[param] = [value]
                query = urlencode(new_params, doseq=True)
                
                variations.append(urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    query,
                    parsed_url.fragment
                )))
        
        return variations
    
    def normalize_url(self, url: str) -> str:
        """
        Normalize a URL for consistent comparison.
        
        Args:
            url (str): URL to normalize.
            
        Returns:
            str: Normalized URL.
        """
        try:
            parsed = urlparse(url)
            
            # Normalize scheme
            scheme = parsed.scheme.lower()
            
            # Normalize netloc
            netloc = parsed.netloc.lower()
            
            # Normalize path
            path = self._normalize_path(parsed.path)
            
            # Normalize query parameters
            query = self._normalize_query(parsed.query)
            
            # Reconstruct URL
            normalized = urlunparse((
                scheme,
                netloc,
                path,
                '',  # params
                query,
                ''   # fragment
            ))
            
            return normalized
            
        except Exception as e:
            self.logger.error(f"Error normalizing URL: {str(e)}")
            return url
    
    def _normalize_path(self, path: str) -> str:
        """
        Normalize URL path component.
        
        Args:
            path (str): Path to normalize.
            
        Returns:
            str: Normalized path.
        """
        # Remove duplicate slashes
        path = re.sub(r'/+', '/', path)
        
        # Remove trailing slash
        path = path.rstrip('/')
        
        # Resolve directory traversal
        parts = []
        for part in path.split('/'):
            if part in ('', '.'):
                continue
            if part == '..':
                if parts:
                    parts.pop()
            else:
                parts.append(part)
        
        # Reconstruct path
        normalized = '/' + '/'.join(parts)
        return normalized if normalized != '//' else '/'
    
    def _normalize_query(self, query: str) -> str:
        """
        Normalize URL query component.
        
        Args:
            query (str): Query string to normalize.
            
        Returns:
            str: Normalized query string.
        """
        # Parse query parameters
        params = parse_qs(query, keep_blank_values=True)
        
        # Sort parameters and values
        normalized_params = {}
        for key in sorted(params.keys()):
            normalized_params[key] = sorted(params[key])
        
        # Reconstruct query string
        return urlencode(normalized_params, doseq=True)
    
    def is_same_resource(self, url1: str, url2: str) -> bool:
        """
        Check if two URLs point to the same resource.
        
        Args:
            url1 (str): First URL.
            url2 (str): Second URL.
            
        Returns:
            bool: True if URLs point to same resource.
        """
        try:
            # Normalize both URLs
            norm1 = self.normalize_url(url1)
            norm2 = self.normalize_url(url2)
            
            # Compare normalized URLs
            return norm1 == norm2
            
        except Exception as e:
            self.logger.error(f"Error comparing URLs: {str(e)}")
            return False
    
    def extract_path_components(self, url: str) -> Dict:
        """
        Extract and analyze path components from URL.
        
        Args:
            url (str): URL to analyze.
            
        Returns:
            dict: Path component analysis.
        """
        analysis = {
            'directories': [],
            'filename': None,
            'extension': None,
            'parameters': {},
            'depth': 0
        }
        
        try:
            parsed = urlparse(url)
            
            # Analyze path components
            path_parts = parsed.path.strip('/').split('/')
            analysis['depth'] = len(path_parts)
            
            # Extract directories and file
            if path_parts:
                if '.' in path_parts[-1]:
                    analysis['filename'] = path_parts[-1]
                    analysis['extension'] = path_parts[-1].split('.')[-1]
                    analysis['directories'] = path_parts[:-1]
                else:
                    analysis['directories'] = path_parts
            
            # Analyze query parameters
            analysis['parameters'] = parse_qs(parsed.query)
            
        except Exception as e:
            self.logger.error(f"Error analyzing URL components: {str(e)}")
        
        return analysis
