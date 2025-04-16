"""
HTTP Client Module

This module handles HTTP requests with support for various methods, headers,
and proxy configurations, specifically designed for cache-based XSS testing.
"""

import logging
from typing import Dict, List, Optional, Union, Tuple
import requests
from requests.exceptions import RequestException
import urllib3
from urllib.parse import urlparse, urljoin
import time
import random
import json
import ssl

class HTTPClient:
    """
    A class to handle HTTP requests for cache-based XSS testing.
    """
    
    def __init__(self, config):
        """
        Initialize the HTTP Client.
        
        Args:
            config (dict): Configuration settings for HTTP requests.
        """
        self.logger = logging.getLogger('cachexssdetector.http_client')
        self.config = config
        
        # Request configuration
        self.timeout = config.get('request_timeout', 30)
        self.max_retries = config.get('max_retries', 3)
        self.retry_delay = config.get('retry_delay', 1)
        self.verify_ssl = config.get('verify_ssl', True)
        self.follow_redirects = config.get('follow_redirects', True)
        
        # Session configuration
        self.session = requests.Session()
        self.session.verify = self.verify_ssl
        
        # Configure retry mechanism
        retry_config = urllib3.Retry(
            total=self.max_retries,
            backoff_factor=self.retry_delay,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_config)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Default headers
        self.default_headers = {
            'User-Agent': config.get('user_agent', 'CacheXSSDetector/1.0'),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        }
        
        self.logger.info("HTTP Client initialized")
    
    def send_request(
        self,
        url: str,
        method: str = 'GET',
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None,
        data: Optional[Union[Dict, str]] = None,
        json_data: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        proxy: Optional[Dict] = None,
        timeout: Optional[int] = None,
        verify: Optional[bool] = None,
        allow_redirects: Optional[bool] = None,
        cache_headers: Optional[Dict] = None
    ) -> Tuple[Optional[requests.Response], Dict]:
        """
        Send an HTTP request with specified parameters.
        
        Args:
            url (str): Target URL.
            method (str, optional): HTTP method (GET, POST, etc.).
            headers (dict, optional): Request headers.
            params (dict, optional): URL parameters.
            data (dict or str, optional): Request body data.
            json_data (dict, optional): JSON request body.
            cookies (dict, optional): Request cookies.
            proxy (dict, optional): Proxy configuration.
            timeout (int, optional): Request timeout.
            verify (bool, optional): SSL verification.
            allow_redirects (bool, optional): Follow redirects.
            cache_headers (dict, optional): Cache-specific headers.
            
        Returns:
            tuple: (Response object or None, Request metadata)
        """
        metadata = {
            'timestamp': time.time(),
            'url': url,
            'method': method,
            'headers_sent': {},
            'response_time': 0,
            'status_code': None,
            'error': None
        }
        
        try:
            # Prepare request headers
            request_headers = self.default_headers.copy()
            if headers:
                request_headers.update(headers)
            if cache_headers:
                request_headers.update(cache_headers)
            
            metadata['headers_sent'] = request_headers
            
            # Configure request parameters
            request_kwargs = {
                'headers': request_headers,
                'params': params,
                'timeout': timeout or self.timeout,
                'verify': self.verify_ssl if verify is None else verify,
                'allow_redirects': self.follow_redirects if allow_redirects is None else allow_redirects,
                'cookies': cookies
            }
            
            # Add body data if present
            if data is not None:
                request_kwargs['data'] = data
            elif json_data is not None:
                request_kwargs['json'] = json_data
            
            # Add proxy if specified
            if proxy:
                request_kwargs['proxies'] = proxy
            
            # Send request and measure response time
            start_time = time.time()
            response = self.session.request(method, url, **request_kwargs)
            metadata['response_time'] = time.time() - start_time
            
            # Update metadata
            metadata['status_code'] = response.status_code
            metadata['response_headers'] = dict(response.headers)
            
            return response, metadata
            
        except RequestException as e:
            self.logger.error(f"Request error for {url}: {str(e)}")
            metadata['error'] = str(e)
            return None, metadata
        
        except Exception as e:
            self.logger.error(f"Unexpected error for {url}: {str(e)}")
            metadata['error'] = str(e)
            return None, metadata
    
    def test_cache_behavior(
        self,
        url: str,
        cache_headers: Optional[Dict] = None,
        test_iterations: int = 3,
        delay_between_requests: float = 1.0
    ) -> List[Dict]:
        """
        Test cache behavior by sending multiple requests.
        
        Args:
            url (str): Target URL.
            cache_headers (dict, optional): Cache-specific headers.
            test_iterations (int, optional): Number of test iterations.
            delay_between_requests (float, optional): Delay between requests.
            
        Returns:
            list: List of request/response metadata for analysis.
        """
        results = []
        
        for i in range(test_iterations):
            # Add cache buster to URL if needed
            test_url = self._add_cache_buster(url) if i > 0 else url
            
            # Send request
            response, metadata = self.send_request(
                test_url,
                cache_headers=cache_headers
            )
            
            if response:
                # Extract cache-related headers
                cache_info = self._extract_cache_info(response)
                metadata['cache_info'] = cache_info
            
            results.append(metadata)
            
            # Wait between requests
            if i < test_iterations - 1:
                time.sleep(delay_between_requests)
        
        return results
    
    def probe_cache_headers(self, url: str) -> Dict:
        """
        Probe server's response to various cache headers.
        
        Args:
            url (str): Target URL.
            
        Returns:
            dict: Cache header probe results.
        """
        probe_results = {
            'supported_headers': [],
            'cache_behavior': {},
            'recommendations': []
        }
        
        # Test different cache control directives
        cache_tests = [
            {'Cache-Control': 'no-cache'},
            {'Cache-Control': 'no-store'},
            {'Cache-Control': 'max-age=0'},
            {'Cache-Control': 'private'},
            {'Cache-Control': 'public'},
            {'Pragma': 'no-cache'},
            {'Expires': '0'}
        ]
        
        for test_headers in cache_tests:
            response, metadata = self.send_request(url, headers=test_headers)
            
            if response:
                # Check if the server honors these headers
                cache_info = self._extract_cache_info(response)
                
                # Analyze server's response
                test_result = {
                    'headers_sent': test_headers,
                    'server_response': cache_info,
                    'is_effective': self._is_cache_header_effective(test_headers, cache_info)
                }
                
                probe_results['cache_behavior'][list(test_headers.keys())[0]] = test_result
                
                # Add to supported headers if effective
                if test_result['is_effective']:
                    probe_results['supported_headers'].extend(test_headers.keys())
        
        # Generate recommendations
        probe_results['recommendations'] = self._generate_cache_recommendations(probe_results)
        
        return probe_results
    
    def _add_cache_buster(self, url: str) -> str:
        """
        Add a cache buster parameter to URL.
        
        Args:
            url (str): Original URL.
            
        Returns:
            str: URL with cache buster.
        """
        parsed = urlparse(url)
        cache_buster = f"_={int(time.time() * 1000)}"
        
        if parsed.query:
            return f"{url}&{cache_buster}"
        else:
            return f"{url}?{cache_buster}"
    
    def _extract_cache_info(self, response: requests.Response) -> Dict:
        """
        Extract cache-related information from response.
        
        Args:
            response: Response object.
            
        Returns:
            dict: Cache-related information.
        """
        cache_info = {
            'cache_control': {},
            'etag': None,
            'last_modified': None,
            'age': None,
            'expires': None,
            'vary': None,
            'cache_status': None
        }
        
        # Extract Cache-Control directives
        if 'Cache-Control' in response.headers:
            cache_info['cache_control'] = self._parse_cache_control(response.headers['Cache-Control'])
        
        # Extract other cache headers
        cache_info['etag'] = response.headers.get('ETag')
        cache_info['last_modified'] = response.headers.get('Last-Modified')
        cache_info['age'] = response.headers.get('Age')
        cache_info['expires'] = response.headers.get('Expires')
        cache_info['vary'] = response.headers.get('Vary')
        
        # Check for CDN/proxy cache indicators
        for header in response.headers:
            if header.lower().startswith(('x-cache', 'cf-cache', 'x-varnish')):
                cache_info['cache_status'] = response.headers[header]
        
        return cache_info
    
    def _parse_cache_control(self, header_value: str) -> Dict:
        """
        Parse Cache-Control header value.
        
        Args:
            header_value (str): Cache-Control header value.
            
        Returns:
            dict: Parsed cache control directives.
        """
        directives = {}
        
        if not header_value:
            return directives
        
        parts = [p.strip() for p in header_value.split(',')]
        
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                directives[key.strip().lower()] = value.strip()
            else:
                directives[part.lower()] = True
        
        return directives
    
    def _is_cache_header_effective(self, test_headers: Dict, cache_info: Dict) -> bool:
        """
        Check if cache headers are effective.
        
        Args:
            test_headers (dict): Test headers sent.
            cache_info (dict): Cache information from response.
            
        Returns:
            bool: True if headers are effective.
        """
        # Check Cache-Control effectiveness
        if 'Cache-Control' in test_headers:
            test_directive = test_headers['Cache-Control'].lower()
            response_directives = cache_info['cache_control']
            
            # Check if the server respects our cache control directive
            if test_directive in ['no-cache', 'no-store']:
                return test_directive in response_directives
            elif 'max-age=' in test_directive:
                return 'max-age' in response_directives
            elif test_directive in ['private', 'public']:
                return test_directive in response_directives
        
        # Check Pragma effectiveness
        if 'Pragma' in test_headers:
            return 'no-cache' in cache_info['cache_control']
        
        # Check Expires effectiveness
        if 'Expires' in test_headers:
            return cache_info['expires'] is not None
        
        return False
    
    def _generate_cache_recommendations(self, probe_results: Dict) -> List[str]:
        """
        Generate cache-related recommendations.
        
        Args:
            probe_results (dict): Probe test results.
            
        Returns:
            list: List of recommendations.
        """
        recommendations = []
        
        # Check for missing important cache headers
        important_headers = {'Cache-Control', 'Vary'}
        missing_headers = important_headers - set(probe_results['supported_headers'])
        
        if 'Cache-Control' in missing_headers:
            recommendations.append(
                "Implement Cache-Control headers to explicitly control caching behavior"
            )
        
        if 'Vary' in missing_headers:
            recommendations.append(
                "Add Vary header to prevent cache poisoning across different contexts"
            )
        
        # Check cache behavior
        cache_behavior = probe_results['cache_behavior']
        
        if 'Cache-Control' in cache_behavior:
            cc_result = cache_behavior['Cache-Control']
            if not cc_result['is_effective']:
                recommendations.append(
                    "Server is not properly honoring Cache-Control directives"
                )
        
        # Check for potentially risky cache configurations
        if 'public' in probe_results['supported_headers'] and 'private' not in probe_results['supported_headers']:
            recommendations.append(
                "Consider using 'private' instead of 'public' for sensitive content"
            )
        
        return recommendations
