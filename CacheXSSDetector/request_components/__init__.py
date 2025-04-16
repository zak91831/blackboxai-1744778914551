"""
Request Components Module

This module initializes and coordinates the request handling components for
cache-based XSS vulnerability detection.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
import asyncio
from .http_client import HTTPClient
from .header_manipulation import HeaderManipulator
from .proxy_integration import ProxyIntegrator

class RequestHandler:
    """
    Request handling coordinator for cache-based XSS detection.
    """
    
    def __init__(self, config):
        """
        Initialize the Request Handler.
        
        Args:
            config (dict): Configuration settings for request handling.
        """
        self.logger = logging.getLogger('cachexssdetector.request_handler')
        self.config = config
        
        # Initialize components
        self.http_client = HTTPClient(config.get('http_client', {}))
        self.header_manipulator = HeaderManipulator(config.get('header_manipulation', {}))
        self.proxy_integrator = ProxyIntegrator(config.get('proxy', {}))
        
        # Request configuration
        self.max_concurrent = config.get('max_concurrent_requests', 10)
        self.request_delay = config.get('request_delay', 0.5)
        self.timeout = config.get('timeout', 30)
        
        # Initialize request queue and semaphore
        self.request_queue = asyncio.Queue()
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        
        self.logger.info("Request Handler initialized")
    
    async def send_request(
        self,
        url: str,
        method: str = 'GET',
        headers: Optional[Dict] = None,
        data: Optional[Dict] = None,
        options: Optional[Dict] = None
    ) -> Dict:
        """
        Send a single HTTP request with cache awareness.
        
        Args:
            url (str): Target URL.
            method (str): HTTP method.
            headers (dict, optional): Request headers.
            data (dict, optional): Request data.
            options (dict, optional): Request options.
            
        Returns:
            dict: Response data.
        """
        request_data = {
            'url': url,
            'method': method,
            'headers': headers or {},
            'data': data,
            'options': options or {}
        }
        
        try:
            # Apply header manipulations
            if headers:
                request_data['headers'] = self.header_manipulator.modify_headers(
                    headers,
                    request_data['options'].get('header_modifications', {})
                )
            
            # Add cache-specific headers
            cache_headers = self.header_manipulator.generate_cache_headers(
                request_data['options'].get('cache_policy', 'default')
            )
            request_data['headers'].update(cache_headers)
            
            # Route through proxy if enabled
            if self.proxy_integrator.proxy_enabled:
                response = await self._send_through_proxy(request_data)
            else:
                response = await self._send_direct(request_data)
            
            return response
            
        except Exception as e:
            error_msg = f"Error sending request to {url}: {str(e)}"
            self.logger.error(error_msg)
            return self._create_error_response(error_msg)
    
    async def send_batch(
        self,
        requests: List[Dict],
        options: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Send multiple requests in parallel with rate limiting.
        
        Args:
            requests (list): List of request configurations.
            options (dict, optional): Batch options.
            
        Returns:
            list: List of responses.
        """
        results = []
        
        try:
            # Initialize request queue
            for request in requests:
                await self.request_queue.put(request)
            
            # Create worker tasks
            tasks = [
                self._request_worker()
                for _ in range(min(self.max_concurrent, len(requests)))
            ]
            
            # Wait for all requests to complete
            workers = await asyncio.gather(*tasks)
            
            # Collect results
            for worker_results in workers:
                results.extend(worker_results)
            
        except Exception as e:
            self.logger.error(f"Error in batch request processing: {str(e)}")
        
        return results
    
    async def test_cache_behavior(
        self,
        url: str,
        variations: List[Dict],
        options: Optional[Dict] = None
    ) -> Dict:
        """
        Test URL with different cache-related request variations.
        
        Args:
            url (str): Target URL.
            variations (list): List of request variations to test.
            options (dict, optional): Test options.
            
        Returns:
            dict: Test results.
        """
        results = {
            'url': url,
            'variations_tested': len(variations),
            'cache_hits': 0,
            'responses': []
        }
        
        try:
            for variation in variations:
                # Generate cache-specific headers
                headers = self.header_manipulator.generate_header_variations(
                    variation.get('headers', {}),
                    variation.get('context', {})
                )
                
                # Send requests with variations
                for header_set in headers:
                    response = await self.send_request(
                        url,
                        headers=header_set,
                        options=variation.get('options', {})
                    )
                    
                    results['responses'].append({
                        'variation': variation,
                        'headers_used': header_set,
                        'response': response
                    })
                    
                    if self._is_cache_hit(response):
                        results['cache_hits'] += 1
                
                # Respect rate limiting
                await asyncio.sleep(self.request_delay)
            
        except Exception as e:
            self.logger.error(f"Error in cache behavior testing: {str(e)}")
        
        return results
    
    async def _request_worker(self) -> List[Dict]:
        """
        Worker for processing requests from queue.
        
        Returns:
            list: Worker results.
        """
        results = []
        
        while True:
            try:
                # Get request from queue
                request = await self.request_queue.get_nowait()
                
                # Process request with semaphore
                async with self.semaphore:
                    response = await self.send_request(**request)
                    results.append(response)
                
                # Mark task as done
                self.request_queue.task_done()
                
                # Respect rate limiting
                await asyncio.sleep(self.request_delay)
                
            except asyncio.QueueEmpty:
                break
            except Exception as e:
                self.logger.error(f"Error in request worker: {str(e)}")
                break
        
        return results
    
    async def _send_through_proxy(self, request_data: Dict) -> Dict:
        """
        Send request through configured proxy.
        
        Args:
            request_data (dict): Request configuration.
            
        Returns:
            dict: Response data.
        """
        try:
            return await self.proxy_integrator.send_request(request_data)
        except Exception as e:
            error_msg = f"Proxy request error: {str(e)}"
            self.logger.error(error_msg)
            return self._create_error_response(error_msg)
    
    async def _send_direct(self, request_data: Dict) -> Dict:
        """
        Send request directly without proxy.
        
        Args:
            request_data (dict): Request configuration.
            
        Returns:
            dict: Response data.
        """
        try:
            return await self.http_client.send_request(request_data)
        except Exception as e:
            error_msg = f"Direct request error: {str(e)}"
            self.logger.error(error_msg)
            return self._create_error_response(error_msg)
    
    def _is_cache_hit(self, response: Dict) -> bool:
        """
        Check if response is a cache hit.
        
        Args:
            response (dict): Response to check.
            
        Returns:
            bool: True if response is from cache.
        """
        headers = response.get('headers', {})
        
        # Check cache indicators
        if 'x-cache' in headers and 'hit' in headers['x-cache'].lower():
            return True
        
        if 'age' in headers and int(headers['age'] or 0) > 0:
            return True
        
        if 'cf-cache-status' in headers and headers['cf-cache-status'].lower() == 'hit':
            return True
        
        return False
    
    def _create_error_response(self, error_message: str) -> Dict:
        """
        Create error response structure.
        
        Args:
            error_message (str): Error description.
            
        Returns:
            dict: Error response structure.
        """
        return {
            'status_code': None,
            'headers': {},
            'content': None,
            'error': error_message,
            'timing': 0
        }

# Version information
__version__ = '1.0.0'
