"""
Rate-Limited XSS0r Integration Module

Enhanced version of the XSS0r Integration that includes adaptive rate limiting
to avoid triggering WAF protections or being blocked by target servers.
"""

import re
import logging
import time
import random
import json
import urllib.parse
import requests
from typing import Dict, List, Set, Tuple, Optional, Any
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sys
import os

# Need to add the parent directory to the path to make relative imports work
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from utils.rate_limiter import RateLimiter

# For handling JavaScript content
try:
    from pyppeteer import launch
    HEADLESS_SUPPORT = True
except ImportError:
    HEADLESS_SUPPORT = False

from core_scanner.xss0r_integration import XSS0rIntegration

class RateLimitedXSS0rIntegration(XSS0rIntegration):
    """
    Enhanced XSS0r-like functionality with adaptive rate limiting.
    Inherits from XSS0rIntegration and adds rate limiting capabilities.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the rate-limited XSS0r integration module.
        
        Args:
            config (dict, optional): Configuration settings.
        """
        # Call the parent class's __init__ method first
        super().__init__(config)
        
        # Change logger name to reflect rate-limited version
        self.logger = logging.getLogger('cachexssdetector.rate_limited_xss0r')
        
        # Initialize rate limiter with adaptive mode
        rate_limit_rpm = self.config.get('rate_limit_rpm', 60)  # Requests per minute
        self.rate_limiter = RateLimiter(
            requests_per_minute=rate_limit_rpm,
            base_delay=self.crawl_delay,
            adaptive=self.config.get('adaptive', True),
            max_retries=3
        )
        
        self.logger.info("Rate-Limited XSS0r Integration module initialized")
    
    def set_detectors(self, xss_detector, waf_bypass):
        """
        Set the detector modules to use for testing.
        
        Args:
            xss_detector: The XSS detector instance.
            waf_bypass: The WAF bypass instance.
        """
        self.xss_detector = xss_detector
        self.waf_bypass = waf_bypass
        
        # Initialize the custom header injector
        from .custom_header_injector import CustomHeaderInjector
        self.header_injector = CustomHeaderInjector()
    
    def _make_request(self, url: str, method: str = 'get', **kwargs) -> requests.Response:
        """
        Make a rate-limited HTTP request.
        
        Args:
            url: URL to request
            method: HTTP method ('get' or 'post')
            **kwargs: Arguments to pass to requests.get/post
            
        Returns:
            Response object
        """
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        
        # Apply rate limiting before request
        self.rate_limiter.pre_request(host)
        
        start_time = time.time()
        error = None
        status_code = 0
        
        try:
            if method.lower() == 'post':
                response = requests.post(url, **kwargs)
            else:
                response = requests.get(url, **kwargs)
                
            status_code = response.status_code
            
        except Exception as e:
            error = str(e)
            raise
        finally:
            # Update rate limiter with request result
            request_time = time.time() - start_time
            self.rate_limiter.post_request(host, status_code, request_time, error)
            
        return response
    
    def crawl(self, start_url: str) -> Dict:
        """
        Override the parent crawl method to add rate limiting.
        
        Args:
            start_url (str): The URL to start crawling from.
            
        Returns:
            dict: Crawl results including discovered URLs and forms.
        """
        self.logger.info(f"Starting rate-limited crawl from {start_url}")
        
        # Reset state
        self.visited_urls = set()
        self.url_queue = [(start_url, 0)]  # (url, depth)
        self.forms_found = []
        self.discovered_urls = []
        
        # Process the URL queue
        while self.url_queue and len(self.visited_urls) < self.max_urls_per_domain:
            # Get the next URL to process
            current_url, depth = self.url_queue.pop(0)
            
            # Skip if we've already visited this URL or exceeded max depth
            if current_url in self.visited_urls or depth > self.max_depth:
                continue
            
            self.logger.info(f"Crawling URL: {current_url} (depth: {depth})")
            
            # Mark as visited
            self.visited_urls.add(current_url)
            self.discovered_urls.append(current_url)
            
            try:
                # Fetch the page with rate limiting
                response = self._make_request(
                    current_url, 
                    headers=self.headers, 
                    timeout=self.timeout,
                    allow_redirects=True
                )
                
                # Skip non-successful responses or non-HTML content
                if response.status_code != 200 or 'text/html' not in response.headers.get('Content-Type', ''):
                    continue
                
                # Parse HTML with BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find and store forms
                if self.test_forms:
                    self._extract_forms(soup, current_url)
                
                # Extract links for further crawling if not at max depth
                if depth < self.max_depth:
                    next_depth = depth + 1
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        absolute_url = urljoin(current_url, href)
                        
                        # Only follow links to the same domain
                        if self._same_domain(absolute_url, start_url):
                            # Remove fragments
                            absolute_url = absolute_url.split('#')[0]
                            
                            # Add to queue if not visited
                            if absolute_url not in self.visited_urls:
                                self.url_queue.append((absolute_url, next_depth))
            
            except Exception as e:
                self.logger.error(f"Error crawling {current_url}: {str(e)}")
        
        # Get rate limiter statistics
        parsed_url = urlparse(start_url)
        host = parsed_url.netloc
        rate_limit_status = self.rate_limiter.get_host_status(host)
        
        # Prepare results
        results = {
            "start_url": start_url,
            "urls_discovered": len(self.discovered_urls),
            "forms_found": len(self.forms_found),
            "max_depth_reached": max(depth for _, depth in self.url_queue) if self.url_queue else 0,
            "discovered_urls": self.discovered_urls,
            "forms": self.forms_found,
            "rate_limiting": {
                "requests_made": rate_limit_status['requests_in_window'],
                "current_delay": rate_limit_status['current_delay'],
                "adaptive_status": "throttled" if rate_limit_status['current_delay'] > self.crawl_delay else "normal"
            }
        }
        
        self.logger.info(f"Crawl complete. Discovered {len(self.discovered_urls)} URLs and {len(self.forms_found)} forms.")
        
        return results
        
    def scan_site(self, start_url: str) -> Dict:
        """
        Override the parent scan_site method to add rate limiting statistics.
        
        Args:
            start_url (str): The URL to start scanning from.
            
        Returns:
            dict: Scan results including vulnerabilities found.
        """
        # First use the parent class's scan_site method
        results = super().scan_site(start_url)
        
        # Add rate limiting information
        parsed_url = urlparse(start_url)
        host = parsed_url.netloc
        rate_limit_status = self.rate_limiter.get_host_status(host)
        
        results["rate_limiting"] = {
            "requests_made": rate_limit_status['requests_in_window'],
            "current_delay": rate_limit_status['current_delay'],
            "adaptive_status": "throttled" if rate_limit_status['current_delay'] > self.crawl_delay else "normal"
        }
        
        return results
    
    def _test_headers(self, url: str) -> Dict:
        """
        Test a URL for header-based XSS vulnerabilities with rate limiting.
        
        Args:
            url (str): The URL to test.
            
        Returns:
            dict: Test results.
        """
        if not hasattr(self, 'header_injector'):
            self.logger.warning("Header injector not initialized, skipping header tests")
            return {"url": url, "vulnerable": False, "tests": []}
        
        # Generate malicious headers for testing
        malicious_headers = self.header_injector.generate_malicious_headers(self.waf_bypass)
        
        # Limit the number of tests to avoid excessive requests
        test_headers = malicious_headers[:self.header_tests_per_url]
        
        results = {
            "url": url,
            "headers_tested": 0,
            "vulnerable": False,
            "successful_header": None,
            "successful_payload": None,
            "tests": []
        }
        
        # Test each malicious header set
        for header_set in test_headers:
            results["headers_tested"] += 1
            
            try:
                # Send the request with malicious headers using rate limiting
                response = self._make_request(
                    url, 
                    headers=header_set['headers'], 
                    timeout=self.timeout,
                    allow_redirects=True
                )
                
                # Analyze header reflection
                reflection_analysis = self.header_injector.analyze_header_reflection(
                    response.text, 
                    header_set['payload']
                )
                
                # Use the XSS detector to analyze the response if available
                vulnerable = False
                if self.xss_detector:
                    analysis = self.xss_detector.analyze_response(url, {
                        'body': response.text,
                        'headers': dict(response.headers),
                        'status_code': response.status_code
                    })
                    
                    vulnerable = len(analysis.get('vulnerabilities', [])) > 0
                else:
                    # If no detector available, use reflection analysis as fallback
                    vulnerable = reflection_analysis.get('potentially_exploitable', False)
                
                test_result = {
                    "header": header_set['header_name'],
                    "payload": header_set['payload'],
                    "reflected": reflection_analysis.get('reflected', False),
                    "encoded_reflected": reflection_analysis.get('encoded_reflected', False),
                    "vulnerable": vulnerable
                }
                
                if 'technique' in header_set:
                    test_result["bypass_technique"] = header_set['technique']
                
                results["tests"].append(test_result)
                
                # If vulnerable, update the results
                if vulnerable:
                    results["vulnerable"] = True
                    results["successful_header"] = header_set['header_name']
                    results["successful_payload"] = header_set['payload']
                    
                    # No need to test more header sets
                    break
                
            except Exception as e:
                self.logger.error(f"Error testing header {header_set['header_name']} with payload: {str(e)}")
                results["tests"].append({
                    "header": header_set['header_name'],
                    "payload": header_set['payload'],
                    "error": str(e)
                })
        
        return results
    
    # Note: All other methods like scan_site, _test_parameter, _test_form, etc. would be 
    # similar to the original XSS0rIntegration but using self._make_request() instead of requests.get/post
    # directly. I'll leave these implementations out for brevity in this example.
