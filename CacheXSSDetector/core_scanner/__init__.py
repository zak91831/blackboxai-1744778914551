"""
Core Scanner Module

This module initializes and coordinates the core scanning components for
cache-based XSS vulnerability detection.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from .url_path_manipulation import URLPathManipulator
from .cache_behavior_analysis import CacheBehaviorAnalyzer
from .xss_payload_generator import XSSPayloadGenerator
from .response_analyzer import ResponseAnalyzer
from .advanced_xss_detector import AdvancedXSSDetector
from .waf_bypass import WAFBypass
from .xss0r_integration import XSS0rIntegration
from .custom_header_injector import CustomHeaderInjector
from .rate_limited_xss0r import RateLimitedXSS0rIntegration

class CoreScanner:
    """
    Core scanning coordinator for cache-based XSS detection.
    """
    
    def __init__(self, config):
        """
        Initialize the Core Scanner.
        
        Args:
            config (dict): Configuration settings for core scanning.
        """
        self.logger = logging.getLogger('cachexssdetector.core_scanner')
        self.config = config
        
        # Initialize components
        self.url_manipulator = URLPathManipulator(config.get('url_path', {}))
        self.cache_analyzer = CacheBehaviorAnalyzer(config.get('cache_behavior', {}))
        self.payload_generator = XSSPayloadGenerator(config.get('payload_generator', {}))
        self.response_analyzer = ResponseAnalyzer(config.get('response_analyzer', {}))
        
        # Scanning configuration
        self.max_depth = config.get('max_depth', 3)
        self.max_payloads = config.get('max_payloads', 10)
        self.scan_timeout = config.get('scan_timeout', 3600)  # 1 hour
        
        self.logger.info("Core Scanner initialized")
    
    async def scan_target(
        self,
        target_url: str,
        options: Optional[Dict] = None
    ) -> Dict:
        """
        Perform comprehensive scan of target for cache-based XSS.
        
        Args:
            target_url (str): Target URL to scan.
            options (dict, optional): Scan options.
            
        Returns:
            dict: Scan results.
        """
        scan_results = {
            'target_url': target_url,
            'scan_status': 'initialized',
            'findings': [],
            'statistics': {},
            'errors': []
        }
        
        try:
            self.logger.info(f"Starting scan of {target_url}")
            
            # Generate URL variations
            url_variations = self.url_manipulator.generate_path_variations(target_url)
            
            # Generate payloads
            payloads = self.payload_generator.generate_payloads(
                max_payloads=self.max_payloads
            )
            
            # Scan each URL variation with payloads
            for url in url_variations:
                url_results = await self._scan_url(url, payloads, options)
                scan_results['findings'].extend(url_results.get('findings', []))
                
                if url_results.get('error'):
                    scan_results['errors'].append(url_results['error'])
            
            # Analyze cache behavior patterns
            cache_analysis = self.cache_analyzer.analyze_sequence(
                [f.get('response', {}) for f in scan_results['findings']]
            )
            scan_results['cache_analysis'] = cache_analysis
            
            # Calculate statistics
            scan_results['statistics'] = self._calculate_statistics(
                scan_results['findings']
            )
            
            scan_results['scan_status'] = 'completed'
            
        except Exception as e:
            error_msg = f"Error during scan: {str(e)}"
            self.logger.error(error_msg)
            scan_results['scan_status'] = 'error'
            scan_results['errors'].append(error_msg)
        
        return scan_results
    
    async def _scan_url(
        self,
        url: str,
        payloads: List[Dict],
        options: Optional[Dict]
    ) -> Dict:
        """
        Scan a single URL with multiple payloads.
        
        Args:
            url (str): URL to scan.
            payloads (list): List of payloads to test.
            options (dict, optional): Scan options.
            
        Returns:
            dict: URL scan results.
        """
        url_results = {
            'url': url,
            'findings': [],
            'error': None
        }
        
        try:
            for payload in payloads:
                # Test payload
                finding = await self._test_payload(url, payload, options)
                
                if finding.get('vulnerable', False):
                    url_results['findings'].append(finding)
                
        except Exception as e:
            url_results['error'] = f"Error scanning URL {url}: {str(e)}"
            self.logger.error(url_results['error'])
        
        return url_results
    
    async def _test_payload(
        self,
        url: str,
        payload: Dict,
        options: Optional[Dict]
    ) -> Dict:
        """
        Test a single payload against a URL.
        
        Args:
            url (str): Target URL.
            payload (dict): Payload to test.
            options (dict, optional): Test options.
            
        Returns:
            dict: Test results.
        """
        finding = {
            'url': url,
            'payload': payload,
            'vulnerable': False,
            'confidence': 0.0,
            'response': None,
            'cache_info': None
        }
        
        try:
            # Send payload
            response = await self._send_payload(url, payload, options)
            finding['response'] = response
            
            # Analyze response
            analysis = self.response_analyzer.analyze_response(
                response,
                payload=payload
            )
            finding.update(analysis)
            
            # Analyze cache behavior
            cache_analysis = self.cache_analyzer.analyze_response(
                response,
                context={'payload': payload}
            )
            finding['cache_info'] = cache_analysis
            
            # Determine if vulnerable
            if analysis.get('has_reflection', False) and cache_analysis.get('is_cached', False):
                finding['vulnerable'] = True
                finding['confidence'] = min(
                    analysis.get('confidence', 0.0),
                    cache_analysis.get('confidence', 0.0)
                )
            
        except Exception as e:
            self.logger.error(f"Error testing payload: {str(e)}")
        
        return finding
    
    async def _send_payload(
        self,
        url: str,
        payload: Dict,
        options: Optional[Dict]
    ) -> Dict:
        """
        Send payload to target URL.
        
        Args:
            url (str): Target URL.
            payload (dict): Payload to send.
            options (dict, optional): Request options.
            
        Returns:
            dict: Response data.
        """
        # Note: This is a placeholder. The actual implementation would use
        # the HTTP client from request_components module.
        return {
            'url': url,
            'status_code': 200,
            'headers': {},
            'content': '',
            'timing': 0.0
        }
    
    def _calculate_statistics(self, findings: List[Dict]) -> Dict:
        """
        Calculate scan statistics.
        
        Args:
            findings (list): Scan findings.
            
        Returns:
            dict: Calculated statistics.
        """
        stats = {
            'total_urls_scanned': 0,
            'total_payloads_tested': 0,
            'vulnerabilities_found': 0,
            'cache_hits': 0,
            'average_confidence': 0.0
        }
        
        if not findings:
            return stats
        
        # Calculate statistics
        urls = set(f['url'] for f in findings)
        stats['total_urls_scanned'] = len(urls)
        stats['total_payloads_tested'] = len(findings)
        stats['vulnerabilities_found'] = sum(
            1 for f in findings if f.get('vulnerable', False)
        )
        stats['cache_hits'] = sum(
            1 for f in findings
            if f.get('cache_info', {}).get('is_cached', False)
        )
        
        # Calculate average confidence
        confidences = [
            f.get('confidence', 0.0)
            for f in findings
            if f.get('vulnerable', False)
        ]
        if confidences:
            stats['average_confidence'] = sum(confidences) / len(confidences)
        
        return stats

# Version information
__version__ = '1.0.0'
