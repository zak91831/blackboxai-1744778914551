"""
Advanced XSS Detector Tests

This module contains tests for the Advanced XSS Detector functionality.
"""

import unittest
import sys
import os

# Add the parent directory to the system path for imports to work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core_scanner.advanced_xss_detector import AdvancedXSSDetector

class TestAdvancedXSSDetector(unittest.TestCase):
    """Test advanced XSS detection functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.config = {
            'max_detection_depth': 3,
            'enable_machine_learning': False,
            'detection_timeout': 60,
            'analyze_dom': True
        }
        self.detector = AdvancedXSSDetector(self.config)
    
    def test_detector_initialization(self):
        """Test detector initialization."""
        self.assertIsNotNone(self.detector)
        self.assertEqual(self.detector.max_detection_depth, 3)
        self.assertFalse(self.detector.enable_machine_learning)
        self.assertEqual(self.detector.detection_timeout, 60)
        self.assertTrue(self.detector.analyze_dom)
    
    def test_analyze_response(self):
        """Test response analysis functionality."""
        # Setup mock response data
        url = "http://example.com/test?param=<script>alert('XSS')</script>"
        response_data = {
            'body': '<html><body>Welcome to our site <script>alert(\'XSS\')</script></body></html>',
            'headers': {
                'Content-Type': 'text/html',
                'X-XSS-Protection': '0'
            },
            'status_code': 200
        }
        
        # Analyze the response
        result = self.detector.analyze_response(url, response_data)
        
        # Verify the analysis result
        self.assertIsNotNone(result)
        self.assertEqual(result['url'], url)
        self.assertIn('vulnerabilities', result)
        self.assertIn('reflection_points', result)
        self.assertIn('defense_mechanisms', result)
        self.assertIn('risk_level', result)
        
    def test_context_aware_payload_generation(self):
        """Test context-aware payload generation."""
        # Generate payloads for different contexts
        html_payloads = self.detector.generate_context_aware_payloads('html_body', max_payloads=3)
        attribute_payloads = self.detector.generate_context_aware_payloads('html_attribute', max_payloads=3)
        script_payloads = self.detector.generate_context_aware_payloads('script_context', max_payloads=3)
        
        # Verify the payloads
        self.assertIsInstance(html_payloads, list)
        self.assertIsInstance(attribute_payloads, list)
        self.assertIsInstance(script_payloads, list)
        
        # Check if payloads are appropriate for the context
        if html_payloads:
            self.assertEqual(html_payloads[0]['context'], 'html_body')
        
        if attribute_payloads:
            self.assertEqual(attribute_payloads[0]['context'], 'html_attribute')
        
        if script_payloads:
            self.assertEqual(script_payloads[0]['context'], 'script_context')

if __name__ == '__main__':
    unittest.main()
