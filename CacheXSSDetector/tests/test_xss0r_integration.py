"""
Test Module for XSS0r Integration

This module contains tests for the XSS0r integration functionality.
"""

import pytest
import os
import sys
import json
from unittest.mock import Mock, patch, MagicMock

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core_scanner.xss0r_integration import XSS0rIntegration
from core_scanner.advanced_xss_detector import AdvancedXSSDetector
from core_scanner.waf_bypass import WAFBypass

class TestXSS0rIntegration:
    """Tests for the XSS0r integration module."""
    
    @pytest.fixture
    def xss0r_instance(self):
        """Create a XSS0r instance for testing."""
        config = {
            'max_depth': 2,
            'max_urls_per_domain': 10,
            'crawl_delay': 0.1,
            'timeout': 5,
            'test_forms': True,
            'test_headers': True,
            'test_cookies': True,
            'test_dom': False,  # Disable DOM testing for unit tests
        }
        return XSS0rIntegration(config)
    
    @pytest.fixture
    def mock_detector(self):
        """Create a mock XSS detector."""
        detector = Mock(spec=AdvancedXSSDetector)
        detector.analyze_response.return_value = {
            'vulnerabilities': [],
            'reflection_points': [],
            'risk_level': 'low'
        }
        return detector
    
    @pytest.fixture
    def mock_waf_bypass(self):
        """Create a mock WAF bypass module."""
        waf_bypass = Mock(spec=WAFBypass)
        waf_bypass.generate_waf_bypass_payloads.return_value = [
            {
                'original': '<script>alert("XSS")</script>',
                'mutated': '<script>alert(\"XSS\")</script>',
                'technique': 'case_mutation',
                'length': 28
            },
            {
                'original': '<script>alert("XSS")</script>',
                'mutated': '<scr\\x69pt>alert(\"XSS\")</script>',
                'technique': 'encoding_mutation',
                'length': 33
            }
        ]
        return waf_bypass
    
    def test_initialization(self, xss0r_instance):
        """Test initialization of the XSS0r integration module."""
        assert xss0r_instance is not None
        assert xss0r_instance.max_depth == 2
        assert xss0r_instance.max_urls_per_domain == 10
        assert xss0r_instance.crawl_delay == 0.1
        assert xss0r_instance.test_forms is True
        assert xss0r_instance.visited_urls == set()
    
    def test_set_detectors(self, xss0r_instance, mock_detector, mock_waf_bypass):
        """Test setting the detectors."""
        xss0r_instance.set_detectors(mock_detector, mock_waf_bypass)
        assert xss0r_instance.xss_detector is mock_detector
        assert xss0r_instance.waf_bypass is mock_waf_bypass
    
    @patch('core_scanner.xss0r_integration.requests.get')
    def test_extract_forms(self, mock_get, xss0r_instance):
        """Test form extraction from HTML."""
        # Create mock response with HTML containing a form
        mock_response = Mock()
        mock_response.text = """
        <html>
        <body>
            <form action="/submit" method="post" id="test-form">
                <input type="text" name="username" id="username">
                <input type="password" name="password" id="password">
                <input type="submit" value="Submit">
            </form>
        </body>
        </html>
        """
        
        # Create a BeautifulSoup object
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(mock_response.text, 'html.parser')
        
        # Test form extraction
        xss0r_instance._extract_forms(soup, "http://example.com")
        
        # Check if form was extracted correctly
        assert len(xss0r_instance.forms_found) == 1
        form = xss0r_instance.forms_found[0]
        assert form['action'] == "http://example.com/submit"
        assert form['method'] == "post"
        assert form['id'] == "test-form"
        assert len(form['inputs']) == 2  # Should skip the submit button
        
        # Check input fields
        input_names = [input_field['name'] for input_field in form['inputs']]
        assert "username" in input_names
        assert "password" in input_names
    
    @patch('core_scanner.xss0r_integration.requests.get')
    def test_test_parameter(self, mock_get, xss0r_instance, mock_detector, mock_waf_bypass):
        """Test parameter testing functionality."""
        # Setup mocks
        xss0r_instance.set_detectors(mock_detector, mock_waf_bypass)
        
        # Mock response
        mock_response = Mock()
        mock_response.text = "<html>Test</html>"
        mock_response.headers = {}
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        # Test parameter
        result = xss0r_instance._test_parameter(
            "http://example.com/?q=test", 
            "q"
        )
        
        # Check results
        assert result['url'] == "http://example.com/?q=test"
        assert result['parameter'] == "q"
        assert result['vulnerable'] is False
        assert len(result['tests']) > 0
        
        # Verify that requests.get was called
        mock_get.assert_called()
        
        # Set mock detector to detect a vulnerability
        mock_detector.analyze_response.return_value = {
            'vulnerabilities': [{'type': 'XSS', 'description': 'Test vulnerability'}],
            'reflection_points': [],
            'risk_level': 'high'
        }
        
        # Test parameter again
        result = xss0r_instance._test_parameter(
            "http://example.com/?q=test", 
            "q"
        )
        
        # Check results with vulnerability
        assert result['vulnerable'] is True
        assert result['successful_payload'] is not None
    
    def test_same_domain(self, xss0r_instance):
        """Test same domain checking."""
        assert xss0r_instance._same_domain("http://example.com", "http://example.com/page") is True
        assert xss0r_instance._same_domain("http://example.com", "https://example.com") is True
        assert xss0r_instance._same_domain("http://www.example.com", "http://example.com") is True
        assert xss0r_instance._same_domain("http://example.com", "http://sub.example.com") is False
        assert xss0r_instance._same_domain("http://example.com", "http://example.org") is False

if __name__ == "__main__":
    pytest.main(["-xvs", "test_xss0r_integration.py"])
