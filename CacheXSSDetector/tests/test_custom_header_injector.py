"""
Test Module for Custom Header Injector

This module contains tests for the CustomHeaderInjector functionality.
"""

import pytest
import os
import sys
import json
from unittest.mock import Mock, patch, MagicMock

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core_scanner.custom_header_injector import CustomHeaderInjector
from core_scanner.waf_bypass import WAFBypass

class TestCustomHeaderInjector:
    """Tests for the CustomHeaderInjector module."""
    
    @pytest.fixture
    def header_injector(self):
        """Create a CustomHeaderInjector instance for testing."""
        return CustomHeaderInjector()
    
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
    
    def test_initialization(self, header_injector):
        """Test initialization of the CustomHeaderInjector."""
        assert header_injector is not None
        assert isinstance(header_injector.reflectable_headers, list)
        assert len(header_injector.reflectable_headers) > 0
        assert isinstance(header_injector.header_payloads, list)
        assert len(header_injector.header_payloads) > 0
    
    def test_generate_malicious_headers_basic(self, header_injector):
        """Test generation of malicious headers without WAF bypass."""
        headers = header_injector.generate_malicious_headers()
        
        # Check we have headers for testing
        assert len(headers) > 0
        
        # Check structure of first header
        first_header = headers[0]
        assert 'header_name' in first_header
        assert 'payload' in first_header
        assert 'headers' in first_header
        
        # Check headers dictionary contains expected header
        assert first_header['header_name'] in first_header['headers']
        assert first_header['payload'] == first_header['headers'][first_header['header_name']]
        
        # Check we have necessary standard headers
        assert 'Accept' in first_header['headers']
        assert 'Connection' in first_header['headers']
    
    def test_generate_malicious_headers_with_waf_bypass(self, header_injector, mock_waf_bypass):
        """Test generation of malicious headers with WAF bypass."""
        headers = header_injector.generate_malicious_headers(mock_waf_bypass)
        
        # Find a header with bypass technique
        bypass_headers = [h for h in headers if 'technique' in h]
        assert len(bypass_headers) > 0
        
        # Check structure
        bypass_header = bypass_headers[0]
        assert 'header_name' in bypass_header
        assert 'payload' in bypass_header
        assert 'technique' in bypass_header
        assert 'headers' in bypass_header
        
        # Check technique is from our mock
        assert bypass_header['technique'] in ['case_mutation', 'encoding_mutation']
    
    def test_analyze_header_reflection_direct(self, header_injector):
        """Test detection of direct header reflection."""
        payload = '<script>alert("XSS")</script>'
        response_text = f"""
        <html>
        <head><title>Test</title></head>
        <body>
        <div>Your User-Agent: {payload}</div>
        </body>
        </html>
        """
        
        result = header_injector.analyze_header_reflection(response_text, payload)
        
        assert result['reflected'] is True
        assert result['potentially_exploitable'] is True
    
    def test_analyze_header_reflection_encoded(self, header_injector):
        """Test detection of encoded header reflection."""
        payload = '<script>alert("XSS")</script>'
        encoded = '<script>alert("XSS")</script>'
        response_text = f"""
        <html>
        <head><title>Test</title></head>
        <body>
        <div>Your User-Agent: {encoded}</div>
        </body>
        </html>
        """
        
        result = header_injector.analyze_header_reflection(response_text, payload)
        
        assert result['reflected'] is False
        assert result['encoded_reflected'] is True
        assert result['potentially_exploitable'] is False
        assert result['needs_manual_verification'] is True
    
    def test_analyze_header_reflection_partial(self, header_injector):
        """Test detection of partial header reflection."""
        payload = '<script>alert("XSS")</script>'
        response_text = f"""
        <html>
        <head><title>Test</title></head>
        <body>
        <div>Your input: alert("XSS")</div>
        </body>
        </html>
        """
        
        result = header_injector.analyze_header_reflection(response_text, payload)
        
        assert result['reflected'] is False
        assert result['partial_reflection'] is True
        assert result['potentially_exploitable'] is False
        assert result['needs_manual_verification'] is True


if __name__ == "__main__":
    pytest.main(["-xvs", "test_custom_header_injector.py"])
