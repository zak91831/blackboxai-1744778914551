#!/usr/bin/env python3
"""
Test Script for Advanced XSS Detector

This script runs the Advanced XSS Detector against example.com to demonstrate
its capabilities in detecting potential XSS vulnerabilities.
"""

import os
import sys
import logging
import json
import requests
from datetime import datetime

# Add the project directory to the path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import required components
from core_scanner.advanced_xss_detector import AdvancedXSSDetector

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('xss_test')

def fetch_url(url, headers=None, params=None):
    """
    Fetch a URL and return the response.
    
    Args:
        url (str): The URL to fetch
        headers (dict): Optional headers to include
        params (dict): Optional query parameters
        
    Returns:
        dict: Response data including headers, body, and status code
    """
    try:
        headers = headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        return {
            'body': response.text,
            'headers': dict(response.headers),
            'status_code': response.status_code,
            'url': response.url
        }
    except Exception as e:
        logger.error(f"Error fetching URL {url}: {str(e)}")
        return {
            'body': '',
            'headers': {},
            'status_code': 0,
            'error': str(e)
        }

def test_url_with_payloads(url, payloads, detector):
    """
    Test a URL with a list of XSS payloads.
    
    Args:
        url (str): The base URL to test
        payloads (list): List of payload strings to try
        detector (AdvancedXSSDetector): The detector instance
        
    Returns:
        dict: Test results
    """
    results = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'tests_run': 0,
        'vulnerabilities_found': 0,
        'analysis': []
    }
    
    logger.info(f"Testing URL: {url}")
    
    # First, test the base URL
    base_response = fetch_url(url)
    base_analysis = detector.analyze_response(url, base_response)
    results['base_analysis'] = base_analysis
    
    # Count any vulnerabilities in the base page
    if base_analysis.get('vulnerabilities'):
        results['vulnerabilities_found'] += len(base_analysis['vulnerabilities'])
    
    # Now test with payloads
    for i, payload in enumerate(payloads):
        logger.info(f"Testing payload {i+1}/{len(payloads)}: {payload[:30]}...")
        
        # Create test URL with payload
        test_url = f"{url}?xss={payload}"
        response = fetch_url(test_url)
        
        # Analyze the response
        analysis = detector.analyze_response(test_url, response)
        
        # Count vulnerabilities
        if analysis.get('vulnerabilities'):
            results['vulnerabilities_found'] += len(analysis['vulnerabilities'])
        
        # Add to results
        results['tests_run'] += 1
        results['analysis'].append({
            'payload': payload,
            'test_url': test_url,
            'status_code': response['status_code'],
            'vulnerabilities': analysis.get('vulnerabilities', []),
            'reflection_points': analysis.get('reflection_points', []),
            'risk_level': analysis.get('risk_level', 'unknown')
        })
    
    return results

def main():
    """Main function to run the test."""
    # Initialize the detector
    config = {
        'max_detection_depth': 3,
        'enable_machine_learning': False,
        'detection_timeout': 60,
        'analyze_dom': True
    }
    detector = AdvancedXSSDetector(config)
    
    # Target URL
    target_url = "https://example.com"
    
    # Generate test payloads for different contexts
    html_payloads = detector.generate_context_aware_payloads('html_body', max_payloads=3)
    attribute_payloads = detector.generate_context_aware_payloads('html_attribute', max_payloads=3)
    script_payloads = detector.generate_context_aware_payloads('script_context', max_payloads=3)
    
    # Extract payload content
    payloads = [p['content'] for p in html_payloads]
    payloads.extend([p['content'] for p in attribute_payloads])
    payloads.extend([p['content'] for p in script_payloads])
    
    # Add some DOM-based payloads
    for dom_payload in detector.dom_based_payloads:
        payloads.append(dom_payload['payload'])
    
    # Run the test
    results = test_url_with_payloads(target_url, payloads, detector)
    
    # Output the results
    print("\n\n==== TEST RESULTS ====")
    print(f"Target URL: {results['url']}")
    print(f"Tests Run: {results['tests_run']}")
    print(f"Potential Vulnerabilities Found: {results['vulnerabilities_found']}")
    print(f"Risk Level: {results.get('base_analysis', {}).get('risk_level', 'unknown')}")
    
    # Print vulnerability details if found
    if results['vulnerabilities_found'] > 0:
        print("\n==== VULNERABILITIES ====")
        for i, test in enumerate(results['analysis']):
            if test['vulnerabilities']:
                print(f"\nTest {i+1}: {test['test_url']}")
                print(f"Risk Level: {test['risk_level']}")
                for vuln in test['vulnerabilities']:
                    print(f"  - Type: {vuln.get('type')}")
                    print(f"    Description: {vuln.get('description')}")
                    print(f"    Risk Level: {vuln.get('risk_level')}")
    
    # Print recommendations
    if 'recommendation' in results.get('base_analysis', {}):
        print("\n==== RECOMMENDATIONS ====")
        print(results['base_analysis']['recommendation'])
    
    # Save detailed results to file
    with open('example_com_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nDetailed results saved to example_com_test_results.json")

if __name__ == "__main__":
    main()
