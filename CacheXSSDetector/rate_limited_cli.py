#!/usr/bin/env python3
"""
Rate-Limited XSS0r Command Line Interface

This script provides a command-line interface for the Rate-Limited XSS0r integration module,
allowing users to easily scan websites for XSS vulnerabilities with adaptive rate limiting.
"""

import os
import sys
import logging
import json
import argparse
import time
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('rate_limited_cli')

# Import our modules
from core_scanner.advanced_xss_detector import AdvancedXSSDetector
from core_scanner.waf_bypass import WAFBypass
from core_scanner.rate_limited_xss0r import RateLimitedXSS0rIntegration

def setup_args():
    """Set up command line arguments."""
    parser = argparse.ArgumentParser(
        description='Rate-Limited XSS0r - Advanced XSS Scanner with Adaptive Rate Limiting and WAF Bypass'
    )
    
    # Target options
    parser.add_argument(
        'url',
        help='Target URL to scan (e.g., http://example.com)'
    )
    
    # Scanning options
    parser.add_argument(
        '--depth', 
        type=int, 
        default=2,
        help='Maximum crawl depth (default: 2)'
    )
    parser.add_argument(
        '--max-urls', 
        type=int, 
        default=50,
        help='Maximum URLs to scan per domain (default: 50)'
    )
    
    # Performance & Rate Limiting options
    parser.add_argument(
        '--delay', 
        type=float, 
        default=1.0,
        help='Base delay between requests in seconds (default: 1.0)'
    )
    parser.add_argument(
        '--timeout', 
        type=int, 
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    parser.add_argument(
        '--rate-limit', 
        type=int, 
        default=60,
        help='Maximum requests per minute (default: 60)'
    )
    parser.add_argument(
        '--disable-adaptive', 
        action='store_false',
        dest='adaptive',
        help='Disable adaptive rate limiting'
    )
    
    # Testing options
    parser.add_argument(
        '--no-forms', 
        action='store_false', 
        dest='test_forms',
        help='Disable form testing'
    )
    parser.add_argument(
        '--no-headers', 
        action='store_false', 
        dest='test_headers',
        help='Disable header testing'
    )
    parser.add_argument(
        '--header-tests', 
        type=int, 
        default=3,
        help='Number of header tests per URL (default: 3)'
    )
    parser.add_argument(
        '--no-cookies', 
        action='store_false', 
        dest='test_cookies',
        help='Disable cookie testing'
    )
    parser.add_argument(
        '--no-dom', 
        action='store_false', 
        dest='test_dom',
        help='Disable DOM-based XSS testing'
    )
    
    # Output options
    parser.add_argument(
        '--output', 
        help='Output file for scan results (JSON format)'
    )
    parser.add_argument(
        '--verbose', 
        action='store_true',
        help='Enable verbose output'
    )
    
    # Advanced options
    parser.add_argument(
        '--blind-xss', 
        action='store_true',
        help='Enable blind XSS testing'
    )
    parser.add_argument(
        '--callback-url',
        default='https://your-callback-server.com/callback',
        help='Callback URL for blind XSS testing'
    )
    
    return parser.parse_args()

def print_banner():
    """Print the Rate-Limited XSS0r banner."""
    banner = r"""
 __   __  _______  _______  _______  ______   
| |  | | (  ____ \/ ___   )/ ___   )(  __  \  
| |  | | | (    \/\/   )  |\/   )  || (  \  ) 
\_|/\/ /| (_____     /   )    /   )|| |   ) | 
  |  |/ |_____  )   /   /    /   / | |   | | 
  |  |        ) |  /   /    /   /  | |   ) | 
 /|__|\ /\____) | /   (_/\ /   (_/\| (__/  )
\_____/ \_______)(_______(________)(__
  Advanced XSS Scanner with Rate Limiting & WAF Bypass
    """
    print(banner)
    print("\nCacheXSSDetector Rate-Limited XSS0r Integration Module\n")

def print_scan_summary(results):
    """Print a summary of the scan results."""
    print("\n====== SCAN SUMMARY ======")
    print(f"Target URL: {results['start_url']}")
    print(f"URLs Scanned: {results['urls_scanned']}")
    print(f"Forms Tested: {results['forms_tested']}")
    print(f"Headers Tested: {results.get('headers_tested', 0)}")
    print(f"Vulnerabilities Found: {results['vulnerabilities_found']}")
    
    # Print rate limiting stats if available
    if 'rate_limiting' in results:
        print("\n====== RATE LIMITING STATS ======")
        rate_info = results['rate_limiting']
        print(f"Requests Made: {rate_info.get('requests_made', 'N/A')}")
        print(f"Final Delay: {rate_info.get('current_delay', 'N/A')}s")
        print(f"Adaptive Status: {rate_info.get('adaptive_status', 'N/A')}")
    
    if results['vulnerabilities_found'] > 0:
        print("\n====== VULNERABILITIES ======")
        for i, vuln in enumerate(results.get('vulnerabilities', [])):
            print(f"\n[{i+1}] {vuln.get('url', 'Unknown URL')}")
            
            if vuln.get('parameter'):
                print(f"    Parameter: {vuln['parameter']}")
            elif vuln.get('vulnerable_input'):
                print(f"    Form Input: {vuln['vulnerable_input']}")
            elif vuln.get('successful_header'):
                print(f"    Header: {vuln['successful_header']}")
            
            print(f"    Payload: {vuln.get('successful_payload', 'Unknown')}")
            
            # Determine vulnerability type
            if vuln.get('parameter'):
                vuln_type = 'Parameter'
            elif vuln.get('vulnerable_input'):
                vuln_type = 'Form'
            elif vuln.get('successful_header'):
                vuln_type = 'HTTP Header'
            else:
                vuln_type = 'DOM'
                
            print(f"    Type: {vuln_type}")
    
    print("\n====== RECOMMENDATIONS ======")
    print("1. Implement proper input validation and output encoding")
    print("2. Use Content Security Policy (CSP) headers")
    print("3. Use modern frameworks with built-in XSS protection")
    print("4. Apply the principle of least privilege for JavaScript")
    print("5. Regularly scan and test for XSS vulnerabilities")

def main():
    """Main function."""
    print_banner()
    
    # Parse arguments
    args = setup_args()
    
    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate URL
    target_url = args.url
    if not (target_url.startswith('http://') or target_url.startswith('https://')):
        target_url = 'http://' + target_url
        logger.info(f"Added http:// prefix to URL: {target_url}")
    
    # Check dependencies
    try:
        import bs4
    except ImportError:
        logger.error("BeautifulSoup4 is required. Install it with: pip install beautifulsoup4")
        return 1
    
    try:
        import pyppeteer
        headless_support = True
    except ImportError:
        logger.warning("Pyppeteer not found. DOM-based XSS testing will be disabled.")
        logger.warning("Install it with: pip install pyppeteer")
        headless_support = False
        args.test_dom = False
    
    # Initialize components
    logger.info("Initializing scanner components...")
    
    # Configure the components
    detector_config = {
        'max_detection_depth': 3,
        'enable_machine_learning': False,
        'detection_timeout': 60,
        'analyze_dom': args.test_dom
    }
    
    xss0r_config = {
        'max_depth': args.depth,
        'max_urls_per_domain': args.max_urls,
        'crawl_delay': args.delay,
        'test_forms': args.test_forms,
        'test_headers': args.test_headers,
        'test_cookies': args.test_cookies,
        'test_dom': args.test_dom and headless_support,
        'blind_xss_enabled': args.blind_xss,
        'callback_url': args.callback_url,
        'header_tests_per_url': args.header_tests,
        'timeout': args.timeout,
        'rate_limit_rpm': args.rate_limit
    }
    
    # Initialize components
    xss_detector = AdvancedXSSDetector(detector_config)
    waf_bypass = WAFBypass()
    scanner = RateLimitedXSS0rIntegration(xss0r_config)
    
    # Set detectors
    scanner.set_detectors(xss_detector, waf_bypass)
    
    # Start the scan
    logger.info(f"Starting rate-limited scan on {target_url}...")
    logger.info(f"Rate limiting set to {args.rate_limit} requests/minute with {'adaptive' if args.adaptive else 'fixed'} timing")
    start_time = time.time()
    
    try:
        # Run the scan
        results = scanner.crawl(target_url)  # First just crawl to test
        
        # Now do the full scan
        results = scanner.scan_site(target_url)
        
        # Calculate scan duration
        scan_duration = time.time() - start_time
        results['scan_duration'] = scan_duration
        
        # Add metadata
        results['scan_time'] = datetime.now().isoformat()
        results['xss0r_version'] = '1.1.0'
        results['rate_limited'] = True
        
        # Print summary
        print_scan_summary(results)
        
        # Save results if output file specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results saved to {args.output}")
        
        logger.info(f"Scan completed in {scan_duration:.2f} seconds")
        
        return 0
        
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
