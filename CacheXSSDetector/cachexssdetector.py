#!/usr/bin/env python3
"""
CacheXSSDetector - A comprehensive tool for detecting cache-based XSS vulnerabilities.

This is the main entry point for the CacheXSSDetector application.
"""

import argparse
import logging
import os
import sys
import yaml
from datetime import datetime

# Add the current directory to the path so we can import our modules
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

# Import core modules
from core_scanner.url_path_manipulation import URLPathManipulator
from core_scanner.cache_behavior_analysis import CacheBehaviorAnalyzer
from core_scanner.xss_payload_generator import XSSPayloadGenerator
from core_scanner.response_analyzer import ResponseAnalyzer
from request_components.http_client import HTTPClient
from verification_system.multi_client_simulator import MultiClientSimulator
from verification_system.cache_hit_miss_detector import CacheHitMissDetector
from verification_system.false_positive_reducer import FalsePositiveReducer
from reporting_module.vulnerability_classification import VulnerabilityClassifier
from reporting_module.risk_assessment import RiskAssessor
from reporting_module.enhanced_reporting_tools import ReportGenerator


def setup_logging(config):
    """
    Set up logging based on the configuration.
    
    Args:
        config (dict): The application configuration.
    """
    log_config = config.get('logging', {})
    log_level = getattr(logging, log_config.get('level', 'INFO'))
    log_format = log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Configure the root logger
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.StreamHandler() if log_config.get('console', True) else logging.NullHandler(),
            logging.FileHandler(log_config.get('file', 'logs/cachexssdetector.log'))
        ]
    )
    
    # Create the logs directory if it doesn't exist
    os.makedirs(os.path.dirname(log_config.get('file', 'logs/cachexssdetector.log')), exist_ok=True)
    
    logger = logging.getLogger('cachexssdetector')
    logger.info("Logging initialized")
    return logger


def load_config(config_path='config.yaml'):
    """
    Load the application configuration from the YAML file.
    
    Args:
        config_path (str): Path to the configuration file.
        
    Returns:
        dict: The configuration as a dictionary.
    """
    try:
        with open(config_path, 'r') as config_file:
            config = yaml.safe_load(config_file)
        return config
    except FileNotFoundError:
        print(f"Configuration file not found: {config_path}")
        print("Please create a configuration file or use the example provided.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing configuration file: {e}")
        sys.exit(1)


def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: The parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="CacheXSSDetector - A tool for detecting cache-based XSS vulnerabilities"
    )
    
    parser.add_argument('--url', '-u', type=str, help='Target URL to scan')
    parser.add_argument('--config', '-c', type=str, default='config.yaml', 
                        help='Path to the configuration file')
    parser.add_argument('--output', '-o', type=str, 
                        help='Output file for the scan report')
    parser.add_argument('--format', '-f', type=str, choices=['html', 'pdf', 'json', 'csv', 'xml'], 
                        help='Report format')
    parser.add_argument('--verbose', '-v', action='store_true', 
                        help='Enable verbose output')
    parser.add_argument('--quiet', '-q', action='store_true', 
                        help='Suppress output')
    parser.add_argument('--depth', '-d', type=int, 
                        help='Maximum scanning depth')
    parser.add_argument('--payloads', '-p', type=str, 
                        help='Path to custom XSS payloads file')
    parser.add_argument('--profile', type=str, 
                        choices=['quick', 'deep', 'stealth'], 
                        help='Use a predefined scanning profile')
    
    return parser.parse_args()


def init_components(config, args):
    """
    Initialize all components based on the configuration and command line arguments.
    
    Args:
        config (dict): The application configuration.
        args (argparse.Namespace): The command line arguments.
        
    Returns:
        dict: A dictionary containing all initialized components.
    """
    # Override config with command line arguments if provided
    scanner_config = config.get('core_scanner', {})
    if args.depth:
        scanner_config['max_depth'] = args.depth
    if args.payloads:
        scanner_config['custom_payloads_path'] = args.payloads
    
    # Initialize HTTP client
    http_client = HTTPClient(config.get('request_components', {}))
    
    # Initialize core scanner components
    url_manipulator = URLPathManipulator(scanner_config)
    cache_analyzer = CacheBehaviorAnalyzer(scanner_config)
    payload_generator = XSSPayloadGenerator(scanner_config)
    response_analyzer = ResponseAnalyzer(scanner_config)
    
    # Initialize verification system components
    verification_config = config.get('verification_system', {})
    multi_client = MultiClientSimulator(verification_config.get('multi_client', {}))
    cache_detector = CacheHitMissDetector(verification_config.get('cache_detection', {}))
    fp_reducer = FalsePositiveReducer(verification_config.get('false_positive', {}))
    
    # Initialize reporting module components
    reporting_config = config.get('reporting', {})
    report_format = args.format or reporting_config.get('default_format', 'html')
    vulnerability_classifier = VulnerabilityClassifier()
    risk_assessor = RiskAssessor()
    report_generator = ReportGenerator(reporting_config, report_format)
    
    return {
        'http_client': http_client,
        'url_manipulator': url_manipulator,
        'cache_analyzer': cache_analyzer,
        'payload_generator': payload_generator,
        'response_analyzer': response_analyzer,
        'multi_client': multi_client,
        'cache_detector': cache_detector,
        'fp_reducer': fp_reducer,
        'vulnerability_classifier': vulnerability_classifier,
        'risk_assessor': risk_assessor,
        'report_generator': report_generator
    }


def run_scan(url, components, config, logger):
    """
    Run the security scan on the target URL.
    
    Args:
        url (str): The target URL to scan.
        components (dict): The initialized components.
        config (dict): The application configuration.
        logger (logging.Logger): The logger instance.
        
    Returns:
        dict: The scan results.
    """
    logger.info(f"Starting scan of {url}")
    
    # Extract components
    http_client = components['http_client']
    url_manipulator = components['url_manipulator']
    cache_analyzer = components['cache_analyzer']
    payload_generator = components['payload_generator']
    response_analyzer = components['response_analyzer']
    multi_client = components['multi_client']
    cache_detector = components['cache_detector']
    fp_reducer = components['fp_reducer']
    
    # Step 1: Generate manipulated URLs
    logger.info("Generating manipulated URLs")
    manipulated_urls = url_manipulator.generate_urls(url)
    
    # Step 2: Generate XSS payloads
    logger.info("Generating XSS payloads")
    payloads = payload_generator.generate_payloads()
    
    # Step 3: Analyze cache behavior
    logger.info("Analyzing cache behavior")
    cache_behavior = cache_analyzer.analyze(url, http_client)
    
    # Step 4: Perform scanning with multiple clients
    logger.info("Performing multi-client scanning")
    raw_results = multi_client.simulate(manipulated_urls, payloads, http_client)
    
    # Step 5: Detect cache hits/misses
    logger.info("Detecting cache hits and misses")
    cache_results = cache_detector.detect(raw_results)
    
    # Step 6: Analyze responses for XSS
    logger.info("Analyzing responses for XSS payloads")
    xss_findings = response_analyzer.analyze(cache_results)
    
    # Step 7: Reduce false positives
    logger.info("Reducing false positives")
    verified_findings = fp_reducer.reduce(xss_findings, http_client)
    
    logger.info(f"Scan completed with {len(verified_findings)} verified findings")
    
    return {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'cache_behavior': cache_behavior,
        'findings': verified_findings
    }


def generate_report(scan_results, components, args):
    """
    Generate a report based on the scan results.
    
    Args:
        scan_results (dict): The scan results.
        components (dict): The initialized components.
        args (argparse.Namespace): The command line arguments.
        
    Returns:
        str: The path to the generated report.
    """
    # Extract components
    vulnerability_classifier = components['vulnerability_classifier']
    risk_assessor = components['risk_assessor']
    report_generator = components['report_generator']
    
    # Classify vulnerabilities
    classified_findings = vulnerability_classifier.classify(scan_results['findings'])
    
    # Assess risk
    risk_assessment = risk_assessor.assess(classified_findings)
    
    # Generate report
    report_data = {
        'url': scan_results['url'],
        'timestamp': scan_results['timestamp'],
        'cache_behavior': scan_results['cache_behavior'],
        'findings': classified_findings,
        'risk_assessment': risk_assessment
    }
    
    output_path = args.output or f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    report_path = report_generator.generate(report_data, output_path)
    
    return report_path


def main():
    """Main function."""
    # Parse arguments
    args = parse_arguments()
    
    # Load configuration
    config = load_config(args.config)
    
    # Set up logging
    logger = setup_logging(config)
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.WARNING)
    
    # Initialize components
    components = init_components(config, args)
    
    # Validate URL
    if not args.url:
        logger.error("No target URL specified. Use --url to specify a target.")
        sys.exit(1)
    
    try:
        # Run the scan
        scan_results = run_scan(args.url, components, config, logger)
        
        # Generate report
        report_path = generate_report(scan_results, components, args)
        
        logger.info(f"Report generated: {report_path}")
        print(f"Report generated: {report_path}")
        
    except Exception as e:
        logger.exception(f"An error occurred during the scan: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
