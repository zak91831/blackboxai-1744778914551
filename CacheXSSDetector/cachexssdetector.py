#!/usr/bin/env python3
"""
CacheXSSDetector - A security scanner for detecting cache-based XSS vulnerabilities

This tool identifies Cross-Site Scripting (XSS) vulnerabilities that can be exploited
through caching mechanisms in web applications and CDNs.
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import core components
from CacheXSSDetector.core_scanner import CoreScanner
from CacheXSSDetector.verification_system import VerificationSystem
from CacheXSSDetector.reporting_module import ReportGenerator, RiskAssessor
from CacheXSSDetector.reporting_module.vulnerability_classification import VulnerabilityClassifier

# Constants
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config', 'default_config.json')
DEFAULT_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'reports')
DEFAULT_LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')

class CacheXSSDetector:
    """
    Main class for the Cache-based XSS Detector tool.
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the Cache-based XSS Detector.
        
        Args:
            config_path (str, optional): Path to configuration file.
        """
        # Set up configuration
        self.config = self._load_config(config_path or DEFAULT_CONFIG_PATH)
        
        # Set up logging
        self._setup_logging()
        
        # Initialize components
        self.core_scanner = CoreScanner(self.config.get('core_scanner', {}))
        self.verification_system = VerificationSystem(self.config.get('verification', {}))
        self.risk_assessor = RiskAssessor(self.config.get('risk_assessment', {}))
        self.vuln_classifier = VulnerabilityClassifier(self.config.get('classification', {}))
        self.report_generator = ReportGenerator(self.config.get('reporting', {}))
        
        self.logger.info("CacheXSSDetector initialized")
    
    def _load_config(self, config_path: str) -> Dict:
        """
        Load configuration from file.
        
        Args:
            config_path (str): Path to configuration file.
            
        Returns:
            dict: Configuration settings.
        """
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Use default configuration if file not found
            return config
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading configuration: {e}")
            print("Using default configuration.")
            return {}
    
    def _setup_logging(self):
        """Set up logging configuration."""
        log_level = getattr(logging, self.config.get('log_level', 'INFO'))
        log_file = os.path.join(
            self.config.get('log_dir', DEFAULT_LOG_DIR),
            f"cachexss_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        
        # Create log directory if it doesn't exist
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Configure root logger
        self.logger = logging.getLogger('cachexssdetector')
        self.logger.setLevel(log_level)
        
        # Create file handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        
        # Create formatter and add to handlers
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
    
    async def scan_target(self, target_url: str, options: Optional[Dict] = None) -> Dict:
        """
        Scan a target URL for cache-based XSS vulnerabilities.
        
        Args:
            target_url (str): Target URL to scan.
            options (dict, optional): Scan options.
            
        Returns:
            dict: Scan results.
        """
        results = {
            'target_url': target_url,
            'scan_start_time': datetime.now().isoformat(),
            'findings': [],
            'verified_findings': [],
            'risk_assessment': {},
            'scan_duration': 0
        }
        
        start_time = time.time()
        
        try:
            self.logger.info(f"Starting scan of {target_url}")
            
            # Perform core scanning
            scan_results = await self.core_scanner.scan_target(target_url, options)
            
            # Verify findings
            if scan_results.get('findings'):
                verification_results = await self.verification_system.verify_batch(scan_results['findings'])
                results['verified_findings'] = verification_results.get('verified_findings', [])
                
                self.logger.info(
                    f"Verified {len(results['verified_findings'])} of {len(scan_results['findings'])} findings"
                )
            
            # Assess risk
            if results['verified_findings']:
                findings_for_assessment = [f['finding'] for f in results['verified_findings']]
                risk_assessment = self.risk_assessor.assess_batch(findings_for_assessment)
                results['risk_assessment'] = risk_assessment
                
                # Classify vulnerabilities
                classification_results = self.vuln_classifier.classify_batch(findings_for_assessment)
                results['vulnerability_classification'] = classification_results
                
                # Combine findings with classifications and risk assessments
                processed_findings = []
                for i, finding in enumerate(findings_for_assessment):
                    processed_finding = finding.copy()
                    
                    # Add risk assessment
                    if i < len(risk_assessment.get('highest_risks', [])):
                        processed_finding['risk_assessment'] = risk_assessment['highest_risks'][i]
                    
                    # Add classification
                    if i < len(classification_results.get('classifications', [])):
                        processed_finding['classification'] = classification_results['classifications'][i]['classification']
                    
                    processed_findings.append(processed_finding)
                
                results['findings'] = processed_findings
            
            results['scan_status'] = 'completed'
            
        except Exception as e:
            error_msg = f"Error during scan: {str(e)}"
            self.logger.error(error_msg)
            results['scan_status'] = 'error'
            results['error'] = error_msg
        
        # Calculate scan duration
        results['scan_duration'] = time.time() - start_time
        results['scan_end_time'] = datetime.now().isoformat()
        
        self.logger.info(
            f"Scan completed in {results['scan_duration']:.2f} seconds. "
            f"Found {len(results['findings'])} verified vulnerabilities."
        )
        
        return results
    
    async def scan_targets(self, targets: List[str], options: Optional[Dict] = None) -> Dict:
        """
        Scan multiple targets.
        
        Args:
            targets (list): List of target URLs to scan.
            options (dict, optional): Scan options.
            
        Returns:
            dict: Aggregated scan results.
        """
        aggregated_results = {
            'targets': targets,
            'scan_start_time': datetime.now().isoformat(),
            'results': [],
            'summary': {
                'total_targets': len(targets),
                'total_findings': 0,
                'risk_levels': {}
            },
            'scan_duration': 0
        }
        
        start_time = time.time()
        
        try:
            for target in targets:
                result = await self.scan_target(target, options)
                aggregated_results['results'].append(result)
                
                # Update summary statistics
                aggregated_results['summary']['total_findings'] += len(result.get('findings', []))
                
                # Update risk level counts
                risk_assessment = result.get('risk_assessment', {})
                for level, count in risk_assessment.get('risk_levels', {}).items():
                    if level in aggregated_results['summary']['risk_levels']:
                        aggregated_results['summary']['risk_levels'][level] += count
                    else:
                        aggregated_results['summary']['risk_levels'][level] = count
        
        except Exception as e:
            error_msg = f"Error during batch scan: {str(e)}"
            self.logger.error(error_msg)
            aggregated_results['error'] = error_msg
        
        # Calculate scan duration
        aggregated_results['scan_duration'] = time.time() - start_time
        aggregated_results['scan_end_time'] = datetime.now().isoformat()
        
        self.logger.info(
            f"Batch scan completed in {aggregated_results['scan_duration']:.2f} seconds. "
            f"Found {aggregated_results['summary']['total_findings']} vulnerabilities "
            f"across {len(targets)} targets."
        )
        
        return aggregated_results
    
    def generate_report(self, scan_results: Dict, output_path: Optional[str] = None) -> str:
        """
        Generate a security report from scan results.
        
        Args:
            scan_results (dict): Scan results to report on.
            output_path (str, optional): Path to save the report.
            
        Returns:
            str: Path to the generated report.
        """
        try:
            self.logger.info("Generating security report")
            
            # Prepare report data
            metadata = {
                'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'generator': 'CacheXSSDetector',
                'version': getattr(self, '__version__', '1.0.0'),
                'scan_duration': scan_results.get('scan_duration', 0)
            }
            
            # Determine output path
            if not output_path:
                output_dir = self.config.get('output_dir', DEFAULT_OUTPUT_DIR)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_path = os.path.join(output_dir, f"cachexss_report_{timestamp}.html")
            
            # Create output directory if it doesn't exist
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Generate report
            report_path = self.report_generator.generate_report(
                {
                    'findings': scan_results.get('findings', []),
                    'summary': scan_results.get('risk_assessment', {}).get('summary', {}),
                    'metadata': metadata,
                    'include_charts': True,
                    'level_colors': {
                        'critical': 'red',
                        'high': 'orange', 
                        'medium': 'yellow',
                        'low': 'blue',
                        'info': 'gray'
                    },
                    'severity_colors': {
                        'critical': 'red',
                        'high': 'orange', 
                        'medium': 'yellow',
                        'low': 'blue',
                        'info': 'gray'
                    }
                },
                output_path
            )
            
            self.logger.info(f"Report generated: {report_path}")
            return report_path
            
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            raise

def main():
    """Main entry point for the CacheXSSDetector tool."""
    parser = argparse.ArgumentParser(description="CacheXSSDetector - A security scanner for detecting cache-based XSS vulnerabilities")
    
    parser.add_argument('-t', '--target', help="Target URL to scan")
    parser.add_argument('-f', '--file', help="File containing list of target URLs")
    parser.add_argument('-c', '--config', help="Path to configuration file")
    parser.add_argument('-o', '--output', help="Path to save the report")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
    parser.add_argument('--version', action='store_true', help="Show version information")
    
    args = parser.parse_args()
    
    # Show version information
    if args.version:
        print("CacheXSSDetector v1.0.0")
        return 0
    
    # Check if target or file is provided
    if not args.target and not args.file:
        parser.print_help()
        print("\nError: You must specify a target URL (-t) or a file containing targets (-f).")
        return 1
    
    try:
        # Initialize detector
        detector = CacheXSSDetector(args.config)
        
        # Get targets
        targets = []
        if args.target:
            targets.append(args.target)
        
        if args.file:
            with open(args.file, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        
        # Configure scan options
        scan_options = {
            'verbose': args.verbose
        }
        
        # Run scan
        if len(targets) == 1:
            # Single target scan
            scan_results = asyncio.run(detector.scan_target(targets[0], scan_options))
        else:
            # Multiple targets scan
            scan_results = asyncio.run(detector.scan_targets(targets, scan_options))
        
        # Generate report
        report_path = detector.generate_report(scan_results, args.output)
        
        print(f"\nScan completed. Report saved to: {report_path}")
        return 0
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        return 130
    except Exception as e:
        print(f"\nError: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
