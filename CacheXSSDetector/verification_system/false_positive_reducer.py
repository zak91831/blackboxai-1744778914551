"""
False Positive Reducer Module

This module implements techniques to reduce false positives in cache-based XSS
detection by verifying vulnerabilities through multiple validation steps.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
import re
import hashlib
import time
from datetime import datetime
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode

class FalsePositiveReducer:
    """
    A class to reduce false positives in vulnerability detection.
    """
    
    def __init__(self, config):
        """
        Initialize the False Positive Reducer.
        
        Args:
            config (dict): Configuration settings for false positive reduction.
        """
        self.logger = logging.getLogger('cachexssdetector.false_positive_reducer')
        self.config = config
        
        # Validation configuration
        self.min_confidence = config.get('min_confidence', 0.8)
        self.verification_rounds = config.get('verification_rounds', 3)
        self.timeout = config.get('timeout', 30)
        
        # Initialize validation patterns
        self._init_patterns()
        
        self.logger.info("False Positive Reducer initialized")
    
    def _init_patterns(self):
        """Initialize validation patterns and rules."""
        # XSS validation patterns
        self.xss_patterns = {
            'reflection': [
                r'<script[^>]*>.*?</script>',
                r'javascript:.*?[(]',
                r'on\w+\s*=\s*["\'][^"\']*["\']'
            ],
            'encoding': [
                r'%3Cscript',
                r'\\x3Cscript',
                r'<script'
            ],
            'context': [
                r'<[^>]*=.*?>',
                r'href\s*=\s*["\'][^"\']*["\']',
                r'src\s*=\s*["\'][^"\']*["\']'
            ]
        }
        
        # Cache validation rules
        self.cache_rules = {
            'headers': [
                'cache-control',
                'etag',
                'last-modified',
                'expires'
            ],
            'indicators': [
                'x-cache',
                'cf-cache-status',
                'age'
            ],
            'behaviors': [
                'public',
                'private',
                'no-cache',
                'must-revalidate'
            ]
        }
        
        # Validation thresholds
        self.thresholds = {
            'reflection_confidence': 0.8,
            'cache_confidence': 0.7,
            'timing_variance': 0.3
        }
    
    def verify_vulnerability(
        self,
        finding: Dict,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Verify a potential vulnerability finding.
        
        Args:
            finding (dict): Vulnerability finding to verify.
            context (dict, optional): Additional context information.
            
        Returns:
            dict: Verification results.
        """
        verification = {
            'verified': False,
            'confidence': 0.0,
            'validations': [],
            'false_positive_indicators': []
        }
        
        try:
            # Perform multiple validation rounds
            for round_num in range(self.verification_rounds):
                validation = self._perform_validation_round(
                    finding,
                    round_num,
                    context
                )
                verification['validations'].append(validation)
            
            # Analyze validation results
            analysis = self._analyze_validations(verification['validations'])
            verification.update(analysis)
            
            # Check for false positive indicators
            fp_indicators = self._check_false_positive_indicators(
                finding,
                verification
            )
            verification['false_positive_indicators'] = fp_indicators
            
            # Make final determination
            if (verification['confidence'] >= self.min_confidence and
                not verification['false_positive_indicators']):
                verification['verified'] = True
            
        except Exception as e:
            self.logger.error(f"Error verifying vulnerability: {str(e)}")
        
        return verification
    
    def verify_batch(
        self,
        findings: List[Dict],
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Verify a batch of vulnerability findings.
        
        Args:
            findings (list): List of findings to verify.
            context (dict, optional): Additional context information.
            
        Returns:
            dict: Batch verification results.
        """
        batch_results = {
            'total': len(findings),
            'verified': 0,
            'false_positives': 0,
            'verified_findings': [],
            'false_positives_findings': [],
            'statistics': {}
        }
        
        try:
            for finding in findings:
                verification = self.verify_vulnerability(finding, context)
                
                if verification['verified']:
                    batch_results['verified'] += 1
                    batch_results['verified_findings'].append({
                        'finding': finding,
                        'verification': verification
                    })
                else:
                    batch_results['false_positives'] += 1
                    batch_results['false_positives_findings'].append({
                        'finding': finding,
                        'verification': verification
                    })
            
            # Calculate statistics
            batch_results['statistics'] = self._calculate_batch_statistics(
                batch_results
            )
            
        except Exception as e:
            self.logger.error(f"Error in batch verification: {str(e)}")
        
        return batch_results
    
    def _perform_validation_round(
        self,
        finding: Dict,
        round_num: int,
        context: Optional[Dict]
    ) -> Dict:
        """
        Perform a single validation round.
        
        Args:
            finding (dict): Finding to validate.
            round_num (int): Validation round number.
            context (dict, optional): Additional context.
            
        Returns:
            dict: Validation round results.
        """
        validation = {
            'round': round_num,
            'timestamp': datetime.now(),
            'tests': [],
            'confidence': 0.0
        }
        
        # Generate unique validation payload
        payload = self._generate_validation_payload(finding, round_num)
        
        # Perform validation tests
        validation['tests'].extend([
            self._validate_reflection(finding, payload),
            self._validate_cache_behavior(finding, payload),
            self._validate_context(finding, payload),
            self._validate_timing(finding, payload)
        ])
        
        # Calculate round confidence
        validation['confidence'] = self._calculate_validation_confidence(
            validation['tests']
        )
        
        return validation
    
    def _generate_validation_payload(
        self,
        finding: Dict,
        round_num: int
    ) -> Dict:
        """
        Generate unique validation payload.
        
        Args:
            finding (dict): Original finding.
            round_num (int): Validation round number.
            
        Returns:
            dict: Validation payload.
        """
        # Generate unique identifier
        unique_id = hashlib.md5(
            f"{finding['id']}_{round_num}_{time.time()}".encode()
        ).hexdigest()[:8]
        
        # Base payload from finding
        base_payload = finding.get('payload', {}).copy()
        
        # Add validation markers
        validation_markers = {
            'id': unique_id,
            'round': round_num,
            'timestamp': int(time.time())
        }
        
        # Modify payload for validation
        payload = {
            'content': self._modify_payload_content(
                base_payload.get('content', ''),
                validation_markers
            ),
            'parameters': self._modify_payload_parameters(
                base_payload.get('parameters', {}),
                validation_markers
            ),
            'markers': validation_markers
        }
        
        return payload
    
    def _modify_payload_content(
        self,
        content: str,
        markers: Dict
    ) -> str:
        """
        Modify payload content with validation markers.
        
        Args:
            content (str): Original content.
            markers (dict): Validation markers.
            
        Returns:
            str: Modified content.
        """
        # Add comment with markers
        marker_comment = f"<!--validation:{markers['id']}-->"
        
        # Add unique attributes to elements
        content = re.sub(
            r'(<[^>]+)',
            f'\\1 data-validation="{markers["id"]}"',
            content
        )
        
        return f"{marker_comment}{content}"
    
    def _modify_payload_parameters(
        self,
        parameters: Dict,
        markers: Dict
    ) -> Dict:
        """
        Modify payload parameters with validation markers.
        
        Args:
            parameters (dict): Original parameters.
            markers (dict): Validation markers.
            
        Returns:
            dict: Modified parameters.
        """
        modified = parameters.copy()
        
        # Add validation parameters
        modified.update({
            'validation_id': markers['id'],
            'validation_round': markers['round'],
            'validation_time': markers['timestamp']
        })
        
        return modified
    
    def _validate_reflection(
        self,
        finding: Dict,
        payload: Dict
    ) -> Dict:
        """
        Validate payload reflection characteristics.
        
        Args:
            finding (dict): Finding to validate.
            payload (dict): Validation payload.
            
        Returns:
            dict: Reflection validation results.
        """
        validation = {
            'type': 'reflection',
            'passed': False,
            'confidence': 0.0,
            'details': []
        }
        
        content = finding.get('response', {}).get('content', '')
        
        # Check for payload markers
        if payload['markers']['id'] in content:
            validation['details'].append({
                'type': 'marker_found',
                'confidence': 0.9
            })
        
        # Check reflection patterns
        for pattern_type, patterns in self.xss_patterns['reflection'].items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.I)
                for match in matches:
                    if payload['markers']['id'] in match.group():
                        validation['details'].append({
                            'type': 'pattern_match',
                            'pattern': pattern_type,
                            'confidence': 0.8
                        })
        
        # Calculate validation confidence
        if validation['details']:
            validation['confidence'] = max(
                detail['confidence']
                for detail in validation['details']
            )
            validation['passed'] = validation['confidence'] >= self.thresholds['reflection_confidence']
        
        return validation
    
    def _validate_cache_behavior(
        self,
        finding: Dict,
        payload: Dict
    ) -> Dict:
        """
        Validate cache behavior characteristics.
        
        Args:
            finding (dict): Finding to validate.
            payload (dict): Validation payload.
            
        Returns:
            dict: Cache behavior validation results.
        """
        validation = {
            'type': 'cache_behavior',
            'passed': False,
            'confidence': 0.0,
            'details': []
        }
        
        headers = finding.get('response', {}).get('headers', {})
        
        # Check cache headers
        for header in self.cache_rules['headers']:
            if header in headers:
                validation['details'].append({
                    'type': 'cache_header',
                    'header': header,
                    'value': headers[header],
                    'confidence': 0.7
                })
        
        # Check cache indicators
        for indicator in self.cache_rules['indicators']:
            if indicator in headers:
                validation['details'].append({
                    'type': 'cache_indicator',
                    'indicator': indicator,
                    'value': headers[indicator],
                    'confidence': 0.8
                })
        
        # Check cache behaviors
        cache_control = headers.get('cache-control', '').lower()
        for behavior in self.cache_rules['behaviors']:
            if behavior in cache_control:
                validation['details'].append({
                    'type': 'cache_behavior',
                    'behavior': behavior,
                    'confidence': 0.6
                })
        
        # Calculate validation confidence
        if validation['details']:
            validation['confidence'] = max(
                detail['confidence']
                for detail in validation['details']
            )
            validation['passed'] = validation['confidence'] >= self.thresholds['cache_confidence']
        
        return validation
    
    def _validate_context(
        self,
        finding: Dict,
        payload: Dict
    ) -> Dict:
        """
        Validate execution context characteristics.
        
        Args:
            finding (dict): Finding to validate.
            payload (dict): Validation payload.
            
        Returns:
            dict: Context validation results.
        """
        validation = {
            'type': 'context',
            'passed': False,
            'confidence': 0.0,
            'details': []
        }
        
        content = finding.get('response', {}).get('content', '')
        
        # Check context patterns
        for pattern_type, patterns in self.xss_patterns['context'].items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.I)
                for match in matches:
                    context = self._extract_context(content, match.span())
                    if payload['markers']['id'] in context:
                        validation['details'].append({
                            'type': 'context_match',
                            'pattern': pattern_type,
                            'context': context,
                            'confidence': 0.8
                        })
        
        # Calculate validation confidence
        if validation['details']:
            validation['confidence'] = max(
                detail['confidence']
                for detail in validation['details']
            )
            validation['passed'] = validation['confidence'] >= 0.7
        
        return validation
    
    def _validate_timing(
        self,
        finding: Dict,
        payload: Dict
    ) -> Dict:
        """
        Validate timing characteristics.
        
        Args:
            finding (dict): Finding to validate.
            payload (dict): Validation payload.
            
        Returns:
            dict: Timing validation results.
        """
        validation = {
            'type': 'timing',
            'passed': False,
            'confidence': 0.0,
            'details': []
        }
        
        # Compare response times
        original_time = finding.get('response', {}).get('time', 0)
        validation_time = finding.get('validation_response', {}).get('time', 0)
        
        if original_time > 0 and validation_time > 0:
            variance = abs(original_time - validation_time) / original_time
            
            validation['details'].append({
                'type': 'timing_variance',
                'original': original_time,
                'validation': validation_time,
                'variance': variance,
                'confidence': 1.0 - min(variance, 1.0)
            })
        
        # Calculate validation confidence
        if validation['details']:
            validation['confidence'] = max(
                detail['confidence']
                for detail in validation['details']
            )
            validation['passed'] = validation['confidence'] >= 0.6
        
        return validation
    
    def _analyze_validations(self, validations: List[Dict]) -> Dict:
        """
        Analyze validation round results.
        
        Args:
            validations (list): Validation round results.
            
        Returns:
            dict: Analysis results.
        """
        analysis = {
            'confidence': 0.0,
            'consistency': 0.0,
            'validation_summary': {}
        }
        
        if not validations:
            return analysis
        
        # Calculate confidence trend
        confidences = [v['confidence'] for v in validations]
        analysis['confidence'] = sum(confidences) / len(confidences)
        
        # Calculate consistency
        passed_validations = sum(
            1 for v in validations
            if any(t['passed'] for t in v['tests'])
        )
        analysis['consistency'] = passed_validations / len(validations)
        
        # Summarize validation types
        summary = defaultdict(list)
        for validation in validations:
            for test in validation['tests']:
                summary[test['type']].append(test['passed'])
        
        analysis['validation_summary'] = {
            test_type: {
                'passed': sum(results),
                'total': len(results),
                'rate': sum(results) / len(results)
            }
            for test_type, results in summary.items()
        }
        
        return analysis
    
    def _check_false_positive_indicators(
        self,
        finding: Dict,
        verification: Dict
    ) -> List[Dict]:
        """
        Check for false positive indicators.
        
        Args:
            finding (dict): Original finding.
            verification (dict): Verification results.
            
        Returns:
            list: Identified false positive indicators.
        """
        indicators = []
        
        # Check validation consistency
        if verification['consistency'] < 0.5:
            indicators.append({
                'type': 'inconsistent_validation',
                'confidence': 0.8,
                'details': 'Inconsistent validation results across rounds'
            })
        
        # Check reflection characteristics
        reflection_summary = verification['validation_summary'].get('reflection', {})
        if reflection_summary.get('rate', 0) < 0.7:
            indicators.append({
                'type': 'unreliable_reflection',
                'confidence': 0.7,
                'details': 'Unreliable payload reflection'
            })
        
        # Check cache behavior
        cache_summary = verification['validation_summary'].get('cache_behavior', {})
        if cache_summary.get('rate', 0) < 0.6:
            indicators.append({
                'type': 'inconsistent_caching',
                'confidence': 0.7,
                'details': 'Inconsistent cache behavior'
            })
        
        return indicators
    
    def _calculate_batch_statistics(self, results: Dict) -> Dict:
        """
        Calculate statistics for batch verification.
        
        Args:
            results (dict): Batch verification results.
            
        Returns:
            dict: Calculated statistics.
        """
        stats = {
            'verification_rate': results['verified'] / results['total'],
            'false_positive_rate': results['false_positives'] / results['total'],
            'confidence_distribution': {},
            'validation_success_rates': {}
        }
        
        # Calculate confidence distribution
        confidences = [
            v['verification']['confidence']
            for v in results['verified_findings']
        ]
        if confidences:
            stats['confidence_distribution'] = {
                'min': min(confidences),
                'max': max(confidences),
                'avg': sum(confidences) / len(confidences)
            }
        
        # Calculate validation success rates
        all_findings = (
            results['verified_findings'] +
            results['false_positives_findings']
        )
        
        validation_counts = defaultdict(lambda: {'passed': 0, 'total': 0})
        
        for finding in all_findings:
            for validation in finding['verification']['validations']:
                for test in validation['tests']:
                    test_type = test['type']
                    validation_counts[test_type]['total'] += 1
                    if test['passed']:
                        validation_counts[test_type]['passed'] += 1
        
        stats['validation_success_rates'] = {
            test_type: counts['passed'] / counts['total']
            for test_type, counts in validation_counts.items()
            if counts['total'] > 0
        }
        
        return stats
    
    def _extract_context(
        self,
        content: str,
        span: Tuple[int, int],
        context_size: int = 50
    ) -> str:
        """
        Extract context around a match.
        
        Args:
            content (str): Content to extract from.
            span (tuple): Start and end positions.
            context_size (int): Size of context to extract.
            
        Returns:
            str: Extracted context.
        """
        start, end = span
        context_start = max(0, start - context_size)
        context_end = min(len(content), end + context_size)
        return content[context_start:context_end]
