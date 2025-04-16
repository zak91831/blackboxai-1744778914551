"""
Verification System Module

This module initializes and coordinates the verification components for
validating cache-based XSS vulnerabilities.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
import asyncio
from .multi_client_simulator import MultiClientSimulator
from .cache_hit_miss_detector import CacheHitMissDetector
from .false_positive_reducer import FalsePositiveReducer

class VerificationSystem:
    """
    Verification coordinator for cache-based XSS detection.
    """
    
    def __init__(self, config):
        """
        Initialize the Verification System.
        
        Args:
            config (dict): Configuration settings for verification.
        """
        self.logger = logging.getLogger('cachexssdetector.verification_system')
        self.config = config
        
        # Initialize components
        self.multi_client = MultiClientSimulator(config.get('multi_client', {}))
        self.cache_detector = CacheHitMissDetector(config.get('cache_detector', {}))
        self.fp_reducer = FalsePositiveReducer(config.get('false_positive', {}))
        
        # Verification configuration
        self.verification_rounds = config.get('verification_rounds', 3)
        self.min_confidence = config.get('min_confidence', 0.8)
        self.timeout = config.get('timeout', 300)  # 5 minutes
        
        self.logger.info("Verification System initialized")
    
    async def verify_finding(
        self,
        finding: Dict,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Verify a potential vulnerability finding.
        
        Args:
            finding (dict): Finding to verify.
            context (dict, optional): Additional context information.
            
        Returns:
            dict: Verification results.
        """
        verification = {
            'finding': finding,
            'verified': False,
            'confidence': 0.0,
            'verification_data': {},
            'cache_behavior': {},
            'false_positive_analysis': {}
        }
        
        try:
            # Simulate multiple client access
            client_simulation = await self.multi_client.simulate_clients(
                finding['url'],
                finding.get('payload'),
                'parallel'
            )
            verification['verification_data']['client_simulation'] = client_simulation
            
            # Analyze cache behavior
            cache_analysis = await self._analyze_cache_behavior(
                finding,
                client_simulation
            )
            verification['cache_behavior'] = cache_analysis
            
            # Reduce false positives
            fp_analysis = await self._reduce_false_positives(
                finding,
                verification
            )
            verification['false_positive_analysis'] = fp_analysis
            
            # Make verification decision
            verification.update(
                self._make_verification_decision(verification)
            )
            
        except Exception as e:
            error_msg = f"Error during verification: {str(e)}"
            self.logger.error(error_msg)
            verification['error'] = error_msg
        
        return verification
    
    async def verify_batch(
        self,
        findings: List[Dict],
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Verify multiple findings in batch.
        
        Args:
            findings (list): List of findings to verify.
            context (dict, optional): Additional context information.
            
        Returns:
            dict: Batch verification results.
        """
        batch_results = {
            'total_findings': len(findings),
            'verified_findings': [],
            'false_positives': [],
            'errors': [],
            'statistics': {}
        }
        
        try:
            # Process findings in parallel
            verification_tasks = [
                self.verify_finding(finding, context)
                for finding in findings
            ]
            
            # Wait for all verifications to complete
            verifications = await asyncio.gather(
                *verification_tasks,
                return_exceptions=True
            )
            
            # Process results
            for verification in verifications:
                if isinstance(verification, Exception):
                    batch_results['errors'].append(str(verification))
                    continue
                
                if verification['verified']:
                    batch_results['verified_findings'].append(verification)
                else:
                    batch_results['false_positives'].append(verification)
            
            # Calculate statistics
            batch_results['statistics'] = self._calculate_batch_statistics(
                batch_results
            )
            
        except Exception as e:
            error_msg = f"Error in batch verification: {str(e)}"
            self.logger.error(error_msg)
            batch_results['errors'].append(error_msg)
        
        return batch_results
    
    async def _analyze_cache_behavior(
        self,
        finding: Dict,
        simulation_data: Dict
    ) -> Dict:
        """
        Analyze cache behavior during verification.
        
        Args:
            finding (dict): Original finding.
            simulation_data (dict): Client simulation data.
            
        Returns:
            dict: Cache behavior analysis.
        """
        try:
            # Analyze cache hits/misses
            cache_analysis = self.cache_detector.analyze_sequence(
                simulation_data.get('responses', [])
            )
            
            # Verify cache persistence
            persistence = await self.multi_client.verify_cache_persistence(
                finding['url'],
                finding.get('payload', {}),
                self.timeout
            )
            
            return {
                'cache_analysis': cache_analysis,
                'persistence': persistence,
                'confidence': self._calculate_cache_confidence(
                    cache_analysis,
                    persistence
                )
            }
            
        except Exception as e:
            self.logger.error(f"Error in cache behavior analysis: {str(e)}")
            return {'error': str(e)}
    
    async def _reduce_false_positives(
        self,
        finding: Dict,
        verification_data: Dict
    ) -> Dict:
        """
        Perform false positive reduction analysis.
        
        Args:
            finding (dict): Original finding.
            verification_data (dict): Verification data.
            
        Returns:
            dict: False positive analysis results.
        """
        try:
            # Verify through multiple rounds
            fp_results = []
            for round_num in range(self.verification_rounds):
                result = self.fp_reducer.verify_vulnerability(
                    finding,
                    {
                        'round': round_num,
                        'verification_data': verification_data
                    }
                )
                fp_results.append(result)
            
            # Analyze verification consistency
            return {
                'results': fp_results,
                'consistent': self._check_verification_consistency(fp_results),
                'confidence': self._calculate_fp_confidence(fp_results)
            }
            
        except Exception as e:
            self.logger.error(f"Error in false positive reduction: {str(e)}")
            return {'error': str(e)}
    
    def _make_verification_decision(self, verification: Dict) -> Dict:
        """
        Make final verification decision.
        
        Args:
            verification (dict): Verification data.
            
        Returns:
            dict: Decision results.
        """
        decision = {
            'verified': False,
            'confidence': 0.0,
            'factors': []
        }
        
        try:
            # Calculate confidence scores
            cache_confidence = verification['cache_behavior'].get('confidence', 0.0)
            fp_confidence = verification['false_positive_analysis'].get('confidence', 0.0)
            
            # Consider verification factors
            if cache_confidence >= self.min_confidence:
                decision['factors'].append('cache_behavior_verified')
            
            if fp_confidence >= self.min_confidence:
                decision['factors'].append('reduced_false_positive')
            
            # Make final decision
            if len(decision['factors']) >= 2:
                decision['verified'] = True
                decision['confidence'] = min(cache_confidence, fp_confidence)
            
        except Exception as e:
            self.logger.error(f"Error in verification decision: {str(e)}")
        
        return decision
    
    def _calculate_cache_confidence(
        self,
        cache_analysis: Dict,
        persistence: Dict
    ) -> float:
        """Calculate confidence in cache behavior."""
        if not cache_analysis or not persistence:
            return 0.0
        
        # Consider multiple factors
        factors = [
            cache_analysis.get('hit_rate', 0.0),
            persistence.get('persistence_duration', 0.0) / self.timeout,
            len(persistence.get('affected_clients', [])) / self.multi_client.num_clients
        ]
        
        return sum(factors) / len(factors)
    
    def _calculate_fp_confidence(self, results: List[Dict]) -> float:
        """Calculate confidence from false positive reduction results."""
        if not results:
            return 0.0
        
        # Calculate average confidence across rounds
        confidences = [r.get('confidence', 0.0) for r in results]
        return sum(confidences) / len(confidences)
    
    def _check_verification_consistency(self, results: List[Dict]) -> bool:
        """Check consistency across verification rounds."""
        if not results:
            return False
        
        # Check if all rounds agree
        verified_results = [r.get('verified', False) for r in results]
        return all(verified_results) or not any(verified_results)
    
    def _calculate_batch_statistics(self, results: Dict) -> Dict:
        """
        Calculate statistics for batch verification.
        
        Args:
            results (dict): Batch results.
            
        Returns:
            dict: Calculated statistics.
        """
        stats = {
            'verification_rate': len(results['verified_findings']) / results['total_findings'],
            'false_positive_rate': len(results['false_positives']) / results['total_findings'],
            'error_rate': len(results['errors']) / results['total_findings'],
            'average_confidence': 0.0
        }
        
        # Calculate average confidence
        confidences = [
            v.get('confidence', 0.0)
            for v in results['verified_findings']
        ]
        if confidences:
            stats['average_confidence'] = sum(confidences) / len(confidences)
        
        return stats

# Version information
__version__ = '1.0.0'
