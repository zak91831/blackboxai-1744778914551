"""
Cache Hit/Miss Detector Module

This module analyzes HTTP responses to detect cache hits and misses,
focusing on timing patterns and cache-related headers.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
import statistics
from collections import defaultdict
import time
from datetime import datetime
import re

class CacheHitMissDetector:
    """
    A class to detect cache hits and misses in HTTP responses.
    """
    
    def __init__(self, config):
        """
        Initialize the Cache Hit/Miss Detector.
        
        Args:
            config (dict): Configuration settings for detection.
        """
        self.logger = logging.getLogger('cachexssdetector.cache_hit_miss_detector')
        self.config = config
        
        # Detection configuration
        self.timing_threshold = config.get('timing_threshold', 0.1)
        self.min_samples = config.get('min_samples', 5)
        self.confidence_threshold = config.get('confidence_threshold', 0.8)
        
        # Initialize detection patterns
        self._init_patterns()
        
        self.logger.info("Cache Hit/Miss Detector initialized")
    
    def _init_patterns(self):
        """Initialize detection patterns."""
        # Cache header patterns
        self.cache_headers = {
            'direct': [
                'x-cache',
                'cf-cache-status',
                'x-drupal-cache',
                'x-varnish-cache',
                'x-cache-hits'
            ],
            'indirect': [
                'age',
                'x-served-by',
                'x-cache-lookup'
            ]
        }
        
        # Cache status indicators
        self.cache_indicators = {
            'hit': [
                'hit',
                'stored',
                'fresh',
                'cached'
            ],
            'miss': [
                'miss',
                'expired',
                'stale',
                'bypass'
            ]
        }
        
        # Timing patterns
        self.timing_patterns = {
            'hit': {
                'max_time': self.timing_threshold,
                'variance_threshold': 0.05
            },
            'miss': {
                'min_time': self.timing_threshold,
                'variance_threshold': 0.2
            }
        }
    
    def analyze_response(
        self,
        response: Dict,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Analyze a single response for cache status.
        
        Args:
            response (dict): Response to analyze.
            context (dict, optional): Additional context information.
            
        Returns:
            dict: Analysis results.
        """
        analysis = {
            'is_hit': False,
            'confidence': 0.0,
            'indicators': [],
            'timing_analysis': {},
            'header_analysis': {}
        }
        
        try:
            # Analyze cache headers
            header_analysis = self._analyze_headers(response)
            analysis['header_analysis'] = header_analysis
            
            # Analyze response timing
            timing_analysis = self._analyze_timing(
                response,
                context
            )
            analysis['timing_analysis'] = timing_analysis
            
            # Combine analyses
            analysis.update(
                self._make_determination(
                    header_analysis,
                    timing_analysis
                )
            )
            
        except Exception as e:
            self.logger.error(f"Error analyzing response: {str(e)}")
        
        return analysis
    
    def analyze_sequence(
        self,
        responses: List[Dict],
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Analyze a sequence of responses for cache patterns.
        
        Args:
            responses (list): Responses to analyze.
            context (dict, optional): Additional context information.
            
        Returns:
            dict: Sequence analysis results.
        """
        analysis = {
            'hit_rate': 0.0,
            'pattern': 'unknown',
            'confidence': 0.0,
            'timing_patterns': {},
            'transitions': {}
        }
        
        try:
            if len(responses) < self.min_samples:
                self.logger.warning(
                    f"Insufficient samples for sequence analysis: {len(responses)}"
                )
                return analysis
            
            # Analyze individual responses
            response_analyses = [
                self.analyze_response(r, context)
                for r in responses
            ]
            
            # Calculate hit rate
            hits = sum(1 for a in response_analyses if a['is_hit'])
            analysis['hit_rate'] = hits / len(responses)
            
            # Analyze timing patterns
            analysis['timing_patterns'] = self._analyze_timing_patterns(
                responses,
                response_analyses
            )
            
            # Analyze transitions
            analysis['transitions'] = self._analyze_transitions(
                response_analyses
            )
            
            # Determine pattern
            pattern_analysis = self._determine_pattern(
                analysis['hit_rate'],
                analysis['timing_patterns'],
                analysis['transitions']
            )
            analysis.update(pattern_analysis)
            
        except Exception as e:
            self.logger.error(f"Error in sequence analysis: {str(e)}")
        
        return analysis
    
    def _analyze_headers(self, response: Dict) -> Dict:
        """
        Analyze cache-related headers.
        
        Args:
            response (dict): Response to analyze.
            
        Returns:
            dict: Header analysis results.
        """
        analysis = {
            'cache_headers': {},
            'indicators': [],
            'confidence': 0.0
        }
        
        try:
            headers = response.get('headers', {})
            
            # Check direct cache headers
            for header in self.cache_headers['direct']:
                if header.lower() in headers:
                    value = headers[header.lower()]
                    analysis['cache_headers'][header] = value
                    
                    # Check for hit/miss indicators
                    indicators = self._extract_cache_indicators(value)
                    analysis['indicators'].extend(indicators)
            
            # Check indirect cache headers
            for header in self.cache_headers['indirect']:
                if header.lower() in headers:
                    value = headers[header.lower()]
                    analysis['cache_headers'][header] = value
                    
                    # Add age indicator if present
                    if header == 'age' and int(value or 0) > 0:
                        analysis['indicators'].append({
                            'type': 'hit',
                            'source': 'age',
                            'confidence': 0.8
                        })
            
            # Calculate confidence
            if analysis['indicators']:
                confidences = [i['confidence'] for i in analysis['indicators']]
                analysis['confidence'] = max(confidences)
            
        except Exception as e:
            self.logger.error(f"Error analyzing headers: {str(e)}")
        
        return analysis
    
    def _analyze_timing(
        self,
        response: Dict,
        context: Optional[Dict]
    ) -> Dict:
        """
        Analyze response timing characteristics.
        
        Args:
            response (dict): Response to analyze.
            context (dict, optional): Context information.
            
        Returns:
            dict: Timing analysis results.
        """
        analysis = {
            'timing': response.get('timing', 0),
            'pattern': 'unknown',
            'confidence': 0.0
        }
        
        try:
            timing = analysis['timing']
            
            # Compare with hit pattern
            hit_pattern = self.timing_patterns['hit']
            if timing <= hit_pattern['max_time']:
                analysis['pattern'] = 'hit'
                analysis['confidence'] = 0.8
            
            # Compare with miss pattern
            miss_pattern = self.timing_patterns['miss']
            if timing >= miss_pattern['min_time']:
                analysis['pattern'] = 'miss'
                analysis['confidence'] = 0.7
            
            # Consider context if available
            if context and 'baseline_timing' in context:
                analysis['confidence'] = self._compare_timing(
                    timing,
                    context['baseline_timing']
                )
            
        except Exception as e:
            self.logger.error(f"Error analyzing timing: {str(e)}")
        
        return analysis
    
    def _analyze_timing_patterns(
        self,
        responses: List[Dict],
        analyses: List[Dict]
    ) -> Dict:
        """
        Analyze timing patterns across responses.
        
        Args:
            responses (list): Original responses.
            analyses (list): Response analyses.
            
        Returns:
            dict: Timing pattern analysis.
        """
        patterns = {
            'hit_timings': [],
            'miss_timings': [],
            'variance': 0.0
        }
        
        try:
            # Separate hit/miss timings
            for response, analysis in zip(responses, analyses):
                timing = response.get('timing', 0)
                if analysis['is_hit']:
                    patterns['hit_timings'].append(timing)
                else:
                    patterns['miss_timings'].append(timing)
            
            # Calculate statistics
            if patterns['hit_timings']:
                patterns['hit_mean'] = statistics.mean(patterns['hit_timings'])
                if len(patterns['hit_timings']) > 1:
                    patterns['hit_variance'] = statistics.variance(
                        patterns['hit_timings']
                    )
            
            if patterns['miss_timings']:
                patterns['miss_mean'] = statistics.mean(patterns['miss_timings'])
                if len(patterns['miss_timings']) > 1:
                    patterns['miss_variance'] = statistics.variance(
                        patterns['miss_timings']
                    )
            
        except Exception as e:
            self.logger.error(f"Error analyzing timing patterns: {str(e)}")
        
        return patterns
    
    def _analyze_transitions(self, analyses: List[Dict]) -> Dict:
        """
        Analyze cache status transitions.
        
        Args:
            analyses (list): Response analyses.
            
        Returns:
            dict: Transition analysis.
        """
        transitions = {
            'counts': defaultdict(int),
            'pattern': 'unknown',
            'consistency': 0.0
        }
        
        try:
            # Count transitions
            for i in range(len(analyses) - 1):
                current = analyses[i]['is_hit']
                next_status = analyses[i + 1]['is_hit']
                transition = f"{current}->{next_status}"
                transitions['counts'][transition] += 1
            
            # Calculate consistency
            total = sum(transitions['counts'].values())
            if total > 0:
                max_transition = max(transitions['counts'].values())
                transitions['consistency'] = max_transition / total
            
            # Determine pattern
            if transitions['consistency'] >= 0.8:
                transitions['pattern'] = 'consistent'
            elif transitions['consistency'] >= 0.5:
                transitions['pattern'] = 'alternating'
            else:
                transitions['pattern'] = 'random'
            
        except Exception as e:
            self.logger.error(f"Error analyzing transitions: {str(e)}")
        
        return transitions
    
    def _make_determination(
        self,
        header_analysis: Dict,
        timing_analysis: Dict
    ) -> Dict:
        """
        Make final cache status determination.
        
        Args:
            header_analysis (dict): Header analysis results.
            timing_analysis (dict): Timing analysis results.
            
        Returns:
            dict: Determination results.
        """
        determination = {
            'is_hit': False,
            'confidence': 0.0,
            'indicators': []
        }
        
        try:
            # Collect indicators
            determination['indicators'].extend(header_analysis['indicators'])
            
            if timing_analysis['pattern'] == 'hit':
                determination['indicators'].append({
                    'type': 'hit',
                    'source': 'timing',
                    'confidence': timing_analysis['confidence']
                })
            elif timing_analysis['pattern'] == 'miss':
                determination['indicators'].append({
                    'type': 'miss',
                    'source': 'timing',
                    'confidence': timing_analysis['confidence']
                })
            
            # Calculate confidence
            confidences = [
                header_analysis['confidence'],
                timing_analysis['confidence']
            ]
            determination['confidence'] = max(confidences)
            
            # Make determination
            hit_indicators = [
                i for i in determination['indicators']
                if i['type'] == 'hit'
            ]
            
            if hit_indicators and determination['confidence'] >= self.confidence_threshold:
                determination['is_hit'] = True
            
        except Exception as e:
            self.logger.error(f"Error making determination: {str(e)}")
        
        return determination
    
    def _determine_pattern(
        self,
        hit_rate: float,
        timing_patterns: Dict,
        transitions: Dict
    ) -> Dict:
        """
        Determine overall cache pattern.
        
        Args:
            hit_rate (float): Cache hit rate.
            timing_patterns (dict): Timing pattern analysis.
            transitions (dict): Transition analysis.
            
        Returns:
            dict: Pattern determination.
        """
        determination = {
            'pattern': 'unknown',
            'confidence': 0.0
        }
        
        try:
            # Consider hit rate
            if hit_rate >= 0.8:
                determination['pattern'] = 'mostly_hits'
                determination['confidence'] = hit_rate
            elif hit_rate <= 0.2:
                determination['pattern'] = 'mostly_misses'
                determination['confidence'] = 1 - hit_rate
            
            # Consider timing consistency
            if timing_patterns.get('hit_variance', float('inf')) <= \
               self.timing_patterns['hit']['variance_threshold']:
                determination['pattern'] = 'consistent_hits'
                determination['confidence'] = 0.9
            
            # Consider transitions
            if transitions['pattern'] == 'consistent':
                determination['pattern'] = 'stable_cache'
                determination['confidence'] = transitions['consistency']
            elif transitions['pattern'] == 'alternating':
                determination['pattern'] = 'alternating_cache'
                determination['confidence'] = transitions['consistency']
            
        except Exception as e:
            self.logger.error(f"Error determining pattern: {str(e)}")
        
        return determination
    
    def _extract_cache_indicators(self, header_value: str) -> List[Dict]:
        """
        Extract cache status indicators from header value.
        
        Args:
            header_value (str): Header value to analyze.
            
        Returns:
            list: Extracted indicators.
        """
        indicators = []
        
        try:
            value_lower = header_value.lower()
            
            # Check hit indicators
            for indicator in self.cache_indicators['hit']:
                if indicator in value_lower:
                    indicators.append({
                        'type': 'hit',
                        'source': 'header',
                        'confidence': 0.9
                    })
            
            # Check miss indicators
            for indicator in self.cache_indicators['miss']:
                if indicator in value_lower:
                    indicators.append({
                        'type': 'miss',
                        'source': 'header',
                        'confidence': 0.9
                    })
            
        except Exception as e:
            self.logger.error(f"Error extracting cache indicators: {str(e)}")
        
        return indicators
    
    def _compare_timing(self, timing: float, baseline: float) -> float:
        """
        Calculate confidence from timing comparison.
        
        Args:
            timing (float): Response timing.
            baseline (float): Baseline timing.
            
        Returns:
            float: Confidence score.
        """
        try:
            if baseline <= 0:
                return 0.0
            
            ratio = timing / baseline
            
            if ratio <= 0.5:
                return 0.9  # Likely cache hit
            elif ratio >= 2.0:
                return 0.8  # Likely cache miss
            else:
                return 0.5  # Uncertain
            
        except Exception:
            return 0.0
