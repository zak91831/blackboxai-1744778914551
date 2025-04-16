"""
Cache Behavior Analysis Module

This module analyzes cache behavior patterns and characteristics for
identifying potential cache-based XSS vulnerabilities.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta
import statistics
from collections import defaultdict
import re
import time

class CacheBehaviorAnalyzer:
    """
    A class to analyze cache behavior patterns.
    """
    
    def __init__(self, config):
        """
        Initialize the Cache Behavior Analyzer.
        
        Args:
            config (dict): Configuration settings for cache analysis.
        """
        self.logger = logging.getLogger('cachexssdetector.cache_behavior_analyzer')
        self.config = config
        
        # Analysis configuration
        self.min_samples = config.get('min_samples', 5)
        self.time_window = config.get('time_window', 300)  # 5 minutes
        self.cache_ttl_threshold = config.get('cache_ttl_threshold', 3600)  # 1 hour
        
        # Initialize patterns
        self._init_patterns()
        
        self.logger.info("Cache Behavior Analyzer initialized")
    
    def _init_patterns(self):
        """Initialize cache analysis patterns."""
        # Cache header patterns
        self.cache_headers = {
            'control': [
                'cache-control',
                'pragma',
                'expires'
            ],
            'validation': [
                'etag',
                'last-modified'
            ],
            'variation': [
                'vary',
                'x-vary'
            ]
        }
        
        # Cache behavior patterns
        self.behavior_patterns = {
            'public_cache': {
                'headers': ['public', 'max-age', 's-maxage'],
                'indicators': ['x-cache', 'cf-cache-status']
            },
            'private_cache': {
                'headers': ['private', 'no-store'],
                'indicators': ['x-cache-status']
            },
            'conditional_cache': {
                'headers': ['must-revalidate', 'proxy-revalidate'],
                'indicators': ['if-none-match', 'if-modified-since']
            }
        }
        
        # Response timing patterns
        self.timing_patterns = {
            'cache_hit': {
                'max_time': 0.1,  # seconds
                'variance': 0.05
            },
            'cache_miss': {
                'min_time': 0.2,
                'variance': 0.2
            }
        }
    
    def analyze_response(
        self,
        response: Dict,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Analyze cache behavior in a single response.
        
        Args:
            response (dict): Response to analyze.
            context (dict, optional): Additional context information.
            
        Returns:
            dict: Analysis results.
        """
        analysis = {
            'is_cached': False,
            'cache_type': 'unknown',
            'ttl': 0,
            'indicators': [],
            'headers_analysis': {},
            'timing_analysis': {},
            'confidence': 0.0
        }
        
        try:
            # Analyze cache headers
            headers_analysis = self._analyze_cache_headers(response)
            analysis['headers_analysis'] = headers_analysis
            
            # Analyze cache indicators
            indicators = self._analyze_cache_indicators(response)
            analysis['indicators'].extend(indicators)
            
            # Analyze response timing
            if 'timing' in response:
                timing_analysis = self._analyze_response_timing(
                    response,
                    context
                )
                analysis['timing_analysis'] = timing_analysis
            
            # Determine cache status
            cache_determination = self._determine_cache_status(
                headers_analysis,
                indicators,
                analysis.get('timing_analysis', {})
            )
            analysis.update(cache_determination)
            
        except Exception as e:
            self.logger.error(f"Error analyzing response: {str(e)}")
        
        return analysis
    
    def analyze_sequence(
        self,
        responses: List[Dict],
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Analyze cache behavior across a sequence of responses.
        
        Args:
            responses (list): Sequence of responses to analyze.
            context (dict, optional): Additional context information.
            
        Returns:
            dict: Sequence analysis results.
        """
        analysis = {
            'cache_pattern': 'unknown',
            'hit_rate': 0.0,
            'ttl_estimate': 0,
            'variations': [],
            'timing_patterns': {},
            'confidence': 0.0
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
            
            # Analyze cache patterns
            pattern_analysis = self._analyze_cache_patterns(response_analyses)
            analysis['cache_pattern'] = pattern_analysis['pattern']
            analysis['variations'] = pattern_analysis['variations']
            
            # Calculate hit rate
            hits = sum(1 for a in response_analyses if a['is_cached'])
            analysis['hit_rate'] = hits / len(responses)
            
            # Estimate TTL
            analysis['ttl_estimate'] = self._estimate_cache_ttl(
                responses,
                response_analyses
            )
            
            # Analyze timing patterns
            analysis['timing_patterns'] = self._analyze_timing_patterns(
                responses,
                response_analyses
            )
            
            # Calculate confidence
            analysis['confidence'] = self._calculate_sequence_confidence(
                pattern_analysis,
                analysis['hit_rate'],
                analysis['timing_patterns']
            )
            
        except Exception as e:
            self.logger.error(f"Error in sequence analysis: {str(e)}")
        
        return analysis
    
    def _analyze_cache_headers(self, response: Dict) -> Dict:
        """
        Analyze cache-related headers.
        
        Args:
            response (dict): Response to analyze.
            
        Returns:
            dict: Header analysis results.
        """
        analysis = {
            'directives': [],
            'validation': {},
            'variation': [],
            'max_age': None
        }
        
        headers = response.get('headers', {})
        
        try:
            # Analyze Cache-Control
            if 'cache-control' in headers:
                directives = self._parse_cache_control(headers['cache-control'])
                analysis['directives'] = directives
                
                if 'max-age' in directives:
                    analysis['max_age'] = int(directives['max-age'])
            
            # Analyze validation headers
            for header in self.cache_headers['validation']:
                if header in headers:
                    analysis['validation'][header] = headers[header]
            
            # Analyze variation headers
            if 'vary' in headers:
                analysis['variation'] = [
                    v.strip()
                    for v in headers['vary'].split(',')
                ]
            
        except Exception as e:
            self.logger.error(f"Error analyzing cache headers: {str(e)}")
        
        return analysis
    
    def _analyze_cache_indicators(self, response: Dict) -> List[Dict]:
        """
        Analyze cache status indicators.
        
        Args:
            response (dict): Response to analyze.
            
        Returns:
            list: Found cache indicators.
        """
        indicators = []
        headers = response.get('headers', {})
        
        try:
            # Check direct cache indicators
            for pattern_type, pattern_headers in self.behavior_patterns.items():
                for header in pattern_headers['indicators']:
                    if header in headers:
                        indicators.append({
                            'type': pattern_type,
                            'header': header,
                            'value': headers[header],
                            'confidence': 0.9
                        })
            
            # Check age header
            if 'age' in headers:
                age = int(headers['age'])
                indicators.append({
                    'type': 'age',
                    'value': age,
                    'confidence': min(age / self.cache_ttl_threshold, 1.0)
                })
            
        except Exception as e:
            self.logger.error(f"Error analyzing cache indicators: {str(e)}")
        
        return indicators
    
    def _analyze_response_timing(
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
            
            # Compare with cache hit pattern
            hit_pattern = self.timing_patterns['cache_hit']
            if timing <= hit_pattern['max_time']:
                analysis['pattern'] = 'cache_hit'
                analysis['confidence'] = 0.8
            
            # Compare with cache miss pattern
            miss_pattern = self.timing_patterns['cache_miss']
            if timing >= miss_pattern['min_time']:
                analysis['pattern'] = 'cache_miss'
                analysis['confidence'] = 0.7
            
            # Consider context if available
            if context and 'baseline_timing' in context:
                analysis['confidence'] = self._compare_timing(
                    timing,
                    context['baseline_timing']
                )
            
        except Exception as e:
            self.logger.error(f"Error analyzing response timing: {str(e)}")
        
        return analysis
    
    def _analyze_cache_patterns(
        self,
        analyses: List[Dict]
    ) -> Dict:
        """
        Analyze cache behavior patterns.
        
        Args:
            analyses (list): Response analyses.
            
        Returns:
            dict: Pattern analysis results.
        """
        pattern_analysis = {
            'pattern': 'unknown',
            'variations': [],
            'confidence': 0.0
        }
        
        try:
            # Count cache status transitions
            transitions = defaultdict(int)
            for i in range(len(analyses) - 1):
                current = analyses[i]['is_cached']
                next_status = analyses[i + 1]['is_cached']
                transition = f"{current}->{next_status}"
                transitions[transition] += 1
            
            # Identify pattern
            if self._is_consistent_caching(transitions):
                pattern_analysis['pattern'] = 'consistent'
                pattern_analysis['confidence'] = 0.9
            elif self._is_alternating_pattern(transitions):
                pattern_analysis['pattern'] = 'alternating'
                pattern_analysis['confidence'] = 0.8
            elif self._is_degrading_pattern(transitions):
                pattern_analysis['pattern'] = 'degrading'
                pattern_analysis['confidence'] = 0.7
            
            # Identify variations
            pattern_analysis['variations'] = self._identify_variations(analyses)
            
        except Exception as e:
            self.logger.error(f"Error analyzing cache patterns: {str(e)}")
        
        return pattern_analysis
    
    def _estimate_cache_ttl(
        self,
        responses: List[Dict],
        analyses: List[Dict]
    ) -> int:
        """
        Estimate cache TTL from response sequence.
        
        Args:
            responses (list): Original responses.
            analyses (list): Response analyses.
            
        Returns:
            int: Estimated TTL in seconds.
        """
        try:
            # Check explicit TTL
            for analysis in analyses:
                if analysis['headers_analysis'].get('max_age'):
                    return analysis['headers_analysis']['max_age']
            
            # Estimate from transitions
            cached_responses = [
                (r, a) for r, a in zip(responses, analyses)
                if a['is_cached']
            ]
            
            if not cached_responses:
                return 0
            
            # Calculate time differences
            times = []
            for i in range(len(cached_responses) - 1):
                current_time = cached_responses[i][0].get('timestamp', 0)
                next_time = cached_responses[i + 1][0].get('timestamp', 0)
                if next_time > current_time:
                    times.append(next_time - current_time)
            
            if times:
                return int(statistics.mean(times))
            
        except Exception as e:
            self.logger.error(f"Error estimating cache TTL: {str(e)}")
        
        return 0
    
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
                if analysis['is_cached']:
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
    
    def _parse_cache_control(self, header: str) -> Dict[str, str]:
        """Parse Cache-Control header directives."""
        directives = {}
        
        try:
            parts = [p.strip() for p in header.split(',')]
            
            for part in parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    directives[key.strip()] = value.strip()
                else:
                    directives[part.strip()] = True
            
        except Exception as e:
            self.logger.error(f"Error parsing Cache-Control header: {str(e)}")
        
        return directives
    
    def _determine_cache_status(
        self,
        headers_analysis: Dict,
        indicators: List[Dict],
        timing_analysis: Dict
    ) -> Dict:
        """
        Determine overall cache status.
        
        Args:
            headers_analysis (dict): Header analysis results.
            indicators (list): Cache indicators.
            timing_analysis (dict): Timing analysis results.
            
        Returns:
            dict: Cache status determination.
        """
        determination = {
            'is_cached': False,
            'cache_type': 'unknown',
            'confidence': 0.0
        }
        
        try:
            # Calculate confidence from different sources
            confidences = []
            
            # Headers confidence
            if headers_analysis.get('max_age'):
                confidences.append(0.8)
            if headers_analysis.get('validation'):
                confidences.append(0.7)
            
            # Indicators confidence
            if indicators:
                confidences.append(
                    max(i['confidence'] for i in indicators)
                )
            
            # Timing confidence
            if timing_analysis.get('confidence'):
                confidences.append(timing_analysis['confidence'])
            
            # Calculate overall confidence
            if confidences:
                determination['confidence'] = sum(confidences) / len(confidences)
            
            # Determine cache status
            if determination['confidence'] >= 0.7:
                determination['is_cached'] = True
                
                # Determine cache type
                if any(i['type'] == 'public_cache' for i in indicators):
                    determination['cache_type'] = 'public'
                elif any(i['type'] == 'private_cache' for i in indicators):
                    determination['cache_type'] = 'private'
                elif any(i['type'] == 'conditional_cache' for i in indicators):
                    determination['cache_type'] = 'conditional'
            
        except Exception as e:
            self.logger.error(f"Error determining cache status: {str(e)}")
        
        return determination
    
    def _is_consistent_caching(self, transitions: Dict[str, int]) -> bool:
        """Check for consistent caching pattern."""
        total = sum(transitions.values())
        if total == 0:
            return False
        
        # Check if most transitions are of the same type
        max_transition = max(transitions.values())
        return max_transition / total >= 0.8
    
    def _is_alternating_pattern(self, transitions: Dict[str, int]) -> bool:
        """Check for alternating cache pattern."""
        hit_miss = transitions.get('True->False', 0)
        miss_hit = transitions.get('False->True', 0)
        total = sum(transitions.values())
        
        return total > 0 and (hit_miss + miss_hit) / total >= 0.6
    
    def _is_degrading_pattern(self, transitions: Dict[str, int]) -> bool:
        """Check for degrading cache pattern."""
        hit_miss = transitions.get('True->False', 0)
        miss_miss = transitions.get('False->False', 0)
        total = sum(transitions.values())
        
        return total > 0 and (hit_miss + miss_miss) / total >= 0.7
    
    def _identify_variations(self, analyses: List[Dict]) -> List[Dict]:
        """Identify cache variations."""
        variations = []
        
        try:
            # Group by cache type
            by_type = defaultdict(list)
            for analysis in analyses:
                by_type[analysis['cache_type']].append(analysis)
            
            # Analyze each type
            for cache_type, type_analyses in by_type.items():
                variation = {
                    'type': cache_type,
                    'count': len(type_analyses),
                    'confidence': statistics.mean(
                        a['confidence'] for a in type_analyses
                    )
                }
                variations.append(variation)
            
        except Exception as e:
            self.logger.error(f"Error identifying variations: {str(e)}")
        
        return variations
    
    def _compare_timing(self, timing: float, baseline: float) -> float:
        """Calculate confidence from timing comparison."""
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
    
    def _calculate_sequence_confidence(
        self,
        pattern_analysis: Dict,
        hit_rate: float,
        timing_patterns: Dict
    ) -> float:
        """Calculate overall confidence for sequence analysis."""
        confidences = [
            pattern_analysis['confidence'],
            hit_rate
        ]
        
        # Add timing confidence if available
        if timing_patterns.get('hit_timings'):
            hit_variance = timing_patterns.get('hit_variance', float('inf'))
            if hit_variance <= self.timing_patterns['cache_hit']['variance']:
                confidences.append(0.8)
        
        return statistics.mean(confidences) if confidences else 0.0
