"""
Risk Assessment Module

This module assesses the risk level of detected cache-based XSS vulnerabilities
based on various factors including impact, exploitability, and cache characteristics.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime
from collections import defaultdict

class RiskAssessor:
    """
    A class to assess risk levels of detected vulnerabilities.
    """
    
    def __init__(self, config):
        """
        Initialize the Risk Assessor.
        
        Args:
            config (dict): Configuration settings for risk assessment.
        """
        self.logger = logging.getLogger('cachexssdetector.risk_assessor')
        self.config = config
        
        # Risk configuration
        self.risk_levels = {
            'critical': {'score': 9.0, 'color': 'red'},
            'high': {'score': 7.0, 'color': 'orange'},
            'medium': {'score': 5.0, 'color': 'yellow'},
            'low': {'score': 3.0, 'color': 'blue'}
        }
        
        # Initialize assessment factors
        self._init_factors()
        
        self.logger.info("Risk Assessor initialized")
    
    def _init_factors(self):
        """Initialize risk assessment factors."""
        # Impact factors
        self.impact_factors = {
            'payload_execution': {
                'weight': 0.35,
                'criteria': {
                    'script_execution': 1.0,
                    'event_handler': 0.8,
                    'javascript_uri': 0.7,
                    'data_uri': 0.6
                }
            },
            'cache_persistence': {
                'weight': 0.25,
                'criteria': {
                    'persistent': 1.0,
                    'semi-persistent': 0.7,
                    'temporary': 0.4
                }
            },
            'affected_scope': {
                'weight': 0.20,
                'criteria': {
                    'global': 1.0,
                    'shared': 0.8,
                    'local': 0.5
                }
            }
        }
        
        # Exploitability factors
        self.exploitability_factors = {
            'cache_predictability': {
                'weight': 0.30,
                'criteria': {
                    'consistent': 1.0,
                    'predictable': 0.7,
                    'variable': 0.4
                }
            },
            'access_complexity': {
                'weight': 0.25,
                'criteria': {
                    'low': 1.0,
                    'medium': 0.6,
                    'high': 0.3
                }
            },
            'authentication': {
                'weight': 0.25,
                'criteria': {
                    'none': 1.0,
                    'single': 0.7,
                    'multiple': 0.4
                }
            }
        }
        
        # Cache-specific factors
        self.cache_factors = {
            'cache_type': {
                'weight': 0.20,
                'criteria': {
                    'public': 1.0,
                    'shared': 0.8,
                    'private': 0.5
                }
            },
            'cache_control': {
                'weight': 0.15,
                'criteria': {
                    'none': 1.0,
                    'weak': 0.7,
                    'strong': 0.4
                }
            },
            'cache_distribution': {
                'weight': 0.15,
                'criteria': {
                    'cdn': 1.0,
                    'reverse_proxy': 0.8,
                    'browser': 0.5
                }
            }
        }
    
    def assess_risk(
        self,
        finding: Dict,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Assess risk level of a vulnerability finding.
        
        Args:
            finding (dict): Vulnerability finding to assess.
            context (dict, optional): Additional context information.
            
        Returns:
            dict: Risk assessment results.
        """
        assessment = {
            'risk_level': 'low',
            'risk_score': 0.0,
            'impact_assessment': {},
            'exploitability_assessment': {},
            'cache_assessment': {},
            'factors': [],
            'recommendations': []
        }
        
        try:
            # Assess impact
            impact_assessment = self._assess_impact(finding)
            assessment['impact_assessment'] = impact_assessment
            
            # Assess exploitability
            exploitability_assessment = self._assess_exploitability(finding)
            assessment['exploitability_assessment'] = exploitability_assessment
            
            # Assess cache characteristics
            cache_assessment = self._assess_cache_characteristics(finding)
            assessment['cache_assessment'] = cache_assessment
            
            # Calculate overall risk
            risk_calculation = self._calculate_risk(
                impact_assessment,
                exploitability_assessment,
                cache_assessment
            )
            assessment.update(risk_calculation)
            
            # Generate recommendations
            assessment['recommendations'] = self._generate_recommendations(
                assessment
            )
            
        except Exception as e:
            error_msg = f"Error during risk assessment: {str(e)}"
            self.logger.error(error_msg)
            assessment['error'] = error_msg
        
        return assessment
    
    def assess_batch(
        self,
        findings: List[Dict],
        context: Optional[Dict] = None
    ) -> Dict:
        """
        Assess risk for multiple findings.
        
        Args:
            findings (list): List of findings to assess.
            context (dict, optional): Additional context information.
            
        Returns:
            dict: Batch assessment results.
        """
        batch_results = {
            'total_findings': len(findings),
            'risk_distribution': defaultdict(int),
            'highest_risks': [],
            'summary': {},
            'statistics': {}
        }
        
        try:
            assessments = []
            
            # Assess each finding
            for finding in findings:
                assessment = self.assess_risk(finding, context)
                assessments.append(assessment)
                
                # Update risk distribution
                batch_results['risk_distribution'][
                    assessment['risk_level']
                ] += 1
            
            # Identify highest risks
            batch_results['highest_risks'] = self._identify_highest_risks(
                findings,
                assessments
            )
            
            # Generate batch summary
            batch_results['summary'] = self._generate_batch_summary(
                findings,
                assessments
            )
            
            # Calculate statistics
            batch_results['statistics'] = self._calculate_batch_statistics(
                assessments
            )
            
        except Exception as e:
            error_msg = f"Error in batch assessment: {str(e)}"
            self.logger.error(error_msg)
            batch_results['error'] = error_msg
        
        return batch_results
    
    def _assess_impact(self, finding: Dict) -> Dict:
        """
        Assess vulnerability impact.
        
        Args:
            finding (dict): Finding to assess.
            
        Returns:
            dict: Impact assessment results.
        """
        assessment = {
            'score': 0.0,
            'factors': [],
            'details': {}
        }
        
        try:
            # Assess payload execution
            payload = finding.get('payload', {})
            execution_score = self._assess_payload_execution(payload)
            assessment['details']['payload_execution'] = {
                'score': execution_score,
                'weight': self.impact_factors['payload_execution']['weight']
            }
            
            # Assess cache persistence
            cache_analysis = finding.get('cache_analysis', {})
            persistence_score = self._assess_cache_persistence(cache_analysis)
            assessment['details']['cache_persistence'] = {
                'score': persistence_score,
                'weight': self.impact_factors['cache_persistence']['weight']
            }
            
            # Assess affected scope
            scope_score = self._assess_affected_scope(finding)
            assessment['details']['affected_scope'] = {
                'score': scope_score,
                'weight': self.impact_factors['affected_scope']['weight']
            }
            
            # Calculate overall impact score
            assessment['score'] = self._calculate_weighted_score(
                assessment['details']
            )
            
            # Identify significant factors
            assessment['factors'] = self._identify_significant_factors(
                assessment['details']
            )
            
        except Exception as e:
            self.logger.error(f"Error assessing impact: {str(e)}")
        
        return assessment
    
    def _assess_exploitability(self, finding: Dict) -> Dict:
        """
        Assess vulnerability exploitability.
        
        Args:
            finding (dict): Finding to assess.
            
        Returns:
            dict: Exploitability assessment results.
        """
        assessment = {
            'score': 0.0,
            'factors': [],
            'details': {}
        }
        
        try:
            # Assess cache predictability
            cache_analysis = finding.get('cache_analysis', {})
            predictability_score = self._assess_cache_predictability(cache_analysis)
            assessment['details']['cache_predictability'] = {
                'score': predictability_score,
                'weight': self.exploitability_factors['cache_predictability']['weight']
            }
            
            # Assess access complexity
            complexity_score = self._assess_access_complexity(finding)
            assessment['details']['access_complexity'] = {
                'score': complexity_score,
                'weight': self.exploitability_factors['access_complexity']['weight']
            }
            
            # Assess authentication requirements
            auth_score = self._assess_authentication(finding)
            assessment['details']['authentication'] = {
                'score': auth_score,
                'weight': self.exploitability_factors['authentication']['weight']
            }
            
            # Calculate overall exploitability score
            assessment['score'] = self._calculate_weighted_score(
                assessment['details']
            )
            
            # Identify significant factors
            assessment['factors'] = self._identify_significant_factors(
                assessment['details']
            )
            
        except Exception as e:
            self.logger.error(f"Error assessing exploitability: {str(e)}")
        
        return assessment
    
    def _assess_cache_characteristics(self, finding: Dict) -> Dict:
        """
        Assess cache-specific characteristics.
        
        Args:
            finding (dict): Finding to assess.
            
        Returns:
            dict: Cache assessment results.
        """
        assessment = {
            'score': 0.0,
            'factors': [],
            'details': {}
        }
        
        try:
            cache_analysis = finding.get('cache_analysis', {})
            
            # Assess cache type
            type_score = self._assess_cache_type(cache_analysis)
            assessment['details']['cache_type'] = {
                'score': type_score,
                'weight': self.cache_factors['cache_type']['weight']
            }
            
            # Assess cache control
            control_score = self._assess_cache_control(cache_analysis)
            assessment['details']['cache_control'] = {
                'score': control_score,
                'weight': self.cache_factors['cache_control']['weight']
            }
            
            # Assess cache distribution
            distribution_score = self._assess_cache_distribution(cache_analysis)
            assessment['details']['cache_distribution'] = {
                'score': distribution_score,
                'weight': self.cache_factors['cache_distribution']['weight']
            }
            
            # Calculate overall cache score
            assessment['score'] = self._calculate_weighted_score(
                assessment['details']
            )
            
            # Identify significant factors
            assessment['factors'] = self._identify_significant_factors(
                assessment['details']
            )
            
        except Exception as e:
            self.logger.error(f"Error assessing cache characteristics: {str(e)}")
        
        return assessment
    
    def _calculate_risk(
        self,
        impact: Dict,
        exploitability: Dict,
        cache: Dict
    ) -> Dict:
        """
        Calculate overall risk level.
        
        Args:
            impact (dict): Impact assessment.
            exploitability (dict): Exploitability assessment.
            cache (dict): Cache assessment.
            
        Returns:
            dict: Risk calculation results.
        """
        calculation = {
            'risk_level': 'low',
            'risk_score': 0.0,
            'factors': []
        }
        
        try:
            # Calculate weighted risk score
            weights = {
                'impact': 0.4,
                'exploitability': 0.35,
                'cache': 0.25
            }
            
            calculation['risk_score'] = (
                impact['score'] * weights['impact'] +
                exploitability['score'] * weights['exploitability'] +
                cache['score'] * weights['cache']
            )
            
            # Determine risk level
            calculation['risk_level'] = self._determine_risk_level(
                calculation['risk_score']
            )
            
            # Combine significant factors
            calculation['factors'].extend(impact['factors'])
            calculation['factors'].extend(exploitability['factors'])
            calculation['factors'].extend(cache['factors'])
            
        except Exception as e:
            self.logger.error(f"Error calculating risk: {str(e)}")
        
        return calculation
    
    def _assess_payload_execution(self, payload: Dict) -> float:
        """Assess payload execution impact."""
        try:
            criteria = self.impact_factors['payload_execution']['criteria']
            
            # Check payload type
            payload_type = payload.get('type', '').lower()
            for type_name, score in criteria.items():
                if type_name in payload_type:
                    return score
            
            return 0.5  # Default score
            
        except Exception:
            return 0.0
    
    def _assess_cache_persistence(self, cache_analysis: Dict) -> float:
        """Assess cache persistence impact."""
        try:
            criteria = self.impact_factors['cache_persistence']['criteria']
            
            # Check persistence duration
            duration = cache_analysis.get('persistence_duration', 0)
            if duration > 3600:  # More than 1 hour
                return criteria['persistent']
            elif duration > 600:  # More than 10 minutes
                return criteria['semi-persistent']
            else:
                return criteria['temporary']
            
        except Exception:
            return 0.0
    
    def _assess_affected_scope(self, finding: Dict) -> float:
        """Assess affected scope impact."""
        try:
            criteria = self.impact_factors['affected_scope']['criteria']
            
            # Check scope characteristics
            cache_analysis = finding.get('cache_analysis', {})
            if cache_analysis.get('is_global', False):
                return criteria['global']
            elif cache_analysis.get('is_shared', False):
                return criteria['shared']
            else:
                return criteria['local']
            
        except Exception:
            return 0.0
    
    def _assess_cache_predictability(self, cache_analysis: Dict) -> float:
        """Assess cache predictability."""
        try:
            criteria = self.exploitability_factors['cache_predictability']['criteria']
            
            # Check cache behavior consistency
            consistency = cache_analysis.get('consistency', 0.0)
            if consistency >= 0.8:
                return criteria['consistent']
            elif consistency >= 0.5:
                return criteria['predictable']
            else:
                return criteria['variable']
            
        except Exception:
            return 0.0
    
    def _assess_access_complexity(self, finding: Dict) -> float:
        """Assess access complexity."""
        try:
            criteria = self.exploitability_factors['access_complexity']['criteria']
            
            # Check complexity factors
            if finding.get('requires_privileged_access', False):
                return criteria['high']
            elif finding.get('requires_specific_conditions', False):
                return criteria['medium']
            else:
                return criteria['low']
            
        except Exception:
            return 0.0
    
    def _assess_authentication(self, finding: Dict) -> float:
        """Assess authentication requirements."""
        try:
            criteria = self.exploitability_factors['authentication']['criteria']
            
            # Check authentication requirements
            if finding.get('requires_authentication', False):
                if finding.get('requires_multiple_auth', False):
                    return criteria['multiple']
                else:
                    return criteria['single']
            else:
                return criteria['none']
            
        except Exception:
            return 0.0
    
    def _assess_cache_type(self, cache_analysis: Dict) -> float:
        """Assess cache type characteristics."""
        try:
            criteria = self.cache_factors['cache_type']['criteria']
            
            # Determine cache type
            cache_type = cache_analysis.get('cache_type', '').lower()
            if 'public' in cache_type:
                return criteria['public']
            elif 'shared' in cache_type:
                return criteria['shared']
            else:
                return criteria['private']
            
        except Exception:
            return 0.0
    
    def _assess_cache_control(self, cache_analysis: Dict) -> float:
        """Assess cache control mechanisms."""
        try:
            criteria = self.cache_factors['cache_control']['criteria']
            
            # Check cache control headers
            headers = cache_analysis.get('cache_headers', {})
            if not headers:
                return criteria['none']
            elif 'must-revalidate' in str(headers):
                return criteria['strong']
            else:
                return criteria['weak']
            
        except Exception:
            return 0.0
    
    def _assess_cache_distribution(self, cache_analysis: Dict) -> float:
        """Assess cache distribution characteristics."""
        try:
            criteria = self.cache_factors['cache_distribution']['criteria']
            
            # Check distribution type
            if cache_analysis.get('is_cdn', False):
                return criteria['cdn']
            elif cache_analysis.get('is_reverse_proxy', False):
                return criteria['reverse_proxy']
            else:
                return criteria['browser']
            
        except Exception:
            return 0.0
    
    def _calculate_weighted_score(self, details: Dict) -> float:
        """Calculate weighted score from details."""
        try:
            total_weight = sum(d['weight'] for d in details.values())
            if total_weight <= 0:
                return 0.0
            
            weighted_sum = sum(
                d['score'] * d['weight']
                for d in details.values()
            )
            
            return weighted_sum / total_weight
            
        except Exception:
            return 0.0
    
    def _identify_significant_factors(self, details: Dict) -> List[Dict]:
        """Identify significant risk factors."""
        factors = []
        
        try:
            # Find factors with high scores
            for name, detail in details.items():
                if detail['score'] >= 0.7:
                    factors.append({
                        'name': name,
                        'score': detail['score'],
                        'weight': detail['weight']
                    })
            
        except Exception as e:
            self.logger.error(f"Error identifying factors: {str(e)}")
        
        return factors
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level from score."""
        try:
            for level, props in self.risk_levels.items():
                if score >= props['score']:
                    return level
            return 'low'
        except Exception:
            return 'low'
    
    def _generate_recommendations(self, assessment: Dict) -> List[Dict]:
        """Generate risk mitigation recommendations."""
        recommendations = []
        
        try:
            # Add general recommendations
            if assessment['risk_level'] in ['critical', 'high']:
                recommendations.append({
                    'priority': 'high',
                    'title': 'Implement Immediate Cache Controls',
                    'description': 'Implement strict cache control headers and validation mechanisms.'
                })
            
            # Add factor-specific recommendations
            for factor in assessment['factors']:
                if factor['name'] == 'cache_persistence':
                    recommendations.append({
                        'priority': 'medium',
                        'title': 'Reduce Cache Persistence',
                        'description': 'Implement shorter cache TTLs and proper cache invalidation.'
                    })
                elif factor['name'] == 'cache_distribution':
                    recommendations.append({
                        'priority': 'medium',
                        'title': 'Review Cache Distribution',
                        'description': 'Review and adjust cache distribution policies.'
                    })
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {str(e)}")
        
        return recommendations
    
    def _identify_highest_risks(
        self,
        findings: List[Dict],
        assessments: List[Dict]
    ) -> List[Dict]:
        """Identify findings with highest risk levels."""
        highest_risks = []
        
        try:
            # Sort by risk score
            risk_items = list(zip(findings, assessments))
            risk_items.sort(
                key=lambda x: x[1]['risk_score'],
                reverse=True
            )
            
            # Take top risks
            for finding, assessment in risk_items[:5]:
                highest_risks.append({
                    'finding': finding,
                    'risk_level': assessment['risk_level'],
                    'risk_score': assessment['risk_score'],
                    'key_factors': assessment['factors']
                })
            
        except Exception as e:
            self.logger.error(f"Error identifying highest risks: {str(e)}")
        
        return highest_risks
    
    def _generate_batch_summary(
        self,
        findings: List[Dict],
        assessments: List[Dict]
    ) -> Dict:
        """Generate summary for batch assessment."""
        summary = {
            'overall_risk_level': 'low',
            'key_findings': [],
            'common_factors': [],
            'affected_components': set()
        }
        
        try:
            # Determine overall risk level
            max_score = max(a['risk_score'] for a in assessments)
            summary['overall_risk_level'] = self._determine_risk_level(max_score)
            
            # Identify key findings
            summary['key_findings'] = self._identify_highest_risks(
                findings,
                assessments
            )
            
            # Analyze common factors
            factor_counts = defaultdict(int)
            for assessment in assessments:
                for factor in assessment['factors']:
                    factor_counts[factor['name']] += 1
            
            # Get most common factors
            summary['common_factors'] = [
                {'name': name, 'count': count}
                for name, count in factor_counts.most_common(3)
            ]
            
            # Collect affected components
            for finding in findings:
                if 'affected_components' in finding:
                    summary['affected_components'].update(
                        finding['affected_components']
                    )
            
            # Convert set to list for serialization
            summary['affected_components'] = list(
                summary['affected_components']
            )
            
        except Exception as e:
            self.logger.error(f"Error generating batch summary: {str(e)}")
        
        return summary
    
    def _calculate_batch_statistics(self, assessments: List[Dict]) -> Dict:
        """Calculate statistics for batch assessment."""
        stats = {
            'risk_levels': defaultdict(int),
            'average_score': 0.0,
            'factor_distribution': defaultdict(int),
            'score_distribution': {
                'min': float('inf'),
                'max': float('-inf'),
                'mean': 0.0
            }
        }
        
        try:
            if not assessments:
                return stats
            
            # Calculate distributions
            scores = []
            for assessment in assessments:
                # Count risk levels
                stats['risk_levels'][
                    assessment['risk_level']
                ] += 1
                
                # Track scores
                score = assessment['risk_score']
                scores.append(score)
                stats['score_distribution']['min'] = min(
                    stats['score_distribution']['min'],
                    score
                )
                stats['score_distribution']['max'] = max(
                    stats['score_distribution']['max'],
                    score
                )
                
                # Count factors
                for factor in assessment['factors']:
                    stats['factor_distribution'][
                        factor['name']
                    ] += 1
            
            # Calculate average score
            stats['average_score'] = sum(scores) / len(scores)
            stats['score_distribution']['mean'] = stats['average_score']
            
        except Exception as e:
            self.logger.error(f"Error calculating batch statistics: {str(e)}")
        
        return stats
