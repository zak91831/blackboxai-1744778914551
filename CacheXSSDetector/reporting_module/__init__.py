"""
Reporting Module Package

This package provides components for generating detailed security reports
for cache-based XSS vulnerabilities.
"""

from .risk_assessment import RiskAssessor
from .vulnerability_classification import VulnerabilityClassifier
from .report_generator import ReportGenerator
from .enhanced_reporting_tools import EnhancedReportGenerator

# For backward compatibility, make EnhancedReportGenerator available as ReportGenerator
ReportGenerator = EnhancedReportGenerator

__all__ = [
    'RiskAssessor',
    'VulnerabilityClassifier',
    'ReportGenerator',
    'EnhancedReportGenerator'
]
