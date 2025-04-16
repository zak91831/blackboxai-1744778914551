"""
CacheXSSDetector Package

A sophisticated security tool for detecting and analyzing cache-based Cross-Site Scripting (XSS) 
vulnerabilities in web applications.
"""

import logging
import os

# Setup default logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
    ]
)

# Create package logger
logger = logging.getLogger('cachexssdetector')

# Package version
__version__ = '1.0.0'

# Export main components
from .core_scanner import CoreScanner, URLPathManipulator, CacheBehaviorAnalyzer, XSSPayloadGenerator, ResponseAnalyzer
from .verification_system import MultiClientSimulator, CacheHitMissDetector, FalsePositiveReducer
from .reporting_module import ReportGenerator, RiskAssessor

__all__ = [
    'CoreScanner',
    'URLPathManipulator', 
    'CacheBehaviorAnalyzer',
    'XSSPayloadGenerator',
    'ResponseAnalyzer',
    'MultiClientSimulator',
    'CacheHitMissDetector',
    'FalsePositiveReducer',
    'ReportGenerator',
    'RiskAssessor'
]
