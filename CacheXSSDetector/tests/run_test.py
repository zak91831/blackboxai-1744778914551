"""
Test runner for the CacheXSSDetector tests.
"""

import os
import sys
import unittest

# Add the parent directory to the Python path for imports to work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import all the test classes
from test_core import (
    TestCoreScanner,
    TestVerificationSystem,
    TestReportGenerator,
    TestHTTPClient
)

if __name__ == '__main__':
    # Create a test suite with multiple tests
    suite = unittest.TestSuite()
    
    # Add basic initialization tests for each component
    suite.addTest(TestCoreScanner('test_scanner_initialization'))
    suite.addTest(TestVerificationSystem('test_verification_initialization'))
    suite.addTest(TestReportGenerator('test_report_generator_initialization'))
    suite.addTest(TestHTTPClient('test_client_initialization'))
    
    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print results
    if result.wasSuccessful():
        print("All tests passed successfully!")
        sys.exit(0)
    else:
        print("Tests failed.")
        sys.exit(1)
