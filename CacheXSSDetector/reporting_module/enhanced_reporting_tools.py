"""
Enhanced Reporting Tools Module

This module extends the basic report generator functionality with advanced
visualization and customization options for security reports.
"""

import logging
from typing import Dict, List, Optional
import os
from datetime import datetime
import base64
import json
from pathlib import Path

# Import the base report generator
from .report_generator import ReportGenerator

class EnhancedReportGenerator(ReportGenerator):
    """
    An enhanced version of the report generator with advanced visualization
    and customization options.
    """
    
    def __init__(self, config, report_format="html"):
        """
        Initialize the Enhanced Report Generator.
        
        Args:
            config (dict): Configuration settings for report generation.
            report_format (str): Format of the report (html, pdf, json, etc.)
        """
        super().__init__(config)
        self.logger = logging.getLogger('cachexssdetector.enhanced_reporting_tools')
        self.report_format = report_format
        
        # Load theme configuration
        self.theme = config.get('reporting', {}).get('customization', {}).get('colors', {})
        
        # Set default colors if not provided
        if not self.theme:
            self.theme = {
                'primary': '#4F46E5',    # Indigo
                'secondary': '#6B7280',  # Gray
                'success': '#10B981',    # Green
                'danger': '#EF4444',     # Red
                'warning': '#F59E0B',    # Amber
                'info': '#3B82F6'        # Blue
            }
        
        # Configure visualization settings
        self.chart_settings = {
            'include_charts': True,
            'chart_theme': 'plotly_white',
            'interactive_charts': True
        }
        
        self.logger.info("Enhanced Report Generator initialized")
    
    def generate(self, report_data, output_path):
        """
        Generate an enhanced report with visualizations and custom styling.
        
        Args:
            report_data (dict): Data to include in the report.
            output_path (str): Path to save the report.
            
        Returns:
            str: Path to the generated report.
        """
        try:
            # Prepare visualization data
            visualization_data = self._prepare_visualization_data(report_data)
            
            # Add visualization data to the report context
            enhanced_data = {**report_data}
            enhanced_data['include_charts'] = self.chart_settings['include_charts']
            
            # Add color mappings for different risk levels
            enhanced_data['severity_colors'] = {
                'critical': 'red',
                'high': 'orange', 
                'medium': 'yellow',
                'low': 'blue',
                'info': 'gray'
            }
            
            enhanced_data['level_colors'] = {
                'critical': 'red',
                'high': 'orange', 
                'medium': 'yellow',
                'low': 'blue',
                'info': 'gray'
            }
            
            # Add chart data as JSON
            if self.chart_settings['include_charts']:
                enhanced_data['risk_distribution_data'] = json.dumps(
                    visualization_data['risk_distribution']
                )
                enhanced_data['cache_behavior_data'] = json.dumps(
                    visualization_data['cache_behavior']
                )
            
            # Generate the report using the base generator
            return super()._save_report(
                super()._render_report(enhanced_data),
                os.path.dirname(output_path)
            )
            
        except Exception as e:
            self.logger.error(f"Error generating enhanced report: {e}")
            raise
    
    def _prepare_visualization_data(self, report_data):
        """
        Prepare data for visualizations.
        
        Args:
            report_data (dict): Report data.
            
        Returns:
            dict: Visualization data.
        """
        visualizations = {}
        
        try:
            # Risk distribution chart data
            risk_counts = report_data.get('summary', {}).get('risk_levels', {})
            visualizations['risk_distribution'] = {
                'labels': list(risk_counts.keys()),
                'values': list(risk_counts.values()),
                'colors': [
                    self.theme['danger'],     # Critical
                    self.theme['warning'],    # High
                    self.theme['info'],       # Medium
                    self.theme['success'],    # Low
                    self.theme['secondary']   # Info
                ]
            }
            
            # Cache behavior chart data
            findings = report_data.get('findings', [])
            cache_statuses = ['hit', 'miss', 'partial', 'unknown']
            cache_counts = {status: 0 for status in cache_statuses}
            
            for finding in findings:
                cache_analysis = finding.get('cache_analysis', {})
                if cache_analysis.get('is_cached', False):
                    cache_counts['hit'] += 1
                else:
                    cache_counts['miss'] += 1
            
            visualizations['cache_behavior'] = {
                'x': list(cache_counts.keys()),
                'y': list(cache_counts.values())
            }
            
        except Exception as e:
            self.logger.error(f"Error preparing visualization data: {e}")
        
        return visualizations
    
    def generate_pdf(self, report_data, output_path):
        """
        Generate a PDF report.
        
        Args:
            report_data (dict): Data to include in the report.
            output_path (str): Path to save the report.
            
        Returns:
            str: Path to the generated PDF report.
        """
        try:
            from weasyprint import HTML
            
            # First generate the HTML report
            html_path = self.generate(report_data, output_path + '.html')
            
            # Convert to PDF
            pdf_path = output_path + '.pdf'
            HTML(html_path).write_pdf(pdf_path)
            
            self.logger.info(f"PDF report generated: {pdf_path}")
            return pdf_path
            
        except ImportError:
            self.logger.error("WeasyPrint not installed. Unable to generate PDF.")
            self.logger.info("Falling back to HTML report generation.")
            return self.generate(report_data, output_path)
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {e}")
            raise

# For backwards compatibility, expose the enhanced generator as ReportGenerator
ReportGenerator = EnhancedReportGenerator
