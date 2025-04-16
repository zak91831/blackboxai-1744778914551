"""
Report Generator Module

This module generates detailed security reports for cache-based XSS vulnerabilities,
including findings, analysis, and recommendations.
"""

import logging
import json
from datetime import datetime
import os
from typing import Dict, List, Optional
import jinja2
import markdown2
import base64
import plotly.graph_objects as go
import plotly.express as px
from pathlib import Path

class ReportGenerator:
    """
    A class to generate comprehensive security reports.
    """
    
    def __init__(self, config):
        """
        Initialize the Report Generator.
        
        Args:
            config (dict): Configuration settings for report generation.
        """
        self.logger = logging.getLogger('cachexssdetector.report_generator')
        self.config = config
        
        # Initialize Jinja2 environment
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(template_dir),
            autoescape=True
        )
        
        # Report configuration
        self.report_config = config.get('reporting', {})
        self.company_info = self.report_config.get('company_info', {})
        
        self.logger.info("Report Generator initialized")
    
    def generate_report(self, scan_results: Dict, output_dir: str) -> str:
        """
        Generate a comprehensive security report.
        
        Args:
            scan_results (dict): Complete scan results including findings and analysis.
            output_dir (str): Directory to save the report.
            
        Returns:
            str: Path to the generated report.
        """
        try:
            # Prepare report data
            report_data = self._prepare_report_data(scan_results)
            
            # Generate visualizations
            report_data['visualizations'] = self._generate_visualizations(scan_results)
            
            # Render report template
            report_html = self._render_report(report_data)
            
            # Save report
            report_path = self._save_report(report_html, output_dir)
            
            self.logger.info(f"Report generated successfully: {report_path}")
            return report_path
            
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            raise
    
    def _prepare_report_data(self, scan_results: Dict) -> Dict:
        """
        Prepare data for report generation.
        
        Args:
            scan_results (dict): Scan results to process.
            
        Returns:
            dict: Processed report data.
        """
        report_data = {
            'title': 'Cache-Based XSS Security Assessment Report',
            'timestamp': datetime.utcnow().isoformat(),
            'company_info': self.company_info,
            'executive_summary': self._generate_executive_summary(scan_results),
            'findings': self._process_findings(scan_results.get('findings', [])),
            'statistics': self._generate_statistics(scan_results),
            'recommendations': self._generate_recommendations(scan_results),
            'appendices': self._generate_appendices(scan_results)
        }
        
        return report_data
    
    def _generate_executive_summary(self, scan_results: Dict) -> Dict:
        """
        Generate executive summary of findings.
        
        Args:
            scan_results (dict): Scan results to summarize.
            
        Returns:
            dict: Executive summary.
        """
        findings = scan_results.get('findings', [])
        risk_assessment = scan_results.get('risk_assessment', {})
        
        summary = {
            'overview': {
                'total_findings': len(findings),
                'risk_levels': self._count_risk_levels(findings),
                'overall_risk': risk_assessment.get('overall_risk', 'Unknown')
            },
            'key_findings': self._extract_key_findings(findings),
            'risk_summary': risk_assessment.get('summary', ''),
            'immediate_actions': self._generate_immediate_actions(findings, risk_assessment)
        }
        
        return summary
    
    def _process_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Process and format findings for the report.
        
        Args:
            findings (list): Raw findings to process.
            
        Returns:
            list: Processed findings.
        """
        processed_findings = []
        
        for finding in findings:
            processed = {
                'id': finding.get('id', 'N/A'),
                'title': self._generate_finding_title(finding),
                'description': finding.get('description', ''),
                'risk_level': finding.get('risk_assessment', {}).get('risk_level', 'Unknown'),
                'risk_score': finding.get('risk_assessment', {}).get('risk_score', 0),
                'classification': finding.get('classification', {}),
                'evidence': self._process_evidence(finding.get('evidence', {})),
                'recommendations': finding.get('recommendations', []),
                'technical_details': self._process_technical_details(finding),
                'cache_analysis': self._process_cache_analysis(finding.get('cache_analysis', {}))
            }
            processed_findings.append(processed)
        
        return processed_findings
    
    def _generate_statistics(self, scan_results: Dict) -> Dict:
        """
        Generate statistical analysis of findings.
        
        Args:
            scan_results (dict): Scan results to analyze.
            
        Returns:
            dict: Statistical analysis.
        """
        findings = scan_results.get('findings', [])
        
        stats = {
            'risk_distribution': self._calculate_risk_distribution(findings),
            'cache_statistics': self._calculate_cache_statistics(findings),
            'vulnerability_types': self._count_vulnerability_types(findings),
            'affected_components': self._analyze_affected_components(findings),
            'temporal_analysis': self._analyze_temporal_patterns(findings)
        }
        
        return stats
    
    def _generate_visualizations(self, scan_results: Dict) -> Dict:
        """
        Generate data visualizations for the report.
        
        Args:
            scan_results (dict): Scan results to visualize.
            
        Returns:
            dict: Generated visualizations.
        """
        findings = scan_results.get('findings', [])
        
        visualizations = {
            'risk_distribution': self._create_risk_distribution_chart(findings),
            'cache_impact': self._create_cache_impact_chart(findings),
            'vulnerability_types': self._create_vulnerability_types_chart(findings),
            'risk_timeline': self._create_risk_timeline_chart(findings)
        }
        
        return visualizations
    
    def _create_risk_distribution_chart(self, findings: List[Dict]) -> str:
        """
        Create a chart showing risk level distribution.
        
        Args:
            findings (list): Findings to visualize.
            
        Returns:
            str: Base64 encoded chart image.
        """
        risk_counts = self._count_risk_levels(findings)
        
        fig = go.Figure(data=[
            go.Bar(
                x=list(risk_counts.keys()),
                y=list(risk_counts.values()),
                marker_color=['#ff0000', '#ff9900', '#ffcc00', '#00cc00', '#0099cc']
            )
        ])
        
        fig.update_layout(
            title='Risk Level Distribution',
            xaxis_title='Risk Level',
            yaxis_title='Number of Findings',
            template='plotly_white'
        )
        
        return self._fig_to_base64(fig)
    
    def _create_cache_impact_chart(self, findings: List[Dict]) -> str:
        """
        Create a chart showing cache-related impact.
        
        Args:
            findings (list): Findings to visualize.
            
        Returns:
            str: Base64 encoded chart image.
        """
        cache_data = self._calculate_cache_statistics(findings)
        
        fig = go.Figure(data=[
            go.Pie(
                labels=list(cache_data.keys()),
                values=list(cache_data.values()),
                hole=.3
            )
        ])
        
        fig.update_layout(
            title='Cache Impact Distribution',
            template='plotly_white'
        )
        
        return self._fig_to_base64(fig)
    
    def _create_vulnerability_types_chart(self, findings: List[Dict]) -> str:
        """
        Create a chart showing vulnerability type distribution.
        
        Args:
            findings (list): Findings to visualize.
            
        Returns:
            str: Base64 encoded chart image.
        """
        vuln_types = self._count_vulnerability_types(findings)
        
        fig = go.Figure(data=[
            go.Bar(
                x=list(vuln_types.keys()),
                y=list(vuln_types.values()),
                marker_color='#3366cc'
            )
        ])
        
        fig.update_layout(
            title='Vulnerability Type Distribution',
            xaxis_title='Vulnerability Type',
            yaxis_title='Count',
            template='plotly_white'
        )
        
        return self._fig_to_base64(fig)
    
    def _create_risk_timeline_chart(self, findings: List[Dict]) -> str:
        """
        Create a timeline chart of findings by risk level.
        
        Args:
            findings (list): Findings to visualize.
            
        Returns:
            str: Base64 encoded chart image.
        """
        # Extract timestamps and risk levels
        timeline_data = []
        for finding in findings:
            timestamp = finding.get('timestamp', datetime.utcnow().isoformat())
            risk_level = finding.get('risk_assessment', {}).get('risk_level', 'Unknown')
            timeline_data.append({
                'timestamp': timestamp,
                'risk_level': risk_level
            })
        
        # Sort by timestamp
        timeline_data.sort(key=lambda x: x['timestamp'])
        
        fig = go.Figure()
        
        for risk_level in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            level_data = [d for d in timeline_data if d['risk_level'] == risk_level]
            if level_data:
                fig.add_trace(go.Scatter(
                    x=[d['timestamp'] for d in level_data],
                    y=[risk_level] * len(level_data),
                    mode='markers',
                    name=risk_level
                ))
        
        fig.update_layout(
            title='Finding Timeline by Risk Level',
            xaxis_title='Time',
            yaxis_title='Risk Level',
            template='plotly_white'
        )
        
        return self._fig_to_base64(fig)
    
    def _fig_to_base64(self, fig) -> str:
        """
        Convert a plotly figure to base64 string.
        
        Args:
            fig: Plotly figure object.
            
        Returns:
            str: Base64 encoded image.
        """
        img_bytes = fig.to_image(format="png")
        return base64.b64encode(img_bytes).decode()
    
    def _render_report(self, report_data: Dict) -> str:
        """
        Render the report template with data.
        
        Args:
            report_data (dict): Data to include in the report.
            
        Returns:
            str: Rendered HTML report.
        """
        template = self.jinja_env.get_template('report_template.html')
        return template.render(**report_data)
    
    def _save_report(self, report_html: str, output_dir: str) -> str:
        """
        Save the report to file.
        
        Args:
            report_html (str): Generated report HTML.
            output_dir (str): Directory to save the report.
            
        Returns:
            str: Path to saved report.
        """
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"security_report_{timestamp}.html"
        report_path = os.path.join(output_dir, filename)
        
        # Write report to file
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_html)
        
        return report_path
    
    def _generate_finding_title(self, finding: Dict) -> str:
        """
        Generate a descriptive title for a finding.
        
        Args:
            finding (dict): Finding to generate title for.
            
        Returns:
            str: Generated title.
        """
        classification = finding.get('classification', {})
        category = classification.get('category', 'Unknown')
        location = finding.get('location', 'Unknown Location')
        
        return f"Cache-Based {category} Vulnerability in {location}"
    
    def _process_evidence(self, evidence: Dict) -> Dict:
        """
        Process and format vulnerability evidence.
        
        Args:
            evidence (dict): Raw evidence to process.
            
        Returns:
            dict: Processed evidence.
        """
        processed = {
            'description': evidence.get('description', ''),
            'request': self._format_http_message(evidence.get('request', {})),
            'response': self._format_http_message(evidence.get('response', {})),
            'screenshots': evidence.get('screenshots', []),
            'additional_info': evidence.get('additional_info', {})
        }
        
        return processed
    
    def _format_http_message(self, message: Dict) -> Dict:
        """
        Format HTTP request/response messages for display.
        
        Args:
            message (dict): HTTP message to format.
            
        Returns:
            dict: Formatted message.
        """
        formatted = {
            'method': message.get('method', ''),
            'url': message.get('url', ''),
            'headers': message.get('headers', {}),
            'body': message.get('body', '')
        }
        
        # Format headers for display
        if formatted['headers']:
            formatted['headers'] = '\n'.join(f"{k}: {v}" for k, v in formatted['headers'].items())
        
        return formatted
    
    def _process_technical_details(self, finding: Dict) -> Dict:
        """
        Process technical details of a finding.
        
        Args:
            finding (dict): Finding to process.
            
        Returns:
            dict: Processed technical details.
        """
        return {
            'vulnerability_type': finding.get('type', 'Unknown'),
            'affected_parameters': finding.get('affected_parameters', []),
            'affected_urls': finding.get('affected_urls', []),
            'technical_description': finding.get('technical_description', ''),
            'proof_of_concept': finding.get('proof_of_concept', ''),
            'attack_vectors': finding.get('attack_vectors', [])
        }
    
    def _process_cache_analysis(self, cache_analysis: Dict) -> Dict:
        """
        Process cache analysis results.
        
        Args:
            cache_analysis (dict): Cache analysis to process.
            
        Returns:
            dict: Processed cache analysis.
        """
        return {
            'is_cached': cache_analysis.get('is_cached', False),
            'cache_duration': cache_analysis.get('cache_duration', 'Unknown'),
            'cache_scope': cache_analysis.get('cache_scope', 'Unknown'),
            'cache_headers': cache_analysis.get('cache_headers', {}),
            'cache_behavior': cache_analysis.get('cache_behavior', 'Unknown'),
            'risk_factors': cache_analysis.get('risk_factors', [])
        }
    
    def _count_risk_levels(self, findings: List[Dict]) -> Dict:
        """
        Count findings by risk level.
        
        Args:
            findings (list): Findings to count.
            
        Returns:
            dict: Risk level counts.
        """
        risk_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for finding in findings:
            risk_level = finding.get('risk_assessment', {}).get('risk_level', 'Unknown')
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
        
        return risk_counts
    
    def _extract_key_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Extract the most significant findings.
        
        Args:
            findings (list): All findings.
            
        Returns:
            list: Key findings.
        """
        # Sort findings by risk score
        sorted_findings = sorted(
            findings,
            key=lambda x: x.get('risk_assessment', {}).get('risk_score', 0),
            reverse=True
        )
        
        # Extract top findings (up to 5)
        key_findings = []
        for finding in sorted_findings[:5]:
            key_findings.append({
                'title': self._generate_finding_title(finding),
                'risk_level': finding.get('risk_assessment', {}).get('risk_level', 'Unknown'),
                'summary': finding.get('summary', '')
            })
        
        return key_findings
    
    def _generate_immediate_actions(self, findings: List[Dict], risk_assessment: Dict) -> List[str]:
        """
        Generate list of immediate actions based on findings.
        
        Args:
            findings (list): All findings.
            risk_assessment (dict): Overall risk assessment.
            
        Returns:
            list: Immediate actions.
        """
        actions = []
        
        # Add critical/high risk findings
        critical_high = [f for f in findings if f.get('risk_assessment', {}).get('risk_level') in ['Critical', 'High']]
        if critical_high:
            actions.append("Address critical and high-risk vulnerabilities immediately:")
            for finding in critical_high[:3]:  # Top 3
                actions.append(f"- {self._generate_finding_title(finding)}")
        
        # Add cache-specific actions
        cache_findings = [f for f in findings if f.get('cache_analysis', {}).get('is_cached', False)]
        if cache_findings:
            actions.append("Review and update caching policies:")
            actions.append("- Implement appropriate Cache-Control headers")
            actions.append("- Configure Vary headers correctly")
            actions.append("- Review cache duration settings")
        
        return actions
