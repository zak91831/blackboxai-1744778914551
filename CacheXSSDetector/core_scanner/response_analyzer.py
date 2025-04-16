"""
Response Analyzer

This module analyzes HTTP responses to detect successful XSS payload injections
and identify potential vulnerabilities in web applications.
"""

import logging
import re
from html.parser import HTMLParser
import bs4
from bs4 import BeautifulSoup
import urllib.parse

class ResponseAnalyzer:
    """
    A class to analyze HTTP responses for signs of XSS vulnerabilities.
    """
    
    def __init__(self, config):
        """
        Initialize the Response Analyzer.
        
        Args:
            config (dict): Configuration settings for response analysis.
        """
        self.logger = logging.getLogger('cachexssdetector.response_analyzer')
        self.logger.info("Response Analyzer initialized")
        
        # Confidence thresholds
        self.high_confidence_threshold = 0.8
        self.medium_confidence_threshold = 0.5
        
        # Known dangerous contexts
        self.dangerous_contexts = [
            'script',
            'javascript:',
            'data:',
            'onclick',
            'onerror',
            'onload',
            'event',
            'eval(',
            'document.write',
            'innerHTML'
        ]
    
    def analyze(self, cache_results):
        """
        Analyze HTTP responses for XSS vulnerabilities.
        
        Args:
            cache_results (dict): The results from the cache detection process,
                                  including HTTP responses and metadata.
            
        Returns:
            list: A list of findings containing detected XSS vulnerabilities.
        """
        self.logger.info("Analyzing responses for XSS vulnerabilities")
        
        findings = []
        
        # Process each cache result
        for result in cache_results:
            url = result.get('url', '')
            response = result.get('response')
            payload = result.get('payload', {})
            cache_info = result.get('cache_info', {})
            
            if not response or not url:
                continue
                
            self.logger.debug(f"Analyzing response for {url}")
            
            # Extract content type from headers
            content_type = self._get_content_type(response)
            
            # Skip unsupported content types
            if not self._is_analyzable_content(content_type):
                self.logger.debug(f"Skipping unsupported content type: {content_type}")
                continue
            
            # Check for payload reflections
            reflection_findings = self._check_payload_reflections(url, response, payload, content_type)
            if reflection_findings:
                for finding in reflection_findings:
                    finding['cache_info'] = cache_info
                    findings.append(finding)
            
            # Check for DOM-based XSS
            dom_findings = self._check_dom_based_xss(url, response, payload)
            if dom_findings:
                for finding in dom_findings:
                    finding['cache_info'] = cache_info
                    findings.append(finding)
            
            # Check for CSP issues
            csp_findings = self._check_csp_issues(url, response)
            if csp_findings:
                for finding in csp_findings:
                    finding['cache_info'] = cache_info
                    findings.append(finding)
        
        self.logger.info(f"Found {len(findings)} potential XSS vulnerabilities")
        
        return findings
    
    def _get_content_type(self, response):
        """
        Extract content type from response headers.
        
        Args:
            response: HTTP response object.
            
        Returns:
            str: The content type or empty string if not found.
        """
        content_type = ''
        if hasattr(response, 'headers') and 'Content-Type' in response.headers:
            content_type = response.headers['Content-Type'].split(';')[0].lower()
        return content_type
    
    def _is_analyzable_content(self, content_type):
        """
        Check if the content type is supported for analysis.
        
        Args:
            content_type (str): The content type to check.
            
        Returns:
            bool: True if the content type is supported, False otherwise.
        """
        analyzable_types = [
            'text/html',
            'application/xhtml+xml',
            'text/xml',
            'application/xml',
            'text/plain',
            'application/json',
            'application/javascript',
            'text/javascript'
        ]
        
        return any(content_type.startswith(t) for t in analyzable_types)
    
    def _check_payload_reflections(self, url, response, payload, content_type):
        """
        Check if any part of the payload is reflected in the response.
        
        Args:
            url (str): The URL being tested.
            response: HTTP response object.
            payload (dict): The payload used in the request.
            content_type (str): The content type of the response.
            
        Returns:
            list: A list of findings for payload reflections.
        """
        findings = []
        
        if not payload or not hasattr(response, 'content'):
            return findings
        
        # The payload string
        payload_str = payload.get('payload', '')
        if not payload_str:
            return findings
        
        # Get response content as string
        try:
            response_content = response.content.decode('utf-8', errors='ignore')
        except Exception as e:
            self.logger.error(f"Error decoding response content: {e}")
            return findings
        
        # Check for direct payload reflection
        if payload_str in response_content:
            self.logger.debug(f"Found direct payload reflection: {payload_str}")
            
            # Determine the context of the reflection
            context = self._determine_reflection_context(response_content, payload_str, content_type)
            
            # Calculate confidence based on context
            confidence = self._calculate_reflection_confidence(context, payload_str)
            
            finding = {
                'url': url,
                'type': 'XSS',
                'subtype': 'reflected',
                'payload': payload,
                'confidence': confidence,
                'context': context,
                'description': f"Payload is reflected in the response {context['type']} context",
                'evidence': {
                    'request_url': url,
                    'response_excerpt': self._get_reflection_excerpt(response_content, payload_str),
                    'content_type': content_type
                },
                'risk': 'high' if confidence >= self.high_confidence_threshold else 'medium'
            }
            
            findings.append(finding)
        
        # Check for encoded payload reflections
        encoded_payloads = self._generate_encoded_variations(payload_str)
        for encoded_payload, encoding_type in encoded_payloads:
            if encoded_payload in response_content:
                self.logger.debug(f"Found encoded payload reflection: {encoded_payload} ({encoding_type})")
                
                context = self._determine_reflection_context(response_content, encoded_payload, content_type)
                confidence = self._calculate_reflection_confidence(context, encoded_payload) * 0.9  # Slightly lower confidence for encoded reflections
                
                finding = {
                    'url': url,
                    'type': 'XSS',
                    'subtype': 'reflected_encoded',
                    'payload': payload,
                    'encoding': encoding_type,
                    'confidence': confidence,
                    'context': context,
                    'description': f"Encoded payload ({encoding_type}) is reflected in the response {context['type']} context",
                    'evidence': {
                        'request_url': url,
                        'response_excerpt': self._get_reflection_excerpt(response_content, encoded_payload),
                        'content_type': content_type
                    },
                    'risk': 'high' if confidence >= self.high_confidence_threshold else 'medium'
                }
                
                findings.append(finding)
        
        # Check for partial payload reflections (for complex payloads)
        if len(payload_str) > 20:
            significant_parts = self._extract_significant_parts(payload_str)
            for part in significant_parts:
                if part in response_content and len(part) > 10:  # Minimum length to avoid false positives
                    self.logger.debug(f"Found partial payload reflection: {part}")
                    
                    context = self._determine_reflection_context(response_content, part, content_type)
                    confidence = self._calculate_reflection_confidence(context, part) * 0.8  # Lower confidence for partial reflections
                    
                    finding = {
                        'url': url,
                        'type': 'XSS',
                        'subtype': 'reflected_partial',
                        'payload': payload,
                        'reflected_part': part,
                        'confidence': confidence,
                        'context': context,
                        'description': f"Part of payload is reflected in the response {context['type']} context",
                        'evidence': {
                            'request_url': url,
                            'response_excerpt': self._get_reflection_excerpt(response_content, part),
                            'content_type': content_type
                        },
                        'risk': 'medium'
                    }
                    
                    findings.append(finding)
        
        return findings
    
    def _check_dom_based_xss(self, url, response, payload):
        """
        Check for DOM-based XSS vulnerabilities.
        
        Args:
            url (str): The URL being tested.
            response: HTTP response object.
            payload (dict): The payload used in the request.
            
        Returns:
            list: A list of findings for DOM-based XSS.
        """
        findings = []
        
        if not hasattr(response, 'content'):
            return findings
        
        try:
            response_content = response.content.decode('utf-8', errors='ignore')
        except Exception as e:
            self.logger.error(f"Error decoding response content: {e}")
            return findings
        
        # Check for DOM sources and sinks
        dom_sources = [
            'document.URL',
            'document.documentURI',
            'document.location',
            'document.referrer',
            'window.location',
            'document.write',
            'document.writeln',
            'document.domain',
            'location.hash',
            'location.href',
            'location.search',
            'location.pathname'
        ]
        
        dom_sinks = [
            'eval',
            'setTimeout',
            'setInterval',
            'document.write',
            'document.writeln',
            'innerHTML',
            'outerHTML',
            'insertAdjacentHTML',
            'onevent'
        ]
        
        # Look for potential DOM-based XSS patterns
        for source in dom_sources:
            if source in response_content:
                source_index = response_content.find(source)
                surrounding_code = response_content[max(0, source_index - 50):min(len(response_content), source_index + 150)]
                
                # Check if this source is used with a sink
                for sink in dom_sinks:
                    if sink in surrounding_code:
                        self.logger.debug(f"Found potential DOM-based XSS: {source} -> {sink}")
                        
                        finding = {
                            'url': url,
                            'type': 'XSS',
                            'subtype': 'dom_based',
                            'payload': payload,
                            'confidence': 0.7,  # Medium-high confidence
                            'description': f"Potential DOM-based XSS detected: {source} -> {sink}",
                            'evidence': {
                                'request_url': url,
                                'source': source,
                                'sink': sink,
                                'code_excerpt': surrounding_code
                            },
                            'risk': 'high'
                        }
                        
                        findings.append(finding)
        
        return findings
    
    def _check_csp_issues(self, url, response):
        """
        Check for Content Security Policy issues.
        
        Args:
            url (str): The URL being tested.
            response: HTTP response object.
            
        Returns:
            list: A list of findings for CSP issues.
        """
        findings = []
        
        if not hasattr(response, 'headers'):
            return findings
        
        # Check if CSP header is present
        csp_header = None
        for header in ['Content-Security-Policy', 'X-Content-Security-Policy', 'X-WebKit-CSP']:
            if header in response.headers:
                csp_header = response.headers[header]
                break
        
        if not csp_header:
            finding = {
                'url': url,
                'type': 'CSP',
                'subtype': 'missing',
                'confidence': 0.6,  # Medium confidence
                'description': "Content Security Policy header is missing",
                'evidence': {
                    'request_url': url
                },
                'risk': 'medium'
            }
            
            findings.append(finding)
            return findings
        
        # Check for unsafe CSP directives
        unsafe_directives = []
        
        if "script-src 'unsafe-inline'" in csp_header or "script-src 'unsafe-eval'" in csp_header:
            unsafe_directives.append("script-src allows unsafe-inline or unsafe-eval")
        
        if "script-src *" in csp_header or "script-src http:" in csp_header:
            unsafe_directives.append("script-src allows any origin or http:")
        
        if "default-src 'none'" not in csp_header and "default-src 'self'" not in csp_header:
            unsafe_directives.append("No strict default-src policy")
        
        if unsafe_directives:
            finding = {
                'url': url,
                'type': 'CSP',
                'subtype': 'unsafe_directives',
                'confidence': 0.7,  # Medium-high confidence
                'description': "Content Security Policy contains unsafe directives",
                'evidence': {
                    'request_url': url,
                    'csp_header': csp_header,
                    'unsafe_directives': unsafe_directives
                },
                'risk': 'medium'
            }
            
            findings.append(finding)
        
        return findings
    
    def _determine_reflection_context(self, response_content, reflected_str, content_type):
        """
        Determine the context in which the payload is reflected.
        
        Args:
            response_content (str): The response content.
            reflected_str (str): The reflected string.
            content_type (str): The content type of the response.
            
        Returns:
            dict: Information about the reflection context.
        """
        context = {
            'type': 'unknown',
            'tag': None,
            'attribute': None,
            'is_executable': False,
            'parent_tags': []
        }
        
        # For HTML content, use BeautifulSoup to analyze context
        if content_type.startswith('text/html') or content_type.startswith('application/xhtml+xml'):
            try:
                # Find all occurrences of the reflected string
                reflection_indices = [m.start() for m in re.finditer(re.escape(reflected_str), response_content)]
                
                if reflection_indices:
                    # Parse the HTML
                    soup = BeautifulSoup(response_content, 'html.parser')
                    
                    # For each occurrence, determine the context
                    for index in reflection_indices:
                        # Find the surrounding HTML
                        context = self._analyze_html_context(soup, response_content, index, reflected_str)
                        
                        # If we found an executable context, no need to check further
                        if context['is_executable']:
                            break
            except Exception as e:
                self.logger.error(f"Error analyzing HTML context: {e}")
                # Fall back to basic context analysis
                context = self._analyze_basic_context(response_content, reflected_str)
        
        # For JavaScript content
        elif content_type.startswith('application/javascript') or content_type.startswith('text/javascript'):
            context['type'] = 'javascript'
            context['is_executable'] = self._is_executable_js_context(response_content, reflected_str)
        
        # For JSON content
        elif content_type.startswith('application/json'):
            context['type'] = 'json'
            context['is_executable'] = False  # JSON itself is not executable
        
        # For plain text content
        elif content_type.startswith('text/plain'):
            context['type'] = 'text'
            context['is_executable'] = False  # Plain text is not executable
        
        # For other content types, use basic context analysis
        else:
            context = self._analyze_basic_context(response_content, reflected_str)
        
        return context
    
    def _analyze_html_context(self, soup, response_content, reflection_index, reflected_str):
        """
        Analyze the HTML context of a reflection.
        
        Args:
            soup (BeautifulSoup): Parsed HTML.
            response_content (str): Raw response content.
            reflection_index (int): Index of the reflection in the content.
            reflected_str (str): The reflected string.
            
        Returns:
            dict: Context information.
        """
        context = {
            'type': 'html',
            'tag': None,
            'attribute': None,
            'is_executable': False,
            'parent_tags': []
        }
        
        # Extract a segment of HTML around the reflection
        start_index = max(0, reflection_index - 100)
        end_index = min(len(response_content), reflection_index + len(reflected_str) + 100)
        segment = response_content[start_index:end_index]
        
        # Find the nearest tags
        tag_pattern = r'<([a-zA-Z0-9]+)(?:\s+[^>]*?)?>'
        tag_matches = list(re.finditer(tag_pattern, segment))
        
        # Find closing tags too
        closing_pattern = r'</([a-zA-Z0-9]+)>'
        closing_matches = list(re.finditer(closing_pattern, segment))
        
        # Combine and sort by position
        all_tags = [(m.start(), m.group(1), 'open') for m in tag_matches] + [(m.start(), m.group(1), 'close') for m in closing_matches]
        all_tags.sort()
        
        # Adjust reflection index to be relative to the segment
        rel_reflection_index = reflection_index - start_index
        
        # Find the tag that contains the reflection
        active_tags = []
        containing_tag = None
        
        for pos, tag_name, tag_type in all_tags:
            if tag_type == 'open':
                active_tags.append(tag_name.lower())
            elif tag_type == 'close' and active_tags and active_tags[-1] == tag_name.lower():
                active_tags.pop()
            
            if pos > rel_reflection_index and containing_tag is None:
                if active_tags:
                    containing_tag = active_tags[-1]
                break
        
        if containing_tag:
            context['tag'] = containing_tag
            context['parent_tags'] = active_tags[:-1] if active_tags else []
        
        # Check if reflection is in an attribute
        attr_pattern = r'([a-zA-Z0-9\-_]+)=(["\'])(.*?)(\2)'
        attr_matches = list(re.finditer(attr_pattern, segment))
        
        for m in attr_matches:
            attr_name = m.group(1).lower()
            attr_value_start = m.start(3)
            attr_value_end = m.end(3)
            
            if attr_value_start <= rel_reflection_index < attr_value_end:
                context['type'] = 'attribute'
                context['attribute'] = attr_name
                
                # Check if this is an event handler or other executable attribute
                is_event_handler = attr_name.startswith('on')
                is_src_script = attr_name == 'src' and context['tag'] == 'script'
                is_href_javascript = attr_name == 'href' and 'javascript:' in m.group(3)
                
                if is_event_handler or is_src_script or is_href_javascript:
                    context['is_executable'] = True
                
                break
        
        # Check if reflection is directly in a script, style, or other special tag
        if context['tag'] in ['script', 'style', 'iframe', 'frame', 'object', 'embed']:
            if context['tag'] == 'script':
                context['type'] = 'javascript'
                context['is_executable'] = True
            elif context['tag'] == 'style':
                context['type'] = 'css'
            else:
                context['is_executable'] = True
        
        # Check if reflection is in a comment
        if '<!--' in segment[:rel_reflection_index] and '-->' in segment[rel_reflection_index:]:
            context['type'] = 'comment'
        
        return context
    
    def _analyze_basic_context(self, response_content, reflected_str):
        """
        Perform basic context analysis when BeautifulSoup parsing fails or for non-HTML content.
        
        Args:
            response_content (str): The response content.
            reflected_str (str): The reflected string.
            
        Returns:
            dict: Basic context information.
        """
        context = {
            'type': 'unknown',
            'is_executable': False
        }
        
        reflection_index = response_content.find(reflected_str)
        if reflection_index == -1:
            return context
            
        # Extract surrounding content
        start_index = max(0, reflection_index - 50)
        end_index = min(len(response_content), reflection_index + len(reflected_str) + 50)
        surrounding = response_content[start_index:end_index]
        
        # Check if in a script tag
        if '<script' in surrounding[:reflection_index - start_index] and '</script>' in surrounding[reflection_index - start_index + len(reflected_str):]:
            context['type'] = 'javascript'
            context['is_executable'] = True
            return context
            
        # Check if in a CSS context
        if '<style' in surrounding[:reflection_index - start_index] and '</style>' in surrounding[reflection_index - start_index + len(reflected_str):]:
            context['type'] = 'css'
            return context
            
        # Check if in an HTML comment
        if '<!--' in surrounding[:reflection_index - start_index] and '-->' in surrounding[reflection_index - start_index + len(reflected_str):]:
            context['type'] = 'comment'
            return context
            
        # Check if in an attribute value
        attr_pattern = r'([a-zA-Z0-9\-_]+)=(["\'])(.*?)(\2)'
        for m in re.finditer(attr_pattern, surrounding):
            attr_name = m.group(1).lower()
            attr_value_start = m.start(3)
            attr_value_end = m.end(3)
            
            rel_reflection_index = reflection_index - start_index
            if attr_value_start <= rel_reflection_index < attr_value_end:
                context['type'] = 'attribute'
                context['attribute'] = attr_name
                
                # Check if this is an event handler
                if attr_name.startswith('on'):
                    context['is_executable'] = True
                    
                return context
        
        # Assume it's in the HTML body if we see HTML tags
        if re.search(r'<[a-zA-Z0-9]+', surrounding) and re.search(r'</[a-zA-Z0-9]+>', surrounding):
            context['type'] = 'html'
            
        return context
    
    def _is_executable_js_context(self, response_content, reflected_str):
        """
        Determine if a reflection in JavaScript context is executable.
        
        Args:
            response_content (str): The response content.
            reflected_str (str): The reflected string.
            
        Returns:
            bool: True if the context is executable, False otherwise.
        """
        reflection_index = response_content.find(reflected_str)
        if reflection_index == -1:
            return False
            
        # Extract surrounding JavaScript
        start_index = max(0, reflection_index - 100)
        end_index = min(len(response_content), reflection_index + len(reflected_str) + 100)
        js_segment = response_content[start_index:end_index]
        
        # Check if the string is in a literal context
        string_contexts = [
            ('"', '"'),  # Double quotes
            ("'", "'"),  # Single quotes
            ('`', '`')   # Template literals
        ]
        
        for start_delim, end_delim in string_contexts:
            # Count the delimiters before the reflection
            segment_before = js_segment[:reflection_index - start_index]
            count_before_start = segment_before.count(start_delim)
            count_before_end = segment_before.count(end_delim)
            
            # If there's an odd number of unmatched delimiters, we're inside a string
            if (count_before_start - count_before_end) % 2 == 1:
                return False
        
        # Not inside a string literal, so it may be executable JavaScript
        return True
    
    def _calculate_reflection_confidence(self, context, reflected_str):
        """
        Calculate confidence level for a reflection being exploitable.
        
        Args:
            context (dict): The reflection context.
            reflected_str (str): The reflected string.
            
        Returns:
            float: Confidence level between 0 and 1.
        """
        # Base confidence level
        confidence = 0.5
        
        # Adjust based on context
        if context['is_executable']:
            confidence = 0.9  # High confidence for executable contexts
        elif context['type'] == 'javascript':
            confidence = 0.8  # High confidence for JavaScript context
        elif context['type'] == 'attribute' and context['attribute'] in ['href', 'src', 'action']:
            confidence = 0.7  # Medium-high confidence for URL attributes
        elif context['type'] == 'html':
            confidence = 0.7  # Medium-high confidence for HTML body
        elif context['type'] == 'attribute':
            confidence = 0.5  # Medium confidence for other attributes
        elif context['type'] == 'comment':
            confidence = 0.3  # Low confidence for comments
        
        # Check if the reflected string contains special characters that might break context
        special_chars = ['<', '>', '\'', '"', '`', '(', ')', '{', '}', '[', ']']
        for char in special_chars:
            if char in reflected_str:
                confidence += 0.05  # Increase confidence slightly for each special character
        
        # Check for dangerous content in the reflected string
        for dangerous_content in self.dangerous_contexts:
            if dangerous_content in reflected_str.lower():
                confidence += 0.1  # Increase confidence for dangerous content
        
        # Cap confidence at 1.0
        return min(1.0, confidence)
    
    def _get_reflection_excerpt(self, response_content, reflected_str):
        """
        Extract an excerpt of the response containing the reflection.
        
        Args:
            response_content (str): The response content.
            reflected_str (str): The reflected string.
            
        Returns:
            str: An excerpt of the response content.
        """
        reflection_index = response_content.find(reflected_str)
        if reflection_index == -1:
            return ""
            
        # Extract surrounding content
        prefix_length = min(75, reflection_index)
        suffix_length = min(75, len(response_content) - reflection_index - len(reflected_str))
        
        prefix = response_content[reflection_index - prefix_length:reflection_index]
        suffix = response_content[reflection_index + len(reflected_str):reflection_index + len(reflected_str) + suffix_length]
        
        # Highlight the reflection
        excerpt = f"{prefix}[REFLECTION]{reflected_str}[/REFLECTION]{suffix}"
        
        return excerpt
    
    def _generate_encoded_variations(self, payload_str):
        """
        Generate encoded variations of the payload.
        
        Args:
            payload_str (str): The original payload string.
            
        Returns:
            list: A list of (encoded_payload, encoding_type) tuples.
        """
        encoded_variations = []
        
        # HTML entity encoding
        html_encoded = ""
        for char in payload_str:
            html_encoded += f"&#{ord(char)};"
        encoded_variations.append((html_encoded, "HTML entity"))
        
        # URL encoding
        url_encoded = urllib.parse.quote(payload_str)
        encoded_variations.append((url_encoded, "URL"))
        
        # Double URL encoding
        double_url_encoded = urllib.parse.quote(urllib.parse.quote(payload_str))
        encoded_variations.append((double_url_encoded, "Double URL"))
        
        # Hexadecimal HTML entity encoding
        hex_encoded = ""
        for char in payload_str:
            hex_encoded += f"&#x{ord(char):x};"
        encoded_variations.append((hex_encoded, "Hex entity"))
        
        # JavaScript Unicode encoding
        js_encoded = ""
        for char in payload_str:
            js_encoded += f"\\u{ord(char):04x}"
        encoded_variations.append((js_encoded, "JavaScript Unicode"))
        
        return encoded_variations
    
    def _extract_significant_parts(self, payload_str):
        """
        Extract significant parts from a complex payload.
        
        Args:
            payload_str (str): The payload string.
            
        Returns:
            list: A list of significant parts of the payload.
        """
        significant_parts = []
        
        # Extract parts between tags
        tag_pattern = r'<([a-zA-Z0-9]+)[^>]*>(.*?)</\1>'
        for match in re.finditer(tag_pattern, payload_str):
            tag_content = match.group(2)
            if tag_content and len(tag_content) > 10:
                significant_parts.append(tag_content)
        
        # Extract script content
        script_pattern = r'<script>(.*?)</script>'
        for match in re.finditer(script_pattern, payload_str):
            script_content = match.group(1)
            if script_content:
                significant_parts.append(script_content)
        
        # Extract event handlers
        event_pattern = r'on\w+="([^"]*)"'
        for match in re.finditer(event_pattern, payload_str):
            handler_content = match.group(1)
            if handler_content:
                significant_parts.append(handler_content)
        
        # Extract URLs
        url_pattern = r'(https?://[^\s"\'<>]+)'
        for match in re.finditer(url_pattern, payload_str):
            url = match.group(1)
            significant_parts.append(url)
        
        # Extract JavaScript code
        js_pattern = r'(alert\([^)]*\)|eval\([^)]*\)|document\.[a-zA-Z]+)'
        for match in re.finditer(js_pattern, payload_str):
            js_code = match.group(1)
            significant_parts.append(js_code)
        
        return significant_parts
