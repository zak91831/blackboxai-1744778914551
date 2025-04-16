"""
Multi-Client Simulator Module

This module simulates multiple clients accessing resources to verify
cache-based XSS vulnerabilities and analyze cache behavior patterns.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
import asyncio
import aiohttp
import random
import time
from datetime import datetime
from collections import defaultdict, Counter
import uuid
import statistics
from urllib.parse import urlencode

class MultiClientSimulator:
    """
    A class to simulate multiple clients for cache behavior testing.
    """
    
    def __init__(self, config):
        """
        Initialize the Multi-Client Simulator.
        
        Args:
            config (dict): Configuration settings for client simulation.
        """
        self.logger = logging.getLogger('cachexssdetector.multi_client_simulator')
        self.config = config
        
        # Simulation configuration
        self.num_clients = config.get('num_clients', 5)
        self.request_delay = config.get('request_delay', 1.0)
        self.max_requests = config.get('max_requests', 100)
        self.timeout = config.get('timeout', 30)
        
        # Initialize client profiles
        self._init_client_profiles()
        
        self.logger.info("Multi-Client Simulator initialized")
    
    def _init_client_profiles(self):
        """Initialize client profiles for simulation."""
        # Browser profiles
        self.browser_profiles = {
            'chrome': {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.5',
                'accept-encoding': 'gzip, deflate, br'
            },
            'firefox': {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.5',
                'accept-encoding': 'gzip, deflate, br'
            },
            'safari': {
                'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'accept-language': 'en-US,en;q=0.5',
                'accept-encoding': 'gzip, deflate, br'
            }
        }
        
        # Client locations
        self.client_locations = [
            {'ip': '192.168.1.100', 'country': 'US'},
            {'ip': '192.168.1.101', 'country': 'UK'},
            {'ip': '192.168.1.102', 'country': 'DE'},
            {'ip': '192.168.1.103', 'country': 'FR'},
            {'ip': '192.168.1.104', 'country': 'JP'}
        ]
    
    async def simulate_clients(
        self,
        url: str,
        payload: Optional[Dict] = None,
        mode: str = 'sequential'
    ) -> Dict:
        """
        Simulate multiple clients accessing a resource.
        
        Args:
            url (str): Target URL.
            payload (dict, optional): Payload to test.
            mode (str): Simulation mode ('sequential' or 'parallel').
            
        Returns:
            dict: Simulation results.
        """
        simulation = {
            'url': url,
            'start_time': datetime.now().isoformat(),
            'mode': mode,
            'clients': [],
            'responses': [],
            'statistics': {},
            'cache_behavior': {}
        }
        
        try:
            # Create client profiles
            clients = self._create_client_profiles()
            simulation['clients'] = clients
            
            # Run simulation
            if mode == 'parallel':
                responses = await self._run_parallel_simulation(
                    url,
                    clients,
                    payload
                )
            else:  # sequential
                responses = await self._run_sequential_simulation(
                    url,
                    clients,
                    payload
                )
            
            simulation['responses'] = responses
            
            # Analyze results
            simulation['statistics'] = self._calculate_statistics(responses)
            simulation['cache_behavior'] = self._analyze_cache_behavior(responses)
            
        except Exception as e:
            error_msg = f"Error in client simulation: {str(e)}"
            self.logger.error(error_msg)
            simulation['error'] = error_msg
        
        return simulation
    
    async def verify_cache_persistence(
        self,
        url: str,
        payload: Optional[Dict] = None,
        timeout: Optional[int] = None
    ) -> Dict:
        """
        Verify cache persistence across multiple clients.
        
        Args:
            url (str): Target URL.
            payload (dict, optional): Payload to verify.
            timeout (int, optional): Verification timeout.
            
        Returns:
            dict: Verification results.
        """
        verification = {
            'url': url,
            'start_time': datetime.now().isoformat(),
            'persistence_verified': False,
            'persistence_duration': 0,
            'affected_clients': [],
            'evidence': []
        }
        
        try:
            timeout = timeout or self.timeout
            start_time = time.time()
            
            # Create client profiles
            clients = self._create_client_profiles()
            
            # Initial verification
            initial_responses = await self._verify_initial_state(
                url,
                clients,
                payload
            )
            
            if not self._is_cache_present(initial_responses):
                return verification
            
            # Periodic verification
            while time.time() - start_time < timeout:
                # Wait between checks
                await asyncio.sleep(self.request_delay)
                
                # Verify persistence
                current_responses = await self._verify_current_state(
                    url,
                    clients,
                    payload
                )
                
                # Check if cache is still present
                if not self._is_cache_present(current_responses):
                    break
                
                # Update affected clients
                affected = self._identify_affected_clients(current_responses)
                verification['affected_clients'] = list(set(
                    verification['affected_clients'] + affected
                ))
                
                # Collect evidence
                verification['evidence'].append({
                    'timestamp': datetime.now().isoformat(),
                    'responses': current_responses
                })
            
            # Calculate persistence duration
            verification['persistence_duration'] = time.time() - start_time
            verification['persistence_verified'] = bool(
                verification['affected_clients']
            )
            
        except Exception as e:
            error_msg = f"Error in cache persistence verification: {str(e)}"
            self.logger.error(error_msg)
            verification['error'] = error_msg
        
        return verification
    
    def _create_client_profiles(self) -> List[Dict]:
        """Create diverse client profiles for simulation."""
        clients = []
        
        try:
            for i in range(self.num_clients):
                # Select random browser and location
                browser = random.choice(list(self.browser_profiles.keys()))
                location = random.choice(self.client_locations)
                
                # Create client profile
                client = {
                    'id': str(uuid.uuid4()),
                    'browser': browser,
                    'headers': self.browser_profiles[browser].copy(),
                    'location': location,
                    'cookies': self._generate_cookies()
                }
                
                # Add location headers
                client['headers']['X-Forwarded-For'] = location['ip']
                client['headers']['X-Country-Code'] = location['country']
                
                clients.append(client)
            
        except Exception as e:
            self.logger.error(f"Error creating client profiles: {str(e)}")
        
        return clients
    
    async def _run_parallel_simulation(
        self,
        url: str,
        clients: List[Dict],
        payload: Optional[Dict]
    ) -> List[Dict]:
        """Run parallel client simulation."""
        responses = []
        
        try:
            # Create tasks for each client
            tasks = [
                self._simulate_client_requests(url, client, payload)
                for client in clients
            ]
            
            # Run tasks concurrently
            client_responses = await asyncio.gather(*tasks)
            
            # Collect responses
            for client_resp in client_responses:
                responses.extend(client_resp)
            
        except Exception as e:
            self.logger.error(f"Error in parallel simulation: {str(e)}")
        
        return responses
    
    async def _run_sequential_simulation(
        self,
        url: str,
        clients: List[Dict],
        payload: Optional[Dict]
    ) -> List[Dict]:
        """Run sequential client simulation."""
        responses = []
        
        try:
            for client in clients:
                # Simulate requests for each client
                client_responses = await self._simulate_client_requests(
                    url,
                    client,
                    payload
                )
                responses.extend(client_responses)
                
                # Wait between clients
                await asyncio.sleep(self.request_delay)
            
        except Exception as e:
            self.logger.error(f"Error in sequential simulation: {str(e)}")
        
        return responses
    
    async def _simulate_client_requests(
        self,
        url: str,
        client: Dict,
        payload: Optional[Dict]
    ) -> List[Dict]:
        """Simulate requests from a single client."""
        responses = []
        
        try:
            async with aiohttp.ClientSession(headers=client['headers']) as session:
                for _ in range(random.randint(1, self.max_requests)):
                    # Send request
                    response = await self._send_request(
                        session,
                        url,
                        client,
                        payload
                    )
                    
                    # Add client information
                    response['client'] = {
                        'id': client['id'],
                        'browser': client['browser'],
                        'location': client['location']
                    }
                    
                    responses.append(response)
                    
                    # Wait between requests
                    await asyncio.sleep(self.request_delay)
            
        except Exception as e:
            self.logger.error(f"Error simulating client requests: {str(e)}")
        
        return responses
    
    async def _verify_initial_state(
        self,
        url: str,
        clients: List[Dict],
        payload: Optional[Dict]
    ) -> List[Dict]:
        """Verify initial cache state."""
        responses = []
        
        try:
            async with aiohttp.ClientSession() as session:
                for client in clients:
                    response = await self._send_request(
                        session,
                        url,
                        client,
                        payload
                    )
                    responses.append(response)
            
        except Exception as e:
            self.logger.error(f"Error verifying initial state: {str(e)}")
        
        return responses
    
    async def _verify_current_state(
        self,
        url: str,
        clients: List[Dict],
        payload: Optional[Dict]
    ) -> List[Dict]:
        """Verify current cache state."""
        responses = []
        
        try:
            async with aiohttp.ClientSession() as session:
                for client in clients:
                    response = await self._send_request(
                        session,
                        url,
                        client,
                        payload
                    )
                    responses.append(response)
            
        except Exception as e:
            self.logger.error(f"Error verifying current state: {str(e)}")
        
        return responses
    
    async def _send_request(
        self,
        session: aiohttp.ClientSession,
        url: str,
        client: Dict,
        payload: Optional[Dict]
    ) -> Dict:
        """Send HTTP request with client profile."""
        response_data = {
            'timestamp': datetime.now().isoformat(),
            'status_code': None,
            'headers': {},
            'content': None,
            'timing': 0
        }
        
        try:
            start_time = time.time()
            
            # Add payload if provided
            if payload:
                url = self._add_payload_to_url(url, payload)
            
            # Send request
            async with session.get(
                url,
                cookies=client['cookies'],
                timeout=self.timeout
            ) as response:
                response_data.update({
                    'status_code': response.status,
                    'headers': dict(response.headers),
                    'content': await response.text(),
                    'timing': time.time() - start_time
                })
            
        except Exception as e:
            error_msg = f"Error sending request: {str(e)}"
            self.logger.error(error_msg)
            response_data['error'] = error_msg
        
        return response_data
    
    def _calculate_statistics(self, responses: List[Dict]) -> Dict:
        """Calculate simulation statistics."""
        stats = {
            'total_requests': len(responses),
            'status_codes': defaultdict(int),
            'average_timing': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        
        try:
            # Calculate metrics
            for response in responses:
                # Count status codes
                status = response.get('status_code')
                if status:
                    stats['status_codes'][status] += 1
                
                # Calculate timing
                timing = response.get('timing', 0)
                stats['average_timing'] += timing
                
                # Count cache hits/misses
                if self._is_cache_hit(response):
                    stats['cache_hits'] += 1
                else:
                    stats['cache_misses'] += 1
            
            # Calculate average timing
            if responses:
                stats['average_timing'] /= len(responses)
            
        except Exception as e:
            self.logger.error(f"Error calculating statistics: {str(e)}")
        
        return stats
    
    def _analyze_cache_behavior(self, responses: List[Dict]) -> Dict:
        """Analyze cache behavior patterns."""
        analysis = {
            'cache_type': 'unknown',
            'consistency': 0.0,
            'patterns': [],
            'variations': []
        }
        
        try:
            # Analyze cache headers
            cache_headers = self._analyze_cache_headers(responses)
            analysis['cache_type'] = cache_headers['type']
            
            # Analyze consistency
            analysis['consistency'] = self._calculate_cache_consistency(responses)
            
            # Identify patterns
            analysis['patterns'] = self._identify_cache_patterns(responses)
            
            # Analyze variations
            analysis['variations'] = self._analyze_cache_variations(responses)
            
        except Exception as e:
            self.logger.error(f"Error analyzing cache behavior: {str(e)}")
        
        return analysis
    
    def _generate_cookies(self) -> Dict[str, str]:
        """Generate random cookies for client."""
        return {
            'session_id': str(uuid.uuid4()),
            'client_id': str(random.randint(1000, 9999))
        }
    
    def _add_payload_to_url(self, url: str, payload: Dict) -> str:
        """Add payload to URL."""
        try:
            if 'parameters' in payload:
                separator = '&' if '?' in url else '?'
                return f"{url}{separator}{urlencode(payload['parameters'])}"
            return url
        except Exception:
            return url
    
    def _is_cache_hit(self, response: Dict) -> bool:
        """Check if response is a cache hit."""
        headers = response.get('headers', {})
        
        return (
            'x-cache' in headers and 'hit' in headers['x-cache'].lower() or
            'cf-cache-status' in headers and headers['cf-cache-status'].lower() == 'hit' or
            'age' in headers and int(headers.get('age', 0)) > 0
        )
    
    def _is_cache_present(self, responses: List[Dict]) -> bool:
        """Check if cache is present in responses."""
        return any(self._is_cache_hit(r) for r in responses)
    
    def _identify_affected_clients(self, responses: List[Dict]) -> List[str]:
        """Identify clients affected by cache."""
        return [
            r['client']['id']
            for r in responses
            if self._is_cache_hit(r)
        ]
    
    def _analyze_cache_headers(self, responses: List[Dict]) -> Dict:
        """Analyze cache-related headers."""
        analysis = {
            'type': 'unknown',
            'headers': defaultdict(int)
        }
        
        for response in responses:
            headers = response.get('headers', {})
            
            # Count cache headers
            for header in headers:
                if header.lower().startswith(('x-cache', 'cf-cache', 'age')):
                    analysis['headers'][header] += 1
            
            # Determine cache type
            if 'cache-control' in headers:
                if 'public' in headers['cache-control'].lower():
                    analysis['type'] = 'public'
                elif 'private' in headers['cache-control'].lower():
                    analysis['type'] = 'private'
        
        return analysis
    
    def _calculate_cache_consistency(self, responses: List[Dict]) -> float:
        """Calculate cache behavior consistency."""
        if not responses:
            return 0.0
        
        hits = sum(1 for r in responses if self._is_cache_hit(r))
        return hits / len(responses)
    
    def _identify_cache_patterns(self, responses: List[Dict]) -> List[Dict]:
        """Identify cache behavior patterns."""
        patterns = []
        
        try:
            # Analyze timing patterns
            timings = [r.get('timing', 0) for r in responses]
            if timings:
                patterns.append({
                    'type': 'timing',
                    'mean': statistics.mean(timings),
                    'variance': statistics.variance(timings) if len(timings) > 1 else 0
                })
            
            # Analyze status code patterns
            status_transitions = defaultdict(int)
            for i in range(len(responses) - 1):
                current = responses[i].get('status_code')
                next_status = responses[i + 1].get('status_code')
                if current and next_status:
                    transition = f"{current}->{next_status}"
                    status_transitions[transition] += 1
            
            if status_transitions:
                patterns.append({
                    'type': 'status_transitions',
                    'transitions': dict(status_transitions)
                })
            
        except Exception as e:
            self.logger.error(f"Error identifying patterns: {str(e)}")
        
        return patterns
    
    def _analyze_cache_variations(self, responses: List[Dict]) -> List[Dict]:
        """Analyze variations in cache behavior."""
        variations = []
        
        try:
            # Group by client
            by_client = defaultdict(list)
            for response in responses:
                client_id = response.get('client', {}).get('id')
                if client_id:
                    by_client[client_id].append(response)
            
            # Analyze variations
            for client_id, client_responses in by_client.items():
                variation = {
                    'client_id': client_id,
                    'cache_hits': sum(
                        1 for r in client_responses
                        if self._is_cache_hit(r)
                    ),
                    'total_requests': len(client_responses)
                }
                variations.append(variation)
            
        except Exception as e:
            self.logger.error(f"Error analyzing variations: {str(e)}")
        
        return variations
