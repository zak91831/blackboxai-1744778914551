"""
Rate Limiter Utility

This module provides functionality to manage request rates and implement
adaptive throttling for scanning operations.
"""

import time
import logging
import random
from typing import Dict, Any, Optional
from collections import deque
from datetime import datetime, timedelta

class RateLimiter:
    """
    Implements rate limiting for network requests to avoid triggering WAF protections
    or being blocked by target servers.
    """
    
    def __init__(self, 
                 requests_per_minute: int = 60,
                 base_delay: float = 1.0,
                 adaptive: bool = True,
                 max_retries: int = 3):
        """
        Initialize the rate limiter.
        
        Args:
            requests_per_minute: Maximum number of requests allowed per minute
            base_delay: Base delay between requests in seconds
            adaptive: Whether to use adaptive throttling based on response codes
            max_retries: Maximum number of retries for failed requests
        """
        self.logger = logging.getLogger('cachexssdetector.rate_limiter')
        self.requests_per_minute = requests_per_minute
        self.base_delay = base_delay
        self.adaptive = adaptive
        self.max_retries = max_retries
        
        # Request history tracking
        self.request_times = deque(maxlen=requests_per_minute)
        self.failure_count = 0
        self.current_delay = base_delay
        self.last_request_time = 0
        
        # Host tracking for per-host limiting
        self.host_data = {}
        
        self.logger.info(f"Rate limiter initialized: {requests_per_minute} req/min, " 
                         f"{base_delay}s base delay, adaptive={adaptive}")
    
    def pre_request(self, host: str) -> float:
        """
        Call before making a request to check if rate limit allows it.
        Will sleep if necessary to maintain rate limits.
        
        Args:
            host: The host being requested
            
        Returns:
            float: Time slept in seconds
        """
        # Initialize host data if needed
        if host not in self.host_data:
            self.host_data[host] = {
                'request_times': deque(maxlen=self.requests_per_minute),
                'failure_count': 0,
                'current_delay': self.base_delay,
                'last_request_time': 0
            }
        
        host_info = self.host_data[host]
        
        # Calculate time since last request
        current_time = time.time()
        elapsed = current_time - host_info['last_request_time']
        
        # If we're using adaptive throttling, adjust based on failures
        delay = host_info['current_delay']
        
        # Calculate minimum wait time to maintain rate limit
        if len(host_info['request_times']) >= self.requests_per_minute:
            # If we've hit our max requests, ensure we're spacing them out properly
            oldest_request = host_info['request_times'][0]
            time_window = current_time - oldest_request
            
            if time_window < 60:  # Less than a minute has passed
                # Sleep to maintain rate limit
                sleep_time = max(60 - time_window, delay)
                if sleep_time > 0:
                    self.logger.debug(f"Rate limiting for {host}: sleeping {sleep_time:.2f}s")
                    time.sleep(sleep_time)
                    return sleep_time
        
        # If we need to enforce a minimum delay between requests
        if elapsed < delay:
            sleep_time = delay - elapsed
            self.logger.debug(f"Enforcing delay for {host}: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
            return sleep_time
            
        return 0.0
    
    def post_request(self, 
                    host: str, 
                    status_code: int, 
                    response_time: float, 
                    error: Optional[str] = None) -> None:
        """
        Call after request completion to update rate limiting status.
        
        Args:
            host: The host that was requested
            status_code: HTTP status code received (0 if error)
            response_time: Time the request took in seconds
            error: Error message if request failed
        """
        # Initialize host data if needed (shouldn't happen if pre_request was called)
        if host not in self.host_data:
            self.host_data[host] = {
                'request_times': deque(maxlen=self.requests_per_minute),
                'failure_count': 0,
                'current_delay': self.base_delay,
                'last_request_time': 0
            }
            
        host_info = self.host_data[host]
        
        # Record the request time
        current_time = time.time()
        host_info['request_times'].append(current_time)
        host_info['last_request_time'] = current_time
        
        # If adaptive throttling is enabled, adjust based on response
        if self.adaptive:
            if error or status_code >= 429 or status_code in (403, 406, 444):
                # Likely hitting rate limits or being blocked
                host_info['failure_count'] += 1
                new_delay = min(host_info['current_delay'] * 2, 30.0)  # Max 30 second delay
                
                self.logger.warning(
                    f"Detected potential rate limiting for {host} "
                    f"(status={status_code}, errors={host_info['failure_count']}). "
                    f"Increasing delay to {new_delay:.2f}s"
                )
                
                host_info['current_delay'] = new_delay
            else:
                # Successful request, gradually reduce delay if we've had failures
                if host_info['failure_count'] > 0:
                    host_info['failure_count'] = max(0, host_info['failure_count'] - 0.5)
                    
                    # Only reduce delay after several successful requests
                    if host_info['failure_count'] == 0 and host_info['current_delay'] > self.base_delay:
                        new_delay = max(host_info['current_delay'] * 0.8, self.base_delay)
                        self.logger.info(f"Reducing delay for {host} to {new_delay:.2f}s")
                        host_info['current_delay'] = new_delay

    def get_host_status(self, host: str) -> Dict[str, Any]:
        """
        Get current rate limiting status for a host.
        
        Args:
            host: The host to get status for
            
        Returns:
            dict: Rate limiting status information
        """
        if host not in self.host_data:
            return {
                'requests_in_window': 0,
                'current_delay': self.base_delay,
                'failure_count': 0,
                'window_usage': 0.0
            }
        
        host_info = self.host_data[host]
        current_time = time.time()
        
        # Count requests in the last minute
        minute_ago = current_time - 60
        requests_in_window = sum(1 for t in host_info['request_times'] if t > minute_ago)
        
        return {
            'requests_in_window': requests_in_window,
            'current_delay': host_info['current_delay'],
            'failure_count': host_info['failure_count'],
            'window_usage': requests_in_window / self.requests_per_minute
        }
