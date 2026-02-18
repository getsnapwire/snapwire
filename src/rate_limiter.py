"""
Rate limiter for API keys using in-memory sliding window approach.
Thread-safe implementation with optional DB backing for persistence.
"""

import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta

# Configuration
RATE_LIMIT_PER_MINUTE = 60

# In-memory storage for request tracking per API key
# Structure: {api_key_id: [timestamp1, timestamp2, ...]}
_request_history = defaultdict(list)
_lock = threading.Lock()


def check_rate_limit(api_key_id):
    """
    Check if an API key is within its rate limit.
    
    Uses a sliding window approach: tracks request timestamps for the past minute.
    
    Args:
        api_key_id (str): The ID of the API key to check
        
    Returns:
        tuple: (allowed: bool, remaining: int, reset_at: int)
            - allowed: True if request is allowed, False if rate limited
            - remaining: Number of requests remaining in current window
            - reset_at: Unix timestamp (seconds) when the rate limit resets
    """
    current_time = time.time()
    window_start = current_time - 60  # 60 second window
    
    with _lock:
        # Clean up old requests outside the window
        if api_key_id in _request_history:
            _request_history[api_key_id] = [
                ts for ts in _request_history[api_key_id]
                if ts > window_start
            ]
        
        # Get current request count
        request_count = len(_request_history[api_key_id])
        
        # Check if rate limit exceeded
        if request_count >= RATE_LIMIT_PER_MINUTE:
            # Find the oldest request in the window
            oldest_request = min(_request_history[api_key_id])
            reset_at = int(oldest_request + 60)
            return (False, 0, reset_at)
        
        # Request is allowed, add it to history
        _request_history[api_key_id].append(current_time)
        
        # Calculate remaining requests and reset time
        remaining = RATE_LIMIT_PER_MINUTE - request_count - 1
        # Reset time is when the oldest request falls out of the window
        oldest_request = min(_request_history[api_key_id])
        reset_at = int(oldest_request + 60)
        
        return (True, remaining, reset_at)


def get_rate_limit_info(api_key_id):
    """
    Get current rate limit info without consuming a request.
    
    Args:
        api_key_id (str): The ID of the API key
        
    Returns:
        dict: Contains request_count, limit, requests_remaining, reset_at
    """
    current_time = time.time()
    window_start = current_time - 60
    
    with _lock:
        if api_key_id not in _request_history:
            return {
                "request_count": 0,
                "limit": RATE_LIMIT_PER_MINUTE,
                "requests_remaining": RATE_LIMIT_PER_MINUTE,
                "reset_at": int(current_time + 60),
            }
        
        # Clean up old requests
        _request_history[api_key_id] = [
            ts for ts in _request_history[api_key_id]
            if ts > window_start
        ]
        
        request_count = len(_request_history[api_key_id])
        
        if request_count == 0:
            reset_at = int(current_time + 60)
        else:
            oldest_request = min(_request_history[api_key_id])
            reset_at = int(oldest_request + 60)
        
        return {
            "request_count": request_count,
            "limit": RATE_LIMIT_PER_MINUTE,
            "requests_remaining": max(0, RATE_LIMIT_PER_MINUTE - request_count),
            "reset_at": reset_at,
        }


def reset_rate_limit(api_key_id):
    """
    Reset rate limit for a specific API key (for testing/admin purposes).
    
    Args:
        api_key_id (str): The ID of the API key to reset
    """
    with _lock:
        if api_key_id in _request_history:
            _request_history[api_key_id] = []


def clear_all_rate_limits():
    """
    Clear all rate limit data (for testing/restart).
    """
    with _lock:
        _request_history.clear()
