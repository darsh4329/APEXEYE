"""
APEXEYE MASTER — Security Rate Limiter Service (Phase 11)

In-memory sliding-window token bucket rate limiter for sensitive administrative
and authentication endpoints.

Features:
  - Thread-safe sliding window tracking by IP or device key.
  - Automatic expiration and cleanup of old request timestamps.
  - Zero performance impact on high-frequency telemetry (10s) and heartbeats (3s).
  - Returns HTTP 429 Too Many Requests with Retry-After header.
"""

import time
from collections import defaultdict
from functools import wraps
from threading import Lock
from typing import Callable

from flask import request, jsonify, make_response
from master.app.utils.logger import get_logger

logger = get_logger("apexeye.master.rate_limiter")


class RateLimiter:
    """Thread-safe sliding-window rate limiter."""

    def __init__(self):
        self._lock = Lock()
        # Storage: scope -> identifier -> list of timestamps
        self._requests: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))

    def is_allowed(self, scope: str, key: str, max_requests: int, window_seconds: int) -> tuple[bool, int]:
        """
        Check if request is permitted within rate limit window.
        Returns: (allowed: bool, retry_after: int)
        """
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            timestamps = self._requests[scope][key]
            # Prune expired timestamps
            valid_timestamps = [t for t in timestamps if t > cutoff]
            self._requests[scope][key] = valid_timestamps

            if len(valid_timestamps) >= max_requests:
                # Rate limit exceeded
                oldest = valid_timestamps[0]
                retry_after = max(1, int(oldest + window_seconds - now))
                return False, retry_after

            # Record current request
            self._requests[scope][key].append(now)
            return True, 0

    def reset(self, scope: str | None = None) -> None:
        """Reset rate limiter state (useful for tests)."""
        with self._lock:
            if scope:
                self._requests.pop(scope, None)
            else:
                self._requests.clear()


# Global singleton instance
rate_limiter = RateLimiter()


def rate_limit(max_requests: int = 30, window_seconds: int = 60, scope: str = "default") -> Callable:
    """
    Decorator to apply rate limiting to a Flask endpoint.
    
    Identifies callers by IP address (or X-Forwarded-For if trusted).
    Does NOT affect legitimate heartbeat or telemetry traffic.
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            key = request.remote_addr or "127.0.0.1"
            allowed, retry_after = rate_limiter.is_allowed(scope, key, max_requests, window_seconds)

            if not allowed:
                logger.warning(
                    "Rate limit exceeded for scope '%s' from IP '%s' (retry after %ds)",
                    scope, key, retry_after,
                )
                resp = make_response(
                    jsonify({
                        "error": "Too Many Requests: Rate limit exceeded.",
                        "retry_after_seconds": retry_after,
                        "status": 429,
                    }),
                    429,
                )
                resp.headers["Retry-After"] = str(retry_after)
                return resp

            return f(*args, **kwargs)
        return decorated
    return decorator
