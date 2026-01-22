"""Simple in-memory rate limiter for authentication endpoints."""

import time
from collections import defaultdict
from threading import Lock
from typing import Tuple
from fastapi import HTTPException, Request


class RateLimiter:
    """
    Simple in-memory rate limiter using sliding window algorithm.

    Tracks failed attempts per IP address and blocks after threshold.
    """

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 300,
        block_seconds: int = 900
    ):
        """
        Initialize rate limiter.

        Args:
            max_attempts: Maximum failed attempts before blocking
            window_seconds: Time window for counting attempts (default 5 min)
            block_seconds: How long to block after max attempts (default 15 min)
        """
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds

        # Track attempts: {ip: [(timestamp, success), ...]}
        self._attempts: dict = defaultdict(list)
        # Track blocks: {ip: block_until_timestamp}
        self._blocks: dict = {}
        self._lock = Lock()

    def _cleanup_old_attempts(self, ip: str) -> None:
        """Remove attempts outside the sliding window."""
        cutoff = time.time() - self.window_seconds
        self._attempts[ip] = [
            (ts, success) for ts, success in self._attempts[ip]
            if ts > cutoff
        ]

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, considering proxies."""
        # Check for forwarded headers (if behind proxy)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Take the first IP in the chain
            return forwarded.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

        # Fall back to direct client IP
        return request.client.host if request.client else "unknown"

    def is_blocked(self, request: Request) -> Tuple[bool, int]:
        """
        Check if IP is currently blocked.

        Returns:
            Tuple of (is_blocked, seconds_remaining)
        """
        ip = self._get_client_ip(request)

        with self._lock:
            if ip in self._blocks:
                block_until = self._blocks[ip]
                now = time.time()

                if now < block_until:
                    return True, int(block_until - now)
                else:
                    # Block expired, remove it
                    del self._blocks[ip]

            return False, 0

    def record_attempt(self, request: Request, success: bool) -> None:
        """
        Record a login attempt.

        Args:
            request: The FastAPI request object
            success: Whether the login was successful
        """
        ip = self._get_client_ip(request)

        with self._lock:
            now = time.time()

            if success:
                # Clear attempts on successful login
                self._attempts[ip] = []
                if ip in self._blocks:
                    del self._blocks[ip]
                return

            # Record failed attempt
            self._attempts[ip].append((now, success))
            self._cleanup_old_attempts(ip)

            # Count recent failures
            failures = sum(1 for _, s in self._attempts[ip] if not s)

            if failures >= self.max_attempts:
                # Block the IP
                self._blocks[ip] = now + self.block_seconds
                self._attempts[ip] = []

    def check_rate_limit(self, request: Request) -> None:
        """
        Check rate limit and raise HTTPException if blocked.

        Call this at the start of login endpoint.
        """
        blocked, remaining = self.is_blocked(request)
        if blocked:
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed login attempts. Try again in {remaining} seconds.",
                headers={"Retry-After": str(remaining)}
            )

    def get_remaining_attempts(self, request: Request) -> int:
        """Get number of remaining attempts before block."""
        ip = self._get_client_ip(request)

        with self._lock:
            self._cleanup_old_attempts(ip)
            failures = sum(1 for _, s in self._attempts[ip] if not s)
            return max(0, self.max_attempts - failures)


# Global rate limiter instance for login endpoint
login_rate_limiter = RateLimiter(
    max_attempts=5,      # 5 failed attempts
    window_seconds=300,  # within 5 minutes
    block_seconds=900    # blocks for 15 minutes
)
