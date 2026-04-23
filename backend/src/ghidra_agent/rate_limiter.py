"""Simple in-memory rate limiter for FastAPI endpoints.

Uses a token-bucket algorithm per user ID.  Buckets are cleaned up
periodically to prevent unbounded memory growth.
"""

import asyncio
import time
from dataclasses import dataclass
from typing import Dict, Optional

from fastapi import HTTPException, Request


@dataclass
class _Bucket:
    tokens: float
    last_update: float


class RateLimitDependency:
    """FastAPI dependency that enforces token-bucket rate limits.

    Parameters:
        rate:      tokens added per second (e.g. 1/60 for 1 per minute)
        capacity:  maximum bucket size (burst allowance)
    """

    _buckets: Dict[str, _Bucket] = {}
    _lock = asyncio.Lock()
    _last_cleanup = time.monotonic()

    def __init__(self, requests_per_minute: int = 30, burst: int = 5):
        self.rate = requests_per_minute / 60.0
        self.capacity = burst

    async def __call__(self, request: Request) -> None:
        key = self._key(request)
        now = time.monotonic()

        async with self._lock:
            # Periodic cleanup every 60s
            if now - self._last_cleanup > 60:
                self._cleanup(now)

            bucket = self._buckets.get(key)
            if bucket is None:
                self._buckets[key] = _Bucket(tokens=self.capacity - 1, last_update=now)
                return

            elapsed = now - bucket.last_update
            bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.rate)
            bucket.last_update = now

            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return

        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please try again later.")

    def _key(self, request: Request) -> str:
        # Prefer authenticated user id, fall back to client IP
        user = getattr(request.state, "user", None)
        if isinstance(user, dict) and user.get("id"):
            return f"user:{user['id']}"
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return f"ip:{forwarded.split(',')[0].strip()}"
        client = request.client
        return f"ip:{client.host}" if client else "ip:unknown"

    @classmethod
    def _cleanup(cls, now: float) -> None:
        stale = [k for k, b in cls._buckets.items() if now - b.last_update > 300]
        for k in stale:
            del cls._buckets[k]
        cls._last_cleanup = now


# Pre-configured limiters
upload_limit = RateLimitDependency(requests_per_minute=5, burst=3)
query_limit = RateLimitDependency(requests_per_minute=30, burst=10)
