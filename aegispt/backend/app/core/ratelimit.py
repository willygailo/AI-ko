"""Async per-engagement token-bucket rate limiter enforcing ScopePolicy.max_rps."""
from __future__ import annotations

import asyncio
import time


class TokenBucketRateLimiter:
    def __init__(self, rps: int) -> None:
        self.rps = max(1, rps)
        self._min_interval = 1.0 / float(self.rps)
        self._lock = asyncio.Lock()
        self._next_allowed = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            if now < self._next_allowed:
                await asyncio.sleep(self._next_allowed - now)
                now = time.monotonic()
            self._next_allowed = max(now, self._next_allowed) + self._min_interval


class RateLimiterRegistry:
    def __init__(self) -> None:
        self._limiters: dict[str, TokenBucketRateLimiter] = {}

    def get(self, engagement_id: str, max_rps: int) -> TokenBucketRateLimiter:
        lim = self._limiters.get(engagement_id)
        if lim is None or lim.rps != max(1, max_rps):
            lim = TokenBucketRateLimiter(max_rps)
            self._limiters[engagement_id] = lim
        return lim


rate_limiters = RateLimiterRegistry()
