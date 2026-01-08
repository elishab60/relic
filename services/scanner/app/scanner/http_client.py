import httpx
import asyncio
import time
from typing import Optional, List, Dict, Any, Callable, Awaitable
from ..config import Settings

class HttpClient:
    def __init__(self, config: Settings, log_callback: Callable[[str, str], Awaitable[None]] = None):
        self.config = config
        self.log_callback = log_callback
        self.client: Optional[httpx.AsyncClient] = None
        self.history: List[Dict[str, Any]] = []
        self.last_request_time = 0.0
        
        # Adaptive Rate Limiting
        self.consecutive_errors = 0
        self.current_delay = config.RATE_LIMIT_DELAY
        self.request_timestamps = [] # For sliding window
        self._lock = asyncio.Lock() # Guard for rate limiting state

    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=self.config.DEFAULT_TIMEOUT,
            headers={"User-Agent": self.config.USER_AGENT},
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            await self.client.aclose()
            self.client = None

    async def _wait_for_rate_limit(self):
        now = time.time()
        
        # 1. Basic Delay
        elapsed = now - self.last_request_time
        if elapsed < self.current_delay:
            wait_time = self.current_delay - elapsed
            await asyncio.sleep(wait_time)
            # Update now after sleep
            now = time.time()
            
        # 2. Adaptive: Requests per minute
        if self.config.ADAPTIVE_RATE_LIMIT:
            # Clean old timestamps (older than 60s)
            self.request_timestamps = [t for t in self.request_timestamps if now - t < 60]
            
            if len(self.request_timestamps) >= self.config.MAX_REQUESTS_PER_MINUTE:
                # Wait until oldest expires
                if self.request_timestamps:
                    oldest = self.request_timestamps[0]
                    # Add a small buffer to ensure we are past the minute mark
                    wait_time = 60 - (now - oldest) + 0.1
                    if wait_time > 0:
                        if self.log_callback:
                            await self.log_callback("WARNING", f"Rate limit reached ({self.config.MAX_REQUESTS_PER_MINUTE} rpm). Slowing down for {wait_time:.2f}s.")
                        await asyncio.sleep(wait_time)

    async def request(self, method: str, url: str, **kwargs) -> Optional[httpx.Response]:
        if not self.client:
            raise RuntimeError("HttpClient not initialized. Use 'async with'.")

        # Rate limiting critical section
        async with self._lock:
            await self._wait_for_rate_limit()
            # Mark the "start" of this request for rate limiting purposes
            # This ensures the next concurrent request sees this timestamp and waits
            self.last_request_time = time.time()
            self.request_timestamps.append(self.last_request_time)

        try:
            start_time = time.time()
            # Timeout handled by client settings, but we wrap to catch errors
            response = await self.client.request(method, url, **kwargs)
            latency = time.time() - start_time
            
            self.history.append({
                "timestamp": start_time,
                "method": method,
                "url": url,
                "status": response.status_code,
                "latency": latency
            })
            
            # Adaptive Logic (safe to run concurrently mostly, but race conditions on consecutive_errors acceptable)
            if self.config.ADAPTIVE_RATE_LIMIT:
                if response.status_code >= 500 or latency > self.config.LATENCY_THRESHOLD:
                    self.consecutive_errors += 1
                    if self.consecutive_errors >= self.config.ERROR_THRESHOLD:
                        # Increase delay
                        new_delay = min(self.current_delay * 2, 5.0) # Cap at 5s
                        
                        # Only log if delay actually changed significantly to avoid spam
                        if new_delay > self.current_delay and self.log_callback:
                             await self.log_callback("WARNING", f"High errors/latency detected. Increasing delay to {new_delay:.2f}s")
                             
                        self.current_delay = new_delay
                        self.consecutive_errors = 0 # Reset counter after adjustment
                else:
                    # Success - slowly decrease delay back to normal
                    if self.consecutive_errors > 0:
                        self.consecutive_errors = max(0, self.consecutive_errors - 1)
                    else:
                        # Decrease delay, but don't go below min
                        self.current_delay = max(self.config.RATE_LIMIT_DELAY, self.current_delay * 0.9)

            return response

        except (httpx.RequestError, httpx.TimeoutException, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as e:
            # Handle connection errors as "errors" for adaptive logic
            if self.config.ADAPTIVE_RATE_LIMIT:
                self.consecutive_errors += 1
                if self.consecutive_errors >= self.config.ERROR_THRESHOLD:
                     self.current_delay = min(self.current_delay * 2, 5.0)
            
            # Re-raise to let caller handle failure
            raise e

    async def get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs) -> Optional[httpx.Response]:
        return await self.request("HEAD", url, **kwargs)
