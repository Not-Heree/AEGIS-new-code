import time
import threading
from typing import Dict

class APIThrottler:
    """
    Centralized throttler for API rate limiting.
    Ensures that calls to specific APIs are spaced out by a minimum delay.
    """
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(APIThrottler, cls).__new__(cls)
                cls._instance._last_call_times = {}
                cls._instance._locks = {}
        return cls._instance

    def _get_lock(self, api_name: str) -> threading.Lock:
        """Get or create a lock for a specific API."""
        with self._lock:
            if api_name not in self._locks:
                self._locks[api_name] = threading.Lock()
            return self._locks[api_name]

    def wait_if_needed(self, api_name: str, delay_seconds: float):
        """
        Hold execution if the last call to this API was too recent.
        
        Args:
            api_name: Unique identifier for the API (e.g., 'intelx', 'hunter')
            delay_seconds: Minimum seconds between calls
        """
        if delay_seconds <= 0:
            return

        api_lock = self._get_lock(api_name)
        
        with api_lock:
            last_time = self._last_call_times.get(api_name, 0)
            current_time = time.time()
            elapsed = current_time - last_time
            
            if elapsed < delay_seconds:
                sleep_time = delay_seconds - elapsed
                from utils.logger import logger
                logger.debug(f"[THROTTLE] Sleeping {sleep_time:.2f}s for API: {api_name}")
                time.sleep(sleep_time)
            
            self._last_call_times[api_name] = time.time()

# Singleton instance
throttler = APIThrottler()
