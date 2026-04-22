"""
Adaptive Rate Limiter Module
===========================
Intelligent throttling engine for active scanning.
Features:
- Multi-tier profiles (Stealth to Aggressive)
- WAF detection and automatic backoff
- Random jitter to bypass pattern-based detection
- Circuit breaker to prevent IP bans
"""

import time
import random
from typing import Dict, Any

from config import Config
from utils.logger import logger

class AdaptiveRateLimiter:
    def __init__(self, profile_name: str = None):
        self.profile_name = profile_name or Config.ARJUN_DEFAULT_PROFILE
        self.profile = Config.ARJUN_RATE_PROFILES.get(self.profile_name, Config.ARJUN_RATE_PROFILES["conservative"])
        
        self.base_rate = self.profile["rate"]
        self.current_delay = 1.0 / self.base_rate
        self.waf_delay_inc = self.profile["waf_delay"]
        self.jitter_factor = self.profile["jitter"]
        
        self.consecutive_waf_errors = 0
        self.total_waf_errors = 0
        self.success_count = 0
        
        logger.info("[RATE LIMIT] Initialized with profile '%s' (Base Rate: %d req/s)", 
                    self.profile_name, self.base_rate)

    def wait(self):
        """Wait for the calculated delay with jitter."""
        jitter = self.current_delay * self.jitter_factor * random.uniform(-1, 1)
        wait_time = max(0.01, self.current_delay + jitter)
        time.sleep(wait_time)

    def handle_response(self, status_code: int) -> str:
        """
        Analyze response status to trigger circuit breaker on 2nd consecutive error.
        Adaptiveness removed as per surgical discovery policy.
        """
        if status_code in [403, 429]:
            self.consecutive_waf_errors += 1
            self.total_waf_errors += 1
            self.success_count = 0
            
            logger.warning("[RATE LIMIT] WAF Detection (%d)! (Consecutive: %d/2)", 
                           status_code, self.consecutive_waf_errors)
            
            if self.consecutive_waf_errors >= Config.ARJUN_CIRCUIT_BREAKER_LIMIT:
                logger.critical("[RATE LIMIT] Circuit Breaker Tripped! Aborting scan for this host.")
                return "ABORT"
            
            return "OK" # Keep same rate for the 2nd attempt
        
        elif 200 <= status_code < 300:
            self.consecutive_waf_errors = 0
            self.success_count += 1
            return "OK"
            
        return "OK"

    def get_stats(self) -> Dict[str, Any]:
        """Return diagnostic stats."""
        return {
            "profile": self.profile_name,
            "current_delay": round(self.current_delay, 3),
            "current_rate": round(1.0 / self.current_delay, 1) if self.current_delay > 0 else 0,
            "waf_errors": self.total_waf_errors,
            "health": "Healthy" if self.consecutive_waf_errors == 0 else "Degraded"
        }
