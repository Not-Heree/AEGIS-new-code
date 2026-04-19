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
        Analyze response status to adjust rate or trigger circuit breaker.
        
        Returns:
            "OK" if continuing, "ABORT" if circuit breaker tripped.
        """
        if status_code in [403, 429]:
            self.consecutive_waf_errors += 1
            self.total_waf_errors += 1
            self.success_count = 0
            
            # Exponential backoff on WAF detection
            new_delay = self.current_delay + self.waf_delay_inc
            logger.warning("[RATE LIMIT] WAF Detection (%d)! Increasing delay from %.2fs to %.2fs (Consecutive: %d)", 
                          status_code, self.current_delay, new_delay, self.consecutive_waf_errors)
            self.current_delay = new_delay
            
            if self.consecutive_waf_errors >= Config.ARJUN_CIRCUIT_BREAKER_LIMIT:
                logger.critical("[RATE LIMIT] Circuit Breaker Tripped! %d consecutive WAF errors. Aborting...", 
                               self.consecutive_waf_errors)
                return "ABORT"
            
            return "SLOW_DOWN"
        
        elif 200 <= status_code < 300:
            self.success_count += 1
            
            # If we had WAF errors, slowly try to recover the rate
            if self.consecutive_waf_errors > 0:
                self.consecutive_waf_errors = 0
                
            if self.current_delay > (1.0 / self.base_rate):
                # Slowly decrease delay if we've had many successes
                if self.success_count >= 10:
                    old_delay = self.current_delay
                    self.current_delay = max(1.0 / self.base_rate, self.current_delay * 0.8)
                    logger.info("[RATE LIMIT] Connection stable (%d successes). Recovering rate: %.2fs -> %.2fs", 
                                self.success_count, old_delay, self.current_delay)
                    self.success_count = 0
            
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
