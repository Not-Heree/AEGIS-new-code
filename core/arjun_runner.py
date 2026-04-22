"""
Arjun HTTP Parameter Discovery Module (Enhanced)
===============================================
Discovers hidden HTTP parameters with context-aware wordlists
and adaptive rate limiting to prevent WAF bans.

Includes:
- SmartWordlistBuilder integration
- AdaptiveRateLimiter integration
- Sequential URL processing with backoff
- Real-time result persistence
"""

import json
import os
import subprocess
import tempfile
import time
from datetime import datetime
from typing import Any, List, Dict
from urllib.parse import urlparse

from config import Config
from utils.logger import logger
from core.smart_wordlist_builder import SmartWordlistBuilder
from core.adaptive_rate_limiter import AdaptiveRateLimiter

def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _resolve_tool_path(tool_path: str) -> str:
    if os.path.isabs(tool_path):
        return tool_path
    return os.path.abspath(os.path.join(_project_root(), tool_path))

def is_available() -> bool:
    arjun_path = _resolve_tool_path(Config.ARJUN_PATH)
    if os.sep in arjun_path or arjun_path.endswith(".exe"):
        return os.path.exists(arjun_path)
    try:
        result = subprocess.run([arjun_path, "--help"], capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except:
        return False

# Smart URL selection logic
MAX_ARJUN_URLS = 25
_PRIORITY_PATHS = ["/api", "/admin", "/search", "/login", "/auth", "/v1", "/v2", "/graphql"]

def _extract_live_urls(http_result: dict) -> list[dict]:
    """Extract URLs with tech metadata for better wordlist generation."""
    all_assets = []
    seen = set()

    for asset in http_result.get("http_assets", []):
        url = asset.get("url", "").strip()
        if url and url not in seen:
            seen.add(url)
            all_assets.append({
                "url": url,
                "tech": asset.get("tech", asset.get("technologies", [])),
                "method": asset.get("method", "GET")
            })

    if len(all_assets) <= MAX_ARJUN_URLS:
        return all_assets

    priority = []
    remaining = []
    for asset in all_assets:
        path = urlparse(asset["url"]).path.lower()
        if any(p in path for p in _PRIORITY_PATHS):
            priority.append(asset)
        else:
            remaining.append(asset)

    selected = priority + remaining[:MAX_ARJUN_URLS - len(priority)]
    return selected

def _parse_arjun_json_output(json_path: str) -> list[dict]:
    """Parse Arjun native JSON output."""
    if not os.path.exists(json_path):
        return []
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        endpoints = []
        if isinstance(data, dict):
            for url, details in data.items():
                params = details.get("params", []) if isinstance(details, dict) else details
                if params:
                    endpoints.append({
                        "url": url,
                        "method": details.get("method", "GET") if isinstance(details, dict) else "GET",
                        "parameters": params,
                        "source": "arjun_smart"
                    })
        return endpoints
    except:
        return []

def run_arjun(
    http_result: dict,
    profile: str = None,
    domain: str = ""
) -> dict[str, Any]:
    """
    Enhanced Arjun runner with Smart Wordlists and Adaptive Throttling.
    """
    live_assets = _extract_live_urls(http_result)
    if not live_assets:
        logger.info("[ARJUN] No live HTTP URLs for discovery — skipping")
        return {"success": True, "endpoints": [], "count": 0}

    logger.info("[ARJUN] Starting smart discovery on %d URLs using profile '%s'", 
                len(live_assets), profile or Config.ARJUN_DEFAULT_PROFILE)

    builder = SmartWordlistBuilder()
    limiter = AdaptiveRateLimiter(profile)
    
    all_endpoints = []
    temp_dir = os.path.join(os.path.dirname(__file__), "..", "temp")
    os.makedirs(temp_dir, exist_ok=True)

    for i, asset in enumerate(live_assets):
        url = asset["url"]
        tech = asset["tech"]
        method = asset["method"]

        logger.info("[ARJUN] [%d/%d] Analyzing %s", i+1, len(live_assets), url)

        # 1. Build surgically precise wordlist
        wordlist_path = builder.build_wordlist_file(url, tech, method)
        
        # 2. Reset Rate Limiter for this specific host to enforce per-host strike policy
        limiter = AdaptiveRateLimiter(profile)
        
        # 3. Adaptive Wait
        limiter.wait()

        # 4. Setup Arjun command
        output_path = os.path.join(temp_dir, f"arjun_out_{i}.json")
        arjun_path = _resolve_tool_path(Config.ARJUN_PATH)
        stats = limiter.get_stats()
        
        cmd = [
            arjun_path,
            "-u", url,
            "-m", method,
            "-w", wordlist_path,
            "-oJ", output_path,
            "--stable",
            "--rate-limit", str(int(stats["current_rate"])),
            "--threads", str(limiter.profile["threads"])
        ]

        logger.debug("[ARJUN] Running: %s", " ".join(cmd))

        try:
            # Run Arjun for this specific URL
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=Config.ARJUN_TIMEOUT)
            
            # 5. Analyze output for WAF detection
            stderr = process.stderr.lower()
            stdout = process.stdout.lower()
            
            combined_output = stderr + stdout
            status = "OK"
            
            if any(x in combined_output for x in ["403 forbidden", "429 too many", "blocked by waf", "protection by"]):
                status = limiter.handle_response(403)
            else:
                limiter.handle_response(200)

            # 6. Collect results
            if os.path.exists(output_path):
                url_endpoints = _parse_arjun_json_output(output_path)
                all_endpoints.extend(url_endpoints)
                os.remove(output_path)
            
            # Cleanup wordlist
            if os.path.exists(wordlist_path):
                os.remove(wordlist_path)

            if status == "ABORT":
                logger.error("[ARJUN] WAF Strike 2! Skipping %s but continuing with other URLs.", url)
                continue

        except subprocess.TimeoutExpired:
            logger.warning("[ARJUN] Timeout for %s, skipping to next URL", url)
        except Exception as e:
            logger.error("[ARJUN] Error scanning %s: %s", url, e)

    total_params = sum(len(e.get("parameters", [])) for e in all_endpoints)
    logger.info("[ARJUN] Discovery complete. Found %d parameters across %d endpoints", 
                total_params, len(all_endpoints))

    return {
        "success": True,
        "endpoints": all_endpoints,
        "count": len(all_endpoints),
        "stats": limiter.get_stats()
    }
