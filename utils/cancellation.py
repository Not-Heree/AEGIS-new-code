"""
Cancellation Utility for Background Tasks
"""
import threading
from utils.logger import logger

_cancel_signals = {}
_signals_lock = threading.Lock()

def register_target(domain):
    domain = domain.lower().strip()
    with _signals_lock:
        if domain not in _cancel_signals:
            _cancel_signals[domain] = threading.Event()
        else:
            _cancel_signals[domain].clear()
    return _cancel_signals[domain]

def signal_cancel(domain):
    domain = domain.lower().strip()
    with _signals_lock:
        if domain in _cancel_signals:
            _cancel_signals[domain].set()
            logger.info(f"[ABORT] Stop signal sent for: {domain}")
            return True
    return False

def is_cancelled(domain):
    domain = domain.lower().strip()
    with _signals_lock:
        signal = _cancel_signals.get(domain)
        if signal and signal.is_set():
            return True
    return False

def cleanup_signal(domain):
    domain = domain.lower().strip()
    with _signals_lock:
        _cancel_signals.pop(domain, None)
