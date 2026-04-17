"""
WebSocket Emit Utilities for Real-time Scan Progress
=====================================================

This module provides helper functions to emit scan progress events
via WebSocket to connected clients.
"""

from utils.logger import logger


def emit_scan_progress(scan_id, phase_name, phase_number, progress_percent, message):
    """
    Emit scan progress update via WebSocket.
    
    Args:
        scan_id: ID of the scan being tracked
        phase_name: Name of the current phase (e.g., "Passive Recon")
        phase_number: Phase number (0-6)
        progress_percent: Progress percentage for this phase
        message: Human-readable status message
    """
    try:
        from app import socketio
        
        event_data = {
            'scan_id': scan_id,
            'phase': phase_number,
            'phase_name': phase_name,
            'progress': progress_percent,
            'message': message,
            'timestamp': __import__('datetime').datetime.utcnow().isoformat()
        }
        
        socketio.emit(
            'scan_progress',
            event_data,
            room=f'scan_{scan_id}',
            skip_sid=None
        )
        
        logger.debug(
            f"Emitted scan progress: scan={scan_id}, phase={phase_number}, "
            f"progress={progress_percent}%"
        )
        
    except Exception as e:
        logger.error(f"Error emitting scan progress: {e}")


def emit_scan_completed(scan_id, results_summary):
    """
    Emit scan completion event.
    
    Args:
        scan_id: ID of the completed scan
        results_summary: Dict with scan results summary
    """
    try:
        from app import socketio
        
        event_data = {
            'scan_id': scan_id,
            'status': 'completed',
            'summary': results_summary,
            'timestamp': __import__('datetime').datetime.utcnow().isoformat()
        }
        
        socketio.emit(
            'scan_completed',
            event_data,
            room=f'scan_{scan_id}'
        )
        
        logger.info(f"Emitted scan completed: scan={scan_id}")
        
    except Exception as e:
        logger.error(f"Error emitting scan completion: {e}")


def emit_scan_error(scan_id, phase_name, error_message):
    """
    Emit scan error event.
    
    Args:
        scan_id: ID of the scan that errored
        phase_name: Phase where error occurred
        error_message: Error details
    """
    try:
        from app import socketio
        
        event_data = {
            'scan_id': scan_id,
            'status': 'error',
            'phase': phase_name,
            'error': error_message,
            'timestamp': __import__('datetime').datetime.utcnow().isoformat()
        }
        
        socketio.emit(
            'scan_error',
            event_data,
            room=f'scan_{scan_id}'
        )
        
        logger.warning(f"Emitted scan error: scan={scan_id}, phase={phase_name}")
        
    except Exception as e:
        logger.error(f"Error emitting scan error: {e}")


def emit_scan_phase_complete(scan_id, phase_number, phase_name, results):
    """
    Emit phase completion event with results.
    
    Args:
        scan_id: ID of the scan
        phase_number: Completed phase number
        phase_name: Completed phase name
        results: Dict with phase results
    """
    try:
        from app import socketio
        
        event_data = {
            'scan_id': scan_id,
            'phase': phase_number,
            'phase_name': phase_name,
            'status': 'completed',
            'results': results,
            'timestamp': __import__('datetime').datetime.utcnow().isoformat()
        }
        
        socketio.emit(
            'phase_completed',
            event_data,
            room=f'scan_{scan_id}'
        )
        
        logger.info(f"Emitted phase completed: scan={scan_id}, phase={phase_number}")
        
    except Exception as e:
        logger.error(f"Error emitting phase completion: {e}")
