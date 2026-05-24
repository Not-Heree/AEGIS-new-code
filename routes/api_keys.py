"""
API Keys Management Routes
==========================
Web UI for managing API keys.
"""

from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from functools import wraps

from core.api_key_manager import APIKeyManager
from utils.logger import logger


bp = Blueprint('api_keys', __name__, url_prefix='/settings/api-keys')


def admin_required(f):
    """Decorator to require admin authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # TODO: Implement proper authentication
        # For now, just pass through
        # In production, check session['user'] == 'admin'
        return f(*args, **kwargs)
    return decorated_function


@bp.route('/')
@admin_required
def index():
    """Show API keys management page."""
    keys_status = APIKeyManager.get_all_keys_status()
    configured_count = sum(1 for status in keys_status.values() if status.get("configured"))

    return render_template(
        'api_keys.html',
        keys_status=keys_status,
        configured_count=configured_count,
        total_keys=len(keys_status),
        active_page="api_keys"
    )


@bp.route('/save', methods=['POST'])
@admin_required
def save_key():
    """Save or update an API key."""
    key_name = request.form.get('key_name')
    key_value = request.form.get('key_value', '').strip()

    if not key_name or key_name not in APIKeyManager.KEY_TYPES:
        flash('Invalid API key type', 'danger')
        return redirect(url_for('api_keys.index'))

    if not key_value:
        flash('API key value cannot be empty', 'danger')
        return redirect(url_for('api_keys.index'))

    # Test key before saving (if requested)
    test_first = request.form.get('test_first') == 'on'

    if test_first:
        logger.info(f"[API_KEYS] Testing {key_name} before saving...")
        test_result = APIKeyManager.test_key(key_name, key_value)

        if not test_result.get("success"):
            flash(f'API key test failed: {test_result.get("error")}', 'danger')
            return redirect(url_for('api_keys.index'))

        flash(f'API key tested successfully: {test_result.get("message")}', 'success')

    # Save key
    success = APIKeyManager.set_key(key_name, key_value, user="admin")

    if success:
        flash(f'{APIKeyManager.KEY_TYPES[key_name]["name"]} saved successfully', 'success')
    else:
        flash('Error saving API key', 'danger')

    return redirect(url_for('api_keys.index'))


@bp.route('/delete', methods=['POST'])
@admin_required
def delete_key():
    """Delete an API key."""
    key_name = request.form.get('key_name')

    if not key_name or key_name not in APIKeyManager.KEY_TYPES:
        flash('Invalid API key type', 'danger')
        return redirect(url_for('api_keys.index'))

    success = APIKeyManager.delete_key(key_name)

    if success:
        flash(f'{APIKeyManager.KEY_TYPES[key_name]["name"]} deleted', 'info')
    else:
        flash('Error deleting API key', 'danger')

    return redirect(url_for('api_keys.index'))


@bp.route('/test/<key_name>', methods=['POST'])
@admin_required
def test_key(key_name):
    """Test an API key."""
    if key_name not in APIKeyManager.KEY_TYPES:
        return jsonify({'success': False, 'error': 'Invalid key type'}), 400

    # Get key value from form (for testing before save) or database
    key_value = request.form.get('key_value')

    result = APIKeyManager.test_key(key_name, key_value)

    return jsonify(result)
