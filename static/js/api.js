// static/js/api.js - API Helper Functions

const API_BASE = '';

const api = {
    async get(url) {
        try {
            const response = await fetch(API_BASE + url);
            return await response.json();
        } catch (error) {
            console.error('API GET Error:', error);
            return { success: false, error: error.message };
        }
    },

    async post(url, data = {}) {
        try {
            const response = await fetch(API_BASE + url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            return await response.json();
        } catch (error) {
            console.error('API POST Error:', error);
            return { success: false, error: error.message };
        }
    },

    async delete(url) {
        try {
            const response = await fetch(API_BASE + url, { method: 'DELETE' });
            return await response.json();
        } catch (error) {
            console.error('API DELETE Error:', error);
            return { success: false, error: error.message };
        }
    },

    async put(url, data = {}) {
        try {
            const response = await fetch(API_BASE + url, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            return await response.json();
        } catch (error) {
            console.error('API PUT Error:', error);
            return { success: false, error: error.message };
        }
    }
};

// Utility Functions
function showAlert(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.querySelector('.main-content').prepend(alertDiv);
    setTimeout(() => alertDiv.remove(), 5000);
}

function formatDate(dateStr) {
    if (!dateStr) return '-';
    return new Date(dateStr).toLocaleString();
}

function formatNumber(num) {
    return (num || 0).toLocaleString();
}