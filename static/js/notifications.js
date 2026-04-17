/**
 * AEGIS Premium Notification System
 * Handles elegant toast messages and custom confirmation dialogs.
 */

class ToastNotification {
    constructor() {
        this.createContainer();
        this.toasts = [];
        this._confirmCallback = null;
    }

    createContainer() {
        if (document.getElementById('toast-container')) return;
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = `
            position: fixed;
            top: 24px;
            right: 24px;
            z-index: 99999;
            max-width: 380px;
            width: 100%;
            display: flex;
            flex-direction: column;
            gap: 12px;
        `;
        document.body.appendChild(container);
    }

    /**
     * Show a premium toast notification
     * @param {string} message - Content
     * @param {string} type - success, error, warning, info
     * @param {number} duration - ms
     */
    show(message, type = 'info', duration = 5000) {
        const id = Date.now();
        const toast = document.createElement('div');
        
        const config = {
            success: { icon: 'bi-check2-circle', color: '#22d3ee', bg: 'rgba(34, 211, 238, 0.05)' },
            error: { icon: 'bi-exclamation-octagon', color: '#f87171', bg: 'rgba(248, 113, 113, 0.05)' },
            warning: { icon: 'bi-exclamation-triangle', color: '#facc15', bg: 'rgba(250, 204, 21, 0.05)' },
            info: { icon: 'bi-info-circle', color: '#38bdf8', bg: 'rgba(56, 189, 248, 0.02)' }
        };

        const { icon, color, bg } = config[type] || config.info;

        toast.id = `toast-${id}`;
        toast.className = 'premium-toast';
        toast.style.cssText = `
            background: #15191e;
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid #222a33;
            border-left: 2px solid ${color};
            color: #f1f5f9;
            padding: 20px 24px;
            border-radius: 4px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            pointer-events: auto;
            transform: translateX(400px);
            transition: transform 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275), opacity 0.3s ease;
            opacity: 0;
        `;

        toast.innerHTML = `
            <div style="display: flex; align-items: center; gap: 16px;">
                <div style="width: 36px; height: 36px; background: ${bg}; color: ${color}; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; border: 1px solid rgba(255,255,255,0.05);">
                    <i class="bi ${icon}"></i>
                </div>
                <div style="font-weight: 800; font-size: 0.75rem; letter-spacing: 0.5px; text-transform: uppercase;">${message}</div>
            </div>
            <button onclick="toast.dismiss('${id}')" style="background: none; border: none; color: #64748b; cursor: pointer; padding: 4px; display: flex; align-items: center; justify-content: center; transition: color 0.2s;">
                <i class="bi bi-x-lg" style="font-size: 1rem;"></i>
            </button>
        `;

        const container = document.getElementById('toast-container');
        container.appendChild(toast);

        // Trigger animation
        requestAnimationFrame(() => {
            toast.style.transform = 'translateX(0)';
            toast.style.opacity = '1';
        });

        if (duration > 0) {
            setTimeout(() => this.dismiss(id), duration);
        }

        return id;
    }

    success(m) { return this.show(m, 'success'); }
    error(m) { return this.show(m, 'error', 7000); }
    warning(m) { return this.show(m, 'warning', 6000); }
    info(m) { return this.show(m, 'info'); }

    dismiss(id) {
        const el = document.getElementById(`toast-${id}`);
        if (el) {
            el.style.transform = 'translateX(400px)';
            el.style.opacity = '0';
            setTimeout(() => el.remove(), 400);
        }
    }

    /**
     * Premium Confirmation Dialog
     * Replaces the browser's native confirm()
     */
    confirm({ title, message, confirmText, cancelText, type = 'danger' }) {
        return new Promise((resolve) => {
            const modalEl = document.getElementById('premium-confirm-modal');
            if (!modalEl) {
                // Fallback to native if modal structure is missing
                resolve(window.confirm(message));
                return;
            }

            const modal = new bootstrap.Modal(modalEl);
            
            // Set content
            document.getElementById('p-confirm-title').textContent = title || 'Confirm Action';
            document.getElementById('p-confirm-body').textContent = message || 'Are you sure?';
            const confirmBtn = document.getElementById('p-confirm-btn');
            
            // Set style based on type
            const typeConfig = {
                danger: { color: '#ef4444', icon: 'bi-exclamation-circle' },
                warning: { color: '#f59e0b', icon: 'bi-exclamation-triangle' },
                primary: { color: '#3b82f6', icon: 'bi-info-circle' },
                info: { color: '#6b7280', icon: 'bi-info-circle' }
            };
            const config = typeConfig[type] || typeConfig.danger;
            
            const iconContainer = document.getElementById('p-confirm-icon-container');
            const iconInner = document.getElementById('p-confirm-icon');
            if (iconContainer) iconContainer.style.color = config.color;
            if (iconInner) {
                iconInner.className = `bi ${config.icon}`;
            }

            confirmBtn.textContent = confirmText || (type === 'danger' ? 'Delete' : 'Confirm');
            confirmBtn.style.backgroundColor = config.color;
            confirmBtn.className = `btn btn-${type} w-100 fw-semibold`;

            const handleConfirm = () => {
                modal.hide();
                modalEl.removeEventListener('hidden.bs.modal', handleCancel);
                resolve(true);
            };

            const handleCancel = () => {
                modalEl.removeEventListener('hidden.bs.modal', handleCancel);
                resolve(false);
            };

            confirmBtn.onclick = handleConfirm;
            modalEl.addEventListener('hidden.bs.modal', handleCancel, { once: true });

            modal.show();
        });
    }
}

// Global instance
const toast = new ToastNotification();
window.toast = toast;
