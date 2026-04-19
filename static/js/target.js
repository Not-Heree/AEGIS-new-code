// static/js/targets.js

document.addEventListener('DOMContentLoaded', function () {
    loadTargets();
});

async function loadTargets() {
    const data = await api.get('/api/targets/');
    const tbody = document.getElementById('targets-table');

    if (!data.targets || data.targets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No targets. Click "Add Target" to begin!</td></tr>';
        return;
    }

    tbody.innerHTML = data.targets.map(t => `
        <tr>
            <td class="fw-800 text-white" style="font-size: 0.8rem; letter-spacing: 0.5px;">${(t.root_domain || t.domain).toUpperCase()}</td>
            <td class="text-secondary small fw-bold">${t.org_name || 'N/A'}</td>
            <td><span class="badge bg-black text-secondary border border-secondary border-opacity-25 fw-800">${(t.status || 'active').toUpperCase()}</span></td>
            <td class="text-white small fw-bold">${formatNumber(t.total_subdomains)}</td>
            <td class="text-white small fw-bold">${formatNumber(t.total_vulns)}</td>
            <td class="text-white small fw-bold">${t.risk_score || 0}/100</td>
            <td>
                <div class="d-flex gap-2">
                    <button class="btn btn-scan btn-sm px-3" onclick="runScan('${t.root_domain || t.domain}')" title="RUN_SCAN">
                        <i class="bi bi-terminal"></i>
                    </button>
                    <button class="btn btn-outline-secondary btn-sm px-3" onclick="viewTarget('${t.root_domain || t.domain}')" title="VIEW_INTELLIGENCE">
                        <i class="bi bi-eye"></i>
                    </button>
                    <button class="btn btn-outline-danger btn-sm px-3 border-opacity-25" onclick="deleteTarget('${t.root_domain || t.domain}')" title="REMOVE_TARGET">
                        <i class="bi bi-trash"></i>
                    </button>
                </div>
            </td>
        </tr>
    `).join('');
}

async function addTarget() {
    const domain = document.getElementById('domain').value.trim();
    const org_name = document.getElementById('org_name').value.trim();

    if (!domain) {
        showAlert('Domain is required!', 'danger');
        return;
    }

    const result = await api.post('/api/targets/', { domain, org_name });

    if (result.success) {
        showAlert('Target added successfully!', 'success');
        bootstrap.Modal.getInstance(document.getElementById('addTargetModal')).hide();
        document.getElementById('addTargetForm').reset();
        loadTargets();
    } else {
        showAlert('Error: ' + result.error, 'danger');
    }
}

async function runScan(domain) {
    const confirmed = await toast.confirm({
        title: 'Run Scan',
        message: `Run full scan on ${domain}? This may take several minutes.`,
        confirmText: 'Start Scan',
        type: 'primary'
    });
    if (!confirmed) return;

    showAlert('Scan started... Monitoring progress...', 'info');
    const result = await api.post(`/api/scans/full/${domain}`);

    if (result.success) {
        const scan_id = result.scan_id;
        
        // Poll for scan status
        pollScanProgress(scan_id, domain);
    } else {
        showAlert('Scan error: ' + result.error, 'danger');
    }
}

async function pollScanProgress(scan_id, domain) {
    const max_attempts = 1000;  // ~16 hours with 60 second intervals
    let attempts = 0;
    
    const poll_interval = setInterval(async () => {
        attempts++;
        
        try {
            const status = await api.get(`/api/scans/status/${scan_id}`);
            
            if (status.success) {
                const scan = status.scan;
                const progress = scan.progress_percent || 0;
                const phase = scan.current_phase || 'unknown';
                const detail = scan.phase_detail || '';
                
                // Update progress alert
                let msg = `Scan in progress: ${phase}`;
                if (detail) msg += ` - ${detail}`;
                if (progress > 0) msg += ` (${progress}%)`;
                
                showAlert(msg, 'info');
                
                // If scan is complete or failed, stop polling
                if (scan.status === 'completed') {
                    clearInterval(poll_interval);
                    showAlert(' Scan completed successfully!', 'success');
                    
                    // Reload target data to show new findings
                    setTimeout(() => {
                        loadTargets();
                        if (window.loadTargetDetail) {
                            loadTargetDetail(domain);
                        }
                    }, 1000);
                    
                } else if (scan.status === 'failed') {
                    clearInterval(poll_interval);
                    showAlert(' Scan failed: ' + (scan.error_message || 'Unknown error'), 'danger');
                    loadTargets();
                }
            }
        } catch (e) {
            console.error('Error polling scan status:', e);
        }
        
        // Stop polling after max attempts
        if (attempts >= max_attempts) {
            clearInterval(poll_interval);
            showAlert('⏱️ Scan is taking longer than expected. Check scan history for status.', 'warning');
            loadTargets();
        }
    }, 60000);  // Poll every 60 seconds
}

function viewTarget(domain) {
    window.location.href = `/targets/${domain}`;
}

async function deleteTarget(domain) {
    const confirmed = await toast.confirm({
        title: 'Delete Target',
        message: `Delete ${domain} and ALL its data? This cannot be undone!`,
        confirmText: 'Delete',
        type: 'danger'
    });
    if (!confirmed) return;

    const result = await api.delete(`/api/targets/${domain}`);

    if (result.success) {
        showAlert('Target deleted!', 'success');
        loadTargets();
    } else {
        showAlert('Error: ' + result.error, 'danger');
    }
}