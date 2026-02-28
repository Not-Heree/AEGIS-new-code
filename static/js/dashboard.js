// static/js/dashboard.js

document.addEventListener('DOMContentLoaded', function () {
    loadDashboard();
});

async function loadDashboard() {
    await loadStats();
    await loadDashboardData();
}

async function loadStats() {
    const stats = await api.get('/api/stats');

    document.getElementById('total-targets').textContent = formatNumber(stats.targets);
    document.getElementById('total-subdomains').textContent = formatNumber(stats.subdomains);
    document.getElementById('total-ports').textContent = formatNumber(stats.ports_services);
    document.getElementById('total-http').textContent = formatNumber(stats.http_assets);
    document.getElementById('total-vulns').textContent = formatNumber(stats.vulnerabilities);
    document.getElementById('total-changes').textContent = formatNumber(stats.changes);
}

async function loadDashboardData() {
    const data = await api.get('/api/dashboard/');

    if (!data.success) {
        console.error('Dashboard load error:', data.error);
        return;
    }

    // Vulnerability breakdown
    const vb = data.vuln_breakdown || {};
    document.getElementById('vuln-critical').textContent = vb.critical || 0;
    document.getElementById('vuln-high').textContent = vb.high || 0;
    document.getElementById('vuln-medium').textContent = vb.medium || 0;
    document.getElementById('vuln-low').textContent = vb.low || 0;
    document.getElementById('vuln-info').textContent = vb.info || 0;

    // Risk score
    const riskScore = data.overall_risk_score || 0;
    const riskEl = document.getElementById('risk-score');
    riskEl.textContent = riskScore;

    let riskClass = 'risk-minimal';
    let riskText = 'MINIMAL';
    if (riskScore >= 80) { riskClass = 'risk-critical'; riskText = 'CRITICAL'; }
    else if (riskScore >= 60) { riskClass = 'risk-high'; riskText = 'HIGH'; }
    else if (riskScore >= 40) { riskClass = 'risk-medium'; riskText = 'MEDIUM'; }
    else if (riskScore >= 20) { riskClass = 'risk-low'; riskText = 'LOW'; }

    riskEl.className = 'risk-score ' + riskClass;
    document.getElementById('risk-level').textContent = riskText;

    // Targets table
    loadTargetsTable(data.targets || []);
}

function loadTargetsTable(targets) {
    const tbody = document.getElementById('targets-table');

    if (targets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No targets. <a href="/targets">Add one!</a></td></tr>';
        return;
    }

    tbody.innerHTML = targets.map(t => `
        <tr>
            <td><strong>${t.root_domain || t.domain || 'N/A'}</strong></td>
            <td>${formatNumber(t.total_subdomains)}</td>
            <td>${formatNumber(t.total_ports)}</td>
            <td>${formatNumber(t.total_http_assets)}</td>
            <td>${formatNumber(t.total_vulns)}</td>
            <td>${t.last_scanned ? formatDate(t.last_scanned) : 'Never'}</td>
            <td>
                <a href="/targets/${t.root_domain || t.domain}" class="btn btn-sm btn-outline-primary">
                    <i class="bi bi-eye"></i>
                </a>
            </td>
        </tr>
    `).join('');
}

async function refreshStats() {
    showAlert('Refreshing...', 'info');
    await loadDashboard();
    showAlert('Dashboard refreshed!', 'success');
}