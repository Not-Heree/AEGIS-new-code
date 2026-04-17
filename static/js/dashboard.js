// static/js/dashboard.js
// ══════════════════════════════════════════════════════
//  Dashboard loader + Direct Recon Redirects
// ══════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', function () {
    loadDashboard();
});

/* ──────────────────────────────────────────────
   Core Dashboard
   ────────────────────────────────────────────── */

async function loadDashboard() {
    await loadStats();
    await loadDashboardData();
}

async function loadStats() {
    var stats = await api.get('/api/stats');
    document.getElementById('total-targets').textContent = formatNumber(stats.targets);
    document.getElementById('total-subdomains').textContent = formatNumber(stats.subdomains);
    document.getElementById('total-http').textContent = formatNumber(stats.http_assets);
    document.getElementById('total-vulns').textContent = formatNumber(stats.vulnerabilities);
    document.getElementById('total-emails').textContent = formatNumber(stats.emails || 0);
    document.getElementById('total-changes').textContent = formatNumber(stats.changes);
}

async function loadDashboardData() {
    var data = await api.get('/api/dashboard/');

    if (!data.success) {
        console.error('Dashboard load error:', data.error);
        return;
    }

    // Vulnerability breakdown
    var vb = data.vuln_breakdown || {};
    document.getElementById('vuln-critical').textContent = vb.critical || 0;
    document.getElementById('vuln-high').textContent = vb.high || 0;
    document.getElementById('vuln-medium').textContent = vb.medium || 0;
    document.getElementById('vuln-low').textContent = vb.low || 0;
    document.getElementById('vuln-info').textContent = vb.info || 0;

    // Check if any target has been scanned
    var targets = data.targets || [];
    var hasScanned = false;
    for (var i = 0; i < targets.length; i++) {
        if (targets[i].last_scan_at) {
            hasScanned = true;
            break;
        }
    }

    // Risk grade
    var riskScore = data.overall_risk_score || 0;
    var gradeEl = document.getElementById('risk-grade');
    var subscoreEl = document.getElementById('risk-subscore');

    if (targets.length === 0 || !hasScanned) {
        gradeEl.textContent = '-';
        gradeEl.className = 'risk-grade text-white opacity-25 fs-5 mt-2';
        gradeEl.innerHTML = ' Run a scan first';
        subscoreEl.className = 'risk-subscore text-white opacity-40 small text-uppercase fw-700 mt-2';
        subscoreEl.textContent = 'No scan data available';
    } else {
        var gradeInfo = riskScoreToGrade(riskScore);
        gradeEl.textContent = gradeInfo.grade;
        gradeEl.className = 'risk-grade ' + gradeInfo.cls;
        subscoreEl.className = 'risk-subscore text-white opacity-40 small text-uppercase fw-700 mt-2';
        subscoreEl.textContent = riskScore + ' / 100 risk score';
    }

    // Passive Recon Summary
    loadPassiveReconSummary();
}

async function loadPassiveReconSummary() {
    try {
        const data = await api.get('/api/passive/');
        if (!data.success) {
            document.getElementById('pr-shodan-stat').textContent = 'No data';
            document.getElementById('pr-censys-stat').textContent = 'No data';
            document.getElementById('pr-whois-stat').textContent = 'No data';
            document.getElementById('pr-cert-stat').textContent = 'No data';
            return;
        }

        const domains = data.domains || [];

        // Aggregate per-source stats across all domains
        let shodanHosts = 0, shodanCves = 0, shodanAvail = false;
        let censysHosts = 0, censysServices = 0, censysAvail = false;
        let whoisDomains = 0, whoisRisks = 0, whoisAvail = false;

        for (const d of domains) {
            if (d.shodan && d.shodan.available) {
                shodanAvail = true;
                shodanHosts += d.shodan.hosts || 0;
                shodanCves += d.shodan.cves || 0;
            }
            if (d.censys && d.censys.available) {
                censysAvail = true;
                censysHosts += d.censys.hosts || 0;
                censysServices += d.censys.services || 0;
            }
            if (d.whois && d.whois.available) {
                whoisAvail = true;
                whoisDomains++;
                whoisRisks += (d.whois.risk_flags || []).length;
            }
        }

        document.getElementById('pr-shodan-stat').textContent = shodanAvail
            ? `${shodanHosts} hosts, ${shodanCves} CVEs`
            : 'Not collected';
        document.getElementById('pr-censys-stat').textContent = censysAvail
            ? `${censysHosts} hosts, ${censysServices} services`
            : 'Not collected';
        document.getElementById('pr-whois-stat').textContent = whoisAvail
            ? `${whoisDomains} domains, ${whoisRisks} risks`
            : 'Not collected';

        // Certificate stats
        document.getElementById('pr-cert-stat').textContent = (data.total_certificates || 0) > 0
            ? `${data.total_certificates} certificates`
            : 'Not collected';

    } catch (e) {
        console.error('Passive recon summary error:', e);
        document.getElementById('pr-shodan-stat').textContent = 'Error';
        document.getElementById('pr-censys-stat').textContent = 'Error';
        document.getElementById('pr-whois-stat').textContent = 'Error';
        document.getElementById('pr-cert-stat').textContent = 'Error';
    }
}

// Targets table
async function loadTargetsTable(targets) {
    const tbody = document.getElementById('targets-table');
    if (!tbody) return;

    if (targets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4 text-muted small fw-800">NO MANAGED ASSETS DETECTED</td></tr>';
        return;
    }

    tbody.innerHTML = targets.slice(0, 10).map(t => {
        const domain = t.root_domain || t.domain || 'N/A';
        const gradeInfo = riskScoreToGrade(t.risk_score || 0);

        return `
            <tr class="align-middle">
                <td class="ps-4">
                    <div class="fw-800 text-white text-uppercase" style="font-size: 0.75rem; letter-spacing: 0.5px;">${domain}</div>
                    <div class="text-muted fw-bold" style="font-size: 0.6rem; opacity: 0.5;">${(t.org_name || 'EXTERNAL').toUpperCase()}</div>
                </td>
                <td class="text-white fw-800 small">${formatNumber(t.total_subdomains || 0)}</td>
                <td class="text-white fw-800 small">${formatNumber(t.http_assets || 0)}</td>
                <td>
                    <span class="badge bg-black ${t.total_vulns > 0 ? 'text-danger border-danger border-opacity-25' : 'text-secondary border-secondary border-opacity-10'} fw-800">
                        ${t.total_vulns || 0}
                    </span>
                </td>
                <td class="text-secondary fw-800 small">${formatNumber(t.emails || 0)}</td>
                <td>
                    <span class="badge bg-black border border-secondary border-opacity-25 fw-800 ${gradeInfo.cls}" style="font-size: 0.65rem;">
                        ${gradeInfo.grade}
                    </span>
                </td>
                <td class="text-muted fw-800 small" style="font-size: 0.65rem;">
                    ${t.last_scan_at ? new Date(t.last_scan_at).toLocaleDateString().toUpperCase() : 'NEVER'}
                </td>
            </tr>
        `;
    }).join('');
}

// Refresh logic
async function refreshStats() {
    const btn = document.querySelector('.btn-scan');
    const originalContent = btn.innerHTML;
    
    btn.disabled = true;
    btn.innerHTML = '<i class="bi bi-arrow-clockwise spin"></i> UPDATING...';
    
    await loadDashboard();
    
    setTimeout(() => {
        btn.disabled = false;
        btn.innerHTML = originalContent;
    }, 500);
}