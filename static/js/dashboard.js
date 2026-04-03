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
        gradeEl.className = 'risk-grade text-muted fs-5 mt-2';
        gradeEl.innerHTML = ' Run a scan first';
        subscoreEl.textContent = 'No scan data available';
    } else {
        var gradeInfo = riskScoreToGrade(riskScore);
        gradeEl.textContent = gradeInfo.grade;
        gradeEl.className = 'risk-grade ' + gradeInfo.cls;
        subscoreEl.textContent = riskScore + ' / 100 risk score';
    }

    // Targets table
    loadTargetsTable(targets);

    // ── Passive Recon source cards + Certificates ──────────
    var passiveSection = document.getElementById('dashboard-passive-recon');
    if (passiveSection && data.passive_recon) {
        var pr = data.passive_recon;

        // Fetch certificate stats asynchronously
        var certData = { total_certificates: 0, summary: { expired: 0, expiring_soon: 0 } };
        try {
            var certResp = await api.get('/api/passive/certificates');
            if (certResp.success) {
                certData = certResp;
            }
        } catch (e) {
            console.warn('Could not load certificate stats:', e);
        }

        var certTotal = certData.total_certificates || 0;
        var certExpired = (certData.summary || {}).expired || 0;
        var certExpiring = (certData.summary || {}).expiring_soon || 0;
        var certRiskCount = certExpired + certExpiring;

        passiveSection.innerHTML =
            '<div class="row text-center">' +

            // ── Shodan Card ──
            '<div class="col-md-3 mb-3 mb-md-0">' +
            '<div class="card h-100 border shadow-sm clickable-card" ' +
            '     onclick="window.location.href=\'/recon?source=shodan\'" role="button">' +
            '<div class="card-body">' +
            '<h6 class="text-info mb-3">Shodan</h6>' +
            '<div class="row">' +
            '<div class="col"><h5 class="mb-0">' + formatNumber(pr.shodan_subdomains) + '</h5>' +
            '<small class="text-muted">Subs</small></div>' +
            '<div class="col"><h5 class="mb-0">' + formatNumber(pr.shodan_ports) + '</h5>' +
            '<small class="text-muted">Ports</small></div>' +
            '</div>' +
            '<div class="mt-2"><small class="text-muted">' +
            'View details</small></div>' +
            '</div></div></div>' +

            // ── Censys Card ──
            '<div class="col-md-3 mb-3 mb-md-0">' +
            '<div class="card h-100 border shadow-sm clickable-card" ' +
            '     onclick="window.location.href=\'/recon?source=censys\'" role="button">' +
            '<div class="card-body">' +
            '<h6 class="text-warning mb-3"> Censys</h6>' +
            '<div class="row">' +
            '<div class="col"><h5 class="mb-0">' + formatNumber(pr.censys_subdomains) + '</h5>' +
            '<small class="text-muted">Subs</small></div>' +
            '<div class="col"><h5 class="mb-0">' + formatNumber(pr.censys_ports) + '</h5>' +
            '<small class="text-muted">Ports</small></div>' +
            '</div>' +
            '<div class="mt-2"><small class="text-muted">' +
            'View details</small></div>' +
            '</div></div></div>' +

            // ── WHOIS Card ──
            '<div class="col-md-3 mb-3 mb-md-0">' +
            '<div class="card h-100 border shadow-sm clickable-card" ' +
            '     onclick="window.location.href=\'/recon?source=whois\'" role="button">' +
            '<div class="card-body">' +
            '<h6 class="text-primary mb-3"> WHOIS</h6>' +
            '<div class="row">' +
            '<div class="col"><h5 class="mb-0">' + formatNumber(pr.whois_domains) + '</h5>' +
            '<small class="text-muted">Domains</small></div>' +
            '<div class="col"><h5 class="mb-0 ' +
            (pr.whois_critical_risks > 0 ? 'text-danger' : 'text-success') + '">' +
            formatNumber(pr.whois_total_risks) + '</h5>' +
            '<small class="text-muted">Risks</small></div>' +
            '</div>' +
            '<div class="mt-2"><small class="text-muted">' +
            'View details</small></div>' +
            '</div></div></div>' +

            // ── Certificates Card ──
            '<div class="col-md-3">' +
            '<div class="card h-100 border shadow-sm clickable-card" ' +
            '     onclick="window.location.href=\'/recon?source=certificates\'" role="button">' +
            '<div class="card-body">' +
            '<h6 class="text-success mb-3"> Certificates</h6>' +
            '<div class="row">' +
            '<div class="col"><h5 class="mb-0">' + formatNumber(certTotal) + '</h5>' +
            '<small class="text-muted">Certs</small></div>' +
            '<div class="col"><h5 class="mb-0 ' +
            (certRiskCount > 0 ? 'text-danger' : 'text-success') + '">' +
            formatNumber(certRiskCount) + '</h5>' +
            '<small class="text-muted">Issues</small></div>' +
            '</div>' +
            '<div class="mt-2"><small class="text-muted">' +
            'View details</small></div>' +
            '</div></div></div>' +

            '</div>';
    }
}

/* ──────────────────────────────────────────────
   Targets Table
   ────────────────────────────────────────────── */

function loadTargetsTable(targets) {
    var tbody = document.getElementById('targets-table');

    if (targets.length === 0) {
        tbody.innerHTML =
            '<tr><td colspan="8" class="text-center text-muted">' +
            'No targets. <a href="/targets">Add one!</a></td></tr>';
        return;
    }

    tbody.innerHTML = targets.map(function (t) {
        var domain = t.root_domain || t.domain || 'N/A';
        var riskScore = t.risk_score || 0;
        var gradeInfo = riskScoreToGrade(riskScore);
        var gradeHTML = t.last_scan_at
            ? '<span class="fw-bold ' + gradeInfo.cls + '">' + gradeInfo.grade + '</span>'
            : '<span class="text-muted small">Run Scan</span>';

        return '<tr>' +
            '<td><strong>' + domain + '</strong></td>' +
            '<td>' + formatNumber(t.total_subdomains) + '</td>' +
            '<td>' + formatNumber(t.total_http_assets) + '</td>' +
            '<td>' + formatNumber(t.total_vulns) + '</td>' +
            '<td>' + formatNumber(t.total_emails) + '</td>' +
            '<td>' + gradeHTML + '</td>' +
            '<td>' + (t.last_scan_at
                ? formatDate(t.last_scan_at)
                : '<span class="text-muted">Never</span>') + '</td>' +
            '<td>' +
            '<a href="/targets/' + domain + '" class="btn btn-sm btn-outline-secondary">' +
            '<i class="bi bi-eye"></i></a></td>' +
            '</tr>';
    }).join('');
}

//Refresh//
async function refreshStats() {
    await loadDashboard();
}