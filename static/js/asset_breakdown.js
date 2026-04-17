// =============================================================================
// Asset Breakdown — Tower Graph, Filter Logic, Domain Selector
// =============================================================================

// ── Constants ────────────────────────────────────────────────────────────

var MAX_CHART_BARS = 20;

var SEVERITY_COLORS = {
    critical: '#ff3333',
    high: '#ff6600',
    medium: '#ffcc00',
    low: '#888888'
};

var TIER_BADGES = {
    critical: '<span class="badge bg-black text-danger border border-danger border-opacity-25 fw-800">CRITICAL</span>',
    high: '<span class="badge bg-black text-warning border border-warning border-opacity-25 fw-800">HIGH VALUE</span>',
    standard: '<span class="badge bg-black text-secondary border border-secondary border-opacity-25 fw-800">STANDARD</span>',
    low: '<span class="badge bg-black text-muted border border-secondary border-opacity-10 fw-800">DEV / TEST</span>'
};

// ── Global State ─────────────────────────────────────────────────────────

var allAssets = [];
var filteredAssets = [];
var towerChart = null;

// ── Initialization ───────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {
    // If domain is pre-set (from target detail page), load directly
    if (DOMAIN) {
        loadAssetBreakdown();
    } else {
        // Load domain list for the selector (sidebar /assets route)
        loadDomainSelector();
    }

    // Attach filter listeners
    var tierEl = document.getElementById('filter-tier');
    var sevEl = document.getElementById('filter-severity');
    var searchEl = document.getElementById('filter-search');

    if (tierEl) tierEl.addEventListener('change', applyFilters);
    if (sevEl) sevEl.addEventListener('change', applyFilters);
    if (searchEl) searchEl.addEventListener('input', applyFilters);
});


// ── Domain Selector ──────────────────────────────────────────────────────

async function loadDomainSelector() {
    try {
        var data = await api.get('/api/targets/');
        var select = document.getElementById('domain-selector');

        if (!select) return;

        var targets = data.targets || [];

        if (targets.length === 0) {
            select.innerHTML = '<option value="">No targets found. Add one first.</option>';
            return;
        }

        targets.forEach(function (t) {
            var opt = document.createElement('option');
            opt.value = t.root_domain || t.domain || '';
            opt.textContent = t.root_domain || t.domain || 'Unknown';
            select.appendChild(opt);
        });

    } catch (err) {
        console.error('Domain selector load error:', err);
    }
}
function onDomainSelected() {
    var select = document.getElementById('domain-selector');
    var selectedDomain = select.value;

    if (!selectedDomain) {
        // Reset to empty state
        showEmptyState(true);
        return;
    }

    DOMAIN = selectedDomain;
    showEmptyState(false);
    loadAssetBreakdown();
}

function showEmptyState(show) {
    var emptyState = document.getElementById('empty-state');
    var tierCards = document.getElementById('tier-cards');
    var filtersCard = document.getElementById('filters-card');
    var chartCard = document.getElementById('chart-card');
    var tableCard = document.getElementById('table-card');

    if (show) {
        if (emptyState) emptyState.style.display = '';
        if (tierCards) tierCards.style.display = 'none';
        if (filtersCard) filtersCard.style.display = 'none';
        if (chartCard) chartCard.style.display = 'none';
        if (tableCard) tableCard.style.display = 'none';
    } else {
        if (emptyState) emptyState.style.display = 'none';
        if (tierCards) tierCards.style.display = '';
        if (filtersCard) filtersCard.style.display = '';
        if (chartCard) chartCard.style.display = '';
        if (tableCard) tableCard.style.display = '';
    }
}


// ── Data Loading ─────────────────────────────────────────────────────────

async function loadAssetBreakdown() {
    try {
        showEmptyState(false);

        var data = await api.get('/api/assets/breakdown/' + DOMAIN);

        if (!data || !data.success) {
            document.getElementById('asset-table-body').innerHTML =
                '<tr><td colspan="9" class="text-center text-danger">' +
                'Failed to load asset data</td></tr>';
            return;
        }

        allAssets = data.assets || [];

        // Update tier summary cards
        var ts = data.tier_summary || {};
        document.getElementById('tier-critical').textContent = ts.critical || 0;
        document.getElementById('tier-high').textContent = ts.high || 0;
        document.getElementById('tier-standard').textContent = ts.standard || 0;
        document.getElementById('tier-low').textContent = ts.low || 0;

        // Apply initial (no) filters
        applyFilters();

    } catch (err) {
        console.error('Asset breakdown load error:', err);
        document.getElementById('asset-table-body').innerHTML =
            '<tr><td colspan="9" class="text-center text-danger">' +
            'Error loading data</td></tr>';
    }
}


// ── Filter Logic ─────────────────────────────────────────────────────────

function applyFilters() {
    var tier = document.getElementById('filter-tier').value;
    var severity = document.getElementById('filter-severity').value;
    var search = document.getElementById('filter-search')
        .value.toLowerCase().trim();

    filteredAssets = allAssets.filter(function (asset) {
        // Tier filter
        if (tier !== 'all' && asset.tier !== tier) {
            return false;
        }

        // Severity filter
        if (severity === 'has_critical' && asset.vuln_counts.critical === 0) {
            return false;
        }
        if (severity === 'has_high' && asset.vuln_counts.high === 0) {
            return false;
        }
        if (severity === 'has_medium' && asset.vuln_counts.medium === 0) {
            return false;
        }
        if (severity === 'has_vulns' && asset.total_vulns === 0) {
            return false;
        }
        if (severity === 'clean' && asset.total_vulns > 0) {
            return false;
        }

        // Search filter
        if (search && asset.host.toLowerCase().indexOf(search) === -1) {
            return false;
        }

        return true;
    });

    // Update counter
    document.getElementById('showing-count').textContent =
        DOMAIN + ' — ' + filteredAssets.length + ' of ' + allAssets.length + ' assets';

    // Re-render chart and table
    renderChart(filteredAssets);
    renderTable(filteredAssets);
}

function clearFilters() {
    document.getElementById('filter-tier').value = 'all';
    document.getElementById('filter-severity').value = 'all';
    document.getElementById('filter-search').value = '';
    applyFilters();
}

function filterByTier(tier) {
    var tierDropdown = document.getElementById('filter-tier');

    // If clicking the already-active tier, reset to all
    if (tierDropdown.value === tier) {
        tierDropdown.value = 'all';
    } else {
        tierDropdown.value = tier;
    }

    // Update tier card visual state
    ['critical', 'high', 'standard', 'low'].forEach(function (t) {
        var card = document.getElementById('tier-card-' + t);
        if (card) card.classList.remove('active-filter');
    });

    if (tierDropdown.value !== 'all') {
        var activeCard = document.getElementById('tier-card-' + tierDropdown.value);
        if (activeCard) activeCard.classList.add('active-filter');
    }

    applyFilters();
}
// ── Tower Chart ──────────────────────────────────────────────────────────

function renderChart(assets) {
    var canvas = document.getElementById('tower-chart');
    if (!canvas) return;
    var ctx = canvas.getContext('2d');

    // Destroy old chart if exists
    if (towerChart) {
        towerChart.destroy();
        towerChart = null;
    }

    // Nothing to show
    if (assets.length === 0) {
        document.getElementById('chart-note').textContent =
            'No assets match the current filters.';
        return;
    }

    // Only show assets with vulns in chart (cleaner)
    var assetsWithVulns = assets.filter(function (a) {
        return a.total_vulns > 0;
    });

    if (assetsWithVulns.length === 0) {
        document.getElementById('chart-note').textContent =
            'No vulnerabilities found on any asset. All clean!';
        return;
    }

    // Limit bars for readability
    var chartAssets = assetsWithVulns.slice(0, MAX_CHART_BARS);
    var chartNote = '';
    if (assetsWithVulns.length > MAX_CHART_BARS) {
        chartNote = 'Showing top ' + MAX_CHART_BARS +
            ' of ' + assetsWithVulns.length +
            ' assets with vulnerabilities. See table for all.';
    }
    document.getElementById('chart-note').textContent = chartNote;

    // Build labels (truncate long hostnames)
    var labels = chartAssets.map(function (a) {
        return truncateLabel(a.host, 25);
    });

    // Full hostnames for tooltips
    var fullHostnames = chartAssets.map(function (a) {
        return a.host;
    });

    towerChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Critical',
                    data: chartAssets.map(function (a) { return a.vuln_counts.critical; }),
                    backgroundColor: SEVERITY_COLORS.critical
                },
                {
                    label: 'High',
                    data: chartAssets.map(function (a) { return a.vuln_counts.high; }),
                    backgroundColor: SEVERITY_COLORS.high
                },
                {
                    label: 'Medium',
                    data: chartAssets.map(function (a) { return a.vuln_counts.medium; }),
                    backgroundColor: SEVERITY_COLORS.medium
                },
                {
                    label: 'Low',
                    data: chartAssets.map(function (a) { return a.vuln_counts.low; }),
                    backgroundColor: SEVERITY_COLORS.low
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'index',
                intersect: false
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        usePointStyle: true,
                        padding: 20
                    }
                },
                tooltip: {
                    callbacks: {
                        title: function (items) {
                            var idx = items[0].dataIndex;
                            return fullHostnames[idx];
                        },
                        afterBody: function (items) {
                            var idx = items[0].dataIndex;
                            var asset = chartAssets[idx];
                            return [
                                '',
                                'Tier: ' + asset.tier.toUpperCase(),
                                'Ports: ' + asset.port_count,
                                'Total vulns: ' + asset.total_vulns
                            ];
                        }
                    }
                }
            },
            scales: {
                x: {
                    stacked: true,
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45,
                        font: { size: 11 }
                    },
                    grid: { display: false }
                },
                y: {
                    stacked: true,
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Vulnerability Count',
                        font: { size: 13 }
                    },
                    ticks: {
                        stepSize: 1,
                        precision: 0
                    }
                }
            }
        }
    });
}


// ── Asset Table ──────────────────────────────────────────────────────────

function renderTable(assets) {
    var tbody = document.getElementById('asset-table-body');
    var tableCount = document.getElementById('table-count');

    if (assets.length === 0) {
        tbody.innerHTML =
            '<tr><td colspan="9" class="text-center text-muted py-4">' +
            'No assets match the current filters.</td></tr>';
        tableCount.textContent = '0 assets';
        return;
    }

    tableCount.textContent = assets.length + ' assets';

    tbody.innerHTML = assets.map(function (a) {
        var tierBadge = TIER_BADGES[a.tier] || TIER_BADGES.standard;

        var critBadge = vulnBadge(a.vuln_counts.critical, 'critical');
        var highBadge = vulnBadge(a.vuln_counts.high, 'high');
        var medBadge = vulnBadge(a.vuln_counts.medium, 'medium');
        var lowBadge = vulnBadge(a.vuln_counts.low, 'low');

        var totalCell = a.total_vulns > 0
            ? '<strong>' + a.total_vulns + '</strong>'
            : '<span class="text-muted">0</span>';

        // Technology list
        var techStr = '';
        if (a.tech && a.tech.length > 0) {
            techStr = a.tech.slice(0, 3).map(function (t) {
                return '<span class="badge bg-secondary-subtle text-secondary border border-secondary-subtle me-1" style="font-size:0.65rem">' +
                    escapeHtml(t) + '</span>';
            }).join('');
            if (a.tech.length > 3) {
                techStr += ' <span class="text-muted">+' +
                    (a.tech.length - 3) + '</span>';
            }
        } else if (a.web_server) {
            techStr = '<small class="text-muted">' +
                escapeHtml(a.web_server) + '</small>';
        } else {
            techStr = '<small class="text-muted">—</small>';
        }

        var portStr = a.port_count > 0
            ? a.port_count.toString()
            : '<span class="text-muted">0</span>';

        return '<tr>' +
            '<td>' + tierBadge + '</td>' +
            '<td><code>' + escapeHtml(a.host) + '</code>' +
            (a.title ? '<br><small class="text-muted">' +
                escapeHtml(a.title) + '</small>' : '') +
            '</td>' +
            '<td class="text-center">' + critBadge + '</td>' +
            '<td class="text-center">' + highBadge + '</td>' +
            '<td class="text-center">' + medBadge + '</td>' +
            '<td class="text-center">' + lowBadge + '</td>' +
            '<td class="text-center">' + totalCell + '</td>' +
            '<td class="text-center">' + portStr + '</td>' +
            '<td>' + techStr + '</td>' +
            '</tr>';
    }).join('');
}


// ── Helpers ──────────────────────────────────────────────────────────────

function vulnBadge(count, severity) {
    if (count === 0) {
        return '<span class="text-muted small fw-800">0</span>';
    }
    var cls = {
        critical: 'text-danger border-danger border-opacity-25',
        high: 'text-warning border-warning border-opacity-25',
        medium: 'text-warning text-opacity-75 border-warning border-opacity-10',
        low: 'text-secondary border-secondary border-opacity-25'
    }[severity] || 'text-secondary';
    
    return '<span class="badge bg-black fw-800 border ' + cls + '">' + count + '</span>';
}

function truncateLabel(text, maxLen) {
    if (!text) return '';
    if (text.length <= maxLen) return text;
    return text.substring(0, maxLen) + '…';
}

function escapeHtml(text) {
    if (!text) return '';
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(text));
    return div.innerHTML;
}