// =============================================================================
// Asset Breakdown — Tower Graph, Filter Logic, Domain Selector
// =============================================================================

// ── Constants ────────────────────────────────────────────────────────────

const TIER_BADGES = {
    "Critical Infrastructure": { label: "Critical",        color: "#E24B4A" },
    "High Value":               { label: "High Value",      color: "#EF9F27" },
    "Customer Surface":         { label: "Customer Surface",color: "#378ADD" },
    "Exposed Development":      { label: "Exposed Dev",     color: "#FAC775" },
    "Standard":                 { label: "Standard",        color: "#888780" },
    "Legacy / Deprecated":      { label: "Legacy",          color: "#7F77DD" },
};

function renderTierBadge(tier, isLegacy) {
    const badge = TIER_BADGES[tier] || TIER_BADGES["Standard"];
    let html = `<span class="badge"
        style="background-color:${badge.color};
               color:#fff;
               font-size:0.72rem;
               padding:2px 8px;
               border-radius:4px;">
        ${badge.label}
    </span>`;

    if (isLegacy && tier !== "Legacy / Deprecated") {
        html += ` <span class="badge"
            style="background-color:#7F77DD;
                   color:#fff;
                   font-size:0.65rem;
                   padding:2px 6px;
                   border-radius:4px;
                   margin-left:4px;">
            Legacy
        </span>`;
    }
    return html;
}

// ── Global State ─────────────────────────────────────────────────────────

var allAssets = [];
var filteredAssets = [];

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
    var tableCard = document.getElementById('table-card');
    var endpointsCard = document.getElementById('endpoints-card');

    if (show) {
        if (emptyState) emptyState.style.display = '';
        if (tierCards) tierCards.style.display = 'none';
        if (filtersCard) filtersCard.style.display = 'none';
        if (tableCard) tableCard.style.display = 'none';
        if (endpointsCard) endpointsCard.style.display = 'none';
    } else {
        if (emptyState) emptyState.style.display = 'none';
        if (tierCards) tierCards.style.display = '';
        if (filtersCard) filtersCard.style.display = '';
        if (tableCard) tableCard.style.display = '';
        if (endpointsCard) endpointsCard.style.display = '';
    }
}


// ── Data Loading ─────────────────────────────────────────────────────────

async function loadAssetBreakdown() {
    try {
        showEmptyState(false);

        var data = await api.get('/api/assets/breakdown/' + DOMAIN);

        if (!data || !data.success) {
            document.getElementById('asset-table-body').innerHTML =
                '<tr><td colspan="11" class="text-center text-danger">' +
                'Failed to load asset data</td></tr>';
            return;
        }

        allAssets = data.assets || [];

        // Update tier summary cards
        var ts = data.tier_summary || {};
        const getTs = (key) => ts[key] || 0;
        
        var elCrit = document.getElementById('tier-critical');
        if (elCrit) elCrit.textContent = getTs("Critical Infrastructure");
        var elHigh = document.getElementById('tier-high');
        if (elHigh) elHigh.textContent = getTs("High Value");
        var elCust = document.getElementById('tier-customer');
        if (elCust) elCust.textContent = getTs("Customer Surface");
        var elExp = document.getElementById('tier-exposed');
        if (elExp) elExp.textContent = getTs("Exposed Development");
        var elStd = document.getElementById('tier-standard');
        if (elStd) elStd.textContent = getTs("Standard");
        var elLeg = document.getElementById('tier-legacy');
        if (elLeg) elLeg.textContent = getTs("Legacy / Deprecated");

        // Apply initial (no) filters
        applyFilters();
        
        // Also load endpoints card below
        loadEndpoints();

    } catch (err) {
        console.error('Asset breakdown load error:', err);
        document.getElementById('asset-table-body').innerHTML =
            '<tr><td colspan="11" class="text-center text-danger">' +
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

    // Re-render table
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
    ['critical', 'high', 'customer', 'exposed', 'standard', 'legacy'].forEach(function (t) {
        var card = document.getElementById('tier-card-' + t);
        if (card) card.classList.remove('active-filter');
    });

    if (tierDropdown.value !== 'all') {
        var idMap = {
            "Critical Infrastructure": "critical",
            "High Value": "high",
            "Customer Surface": "customer",
            "Exposed Development": "exposed",
            "Standard": "standard",
            "Legacy / Deprecated": "legacy"
        };
        var activeCard = document.getElementById('tier-card-' + idMap[tierDropdown.value]);
        if (activeCard) activeCard.classList.add('active-filter');
    }

    applyFilters();
}

// ── Asset Table ──────────────────────────────────────────────────────────

function renderTable(assets) {
    var tbody = document.getElementById('asset-table-body');
    var tableCount = document.getElementById('table-count');

    if (assets.length === 0) {
        tbody.innerHTML =
            '<tr><td colspan="11" class="text-center text-muted py-4">' +
            'No assets match the current filters.</td></tr>';
        tableCount.textContent = '0 assets';
        return;
    }

    tableCount.textContent = assets.length + ' assets';

    tbody.innerHTML = assets.map(function (a) {
        var tierBadge = renderTierBadge(a.tier, a.is_legacy);

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
            techStr = a.tech.map(function (t) {
                return '<span class="badge bg-secondary-subtle text-secondary border border-secondary-subtle me-1" style="font-size:0.65rem">' +
                    escapeHtml(t) + '</span>';
            }).join('');
        } else if (a.web_server) {
            techStr = '<small class="text-muted">' +
                escapeHtml(a.web_server) + '</small>';
        } else {
            techStr = '<small class="text-muted">—</small>';
        }

        var portList = (a.ports || []).sort((x, y) => x - y);
        var portStr = portList.length > 0
            ? portList.map(p => '<span class="badge bg-dark border border-secondary text-secondary me-1" style="font-size:0.65rem">' + p + '</span>').join('')
            : '<span class="text-muted small">—</span>';

        var statusCode = a.status_code || 0;
        var statusBadge = '';
        if (statusCode > 0) {
            var statusClass = statusCode < 300 ? 'bg-success'
                : statusCode < 400 ? 'bg-info'
                : statusCode < 500 ? 'bg-warning text-dark' : 'bg-danger';
            statusBadge = '<span class="badge ' + statusClass + '">' + statusCode + '</span>';
        } else {
            statusBadge = '<span class="badge bg-secondary">-</span>';
        }

        var titleStr = a.title 
            ? '<small class="text-muted">' + escapeHtml(a.title) + '</small>' 
            : '<span class="text-muted">-</span>';

        // Endpoint badge (informational, not clickable anymore as we have a card below)
        var endpointStr = a.endpoint_count > 0
            ? `<span class="badge bg-dark border border-info-subtle text-info">${a.endpoint_count}</span>`
            : '<span class="text-muted">0</span>';

        let htmlRow = '<tr>' +
            '<td>' + tierBadge + '</td>' +
            '<td><code>' + escapeHtml(a.host) + '</code></td>' +
            '<td>' + statusBadge + '</td>' +
            '<td>' + titleStr + '</td>' +
            '<td class="text-center">' + critBadge + '</td>' +
            '<td class="text-center">' + highBadge + '</td>' +
            '<td class="text-center">' + medBadge + '</td>' +
            '<td class="text-center">' + lowBadge + '</td>' +
            '<td class="text-center">' + totalCell + '</td>' +
            '<td class="text-center">' + portStr + '</td>' +
            '<td>' + techStr + '</td>' +
            '</tr>';
            
        if (a.tier === "Exposed Development") {
            htmlRow += `<tr>
                <td colspan="11" style="
                    padding: 4px 12px 8px 12px;
                    font-size: 0.78rem;
                    color: #FAC775;
                    border-bottom: 1px solid rgba(250,199,117,0.2);">
                    ⚠ Publicly reachable development environment
                    — verify this exposure is intentional.
                </td>
            </tr>`;
        }
        return htmlRow;
    }).join('');
}


// ── Discovered Endpoints (Arjun) ──────────────────────────────────────────

async function loadEndpoints() {
    var listEl = document.getElementById('endpoints-list');
    var countEl = document.getElementById('endpoint-count');
    if (!listEl) return;

    try {
        var data = await api.get('/api/assets/endpoints/' + DOMAIN);
        var endpoints = data.endpoints || [];

        countEl.textContent = endpoints.length;

        if (endpoints.length === 0) {
            listEl.innerHTML = '<div class="text-center py-4"><p class="text-muted">No hidden endpoints discovered yet. Run a scan with Parameter Discovery enabled.</p></div>';
            return;
        }

        let html = `
            <table class="table table-hover table-sm mb-0">
                <thead class="table-dark">
                    <tr>
                        <th style="width: 100px;">Method</th>
                        <th>URL</th>
                        <th>Discovered Parameters</th>
                        <th style="width: 120px;">Source</th>
                    </tr>
                </thead>
                <tbody>
        `;

        html += endpoints.map(e => {
            const params = (e.parameters || []).map(p => 
                `<span class="badge bg-secondary-subtle text-light border border-secondary me-1 mb-1" style="font-size:0.7rem">${escapeHtml(p)}</span>`
            ).join('');
            
            const sourceColor = e.source === 'arjun_smart' ? 'bg-info' : 'bg-secondary';

            return `
                <tr>
                    <td><span class="badge bg-primary">${escapeHtml(e.method || 'GET')}</span></td>
                    <td><small><code>${escapeHtml(e.url)}</code></small></td>
                    <td style="white-space:normal;">${params || '<span class="text-muted small">None</span>'}</td>
                    <td><span class="badge ${sourceColor} text-dark" style="font-size:0.65rem">${escapeHtml(e.source || 'arjun')}</span></td>
                </tr>
            `;
        }).join('');

        html += '</tbody></table>';
        listEl.innerHTML = html;

    } catch (err) {
        console.error('Endpoints load error:', err);
        listEl.innerHTML = '<p class="text-danger text-center py-3">Error loading discovered endpoints.</p>';
    }
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