// Global state
let config = {
    mode: 'ip-to-ip',
    filter: '',
    topN: 50,
    ipVersion: 'all',
    timeRange: '15m',
    leftIF: 0,
    rightIF: 0,
    leftExporter: '',
    rightExporter: ''
};

let autoRefreshInterval = null;
let lastData = null;
let interfacesData = null;
let exportersData = null;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', async () => {
    // Load initial config from server
    try {
        const response = await fetch('/config');
        const serverConfig = await response.json();
        config.mode = serverConfig.mode || 'ip-to-ip';
        config.filter = serverConfig.filter || '';
        config.topN = serverConfig.topN || 50;
    } catch (e) {
        console.warn('Failed to load config, using defaults');
    }

    // Update UI with config
    document.getElementById('mode-select').value = config.mode;
    document.getElementById('filter-input').value = config.filter;
    document.getElementById('topn-slider').value = config.topN;
    document.getElementById('topn-value').textContent = config.topN;

    // Setup event listeners
    setupEventListeners();

    // Load interfaces for firewall mode
    await loadInterfaces();

    // Update interface selects visibility
    updateInterfaceSelectsVisibility();

    // Initial load
    await refreshData();
});

function setupEventListeners() {
    // Mode select
    document.getElementById('mode-select').addEventListener('change', (e) => {
        config.mode = e.target.value;
        updateInterfaceSelectsVisibility();
        refreshData();
    });

    // Left exporter select
    document.getElementById('left-exporter-select').addEventListener('change', (e) => {
        config.leftExporter = e.target.value;
        updateInterfaceOptionsForExporter('left');
        refreshData();
    });

    // Left interface select
    document.getElementById('left-if-select').addEventListener('change', (e) => {
        config.leftIF = parseInt(e.target.value);
        refreshData();
    });

    // Right exporter select
    document.getElementById('right-exporter-select').addEventListener('change', (e) => {
        config.rightExporter = e.target.value;
        updateInterfaceOptionsForExporter('right');
        refreshData();
    });

    // Right interface select
    document.getElementById('right-if-select').addEventListener('change', (e) => {
        config.rightIF = parseInt(e.target.value);
        refreshData();
    });

    // IP version select
    document.getElementById('ipversion-select').addEventListener('change', (e) => {
        config.ipVersion = e.target.value;
        refreshData();
    });

    // Time range select
    document.getElementById('timerange-select').addEventListener('change', (e) => {
        config.timeRange = e.target.value;
        refreshData();
    });

    // Filter input
    document.getElementById('filter-input').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            config.filter = e.target.value;
            refreshData();
        }
    });

    document.getElementById('apply-filter').addEventListener('click', () => {
        config.filter = document.getElementById('filter-input').value;
        refreshData();
    });

    document.getElementById('clear-filter').addEventListener('click', () => {
        config.filter = '';
        document.getElementById('filter-input').value = '';
        refreshData();
    });

    // Top N slider
    document.getElementById('topn-slider').addEventListener('input', (e) => {
        config.topN = parseInt(e.target.value);
        document.getElementById('topn-value').textContent = config.topN;
    });

    document.getElementById('topn-slider').addEventListener('change', () => {
        refreshData();
    });

    // Auto-refresh toggle
    document.getElementById('auto-refresh').addEventListener('change', (e) => {
        if (e.target.checked) {
            autoRefreshInterval = setInterval(refreshData, 10000);
        } else {
            clearInterval(autoRefreshInterval);
            autoRefreshInterval = null;
        }
    });

    // Refresh button
    document.getElementById('refresh-btn').addEventListener('click', refreshData);

    // Window resize
    window.addEventListener('resize', () => {
        if (lastData) {
            renderSankey(lastData);
        }
    });
}

async function refreshData() {
    const statusEl = document.getElementById('connection-status');

    try {
        // Build API URL
        let url = `/api/v1/sankey?mode=${config.mode}&topN=${config.topN}`;
        if (config.filter) {
            url += `&filter=${encodeURIComponent(config.filter)}`;
        }
        if (config.ipVersion && config.ipVersion !== 'all') {
            url += `&ipVersion=${config.ipVersion}`;
        }
        if (config.timeRange && config.timeRange !== 'all') {
            url += `&timeRange=${config.timeRange}`;
        }
        if (config.mode === 'firewall') {
            if (config.leftIF > 0) {
                url += `&leftIF=${config.leftIF}`;
            }
            if (config.rightIF > 0) {
                url += `&rightIF=${config.rightIF}`;
            }
            if (config.leftExporter) {
                url += `&leftExporter=${encodeURIComponent(config.leftExporter)}`;
            }
            if (config.rightExporter) {
                url += `&rightExporter=${encodeURIComponent(config.rightExporter)}`;
            }
        }

        const response = await fetch(url);

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.details || error.error || 'API error');
        }

        const data = await response.json();
        lastData = data;

        // Update status
        statusEl.textContent = 'Connected';
        statusEl.className = 'status-ok';

        // Update stats
        await updateStats();

        // Render Sankey
        renderSankey(data);

        // Update timestamp
        document.getElementById('stats-updated').textContent =
            `Updated: ${new Date().toLocaleTimeString()}`;

    } catch (error) {
        console.error('Failed to fetch data:', error);
        statusEl.textContent = `Error: ${error.message}`;
        statusEl.className = 'status-error';
    }
}

async function updateStats() {
    try {
        const response = await fetch('/api/v1/stats');
        if (response.ok) {
            const stats = await response.json();
            document.getElementById('stats-flows').textContent =
                `Flows: ${formatNumber(stats.currentFlows)}`;
            document.getElementById('stats-bytes').textContent =
                `Bytes: ${formatBytes(stats.totalBytes)}`;
            document.getElementById('stats-packets').textContent =
                `Packets: ${formatNumber(stats.totalPackets)}`;
        }
    } catch (e) {
        console.warn('Failed to fetch stats');
    }
}

function renderSankey(data) {
    const container = document.getElementById('sankey-container');
    const svg = d3.select('#sankey-svg');

    // Clear previous content
    svg.selectAll('*').remove();

    // Handle empty data
    if (!data.nodes || data.nodes.length === 0 || !data.links || data.links.length === 0) {
        svg.append('text')
            .attr('x', container.clientWidth / 2)
            .attr('y', container.clientHeight / 2)
            .attr('text-anchor', 'middle')
            .attr('fill', '#888')
            .text('No flow data available');
        return;
    }

    // Set dimensions
    const margin = { top: 20, right: 150, bottom: 20, left: 150 };
    const width = container.clientWidth - margin.left - margin.right;
    const height = Math.max(container.clientHeight - margin.top - margin.bottom, 400);

    svg.attr('width', width + margin.left + margin.right)
       .attr('height', height + margin.top + margin.bottom);

    const g = svg.append('g')
        .attr('transform', `translate(${margin.left},${margin.top})`);

    // Build node set from links to ensure all referenced nodes exist
    const nodeSet = new Set();
    data.links.forEach(l => {
        nodeSet.add(l.source);
        nodeSet.add(l.target);
    });

    // Filter nodes to only include those referenced in links
    const filteredNodes = data.nodes.filter(n => nodeSet.has(n.id));

    // If we have links but missing nodes, add them
    nodeSet.forEach(id => {
        if (!filteredNodes.find(n => n.id === id)) {
            filteredNodes.push({
                id: id,
                type: 'unknown',
                label: id
            });
        }
    });

    // Prepare sankey data - use string IDs directly
    const sankeyData = {
        nodes: filteredNodes.map(n => ({ ...n })),
        links: data.links.map(l => ({
            source: l.source,  // Use string ID directly
            target: l.target,  // Use string ID directly
            value: l.value,
            packets: l.packets,
            protocol: l.protocol,
            flows: l.flows,
            sourceName: l.source,
            targetName: l.target
        }))
    };

    // Create sankey layout
    const sankey = d3.sankey()
        .nodeWidth(20)
        .nodePadding(15)
        .extent([[0, 0], [width, height]])
        .nodeId(d => d.id)
        .nodeAlign(d3.sankeyLeft)
        .nodeSort((a, b) => {
            // Sortiere nach sortKey (Interface-ID) um IPs nach Interface zu gruppieren
            if (a.sortKey !== b.sortKey) {
                return a.sortKey - b.sortKey;
            }
            // Bei gleichem sortKey nach Label sortieren
            return (a.label || a.id).localeCompare(b.label || b.id);
        });

    let layoutResult;
    try {
        layoutResult = sankey({
            nodes: sankeyData.nodes.map(d => Object.assign({}, d)),
            links: sankeyData.links.map(d => Object.assign({}, d))
        });
    } catch (e) {
        console.error('Sankey layout error:', e);
        svg.append('text')
            .attr('x', container.clientWidth / 2)
            .attr('y', container.clientHeight / 2)
            .attr('text-anchor', 'middle')
            .attr('fill', '#f44336')
            .text('Layout error: ' + e.message);
        return;
    }

    const { nodes, links } = layoutResult;

    // Color scale - includes firewall mode types
    const colorScale = d3.scaleOrdinal()
        .domain(['source', 'target', 'service', 'internal', 'firewall', 'wan', 'external', 'left', 'right', 'left-if', 'right-if'])
        .range(['#4CAF50', '#2196F3', '#FF9800', '#4CAF50', '#9C27B0', '#E91E63', '#2196F3', '#4CAF50', '#2196F3', '#9C27B0', '#E91E63']);

    // Define gradient for links
    const defs = svg.append('defs');

    links.forEach((link, i) => {
        const gradient = defs.append('linearGradient')
            .attr('id', `gradient-${i}`)
            .attr('gradientUnits', 'userSpaceOnUse')
            .attr('x1', link.source.x1)
            .attr('x2', link.target.x0);

        gradient.append('stop')
            .attr('offset', '0%')
            .attr('stop-color', colorScale(link.source.type || 'source'))
            .attr('stop-opacity', 0.6);

        gradient.append('stop')
            .attr('offset', '100%')
            .attr('stop-color', colorScale(link.target.type || 'target'))
            .attr('stop-opacity', 0.6);
    });

    // Draw links
    const link = g.append('g')
        .attr('fill', 'none')
        .selectAll('path')
        .data(links)
        .join('path')
        .attr('d', d3.sankeyLinkHorizontal())
        .attr('stroke', (d, i) => `url(#gradient-${i})`)
        .attr('stroke-width', d => Math.max(1, d.width))
        .attr('stroke-dasharray', d => d.inferred ? '8,4' : 'none')
        .attr('class', d => d.inferred ? 'sankey-link inferred' : 'sankey-link')
        .on('mouseover', showLinkTooltip)
        .on('mouseout', hideTooltip);

    // Draw nodes
    const node = g.append('g')
        .selectAll('g')
        .data(nodes)
        .join('g')
        .attr('class', 'sankey-node');

    node.append('rect')
        .attr('x', d => d.x0)
        .attr('y', d => d.y0)
        .attr('height', d => Math.max(1, d.y1 - d.y0))
        .attr('width', d => d.x1 - d.x0)
        .attr('fill', d => colorScale(d.type || 'source'))
        .attr('opacity', 0.9)
        .on('mouseover', showNodeTooltip)
        .on('mouseout', hideTooltip);

    // Add node labels
    node.append('text')
        .attr('x', d => d.x0 < width / 2 ? d.x0 - 6 : d.x1 + 6)
        .attr('y', d => (d.y1 + d.y0) / 2)
        .attr('dy', '0.35em')
        .attr('text-anchor', d => d.x0 < width / 2 ? 'end' : 'start')
        .attr('class', 'node-label')
        .text(d => truncateLabel(d.label || d.id, 25));
}

function showLinkTooltip(event, d) {
    const tooltip = document.getElementById('tooltip');
    const inferredNote = d.inferred ? '<div class="tooltip-row inferred-note"><span>⚠️ Inferiert</span> Keine echten Daten von diesem Exporter</div>' : '';
    tooltip.innerHTML = `
        <div class="tooltip-title">${d.sourceName} &rarr; ${d.targetName}</div>
        <div class="tooltip-row"><span>Bytes:</span> ${formatBytes(d.value)}</div>
        <div class="tooltip-row"><span>Packets:</span> ${formatNumber(d.packets)}</div>
        <div class="tooltip-row"><span>Protocol:</span> ${d.protocol}</div>
        <div class="tooltip-row"><span>Flows:</span> ${formatNumber(d.flows)}</div>
        ${inferredNote}
    `;
    positionTooltip(event);
}

function showNodeTooltip(event, d) {
    const tooltip = document.getElementById('tooltip');
    const totalValue = d.sourceLinks.reduce((sum, l) => sum + l.value, 0) +
                       d.targetLinks.reduce((sum, l) => sum + l.value, 0);

    tooltip.innerHTML = `
        <div class="tooltip-title">${d.label || d.id}</div>
        <div class="tooltip-row"><span>Type:</span> ${d.type}</div>
        <div class="tooltip-row"><span>Total Bytes:</span> ${formatBytes(totalValue)}</div>
        <div class="tooltip-row"><span>Connections:</span> ${d.sourceLinks.length + d.targetLinks.length}</div>
    `;
    positionTooltip(event);
}

function positionTooltip(event) {
    const tooltip = document.getElementById('tooltip');
    tooltip.style.display = 'block';
    tooltip.style.left = (event.pageX + 15) + 'px';
    tooltip.style.top = (event.pageY - 10) + 'px';
}

function hideTooltip() {
    document.getElementById('tooltip').style.display = 'none';
}

// Utility functions
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatNumber(num) {
    if (num === undefined || num === null) return '-';
    return num.toLocaleString();
}

function truncateLabel(label, maxLength) {
    if (label.length <= maxLength) return label;
    return label.substring(0, maxLength - 3) + '...';
}

// Load interfaces from API
async function loadInterfaces() {
    try {
        const response = await fetch('/api/v1/interfaces');
        if (response.ok) {
            interfacesData = await response.json();
            exportersData = interfacesData.exporters || [];
            populateExporterSelects();
            populateInterfaceSelects();
        }
    } catch (e) {
        console.warn('Failed to load interfaces:', e);
    }
}

// Populate exporter dropdowns
function populateExporterSelects() {
    if (!exportersData || exportersData.length === 0) return;

    const leftExpSelect = document.getElementById('left-exporter-select');
    const rightExpSelect = document.getElementById('right-exporter-select');

    leftExpSelect.innerHTML = '<option value="">All Exporters</option>';
    rightExpSelect.innerHTML = '<option value="">All Exporters</option>';

    for (const exp of exportersData) {
        const label = exp.name !== exp.ip ? `${exp.name} (${exp.ip})` : exp.ip;
        leftExpSelect.innerHTML += `<option value="${exp.ip}">${label}</option>`;
        rightExpSelect.innerHTML += `<option value="${exp.ip}">${label}</option>`;
    }
}

// Update interface options based on selected exporter
function updateInterfaceOptionsForExporter(side) {
    const expSelect = document.getElementById(`${side}-exporter-select`);
    const ifSelect = document.getElementById(`${side}-if-select`);
    const selectedExporter = expSelect.value;

    // Clear and reset
    if (side === 'left') {
        ifSelect.innerHTML = '<option value="0">All IFs</option>';
    } else {
        ifSelect.innerHTML = '<option value="0">Auto (WAN)</option>';
    }

    if (!exportersData) return;

    // If a specific exporter is selected, only show its interfaces
    if (selectedExporter) {
        const exporter = exportersData.find(e => e.ip === selectedExporter);
        if (exporter && exporter.interfaces) {
            for (const iface of exporter.interfaces) {
                const label = formatInterfaceLabel(iface);
                ifSelect.innerHTML += `<option value="${iface.id}">${label}</option>`;
            }
            // Set default to WAN for right side
            if (side === 'right' && exporter.wanId > 0) {
                ifSelect.value = exporter.wanId;
                config.rightIF = exporter.wanId;
            }
        }
    } else {
        // Show all interfaces grouped by exporter
        for (const exp of exportersData) {
            const shortName = exp.name !== exp.ip ? exp.name : exp.ip.split('.').slice(-2).join('.');
            for (const iface of exp.interfaces) {
                const label = `[${shortName}] ` + formatInterfaceLabel(iface);
                ifSelect.innerHTML += `<option value="${iface.id}" data-exporter="${exp.ip}">${label}</option>`;
            }
        }
    }
}

// Format interface label
function formatInterfaceLabel(iface) {
    let label = `IF:${iface.id}`;
    if (iface.topSubnet) {
        label += ` - ${iface.topSubnet}`;
        if (iface.topSubnetIps > 1) {
            label += ` (${iface.topSubnetIps} IPs)`;
        }
    } else if (iface.publicIps > 0) {
        label += ` (${iface.publicIps} public IPs)`;
    }
    if (iface.isWan) {
        label += ' [WAN]';
    }
    return label;
}

// Populate interface dropdowns (legacy, now uses exporter-aware version)
function populateInterfaceSelects() {
    if (!interfacesData) return;

    // Use new exporter-aware population
    updateInterfaceOptionsForExporter('left');
    updateInterfaceOptionsForExporter('right');

    // Set default right to global WAN if no exporter selected
    if (!config.rightExporter && interfacesData.wanId > 0) {
        const rightSelect = document.getElementById('right-if-select');
        rightSelect.value = interfacesData.wanId;
        config.rightIF = interfacesData.wanId;
    }
}

// Show/hide interface selects based on mode
function updateInterfaceSelectsVisibility() {
    const container = document.getElementById('interface-selects');
    if (config.mode === 'firewall') {
        container.style.display = 'flex';
        // Reload interfaces when switching to firewall mode
        loadInterfaces();
    } else {
        container.style.display = 'none';
    }
}
