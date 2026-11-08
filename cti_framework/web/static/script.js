// =====================================================================
// CTI SOC Operations Dashboard - Frontend Core Controller
// =====================================================================

let currentView = 'overview';
let activeRunId = null;
let timelineChart = null;
let distributionChart = null;
let currentInspectedRule = null;
let currentInspectedReport = null;
let eventSource = null;

// Initialize on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
    initClock();
    setupSSE();
    loadOverview();
    
    // Auto-refresh overview KPIs every 15s
    setInterval(() => {
        if (currentView === 'overview') {
            loadOverview(true);
        }
    }, 15000);
});


// --- Toast Notification System ---
function showToast(message, isError = false) {
    let container = document.getElementById('soc-toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'soc-toast-container';
        container.style.cssText = 'position:fixed;bottom:24px;right:24px;z-index:99999;display:flex;flex-direction:column;gap:10px;max-width:420px;pointer-events:none;';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.style.cssText = `padding:12px 18px;border-radius:6px;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;font-size:13px;line-height:1.4;color:#fff;background:${isError ? 'rgba(239,68,68,0.95)' : 'rgba(15,23,42,0.95)'};border:1px solid ${isError ? '#ef4444' : 'rgba(56,189,248,0.4)'};box-shadow:0 10px 25px rgba(0,0,0,0.5);pointer-events:auto;opacity:0;transform:translateY(10px);transition:all 0.25s cubic-bezier(0.16,1,0.3,1);`;
    toast.textContent = message;
    container.appendChild(toast);

    requestAnimationFrame(() => {
        toast.style.opacity = '1';
        toast.style.transform = 'translateY(0)';
    });

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(10px)';
        setTimeout(() => {
            if (toast.parentElement) toast.parentElement.removeChild(toast);
        }, 300);
    }, 4000);
}

// --- Clock ---
function initClock() {
    const clockEl = document.getElementById('soc-clock');
    function update() {
        const now = new Date();
        const utcStr = now.toISOString().slice(11, 19) + ' UTC';
        clockEl.textContent = utcStr;
    }
    update();
    setInterval(update, 1000);
}

// --- Navigation & View Switching ---
function switchView(viewName) {
    currentView = viewName;

    // Update Sidebar Navigation
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    const activeNav = document.getElementById(`nav-${viewName}`);
    if (activeNav) activeNav.classList.add('active');

    // Update Page Header Title
    const headings = {
            'overview': 'SOC Command Center',
            'monitor': 'Live Agent Monitor',
            'cti': 'CTI Explorer',
            'iocs': 'IOC Management',
            'mitre': 'MITRE ATT&CK',
            'skills': 'Agent Skills & Hunter',
            'rules': 'Defensive Rules',
            'tools': 'Tool Registry',
            'health': 'System Health'
        };
    document.getElementById('page-heading').textContent = headings[viewName] || 'SOC Dashboard';

    // Toggle Section
    document.querySelectorAll('.view-section').forEach(sec => sec.classList.remove('active'));
    const targetSec = document.getElementById(`view-${viewName}`);
    if (targetSec) targetSec.classList.add('active');

    // Load data for specific view
    switch (viewName) {
        case 'overview': loadOverview(); break;
        case 'monitor': loadAgentRuns(); break;
        case 'cti': loadCTIReports(); break;
        case 'iocs': loadIOCs(); break;
        case 'mitre': loadMitreMappings(); break;
        case 'skills': loadSkills(); break;
        case 'rules': loadDefenseRules(); break;
        case 'tools': loadTools(); break;
        case 'health': loadHealth(); break;
    }
}

// --- Real-Time Server-Sent Events (SSE) Telemetry ---
function setupSSE() {
    const dot = document.getElementById('dot-sse');
    const text = document.getElementById('text-sse');

    if (eventSource) {
        eventSource.close();
    }

    eventSource = new EventSource('/api/agent/events/stream');

    eventSource.onopen = () => {
        dot.className = 'status-dot pulse';
        dot.style.background = 'var(--ok)';
        text.textContent = 'SSE Telemetry: Live';
    };

    eventSource.addEventListener('agent_event', (e) => {
        try {
            const ev = JSON.parse(e.data);
            handleIncomingAgentEvent(ev);
        } catch (err) {
            console.error('Lỗi phân tích event SSE:', err);
        }
    });

    eventSource.onerror = () => {
        dot.className = 'status-dot';
        dot.style.background = 'var(--high)';
        text.textContent = 'SSE: Reconnecting...';
    };
}

function handleIncomingAgentEvent(ev) {
    // 1. If currently inspecting this run on Monitor view, append node live!
    if (currentView === 'monitor' && activeRunId === ev.run_id) {
        appendTimelineNode(ev);
        // If run finished, refresh run details
        if (ev.event_type === 'run_completed' || ev.event_type === 'run_failed') {
            setTimeout(() => inspectRun(activeRunId), 1000);
            loadAgentRuns();
        }
    }

    // 2. Prepend to Overview Event feed if on Overview view
    const overviewTbody = document.getElementById('overview-events-tbody');
    if (overviewTbody) {
        const tr = createEventRow(ev);
        if (overviewTbody.firstChild) {
            overviewTbody.insertBefore(tr, overviewTbody.firstChild);
            if (overviewTbody.children.length > 10) {
                overviewTbody.removeChild(overviewTbody.lastChild);
            }
        } else {
            overviewTbody.appendChild(tr);
        }
    }

    // 3. Update active runs badge if needed
    if (ev.event_type === 'run_started' || ev.event_type === 'run_completed' || ev.event_type === 'run_failed') {
        loadOverview(true);
    }
}

// =====================================================================
// VIEW 1: OVERVIEW CONTROLLER
// =====================================================================
async function loadOverview(silent = false) {
    try {
        const res = await fetch('/api/dashboard/overview');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        // 1. Update KPIs
        const k = data.kpis;
        document.getElementById('kpi-reports').textContent = k.total_reports;
        document.getElementById('kpi-iocs').textContent = k.total_iocs;
        document.getElementById('kpi-runs').textContent = k.total_runs;
        document.getElementById('kpi-runs-ok').textContent = `${k.completed_tasks} OK`;
        document.getElementById('kpi-runs-fail').textContent = `${k.failed_tasks} Lỗi`;
        document.getElementById('kpi-mitre').textContent = k.total_mitre;
        if (document.getElementById('kpi-skills')) {
            try {
                const skRes = await fetch('/api/skills');
                if (skRes.ok) {
                    const skData = await skRes.json();
                    const totalSk = skData.length;
                    const approvedSk = skData.filter(s => s.approval_status === 'approved').length;
                    const pendingSk = totalSk - approvedSk;
                    document.getElementById('kpi-skills').textContent = totalSk;
                    if (document.getElementById('kpi-skills-approved')) {
                        document.getElementById('kpi-skills-approved').textContent = `${approvedSk} Đã duyệt`;
                    }
                    if (document.getElementById('kpi-skills-pending')) {
                        document.getElementById('kpi-skills-pending').textContent = `${pendingSk} Chờ duyệt`;
                    }
                    const skBadge = document.getElementById('badge-skills-count');
                    if (skBadge) skBadge.textContent = totalSk;
                }
            } catch (_) {}
        }

        // Update Nav badges
        document.getElementById('badge-running-runs').textContent = k.running_tasks;
        document.getElementById('badge-reports-count').textContent = k.total_reports;
        document.getElementById('badge-iocs-count').textContent = k.total_iocs;
        document.getElementById('badge-mitre-count').textContent = k.total_mitre;
        document.getElementById('badge-rules-awaiting').textContent = k.awaiting_approval_rules;

        // Fetch skills count for badge
        try {
            const skRes = await fetch('/api/skills');
            if (skRes.ok) {
                const skData = await skRes.json();
                const skBadge = document.getElementById('badge-skills-count');
                if (skBadge) skBadge.textContent = skData.length;
            }
        } catch (_) {}

        // Model status pill
        const h = data.system_health;
        const dotModel = document.getElementById('dot-model');
        const textModel = document.getElementById('text-model');
        if (h.ollama_connected) {
            dotModel.className = 'status-dot';
            dotModel.style.background = 'var(--ok)';
            textModel.textContent = `Ollama: ${h.active_model} (${h.ollama_latency_ms}ms)`;
        } else {
            dotModel.className = 'status-dot offline';
            dotModel.style.background = 'var(--crit)';
            textModel.textContent = 'Ollama: Không khả dụng';
        }

        // 2. Render Charts
        renderOverviewCharts(data.timeline, data.distributions);

        // 3. Recent Events Table
        const evTbody = document.getElementById('overview-events-tbody');
        if (data.recent_events && data.recent_events.length > 0) {
            evTbody.innerHTML = '';
            data.recent_events.forEach(ev => evTbody.appendChild(createEventRow(ev)));
        } else {
            evTbody.innerHTML = '<tr><td colspan="3" class="empty-state">Chưa có sự kiện vận hành nào được ghi nhận.</td></tr>';
        }

        // 4. Recent Runs Table
        const runsTbody = document.getElementById('overview-runs-tbody');
        if (data.recent_runs && data.recent_runs.length > 0) {
            runsTbody.innerHTML = data.recent_runs.map(r => `
                <tr>
                    <td><span class="code-cell">${r.run_id ? r.run_id.slice(0, 8) + '...' : '--'}</span></td>
                    <td style="max-width: 320px; white-space: normal; overflow-wrap: anywhere;">${escapeHtml(r.task || '')}</td>
                    <td>${getStatusBadge(r.status)}</td>
                    <td><button class="btn-secondary" style="padding: 3px 8px; font-size: 11px;" onclick="switchView('monitor'); inspectRun('${r.run_id}')">Xem</button></td>
                </tr>
            `).join('');
        } else {
            runsTbody.innerHTML = '<tr><td colspan="4" class="empty-state">Chưa có tác vụ Agent nào được chạy.</td></tr>';
        }

    } catch (e) {
        console.error('Lỗi tải Overview:', e);
    }
}

function createEventRow(ev) {
    const tr = document.createElement('tr');
    const badge = getEventBadge(ev.event_type, ev.status);
    const timeStr = ev.timestamp ? ev.timestamp.slice(11, 19) : '--:--:--';
    tr.innerHTML = `
        <td>${badge}</td>
        <td style="font-size: 12px; color: var(--text-primary);">${escapeHtml(ev.summary || ev.tool_name || '')}</td>
        <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${timeStr}</td>
    `;
    return tr;
}

function renderOverviewCharts(timelineData, distData) {
    // 1. Timeline Chart
    const ctxTimeline = document.getElementById('chart-timeline');
    if (ctxTimeline) {
        const labels = timelineData.map(d => d.date);
        const counts = timelineData.map(d => d.count);

        if (timelineChart) timelineChart.destroy();
        timelineChart = new Chart(ctxTimeline, {
            type: 'line',
            data: {
                labels: labels.length > 0 ? labels : ['Hôm nay'],
                datasets: [{
                    label: 'Agent Runs',
                    data: counts.length > 0 ? counts : [0],
                    borderColor: '#50bda0',
                    backgroundColor: 'rgba(80, 189, 160, 0.06)',
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2,
                    pointBackgroundColor: '#50bda0',
                    pointRadius: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8a8f98', font: { family: 'JetBrains Mono', size: 10 } } },
                    y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8a8f98', stepSize: 1, font: { family: 'JetBrains Mono', size: 10 } } }
                }
            }
        });
    }

    // 2. Artifact Distribution Chart
    const ctxDist = document.getElementById('chart-distribution');
    if (ctxDist) {
        const iocTypes = distData.ioc_types || {};
        const rulesTypes = distData.rules_by_type || {};

        const labels = [];
        const values = [];
        const colors = ['#50bda0', '#7298c8', '#b5a077', '#8f9ba9', '#b18291', '#657f9d', '#7d9e81'];

        for (const [k, v] of Object.entries(iocTypes)) {
            labels.push(`IOC: ${k.toUpperCase()}`);
            values.push(v);
        }
        for (const [k, v] of Object.entries(rulesTypes)) {
            labels.push(`Rule: ${k.toUpperCase()}`);
            values.push(v);
        }

        if (distributionChart) distributionChart.destroy();
        distributionChart = new Chart(ctxDist, {
            type: 'doughnut',
            data: {
                labels: labels.length > 0 ? labels : ['Chưa có dữ liệu'],
                datasets: [{
                    data: values.length > 0 ? values : [1],
                    backgroundColor: values.length > 0 ? colors.slice(0, values.length) : ['#1e293b'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#9aa0a8', font: { size: 11 }, boxWidth: 9, boxHeight: 9, padding: 12, usePointStyle: true } }
                },
                cutout: '65%'
            }
        });
    }
}

// =====================================================================
// VIEW 2: LIVE AGENT MONITOR CONTROLLER
// =====================================================================
let cachedRuns = [];

async function loadAgentRuns() {
    try {
        const status = document.getElementById('filter-runs-status').value;
        const url = `/api/agent/runs${status !== 'all' ? `?status=${status}` : ''}`;
        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        cachedRuns = data.runs || [];

        renderRunsList(cachedRuns);

        // Auto inspect first run if none selected
        if (cachedRuns.length > 0 && !activeRunId) {
            inspectRun(cachedRuns[0].run_id);
        }
    } catch (e) {
        console.error('Lỗi loadAgentRuns:', e);
    }
}

function filterRuns() {
    const q = document.getElementById('filter-runs-search').value.toLowerCase();
    const filtered = cachedRuns.filter(r => 
        (r.run_id && r.run_id.toLowerCase().includes(q)) ||
        (r.task && r.task.toLowerCase().includes(q))
    );
    renderRunsList(filtered);
}

function renderRunsList(runs) {
    const container = document.getElementById('monitor-runs-list');
    document.getElementById('monitor-runs-count').textContent = `${runs.length} Runs`;

    if (runs.length === 0) {
        container.innerHTML = '<div class="empty-state">Không tìm thấy Agent Run nào phù hợp.</div>';
        return;
    }

    container.innerHTML = runs.map(r => {
        const isActive = activeRunId === r.run_id;
        const timeStr = r.start_time ? r.start_time.slice(0, 19).replace('T', ' ') : '--';
        return `
            <div class="kpi-card run-item" style="padding: 12px 14px; cursor: pointer; border-left: 3px solid ${isActive ? 'var(--neon-cyan)' : 'transparent'}; background: ${isActive ? 'var(--bg-elevated)' : 'var(--bg-surface)'}; flex-shrink: 0; min-height: 84px;" onclick="inspectRun('${r.run_id}')">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span class="code-cell" style="font-size: 11px;">${r.run_id.slice(0, 10)}...</span>
                    ${getStatusBadge(r.status)}
                </div>
                <div style="font-size: 12px; color: var(--text-primary); font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-bottom: 6px;">
                    ${escapeHtml(r.task || '')}
                </div>
                <div style="display: flex; justify-content: space-between; font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">
                    <span>${timeStr}</span>
                    <span>${r.total_steps || 0} steps</span>
                </div>
            </div>
        `;
    }).join('');
}

async function inspectRun(runId) {
    activeRunId = runId;
    renderRunsList(cachedRuns); // Re-render to highlight active card

    document.getElementById('monitor-empty-state').style.display = 'none';
    document.getElementById('monitor-active-view').style.display = 'block';

    try {
        const res = await fetch(`/api/agent/runs/${runId}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        // Header info
        document.getElementById('inspector-run-id').textContent = data.run_id;
        document.getElementById('inspector-status-badge').innerHTML = getStatusBadge(data.status);
        document.getElementById('inspector-task-desc').textContent = data.task || '--';
        document.getElementById('inspector-model').textContent = data.model_name || 'qwen2.5:7b';
        document.getElementById('inspector-steps').textContent = data.total_steps || 0;
        
        // Profile, Focus, and xAI Trust badges
        const profBadge = document.getElementById('inspector-profile-badge');
        if (profBadge) {
            const p = (data.cti_profile || 'all').toUpperCase();
            profBadge.textContent = `Domain: ${p === 'WEB' ? 'Web Security' : (p === 'NETWORK' ? 'Network Security' : (p === 'ENDPOINT' ? 'Endpoint Malware' : 'Universal 360'))}`;
            profBadge.style.display = 'inline-block';
        }
        const focBadge = document.getElementById('inspector-focus-badge');
        if (focBadge) {
            const f = data.artifact_focus || 'all';
            if (f !== 'all') {
                focBadge.textContent = `Focus: ${f.toUpperCase()}`;
                focBadge.style.display = 'inline-block';
            } else {
                focBadge.style.display = 'none';
            }
        }
        const xaiBadge = document.getElementById('inspector-xai-badge');
        if (xaiBadge) {
            if (data.trust_score !== null && data.trust_score !== undefined && data.trust_score > 0) {
                xaiBadge.innerHTML = ` xAI Grounded: ${data.trust_score}% (Real)`;
                xaiBadge.style.display = 'inline-block';
            } else {
                xaiBadge.style.display = 'none';
            }
        }
        
        const start = data.start_time ? data.start_time.slice(11, 19) : '';
        const end = data.end_time ? data.end_time.slice(11, 19) : (data.status === 'running' ? 'Đang chạy' : '');
        document.getElementById('inspector-time').textContent = `${start}  ${end}`;

        // Timeline
        const timeline = document.getElementById('inspector-timeline');
        timeline.innerHTML = '';
        if (data.events && data.events.length > 0) {
            data.events.forEach(ev => appendTimelineNode(ev));
        } else {
            timeline.innerHTML = '<div class="empty-state" style="padding: 20px;">Chưa có event nào trong run này.</div>';
        }

        // Result box
        const resultBox = document.getElementById('inspector-result-box');
        if (data.result) {
            resultBox.innerHTML = marked.parse(data.result);
        } else {
            resultBox.innerHTML = '<em>Chưa có kết quả tổng hợp hoặc tiến trình đang diễn ra...</em>';
        }

    } catch (e) {
        console.error('Lỗi inspectRun:', e);
    }
}

function appendTimelineNode(ev) {
    const timeline = document.getElementById('inspector-timeline');
    const item = document.createElement('div');
    const isError = ev.status === 'error' || ev.event_type === 'run_failed';
    const isSuccess = ev.status === 'success' || ev.event_type === 'run_completed';
    item.className = `timeline-item ${isError ? 'error' : (isSuccess ? 'success' : '')}`;

    const badge = getEventBadge(ev.event_type, ev.status);
    const duration = ev.duration_ms > 0 ? `<span class="badge badge-muted">${ev.duration_ms}ms</span>` : '';
    const timeStr = ev.timestamp ? ev.timestamp.slice(11, 19) : '';

    let codeBlock = '';
    if (ev.input_summary || ev.output_summary) {
        codeBlock = `
            <div class="timeline-code">
                ${ev.input_summary ? `<div><strong>Input:</strong> ${escapeHtml(ev.input_summary)}</div>` : ''}
                ${ev.output_summary ? `<div><strong>Output:</strong> ${escapeHtml(ev.output_summary)}</div>` : ''}
            </div>
        `;
    }

    item.innerHTML = `
        <div class="timeline-dot"></div>
        <div class="timeline-content">
            <div class="timeline-header">
                <div style="display: flex; align-items: center; gap: 8px;">
                    ${badge}
                    ${duration}
                    ${ev.step > 0 ? `<span class="badge badge-muted">Step ${ev.step}</span>` : ''}
                </div>
                <span class="timeline-time">${timeStr}</span>
            </div>
            <div class="timeline-body">${escapeHtml(ev.summary || '')}</div>
            ${codeBlock}
        </div>
    `;
    timeline.appendChild(item);
}

// =====================================================================
// VIEW 3: CTI EXPLORER CONTROLLER
// =====================================================================
async function loadCTIReports() {
    try {
        const search = document.getElementById('filter-cti-search').value;
        const url = `/api/cti/reports${search ? `?search=${encodeURIComponent(search)}` : ''}`;
        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const tbody = document.getElementById('cti-reports-tbody');
        if (!data.reports || data.reports.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Chưa có bài báo CTI nào được thu thập. Hãy bấm "Cào Tin Mới Ngay"!</td></tr>';
            return;
        }

        tbody.innerHTML = data.reports.map(r => `
            <tr>
                <td><span class="code-cell">#${r.id}</span></td>
                <td style="font-weight: 600; color: #fff; max-width: 280px;">
                    <a href="${escapeHtml(r.source_url)}" target="_blank" style="color: #fff; text-decoration: none;" onmouseover="this.style.color='var(--neon-cyan)'" onmouseout="this.style.color='#fff'">${escapeHtml(r.title)}</a>
                </td>
                <td style="max-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                    <a href="${escapeHtml(r.source_url)}" target="_blank" style="color: var(--neon-cyan); text-decoration: none; font-size: 11px;" title="${escapeHtml(r.source_url)}">${escapeHtml(r.source_url)}</a>
                </td>
                <td><span class="badge badge-info">${r.ioc_count || 0} IOCs</span></td>
                <td><span class="badge badge-low">${r.mitre_count || 0} Techniques</span></td>
                <td><span class="badge badge-ok">${r.rule_count || 0} Rules</span></td>
                <td style="font-family: var(--font-mono); font-size: 11px;">${r.created_at ? r.created_at.slice(0, 16).replace('T', ' ') : '--'}</td>
                <td>
                    <div style="display: flex; gap: 6px;">
                        <button class="btn-secondary" style="padding: 3px 8px; font-size: 11px;" onclick="openReportModal(${r.id})"> Chi tiết</button>
                        <a href="${escapeHtml(r.source_url)}" target="_blank" class="btn-primary" style="padding: 3px 8px; font-size: 11px; text-decoration: none; display: inline-flex; align-items: center; gap: 3px;"> Báo Gốc ↗</a>
                    </div>
                </td>
            </tr>
        `).join('');

    } catch (e) {
        console.error('Lỗi loadCTIReports:', e);
    }
}

async function openReportModal(reportId) {
    try {
        const res = await fetch(`/api/cti/reports/${reportId}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const rep = await res.json();
        currentInspectedReport = rep;

        document.getElementById('report-modal-id').textContent = rep.id;
        document.getElementById('rep-detail-title').textContent = rep.title;
        document.getElementById('rep-detail-source').href = rep.source_url;
        document.getElementById('rep-detail-source').textContent = rep.source_url;

        // Data Provenance fields
        const pubEl = document.getElementById('rep-detail-publisher');
        if (pubEl) pubEl.textContent = rep.source_publisher || 'Threat Intelligence Feed';
        
        const pubDateEl = document.getElementById('rep-detail-published');
        if (pubDateEl) pubDateEl.textContent = rep.published_date || 'N/A';
        
        const fetchedEl = document.getElementById('rep-detail-fetched-at');
        if (fetchedEl) fetchedEl.textContent = rep.fetched_at || rep.created_at || 'N/A';
        
        const httpBadge = document.getElementById('rep-detail-http-status');
        if (httpBadge) {
            const code = rep.http_status || 200;
            httpBadge.textContent = `${code} ${code === 200 ? 'OK' : 'ERR'}`;
            httpBadge.className = code === 200 ? 'badge badge-ok' : 'badge badge-crit';
        }
        
        const fetchBadge = document.getElementById('rep-detail-fetch-status');
        if (fetchBadge) {
            const fStatus = (rep.fetch_status || 'success').toUpperCase();
            fetchBadge.textContent = fStatus;
            fetchBadge.className = fStatus === 'SUCCESS' ? 'badge badge-ok' : 'badge badge-high';
        }
        
        const hashEl = document.getElementById('rep-detail-hash');
        if (hashEl) {
            hashEl.textContent = rep.content_hash || 'Chưa tính toán';
        }

        const headerBtn = document.getElementById('rep-detail-header-btn');
        if (headerBtn) {
            headerBtn.href = rep.source_url || '#';
            headerBtn.style.display = (rep.source_url && rep.source_url.startsWith('http')) ? 'inline-flex' : 'none';
        }
        document.getElementById('rep-detail-summary').innerHTML = marked.parse(rep.summary || 'Không có bản tóm tắt.');
        document.getElementById('rep-detail-evidence').textContent = rep.raw_content || 'Không có nội dung thô.';

        // IOCs tab
        const iocTbody = document.getElementById('rep-detail-iocs-tbody');
        iocTbody.innerHTML = (rep.iocs && rep.iocs.length > 0) ? rep.iocs.map(i => `
            <tr><td><span class="badge badge-info">${i.ioc_type}</span></td><td><code class="code-cell">${i.ioc_value}</code></td><td>${getIocStatusBadge(i.status)}</td></tr>
        `).join('') : '<tr><td colspan="3" class="empty-state">Không có IoC nào gắn với bài báo này.</td></tr>';

        // MITRE tab
        const mitreTbody = document.getElementById('rep-detail-mitre-tbody');
        mitreTbody.innerHTML = (rep.mitre && rep.mitre.length > 0) ? rep.mitre.map(m => `
            <tr><td><span class="code-cell">${m.technique_id}</span></td><td>${escapeHtml(m.technique_name || '')}</td><td><span class="badge badge-low">${m.tactic || 'General'}</span></td><td><em>${escapeHtml(m.evidence || '')}</em></td></tr>
        `).join('') : '<tr><td colspan="4" class="empty-state">Không có kỹ thuật MITRE nào.</td></tr>';

        // Rules tab
        const rulesTbody = document.getElementById('rep-detail-rules-tbody');
        rulesTbody.innerHTML = (rep.rules && rep.rules.length > 0) ? rep.rules.map(rl => `
            <tr><td><span class="badge badge-info">${rl.rule_type.toUpperCase()}</span></td><td>${escapeHtml(rl.rule_name)}</td><td>${getRuleSyntaxBadge(rl.syntax_status)}</td><td>${getRuleApprovalBadge(rl.approval_status)}</td></tr>
        `).join('') : '<tr><td colspan="4" class="empty-state">Không có rule nào.</td></tr>';

        // History tab
        const histEl = document.getElementById('rep-detail-history-content');
        if (rep.agent_run) {
            histEl.innerHTML = `
                <div><strong>Run ID:</strong> <span class="code-cell">${rep.agent_run.run_id}</span></div>
                <div><strong>Model:</strong> ${rep.agent_run.model_name || 'qwen2.5:7b'}</div>
                <div><strong>Trạng thái:</strong> ${getStatusBadge(rep.agent_run.status)}</div>
                <div style="margin-top: 8px;"><button class="btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="closeReportModal(); switchView('monitor'); inspectRun('${rep.agent_run.run_id}')">Xem Timeline trong Monitor</button></div>
            `;
            loadReportXaiAudit(rep.agent_run.run_id, rep.agent_run.trust_score);
        } else {
            histEl.textContent = 'Không tìm thấy Agent Run liên kết.';
            loadReportXaiAudit(null, null);
        }

        switchReportTab('summary');
        document.getElementById('modal-report-detail').classList.add('open');
    } catch (e) {
        console.error('Lỗi openReportModal:', e);
    }
}

let currentReportXaiItems = [];
let currentXaiFilter = 'all';

async function loadReportXaiAudit(runId, runTrustScore) {
    const tbody = document.getElementById('rep-detail-xai-tbody');
    const claimsTbody = document.getElementById('rep-detail-claims-tbody');
    const scoreVal = document.getElementById('rep-xai-score-val');
    const badgeStatus = document.getElementById('rep-xai-badge-status');

    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Đang tải và đối soát dữ liệu kiểm chứng xAI...</td></tr>';
    if (claimsTbody) claimsTbody.innerHTML = '<tr><td colspan="5" class="empty-state">Đang tải nhận định kỹ thuật...</td></tr>';

    try {
        let reportId = currentInspectedReport ? currentInspectedReport.id : null;
        let url = reportId ? `/api/xai/iocs?report_id=${reportId}` : (runId ? `/api/xai/iocs?run_id=${runId}` : '/api/xai/iocs');
        const res = await fetch(url);
        const data = await res.json();
        currentReportXaiItems = data.verifications || [];

        // Fallback to legacy xai_verifications if table empty
        if (currentReportXaiItems.length === 0 && runId) {
            const fbRes = await fetch(`/api/xai/run/${runId}`);
            if (fbRes.ok) {
                const fbData = await fbRes.json();
                currentReportXaiItems = (fbData.verifications || []).map(v => ({
                    id: v.id,
                    indicator: v.entity_value,
                    indicator_type: v.entity_type,
                    source_match_status: v.is_grounded ? 'exact_match' : 'not_found',
                    context_assessment: v.explanation || 'Đối soát tự động nguyên văn',
                    maliciousness_status: v.is_grounded ? 'maliciousness_confirmed' : 'insufficient_evidence',
                    trust_score: v.trust_score !== undefined ? v.trust_score : (v.is_grounded ? 0.9 : 0.0),
                    trust_status: v.is_grounded ? 'verified' : 'rejected',
                    evidence_quote: v.exact_quote || '',
                    evidence_location: `offset: ${v.char_offset_start}..${v.char_offset_end}`,
                    approval_status: 'pending_review'
                }));
            }
        }

        // Aggregate Score
        let score = 0;
        if (currentReportXaiItems.length > 0) {
            const sum = currentReportXaiItems.reduce((acc, it) => acc + (it.trust_score || 0), 0);
            score = Math.round((sum / currentReportXaiItems.length) * 100);
        } else if (runTrustScore !== null && runTrustScore !== undefined) {
            score = Math.round(runTrustScore);
        }

        if (scoreVal) scoreVal.textContent = `${score}% TRUST SCORE`;
        if (badgeStatus) {
            if (score >= 80) {
                badgeStatus.className = 'badge badge-ok';
                badgeStatus.textContent = 'VERIFIED TRUSTED';
            } else if (score >= 50) {
                badgeStatus.className = 'badge badge-high';
                badgeStatus.textContent = 'PARTIALLY VERIFIED';
            } else {
                badgeStatus.className = 'badge badge-crit';
                badgeStatus.textContent = 'UNVERIFIED / RISKY';
            }
        }

        renderFilteredXaiTable(currentXaiFilter);

        // Fetch Claims
        if (reportId && claimsTbody) {
            const cRes = await fetch(`/api/xai/claims?report_id=${reportId}`);
            if (cRes.ok) {
                const cData = await cRes.json();
                renderClaimsTable(cData.claims || []);
            }
        }
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state">Lỗi tải dữ liệu kiểm chứng xAI: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function filterReportXai(filterStatus) {
    currentXaiFilter = filterStatus;
    ['all', 'verified', 'partially_verified', 'unverified', 'rejected'].forEach(st => {
        const btn = document.getElementById(`btn-xai-filter-${st}`);
        if (btn) {
            if (st === filterStatus) btn.classList.add('active');
            else btn.classList.remove('active');
        }
    });
    renderFilteredXaiTable(filterStatus);
}

function renderFilteredXaiTable(filterStatus) {
    const tbody = document.getElementById('rep-detail-xai-tbody');
    let items = currentReportXaiItems;
    if (filterStatus && filterStatus !== 'all') {
        items = items.filter(it => it.trust_status === filterStatus);
    }

    if (!items || items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state">Không có chỉ số nào khớp với bộ lọc "${filterStatus.toUpperCase()}".</td></tr>`;
        return;
    }

    tbody.innerHTML = items.map(v => {
        const matchBadge = v.source_match_status === 'exact_match'
            ? '<span class="badge badge-ok" title="Khớp chính xác từng ký tự">EXACT MATCH</span>'
            : (v.source_match_status === 'normalized_match'
                ? '<span class="badge badge-info" title="Khớp sau khi giải bẫy defanging">NORMALIZED</span>'
                : '<span class="badge badge-crit" title="Không hề xuất hiện trong bài">NOT FOUND</span>');

        const malBadge = v.maliciousness_status === 'maliciousness_confirmed'
            ? '<span class="badge badge-crit">C2/MALICIOUS</span>'
            : (v.maliciousness_status === 'example_or_benign'
                ? '<span class="badge badge-muted">EXAMPLE/TEST</span>'
                : (v.maliciousness_status === 'mentioned_not_confirmed'
                    ? '<span class="badge badge-med">MENTIONED ONLY</span>'
                    : '<span class="badge badge-high">UNCONFIRMED</span>'));

        const appBadge = v.approval_status === 'approved'
            ? '<span class="badge badge-ok">APPROVED</span>'
            : (v.approval_status === 'rejected'
                ? '<span class="badge badge-crit">REJECTED</span>'
                : '<span class="badge badge-high">PENDING</span>');

        const scorePct = Math.round((v.trust_score || 0) * 100);
        const scoreBadge = `<span class="badge ${scorePct >= 80 ? 'badge-ok' : (scorePct >= 50 ? 'badge-med' : 'badge-crit')}">${scorePct}%</span>`;

        const quote = v.evidence_quote
            ? `<div style="font-size: 11px; color: #a5f3fc; font-style: italic;">"${escapeHtml(v.evidence_quote)}"</div>
               <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px;"> ${escapeHtml(v.evidence_location || '')}</div>`
            : '<span style="color: var(--text-muted); font-size: 11px;">Không có trích dẫn</span>';

        const actionBtns = `
            <div style="display: flex; gap: 4px;">
                <button class="btn-secondary" style="padding: 2px 6px; font-size: 10px; color: var(--ok); border-color: var(--ok);" onclick="approveIOCVerification(${v.id}, 'approved')">Duyệt</button>
                <button class="btn-secondary" style="padding: 2px 6px; font-size: 10px; color: var(--crit); border-color: var(--crit);" onclick="approveIOCVerification(${v.id}, 'rejected')">Từ Chối</button>
            </div>
        `;

        return `
            <tr>
                <td>
                    <strong style="color: #fff; font-family: var(--font-mono); font-size: 12px;">${escapeHtml(v.indicator || v.entity_value || '')}</strong>
                    <div style="font-size: 10px; color: var(--text-muted);">${escapeHtml(v.indicator_type || v.entity_type || 'ioc').toUpperCase()}</div>
                </td>
                <td>${matchBadge}</td>
                <td>
                    ${malBadge}
                    <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px; max-width: 140px;">${escapeHtml(v.context_assessment || '')}</div>
                </td>
                <td>${scoreBadge}</td>
                <td style="max-width: 240px; line-height: 1.3;">${quote}</td>
                <td>${appBadge}</td>
                <td>${actionBtns}</td>
            </tr>
        `;
    }).join('');
}

function renderClaimsTable(claims) {
    const tbody = document.getElementById('rep-detail-claims-tbody');
    if (!tbody) return;
    if (!claims || claims.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Không có nhận định hành vi nào được ghi nhận cho báo cáo này.</td></tr>';
        return;
    }

    tbody.innerHTML = claims.map(c => {
        const stBadge = c.verification_status === 'verified'
            ? '<span class="badge badge-ok">VERIFIED</span>'
            : (c.verification_status === 'insufficient_evidence'
                ? '<span class="badge badge-med">INSUFFICIENT EVIDENCE</span>'
                : '<span class="badge badge-crit">REJECTED</span>');

        const scorePct = Math.round((c.trust_score || 0) * 100);

        return `
            <tr>
                <td><strong style="color: #fff; font-size: 12px;">${escapeHtml(c.claim)}</strong></td>
                <td><span class="badge badge-info">${escapeHtml(c.claim_type.toUpperCase())}</span></td>
                <td>${stBadge}</td>
                <td style="font-size: 11px; color: #a5f3fc; font-style: italic; max-width: 220px;">
                    ${c.evidence_quote ? `"${escapeHtml(c.evidence_quote)}"` : '<span style="color: var(--text-muted);">Thiếu trích dẫn</span>'}
                </td>
                <td style="font-size: 11px; color: var(--text-secondary); max-width: 200px;">
                    <div>${escapeHtml(c.reasoning_summary || '')}</div>
                    <div style="font-size: 10px; color: var(--neon-cyan); margin-top: 2px;">Trust Score: ${scorePct}%</div>
                </td>
            </tr>
        `;
    }).join('');
}

async function approveIOCVerification(verificationId, status) {
    try {
        const reason = status === 'approved' ? 'Chuyên viên SOC phê duyệt sau khi đối soát bằng chứng nguồn.' : 'Chuyên viên SOC từ chối do không đủ bằng chứng độc hại.';
        const res = await fetch('/api/xai/ioc/approve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                verification_id: verificationId,
                approval_status: status,
                reviewer: 'SOC Analyst',
                reason: reason
            })
        });
        const data = await res.json();
        showToast(data.message, status === 'approved' ? 'success' : 'info');
        
        // Refresh local state and re-render
        const item = currentReportXaiItems.find(it => it.id === verificationId);
        if (item) {
            item.approval_status = status;
            renderFilteredXaiTable(currentXaiFilter);
        }
    } catch (e) {
        showToast(`Lỗi phê duyệt IoC: ${e.message}`, 'error');
    }
}

async function approveSkillVerification(skillName, status) {
    try {
        const reason = status === 'approved' ? 'Chuyên viên SOC phê duyệt kỹ năng sau khi kiểm tra mã nguồn.' : 'Từ chối.';
        const res = await fetch('/api/xai/skill/approve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                skill_name: skillName,
                approval_status: status,
                reviewer: 'SOC Analyst',
                reason: reason
            })
        });
        const data = await res.json();
        showToast(data.message, 'success');
        loadSkills(currentSkillDomainFilter);
    } catch (e) {
        showToast(`Lỗi phê duyệt Skill: ${e.message}`, 'error');
    }
}

async function approveAllSkills() {
    try {
        const res = await fetch('/api/xai/skills/approve-all', { method: 'POST' });
        const data = await res.json();
        showToast(data.message, 'success');
        loadSkills(currentSkillDomainFilter);
    } catch (e) {
        showToast('Lỗi phê duyệt toàn bộ: ' + e.message, 'error');
    }
}

async function loadReportXaiAudit(runId, runTrustScore) {
    const tbody = document.getElementById('rep-detail-xai-tbody');
    const scoreVal = document.getElementById('rep-xai-score-val');
    const badgeStatus = document.getElementById('rep-xai-badge-status');

    if (!runId) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Không có bản kiểm chứng xAI nào cho báo cáo này.</td></tr>';
        if (scoreVal) scoreVal.textContent = 'N/A';
        return;
    }

    try {
        const res = await fetch(`/api/xai/run/${runId}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const score = runTrustScore !== null && runTrustScore !== undefined ? runTrustScore : (data.verifications.length > 0 ? 100 : 0);
        if (scoreVal) scoreVal.textContent = `${score}% GROUNDED`;
        if (badgeStatus) {
            if (score >= 90) {
                badgeStatus.className = 'badge badge-ok';
                badgeStatus.textContent = 'VERIFIED REAL';
            } else {
                badgeStatus.className = 'badge badge-high';
                badgeStatus.textContent = 'REVIEW NEEDED';
            }
        }

        if (data.verifications && data.verifications.length > 0) {
            tbody.innerHTML = data.verifications.map(v => {
                const isGrounded = v.is_grounded || v.grounding_status === 'GROUNDED_VERBATIM';
                const statusBadge = isGrounded
                    ? '<span class="badge badge-ok">GROUNDED 100%</span>'
                    : '<span class="badge badge-crit">UNVERIFIED</span>';
                const offset = (v.char_offset_start !== -1 && v.char_offset_start !== undefined)
                    ? `<code class="code-cell" style="font-size: 11px;">[${v.char_offset_start}..${v.char_offset_end}]</code>`
                    : '<span class="badge badge-muted">N/A</span>';
                const quote = v.exact_quote
                    ? `<span style="color: #a5f3fc; font-style: italic;">"${escapeHtml(v.exact_quote)}"</span>`
                    : '<span style="color: var(--text-muted);">Không có trích dẫn</span>';

                return `
                    <tr>
                        <td><span class="badge badge-info">${escapeHtml(v.entity_type.toUpperCase())}</span></td>
                        <td><strong style="color: #fff; font-family: var(--font-mono);">${escapeHtml(v.entity_value)}</strong></td>
                        <td>${statusBadge}</td>
                        <td>${offset}</td>
                        <td style="max-width: 320px; font-size: 12px; line-height: 1.4;">${quote}</td>
                    </tr>
                `;
            }).join('');
        } else {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Chưa ghi nhận mục kiểm chứng chi tiết cho Run này.</td></tr>';
        }
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Lỗi tải dữ liệu xAI: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function switchReportTab(tabName) {
    document.querySelectorAll('#modal-report-detail .tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('#modal-report-detail .tab-pane').forEach(p => p.classList.remove('active'));
    
    // Find target tab
    const tabs = ['summary', 'evidence', 'iocs', 'mitre', 'rules', 'history', 'xai'];
    const idx = tabs.indexOf(tabName);
    if (idx !== -1) {
        document.querySelectorAll('#modal-report-detail .tab-btn')[idx].classList.add('active');
        document.getElementById(`tab-rep-${tabName}`).classList.add('active');
    }
}

function closeReportModal() {
    document.getElementById('modal-report-detail').classList.remove('open');
}

// =====================================================================
// VIEW 4: IOC MANAGEMENT CONTROLLER
// =====================================================================
async function loadIOCs() {
    try {
        const type = document.getElementById('filter-ioc-type').value;
        const status = document.getElementById('filter-ioc-status').value;
        const search = document.getElementById('filter-ioc-search').value;

        let url = '/api/iocs?limit=100';
        if (type !== 'all') url += `&ioc_type=${type}`;
        if (status !== 'all') url += `&status=${status}`;
        if (search) url += `&search=${encodeURIComponent(search)}`;

        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const tbody = document.getElementById('iocs-tbody');
        if (!data.iocs || data.iocs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Chưa có IOC nào phù hợp bộ lọc.</td></tr>';
            return;
        }

        tbody.innerHTML = data.iocs.map(ioc => `
            <tr>
                <td><span class="badge badge-info">${ioc.ioc_type.toUpperCase()}</span></td>
                <td><code class="code-cell" style="font-size: 13px;">${escapeHtml(ioc.ioc_value)}</code></td>
                <td>${getIocStatusBadge(ioc.status)}</td>
                <td><span class="badge badge-muted">${ioc.confidence || 'medium'}</span></td>
                <td style="max-width: 250px; font-size: 12px; color: var(--text-secondary);">${escapeHtml(ioc.context || 'Trích xuất tự động từ báo cáo')}</td>
                <td style="font-family: var(--font-mono); font-size: 11px;">${ioc.timestamp ? ioc.timestamp.slice(0, 16).replace('T', ' ') : '--'}</td>
                <td>
                    <select class="form-control" style="padding: 2px 6px; font-size: 11px; width: 110px;" onchange="changeIocStatus(${ioc.id}, this.value)">
                        <option value="observed" ${ioc.status === 'observed' ? 'selected' : ''}>Observed</option>
                        <option value="candidate" ${ioc.status === 'candidate' ? 'selected' : ''}>Candidate</option>
                        <option value="verified" ${ioc.status === 'verified' ? 'selected' : ''}>Verified</option>
                        <option value="benign" ${ioc.status === 'benign' ? 'selected' : ''}>Benign</option>
                    </select>
                </td>
            </tr>
        `).join('');

    } catch (e) {
        console.error('Lỗi loadIOCs:', e);
    }
}

async function changeIocStatus(iocId, newStatus) {
    try {
        const res = await fetch(`/api/iocs/${iocId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        loadIOCs();
    } catch (e) {
        alert('Lỗi cập nhật IOC: ' + e.message);
    }
}

function exportIOCs(format) {
    window.open(`/api/iocs/export?format=${format}`, '_blank');
}

// =====================================================================
// VIEW 5: MITRE ATT&CK EXPLORER CONTROLLER
// =====================================================================
async function loadMitreMappings() {
    try {
        const tactic = document.getElementById('filter-mitre-tactic').value;
        const search = document.getElementById('filter-mitre-search').value;

        let url = '/api/mitre/mappings?limit=100';
        if (tactic !== 'all') url += `&tactic=${encodeURIComponent(tactic)}`;
        if (search) url += `&search=${encodeURIComponent(search)}`;

        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const tbody = document.getElementById('mitre-tbody');
        if (!data.mappings || data.mappings.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Chưa có kết quả ánh xạ MITRE ATT&CK nào. Hãy chạy Agent để phân tích!</td></tr>';
            return;
        }

        tbody.innerHTML = data.mappings.map(m => `
            <tr>
                <td><span class="code-cell" style="font-weight: 700;">${m.technique_id}</span></td>
                <td style="font-weight: 600; color: #fff;">${escapeHtml(m.technique_name || 'Kỹ thuật ATT&CK')}</td>
                <td><span class="badge badge-low">${escapeHtml(m.tactic || 'General')}</span></td>
                <td><span class="badge badge-ok">${m.status || 'candidate'}</span></td>
                <td><span class="badge badge-muted">${m.confidence || 'medium'}</span></td>
                <td style="max-width: 320px; font-size: 12px; font-style: italic; color: #cbd5e1;">"${escapeHtml(m.evidence || 'N/A')}"</td>
                <td style="font-family: var(--font-mono); font-size: 11px;">${m.timestamp ? m.timestamp.slice(0, 16).replace('T', ' ') : '--'}</td>
            </tr>
        `).join('');

    } catch (e) {
        console.error('Lỗi loadMitreMappings:', e);
    }
}

async function openMitreMatrixModal() {
    const modal = document.getElementById('modal-mitre-matrix');
    modal.classList.add('open');
    try {
        const res = await fetch('/api/mitre/matrix');
        const data = await res.json();
        const tbody = document.getElementById('mitre-matrix-tbody');
        tbody.innerHTML = Object.entries(data.techniques).map(([tid, info]) => `
            <tr>
                <td><span class="code-cell">${tid}</span></td>
                <td style="font-weight: 600; color: #fff;">${info.name}</td>
                <td><span class="badge badge-low">${info.tactic}</span></td>
                <td style="font-size: 12px; color: var(--text-secondary);">${info.description}</td>
            </tr>
        `).join('');
    } catch (e) {
        console.error(e);
    }
}

function closeMitreMatrixModal() {
    document.getElementById('modal-mitre-matrix').classList.remove('open');
}

// =====================================================================
// VIEW 6: DEFENSIVE RULES CONTROLLER
// =====================================================================
async function loadDefenseRules() {
    try {
        const type = document.getElementById('filter-rules-type').value;
        const syntax = document.getElementById('filter-rules-syntax').value;
        const approval = document.getElementById('filter-rules-approval').value;
        const search = document.getElementById('filter-rules-search').value;

        let url = '/api/rules?limit=100';
        if (type !== 'all') url += `&rule_type=${type}`;
        if (syntax !== 'all') url += `&syntax_status=${syntax}`;
        if (approval !== 'all') url += `&approval_status=${approval}`;
        if (search) url += `&search=${encodeURIComponent(search)}`;

        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const tbody = document.getElementById('rules-tbody');
        if (!data.rules || data.rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Chưa có luật phòng thủ nào trong cơ sở dữ liệu.</td></tr>';
            return;
        }

        tbody.innerHTML = data.rules.map(r => `
            <tr>
                <td><span class="code-cell">#${r.id}</span></td>
                <td><span class="badge badge-info">${r.rule_type.toUpperCase()}</span></td>
                <td style="font-weight: 600; color: #fff;">${escapeHtml(r.rule_name)}</td>
                <td>${getRuleSyntaxBadge(r.syntax_status, r.validation_error)}</td>
                <td>${getRuleApprovalBadge(r.approval_status)}</td>
                <td style="font-size: 12px;">${escapeHtml(r.approved_by || '--')}</td>
                <td style="font-family: var(--font-mono); font-size: 11px;">${r.timestamp ? r.timestamp.slice(0, 16).replace('T', ' ') : '--'}</td>
                <td>
                    <button class="btn-secondary" style="padding: 4px 10px; font-size: 11px;" onclick="openRuleModal(${r.id})">Kiểm tra & Duyệt</button>
                </td>
            </tr>
        `).join('');

    } catch (e) {
        console.error('Lỗi loadDefenseRules:', e);
    }
}

async function openRuleModal(ruleId) {
    try {
        const res = await fetch(`/api/rules?limit=100`);
        const data = await res.json();
        const rule = (data.rules || []).find(r => r.id === ruleId);
        if (!rule) return;
        currentInspectedRule = rule;

        document.getElementById('modal-rule-name').textContent = rule.rule_name;
        document.getElementById('modal-rule-meta').textContent = `Loại: ${rule.rule_type.toUpperCase()} | Tạo lúc: ${rule.timestamp}`;
        document.getElementById('modal-rule-syntax-badge').innerHTML = getRuleSyntaxBadge(rule.syntax_status);
        document.getElementById('modal-rule-approval-badge').innerHTML = getRuleApprovalBadge(rule.approval_status);
        document.getElementById('modal-rule-content').textContent = rule.rule_content;

        const valBox = document.getElementById('modal-rule-validator-box');
        if (rule.syntax_status === 'invalid') {
            valBox.style.display = 'block';
            valBox.style.background = 'var(--crit-bg)';
            valBox.style.border = '1px solid rgba(239, 68, 68, 0.3)';
            valBox.style.color = 'var(--crit)';
            valBox.innerHTML = `<strong>Lỗi cú pháp Validator:</strong> ${escapeHtml(rule.validation_error || 'Không hợp lệ')}`;
        } else if (rule.syntax_status === 'valid') {
            valBox.style.display = 'block';
            valBox.style.background = 'var(--ok-bg)';
            valBox.style.border = '1px solid rgba(16, 185, 129, 0.3)';
            valBox.style.color = 'var(--ok)';
            valBox.innerHTML = `<strong>Cú pháp hợp lệ:</strong> Đã vượt qua kiểm tra cấu trúc ${rule.rule_type.toUpperCase()}.`;
        } else {
            valBox.style.display = 'none';
        }

        document.getElementById('modal-rule-detail').classList.add('open');
    } catch (e) {
        console.error('Lỗi openRuleModal:', e);
    }
}

function closeRuleModal() {
    document.getElementById('modal-rule-detail').classList.remove('open');
}

function copyRuleCode() {
    if (!currentInspectedRule) return;
    navigator.clipboard.writeText(currentInspectedRule.rule_content);
    alert('Đã sao chép nội dung Rule vào Clipboard!');
}

async function triggerRuleRevalidate() {
    if (!currentInspectedRule) return;
    try {
        const res = await fetch(`/api/rules/${currentInspectedRule.id}/validate`, { method: 'POST' });
        const data = await res.json();
        alert(`Kết quả kiểm tra: ${data.syntax_status.toUpperCase()} ${data.validation_error ? `(${data.validation_error})` : ''}`);
        openRuleModal(currentInspectedRule.id);
        loadDefenseRules();
    } catch (e) {
        alert('Lỗi revalidate: ' + e.message);
    }
}

async function approveCurrentRule() {
    if (!currentInspectedRule) return;
    try {
        const res = await fetch(`/api/rules/${currentInspectedRule.id}/approve`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ analyst_name: 'SOC Analyst (Admin)' })
        });
        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Lỗi duyệt');
        }
        alert('Đã phê duyệt Rule thành công!');
        closeRuleModal();
        loadDefenseRules();
        loadOverview(true);
    } catch (e) {
        alert(e.message);
    }
}

async function rejectCurrentRule() {
    if (!currentInspectedRule) return;
    const reason = prompt('Nhập lý do từ chối rule này:');
    if (!reason) return;
    try {
        const res = await fetch(`/api/rules/${currentInspectedRule.id}/reject`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: reason })
        });
        alert('Đã từ chối Rule.');
        closeRuleModal();
        loadDefenseRules();
        loadOverview(true);
    } catch (e) {
        alert(e.message);
    }
}

function downloadCurrentRule() {
    if (!currentInspectedRule) return;
    window.open(`/api/rules/${currentInspectedRule.id}/download`, '_blank');
}

// =====================================================================
// VIEW 7: TOOL REGISTRY CONTROLLER
// =====================================================================
async function loadTools() {
    try {
        const res = await fetch('/api/tools');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        const grid = document.getElementById('tools-grid');
        grid.innerHTML = data.tools.map(tool => {
            const successRate = tool.total_calls > 0 ? Math.round((tool.success_calls / tool.total_calls) * 100) : 100;
            return `
                <div class="kpi-card" style="padding: 18px;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; gap: 14px;">
                        <div style="flex: 1; min-width: 0;">
                            <span class="code-cell" style="font-size: 14px; font-weight: 700;">${tool.name}</span>
                            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px; line-height: 1.45;">${escapeHtml(tool.description)}</div>
                        </div>
                        <label class="toggle-switch" style="flex-shrink: 0; min-width: 44px; margin-top: 2px;">
                            <input type="checkbox" ${tool.enabled ? 'checked' : ''} onchange="toggleTool('${tool.name}')">
                            <span class="slider"></span>
                        </label>
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 12px; font-family: var(--font-mono); color: var(--text-muted); padding-top: 10px; border-top: 1px solid var(--border-subtle);">
                        <div>Tổng gọi: <strong style="color: #fff;">${tool.total_calls}</strong></div>
                        <div>Tỉ lệ OK: <strong style="color: var(--ok);">${successRate}%</strong></div>
                        <div>Độ trễ TB: <strong style="color: var(--neon-cyan);">${tool.avg_duration_ms}ms</strong></div>
                        <div>Trạng thái: ${tool.enabled ? '<span class="badge badge-ok">ENABLED</span>' : '<span class="badge badge-crit">DISABLED</span>'}</div>
                    </div>
                </div>
            `;
        }).join('');

    } catch (e) {
        console.error('Lỗi loadTools:', e);
    }
}

async function toggleTool(toolName) {
    try {
        const res = await fetch(`/api/tools/${encodeURIComponent(toolName)}/toggle`, { method: 'POST' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        loadTools();
    } catch (e) {
        alert('Lỗi toggle tool: ' + e.message);
    }
}

// =====================================================================
// VIEW 8: SYSTEM HEALTH CONTROLLER
// =====================================================================
async function loadHealth() {
    try {
        const res = await fetch('/api/system/health');
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        // Backend
        document.getElementById('health-backend').textContent = 'ONLINE';
        document.getElementById('health-backend-info').textContent = `${data.backend.framework} (Python ${data.backend.python_version})`;

        // Database
        document.getElementById('health-db').textContent = 'CONNECTED';
        document.getElementById('health-db-info').textContent = `${data.database.path} (${data.database.type})`;

        // Ollama
        const ollamaEl = document.getElementById('health-ollama');
        const ollamaInfo = document.getElementById('health-ollama-info');
        if (data.model_runtime.connected) {
            ollamaEl.textContent = 'ONLINE';
            ollamaEl.style.color = 'var(--ok)';
            ollamaInfo.textContent = `Model: ${data.model_runtime.active_model} | Latency: ${data.model_runtime.latency_ms}ms`;
        } else {
            ollamaEl.textContent = 'OFFLINE';
            ollamaEl.style.color = 'var(--crit)';
            ollamaInfo.textContent = 'Không kết nối được tới http://localhost:11434';
        }

        // Active SSE
        document.getElementById('health-sse-clients').textContent = data.active_sse_subscribers;

    } catch (e) {
        console.error('Lỗi loadHealth:', e);
    }
}

// =====================================================================
// MODAL: START TASK CONTROLLER
// =====================================================================
function openStartTaskModal() {
    document.getElementById('modal-start-task').classList.add('open');
}

function closeStartTaskModal() {
    document.getElementById('modal-start-task').classList.remove('open');
}

function toggleTaskMode(mode) {
    const customGroup = document.getElementById('custom-task-input-group');
    const rssGroup = document.getElementById('rss-source-select-group');
    if (customGroup) customGroup.style.display = (mode === 'custom') ? 'block' : 'none';
    if (rssGroup) rssGroup.style.display = (mode === 'scrape_rss') ? 'block' : 'none';
}

function onProfileSelectChange(val) {
    const focusSelect = document.getElementById('task-focus-select');
    if (!focusSelect) return;
    if (val === 'web') {
        focusSelect.value = 'cve';
    } else if (val === 'network') {
        focusSelect.value = 'ipv4';
    } else if (val === 'endpoint') {
        focusSelect.value = 'hash';
    } else {
        focusSelect.value = 'all';
    }
}

async function submitAgentTask() {
    const mode = document.getElementById('task-mode-select').value;
    const text = document.getElementById('task-text-input').value;
    const maxSteps = parseInt(document.getElementById('task-max-steps').value) || 8;
    const rssSource = document.getElementById('task-rss-source') ? document.getElementById('task-rss-source').value : "https://feeds.feedburner.com/TheHackersNews";
    const profile = document.getElementById('task-profile-select') ? document.getElementById('task-profile-select').value : 'all';
    const focus = document.getElementById('task-focus-select') ? document.getElementById('task-focus-select').value : 'all';

    if (mode === 'custom' && !text.trim()) {
        alert('Vui lòng nhập nội dung báo cáo cần phân tích!');
        return;
    }

    try {
        const res = await fetch('/api/agent/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                task_type: mode,
                rss_source: rssSource,
                custom_text: text,
                model_name: 'qwen2.5:7b',
                max_steps: maxSteps,
                cti_profile: profile,
                artifact_focus: focus
            })
        });

        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Lỗi khởi chạy');
        }

        const data = await res.json();
        closeStartTaskModal();

        // Switch to Monitor view and inspect new run
        switchView('monitor');
        activeRunId = data.run_id;
        loadAgentRuns();
        setTimeout(() => inspectRun(data.run_id), 500);

    } catch (e) {
        alert('Lỗi khởi động Agent: ' + e.message);
    }
}

function triggerQuickScrape() {
    document.getElementById('task-mode-select').value = 'scrape_rss';
    toggleTaskMode('scrape_rss');
    submitAgentTask();
}

// =====================================================================
// HELPER BADGE RENDERERS
// =====================================================================
function getStatusBadge(status) {
    switch (status) {
        case 'running': return '<span class="badge badge-low"><span class="status-dot pulse" style="width:6px; height:6px;"></span> RUNNING</span>';
        case 'success':
        case 'completed': return '<span class="badge badge-ok">COMPLETED</span>';
        case 'failed': return '<span class="badge badge-crit">FAILED</span>';
        default: return `<span class="badge badge-muted">${status ? status.toUpperCase() : 'UNKNOWN'}</span>`;
    }
}

function getEventBadge(eventType, status) {
    switch (eventType) {
        case 'run_started': return '<span class="badge badge-info">RUN STARTED</span>';
        case 'model_request_started': return '<span class="badge badge-muted">MODEL REQ</span>';
        case 'model_response_received': return '<span class="badge badge-low">MODEL RESP</span>';
        case 'tool_call_requested': return '<span class="badge badge-med">TOOL REQ</span>';
        case 'tool_execution_started': return '<span class="badge badge-muted">EXEC START</span>';
        case 'tool_execution_completed': return '<span class="badge badge-ok">TOOL OK</span>';
        case 'tool_execution_failed': return '<span class="badge badge-crit">TOOL ERR</span>';
        case 'validation_completed': return '<span class="badge badge-ok">VALIDATED</span>';
        case 'skill_synthesized': return '<span class="badge badge-info" style="border: 1px solid #38bdf8;">SKILL SYNTHESIZED</span>';
        case 'xai_audit_completed': return '<span class="badge badge-ok" style="border: 1px solid #10b981;">xAI AUDIT 100%</span>';
        case 'run_completed': return '<span class="badge badge-ok">RUN FINISHED</span>';
        case 'run_failed': return '<span class="badge badge-crit">RUN FAILED</span>';
        default: return `<span class="badge badge-muted">${eventType ? eventType.toUpperCase() : 'INFO'}</span>`;
    }
}

function getIocStatusBadge(status) {
    switch (status) {
        case 'verified': return '<span class="badge badge-crit">VERIFIED MALICIOUS</span>';
        case 'candidate': return '<span class="badge badge-high">CANDIDATE</span>';
        case 'observed': return '<span class="badge badge-med">OBSERVED</span>';
        case 'benign': return '<span class="badge badge-ok">BENIGN</span>';
        default: return '<span class="badge badge-muted">UNKNOWN</span>';
    }
}

function getRuleSyntaxBadge(status, errorMsg) {
    switch (status) {
        case 'valid': return '<span class="badge badge-ok">VALID SYNTAX</span>';
        case 'invalid': return `<span class="badge badge-crit" title="${escapeHtml(errorMsg || '')}">SYNTAX ERROR</span>`;
        default: return '<span class="badge badge-med">PENDING VALIDATION</span>';
    }
}

function getRuleApprovalBadge(status) {
    switch (status) {
        case 'approved': return '<span class="badge badge-ok">APPROVED</span>';
        case 'rejected': return '<span class="badge badge-crit">REJECTED</span>';
        default: return '<span class="badge badge-high">AWAITING APPROVAL</span>';
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return str.toString()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// ==================== WAZUH SIEM INTEGRATION ====================

async function checkWazuhStatus(notify = false) {
    const dot = document.getElementById('dot-wazuh');
    const text = document.getElementById('text-wazuh');
    try {
        const res = await fetch('/api/wazuh/status');
        const data = await res.json();
        if (data.connected) {
            if (dot) dot.style.background = '#22c55e'; // Neon Green
            const activeAgents = data.agents ? data.agents.active : 0;
            const totalAgents = data.agents ? data.agents.total : 0;
            if (text) text.textContent = `Wazuh: ${data.version} (${totalAgents} Agents)`;
            if (notify) {
                showToast(`Wazuh SIEM (${data.version}) đang hoạt động! Quản lý: ${data.manager_name}, Agents: ${totalAgents} (${activeAgents} Online). CDB List CTI: ${data.has_cti_list ? 'Đã nạp' : 'Chưa nạp'}.`);
            }
        } else {
            if (dot) dot.style.background = '#ef4444'; // Red
            if (text) text.textContent = 'Wazuh: Ngắt kết nối';
            if (notify) {
                showToast(`Không thể kết nối Wazuh: ${data.error || 'Server offline'}`, true);
            }
        }
    } catch (err) {
        if (dot) dot.style.background = '#ef4444';
        if (text) text.textContent = 'Wazuh: Lỗi kết nối';
        if (notify) showToast(`Lỗi gọi API Wazuh: ${err.message}`, true);
    }
}

async function syncIOCsToWazuh() {
    showToast('Đang trích xuất và đồng bộ toàn bộ IOCs sang Wazuh CDB List...');
    try {
        const res = await fetch('/api/wazuh/sync', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ statuses: ['verified', 'observed', 'candidate'] })
        });
        const data = await res.json();
        if (data.status === 'success') {
            showToast(`Thành công! Đã đồng bộ ${data.synced_count} IOCs vào Wazuh CDB List. Wazuh Manager đã reload!`);
            checkWazuhStatus(false);
        } else if (data.status === 'skipped') {
            showToast(`Bỏ qua: ${data.message}`);
        } else {
            showToast(`Đồng bộ thất bại: ${data.message}`, true);
        }
    } catch (err) {
        showToast(`Lỗi đồng bộ Wazuh: ${err.message}`, true);
    }
}

function openWazuhTestModal() {
    const modal = document.getElementById('modal-wazuh-test');
    if (modal) modal.classList.add('active');
}

function closeWazuhTestModal() {
    const modal = document.getElementById('modal-wazuh-test');
    if (modal) modal.classList.remove('active');
}

function setWazuhTestIp(ip) {
    const input = document.getElementById('wazuh-test-ip');
    if (input) input.value = ip;
}

async function runWazuhTestAlert() {
    const ip = document.getElementById('wazuh-test-ip').value.trim();
    const outputEl = document.getElementById('wazuh-test-output');
    if (!ip) {
        showToast('Vui lòng nhập địa chỉ IP cần kiểm thử.', true);
        return;
    }
    outputEl.textContent = 'Đang gửi log sự kiện tới Wazuh Engine (wazuh-logtest) để phân tích...';
    try {
        const res = await fetch('/api/wazuh/test-alert', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ test_ip: ip })
        });
        const data = await res.json();
        const testRes = data.result || {};
        if (testRes.fired_alert) {
            outputEl.style.borderColor = 'var(--neon-green)';
            outputEl.textContent = `[+] KẾT QUẢ: WAZUH PHÁT HIỆN THÀNH CÔNG VÀ KÍCH HOẠT CẢNH BÁO BẢO MẬT!\n` +
                                   `=================================================================\n\n` +
                                   testRes.output;
            showToast(`Wazuh đã kích hoạt cảnh báo với IP ${ip}!`);
        } else {
            outputEl.style.borderColor = 'var(--border-color)';
            outputEl.textContent = `[-] KẾT QUẢ: Log sự kiện không kích hoạt cảnh báo độc hại (IP không nằm trong CTI list).\n` +
                                   `=================================================================\n\n` +
                                   (testRes.output || 'Không có cảnh báo.');
        }
    } catch (err) {
        outputEl.textContent = `Lỗi kiểm thử: ${err.message}`;
    }
}

// =====================================================================
// AUTONOMOUS DEFENSE: AGENT SKILLS & ACTIVE HUNTER CONTROLLER
// =====================================================================
let currentSkillDomainFilter = 'all';
let currentViewingSkill = null;

async function loadSkills(domainFilter = null) {
    if (domainFilter !== null) {
        currentSkillDomainFilter = domainFilter;
    }
    const tbody = document.getElementById('skills-tbody');
    const badgeCount = document.getElementById('badge-skills-count');

    try {
        let url = '/api/skills';
        if (currentSkillDomainFilter && currentSkillDomainFilter !== 'all') {
            url += `?domain=${encodeURIComponent(currentSkillDomainFilter)}`;
        }
        const res = await fetch(url);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const skills = await res.json();

        if (badgeCount) badgeCount.textContent = skills.length;

        if (!skills || skills.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="empty-state">Chưa có Python Skill nào được Agent tự động sinh cho lĩnh vực "${currentSkillDomainFilter}". Hãy chạy một Run với Profile tương ứng để Agent lập trình Skill!</td></tr>`;
            return;
        }

        tbody.innerHTML = skills.map(sk => {
            const domainBadge = sk.domain === 'web' 
                ? '<span class="badge badge-info" style="border:1px solid #38bdf8;">WEB SECURITY</span>'
                : (sk.domain === 'network'
                    ? '<span class="badge badge-med" style="border:1px solid #eab308;">NETWORK SECURITY</span>'
                    : '<span class="badge badge-low">ENDPOINT</span>');

            const appStatus = sk.approval_status || 'pending_review';
            const testStatus = sk.test_status || 'passed';
            
            const appBadge = appStatus === 'approved'
                ? '<span class="badge badge-ok">APPROVED</span>'
                : (appStatus === 'rejected'
                    ? '<span class="badge badge-crit">REJECTED</span>'
                    : '<span class="badge badge-high">PENDING APPROVAL</span>');

            const testBadge = testStatus === 'passed'
                ? '<span class="badge badge-ok">SANDBOX OK</span>'
                : (testStatus === 'syntax_error' ? '<span class="badge badge-crit">SYNTAX ERR</span>' : '<span class="badge badge-high">TEST PENDING</span>');

            const lastExec = sk.last_executed ? sk.last_executed.slice(0, 19).replace('T', ' ') : 'Chưa chạy';

            const approveBtn = appStatus !== 'approved'
                ? `<button class="btn-secondary" style="padding: 3px 8px; font-size: 11px; border-color: var(--ok); color: var(--ok);" onclick="approveSkillVerification('${escapeHtml(sk.skill_name)}', 'approved')"> Duyệt</button>`
                : `<button class="btn-secondary" style="padding: 3px 8px; font-size: 11px; border-color: var(--crit); color: var(--crit);" onclick="approveSkillVerification('${escapeHtml(sk.skill_name)}', 'rejected')"> Thu Hồi</button>`;

            const hunterBtn = appStatus === 'approved'
                ? `<button class="btn-primary" style="padding: 3px 8px; font-size: 11px;" onclick="executeHunterSkill('${escapeHtml(sk.skill_name)}')">▶ Hunter</button>`
                : `<button class="btn-secondary" style="padding: 3px 8px; font-size: 11px; opacity: 0.6;" title="Kỹ năng chưa duyệt, bị chặn bởi xAI Gate" onclick="executeHunterSkill('${escapeHtml(sk.skill_name)}')"> Hunter</button>`;

            return `
                <tr>
                    <td>
                        <strong style="color: #fff; font-family: var(--font-mono);">${escapeHtml(sk.skill_name)}</strong>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 2px;">${escapeHtml(sk.description || '')}</div>
                    </td>
                    <td>${domainBadge}</td>
                    <td><span class="badge badge-low">${escapeHtml(sk.target_threat || 'General Threat')}</span></td>
                    <td>
                        <div>${testBadge}</div>
                        <div style="margin-top: 4px;">${appBadge}</div>
                    </td>
                    <td><span class="badge badge-muted">${sk.execution_count || 0} lần</span></td>
                    <td style="font-size: 11px; font-family: var(--font-mono); color: var(--text-muted);">${lastExec}</td>
                    <td>
                        <div style="display: flex; gap: 4px; flex-wrap: wrap;">
                            <button class="btn-secondary" style="padding: 3px 8px; font-size: 11px;" onclick="openSkillCodeModal('${escapeHtml(sk.skill_name)}')"> Code</button>
                            ${approveBtn}
                            ${hunterBtn}
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state">Lỗi nạp Skills: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function filterSkillsByDomain(domain) {
    currentSkillDomainFilter = domain;
    ['all', 'web', 'network', 'endpoint'].forEach(d => {
        const btn = document.getElementById(`skill-filter-btn-${d}`);
        if (btn) {
            if (d === domain) btn.classList.add('active');
            else btn.classList.remove('active');
        }
    });
    loadSkills(domain);
}

async function openSkillCodeModal(skillName) {
    try {
        const res = await fetch(`/api/skills/${encodeURIComponent(skillName)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const sk = await res.json();
        currentViewingSkill = sk;

        document.getElementById('modal-skill-name').textContent = sk.skill_name;
        document.getElementById('modal-skill-domain').textContent = (sk.domain || 'all').toUpperCase();
        document.getElementById('modal-skill-threat').textContent = sk.target_threat || 'N/A';
        document.getElementById('modal-skill-filepath').textContent = sk.file_path || `skills/generated/${sk.skill_name}.py`;
        document.getElementById('modal-skill-code-content').textContent = sk.skill_code || sk.code || '# Không có mã nguồn.';

        const approveModalBtn = document.getElementById('btn-modal-approve-skill');
        if (approveModalBtn) {
            if (sk.approval_status === 'approved') {
                approveModalBtn.textContent = ' Thu Hồi Phê Duyệt';
                approveModalBtn.style.color = 'var(--crit)';
                approveModalBtn.style.borderColor = 'var(--crit)';
            } else {
                approveModalBtn.textContent = ' Phê Duyệt Kỹ Năng Này';
                approveModalBtn.style.color = 'var(--ok)';
                approveModalBtn.style.borderColor = 'var(--ok)';
            }
        }

        document.getElementById('modal-skill-code').classList.add('open');
    } catch (e) {
        showToast('Lỗi nạp mã Skill: ' + e.message, 'error');
    }
}

async function approveCurrentSkillFromModal() {
    if (!currentViewingSkill) return;
    const name = currentViewingSkill.skill_name;
    const currentStatus = currentViewingSkill.approval_status || 'pending_review';
    const newStatus = currentStatus === 'approved' ? 'pending_review' : 'approved';
    await approveSkillVerification(name, newStatus);
    currentViewingSkill.approval_status = newStatus;
    openSkillCodeModal(name);
}

function closeSkillCodeModal() {
    document.getElementById('modal-skill-code').classList.remove('open');
}

function copySkillCode() {
    const code = document.getElementById('modal-skill-code-content').textContent;
    if (navigator.clipboard) {
        navigator.clipboard.writeText(code).then(() => {
            showToast('Đã sao chép mã Python Skill vào Clipboard!');
        });
    } else {
        showToast('Trình duyệt không hỗ trợ tự động copy.');
    }
}

function runHunterFromModal() {
    if (!currentViewingSkill) return;
    const name = currentViewingSkill.skill_name;
    closeSkillCodeModal();
    executeHunterSkill(name);
}

function appendHunterConsoleLog(msg) {
    const consoleEl = document.getElementById('hunter-console-output');
    if (!consoleEl) return;
    const time = new Date().toISOString().slice(11, 19);
    consoleEl.textContent += `\n[${time}] ${msg}`;
    consoleEl.scrollTop = consoleEl.scrollHeight;
}

function handleHunterTargetDirChange(val) {
    const container = document.getElementById('hunter-custom-dir-container');
    if (container) {
        if (val === 'custom') {
            container.style.display = 'flex';
            const input = document.getElementById('hunter-custom-dir-input');
            if (input) input.focus();
        } else {
            container.style.display = 'none';
        }
    }
}

function getEffectiveHunterTargetPath() {
    const select = document.getElementById('hunter-target-dir-select');
    if (!select) return 'cti_framework/sandbox/web_root';
    if (select.value === 'custom') {
        const input = document.getElementById('hunter-custom-dir-input');
        const customVal = input ? input.value.trim() : '';
        return customVal || '.';
    }
    return select.value;
}

async function executeHunterSkill(skillName, targetParams = null) {
    const selectedPath = (targetParams && targetParams.target_path) ? targetParams.target_path : getEffectiveHunterTargetPath();
    const finalParams = Object.assign({ target_path: selectedPath }, targetParams || {});

    const statusBadge = document.getElementById('hunter-status-badge');
    if (statusBadge) {
        statusBadge.className = 'badge badge-low pulse';
        statusBadge.textContent = 'EXECUTING SKILL...';
    }

    appendHunterConsoleLog(`=======================================================`);
    appendHunterConsoleLog(`[Hunter Agent] Đang khởi chạy kỹ năng: ${skillName}`);
    appendHunterConsoleLog(`[Hunter Agent] Mục tiêu kiểm toán: [${selectedPath}]`);
    appendHunterConsoleLog(`[Hunter Agent] Nạp module độc lập từ cti_framework/skills/generated/${skillName}.py...`);

    try {
        const res = await fetch('/api/hunter/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                skill_name: skillName,
                target_params: finalParams
            })
        });

        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Lỗi thực thi Hunter Agent');
        }

        const data = await res.json();
        const result = data.action_result || data.result || {};
        const statusText = typeof result === 'string' ? result : (result.status || data.status || 'DONE');
        appendHunterConsoleLog(`[Hunter Agent] Trạng thái: ${statusText} (${data.execution_time_ms || 0}ms)`);
        appendHunterConsoleLog(`[Hunter Agent] Báo cáo chi tiết: ${typeof result === 'object' ? JSON.stringify(result, null, 2) : result}`);

        if (result.findings && result.findings.length > 0) {
            result.findings.forEach(f => {
                appendHunterConsoleLog(`  🚨 [PHÁT HIỆN MÃ ĐỘC] 📁 Tệp: ${f.file} (📌 Dòng ${f.line}) | 🛑 Chữ ký: ${f.threat_signature}`);
                appendHunterConsoleLog(`     ⚠️ Đoạn mã nguy hiểm: "${f.evidence_snippet}"`);
            });
        } else {
            appendHunterConsoleLog(`  ✅ [AN TOÀN] Không phát hiện dấu hiệu mã độc nào trong thư mục mục tiêu.`);
        }

        if (result.status === 'THREAT_FOUND' || (result.findings && result.findings.length > 0)) {
            if (statusBadge) {
                statusBadge.className = 'badge badge-crit';
                statusBadge.textContent = 'ALERT: THREAT DETECTED';
            }
            showToast(` Hunter Agent phát hiện nguy cơ bảo mật với skill ${skillName}!`, true);
        } else {
            if (statusBadge) {
                statusBadge.className = 'badge badge-ok';
                statusBadge.textContent = 'STANDBY (ALL CLEAN)';
            }
            showToast(` Hunter Agent đã chạy xong skill ${skillName}. Không phát hiện mối đe dọa.`);
        }

        loadSkills(currentSkillDomainFilter);

    } catch (e) {
        appendHunterConsoleLog(`[Hunter Agent]  LỖI NGOẠI LỆ: ${e.message}`);
        if (statusBadge) {
            statusBadge.className = 'badge badge-crit';
            statusBadge.textContent = 'EXECUTION ERROR';
        }
        showToast('Lỗi chạy Hunter: ' + e.message, true);
    }
}

async function triggerDomainHunt(domain, targetPath = null) {
    if (currentView !== 'skills') {
        switchView('skills');
    }

    const finalPath = targetPath || getEffectiveHunterTargetPath();

    const statusBadge = document.getElementById('hunter-status-badge');
    if (statusBadge) {
        statusBadge.className = 'badge badge-low pulse';
        statusBadge.textContent = `HUNTING DOMAIN: ${domain.toUpperCase()}`;
    }

    appendHunterConsoleLog(`=======================================================`);
    appendHunterConsoleLog(`[Hunter Agent] Bắt đầu chiến dịch tự động rà quét lĩnh vực: [${domain.toUpperCase()}]`);
    appendHunterConsoleLog(`[Hunter Agent] Thư mục mục tiêu: [${finalPath}]`);

    try {
        const res = await fetch('/api/hunter/hunt-domain', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                domain: domain,
                target_path: finalPath
            })
        });

        if (!res.ok) {
            const err = await res.json();
            throw new Error(err.detail || 'Lỗi Domain Hunt');
        }

        const data = await res.json();
        const total = data.total_skills_executed || data.skills_executed || (data.results ? data.results.length : 0);
        appendHunterConsoleLog(`[Hunter Agent] Hoàn thành rà quét! Tổng kỹ năng đã chạy: ${total}`);

        let anyThreat = false;
        const resultsList = data.results || data.reports || [];
        if (resultsList.length > 0) {
            resultsList.forEach(r => {
                const sName = r.skill_name || 'Skill';
                const resObj = r.action_result || r.result || {};
                const resStatus = typeof resObj === 'string' ? resObj : (resObj.status || 'OK');
                appendHunterConsoleLog(`-> Kỹ năng [${sName}]: ${resStatus}`);

                if (resObj.findings && resObj.findings.length > 0) {
                    anyThreat = true;
                    resObj.findings.forEach(f => {
                        appendHunterConsoleLog(`  🚨 [PHÁT HIỆN MÃ ĐỘC] 📁 Tệp: ${f.file} (📌 Dòng ${f.line}) | 🛑 Chữ ký: ${f.threat_signature}`);
                        if (f.evidence_snippet) {
                            appendHunterConsoleLog(`     ⚠️ Đoạn mã nguy hiểm: "${f.evidence_snippet}"`);
                        }
                    });
                } else {
                    appendHunterConsoleLog(`  ✅ [KỸ NĂNG SẠCH] Kỹ năng [${sName}] không phát hiện mối đe dọa.`);
                }
            });
        }

        if (statusBadge) {
            statusBadge.className = anyThreat ? 'badge badge-crit' : 'badge badge-ok';
            statusBadge.textContent = anyThreat ? 'ALERT: THREAT DETECTED' : 'STANDBY';
        }

        showToast(`Chiến dịch rà quét ${domain.toUpperCase()} hoàn tất. Đã thực thi ${total} skills.`);
        loadSkills(domain);

    } catch (e) {
        appendHunterConsoleLog(`[Hunter Agent]  LỖI CHIẾN DỊCH: ${e.message}`);
        if (statusBadge) {
            statusBadge.className = 'badge badge-crit';
            statusBadge.textContent = 'ERROR';
        }
    }
}

