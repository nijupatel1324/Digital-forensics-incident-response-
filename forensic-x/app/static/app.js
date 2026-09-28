/**
 * FORENSIC-X — Interactive Frontend Controller
 * app/static/app.js
 *
 * Premium SOC Dashboard with Chart.js analytics, visual timeline,
 * threat matrix, activity feed, and toast notifications.
 */

const API_BASE = "/api/v1";
let authToken = localStorage.getItem("forensicx_token") || null;
let currentCaseId = null;
let currentUser = null;
let severityChart = null;
let iocTypeChart = null;
let allCasesCache = [];
let allIOCsCache = [];
let timelineVisualMode = false;
let timelineEventsCache = [];

document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    checkAuth();
    setupEventListeners();
});

// ── Toast Notifications ──────────────────────────────────────
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    const icons = { success: "&#10003;", error: "&#10007;", info: "&#8505;", warning: "&#9888;" };
    toast.innerHTML = `<span>${icons[type] || icons.info}</span> ${escapeHtml(message)}`;
    container.appendChild(toast);
    setTimeout(() => { if (toast.parentNode) toast.remove(); }, 4200);
}

// ── Tab Management ───────────────────────────────────────────
function initTabs() {
    const tabBtns = document.querySelectorAll(".nav-tab-btn");
    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            tabBtns.forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            const targetId = btn.getAttribute("data-tab");
            const targetPanel = document.getElementById(targetId);
            if (targetPanel) {
                targetPanel.classList.add("active");
                loadTabContent(targetId);
            }
        });
    });
}

function loadTabContent(tabId) {
    if (!authToken) return;
    switch (tabId) {
        case "overview-tab":
            loadOverview();
            break;
        case "cases-tab":
            loadCases();
            break;
        case "evidence-tab":
            loadEvidence();
            break;
        case "timeline-tab":
            loadTimeline();
            break;
        case "iocs-tab":
            loadIOCsAndAlerts();
            break;
        case "incidents-tab":
            loadIncidents();
            break;
        case "reports-tab":
            break;
    }
}

// ── Authentication ───────────────────────────────────────────
async function checkAuth() {
    if (!authToken) {
        showLoginModal();
        return;
    }
    try {
        const res = await fetch(`${API_BASE}/users/me`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        if (res.ok) {
            currentUser = await res.json();
            updateUserUI();
            loadOverview();
        } else {
            logout();
        }
    } catch (e) {
        console.error("Auth check failed:", e);
        showLoginModal();
    }
}

function updateUserUI() {
    const userDisplay = document.getElementById("user-display");
    if (userDisplay && currentUser) {
        userDisplay.textContent = `${currentUser.full_name} (${currentUser.is_superuser ? "Superadmin" : "Analyst"})`;
    }
}

function showLoginModal() {
    const modal = document.getElementById("login-modal");
    if (modal) modal.classList.add("active");
}

function hideLoginModal() {
    const modal = document.getElementById("login-modal");
    if (modal) modal.classList.remove("active");
}

async function handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById("login-email").value;
    const password = document.getElementById("login-password").value;
    const errorElem = document.getElementById("login-error");

    const formData = new URLSearchParams();
    formData.append("username", email);
    formData.append("password", password);

    try {
        const res = await fetch(`${API_BASE}/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: formData.toString()
        });

        if (res.ok) {
            const data = await res.json();
            authToken = data.access_token;
            localStorage.setItem("forensicx_token", authToken);
            hideLoginModal();
            showToast("Authentication successful. Welcome back.", "success");
            checkAuth();
        } else {
            const err = await res.json();
            if (errorElem) {
                errorElem.textContent = err.detail || "Authentication failed.";
                errorElem.style.display = "block";
            }
        }
    } catch (err) {
        if (errorElem) {
            errorElem.textContent = "Network error connecting to API.";
            errorElem.style.display = "block";
        }
    }
}

function logout() {
    authToken = null;
    localStorage.removeItem("forensicx_token");
    showLoginModal();
}

// ── Overview & Statistics ────────────────────────────────────
async function loadOverview() {
    try {
        const [casesRes, iocsRes, rulesRes] = await Promise.all([
            fetch(`${API_BASE}/cases?page_size=50`, { headers: { Authorization: `Bearer ${authToken}` } }),
            fetch(`${API_BASE}/iocs?page_size=100`, { headers: { Authorization: `Bearer ${authToken}` } }),
            fetch(`${API_BASE}/detection/rules`, { headers: { Authorization: `Bearer ${authToken}` } }),
        ]);

        if (casesRes.ok) {
            const casesData = await casesRes.json();
            allCasesCache = casesData.items || [];
            document.getElementById("stat-cases-count").textContent = casesData.total;
            renderOverviewCases(allCasesCache.slice(0, 5));
            populateCaseSelectors(allCasesCache);
            renderSeverityChart(allCasesCache);
        }

        if (iocsRes.ok) {
            const iocsData = await iocsRes.json();
            allIOCsCache = iocsData.items || [];
            document.getElementById("stat-iocs-count").textContent = iocsData.total;
            renderIOCTypeChart(allIOCsCache);
        }

        if (rulesRes.ok) {
            const rulesData = await rulesRes.json();
            document.getElementById("stat-rules-count").textContent = rulesData.length;
        }

        renderActivityFeed();
    } catch (e) {
        console.error("Failed to load overview:", e);
    }
}

// ── Chart.js: Severity Distribution ──────────────────────────
function renderSeverityChart(cases) {
    const ctx = document.getElementById("chart-severity");
    if (!ctx) return;

    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    cases.forEach(c => {
        const p = (c.priority || "medium").toLowerCase();
        if (counts[p] !== undefined) counts[p]++;
    });

    if (severityChart) severityChart.destroy();

    severityChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: ["Critical", "High", "Medium", "Low"],
            datasets: [{
                data: [counts.critical, counts.high, counts.medium, counts.low],
                backgroundColor: [
                    "rgba(239, 68, 68, 0.8)",
                    "rgba(249, 115, 22, 0.8)",
                    "rgba(245, 158, 11, 0.8)",
                    "rgba(59, 130, 246, 0.8)"
                ],
                borderColor: [
                    "rgba(239, 68, 68, 1)",
                    "rgba(249, 115, 22, 1)",
                    "rgba(245, 158, 11, 1)",
                    "rgba(59, 130, 246, 1)"
                ],
                borderWidth: 2,
                hoverOffset: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "65%",
            plugins: {
                legend: {
                    position: "bottom",
                    labels: { color: "#94a3b8", font: { size: 11, family: "Inter" }, padding: 16, usePointStyle: true, pointStyleWidth: 10 }
                }
            },
            animation: { animateRotate: true, animateScale: true, duration: 800 }
        }
    });
}

// ── Chart.js: IOC Type Breakdown ─────────────────────────────
function renderIOCTypeChart(iocs) {
    const ctx = document.getElementById("chart-ioc-types");
    if (!ctx) return;

    const typeCounts = {};
    iocs.forEach(ioc => {
        const t = ioc.ioc_type || "unknown";
        typeCounts[t] = (typeCounts[t] || 0) + 1;
    });

    const labels = Object.keys(typeCounts);
    const data = Object.values(typeCounts);
    const colors = [
        "rgba(244,63,94,0.75)", "rgba(245,158,11,0.75)", "rgba(168,85,247,0.75)",
        "rgba(59,130,246,0.75)", "rgba(6,182,212,0.75)", "rgba(16,185,129,0.75)",
        "rgba(99,102,241,0.75)", "rgba(236,72,153,0.75)"
    ];

    if (iocTypeChart) iocTypeChart.destroy();

    iocTypeChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: labels.map(l => l.replace(/_/g, " ").replace(/file hash/i, "Hash")),
            datasets: [{
                label: "Count",
                data: data,
                backgroundColor: colors.slice(0, labels.length),
                borderColor: colors.slice(0, labels.length).map(c => c.replace("0.75", "1")),
                borderWidth: 1,
                borderRadius: 6,
                borderSkipped: false,
                barPercentage: 0.65
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: "y",
            scales: {
                x: {
                    grid: { color: "rgba(51,65,85,0.2)", drawBorder: false },
                    ticks: { color: "#64748b", font: { size: 10, family: "Inter" } }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: "#94a3b8", font: { size: 11, family: "Inter" } }
                }
            },
            plugins: {
                legend: { display: false }
            },
            animation: { duration: 700 }
        }
    });
}

// ── Activity Feed ────────────────────────────────────────────
function renderActivityFeed() {
    const feed = document.getElementById("activity-feed");
    if (!feed) return;

    const activities = [];

    allCasesCache.forEach(c => {
        activities.push({
            icon: "case",
            emoji: "&#128193;",
            text: `Case <b>${escapeHtml(c.case_number)}</b> created: ${escapeHtml(c.name)}`,
            time: c.created_at
        });
    });

    allIOCsCache.forEach(ioc => {
        activities.push({
            icon: "ioc",
            emoji: "&#127919;",
            text: `IOC flagged: <span class="code-font" style="color:var(--accent-cyan)">${escapeHtml(ioc.value)}</span> (${ioc.ioc_type})`,
            time: ioc.created_at
        });
    });

    activities.sort((a, b) => new Date(b.time) - new Date(a.time));

    feed.innerHTML = "";
    const displayItems = activities.slice(0, 12);

    if (displayItems.length === 0) {
        feed.innerHTML = `<div class="feed-item"><div class="feed-body"><div class="feed-text" style="color:var(--text-muted)">No activity yet. Create a case to get started.</div></div></div>`;
        return;
    }

    displayItems.forEach(a => {
        const item = document.createElement("div");
        item.className = "feed-item";
        const timeStr = a.time ? new Date(a.time).toLocaleString() : "";
        item.innerHTML = `
                <div class="feed-icon ${a.icon}">${a.emoji}</div>
                <div class="feed-body">
                    <div class="feed-text">${a.text}</div>
                    <div class="feed-time">${timeStr}</div>
                </div>
            `;
        feed.appendChild(item);
    });
}

// ── Case Rendering & Selectors ───────────────────────────────
function renderOverviewCases(cases) {
    const tbody = document.getElementById("recent-cases-table");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (!cases || cases.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted)">No cases found. Create your first case above!</td></tr>`;
        return;
    }

    cases.forEach(c => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
                <td><span class="code-font font-bold">${c.case_number}</span></td>
                <td><b>${escapeHtml(c.name)}</b></td>
                <td><span class="badge badge-${c.priority}">${c.priority}</span></td>
                <td><span class="badge badge-info">${c.status}</span></td>
                <td><button class="btn btn-outline btn-sm" onclick="selectCase('${c.id}')">Select</button></td>
            `;
        tbody.appendChild(tr);
    });
}

function populateCaseSelectors(cases) {
    const selectors = document.querySelectorAll(".case-selector");
    selectors.forEach(sel => {
        const currentVal = sel.value;
        sel.innerHTML = `<option value="">-- Select Active Case --</option>`;
        cases.forEach(c => {
            const opt = document.createElement("option");
            opt.value = c.id;
            opt.textContent = `[${c.case_number}] ${c.name}`;
            if (c.id === currentCaseId) opt.selected = true;
            sel.appendChild(opt);
        });
    });
}

function selectCase(caseId) {
    currentCaseId = caseId;
    const selectors = document.querySelectorAll(".case-selector");
    selectors.forEach(s => s.value = caseId);

    const activeTab = document.querySelector(".nav-tab-btn.active")?.getAttribute("data-tab");
    if (activeTab) loadTabContent(activeTab);

    const c = allCasesCache.find(x => x.id === caseId);
    if (c) showToast(`Active case: ${c.case_number}`, "info");
}

// ── Cases Management ─────────────────────────────────────────
async function loadCases() {
    try {
        const res = await fetch(`${API_BASE}/cases?page_size=50`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        if (res.ok) {
            const data = await res.json();
            const tbody = document.getElementById("all-cases-table");
            if (!tbody) return;
            tbody.innerHTML = "";

            data.items.forEach(c => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                        <td><span class="code-font font-bold">${c.case_number}</span></td>
                        <td><b>${escapeHtml(c.name)}</b><br><small style="color:var(--text-muted)">${escapeHtml(c.description || "")}</small></td>
                        <td><span class="badge badge-${c.priority}">${c.priority}</span></td>
                        <td><span class="badge badge-info">${c.classification}</span></td>
                        <td><span class="badge badge-success">${c.status}</span></td>
                        <td>
                            <button class="btn btn-outline btn-sm" onclick="selectCase('${c.id}')">Investigate</button>
                        </td>
                    `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        console.error("Failed to load cases:", e);
    }
}

async function handleCreateCase(e) {
    e.preventDefault();
    const name = document.getElementById("case-name").value;
    const description = document.getElementById("case-desc").value;
    const priority = document.getElementById("case-priority").value;
    const classification = document.getElementById("case-classification").value;

    try {
        const res = await fetch(`${API_BASE}/cases`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${authToken}`,
            },
            body: JSON.stringify({ name, description, priority, classification })
        });

        if (res.ok) {
            const created = await res.json();
            currentCaseId = created.id;
            loadCases();
            loadOverview();
            hideModal("create-case-modal");
            document.getElementById("create-case-form").reset();
            showToast(`Case ${created.case_number} created successfully.`, "success");
        }
    } catch (e) {
        console.error("Create case error:", e);
        showToast("Failed to create case.", "error");
    }
}

// ── Evidence Vault ───────────────────────────────────────────
async function loadEvidence() {
    const caseId = currentCaseId || document.getElementById("evidence-case-select")?.value;
    if (!caseId) {
        document.getElementById("evidence-table").innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">Please select a Case above to view evidence artifacts.</td></tr>`;
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/cases/${caseId}/evidence`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        if (res.ok) {
            const data = await res.json();
            const tbody = document.getElementById("evidence-table");
            tbody.innerHTML = "";

            if (data.items.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">No evidence items uploaded yet. Use the upload button above.</td></tr>`;
                return;
            }

            data.items.forEach(ev => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                        <td><span class="code-font">${ev.evidence_number}</span></td>
                        <td><b>${escapeHtml(ev.name)}</b><br><small class="code-font" style="color:var(--text-muted)">${escapeHtml(ev.original_filename)}</small></td>
                        <td><span class="badge badge-info">${ev.source_type}</span></td>
                        <td>${(ev.size_bytes / 1024).toFixed(1)} KB</td>
                        <td><span class="code-font" style="font-size:0.72rem; color:var(--accent-cyan)">${ev.sha256 ? ev.sha256.substring(0, 16) + '...' : 'N/A'}</span></td>
                        <td>
                            <button class="btn btn-outline btn-sm" onclick="analyzeEvidence('${ev.id}')">Analyze</button>
                            <button class="btn btn-outline btn-sm" onclick="verifyEvidence('${ev.id}')">Verify</button>
                        </td>
                    `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        console.error("Load evidence error:", e);
    }
}

async function handleUploadEvidence(e) {
    e.preventDefault();
    const caseId = currentCaseId || document.getElementById("evidence-case-select")?.value;
    if (!caseId) {
        showToast("Please select a Case first!", "warning");
        return;
    }

    const fileInput = document.getElementById("upload-file");
    const nameInput = document.getElementById("upload-name");
    const sourceSelect = document.getElementById("upload-source-type");

    if (!fileInput.files.length) {
        showToast("Please choose a file to upload.", "warning");
        return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    formData.append("name", nameInput.value || fileInput.files[0].name);
    formData.append("source_type", sourceSelect.value);

    try {
        const res = await fetch(`${API_BASE}/cases/${caseId}/evidence/upload`, {
            method: "POST",
            headers: { Authorization: `Bearer ${authToken}` },
            body: formData,
        });

        if (res.ok) {
            hideModal("upload-evidence-modal");
            document.getElementById("upload-evidence-form").reset();
            loadEvidence();
            showToast("Evidence ingested. Cryptographic hashes computed.", "success");
        } else {
            const err = await res.json();
            showToast("Upload failed: " + (err.detail || "Unknown error"), "error");
        }
    } catch (e) {
        console.error("Upload error:", e);
        showToast("Upload network error.", "error");
    }
}

async function analyzeEvidence(evidenceId) {
    showToast("Running forensic analysis...", "info");
    try {
        const res = await fetch(`${API_BASE}/evidence/${evidenceId}/analyze`, {
            method: "POST",
            headers: { Authorization: `Bearer ${authToken}` }
        });
        if (res.ok) {
            const result = await res.json();
            showToast(`Analysis complete! Parser: ${result.parser_used}, Events: ${result.events_extracted}`, "success");
            loadTimeline();
        } else {
            const err = await res.json();
            showToast("Analysis error: " + err.detail, "error");
        }
    } catch (e) {
        console.error("Analyze error:", e);
        showToast("Analysis request failed.", "error");
    }
}

async function verifyEvidence(evidenceId) {
    showToast("Verifying cryptographic integrity...", "info");
    try {
        const res = await fetch(`${API_BASE}/evidence/${evidenceId}/verify`, {
            method: "POST",
            headers: { Authorization: `Bearer ${authToken}` }
        });
        if (res.ok) {
            const result = await res.json();
            if (result.is_intact) {
                showToast("Integrity VERIFIED: SHA-256 checksum matches.", "success");
            } else {
                showToast("INTEGRITY FAILURE: Evidence may be tampered!", "error");
            }
        }
    } catch (e) {
        console.error("Verify error:", e);
    }
}

// ── Timeline Explorer ────────────────────────────────────────
async function loadTimeline() {
    const caseId = currentCaseId || document.getElementById("timeline-case-select")?.value;
    if (!caseId) {
        document.getElementById("timeline-table").innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">Please select a Case above to explore timeline events.</td></tr>`;
        document.getElementById("visual-timeline-container").innerHTML = `<p style="color: var(--text-muted); font-size: 0.85rem;">Select a case to visualize the attack timeline.</p>`;
        return;
    }

    const search = document.getElementById("timeline-search")?.value || "";
    const severity = document.getElementById("timeline-severity-filter")?.value || "";

    let url = `${API_BASE}/cases/${caseId}/timeline?page_size=100`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    if (severity) url += `&severity=${encodeURIComponent(severity)}`;

    try {
        const res = await fetch(url, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        if (res.ok) {
            const data = await res.json();
            timelineEventsCache = data.items || [];
            renderTimelineTable(timelineEventsCache);
            renderVisualTimeline(timelineEventsCache);
        }
    } catch (e) {
        console.error("Load timeline error:", e);
    }
}

function renderTimelineTable(events) {
    const tbody = document.getElementById("timeline-table");
    tbody.innerHTML = "";

    if (events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">No timeline events matching query. Ingest logs or add manual notes.</td></tr>`;
        return;
    }

    events.forEach(e => {
        const tr = document.createElement("tr");
        const sevClass = e.severity.toLowerCase();
        tr.innerHTML = `
                <td><span class="code-font" style="font-size:0.72rem">${e.event_timestamp ? e.event_timestamp.substring(0, 19).replace("T", " ") : ""}</span></td>
                <td><span class="badge badge-info">${escapeHtml(e.source)}</span></td>
                <td><span class="badge badge-low">${escapeHtml(e.event_type)}</span></td>
                <td><span class="badge badge-${sevClass}">${e.severity}</span></td>
                <td>${escapeHtml(e.description)}</td>
                <td>${e.is_ioc_matched ? '<span class="badge badge-critical">IOC MATCH</span>' : '<span style="color:var(--text-muted)">-</span>'}</td>
            `;
        tbody.appendChild(tr);
    });
}

function renderVisualTimeline(events) {
    const container = document.getElementById("visual-timeline-container");
    if (!container) return;
    container.innerHTML = "";

    if (events.length === 0) {
        container.innerHTML = `<p style="color: var(--text-muted); font-size: 0.85rem;">No events to display.</p>`;
        return;
    }

    events.forEach(e => {
        const node = document.createElement("div");
        const sevClass = e.severity.toLowerCase();
        node.className = `timeline-node ${sevClass}`;

        const ts = e.event_timestamp ? e.event_timestamp.substring(0, 19).replace("T", " ") : "Unknown time";
        const tags = [];
        if (e.source) tags.push(`<span class="badge badge-info">${escapeHtml(e.source)}</span>`);
        if (e.event_type) tags.push(`<span class="badge badge-low">${escapeHtml(e.event_type)}</span>`);
        if (e.is_ioc_matched) tags.push(`<span class="badge badge-critical">IOC MATCH</span>`);
        if (e.mitre_technique) tags.push(`<span class="badge badge-purple">${escapeHtml(e.mitre_technique)}</span>`);

        node.innerHTML = `
                <div class="timeline-card">
                    <div class="timeline-time">${ts} UTC</div>
                    <div class="timeline-event-title"><span class="badge badge-${sevClass}">${e.severity}</span> ${escapeHtml(e.event_type || "Event")}</div>
                    <div class="timeline-event-desc">${escapeHtml(e.description)}</div>
                    <div class="timeline-tags">${tags.join("")}</div>
                </div>
            `;
        container.appendChild(node);
    });
}

function toggleTimelineView() {
    timelineVisualMode = !timelineVisualMode;
    const tableView = document.getElementById("timeline-table-view");
    const visualView = document.getElementById("timeline-visual-view");
    const toggleBtn = document.getElementById("toggle-timeline-view");

    if (timelineVisualMode) {
        tableView.style.display = "none";
        visualView.style.display = "block";
        toggleBtn.textContent = "Table View";
    } else {
        tableView.style.display = "block";
        visualView.style.display = "none";
        toggleBtn.textContent = "Visual View";
    }
}

// ── IOCs & Detection Alerts ──────────────────────────────────
async function loadIOCsAndAlerts() {
    try {
        const [iocsRes, rulesRes] = await Promise.all([
            fetch(`${API_BASE}/iocs?page_size=100`, { headers: { Authorization: `Bearer ${authToken}` } }),
            fetch(`${API_BASE}/detection/rules`, { headers: { Authorization: `Bearer ${authToken}` } })
        ]);

        if (iocsRes.ok) {
            const data = await iocsRes.json();
            allIOCsCache = data.items || [];

            // Update threat matrix
            updateThreatMatrix(allIOCsCache);

            const tbody = document.getElementById("iocs-table");
            tbody.innerHTML = "";

            if (allIOCsCache.length === 0) {
                tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No IOCs registered yet.</td></tr>`;
            } else {
                allIOCsCache.forEach(ioc => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                            <td><span class="badge badge-info">${ioc.ioc_type}</span></td>
                            <td><span class="code-font" style="color:var(--accent-cyan)">${escapeHtml(ioc.value)}</span></td>
                            <td>${escapeHtml(ioc.threat_type)}</td>
                            <td><span class="badge badge-${ioc.severity}">${ioc.severity}</span></td>
                            <td><span class="badge badge-medium">TLP:${ioc.tlp.toUpperCase()}</span></td>
                        `;
                    tbody.appendChild(tr);
                });
            }
        }

        if (rulesRes.ok) {
            const rules = await rulesRes.json();
            const tbody = document.getElementById("detection-rules-table");
            tbody.innerHTML = "";

            if (rules.length === 0) {
                tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No detection rules configured.</td></tr>`;
            } else {
                rules.forEach(r => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                            <td><b>${escapeHtml(r.name)}</b></td>
                            <td><span class="badge badge-purple">${r.mitre_technique || "N/A"}</span></td>
                            <td><span class="badge badge-${r.severity}">${r.severity}</span></td>
                            <td><span class="code-font" style="font-size:0.72rem">${escapeHtml(r.pattern.substring(0, 45))}${r.pattern.length > 45 ? '...' : ''}</span></td>
                        `;
                    tbody.appendChild(tr);
                });
            }
        }
    } catch (e) {
        console.error("IOC/Detection load error:", e);
    }
}

function updateThreatMatrix(iocs) {
    const counts = { ip: 0, domain: 0, hash: 0, email: 0, url: 0, mutex: 0 };
    iocs.forEach(ioc => {
        const t = (ioc.ioc_type || "").toLowerCase();
        if (t.includes("ip")) counts.ip++;
        else if (t.includes("domain")) counts.domain++;
        else if (t.includes("hash") || t.includes("sha") || t.includes("md5")) counts.hash++;
        else if (t.includes("email")) counts.email++;
        else if (t.includes("url")) counts.url++;
        else if (t.includes("mutex") || t.includes("registry")) counts.mutex++;
    });

    const matrix = document.getElementById("threat-matrix");
    if (!matrix) return;
    const cells = matrix.querySelectorAll(".threat-cell");
    const order = ["ip", "domain", "hash", "email", "url", "mutex"];
    cells.forEach((cell, i) => {
        const key = order[i];
        if (key && counts[key] !== undefined) {
            cell.querySelector(".count").textContent = counts[key];
        }
    });
}

async function handleRunDetectionScan() {
    const caseId = currentCaseId || document.getElementById("iocs-case-select")?.value;
    if (!caseId) {
        showToast("Please select a Case to run the Detection Scan!", "warning");
        return;
    }

    showToast("Running IOC & rule-based detection scan...", "info");

    try {
        const [iocRes, ruleRes] = await Promise.all([
            fetch(`${API_BASE}/cases/${caseId}/iocs/scan`, { method: "POST", headers: { Authorization: `Bearer ${authToken}` } }),
            fetch(`${API_BASE}/cases/${caseId}/detection/scan`, { method: "POST", headers: { Authorization: `Bearer ${authToken}` } }),
        ]);

        if (iocRes.ok && ruleRes.ok) {
            const iocData = await iocRes.json();
            const alertsData = await ruleRes.json();
            showToast(`Scan complete! IOC Matches: ${iocData.matches_found}, Rule Alerts: ${alertsData.length}`, "success");
            loadTimeline();
        }
    } catch (e) {
        console.error("Scan error:", e);
        showToast("Detection scan failed.", "error");
    }
}

// ── Incidents ────────────────────────────────────────────────
async function loadIncidents() {
    try {
        const res = await fetch(`${API_BASE}/incidents?page_size=20`, {
            headers: { Authorization: `Bearer ${authToken}` }
        });
        if (res.ok) {
            const data = await res.json();
            const tbody = document.getElementById("incidents-table");
            tbody.innerHTML = "";

            if (!data.items || data.items.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">No incidents registered.</td></tr>`;
                return;
            }

            data.items.forEach(inc => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                        <td><span class="code-font font-bold">${inc.incident_number}</span></td>
                        <td><b>${escapeHtml(inc.title)}</b></td>
                        <td><span class="badge badge-${inc.severity}">${inc.severity}</span></td>
                        <td><span class="badge badge-info">${inc.phase}</span></td>
                        <td><span class="badge badge-success">${inc.status}</span></td>
                        <td>${inc.tasks.length} tasks</td>
                    `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        console.error("Incidents load error:", e);
    }
}

// ── Reports ──────────────────────────────────────────────────
function downloadReport(format) {
    const caseId = currentCaseId || document.getElementById("reports-case-select")?.value;
    if (!caseId) {
        showToast("Please select an active Case to generate reports.", "warning");
        return;
    }
    showToast(`Generating ${format.toUpperCase()} report...`, "info");
    const url = `${API_BASE}/cases/${caseId}/reports/${format}`;
    window.open(url, "_blank");
}

// ── Helpers ──────────────────────────────────────────────────
function showModal(id) {
    const m = document.getElementById(id);
    if (m) m.classList.add("active");
}

function hideModal(id) {
    const m = document.getElementById(id);
    if (m) m.classList.remove("active");
}

function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function setupEventListeners() {
    document.getElementById("login-form")?.addEventListener("submit", handleLogin);
    document.getElementById("create-case-form")?.addEventListener("submit", handleCreateCase);
    document.getElementById("upload-evidence-form")?.addEventListener("submit", handleUploadEvidence);
    document.getElementById("logout-btn")?.addEventListener("click", logout);
    document.getElementById("toggle-timeline-view")?.addEventListener("click", toggleTimelineView);

    document.querySelectorAll(".case-selector").forEach(sel => {
        sel.addEventListener("change", (e) => selectCase(e.target.value));
    });
}
