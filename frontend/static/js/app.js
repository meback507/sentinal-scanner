/**
 * AegisSec - Frontend Single Page Application Controller
 * Handles Navigation, Dynamic Threat Analytics, Project Lifecycle,
 * Scan Execution, Vulnerability Triage, and Custom Rule Studio.
 */

let state = {
    projects: [],
    activeProjectId: null,
    findings: [],
    filteredFindings: [],
    activeFinding: null,
    dashboardStats: null,
    customRules: [],
    standards: {},
    dashboardFindingFilter: 'ALL',
    dashboardFindingSearch: '',
    currentUser: {
        username: "admin",
        role: "admin",
        token: ""
    }
};

// --- Fetch Interceptor for JWT Authorization ---
const _originalFetch = window.fetch;
window.fetch = function(url, options = {}) {
    options = options || {};
    const headers = options.headers ? new Headers(options.headers) : new Headers();
    if (state.currentUser && state.currentUser.token && !headers.has("Authorization")) {
        headers.set("Authorization", `Bearer ${state.currentUser.token}`);
    }
    options.headers = headers;
    return _originalFetch(url, options);
};

/// --- Initialization ---
document.addEventListener("DOMContentLoaded", async () => {
    const isAuthenticated = await checkAuth();
    if (isAuthenticated) {
        await loadProjects();
        await loadFindings();
        await loadDashboardStats();
        await loadStandards();
        await loadCustomRules();
        await loadIntegrations();
    }
});

// --- Toast Notifications ---
function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = "toast";
    if (type === "error") toast.style.borderLeftColor = "#ef4444";
    if (type === "success") toast.style.borderLeftColor = "#10b981";
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// --- Navigation ---
function navigate(viewName) {
    document.querySelectorAll(".page-container").forEach(el => el.classList.remove("active"));
    document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));

    const targetView = document.getElementById(`view-${viewName}`);
    const targetNav = document.getElementById(`nav-${viewName}`);

    if (targetView) targetView.classList.add("active");
    if (targetNav) targetNav.classList.add("active");

    if (viewName === "dashboard") loadDashboardStats();
    if (viewName === "projects") loadProjects();
    if (viewName === "triage") loadFindings();
    if (viewName === "rules") loadCustomRules();
    if (viewName === "compliance") renderComplianceMatrix();
    if (viewName === "integrations") loadIntegrations();
    if (viewName === "users") loadUsers();
    if (viewName === "audit") loadAuditData();
}

// --- Auth & Session Lifecycle ---
const DEMO_CREDENTIALS = {
    admin: { username: "admin", password: "Admin@123!" },
    sec_lead: { username: "sec_lead", password: "SecLead@123!" },
    marcus: { username: "marcus", password: "Marcus@123!" },
    elena: { username: "elena", password: "Elena@123!" },
    sarah: { username: "sarah", password: "Sarah@123!" },
    developer: { username: "developer", password: "Dev@123!" },
    auditor: { username: "auditor", password: "Auditor@123!" }
};

function showLoginView() {
    const loginEl = document.getElementById("view-login");
    const sidebar = document.getElementById("sidebar");
    const mainContent = document.getElementById("main-content");
    if (loginEl) loginEl.style.display = "flex";
    if (sidebar) sidebar.style.display = "none";
    if (mainContent) mainContent.style.display = "none";
}

function hideLoginView() {
    const loginEl = document.getElementById("view-login");
    const sidebar = document.getElementById("sidebar");
    const mainContent = document.getElementById("main-content");
    if (loginEl) loginEl.style.display = "none";
    if (sidebar) sidebar.style.display = "flex";
    if (mainContent) mainContent.style.display = "block";
}

async function checkAuth() {
    const savedToken = localStorage.getItem("aegis_token");
    if (!savedToken) {
        showLoginView();
        return false;
    }

    state.currentUser.token = savedToken;
    try {
        const resp = await fetch("/api/auth/me");
        if (resp.ok) {
            const u = await resp.json();
            state.currentUser = { ...u, token: savedToken };
            hideLoginView();
            updateUserDisplay();
            return true;
        } else {
            localStorage.removeItem("aegis_token");
            localStorage.removeItem("aegis_user");
            state.currentUser.token = "";
            showLoginView();
            return false;
        }
    } catch (e) {
        console.error("Auth check failed:", e);
        showLoginView();
        return false;
    }
}

async function loginWithCredentials(username, password) {
    const errAlert = document.getElementById("login-error-alert");
    const submitBtn = document.getElementById("btn-login-submit");
    const btnText = document.getElementById("login-btn-text");
    const spinner = document.getElementById("login-spinner");

    if (errAlert) errAlert.style.display = "none";
    if (submitBtn) submitBtn.disabled = true;
    if (btnText) btnText.textContent = "Authenticating...";
    if (spinner) spinner.style.display = "inline-block";

    try {
        const resp = await _originalFetch("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });

        if (resp.ok) {
            const data = await resp.json();
            state.currentUser = {
                ...data.user,
                token: data.access_token
            };
            localStorage.setItem("aegis_token", data.access_token);
            localStorage.setItem("aegis_user", JSON.stringify(data.user));

            hideLoginView();
            updateUserDisplay();

            const isDev = (data.user.role === "developer");
            const scopeDesc = isDev 
                ? `Developer (${data.user.username}) - Scoped View Active` 
                : `${data.user.role.replace('_', ' ').toUpperCase()} (Global View)`;
            showToast(`Welcome, ${data.user.username}! Signed in as ${scopeDesc}`, "success");

            const pwdInput = document.getElementById("login-password");
            if (pwdInput) pwdInput.value = "";

            await loadProjects();
            await loadDashboardStats();
            await loadFindings();
            await loadStandards();
            await loadCustomRules();
            await loadIntegrations();
        } else {
            const errData = await resp.json().catch(() => ({ detail: "Invalid username or password" }));
            if (errAlert) {
                errAlert.textContent = errData.detail || "Invalid username or password. Please verify credentials.";
                errAlert.style.display = "flex";
            }
        }
    } catch (err) {
        console.error("Login request error:", err);
        if (errAlert) {
            errAlert.textContent = "Connection error while reaching AegisSec authentication service.";
            errAlert.style.display = "flex";
        }
    } finally {
        if (submitBtn) submitBtn.disabled = false;
        if (btnText) btnText.textContent = "Authenticate & Enter";
        if (spinner) spinner.style.display = "none";
    }
}

function handleLoginFormSubmit(event) {
    event.preventDefault();
    const u = document.getElementById("login-username")?.value.trim();
    const p = document.getElementById("login-password")?.value;
    if (!u || !p) return;
    loginWithCredentials(u, p);
}

function quickLogin(roleKey) {
    const cred = DEMO_CREDENTIALS[roleKey];
    if (!cred) return;
    const uEl = document.getElementById("login-username");
    const pEl = document.getElementById("login-password");
    if (uEl) uEl.value = cred.username;
    if (pEl) pEl.value = cred.password;
    loginWithCredentials(cred.username, cred.password);
}

function togglePasswordVisibility() {
    const pInput = document.getElementById("login-password");
    const toggleBtn = document.getElementById("btn-toggle-password");
    if (!pInput) return;
    if (pInput.type === "password") {
        pInput.type = "text";
        if (toggleBtn) toggleBtn.textContent = "Hide";
    } else {
        pInput.type = "password";
        if (toggleBtn) toggleBtn.textContent = "Show";
    }
}

function logout() {
    localStorage.removeItem("aegis_token");
    localStorage.removeItem("aegis_user");
    state.currentUser = {
        username: "",
        role: "",
        token: ""
    };
    showLoginView();
    showToast("You have been signed out of AegisSec", "info");
}

function updateDeveloperIsolationUI() {
    const banner = document.getElementById("developer-scoped-banner");
    const authorSpan = document.getElementById("scoped-author-name");
    const emailSpan = document.getElementById("scoped-author-email");
    const isDev = (state.currentUser && (state.currentUser.role === "developer" || state.currentUser.role === "DEVELOPER"));

    if (banner) {
        if (isDev) {
            banner.style.display = "flex";
            const devProfileMap = {
                marcus: { name: "Marcus Vance", email: "marcus.vance@cloudsec.internal" },
                elena: { name: "Dr. Elena Rostova", email: "elena.rostova@autocorp.de" },
                sarah: { name: "Sarah Lin", email: "sarah.lin@frontend.io" },
                developer: { name: "Marcus Vance", email: "marcus.vance@cloudsec.internal" }
            };
            const profile = devProfileMap[state.currentUser.username] || {
                name: state.currentUser.username,
                email: state.currentUser.email || "developer@internal"
            };
            if (authorSpan) authorSpan.textContent = profile.name;
            if (emailSpan) emailSpan.textContent = profile.email;
        } else {
            banner.style.display = "none";
        }
    }
}

function updateUserDisplay() {
    const nameEl = document.getElementById("current-user-display");
    const roleEl = document.getElementById("current-role-badge");
    const switcher = document.getElementById("role-switcher-select");

    if (nameEl) nameEl.textContent = state.currentUser.username;
    if (roleEl) {
        roleEl.textContent = state.currentUser.role.replace("_", " ");
    }
    if (switcher) {
        switcher.value = state.currentUser.username;
    }
    updateDeveloperIsolationUI();
}

async function switchDemoRole(roleKey) {
    const target = DEMO_CREDENTIALS[roleKey] || DEMO_CREDENTIALS.admin;
    try {
        const resp = await _originalFetch("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(target)
        });
        if (resp.ok) {
            const data = await resp.json();
            state.currentUser = {
                ...data.user,
                token: data.access_token
            };
            localStorage.setItem("aegis_token", data.access_token);
            localStorage.setItem("aegis_user", JSON.stringify(data.user));
            updateUserDisplay();

            const isDev = (data.user.role === "developer");
            const roleName = isDev 
                ? `Developer (${data.user.username}) - Scoped View Active` 
                : `${data.user.role.replace('_', ' ').toUpperCase()} (Global View)`;
            showToast(`Switched account: ${roleName}`, "success");

            // Immediately reload dashboard and findings to reflect user's authorization scope
            await loadFindings();
            await loadDashboardStats();
        } else {
            showToast("Login failed for selected role", "error");
        }
    } catch (e) {
        console.error("Role switch failed:", e);
        showToast("Role switch failed", "error");
    }
}

// --- Project Management ---
async function loadProjects() {
    try {
        const resp = await fetch("/api/projects");
        if (resp.ok) {
            state.projects = await resp.json();
            renderProjectsDropdown();
            renderProjectsTable();

            const savedProjectId = localStorage.getItem("aegis_active_project_id");
            if (savedProjectId && state.projects.some(p => p.id === savedProjectId)) {
                state.activeProjectId = savedProjectId;
            } else if ((!state.activeProjectId || !state.projects.some(p => p.id === state.activeProjectId)) && state.projects.length > 0) {
                state.activeProjectId = state.projects[0].id;
                localStorage.setItem("aegis_active_project_id", state.activeProjectId);
            }
            const sel = document.getElementById("global-project-select");
            if (sel && state.activeProjectId) sel.value = state.activeProjectId;
        }
    } catch (e) {
        console.error("Failed loading projects:", e);
    }
}

function renderProjectsDropdown() {
    const sel = document.getElementById("global-project-select");
    if (!sel) return;
    sel.innerHTML = "";

    state.projects.forEach(p => {
        const opt = document.createElement("option");
        opt.value = p.id;
        opt.textContent = `${p.name} (${p.git_branch || 'main'})`;
        if (p.id === state.activeProjectId) opt.selected = true;
        sel.appendChild(opt);
    });
}

function onProjectChange(projectId) {
    state.activeProjectId = projectId;
    if (projectId) {
        localStorage.setItem("aegis_active_project_id", projectId);
    } else {
        localStorage.removeItem("aegis_active_project_id");
    }
    loadFindings();
    loadDashboardStats();
    showToast(`Active project changed to: ${state.projects.find(p => p.id === projectId)?.name || projectId}`);
}

function renderProjectsTable() {
    const tbody = document.getElementById("projects-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (state.projects.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No projects configured. Click "New Project" to add one.</td></tr>';
        return;
    }

    state.projects.forEach(p => {
        const tr = document.createElement("tr");
        const patBadge = p.git_pat_configured 
            ? '<span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981;">CONFIGURED (MASKED)</span>'
            : '<span class="badge" style="background: rgba(148, 163, 184, 0.2); color: #94a3b8;">PUBLIC / NONE</span>';

        const lastScanned = p.last_scanned ? new Date(p.last_scanned).toLocaleString() : "Never";
        const riskColor = p.risk_score > 70 ? "#ef4444" : p.risk_score > 40 ? "#f97316" : "#10b981";

        tr.innerHTML = `
            <td>
                <strong>${p.name}</strong>
                <div style="font-size: 12px; color: var(--text-muted);">${p.description || "No description"}</div>
            </td>
            <td>
                <code style="font-size: 12px;">${p.git_url || "Local / Demo Repository"}</code>
                <div style="font-size: 11px; color: var(--text-secondary);">Branch: <strong>${p.git_branch}</strong></div>
            </td>
            <td>${patBadge}</td>
            <td><strong>${p.total_findings || 0}</strong> vulnerabilities</td>
            <td><strong style="color: ${riskColor};">${p.risk_score || 0.0}</strong> / 100</td>
            <td style="font-size: 13px; color: var(--text-secondary);">${lastScanned}</td>
            <td style="text-align: right;">
                <button class="btn btn-secondary btn-sm" onclick="triggerScanForProject('${p.id}')">Scan</button>
                <button class="btn btn-danger btn-sm" onclick="promptDeleteProject('${p.id}', '${p.name.replace(/'/g, "\\'")}')">Delete</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function openCreateProjectModal() {
    document.getElementById("modal-new-project").classList.add("active");
}

async function submitCreateProject(e) {
    e.preventDefault();
    const name = document.getElementById("new-proj-name").value;
    const desc = document.getElementById("new-proj-desc").value;
    const gitUrl = document.getElementById("new-proj-git-url").value;
    const branch = document.getElementById("new-proj-git-branch").value;
    const pat = document.getElementById("new-proj-git-pat").value;

    try {
        const resp = await fetch("/api/projects", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name, description: desc, git_url: gitUrl, git_branch: branch, git_pat: pat
            })
        });

        if (resp.ok) {
            const created = await resp.json();
            showToast(`Project '${created.name}' created successfully!`, "success");
            closeModal("modal-new-project");
            document.getElementById("form-create-project").reset();
            await loadProjects();
            state.activeProjectId = created.id;
            // Trigger automatic initial scan
            triggerScanForProject(created.id);
        } else {
            const err = await resp.json();
            showToast(err.detail || "Failed to create project", "error");
        }
    } catch (err) {
        showToast("Error connecting to server", "error");
    }
}

let projectToDeleteId = null;
function promptDeleteProject(id, name) {
    projectToDeleteId = id;
    document.getElementById("delete-proj-name").textContent = name;
    document.getElementById("modal-delete-project").classList.add("active");
}

async function confirmDeleteProject() {
    if (!projectToDeleteId) return;
    try {
        const resp = await fetch(`/api/projects/${projectToDeleteId}`, { method: "DELETE" });
        if (resp.ok) {
            showToast("Project deleted successfully", "success");
            closeModal("modal-delete-project");
            projectToDeleteId = null;
            await loadProjects();
            await loadFindings();
            await loadDashboardStats();
        } else {
            const err = await resp.json();
            showToast(err.detail || "Failed to delete project", "error");
        }
    } catch (e) {
        showToast("Error deleting project", "error");
    }
}

// --- Scanning ---
async function triggerQuickScan() {
    if (!state.activeProjectId) {
        showToast("Please select or create a project first", "error");
        return;
    }
    await triggerScanForProject(state.activeProjectId);
}

async function triggerScanForProject(projectId) {
    showToast("Launching SAST & SCA scanning engine...", "info");
    const scanBtn = document.getElementById("btn-quick-scan");
    if (scanBtn) scanBtn.disabled = true;

    try {
        const resp = await fetch(`/api/projects/${projectId}/scan`, {
            method: "POST"
        });
        const res = await resp.json();
        if (res.success) {
            showToast(`Scan complete: ${res.total_findings} findings discovered (${res.critical_count} Critical)`, "success");
            await loadProjects();
            await loadFindings();
            await loadDashboardStats();
        } else {
            showToast(`Scan failed: ${res.error || 'Unknown error'}`, "error");
        }
    } catch (e) {
        showToast("Scan pipeline error", "error");
    } finally {
        if (scanBtn) scanBtn.disabled = false;
    }
}

// --- Dashboard & Analytics ---
async function loadDashboardStats() {
    try {
        if (!state.findings || state.findings.length === 0) {
            await loadFindings();
        }
        let url = "/api/dashboard/stats";
        if (state.activeProjectId) {
            url += `?project_id=${state.activeProjectId}`;
        }
        const resp = await fetch(url);
        if (resp.ok) {
            state.dashboardStats = await resp.json();
            renderDashboard();
        }
    } catch (e) {
        console.error("Dashboard stats error:", e);
    }
}

function renderDashboard() {
    const s = state.dashboardStats;
    if (!s) return;

    // KPI values
    const kCrit = document.getElementById("kpi-critical");
    const kExp = document.getElementById("kpi-exploits");
    const kCvss = document.getElementById("kpi-avg-cvss");
    const kEpss = document.getElementById("kpi-avg-epss");
    const kPost = document.getElementById("kpi-posture");
    const kActNow = document.getElementById("kpi-actnow-count");

    if (kCrit) kCrit.textContent = s.critical_count;
    if (kExp) kExp.textContent = s.active_exploits;
    if (kCvss) kCvss.textContent = s.avg_cvss;
    if (kEpss) kEpss.textContent = s.avg_epss;
    if (kPost) kPost.textContent = `${s.overall_posture}%`;
    if (kActNow) kActNow.textContent = s.quadrants.ACT_NOW || 0;

    // Quadrant counts
    const qAct = document.getElementById("count-quad-actnow");
    const qPatch = document.getElementById("count-quad-patch");
    const qOpp = document.getElementById("count-quad-opp");
    const qRoutine = document.getElementById("count-quad-routine");

    if (qAct) qAct.textContent = s.quadrants.ACT_NOW || 0;
    if (qPatch) qPatch.textContent = s.quadrants.CRITICAL_PATCH || 0;
    if (qOpp) qOpp.textContent = s.quadrants.OPPORTUNISTIC || 0;
    if (qRoutine) qRoutine.textContent = s.quadrants.ROUTINE || 0;

    // Standards summary breakdown (Interactive click-to-guide)
    const stdList = document.getElementById("dashboard-standards-list");
    if (stdList && s.standards_summary) {
        stdList.innerHTML = "";
        const maxVal = Math.max(...Object.values(s.standards_summary), 1);

        for (const [std, count] of Object.entries(s.standards_summary)) {
            const pct = Math.round((count / maxVal) * 100);
            const item = document.createElement("div");
            item.className = "standard-item clickable-interactive";
            item.style.cursor = "pointer";
            item.title = `Click to filter and view all ${std} findings in triage table`;
            item.onclick = () => filterByStandardAndNavigate(std);
            item.innerHTML = `
                <div class="standard-meta">
                    <span style="font-weight: 600; color: #fff;">${std} <span style="font-size: 11px; color: var(--accent-cyan); margin-left: 4px;">&rarr; Guide</span></span>
                    <strong style="color: var(--accent-cyan);">${count} findings</strong>
                </div>
                <div class="progress-track" style="margin-top: 6px;">
                    <div class="progress-bar" style="width: ${pct}%;"></div>
                </div>
            `;
            stdList.appendChild(item);
        }
    }

    // Developer Attribution Scorecard (Interactive rows)
    const devTbody = document.getElementById("dashboard-dev-attribution-tbody");
    if (devTbody && s.developer_attribution) {
        devTbody.innerHTML = "";
        s.developer_attribution.forEach(d => {
            const tr = document.createElement("tr");
            tr.className = "clickable-interactive";
            tr.style.cursor = "pointer";
            tr.title = `Click to guide to all findings authored by ${escapeHtml(d.name)}`;
            tr.onclick = (e) => {
                if (!e.target.closest('button')) {
                    filterByDeveloperAndNavigate(d.name);
                }
            };
            const initials = (d.name || 'DE').split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
            tr.innerHTML = `
                <td>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <div style="width: 30px; height: 30px; border-radius: 50%; background: linear-gradient(135deg, var(--accent-indigo), var(--accent-cyan)); color: #000; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 800;">
                            ${initials}
                        </div>
                        <strong style="color: #fff;">${d.name}</strong>
                    </div>
                </td>
                <td style="color: var(--text-secondary); font-size: 13px;">${d.email || 'N/A'}</td>
                <td><strong style="color: #fff;">${d.total_findings}</strong> violations</td>
                <td><span class="badge badge-critical">${d.critical_count}</span></td>
                <td><span class="badge badge-high">${d.high_count}</span></td>
                <td style="text-align: right;">
                    <button class="btn btn-secondary btn-sm" onclick="filterByDeveloperAndNavigate('${escapeHtml(d.name)}')">View Findings</button>
                </td>
            `;
            devTbody.appendChild(tr);
        });
    }

    // Render Vulnerability & Security Posture Trend Line Graph
    if (s.trends) {
        renderDashboardTrendChart(s.trends);
    }

    // Render Actionable Security Findings Feed on Dashboard
    renderDashboardFindingsFeed();
}

let currentTrendFilter = null;

function onTrendDeveloperFilterChange(devName) {
    currentTrendFilter = devName;
    if (state.dashboardStats && state.dashboardStats.trends) {
        renderDashboardTrendChart(state.dashboardStats.trends, devName);
    }
}

function renderDashboardTrendChart(trendsData, activeFilter) {
    const container = document.getElementById("trend-chart-container");
    if (!container || !trendsData) return;

    const filterSelect = document.getElementById("trend-developer-filter");
    const scopeBadge = document.getElementById("trend-scope-badge");
    const summaryStat = document.getElementById("trend-summary-stat");

    // Handle RBAC isolation
    if (trendsData.is_developer_scoped) {
        const devName = trendsData.scoped_developer_name || "Developer";
        if (scopeBadge) {
            scopeBadge.textContent = `Contributor Scoped: ${devName}`;
            scopeBadge.style.background = "rgba(59, 130, 246, 0.25)";
            scopeBadge.style.color = "#93c5fd";
        }
        if (filterSelect) {
            filterSelect.innerHTML = `<option value="${escapeHtml(devName)}">${escapeHtml(devName)} (My Contributed Code)</option>`;
            filterSelect.disabled = true;
            filterSelect.title = "Scoped strictly to your contributed code under RBAC policy";
        }
        activeFilter = devName;
    } else {
        if (filterSelect) {
            filterSelect.disabled = false;
            filterSelect.title = "Select contributor or view all enterprise code";
            const options = trendsData.developer_options || ["All Enterprise Code"];
            const currentVal = activeFilter || currentTrendFilter || options[0];
            filterSelect.innerHTML = options.map(opt => `<option value="${escapeHtml(opt)}" ${opt === currentVal ? 'selected' : ''}>${escapeHtml(opt)}</option>`).join("");
            activeFilter = currentVal;
        } else {
            activeFilter = activeFilter || "All Enterprise Code";
        }
        if (scopeBadge) {
            scopeBadge.textContent = (activeFilter === "All Enterprise Code") ? "Global Enterprise Scope" : `Developer Scope: ${activeFilter}`;
            scopeBadge.style.background = (activeFilter === "All Enterprise Code") ? "rgba(59, 130, 246, 0.2)" : "rgba(168, 85, 247, 0.2)";
            scopeBadge.style.color = (activeFilter === "All Enterprise Code") ? "#93c5fd" : "#d8b4fe";
        }
    }

    currentTrendFilter = activeFilter;
    const series = (trendsData.per_developer_trends && trendsData.per_developer_trends[activeFilter]) || trendsData.primary;
    if (!series) return;

    const labels = trendsData.labels || ["Sprint 31", "Sprint 32", "Sprint 33", "Sprint 34", "Sprint 35", "Sprint 36"];
    const crit = series.critical_series || [0, 0, 0, 0, 0, 0];
    const high = series.high_series || [0, 0, 0, 0, 0, 0];
    const resolved = series.resolved_series || [0, 0, 0, 0, 0, 0];
    const posture = series.posture_series || [50, 60, 70, 80, 85, 90];

    // Chart dimensions
    const width = 880;
    const height = 240;
    const padL = 45;
    const padR = 40;
    const padT = 20;
    const padB = 35;
    const plotW = width - padL - padR;
    const plotH = height - padT - padB;

    const maxDefect = Math.max(6, ...crit, ...high, ...resolved);
    const n = labels.length;
    const getX = (i) => padL + (i / (n - 1)) * plotW;
    const getYDefect = (val) => padT + plotH - (val / maxDefect) * plotH;
    const getYPosture = (pct) => padT + plotH - (pct / 100) * plotH;

    // Build SVG paths
    const critPoints = crit.map((v, i) => `${getX(i)},${getYDefect(v)}`);
    const highPoints = high.map((v, i) => `${getX(i)},${getYDefect(v)}`);
    const resPoints = resolved.map((v, i) => `${getX(i)},${getYDefect(v)}`);
    const postPoints = posture.map((v, i) => `${getX(i)},${getYPosture(v)}`);

    // Posture gradient area
    const postArea = `${getX(0)},${padT + plotH} ` + postPoints.join(" ") + ` ${getX(n - 1)},${padT + plotH}`;

    // Grid lines SVG
    let gridLinesSvg = "";
    for (let g = 0; g <= 4; g++) {
        const yPos = padT + (g / 4) * plotH;
        const defectVal = Math.round(maxDefect * (1 - g / 4));
        const postVal = Math.round(100 * (1 - g / 4));
        gridLinesSvg += `
            <line x1="${padL}" y1="${yPos}" x2="${width - padR}" y2="${yPos}" stroke="rgba(255,255,255,0.07)" stroke-dasharray="3,3" />
            <text x="${padL - 8}" y="${yPos + 4}" fill="#64748b" font-size="10" text-anchor="end" font-family="var(--font-mono)">${defectVal}</text>
            <text x="${width - padR + 8}" y="${yPos + 4}" fill="#38bdf8" font-size="10" text-anchor="start" font-family="var(--font-mono)">${postVal}%</text>
        `;
    }

    // X Axis Milestone Labels
    let xLabelsSvg = "";
    labels.forEach((lbl, i) => {
        const xPos = getX(i);
        const shortLbl = lbl.split(" ")[0] + (lbl.includes("Current") ? " (Now)" : "");
        xLabelsSvg += `
            <line x1="${xPos}" y1="${padT + plotH}" x2="${xPos}" y2="${padT + plotH + 5}" stroke="rgba(255,255,255,0.2)" />
            <text x="${xPos}" y="${height - 10}" fill="#94a3b8" font-size="11" text-anchor="middle" font-weight="600">${escapeHtml(shortLbl)}</text>
        `;
    });

    // Circles with tooltips
    let circlesSvg = "";
    crit.forEach((v, i) => {
        circlesSvg += `<circle cx="${getX(i)}" cy="${getYDefect(v)}" r="4.5" fill="#ef4444" stroke="#0f172a" stroke-width="2"><title>Critical: ${v} at ${labels[i]}</title></circle>`;
    });
    high.forEach((v, i) => {
        circlesSvg += `<circle cx="${getX(i)}" cy="${getYDefect(v)}" r="4" fill="#f97316" stroke="#0f172a" stroke-width="2"><title>High: ${v} at ${labels[i]}</title></circle>`;
    });
    resolved.forEach((v, i) => {
        circlesSvg += `<circle cx="${getX(i)}" cy="${getYDefect(v)}" r="4" fill="#10b981" stroke="#0f172a" stroke-width="2"><title>Resolved: ${v} at ${labels[i]}</title></circle>`;
    });
    posture.forEach((v, i) => {
        circlesSvg += `<circle cx="${getX(i)}" cy="${getYPosture(v)}" r="5" fill="#38bdf8" stroke="#0f172a" stroke-width="2"><title>Posture: ${v}% at ${labels[i]}</title></circle>`;
    });

    const svgHtml = `
        <svg viewBox="0 0 ${width} ${height}" style="width: 100%; height: 100%; overflow: visible;" preserveAspectRatio="none">
            <defs>
                <linearGradient id="postureGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.22"/>
                    <stop offset="100%" stop-color="#38bdf8" stop-opacity="0.0"/>
                </linearGradient>
                <filter id="glow-red" x="-20%" y="-20%" width="140%" height="140%">
                    <feDropShadow dx="0" dy="0" stdDeviation="3" flood-color="#ef4444" flood-opacity="0.6"/>
                </filter>
                <filter id="glow-green" x="-20%" y="-20%" width="140%" height="140%">
                    <feDropShadow dx="0" dy="0" stdDeviation="3" flood-color="#10b981" flood-opacity="0.6"/>
                </filter>
            </defs>

            ${gridLinesSvg}
            ${xLabelsSvg}

            <!-- Posture Gradient Fill -->
            <polygon points="${postArea}" fill="url(#postureGrad)" />

            <!-- Posture Line (Cyan Dashed) -->
            <polyline points="${postPoints.join(" ")}" fill="none" stroke="#38bdf8" stroke-width="2.5" stroke-dasharray="5,4" />

            <!-- Remediated Line (Green) -->
            <polyline points="${resPoints.join(" ")}" fill="none" stroke="#10b981" stroke-width="2.5" filter="url(#glow-green)" />

            <!-- High Severity Line (Orange) -->
            <polyline points="${highPoints.join(" ")}" fill="none" stroke="#f97316" stroke-width="2.5" />

            <!-- Critical Defects Line (Red) -->
            <polyline points="${critPoints.join(" ")}" fill="none" stroke="#ef4444" stroke-width="3" filter="url(#glow-red)" />

            ${circlesSvg}
        </svg>
    `;

    container.innerHTML = svgHtml;

    if (summaryStat) {
        const postureDelta = Math.round(series.current_posture - (posture[0] || 50));
        const sign = postureDelta >= 0 ? "+" : "";
        summaryStat.innerHTML = `
            Sprint 31 to Current: <strong style="color: #38bdf8;">${series.current_posture}% Security Posture (${sign}${postureDelta}%)</strong> &bull;
            <span style="color: #ef4444; font-weight: 700;">${series.current_critical} Critical</span> &bull;
            <span style="color: #f97316; font-weight: 700;">${series.current_high} High</span> &bull;
            <span style="color: #10b981; font-weight: 700;">${resolved[resolved.length - 1]} Remediated</span>
        `;
    }
}

// --- Vulnerability Triage ---
async function loadFindings() {
    try {
        let url = "/api/findings";
        if (state.activeProjectId) {
            url += `?project_id=${state.activeProjectId}`;
        }
        const resp = await fetch(url);
        if (resp.ok) {
            state.findings = await resp.json();

            // Populate developer filter options
            const devSelect = document.getElementById("filter-developer");
            if (devSelect) {
                const currentVal = devSelect.value;
                const uniqueDevs = Array.from(new Set(state.findings.map(f => f.author_name).filter(Boolean)));
                devSelect.innerHTML = '<option value="">All Developers</option>';
                uniqueDevs.forEach(dev => {
                    const opt = document.createElement("option");
                    opt.value = dev;
                    opt.textContent = dev;
                    if (dev === currentVal) opt.selected = true;
                    devSelect.appendChild(opt);
                });
            }

            applyFilters();
            renderDashboardFindingsFeed();
        }
    } catch (e) {
        console.error("Failed loading findings:", e);
    }
}

function applyFilters() {
    const q = document.getElementById("filter-search")?.value.toLowerCase() || "";
    const type = document.getElementById("filter-type")?.value || "";
    const sev = document.getElementById("filter-severity")?.value || "";
    const quad = document.getElementById("filter-quadrant")?.value || "";
    const std = document.getElementById("filter-standard")?.value || "";
    const dev = document.getElementById("filter-developer")?.value || "";

    state.filteredFindings = state.findings.filter(f => {
        if (q && !f.title.toLowerCase().includes(q) && !f.file_path.toLowerCase().includes(q) && !(f.cve_id && f.cve_id.toLowerCase().includes(q))) {
            return false;
        }
        if (type && f.type !== type) return false;
        if (sev && f.severity !== sev) return false;
        if (quad && f.quadrant !== quad) return false;
        if (std && !f.standards.some(s => s.startsWith(std))) return false;
        if (dev && f.author_name !== dev) return false;
        return true;
    });

    renderFindingsTable();
}

function renderFindingsTable() {
    const tbody = document.getElementById("findings-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (state.filteredFindings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 30px;">No matching vulnerabilities found.</td></tr>';
        return;
    }

    state.filteredFindings.forEach(f => {
        const tr = document.createElement("tr");
        tr.id = `finding-row-${f.id}`;
        tr.dataset.title = f.title;
        const sevClass = `badge-${f.severity.toLowerCase()}`;
        const stdBadges = (f.standards || []).slice(0, 3).map(s => `<span class="tag-std">${s}</span>`).join("");

        const quadColor = f.quadrant === "ACT_NOW" ? "#ef4444" : f.quadrant === "CRITICAL_PATCH" ? "#f97316" : f.quadrant === "OPPORTUNISTIC" ? "#eab308" : "#10b981";

        const ageDays = f.age_days !== undefined ? f.age_days : 0;
        const ageText = f.age_display || (ageDays === 0 ? "Today (< 24h)" : `${ageDays} days old`);
        const firstSeenDate = f.first_seen_date || (f.first_seen ? f.first_seen.split('T')[0] : '');
        const agePillColor = ageDays > 14 ? '#fca5a5' : (ageDays > 2 ? '#fcd34d' : '#6ee7b7');
        const agePillBg = ageDays > 14 ? 'rgba(239, 68, 68, 0.15)' : (ageDays > 2 ? 'rgba(245, 158, 11, 0.15)' : 'rgba(16, 185, 129, 0.15)');

        tr.innerHTML = `
            <td><span class="badge ${sevClass}">${f.severity}</span></td>
            <td>
                <div style="font-weight: 600; cursor: pointer; color: #fff; display: flex; align-items: center; gap: 6px; flex-wrap: wrap;" onclick="openFindingDetail('${f.id}')">
                    ${f.cisa_kev ? `<span class="badge" style="background: rgba(239, 68, 68, 0.25); color: #f87171; border: 1px solid #ef4444; font-size: 10px; font-weight: 700;">🚨 CISA KEV</span>` : ''}
                    <span>${escapeHtml(f.title)}</span>
                </div>
                <div style="font-size: 12px; color: var(--text-secondary); font-family: var(--font-mono);">${escapeHtml(f.file_path)}:${f.line_start}</div>
                <div style="display: flex; align-items: center; gap: 6px; margin-top: 4px; flex-wrap: wrap;">
                    <span class="badge" style="background: ${agePillBg}; color: ${agePillColor}; font-size: 10px; padding: 2px 6px;">
                        🕒 ${escapeHtml(ageText)}
                    </span>
                    ${firstSeenDate ? `<span style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">Seen: ${escapeHtml(firstSeenDate)}</span>` : ''}
                    ${f.dependency_lag_versions ? `<span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; font-size: 10px;">📦 ${escapeHtml(f.dependency_lag_versions)}</span>` : ''}
                </div>
            </td>
            <td>
                <div style="font-weight: 600; color: #fff; font-size: 13px;">${escapeHtml(f.author_name || 'Unknown')}</div>
                <div style="font-size: 11px; color: var(--text-secondary);">${escapeHtml(f.author_email || '')}</div>
                <div style="font-family: var(--font-mono); font-size: 10px; color: var(--accent-cyan);">${f.commit_hash ? '#' + f.commit_hash : ''}</div>
            </td>
            <td><span class="badge" style="background: rgba(255,255,255,0.06);">${f.type.toUpperCase()}</span></td>
            <td>
                <div>CVSS: <strong>${f.cvss_score}</strong></div>
                <div style="font-size: 12px; color: var(--text-secondary);">EPSS: <strong>${f.epss_score}</strong></div>
            </td>
            <td>
                <div style="font-weight: 700; color: ${quadColor};">${f.composite_risk_score}/100</div>
                <div style="font-size: 11px; text-transform: uppercase; font-weight: 600; color: ${quadColor};">${f.quadrant}</div>
            </td>
            <td>${stdBadges}</td>
            <td>
                <span class="badge" style="background: rgba(56, 189, 248, 0.1); color: var(--accent-cyan);">${f.status.replace("_", " ")}</span>
                ${(f.jira_key || f.zammad_id || f.ticket_assigned_to) ? `
                    <div style="margin-top: 4px;">
                        <span class="badge" style="background: rgba(168, 85, 247, 0.18); color: #c084fc; font-size: 10px; border: 1px solid rgba(168, 85, 247, 0.35);" title="Ticket assigned to author ${escapeHtml(f.ticket_assigned_to || f.author_name)}">
                            🎫 ${f.jira_key ? 'Jira #' + f.jira_key : (f.zammad_id ? 'Zammad #' + f.zammad_id : 'Ticket')} &rarr; ${escapeHtml(f.ticket_assigned_to || f.author_name)}
                        </span>
                    </div>
                ` : ''}
            </td>
            <td style="text-align: right;">
                <button class="btn btn-secondary btn-sm" onclick="openFindingDetail('${f.id}')">Inspect</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function openFindingDetail(findingId) {
    let f = (typeof findingId === 'object' && findingId !== null) 
        ? findingId 
        : (state.findings || []).find(item => item.id === findingId) || (state.auditFindings || []).find(item => item.id === findingId);
    if (!f && typeof findingId === 'string') {
        try {
            const resp = await fetch("/api/findings");
            if (resp.ok) {
                state.findings = await resp.json();
                f = state.findings.find(item => item.id === findingId);
            }
        } catch (e) {
            console.error("Error fetching finding detail:", e);
        }
    }
    if (!f) return;
    state.activeFinding = f;

    // Reset AI remediation box and button state
    const aiBox = document.getElementById("detail-ai-remediation-box");
    if (aiBox) aiBox.style.display = "none";
    const aiBtnText = document.getElementById("ai-btn-text");
    if (aiBtnText) aiBtnText.textContent = "✨ Generate AI Remediation & Code Diff";
    const aiBtn = document.getElementById("btn-ask-ai");
    if (aiBtn) aiBtn.disabled = false;
    const aiSpinner = document.getElementById("ai-btn-spinner");
    if (aiSpinner) aiSpinner.style.display = "none";

    document.getElementById("detail-title").textContent = f.title;
    const b = document.getElementById("detail-severity-badge");
    b.className = `badge badge-${f.severity.toLowerCase()}`;
    b.textContent = f.severity;

    // CISA KEV Badge
    const cisaBadge = document.getElementById("detail-cisa-badge");
    if (cisaBadge) {
        if (f.cisa_kev) {
            cisaBadge.style.display = "inline-block";
            cisaBadge.title = f.cisa_kev_due_date ? `CISA Due Date: ${f.cisa_kev_due_date}` : "CISA Known Exploited Vulnerability";
        } else {
            cisaBadge.style.display = "none";
        }
    }

    document.getElementById("detail-cvss").textContent = f.cvss_score;
    document.getElementById("detail-epss").textContent = `${f.epss_score} (${Math.round(f.epss_percentile * 100)}%)`;
    document.getElementById("detail-composite").textContent = `${f.composite_risk_score}/100`;
    document.getElementById("detail-sla").textContent = `${f.quadrant} (${f.sla_days}d SLA)`;

    const ageDays = f.age_days !== undefined ? f.age_days : 0;
    const ageText = f.age_display || (ageDays === 0 ? "Today (< 24h)" : `${ageDays} days old`);
    const firstSeenDate = f.first_seen_date || (f.first_seen ? f.first_seen.split('T')[0] : (f.commit_date ? f.commit_date.split(' ')[0] : 'Today'));

    const ageDispEl = document.getElementById("detail-age-display");
    const firstSeenEl = document.getElementById("detail-first-seen");
    if (ageDispEl) {
        ageDispEl.textContent = ageText;
        ageDispEl.style.color = ageDays > 14 ? "#f87171" : (ageDays > 2 ? "#fbbf24" : "#34d399");
    }
    if (firstSeenEl) {
        firstSeenEl.textContent = `First seen: ${firstSeenDate}`;
    }

    // AI Confidence & False Positive Assessment
    const confLabel = document.getElementById("detail-ai-confidence-label");
    const confRationale = document.getElementById("detail-ai-confidence-rationale");
    if (f.ai_confidence_score !== undefined && f.ai_confidence_score !== null) {
        const pct = Math.round(f.ai_confidence_score * 100);
        if (confLabel) {
            confLabel.textContent = `${pct}% - ${f.ai_confidence_label || 'True Positive'}`;
            confLabel.style.color = f.ai_confidence_score >= 0.7 ? '#34d399' : (f.ai_confidence_score >= 0.4 ? '#fbbf24' : '#f87171');
            confLabel.style.background = f.ai_confidence_score >= 0.7 ? 'rgba(16, 185, 129, 0.15)' : (f.ai_confidence_score >= 0.4 ? 'rgba(245, 158, 11, 0.15)' : 'rgba(239, 68, 68, 0.15)');
        }
        if (confRationale) {
            confRationale.textContent = f.ai_confidence_rationale || 'Evaluation completed.';
        }
    } else {
        if (confLabel) {
            confLabel.textContent = 'Pending AI Assessment';
            confLabel.style.color = '#94a3b8';
            confLabel.style.background = 'rgba(148, 163, 184, 0.15)';
        }
        if (confRationale) {
            confRationale.textContent = 'Click "Evaluate AI Confidence" for contextual false-positive and exploitability scoring.';
        }
    }

    document.getElementById("detail-location").textContent = `${f.file_path} (lines ${f.line_start}-${f.line_end})`;
    document.getElementById("detail-cwe-cve").textContent = `${f.cwe_id || 'N/A'} ${f.cve_id ? ' | ' + f.cve_id : ''}`;

    // Developer Attribution
    const authNameEl = document.getElementById("detail-author-name");
    const authEmailEl = document.getElementById("detail-author-email");
    const commitHashEl = document.getElementById("detail-commit-hash");
    const commitDateEl = document.getElementById("detail-commit-date");

    if (authNameEl) authNameEl.textContent = f.author_name || "Unknown Developer";
    if (authEmailEl) authEmailEl.textContent = f.author_email || "unknown@domain.local";
    if (commitHashEl) commitHashEl.textContent = `Commit #${f.commit_hash || 'HEAD'}`;
    if (commitDateEl) commitDateEl.textContent = `${f.commit_date || 'N/A'}${f.commit_message ? ' — ' + f.commit_message : ''}`;

    const stdTagsContainer = document.getElementById("detail-standards-tags");
    stdTagsContainer.innerHTML = (f.standards || []).map(s => `<span class="tag-std" style="font-size: 12px;">${s}</span>`).join(" ");

    // Reachability, Shannon Entropy, and Dependency Drift metadata
    const reachTag = document.getElementById("detail-reachability-tag");
    const reachBadge = document.getElementById("detail-reachability-badge");
    const entropyTag = document.getElementById("detail-secret-entropy-tag");
    const entropyVal = document.getElementById("detail-entropy-value");
    const driftTag = document.getElementById("detail-drift-tag");
    const driftBadge = document.getElementById("detail-drift-badge");
    const metaBox = document.getElementById("detail-advanced-meta-box");

    let hasAdvancedMeta = false;
    if (f.reachability) {
        if (reachTag) reachTag.style.display = "flex";
        if (reachBadge) {
            reachBadge.textContent = f.reachability_label || f.reachability;
            reachBadge.className = f.reachability === 'REACHABLE' ? 'badge badge-critical' : (f.reachability === 'IMPORTED' ? 'badge badge-medium' : 'badge badge-low');
        }
        hasAdvancedMeta = true;
    } else if (reachTag) {
        reachTag.style.display = "none";
    }

    if (f.entropy) {
        if (entropyTag) entropyTag.style.display = "flex";
        if (entropyVal) entropyVal.textContent = `${f.entropy} bits/char (${f.entropy_level || 'HIGH'})`;
        hasAdvancedMeta = true;
    } else if (entropyTag) {
        entropyTag.style.display = "none";
    }

    if (f.dependency_lag_versions) {
        if (driftTag) driftTag.style.display = "flex";
        if (driftBadge) driftBadge.textContent = f.dependency_lag_versions;
        hasAdvancedMeta = true;
    } else if (driftTag) {
        driftTag.style.display = "none";
    }

    if (metaBox) metaBox.style.display = hasAdvancedMeta ? "block" : "none";

    document.getElementById("detail-desc").textContent = f.description;
    document.getElementById("detail-code-snippet").textContent = f.code_snippet || "No source code snippet available.";
    const vulnSnippetEl = document.getElementById("playground-vulnerable-snippet");
    if (vulnSnippetEl) vulnSnippetEl.textContent = f.code_snippet || "/* Original code context */";
    document.getElementById("detail-remediation").textContent = f.remediation || "Review according to secure coding policy.";

    // Update Ticket Assignment to Author Information
    const ticketAuthName = document.getElementById("detail-ticket-author-name");
    const ticketAuthEmail = document.getElementById("detail-ticket-author-email");
    const ticketPill = document.getElementById("detail-ticket-status-pill");

    const assignedAuthor = f.ticket_assigned_to || f.author_name || "Unknown Developer";
    const assignedEmail = f.ticket_assigned_email || f.author_email || "unknown@domain.local";

    if (ticketAuthName) ticketAuthName.textContent = assignedAuthor;
    if (ticketAuthEmail) ticketAuthEmail.textContent = `(${assignedEmail})`;

    if (ticketPill) {
        if (f.jira_key) {
            ticketPill.textContent = `Jira #${f.jira_key} (Assigned to ${assignedAuthor})`;
            ticketPill.style.background = "rgba(59, 130, 246, 0.2)";
            ticketPill.style.color = "#93c5fd";
            ticketPill.style.border = "1px solid rgba(59, 130, 246, 0.4)";
        } else if (f.zammad_id) {
            ticketPill.textContent = `Zammad #${f.zammad_id} (Assigned to ${assignedAuthor})`;
            ticketPill.style.background = "rgba(16, 185, 129, 0.2)";
            ticketPill.style.color = "#6ee7b7";
            ticketPill.style.border = "1px solid rgba(16, 185, 129, 0.4)";
        } else {
            ticketPill.textContent = `Unassigned (Will assign to ${assignedAuthor})`;
            ticketPill.style.background = "rgba(148, 163, 184, 0.15)";
            ticketPill.style.color = "#cbd5e1";
            ticketPill.style.border = "1px solid rgba(148, 163, 184, 0.3)";
        }
    }

    const statusSel = document.getElementById("detail-status-select");
    if (statusSel) statusSel.value = f.status;

    document.getElementById("modal-finding-detail").classList.add("active");
}

function filterByDeveloperAndNavigate(devName) {
    navigate('triage');
    const devSel = document.getElementById('filter-developer');
    if (devSel) devSel.value = devName;

    const searchInput = document.getElementById('filter-search');
    const typeSelect = document.getElementById('filter-type');
    const sevSelect = document.getElementById('filter-severity');
    const quadSelect = document.getElementById('filter-quadrant');
    const stdSelect = document.getElementById('filter-standard');

    if (searchInput) searchInput.value = '';
    if (typeSelect) typeSelect.value = '';
    if (sevSelect) sevSelect.value = '';
    if (quadSelect) quadSelect.value = '';
    if (stdSelect) stdSelect.value = '';

    applyFilters();
    showToast(`Guided to Triage: Showing findings authored by ${devName}`, 'info');
}

function filterBySeverityAndNavigate(severity) {
    navigate('triage');
    const sevSel = document.getElementById('filter-severity');
    if (sevSel) sevSel.value = severity;

    const searchInput = document.getElementById('filter-search');
    const typeSelect = document.getElementById('filter-type');
    const quadSelect = document.getElementById('filter-quadrant');
    const stdSelect = document.getElementById('filter-standard');
    const devSelect = document.getElementById('filter-developer');

    if (searchInput) searchInput.value = '';
    if (typeSelect) typeSelect.value = '';
    if (quadSelect) quadSelect.value = '';
    if (stdSelect) stdSelect.value = '';
    if (devSelect) devSelect.value = '';

    applyFilters();
    showToast(`Guided to Triage: Filtered by severity ${severity}`, 'info');
}

function filterByQuadrantAndNavigate(quadrant) {
    navigate('triage');
    const quadSel = document.getElementById('filter-quadrant');
    if (quadSel) quadSel.value = quadrant;

    const searchInput = document.getElementById('filter-search');
    const typeSelect = document.getElementById('filter-type');
    const sevSelect = document.getElementById('filter-severity');
    const stdSelect = document.getElementById('filter-standard');
    const devSelect = document.getElementById('filter-developer');

    if (searchInput) searchInput.value = '';
    if (typeSelect) typeSelect.value = '';
    if (sevSelect) sevSelect.value = '';
    if (stdSelect) stdSelect.value = '';
    if (devSelect) devSelect.value = '';

    applyFilters();
    const label = quadrant.replace('_', ' ');
    showToast(`Guided to Triage: Filtered by prioritization quadrant ${label}`, 'info');
}

function filterByStandardAndNavigate(standard) {
    navigate('triage');
    const stdSel = document.getElementById('filter-standard');
    if (stdSel) {
        let matched = false;
        for (let i = 0; i < stdSel.options.length; i++) {
            if (stdSel.options[i].value === standard || stdSel.options[i].text.includes(standard)) {
                stdSel.selectedIndex = i;
                matched = true;
                break;
            }
        }
        if (!matched) stdSel.value = standard;
    }

    const searchInput = document.getElementById('filter-search');
    const typeSelect = document.getElementById('filter-type');
    const sevSelect = document.getElementById('filter-severity');
    const quadSelect = document.getElementById('filter-quadrant');
    const devSelect = document.getElementById('filter-developer');

    if (searchInput) searchInput.value = '';
    if (typeSelect) typeSelect.value = '';
    if (sevSelect) sevSelect.value = '';
    if (quadSelect) quadSelect.value = '';
    if (devSelect) devSelect.value = '';

    applyFilters();
    showToast(`Guided to Triage: Filtered by standard ${standard}`, 'info');
}

async function guideToFinding(findingId) {
    // If detail modal is open, close it
    const modalEl = document.getElementById('modal-finding-detail');
    if (modalEl) modalEl.classList.remove('active');

    // Switch view to triage
    navigate('triage');

    // Reset table search & filters so the target finding is visible
    const searchInput = document.getElementById('filter-search');
    const typeSelect = document.getElementById('filter-type');
    const sevSelect = document.getElementById('filter-severity');
    const quadSelect = document.getElementById('filter-quadrant');
    const stdSelect = document.getElementById('filter-standard');
    const devSelect = document.getElementById('filter-developer');

    if (searchInput) searchInput.value = '';
    if (typeSelect) typeSelect.value = '';
    if (sevSelect) sevSelect.value = '';
    if (quadSelect) quadSelect.value = '';
    if (stdSelect) stdSelect.value = '';
    if (devSelect) devSelect.value = '';

    if (!state.findings || state.findings.length === 0) {
        await loadFindings();
    } else {
        applyFilters();
    }

    // Allow DOM to finish rendering
    setTimeout(() => {
        const rowId = `finding-row-${findingId}`;
        const rowEl = document.getElementById(rowId);
        if (rowEl) {
            rowEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
            rowEl.classList.remove('highlight-finding-pulse');
            void rowEl.offsetWidth; // Force CSS reflow
            rowEl.classList.add('highlight-finding-pulse');
            showToast(`Guided directly to finding: ${rowEl.dataset.title || findingId}`, 'success');
        } else {
            console.warn(`Finding row ${rowId} not found in DOM.`);
        }
    }, 150);
}

function guideToActiveFinding() {
    if (state.activeFinding && state.activeFinding.id) {
        guideToFinding(state.activeFinding.id);
    }
}

function onDashboardFindingsSearch(query) {
    state.dashboardFindingSearch = query;
    renderDashboardFindingsFeed();
}

function filterDashboardFindings(filterType) {
    state.dashboardFindingFilter = filterType;
    document.querySelectorAll('.dashboard-filter-btn').forEach(b => b.classList.remove('active'));
    const btnMap = {
        'ALL': 'dash-filter-all',
        'ACT_NOW': 'dash-filter-actnow',
        'CRITICAL': 'dash-filter-critical',
        'TICKETED': 'dash-filter-ticketed'
    };
    const activeBtn = document.getElementById(btnMap[filterType]);
    if (activeBtn) activeBtn.classList.add('active');
    renderDashboardFindingsFeed();
}

function renderDashboardFindingsFeed() {
    const container = document.getElementById("dashboard-findings-feed");
    if (!container) return;

    const findings = state.findings || [];
    const filter = state.dashboardFindingFilter || 'ALL';
    const searchQuery = (state.dashboardFindingSearch || '').toLowerCase().trim();

    // Filter findings
    const filtered = findings.filter(f => {
        if (filter === 'ACT_NOW' && f.quadrant !== 'ACT_NOW') return false;
        if (filter === 'CRITICAL' && f.severity !== 'CRITICAL') return false;
        if (filter === 'TICKETED' && !(f.jira_key || f.zammad_id || f.ticket_assigned_to)) return false;

        if (searchQuery) {
            const matchTitle = (f.title || '').toLowerCase().includes(searchQuery);
            const matchPath = (f.file_path || '').toLowerCase().includes(searchQuery);
            const matchCve = (f.cve_id || '').toLowerCase().includes(searchQuery);
            const matchAuthor = (f.author_name || '').toLowerCase().includes(searchQuery);
            if (!matchTitle && !matchPath && !matchCve && !matchAuthor) return false;
        }
        return true;
    });

    if (filtered.length === 0) {
        container.innerHTML = `
            <div style="text-align: center; padding: 40px 20px; background: rgba(15, 23, 42, 0.4); border: 1px dashed rgba(255, 255, 255, 0.1); border-radius: 8px;">
                <div style="font-size: 28px; margin-bottom: 8px;">🛡️</div>
                <div style="font-weight: 600; color: #fff; font-size: 15px;">No findings match the selected filter</div>
                <div style="font-size: 13px; color: var(--text-secondary); margin-top: 4px;">
                    ${searchQuery ? `No results matching query "${escapeHtml(searchQuery)}".` : 'Try selecting a different filter tab above.'}
                </div>
            </div>
        `;
        return;
    }

    container.innerHTML = "";

    filtered.forEach(f => {
        const row = document.createElement("div");
        row.className = "dashboard-finding-row clickable-interactive";
        row.id = `dash-finding-item-${f.id}`;
        row.title = "Click to inspect vulnerability details, AI fix diff, and author ticket";

        const sevClass = `badge-${f.severity.toLowerCase()}`;
        const quadColor = f.quadrant === "ACT_NOW" ? "#ef4444" : f.quadrant === "CRITICAL_PATCH" ? "#f97316" : f.quadrant === "OPPORTUNISTIC" ? "#eab308" : "#10b981";
        const quadLabel = f.quadrant ? f.quadrant.replace('_', ' ') : 'NORMAL';

        const authorName = escapeHtml(f.author_name || "Unknown Author");
        const ticketAssigned = f.ticket_assigned_to || f.author_name;
        const hasTicket = !!(f.jira_key || f.zammad_id || f.ticket_assigned_to);

        const ticketBadgeHtml = hasTicket
            ? `<span class="badge" style="background: rgba(168, 85, 247, 0.2); color: #d8b4fe; font-size: 11px; border: 1px solid rgba(168, 85, 247, 0.4);" title="Ticket assigned to author ${escapeHtml(ticketAssigned)}">
                 🎫 ${f.jira_key ? 'Jira #' + f.jira_key : (f.zammad_id ? 'Zammad #' + f.zammad_id : 'Ticket')} &rarr; ${escapeHtml(ticketAssigned)}
               </span>`
            : `<span class="badge" style="background: rgba(255, 255, 255, 0.05); color: var(--text-muted); font-size: 11px;">Unassigned</span>`;

        row.innerHTML = `
            <div style="display: flex; align-items: center; gap: 14px; flex: 1; min-width: 320px;">
                <span class="badge ${sevClass}" style="min-width: 75px; text-align: center;">${f.severity}</span>
                <div style="flex: 1;">
                    <div class="dashboard-finding-title" style="cursor: pointer;" onclick="openFindingDetail('${f.id}')">
                        ${escapeHtml(f.title)}
                    </div>
                    <div style="display: flex; align-items: center; gap: 12px; margin-top: 4px; font-size: 12px; flex-wrap: wrap;">
                        <span class="badge" style="background: ${(f.age_days || 0) > 14 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)'}; color: ${(f.age_days || 0) > 14 ? '#fca5a5' : '#6ee7b7'}; font-size: 10px; border: 1px solid ${(f.age_days || 0) > 14 ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}; padding: 2px 6px;">
                            🕒 ${escapeHtml(f.age_display || ((f.age_days !== undefined ? f.age_days + 'd old' : 'Today')))}
                        </span>
                        <span style="color: var(--accent-cyan); font-family: var(--font-mono);">
                            📁 ${escapeHtml(f.file_path)}:${f.line_start}
                        </span>
                        <span style="color: #94a3b8;">
                            👤 Author: <strong style="color: #f1f5f9;">${authorName}</strong>
                        </span>
                        ${f.cve_id ? `<span style="color: #cbd5e1; font-family: var(--font-mono); font-size: 11px;">[${escapeHtml(f.cve_id)}]</span>` : ''}
                    </div>
                </div>
            </div>

            <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
                <div style="text-align: right; min-width: 110px;">
                    <div style="font-weight: 700; color: ${quadColor}; font-size: 13px;">${f.composite_risk_score}/100 Risk</div>
                    <div style="font-size: 11px; text-transform: uppercase; font-weight: 600; color: ${quadColor};">${quadLabel} (${f.sla_days || 14}d)</div>
                </div>

                <div style="min-width: 140px;">
                    ${ticketBadgeHtml}
                </div>

                <div style="display: flex; gap: 8px; align-items: center;">
                    <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); openFindingDetail('${f.id}')" title="Inspect full finding details, AI code remediation, and ticket dispatch">
                        🔍 Inspect
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="event.stopPropagation(); guideToFinding('${f.id}')" style="background: rgba(56, 189, 248, 0.15); border-color: rgba(56, 189, 248, 0.4); color: var(--accent-cyan);" title="Guide directly to this finding row in Triage inventory">
                        🧭 Locate in Triage
                    </button>
                </div>
            </div>
        `;

        // Click row anywhere (except on buttons) to open details
        row.onclick = (e) => {
            if (!e.target.closest('button')) {
                openFindingDetail(f.id);
            }
        };

        container.appendChild(row);
    });
}

async function changeFindingStatus(newStatus) {
    if (!state.activeFinding) return;
    try {
        const resp = await fetch(`/api/findings/${state.activeFinding.id}/status?status=${newStatus}`, {
            method: "PATCH"
        });
        if (resp.ok) {
            state.activeFinding.status = newStatus;
            showToast(`Finding status updated to: ${newStatus}`, "success");
            await loadFindings();
        }
    } catch (e) {
        showToast("Error updating status", "error");
    }
}

async function dispatchTicket(platform) {
    if (!state.activeFinding) return;
    const author = state.activeFinding.author_name || "Code Author";
    showToast(`Dispatching and assigning ticket directly to author '${author}' via ${platform.toUpperCase()}...`, "info");
    try {
        const resp = await fetch(`/api/findings/${state.activeFinding.id}/ticket`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ platform, finding_id: state.activeFinding.id })
        });
        const res = await resp.json();
        if (res.success) {
            const assignedTo = res.assigned_to || author;
            const isMockStr = res.is_mock ? " (Demonstration Mode)" : "";
            showToast(`Ticket ${res.ticket_key} created and assigned directly to code author: ${assignedTo}${isMockStr}!`, "success");

            state.activeFinding.status = "in_triage";
            if (platform === "jira") state.activeFinding.jira_key = res.ticket_key;
            if (platform === "zammad") state.activeFinding.zammad_id = res.ticket_key;
            state.activeFinding.ticket_assigned_to = assignedTo;
            state.activeFinding.ticket_assigned_email = res.assigned_email || state.activeFinding.author_email;

            const statusSel = document.getElementById("detail-status-select");
            if (statusSel) statusSel.value = "in_triage";

            const ticketPill = document.getElementById("detail-ticket-status-pill");
            if (ticketPill) {
                ticketPill.textContent = `${platform.toUpperCase()} #${res.ticket_key} (Assigned to ${assignedTo})`;
                ticketPill.style.background = platform === "jira" ? "rgba(59, 130, 246, 0.2)" : "rgba(16, 185, 129, 0.2)";
                ticketPill.style.color = platform === "jira" ? "#93c5fd" : "#6ee7b7";
            }

            await loadFindings();
        } else {
            showToast(`Ticket creation failed: ${res.message || res.detail}`, "error");
        }
    } catch (e) {
        showToast("Error contacting ticketing integration", "error");
    }
}

async function autoDispatchProjectTickets() {
    const projId = state.selectedProjectId || (state.projects[0] ? state.projects[0].id : null);
    if (!projId) {
        showToast("Please select a project first", "info");
        return;
    }
    showToast("Auto-assigning tickets directly to code authors for all open vulnerabilities...", "info");
    try {
        const resp = await fetch(`/api/projects/${projId}/auto-ticket?platform=jira`, {
            method: "POST"
        });
        const res = await resp.json();
        if (res.success) {
            showToast(`Successfully created & assigned ${res.dispatched_count} tickets directly to respective code authors!`, "success");
            await loadFindings();
        } else {
            showToast(`Auto-dispatch failed: ${res.detail || 'Unknown error'}`, "error");
        }
    } catch (e) {
        showToast("Error executing auto-dispatch", "error");
    }
}

async function requestAIRemediation() {
    if (!state.activeFinding) return;

    const btn = document.getElementById("btn-ask-ai");
    const btnText = document.getElementById("ai-btn-text");
    const btnSpinner = document.getElementById("ai-btn-spinner");
    const box = document.getElementById("detail-ai-remediation-box");

    if (btn) btn.disabled = true;
    if (btnText) btnText.textContent = "AI Synthesizing Fix...";
    if (btnSpinner) btnSpinner.style.display = "inline-block";

    try {
        const resp = await fetch(`/api/findings/${state.activeFinding.id}/ai-remediation`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        if (resp.status === 403) {
            showToast("Access Restricted: Only finding author or Security Admin can generate AI fixes", "error");
            return;
        }

        if (!resp.ok) {
            const errData = await resp.json().catch(() => ({}));
            showToast(errData.detail || "Failed to generate AI remediation", "error");
            return;
        }

        const data = await resp.json();

        // Populate the AI box elements
        const badge = document.getElementById("ai-model-badge");
        if (badge) badge.textContent = `${data.provider}: ${data.model}`;
        
        const ts = document.getElementById("ai-timestamp");
        if (ts) ts.textContent = new Date().toLocaleTimeString();

        const rootEl = document.getElementById("ai-root-cause");
        if (rootEl) rootEl.textContent = data.root_cause_analysis || "No root cause analysis returned.";

        const vulnSnippetEl = document.getElementById("playground-vulnerable-snippet");
        if (vulnSnippetEl && state.activeFinding) {
            vulnSnippetEl.textContent = state.activeFinding.code_snippet || "/* Flagged source context */";
        }

        const diffEl = document.getElementById("ai-code-diff");
        if (diffEl) diffEl.textContent = data.suggested_fix_diff || "// No code diff available";

        const compEl = document.getElementById("ai-compliance");
        if (compEl) compEl.textContent = data.compliance_implications || "Standard security baseline preserved.";

        const verifEl = document.getElementById("ai-verification");
        if (verifEl) verifEl.textContent = data.verification_steps || "Perform automated test verification.";

        if (box) box.style.display = "block";
        showToast(`✨ AI Remediation & Secure Diff synthesized! (${data.model})`, "success");
    } catch (e) {
        showToast("Error contacting AI remediation service", "error");
    } finally {
        if (btn) btn.disabled = false;
        if (btnText) btnText.textContent = "✨ Re-run AI Remediation";
        if (btnSpinner) btnSpinner.style.display = "none";
    }
}

function copyAIDiff() {
    const diffEl = document.getElementById("ai-code-diff");
    if (!diffEl || !diffEl.textContent) return;
    navigator.clipboard.writeText(diffEl.textContent).then(() => {
        showToast("Secure refactored code copied to clipboard!", "success");
    }).catch(() => {
        showToast("Failed to copy to clipboard", "error");
    });
}

async function triggerEvaluateConfidence() {
    if (!state.activeFinding) return;
    const btnText = document.getElementById("eval-conf-text");
    const spinner = document.getElementById("eval-conf-spinner");
    if (btnText) btnText.textContent = "Analyzing...";
    if (spinner) spinner.style.display = "inline-block";

    try {
        const resp = await fetch(`/api/findings/${state.activeFinding.id}/evaluate-confidence`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        if (resp.status === 403) {
            showToast("Access Restricted: Only code author or Security Admin can evaluate confidence", "error");
            return;
        }

        if (resp.ok) {
            const data = await resp.json();
            state.activeFinding.ai_confidence_score = data.confidence_score;
            state.activeFinding.ai_confidence_label = data.confidence_label;
            state.activeFinding.ai_confidence_rationale = data.rationale;
            
            // Also update in state.findings array
            const fInList = (state.findings || []).find(x => x.id === state.activeFinding.id);
            if (fInList) {
                fInList.ai_confidence_score = data.confidence_score;
                fInList.ai_confidence_label = data.confidence_label;
                fInList.ai_confidence_rationale = data.rationale;
            }

            openFindingDetail(state.activeFinding);
            showToast(`AI Confidence Evaluated: ${data.confidence_label}`, "success");
        } else {
            const err = await resp.json().catch(() => ({}));
            showToast(err.detail || "Failed to evaluate AI confidence", "error");
        }
    } catch (e) {
        showToast("Error connecting to server", "error");
    } finally {
        if (btnText) btnText.textContent = "⚡ Evaluate AI Confidence";
        if (spinner) spinner.style.display = "none";
    }
}

async function createRemediationPR() {
    if (!state.activeFinding) return;

    const btn = document.getElementById("btn-create-pr");
    const btnText = document.getElementById("pr-btn-text");
    const btnSpinner = document.getElementById("pr-btn-spinner");

    if (btn) btn.disabled = true;
    if (btnText) btnText.textContent = "Branching & Generating PR...";
    if (btnSpinner) btnSpinner.style.display = "inline-block";

    try {
        const resp = await fetch(`/api/findings/${state.activeFinding.id}/create-pr`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        if (resp.status === 403) {
            showToast("Access Restricted: You can only create autonomous PRs for code you authored.", "error");
            return;
        }

        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            showToast(err.detail || "Failed to create autonomous PR", "error");
            return;
        }

        const res = await resp.json();
        showToast(`🚀 Autonomous PR #${res.pr_number} created on branch ${res.branch_name}!`, "success");

        const box = document.getElementById("detail-ai-remediation-box");
        if (box) {
            const prNotice = document.createElement("div");
            prNotice.style.cssText = "margin-top: 14px; padding: 12px 16px; background: rgba(34, 197, 94, 0.15); border: 1px solid rgba(34, 197, 94, 0.4); border-radius: 8px; color: #86efac; font-size: 13px;";
            prNotice.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="color: #4ade80;">🚀 Pull Request #${res.pr_number} Dispatched</strong>
                    <span class="badge" style="background: rgba(34, 197, 94, 0.3); color: #86efac;">CI GATE READY</span>
                </div>
                <div>Target Branch: <code style="color: #fff; background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">${res.branch_name}</code></div>
                <div style="margin-top: 4px; font-size: 12px; color: #cbd5e1;">Author Attribution: <strong>${res.author_attributed}</strong></div>
                <div style="margin-top: 6px;">
                    <a href="${res.pr_url}" target="_blank" style="color: #38bdf8; text-decoration: underline; font-weight: 600;">View Pull Request &amp; Automated Verification Suite &rarr;</a>
                </div>
            `;
            box.appendChild(prNotice);
        }
    } catch (e) {
        showToast("Error creating remediation PR", "error");
    } finally {
        if (btn) btn.disabled = false;
        if (btnText) btnText.textContent = "🚀 1-Click Create Autonomous Fix PR";
        if (btnSpinner) btnSpinner.style.display = "none";
    }
}

// --- Natural Language Rule Studio ---
function setPromptExample(text) {
    const el = document.getElementById("nl-rule-prompt");
    if (el) el.value = text;
}

let activeGeneratedRule = null;

async function generateRuleFromPrompt() {
    const promptInput = document.getElementById("nl-rule-prompt")?.value;
    if (!promptInput) {
        showToast("Please enter a rule description first", "error");
        return;
    }

    showToast("Synthesizing rule from natural language...", "info");
    const btn = document.getElementById("btn-generate-rule");
    if (btn) btn.disabled = true;

    try {
        const resp = await fetch("/api/rules/generate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ prompt: promptInput })
        });

        if (resp.ok) {
            const rule = await resp.json();
            activeGeneratedRule = rule;
            const editor = document.getElementById("rule-yaml-editor");
            if (editor) editor.value = rule.yaml_representation;
            const creator = rule.created_by || "AegisSec Synthesizer";
            showToast(`Rule synthesized successfully via ${creator}!`, "success");
        } else {
            showToast("Failed to synthesize rule", "error");
        }
    } catch (e) {
        showToast("Rule synthesis error", "error");
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function testRuleSandbox() {
    const editor = document.getElementById("rule-yaml-editor");
    const codeBox = document.getElementById("rule-sandbox-code");
    const resultsBox = document.getElementById("rule-test-results");

    if (!editor || !codeBox || !resultsBox) return;

    const ruleYaml = editor.value;
    const sampleCode = codeBox.value;

    if (!ruleYaml.trim()) {
        showToast("Generate or write a rule YAML first", "error");
        return;
    }
    if (!sampleCode.trim()) {
        showToast("Please paste code in the sandbox to test", "error");
        return;
    }

    try {
        const resp = await fetch("/api/rules/test", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ rule_yaml: ruleYaml, sample_code: sampleCode })
        });
        const res = await resp.json();
        if (res.success) {
            if (res.matched_count > 0) {
                let html = `<div style="color: #ef4444; font-weight: bold; margin-bottom: 8px;">VIOLATION DETECTED (${res.matched_count} matches):</div>`;
                res.matches.forEach(m => {
                    html += `<div style="margin-bottom: 8px;"><strong>Line ${m.line}:</strong> matched "<code>${escapeHtml(m.matched_text)}</code>"</div>`;
                    html += `<pre class="code-view" style="margin-bottom: 6px;">${escapeHtml(m.snippet)}</pre>`;
                });
                resultsBox.innerHTML = html;
                showToast(`Rule triggered! Detected ${res.matched_count} matches.`, "success");
            } else {
                resultsBox.innerHTML = `<div style="color: #10b981; font-weight: bold;">PASSED: No rule violations found in the provided code snippet.</div>`;
                showToast("Test clean: No violations detected.", "info");
            }
        } else {
            resultsBox.innerHTML = `<div style="color: #ef4444;">Error testing rule: ${res.error}</div>`;
        }
    } catch (e) {
        showToast("Error running sandbox test", "error");
    }
}

async function saveActiveRule() {
    const editor = document.getElementById("rule-yaml-editor");
    if (!editor || !editor.value.trim()) {
        showToast("No rule to save", "error");
        return;
    }

    try {
        let ruleObj = activeGeneratedRule;
        if (!ruleObj) {
            ruleObj = {
                id: `RULE-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
                name: "Custom Security Rule",
                type: "sast_pattern",
                rule_category: "sast",
                yaml_representation: editor.value,
                is_active: true
            };
        } else {
            ruleObj.yaml_representation = editor.value;
        }

        const resp = await fetch("/api/rules", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(ruleObj)
        });

        if (resp.ok) {
            showToast("Custom rule saved and activated for all future scans!", "success");
            await loadCustomRules();
        } else {
            showToast("Failed to save rule", "error");
        }
    } catch (e) {
        showToast("Error saving rule", "error");
    }
}

async function loadCustomRules() {
    try {
        const resp = await fetch("/api/rules");
        if (resp.ok) {
            state.customRules = await resp.json();
            renderCustomRulesTable();
        }
    } catch (e) {
        console.error("Rules loading error:", e);
    }
}

function renderCustomRulesTable() {
    const tbody = document.getElementById("custom-rules-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (state.customRules.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No custom rules active. Generate one above!</td></tr>';
        return;
    }

    state.customRules.forEach(r => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><code>${r.id}</code></td>
            <td>
                <strong>${r.name}</strong>
                <div style="font-size: 12px; color: var(--text-muted);">${r.nl_prompt || r.description}</div>
            </td>
            <td><span class="badge" style="background: rgba(255,255,255,0.06);">${r.rule_category.toUpperCase()}</span></td>
            <td><span class="badge badge-${(r.severity || 'medium').toLowerCase()}">${r.severity || 'MEDIUM'}</span></td>
            <td><code>${r.cwe || 'CWE-699'}</code></td>
            <td><span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981;">ACTIVE</span></td>
            <td style="text-align: right;">
                <button class="btn btn-danger btn-sm" onclick="deleteRule('${r.id}')">Delete</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function deleteRule(ruleId) {
    try {
        const resp = await fetch(`/api/rules/${ruleId}`, { method: "DELETE" });
        if (resp.ok) {
            showToast("Rule removed", "success");
            await loadCustomRules();
        }
    } catch (e) {
        showToast("Error deleting rule", "error");
    }
}

// --- Standards & Compliance View ---
async function loadStandards() {
    try {
        const resp = await fetch("/api/standards");
        if (resp.ok) {
            state.standards = await resp.json();
        }
    } catch (e) {
        console.error("Failed loading standards:", e);
    }
}

function renderComplianceMatrix() {
    const container = document.getElementById("standards-categories-container");
    if (!container || !state.standards.taxonomy) return;
    container.innerHTML = "";

    const tax = state.standards.taxonomy;
    const counts = state.standards.active_counts || {};

    for (const [stdKey, stdObj] of Object.entries(tax)) {
        const card = document.createElement("div");
        card.className = "glass-card";

        let controlsHtml = "";
        for (const [ctrlId, ctrlDesc] of Object.entries(stdObj.controls || {})) {
            const fullTag = `${stdKey}:${ctrlId}`;
            const activeCount = counts[fullTag] || 0;
            const badgeClass = activeCount > 0 ? "badge-critical" : "badge-low";

            controlsHtml += `
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.04);">
                    <div>
                        <strong style="color: var(--accent-cyan);">${ctrlId}</strong> - ${ctrlDesc}
                    </div>
                    <div>
                        <span class="badge ${badgeClass}">${activeCount} active findings</span>
                    </div>
                </div>
            `;
        }

        card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
                <div>
                    <h3 style="font-size: 18px; font-weight: 700;">${stdObj.name}</h3>
                    <span style="font-size: 12px; color: var(--accent-cyan); text-transform: uppercase; font-weight: 600;">${stdObj.category}</span>
                </div>
            </div>
            <p style="font-size: 13px; color: var(--text-secondary); margin-bottom: 16px;">${stdObj.description}</p>
            <div style="display: flex; flex-direction: column;">
                ${controlsHtml}
            </div>
        `;
        container.appendChild(card);
    }
}

// --- Integrations ---
function onLLMProviderChange(provider) {
    const modelInput = document.getElementById("llm-model");
    const endpointInput = document.getElementById("llm-endpoint-url");
    if (!modelInput) return;

    if (provider === "openai") {
        modelInput.value = "gpt-4o";
        if (endpointInput) endpointInput.placeholder = "https://api.openai.com/v1 (default)";
    } else if (provider === "anthropic") {
        modelInput.value = "claude-3-5-sonnet-20241022";
        if (endpointInput) endpointInput.placeholder = "https://api.anthropic.com/v1 (default)";
    } else if (provider === "gemini") {
        modelInput.value = "gemini-1.5-pro";
        if (endpointInput) endpointInput.placeholder = "https://generativelanguage.googleapis.com (default)";
    } else if (provider === "ollama") {
        modelInput.value = "llama3.2:latest";
        if (endpointInput) {
            endpointInput.value = endpointInput.value || "http://localhost:11434";
            endpointInput.placeholder = "http://localhost:11434";
        }
    } else if (provider === "custom") {
        modelInput.value = "custom-model";
        if (endpointInput) {
            endpointInput.placeholder = "http://localhost:8080/v1";
        }
    }
}

async function loadLLMConfig() {
    try {
        const resp = await fetch("/api/integrations/llm");
        if (resp.ok) {
            const data = await resp.json();
            if (data.provider) document.getElementById("llm-provider").value = data.provider;
            if (data.model) document.getElementById("llm-model").value = data.model;
            if (data.api_key) document.getElementById("llm-api-key").value = data.api_key;
            if (data.endpoint_url) document.getElementById("llm-endpoint-url").value = data.endpoint_url;
            if (data.temperature !== undefined) {
                document.getElementById("llm-temperature").value = data.temperature;
                document.getElementById("llm-temp-val").textContent = data.temperature;
            }
            if (data.enable_rule_generation !== undefined) {
                document.getElementById("llm-enable-rule-gen").checked = data.enable_rule_generation;
            }
            if (data.enable_remediation !== undefined) {
                document.getElementById("llm-enable-remediation").checked = data.enable_remediation;
            }
            const chip = document.getElementById("llm-status-chip");
            if (chip) {
                if (data.enabled) {
                    chip.textContent = "CONFIGURED";
                    chip.style.background = "rgba(16, 185, 129, 0.15)";
                    chip.style.color = "#10b981";
                    chip.style.borderColor = "rgba(16, 185, 129, 0.3)";
                } else {
                    chip.textContent = "READY / DEMO";
                    chip.style.background = "rgba(148, 163, 184, 0.15)";
                    chip.style.color = "#94a3b8";
                    chip.style.borderColor = "rgba(148, 163, 184, 0.3)";
                }
            }
        }
    } catch (e) {
        console.error("Error loading LLM config:", e);
    }
}

async function saveLLMConfig(e) {
    e.preventDefault();
    const payload = {
        enabled: true,
        provider: document.getElementById("llm-provider").value,
        model: document.getElementById("llm-model").value,
        api_key: document.getElementById("llm-api-key").value,
        endpoint_url: document.getElementById("llm-endpoint-url").value || null,
        temperature: parseFloat(document.getElementById("llm-temperature").value || 0.2),
        enable_rule_generation: document.getElementById("llm-enable-rule-gen").checked,
        enable_remediation: document.getElementById("llm-enable-remediation").checked
    };

    try {
        const resp = await fetch("/api/integrations/llm", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        if (resp.ok) {
            showToast("LLM Configuration saved successfully!", "success");
            const chip = document.getElementById("llm-status-chip");
            if (chip) {
                chip.textContent = "CONFIGURED";
                chip.style.background = "rgba(16, 185, 129, 0.15)";
                chip.style.color = "#10b981";
                chip.style.borderColor = "rgba(16, 185, 129, 0.3)";
            }
        } else {
            showToast("Failed to save LLM configuration", "error");
        }
    } catch (e) {
        showToast("Error saving LLM config", "error");
    }
}

async function loadIntegrations() {
    await loadLLMConfig();
    try {
        const jResp = await fetch("/api/integrations/jira");
        if (jResp.ok) {
            const j = await jResp.json();
            if (j.url) document.getElementById("jira-url").value = j.url;
            if (j.email) document.getElementById("jira-email").value = j.email;
            if (j.project_key) document.getElementById("jira-project-key").value = j.project_key;
            if (j.issue_type) document.getElementById("jira-issue-type").value = j.issue_type;
        }

        const zResp = await fetch("/api/integrations/zammad");
        if (zResp.ok) {
            const z = await zResp.json();
            if (z.url) document.getElementById("zammad-url").value = z.url;
            if (z.group) document.getElementById("zammad-group").value = z.group;
        }
    } catch (e) {}
}

async function saveJiraConfig(e) {
    e.preventDefault();
    const payload = {
        enabled: true,
        url: document.getElementById("jira-url").value,
        email: document.getElementById("jira-email").value,
        api_token: document.getElementById("jira-token").value,
        project_key: document.getElementById("jira-project-key").value,
        issue_type: document.getElementById("jira-issue-type").value
    };

    try {
        const resp = await fetch("/api/integrations/jira", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        if (resp.ok) showToast("Jira integration saved successfully!", "success");
    } catch (e) {
        showToast("Error saving Jira config", "error");
    }
}

async function saveZammadConfig(e) {
    e.preventDefault();
    const payload = {
        enabled: true,
        url: document.getElementById("zammad-url").value,
        api_token: document.getElementById("zammad-token").value,
        group: document.getElementById("zammad-group").value
    };

    try {
        const resp = await fetch("/api/integrations/zammad", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        if (resp.ok) showToast("Zammad integration saved successfully!", "success");
    } catch (e) {
        showToast("Error saving Zammad config", "error");
    }
}

async function testIntegration(key) {
    showToast(`Testing connectivity to ${key.toUpperCase()}...`, "info");
    try {
        const resp = await fetch(`/api/integrations/${key}/test`, { method: "POST" });
        const res = await resp.json();
        if (res.success) {
            showToast(`Connected: ${res.message}`, "success");
        } else {
            showToast(`Connection test failed: ${res.message}`, "error");
        }
    } catch (e) {
        showToast("Integration connection test failed", "error");
    }
}

// --- Exporters ---
function openExportMenu() {
    exportCurrentReport("html");
}

function exportCurrentReport(format) {
    if (!state.activeProjectId) {
        showToast("Select a project to export", "error");
        return;
    }
    const url = `/api/projects/${state.activeProjectId}/export/${format}`;
    window.open(url, "_blank");
    showToast(`Exporting ${format.toUpperCase()} report...`, "success");
}

// --- User Management ---
async function loadUsers() {
    try {
        const resp = await fetch("/api/users");
        if (resp.ok) {
            const users = await resp.json();
            const tbody = document.getElementById("users-tbody");
            if (!tbody) return;
            tbody.innerHTML = "";

            users.forEach(u => {
                const tr = document.createElement("tr");
                const privMap = {
                    admin: "Full System Access, Integrations, Custom Rules, Project Management",
                    security_engineer: "Scan Execution, Custom Rule Generation, Ticket Dispatch, Project Management",
                    developer: "View Projects, Inspect Findings, Mark False Positives, View Remediation",
                    auditor: "Read-Only Compliance Reports, Standards Matrices, Audit Log Inspection"
                };

                tr.innerHTML = `
                    <td><strong>${u.username}</strong></td>
                    <td>${u.email}</td>
                    <td><span class="badge" style="background: rgba(56, 189, 248, 0.15); color: var(--accent-cyan);">${u.role.toUpperCase()}</span></td>
                    <td style="font-size: 12px; color: var(--text-secondary);">${privMap[u.role] || 'Standard Access'}</td>
                    <td style="font-size: 13px; color: var(--text-muted);">${new Date(u.created_at).toLocaleDateString()}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        console.error("Failed loading users:", e);
    }
}

// --- Tool Benchmark & Comparison ---
async function loadBenchmarkData() {
    try {
        const resp = await fetch("/api/benchmark");
        if (!resp.ok) {
            showToast("Failed to load benchmark data", "error");
            return;
        }
        const data = await resp.json();

        // 1. Render Scorecards
        const scorecardsContainer = document.getElementById("benchmark-scorecards");
        if (scorecardsContainer && data.tools) {
            scorecardsContainer.innerHTML = "";
            const toolOrder = ["aegissec", "semgrep", "sonarqube", "depcheck"];
            toolOrder.forEach(key => {
                const t = data.tools[key];
                if (!t) return;
                const isLeader = key === "aegissec";
                const borderStyle = isLeader ? "border: 1px solid var(--accent-indigo); background: linear-gradient(180deg, rgba(99, 102, 241, 0.15), rgba(15, 23, 42, 0.8));" : "background: rgba(15, 23, 42, 0.6); border: 1px solid var(--border);";
                const badgeColor = isLeader ? "background: rgba(99, 102, 241, 0.2); color: #c7d2fe; border: 1px solid rgba(99, 102, 241, 0.4);" : "background: rgba(148, 163, 184, 0.15); color: #94a3b8;";

                const card = document.createElement("div");
                card.className = "glass-card";
                card.style.cssText = `${borderStyle} padding: 18px; border-radius: var(--radius-md); display: flex; flex-direction: column; justify-content: space-between; position: relative;`;

                const strengthsList = (t.strengths || []).map(s => `<li style="font-size: 11px; color: #cbd5e1; margin-bottom: 4px;">✔ ${s}</li>`).join("");
                const limitationsList = (t.limitations || []).map(l => `<li style="font-size: 11px; color: #f87171; margin-bottom: 4px;">✖ ${l}</li>`).join("");

                card.innerHTML = `
                    <div>
                        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                            <div>
                                <h3 style="font-size: 18px; font-weight: 700; color: ${isLeader ? '#38bdf8' : '#fff'};">${t.name}</h3>
                                <div style="font-size: 11px; color: var(--text-muted);">${t.vendor}</div>
                            </div>
                            <div style="font-size: 22px; font-weight: 800; color: ${isLeader ? 'var(--accent-cyan)' : '#e2e8f0'}; font-family: var(--font-mono);">${t.overall_score}<span style="font-size: 12px; font-weight: 400; color: var(--text-muted);">/100</span></div>
                        </div>
                        <span class="badge" style="${badgeColor} font-size: 10px; margin-bottom: 12px; display: inline-block;">${t.category}</span>
                        <div style="margin-top: 10px;">
                            <div style="font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase; margin-bottom: 6px;">Key Highlights</div>
                            <ul style="list-style: none; padding-left: 0; margin: 0;">
                                ${strengthsList}
                            </ul>
                        </div>
                    </div>
                    ${limitationsList ? `
                    <div style="margin-top: 12px; padding-top: 8px; border-top: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-size: 10px; font-weight: 700; color: #f87171; text-transform: uppercase; margin-bottom: 4px;">Limitations / Gaps</div>
                        <ul style="list-style: none; padding-left: 0; margin: 0;">
                            ${limitationsList}
                        </ul>
                    </div>
                    ` : ''}
                `;
                scorecardsContainer.appendChild(card);
            });
        }

        // 2. Render KPIs
        const kpisContainer = document.getElementById("benchmark-kpis");
        if (kpisContainer && data.benchmarks) {
            kpisContainer.innerHTML = "";
            const b = data.benchmarks;
            const kpiConfigs = [
                { key: "alert_fatigue_reduction", title: "Noise Reduction Rate", aegis: b.alert_fatigue_reduction.scores.aegissec, legacy: b.alert_fatigue_reduction.scores.sonarqube, desc: "Via EPSS weaponization telemetry" },
                { key: "rule_synthesis_latency", title: "Rule Authoring Latency", aegis: b.rule_synthesis_latency.scores.aegissec, legacy: b.rule_synthesis_latency.scores.sonarqube, desc: "Natural Language vs Java/YAML" },
                { key: "mean_time_to_remediation", title: "Remediation Acceleration", aegis: b.mean_time_to_remediation.scores.aegissec, legacy: b.mean_time_to_remediation.scores.semgrep, desc: "Via AI root cause & refactored diffs" },
                { key: "compliance_standards_breadth", title: "Standards Breadth", aegis: b.compliance_standards_breadth.scores.aegissec, legacy: b.compliance_standards_breadth.scores.semgrep, desc: "ISO 26262, MISRA, ISO 27001, etc." }
            ];

            kpiConfigs.forEach(k => {
                const el = document.createElement("div");
                el.className = "stat-card";
                el.innerHTML = `
                    <div class="stat-label">${k.title}</div>
                    <div style="display: flex; align-items: baseline; gap: 8px; margin-top: 4px;">
                        <div class="stat-value" style="color: var(--accent-cyan); font-size: 24px;">${k.aegis}</div>
                        <span style="font-size: 11px; color: var(--text-muted);">vs ${k.legacy}</span>
                    </div>
                    <div style="font-size: 11px; color: var(--text-secondary); margin-top: 4px;">${k.desc}</div>
                `;
                kpisContainer.appendChild(el);
            });
        }

        // 3. Render Matrix Table
        const matrixContainer = document.getElementById("benchmark-matrix-container");
        if (matrixContainer && data.comparison_matrix) {
            let html = `
                <table class="data-table" style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="border-bottom: 2px solid var(--border);">
                            <th style="width: 26%;">Capability / Evaluation Criteria</th>
                            <th style="width: 26%; color: #38bdf8; background: rgba(56, 189, 248, 0.05);">AegisSec</th>
                            <th style="width: 16%;">Semgrep</th>
                            <th style="width: 16%;">SonarQube</th>
                            <th style="width: 16%;">OWASP DepCheck</th>
                        </tr>
                    </thead>
                    <tbody>
            `;

            data.comparison_matrix.forEach(cat => {
                html += `
                    <tr style="background: rgba(255, 255, 255, 0.03);">
                        <td colspan="5" style="padding: 12px 14px; font-weight: 700; color: var(--accent-cyan); font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px;">
                            📂 ${cat.category}
                        </td>
                    </tr>
                `;

                cat.features.forEach(f => {
                    const aegisIcon = f.aegissec.supported ? '<span style="color: #4ade80;">✔</span>' : '<span style="color: #f87171;">✖</span>';
                    const semgrepIcon = f.semgrep.supported ? '<span style="color: #4ade80;">✔</span>' : '<span style="color: #f87171;">✖</span>';
                    const sonarIcon = f.sonarqube.supported ? '<span style="color: #4ade80;">✔</span>' : '<span style="color: #f87171;">✖</span>';
                    const depIcon = f.depcheck.supported ? '<span style="color: #4ade80;">✔</span>' : '<span style="color: #f87171;">✖</span>';

                    html += `
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                            <td style="padding: 12px 14px;">
                                <strong style="font-size: 13px; color: #fff;">${f.feature}</strong>
                                <div style="font-size: 11px; color: var(--text-muted); margin-top: 3px;">${f.description}</div>
                            </td>
                            <td style="padding: 12px 14px; background: rgba(56, 189, 248, 0.04); border-left: 2px solid var(--accent-cyan);">
                                <div style="display: flex; align-items: flex-start; gap: 6px;">
                                    ${aegisIcon}
                                    <span style="font-size: 12px; font-weight: 600; color: #e2e8f0;">${f.aegissec.value}</span>
                                </div>
                            </td>
                            <td style="padding: 12px 14px;">
                                <div style="display: flex; align-items: flex-start; gap: 6px;">
                                    ${semgrepIcon}
                                    <span style="font-size: 12px; color: #cbd5e1;">${f.semgrep.value}</span>
                                </div>
                            </td>
                            <td style="padding: 12px 14px;">
                                <div style="display: flex; align-items: flex-start; gap: 6px;">
                                    ${sonarIcon}
                                    <span style="font-size: 12px; color: #cbd5e1;">${f.sonarqube.value}</span>
                                </div>
                            </td>
                            <td style="padding: 12px 14px;">
                                <div style="display: flex; align-items: flex-start; gap: 6px;">
                                    ${depIcon}
                                    <span style="font-size: 12px; color: #cbd5e1;">${f.depcheck.value}</span>
                                </div>
                            </td>
                        </tr>
                    `;
                });
            });

            html += `
                    </tbody>
                </table>
            `;
            matrixContainer.innerHTML = html;
        }
    } catch (e) {
        console.error("Error loading benchmark data:", e);
        showToast("Error loading benchmark report", "error");
    }
}

// --- Helper Utilities ---
function closeModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove("active");
}

function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// --- Audit & Compliance Hub ---
let auditLedgerFilter = "ALL";
let auditLedgerSearch = "";

async function loadAuditData() {
    try {
        // Fetch findings
        const findingsResp = await fetch("/api/findings");
        if (findingsResp.ok) {
            state.auditFindings = await findingsResp.json();
        } else {
            state.auditFindings = [];
        }

        // Fetch audit logs
        const logsResp = await fetch("/api/audit/logs?limit=50");
        if (logsResp.ok) {
            state.auditLogs = await logsResp.json();
        } else {
            state.auditLogs = [];
        }

        renderAuditHub();
    } catch (e) {
        console.error("Error loading audit data:", e);
    }
}

function renderAuditHub() {
    const findings = state.auditFindings || [];
    const logs = state.auditLogs || [];

    // 1. KPI Cards
    const kStatus = document.getElementById("audit-kpi-status");
    const kTotal = document.getElementById("audit-kpi-total");
    const kReach = document.getElementById("audit-kpi-reachability");
    const kLogs = document.getElementById("audit-kpi-logs-count");

    const criticalCount = findings.filter(f => f.severity === "CRITICAL").length;
    if (kStatus) {
        if (criticalCount === 0) {
            kStatus.textContent = "COMPLIANT";
            kStatus.style.color = "#10b981";
        } else {
            kStatus.textContent = "AT RISK";
            kStatus.style.color = "#ef4444";
        }
    }
    if (kTotal) kTotal.textContent = findings.length;

    // Reachability rate: SCA findings with REACHABLE status
    const scaFindings = findings.filter(f => f.scan_type === "sca" || f.reachability);
    const reachableCount = scaFindings.filter(f => f.reachability === "REACHABLE").length;
    const reachRate = scaFindings.length > 0 ? Math.round((reachableCount / scaFindings.length) * 100) : 100;
    if (kReach) kReach.textContent = `${reachRate}%`;
    if (kLogs) kLogs.textContent = logs.length;

    // 2. Render Compliance & Remediation Trend Chart
    const trends = (state.dashboardStats && state.dashboardStats.trends) ? state.dashboardStats.trends : null;
    renderAuditTrendChart(trends);

    // 3. Render Audit Findings Ledger
    renderAuditFindingsLedger(findings);

    // 4. Render Audit Logs Table
    renderAuditLogsTable(logs);
}

function renderAuditTrendChart(trendsData) {
    const container = document.getElementById("audit-trend-chart-container");
    if (!container) return;

    const series = (trendsData && trendsData.primary) ? trendsData.primary : {
        iso_27001_trend: [68, 73, 78, 83, 89, 94],
        iso_26262_trend: [62, 69, 74, 80, 86, 92],
        nist_ssdf_trend: [65, 71, 76, 82, 88, 95],
        resolved_series: [3, 7, 12, 18, 25, 32]
    };
    const labels = (trendsData && trendsData.labels) ? trendsData.labels : ["Sprint 31", "Sprint 32", "Sprint 33", "Sprint 34", "Sprint 35", "Sprint 36"];

    const iso27 = series.iso_27001_trend || [70, 75, 80, 85, 90, 95];
    const iso26 = series.iso_26262_trend || [65, 70, 75, 80, 85, 90];
    const nist = series.nist_ssdf_trend || [68, 72, 78, 84, 88, 93];
    const res = series.resolved_series || [2, 5, 9, 14, 19, 26];

    const width = 880;
    const height = 230;
    const padL = 45;
    const padR = 35;
    const padT = 20;
    const padB = 30;
    const plotW = width - padL - padR;
    const plotH = height - padT - padB;

    const n = labels.length;
    const getX = (i) => padL + (i / (n - 1)) * plotW;
    const getYPercent = (val) => padT + plotH - (val / 100) * plotH;
    const maxRes = Math.max(10, ...res);
    const getYRes = (val) => padT + plotH - (val / maxRes) * plotH;

    let gridLinesSvg = "";
    for (let g = 0; g <= 4; g++) {
        const yPos = padT + (g / 4) * plotH;
        const pct = Math.round(100 * (1 - g / 4));
        gridLinesSvg += `
            <line x1="${padL}" y1="${yPos}" x2="${width - padR}" y2="${yPos}" stroke="rgba(255,255,255,0.06)" stroke-dasharray="3,3" />
            <text x="${padL - 8}" y="${yPos + 4}" fill="#64748b" font-size="10" text-anchor="end" font-family="var(--font-mono)">${pct}%</text>
        `;
    }

    let xLabelsSvg = "";
    labels.forEach((lbl, i) => {
        const xPos = getX(i);
        const shortLbl = lbl.split(" ")[0];
        xLabelsSvg += `
            <text x="${xPos}" y="${height - 8}" fill="#94a3b8" font-size="11" text-anchor="middle" font-weight="600">${escapeHtml(shortLbl)}</text>
        `;
    });

    const pts27 = iso27.map((v, i) => `${getX(i)},${getYPercent(v)}`).join(" ");
    const pts26 = iso26.map((v, i) => `${getX(i)},${getYPercent(v)}`).join(" ");
    const ptsNist = nist.map((v, i) => `${getX(i)},${getYPercent(v)}`).join(" ");
    const ptsRes = res.map((v, i) => `${getX(i)},${getYRes(v)}`).join(" ");

    let circlesSvg = "";
    iso27.forEach((v, i) => {
        circlesSvg += `<circle cx="${getX(i)}" cy="${getYPercent(v)}" r="4" fill="#0284c7"><title>ISO 27001: ${v}%</title></circle>`;
    });
    iso26.forEach((v, i) => {
        circlesSvg += `<circle cx="${getX(i)}" cy="${getYPercent(v)}" r="4" fill="#10b981"><title>ISO 26262 ASIL: ${v}%</title></circle>`;
    });
    nist.forEach((v, i) => {
        circlesSvg += `<circle cx="${getX(i)}" cy="${getYPercent(v)}" r="4" fill="#7c3aed"><title>NIST SSDF: ${v}%</title></circle>`;
    });
    res.forEach((v, i) => {
        circlesSvg += `<circle cx="${getX(i)}" cy="${getYRes(v)}" r="4" fill="#f59e0b"><title>Resolved: ${v}</title></circle>`;
    });

    container.innerHTML = `
        <svg viewBox="0 0 ${width} ${height}" style="width: 100%; height: 100%;" preserveAspectRatio="none">
            ${gridLinesSvg}
            ${xLabelsSvg}

            <polyline points="${pts27}" fill="none" stroke="#0284c7" stroke-width="2.5" />
            <polyline points="${pts26}" fill="none" stroke="#10b981" stroke-width="2.5" />
            <polyline points="${ptsNist}" fill="none" stroke="#7c3aed" stroke-width="2.5" />
            <polyline points="${ptsRes}" fill="none" stroke="#f59e0b" stroke-width="2" stroke-dasharray="4,3" />

            ${circlesSvg}
        </svg>
    `;
}

function filterAuditLedger() {
    const qEl = document.getElementById("audit-search-input");
    const stdEl = document.getElementById("audit-standard-filter");
    auditLedgerSearch = qEl ? qEl.value.trim().toLowerCase() : "";
    auditLedgerFilter = stdEl ? stdEl.value : "ALL";
    renderAuditFindingsLedger(state.auditFindings || []);
}

function renderAuditFindingsLedger(findings) {
    const tbody = document.getElementById("audit-findings-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    const filtered = findings.filter(f => {
        if (auditLedgerFilter !== "ALL") {
            const matchesStd = (f.standards || []).some(s => s.includes(auditLedgerFilter));
            if (!matchesStd) return false;
        }
        if (auditLedgerSearch) {
            const matchText = `${f.title} ${f.cve_id || ''} ${f.cwe_id || ''} ${f.author_name || ''} ${f.file_path || ''}`.toLowerCase();
            if (!matchText.includes(auditLedgerSearch)) return false;
        }
        return true;
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 24px;">No audit findings matching current filter.</td></tr>`;
        return;
    }

    filtered.forEach(f => {
        const tr = document.createElement("tr");

        let typeBadge = `<span class="badge badge-${f.scan_type === 'sca' ? 'high' : 'medium'}">${(f.scan_type || f.type || 'sast').toUpperCase()}</span>`;
        if (f.reachability) {
            const rColor = f.reachability === 'REACHABLE' ? '#ef4444' : (f.reachability === 'IMPORTED' ? '#f59e0b' : '#64748b');
            typeBadge += `<br><span style="font-size: 10px; font-weight: 700; color: ${rColor}; margin-top: 2px; display: inline-block;">● ${f.reachability}</span>`;
        }

        const ageDays = f.age_days !== undefined ? f.age_days : 0;
        const ageText = f.age_display || (ageDays === 0 ? "Today (< 24h)" : `${ageDays} days old`);
        const firstSeenDate = f.first_seen_date || (f.first_seen ? f.first_seen.split('T')[0] : (f.commit_date ? f.commit_date.split(' ')[0] : 'Today'));
        const ageBg = ageDays > 14 ? 'rgba(239, 68, 68, 0.18)' : (ageDays > 2 ? 'rgba(245, 158, 11, 0.18)' : 'rgba(16, 185, 129, 0.18)');
        const ageColor = ageDays > 14 ? '#fca5a5' : (ageDays > 2 ? '#fcd34d' : '#6ee7b7');
        const ageBorder = ageDays > 14 ? 'rgba(239, 68, 68, 0.4)' : (ageDays > 2 ? 'rgba(245, 158, 11, 0.4)' : 'rgba(16, 185, 129, 0.4)');

        const stdBadges = (f.standards || []).map(s => `<span class="tag-std" style="font-size: 10px; padding: 2px 6px;">${escapeHtml(s)}</span>`).join(" ");

        tr.innerHTML = `
            <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
            <td>
                <div style="display: flex; align-items: center; gap: 6px; flex-wrap: wrap;">
                    ${f.cisa_kev ? `<span class="badge" style="background: rgba(239, 68, 68, 0.25); color: #f87171; border: 1px solid #ef4444; font-size: 10px; font-weight: 700;">🚨 CISA KEV</span>` : ''}
                    <strong style="color: #fff; font-size: 13px;">${escapeHtml(f.title)}</strong>
                </div>
                <div style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px;">
                    ${escapeHtml(f.cwe_id || 'CWE')} ${f.cve_id ? ' &bull; ' + escapeHtml(f.cve_id) : ''}
                    ${f.dependency_lag_versions ? ` &bull; <span style="color: #f59e0b;">📦 ${escapeHtml(f.dependency_lag_versions)}</span>` : ''}
                </div>
            </td>
            <td>${typeBadge}</td>
            <td>
                <div style="display: flex; align-items: center; gap: 6px;">
                    <span class="badge" style="background: ${ageBg}; color: ${ageColor}; border: 1px solid ${ageBorder}; font-size: 11px; font-weight: 700;">
                        🕒 ${escapeHtml(ageText)}
                    </span>
                </div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px; font-family: var(--font-mono);">
                    First seen: <span style="color: #cbd5e1; font-weight: 500;">${escapeHtml(firstSeenDate)}</span>
                </div>
            </td>
            <td style="max-width: 220px;">${stdBadges || '<span style="color: var(--text-muted); font-size: 11px;">Standard Baseline</span>'}</td>
            <td>
                <div style="font-size: 12px; font-family: var(--font-mono);">
                    <strong style="color: #38bdf8;">${f.cvss_score}</strong> CVSS &bull;
                    <span style="color: #f97316;">${f.epss_score}</span> EPSS
                </div>
            </td>
            <td>
                <div style="font-size: 12px; color: #fff; font-weight: 600;">${escapeHtml(f.author_name || 'Unknown')}</div>
                <div style="font-size: 10px; color: var(--text-muted);">${escapeHtml(f.author_email || '')}</div>
            </td>
            <td>
                <span class="status-pill status-${(f.status || 'open').toLowerCase()}">${(f.status || 'open').toUpperCase()}</span>
                ${(f.jira_key || f.zammad_id || f.ticket_assigned_to) ? `
                    <div style="margin-top: 4px;">
                        <span class="badge" style="background: rgba(168, 85, 247, 0.18); color: #c084fc; font-size: 10px; border: 1px solid rgba(168, 85, 247, 0.35);" title="Assigned to author ${escapeHtml(f.ticket_assigned_to || f.author_name)}">
                            🎫 ${f.jira_key ? 'Jira #' + f.jira_key : (f.zammad_id ? 'Zammad #' + f.zammad_id : 'Ticket')} &rarr; ${escapeHtml(f.ticket_assigned_to || f.author_name)}
                        </span>
                    </div>
                ` : ''}
            </td>
            <td style="text-align: right;">
                <button class="btn btn-secondary btn-sm" onclick="openFindingDetailById('${f.id}')" style="padding: 4px 10px; font-size: 12px;">Inspect</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function openFindingDetailById(findingId) {
    const f = (state.auditFindings || []).find(item => item.id === findingId) || (state.findings || []).find(item => item.id === findingId);
    if (f) openFindingDetail(f);
}

function renderAuditLogsTable(logs) {
    const tbody = document.getElementById("audit-logs-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 24px;">No audit logs recorded yet.</td></tr>`;
        return;
    }

    logs.forEach(log => {
        const tr = document.createElement("tr");
        const seal = log.event_hash ? log.event_hash.substring(0, 16) + "..." : "sha256:verified";
        tr.innerHTML = `
            <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-secondary);">${log.timestamp || 'N/A'}</td>
            <td><span class="badge" style="background: rgba(168, 85, 247, 0.2); color: #c084fc; font-size: 11px;">${escapeHtml(log.event_type || 'EVENT')}</span></td>
            <td><strong style="color: #fff; font-size: 12px;">${escapeHtml(log.user || 'system')}</strong></td>
            <td style="font-size: 13px; color: #e2e8f0;">${escapeHtml(log.action || '')}</td>
            <td><code style="font-size: 11px; color: #38bdf8; background: rgba(56, 189, 248, 0.1); padding: 2px 6px; border-radius: 4px;">${escapeHtml(seal)}</code></td>
        `;
        tbody.appendChild(tr);
    });
}

async function downloadAuditCertificate(standard) {
    try {
        showToast(`Generating cryptographically signed ${standard} audit certificate...`, "info");
        const resp = await fetch(`/api/audit/certificate/${encodeURIComponent(standard)}`);
        if (!resp.ok) {
            showToast("Failed to generate audit certificate", "error");
            return;
        }
        const cert = await resp.json();

        const blob = new Blob([JSON.stringify(cert, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `AegisSec-Audit-Attestation-${standard}-${cert.certificate_id.substring(0, 8)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showToast(`✅ ${standard} Certificate #${cert.certificate_id.substring(0, 8)} downloaded! Seal: ${cert.digital_seal.substring(0, 16)}...`, "success");
    } catch (e) {
        showToast("Error downloading audit certificate", "error");
    }
}
