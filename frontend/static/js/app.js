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
    sonarRules: [],
    sonarStats: null,
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
const _originalFetch = window.fetch ? window.fetch.bind(window) : null;
window.fetch = function(url, options = {}) {
    options = options || {};
    try {
        const headers = options.headers ? new Headers(options.headers) : new Headers();
        if (state.currentUser && state.currentUser.token && !headers.has("Authorization")) {
            headers.set("Authorization", `Bearer ${state.currentUser.token}`);
        }
        options.headers = headers;
    } catch (e) {
        if (state.currentUser && state.currentUser.token) {
            options.headers = options.headers || {};
            if (typeof options.headers === "object" && !options.headers["Authorization"]) {
                options.headers["Authorization"] = `Bearer ${state.currentUser.token}`;
            }
        }
    }
    return _originalFetch(url, options);
};

/// --- Initialization ---
async function initializeApp() {
    const isAuthenticated = await checkAuth();
    if (isAuthenticated) {
        await loadProjects();
        await loadFindings();
        await loadDashboardStats();
        await loadStandards();
        await loadCustomRules();
        await loadSonarRules();
        await loadIntegrations();
    }
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initializeApp);
} else {
    initializeApp();
}

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
    if (viewName === "users" && state.currentUser && state.currentUser.role !== "admin") {
        showToast("Access Denied: Only administrators have access to RBAC user management.", "error");
        navigate("projects");
        return;
    }

    document.querySelectorAll(".page-container").forEach(el => el.classList.remove("active"));
    document.querySelectorAll(".nav-item").forEach(el => el.classList.remove("active"));

    const targetView = document.getElementById(`view-${viewName}`);
    const targetNav = document.getElementById(`nav-${viewName}`);

    if (targetView) targetView.classList.add("active");
    if (targetNav) targetNav.classList.add("active");

    if (viewName === "dashboard") loadDashboardStats();
    if (viewName === "projects") loadProjects();
    if (viewName === "triage") loadFindings();
    if (viewName === "rules") { loadCustomRules(); loadSonarRules(); }
    if (viewName === "compliance") { renderComplianceMatrix(); loadRegulatoryComplianceData(); }
    if (viewName === "benchmark") loadBenchmarkData();
    if (viewName === "integrations") loadIntegrations();
    if (viewName === "users") loadUsers();
    if (viewName === "audit") loadAuditData();
    if (viewName === "threat-model") loadThreatModelData();
    if (viewName === "policy-studio") loadPolicyStudioData();
    if (viewName === "attack-paths") loadAttackPathData();
    if (viewName === "api-fuzzer") loadAPIFuzzerData();
    if (viewName === "llm-sec") loadLLMSecData();
    if (viewName === "sbom-drift") loadSBOMDriftData();
    if (viewName === "deptree") loadDependencyTree();
    if (viewName === "sandbox") loadSandboxData();
}

// --- Auth & Session Lifecycle ---

function showLoginView() {
    const loginEl = document.getElementById("view-login");
    const sidebar = document.getElementById("sidebar");
    const mainContent = document.getElementById("main-content");
    if (loginEl) loginEl.style.display = "flex";
    if (sidebar) sidebar.style.display = "none";
    if (mainContent) mainContent.style.display = "none";

    const uEl = document.getElementById("login-username");
    const pEl = document.getElementById("login-password");
    if (uEl && !uEl.value) uEl.value = "admin";
    if (pEl) pEl.value = "";
    const errAlert = document.getElementById("login-error-alert");
    if (errAlert) errAlert.style.display = "none";
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
    if (savedToken) {
        state.currentUser.token = savedToken;
        try {
            const resp = await _originalFetch("/api/auth/me", {
                headers: { "Authorization": `Bearer ${savedToken}` }
            });
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
                window.location.replace("/login");
                return false;
            }
        } catch (e) {
            console.error("Auth verification failed:", e);
        }
    }

    // Unauthenticated: redirect directly to dedicated login page
    window.location.replace("/login");
    return false;
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
            sessionStorage.removeItem("aegis_logged_out");

            hideLoginView();
            updateUserDisplay();

            showToast(`Welcome back, ${data.user.username}!`, "success");

            const pwdInput = document.getElementById("login-password");
            if (pwdInput) pwdInput.value = "";

            await loadProjects();
            await loadDashboardStats();
            await loadFindings();
            await loadStandards();
            await loadCustomRules();
            await loadSonarRules();
            await loadIntegrations();
        } else {
            const errData = await resp.json().catch(() => ({ detail: "Invalid username or password" }));
            if (errAlert) {
                errAlert.textContent = errData.detail || "Invalid credentials. Please verify your password.";
                errAlert.style.display = "flex";
            }
        }
    } catch (err) {
        console.error("Login request error:", err);
        if (errAlert) {
            errAlert.textContent = "Unable to connect to Sentinel AppSec authentication service.";
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

async function logout() {
    try {
        await _originalFetch("/api/auth/logout", { method: "POST" });
    } catch (e) {}
    sessionStorage.setItem("aegis_logged_out", "1");
    localStorage.removeItem("aegis_token");
    localStorage.removeItem("aegis_user");
    state.currentUser = {
        username: "",
        role: "",
        token: ""
    };
    window.location.replace("/login");
}

function updateDeveloperIsolationUI() {
    const banner = document.getElementById("developer-scoped-banner");
    const authorSpan = document.getElementById("scoped-author-name");
    const emailSpan = document.getElementById("scoped-author-email");
    const isDev = (state.currentUser && (state.currentUser.role === "developer" || state.currentUser.role === "DEVELOPER"));

    if (banner) {
        if (isDev) {
            banner.style.display = "flex";
            if (authorSpan) authorSpan.textContent = state.currentUser.username;
            if (emailSpan) emailSpan.textContent = state.currentUser.email || `${state.currentUser.username}@internal`;
        } else {
            banner.style.display = "none";
        }
    }
}

function updateUserDisplay() {
    const nameEl = document.getElementById("current-user-display");
    const roleEl = document.getElementById("current-role-badge");

    if (nameEl) nameEl.textContent = state.currentUser.username || "Admin";
    if (roleEl) {
        roleEl.textContent = (state.currentUser.role || "admin").replace("_", " ");
    }
    
    // RBAC menu visibility: Only admin can access Users & RBAC view
    const navUsers = document.getElementById("nav-users");
    if (navUsers) {
        navUsers.style.display = (state.currentUser && state.currentUser.role === "admin") ? "flex" : "none";
    }

    // Project creation button visibility: Only admin and security_engineer
    const btnCreateProj = document.getElementById("btn-open-create-project");
    if (btnCreateProj) {
        const canCreate = state.currentUser && (state.currentUser.role === "admin" || state.currentUser.role === "security_engineer");
        btnCreateProj.style.display = canCreate ? "inline-flex" : "none";
    }

    updateDeveloperIsolationUI();
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

    renderRuleProjectSelectors();
}

function renderRuleProjectSelectors() {
    const nlSel = document.getElementById("nl-rule-project-select");
    const builderSel = document.getElementById("builder-rule-project");

    if (nlSel) {
        const prevVal = nlSel.value || state.activeProjectId || "";
        nlSel.innerHTML = '<option value="">🌐 All Projects (Global Scope)</option>';
        (state.projects || []).forEach(p => {
            const opt = document.createElement("option");
            opt.value = p.id;
            opt.textContent = `📁 ${p.name}`;
            if (p.id === prevVal) opt.selected = true;
            nlSel.appendChild(opt);
        });
        onRuleScopeChange();
    }

    if (builderSel) {
        const prevVal = builderSel.value || state.activeProjectId || "";
        builderSel.innerHTML = '<option value="">🌐 All Projects (Global Policy)</option>';
        (state.projects || []).forEach(p => {
            const opt = document.createElement("option");
            opt.value = p.id;
            opt.textContent = `📁 ${p.name}`;
            if (p.id === prevVal) opt.selected = true;
            builderSel.appendChild(opt);
        });
    }
}

function onRuleScopeChange() {
    const sel = document.getElementById("nl-rule-project-select");
    const badge = document.getElementById("nl-rule-scope-badge");
    const hint = document.getElementById("nl-rule-scope-hint");
    if (!sel) return;

    if (sel.value) {
        const proj = (state.projects || []).find(p => p.id === sel.value);
        const pName = proj ? proj.name : sel.value;
        if (badge) {
            badge.textContent = `PROJECT: ${pName.toUpperCase()}`;
            badge.style.background = "rgba(56, 189, 248, 0.2)";
            badge.style.color = "#38bdf8";
        }
        if (hint) hint.textContent = `Rule executes only during scans of '${pName}'`;
    } else {
        if (badge) {
            badge.textContent = "GLOBAL RULE (ALL PROJECTS)";
            badge.style.background = "rgba(148, 163, 184, 0.2)";
            badge.style.color = "#94a3b8";
        }
        if (hint) hint.textContent = "Rule executes across all projects in the organization";
    }
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
    renderRuleProjectSelectors();
    loadCustomRules();
    showToast(`Active project changed to: ${state.projects.find(p => p.id === projectId)?.name || projectId}`);
}

function renderProjectsTable() {
    const tbody = document.getElementById("projects-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (state.projects.length === 0) {
        tbody.innerHTML = `<tr>
            <td colspan="8" style="text-align: center; color: var(--text-muted); padding: 48px 20px;">
                <div style="font-size: 15px; margin-bottom: 12px; color: var(--text-secondary); font-weight: 500;">No security projects configured or assigned to your account.</div>
                ${state.currentUser && (state.currentUser.role === 'admin' || state.currentUser.role === 'security_engineer') ? `
                <button class="btn btn-primary btn-sm" onclick="openCreateProjectModal()" style="display: inline-flex; align-items: center; gap: 6px;">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                    <span>Create Your First Project</span>
                </button>` : `<div style="font-size: 13px; color: var(--text-muted);">Please contact your security administrator to assign you to a project.</div>`}
            </td>
        </tr>`;
        return;
    }

    const isAdmin = state.currentUser && state.currentUser.role === "admin";
    state.projects.forEach(p => {
        const tr = document.createElement("tr");
        const patBadge = p.git_pat_configured 
            ? '<span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981;">CONFIGURED (MASKED)</span>'
            : '<span class="badge" style="background: rgba(148, 163, 184, 0.2); color: #94a3b8;">PUBLIC / NONE</span>';

        const lastScanned = p.last_scanned ? new Date(p.last_scanned).toLocaleString() : "Never";
        const riskColor = p.risk_score > 70 ? "#ef4444" : p.risk_score > 40 ? "#f97316" : "#10b981";
        const memberCount = p.member_count !== undefined ? p.member_count : (p.members ? p.members.length : 0);
        const memberBadge = memberCount > 0
            ? `<button class="btn btn-sm btn-link p-0 text-decoration-none" onclick="openProjectMembersModal('${p.id}', '${p.name.replace(/'/g, "\\'")}')" style="color: #38bdf8; font-weight: 600;"><span class="badge" style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); font-size: 11px;">👥 ${memberCount} Member${memberCount !== 1 ? 's' : ''}</span></button>`
            : `<button class="btn btn-sm btn-link p-0 text-decoration-none" onclick="openProjectMembersModal('${p.id}', '${p.name.replace(/'/g, "\\'")}')" style="color: #94a3b8;"><span class="badge" style="background: rgba(148, 163, 184, 0.15); color: #94a3b8; font-size: 11px;">+ Assign Team</span></button>`;

        tr.innerHTML = `
            <td>
                <strong>${escapeHtml(p.name)}</strong>
                <div style="font-size: 12px; color: var(--text-muted);">${escapeHtml(p.description || "No description")}</div>
            </td>
            <td>
                <code style="font-size: 12px;">${escapeHtml(p.git_url || "Local / Demo Repository")}</code>
                <div style="font-size: 11px; color: var(--text-secondary);">Branch: <strong>${escapeHtml(p.git_branch)}</strong></div>
            </td>
            <td>${memberBadge}</td>
            <td>${patBadge}</td>
            <td>
                <div style="display: flex; align-items: center; gap: 6px;">
                    <strong>${p.total_findings || 0}</strong>
                    <span class="badge" style="font-size: 10px; ${p.risk_score < 40 ? 'background: rgba(16, 185, 129, 0.2); color: #10b981;' : 'background: rgba(239, 68, 68, 0.2); color: #f87171;'}">${p.risk_score < 40 ? 'GATE PASS' : 'GATE FAIL'}</span>
                </div>
            </td>
            <td><strong style="color: ${riskColor};">${p.risk_score || 0.0}</strong> / 100</td>
            <td style="font-size: 13px; color: var(--text-secondary);">${lastScanned}</td>
            <td style="text-align: right; display: flex; gap: 4px; justify-content: flex-end; flex-wrap: wrap;">
                <button class="btn btn-secondary btn-sm" onclick="openProjectMembersModal('${p.id}', '${p.name.replace(/'/g, "\\'")}')" title="Manage project team members" style="color: #38bdf8; border-color: rgba(56, 189, 248, 0.4);">👥 Team</button>
                <button class="btn btn-secondary btn-sm" onclick="openBadgeModal('${p.id}', '${p.name.replace(/'/g, "\\'")}')" title="Get dynamic SVG status badge for GitHub README" style="color: #38bdf8; border-color: rgba(56, 189, 248, 0.4);">🛡️ Badge</button>
                <button class="btn btn-secondary btn-sm" onclick="triggerScanForProject('${p.id}')">Scan</button>
                <button class="btn btn-secondary btn-sm" onclick="triggerScanForProject('${p.id}', 'secrets')" title="Scan secrets & credentials only" style="color: #f472b6; border-color: rgba(244, 114, 182, 0.4);">🔑 Secrets</button>
                ${isAdmin ? `<button class="btn btn-danger btn-sm" onclick="promptDeleteProject('${p.id}', '${p.name.replace(/'/g, "\\'")}')">Delete</button>` : ''}
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function openCreateProjectModal() {
    openModal("modal-new-project");
    const nameInput = document.getElementById("new-proj-name");
    if (nameInput) setTimeout(() => nameInput.focus(), 60);

    const membersGroup = document.getElementById("new-proj-members-group");
    const membersList = document.getElementById("new-proj-members-list");
    if (!membersList) return;
    
    // Only admin can assign other members; if not admin, hide member selection
    if (state.currentUser && state.currentUser.role !== "admin") {
        if (membersGroup) membersGroup.style.display = "none";
        return;
    }
    if (membersGroup) membersGroup.style.display = "block";

    if (!state.users || state.users.length === 0) {
        try {
            const resp = await fetch("/api/users");
            if (resp.ok) {
                state.users = await resp.json();
            }
        } catch (e) {
            console.error("Could not fetch users for project creation:", e);
        }
    }

    const eligibleUsers = (state.users || []).filter(u => u.role !== "admin");
    if (eligibleUsers.length === 0) {
        membersList.innerHTML = `<span style="font-size: 12px; color: var(--text-muted);">No non-admin users registered yet. You can assign users later.</span>`;
    } else {
        membersList.innerHTML = eligibleUsers.map(u => `
            <label class="d-flex align-items-center gap-2 mb-2 p-1" style="font-size: 13px; cursor: pointer;">
                <input type="checkbox" name="new-proj-member" value="${u.id}" class="form-check-input mt-0">
                <span style="font-weight: 500; color: #fff;">${escapeHtml(u.username)}</span>
                <span class="badge" style="background: rgba(56, 189, 248, 0.15); color: var(--accent-cyan); font-size: 10px;">${escapeHtml(u.role)}</span>
                <span style="font-size: 11px; color: var(--text-muted);">${escapeHtml(u.email)}</span>
            </label>
        `).join("");
    }
}

async function submitCreateProject(e) {
    e.preventDefault();
    const name = document.getElementById("new-proj-name")?.value.trim();
    const desc = document.getElementById("new-proj-desc")?.value.trim();
    const gitUrl = document.getElementById("new-proj-git-url")?.value.trim();
    const branch = document.getElementById("new-proj-git-branch")?.value.trim() || "main";
    const pat = document.getElementById("new-proj-git-pat")?.value.trim();

    if (!name) {
        showToast("Project Name is required", "error");
        return;
    }

    const assignedUsers = [];
    document.querySelectorAll("input[name='new-proj-member']:checked").forEach(cb => {
        assignedUsers.push(cb.value);
    });

    const submitBtn = e.target.querySelector('button[type="submit"]');
    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = "Creating...";
    }

    try {
        const resp = await fetch("/api/projects", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name, description: desc, git_url: gitUrl, git_branch: branch, git_pat: pat,
                assigned_users: assignedUsers.length > 0 ? assignedUsers : undefined
            })
        });

        if (resp.ok) {
            const created = await resp.json();
            showToast(`Project '${created.name}' created successfully!`, "success");
            closeModal("modal-new-project");
            document.getElementById("form-create-project").reset();
            await loadProjects();
            state.activeProjectId = created.id;
            triggerScanForProject(created.id);
        } else {
            const err = await resp.json().catch(() => ({}));
            showToast(err.detail || "Failed to create project", "error");
        }
    } catch (err) {
        showToast("Error connecting to server", "error");
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = "Create Project";
        }
    }
}

let currentMembersProjectId = null;

async function openProjectMembersModal(projectId, projectName) {
    currentMembersProjectId = projectId;
    const titleEl = document.getElementById("project-members-modal-title");
    const idInput = document.getElementById("project-members-project-id");
    const addSection = document.getElementById("project-members-add-section");
    
    if (titleEl) titleEl.textContent = projectName || projectId;
    if (idInput) idInput.value = projectId;

    const isAdmin = state.currentUser && state.currentUser.role === "admin";
    if (addSection) {
        addSection.style.display = isAdmin ? "block" : "none";
    }

    openModal("modal-project-members");
    await loadProjectMembers(projectId);
}

async function loadProjectMembers(projectId) {
    const tbody = document.getElementById("project-members-tbody");
    const userSelect = document.getElementById("project-members-user-select");
    if (tbody) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">Loading team members...</td></tr>';
    }

    try {
        const resp = await fetch(`/api/projects/${projectId}/members`);
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            showToast(err.detail || "Failed to fetch project members", "error");
            if (tbody) tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--severity-critical); padding: 20px;">${escapeHtml(err.detail || "Error loading members")}</td></tr>`;
            return;
        }

        const members = await resp.json();
        const isAdmin = state.currentUser && state.currentUser.role === "admin";

        if (!members || members.length === 0) {
            if (tbody) {
                tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 24px;">No members explicitly assigned yet. Only Administrators can view this project.</td></tr>`;
            }
        } else if (tbody) {
            tbody.innerHTML = members.map(m => {
                const assignedDate = m.assigned_at ? new Date(m.assigned_at).toLocaleDateString() : "Active";
                return `
                    <tr>
                        <td>
                            <div class="d-flex align-items-center gap-2">
                                <span class="badge" style="background: rgba(56, 189, 248, 0.15); color: var(--accent-cyan); font-weight: 700;">@</span>
                                <strong>${escapeHtml(m.username || m.user_id)}</strong>
                            </div>
                        </td>
                        <td style="color: var(--text-secondary); font-size: 13px;">${escapeHtml(m.email || "-")}</td>
                        <td>
                            <span class="badge" style="background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); text-transform: uppercase; font-size: 10px;">
                                ${escapeHtml(m.role || "developer")}
                            </span>
                        </td>
                        <td style="font-size: 12px; color: var(--text-muted);">${assignedDate}</td>
                        <td style="text-align: right;">
                            ${isAdmin ? `
                                <button class="btn btn-danger btn-sm" onclick="removeProjectMember('${m.user_id}', '${escapeHtml(m.username || m.user_id)}')" style="font-size: 11px; padding: 3px 8px;">
                                    Unassign
                                </button>
                            ` : `<span style="font-size: 11px; color: var(--text-muted);">Assigned</span>`}
                        </td>
                    </tr>
                `;
            }).join("");
        }

        // If admin, populate the user select dropdown with users not yet assigned
        if (isAdmin && userSelect) {
            if (!state.users || state.users.length === 0) {
                try {
                    const uResp = await fetch("/api/users");
                    if (uResp.ok) state.users = await uResp.json();
                } catch (e) {
                    console.error("Failed loading users for member selector:", e);
                }
            }

            const assignedUserIds = new Set((members || []).map(m => m.user_id));
            const availableUsers = (state.users || []).filter(u => u.role !== "admin" && !assignedUserIds.has(u.id));

            userSelect.innerHTML = '<option value="">-- Select User to Assign --</option>';
            availableUsers.forEach(u => {
                const opt = document.createElement("option");
                opt.value = u.id;
                opt.textContent = `${u.username} (${u.email} - ${u.role})`;
                userSelect.appendChild(opt);
            });
        }
    } catch (e) {
        console.error("Error loading project members:", e);
        if (tbody) tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--severity-critical); padding: 20px;">Network error loading team members.</td></tr>';
    }
}

async function addSelectedUserToProject() {
    const projectId = currentMembersProjectId || document.getElementById("project-members-project-id")?.value;
    const userSelect = document.getElementById("project-members-user-select");
    const roleSelect = document.getElementById("project-members-role-select");
    const userId = userSelect?.value;
    const role = roleSelect?.value || "developer";

    if (!projectId || !userId) {
        showToast("Please select a user to assign to this project", "error");
        return;
    }

    try {
        const resp = await fetch(`/api/projects/${projectId}/members`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ user_id: userId, role })
        });

        if (resp.ok) {
            showToast("User successfully assigned to project!", "success");
            await loadProjectMembers(projectId);
            await loadProjects();
        } else {
            const err = await resp.json().catch(() => ({}));
            showToast(err.detail || "Failed to assign user to project", "error");
        }
    } catch (e) {
        showToast("Network error assigning user", "error");
    }
}

async function removeProjectMember(userId, username) {
    const projectId = currentMembersProjectId || document.getElementById("project-members-project-id")?.value;
    if (!projectId || !userId) return;

    if (!confirm(`Are you sure you want to remove ${username || 'this user'} from this project? They will immediately lose access to all its findings and scans.`)) {
        return;
    }

    try {
        const resp = await fetch(`/api/projects/${projectId}/members/${userId}`, {
            method: "DELETE"
        });

        if (resp.ok) {
            showToast(`User '${username}' removed from project.`, "success");
            await loadProjectMembers(projectId);
            await loadProjects();
        } else {
            const err = await resp.json().catch(() => ({}));
            showToast(err.detail || "Failed to remove user from project", "error");
        }
    } catch (e) {
        showToast("Network error removing user", "error");
    }
}

let projectToDeleteId = null;
function promptDeleteProject(id, name) {
    projectToDeleteId = id;
    const nameEl = document.getElementById("delete-proj-name");
    if (nameEl) nameEl.textContent = name;
    openModal("modal-delete-project");
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

async function triggerScanForProject(projectId, scanType = "full") {
    const label = scanType === "secrets" ? "Secret & Credential Scanner" : "SAST & SCA scanning engine";
    showToast(`Launching ${label}...`, "info");
    const scanBtn = document.getElementById("btn-quick-scan");
    if (scanBtn) scanBtn.disabled = true;

    try {
        const resp = await fetch(`/api/projects/${projectId}/scan?scan_type=${scanType}`, {
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

function getVulnerabilityTemperature(val, maxVal) {
    const v = Number(val) || 0;
    const max = Number(maxVal) || 20;
    const ratio = max > 0 ? (v / max) : 0;

    // Thermal Temperature Color Spectrum:
    // High / Critical (Hot): Fire Red (#ef4444)
    // Elevated (Warm): Sunset Orange (#f97316)
    // Moderate (Tepid): Golden Amber (#f59e0b)
    // Low / Secure (Cool): Emerald Green (#10b981)
    // Zero Flaws (Cold): Ice Cyan (#06b6d4)
    if (v >= 15 || ratio >= 0.70) {
        return {
            color: "#ef4444",
            lightColor: "#fca5a5",
            bg: "rgba(239, 68, 68, 0.22)",
            label: "Critical (Hot)",
            zone: "hot"
        };
    } else if (v >= 10 || ratio >= 0.50) {
        return {
            color: "#f97316",
            lightColor: "#fdba74",
            bg: "rgba(249, 115, 22, 0.22)",
            label: "Elevated (Warm)",
            zone: "warm"
        };
    } else if (v >= 5 || ratio >= 0.28) {
        return {
            color: "#f59e0b",
            lightColor: "#fde68a",
            bg: "rgba(245, 158, 11, 0.20)",
            label: "Moderate (Tepid)",
            zone: "tepid"
        };
    } else if (v > 0) {
        return {
            color: "#10b981",
            lightColor: "#6ee7b7",
            bg: "rgba(16, 185, 129, 0.20)",
            label: "Low (Cool)",
            zone: "cool"
        };
    } else {
        return {
            color: "#06b6d4",
            lightColor: "#67e8f9",
            bg: "rgba(6, 182, 212, 0.20)",
            label: "Zero Flaws (Cold)",
            zone: "cold"
        };
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
    const med = series.medium_series || [0, 0, 0, 0, 0, 0];
    const low = series.current_low || 0;

    // Single vulnerability count series across sprint milestones
    const vulnSeries = (series.vulnerability_series && series.vulnerability_series.length === labels.length)
        ? series.vulnerability_series
        : labels.map((_, i) => (crit[i] || 0) + (high[i] || 0) + (med[i] || 0) + low);

    // Chart dimensions
    const width = 880;
    const height = 240;
    const padL = 50;
    const padR = 40;
    const padT = 25;
    const padB = 35;
    const plotW = width - padL - padR;
    const plotH = height - padT - padB;

    const maxVuln = Math.max(5, Math.ceil(Math.max(...vulnSeries) * 1.25));
    const n = labels.length;
    const getX = (i) => padL + (i / (n - 1)) * plotW;
    const getY = (val) => padT + plotH - (val / maxVuln) * plotH;

    // Build SVG path points
    const vulnPoints = vulnSeries.map((v, i) => `${getX(i)},${getY(v)}`);
    const vulnArea = `${getX(0)},${padT + plotH} ` + vulnPoints.join(" ") + ` ${getX(n - 1)},${padT + plotH}`;

    // Temperature stops along the timeline (horizontal gradient)
    let tempLineStops = "";
    let tempAreaStops = "";
    vulnSeries.forEach((v, i) => {
        const pct = Math.round((i / (n - 1)) * 100);
        const info = getVulnerabilityTemperature(v, maxVuln);
        tempLineStops += `<stop offset="${pct}%" stop-color="${info.color}"/>`;
        tempAreaStops += `<stop offset="${pct}%" stop-color="${info.color}" stop-opacity="0.32"/>`;
    });

    // Grid lines SVG
    let gridLinesSvg = "";
    for (let g = 0; g <= 4; g++) {
        const yPos = padT + (g / 4) * plotH;
        const countVal = Math.round(maxVuln * (1 - g / 4));
        const gridInfo = getVulnerabilityTemperature(countVal, maxVuln);
        gridLinesSvg += `
            <line x1="${padL}" y1="${yPos}" x2="${width - padR}" y2="${yPos}" stroke="rgba(255,255,255,0.07)" stroke-dasharray="3,3" />
            <text x="${padL - 10}" y="${yPos + 4}" fill="${gridInfo.color}" font-size="11" font-weight="600" text-anchor="end" font-family="var(--font-mono)">${countVal}</text>
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

    // Milestone circles with temperature glowing drop-shadow and count badges
    let nodesSvg = "";
    vulnSeries.forEach((v, i) => {
        const cx = getX(i);
        const cy = getY(v);
        const info = getVulnerabilityTemperature(v, maxVuln);
        nodesSvg += `
            <circle cx="${cx}" cy="${cy}" r="5.5" fill="${info.color}" stroke="#0f172a" stroke-width="2.5" style="filter: drop-shadow(0 0 6px ${info.color}); cursor: pointer;">
                <title>${labels[i]}: ${v} Vulnerabilities &bull; Thermal Status: ${info.label}</title>
            </circle>
            <text x="${cx}" y="${cy - 10}" fill="${info.lightColor}" font-size="11" font-weight="700" text-anchor="middle" font-family="var(--font-mono)">${v}</text>
        `;
    });

    const svgHtml = `
        <svg viewBox="0 0 ${width} ${height}" style="width: 100%; height: 100%; overflow: visible;" preserveAspectRatio="none">
            <defs>
                <linearGradient id="vulnTempLineGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                    ${tempLineStops}
                </linearGradient>
                <linearGradient id="vulnTempAreaGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                    ${tempAreaStops}
                </linearGradient>
                <linearGradient id="dashVerticalFade" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="#ffffff" stop-opacity="1"/>
                    <stop offset="80%" stop-color="#ffffff" stop-opacity="0.3"/>
                    <stop offset="100%" stop-color="#ffffff" stop-opacity="0.0"/>
                </linearGradient>
                <mask id="dashAreaMask">
                    <rect x="0" y="0" width="${width}" height="${height}" fill="url(#dashVerticalFade)" />
                </mask>
                <filter id="glow-temp" x="-20%" y="-20%" width="140%" height="140%">
                    <feDropShadow dx="0" dy="0" stdDeviation="3.5" flood-color="#f97316" flood-opacity="0.4"/>
                </filter>
            </defs>

            ${gridLinesSvg}
            ${xLabelsSvg}

            <!-- Vulnerability Area Gradient Fill with Thermal Spectrum and Vertical Fade -->
            <polygon points="${vulnArea}" fill="url(#vulnTempAreaGrad)" mask="url(#dashAreaMask)" />

            <!-- Single Vulnerability Count Trend Line with Dynamic Thermal Spectrum -->
            <polyline points="${vulnPoints.join(" ")}" fill="none" stroke="url(#vulnTempLineGrad)" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" filter="url(#glow-temp)" />

            ${nodesSvg}
        </svg>
    `;

    container.innerHTML = svgHtml;

    if (summaryStat) {
        const startVal = vulnSeries[0] || 0;
        const endVal = vulnSeries[vulnSeries.length - 1] || 0;
        const startInfo = getVulnerabilityTemperature(startVal, maxVuln);
        const endInfo = getVulnerabilityTemperature(endVal, maxVuln);
        const diff = endVal - startVal;
        const pctChange = startVal > 0 ? Math.round(Math.abs(diff) / startVal * 100) : 0;
        const statusText = diff <= 0 ? `${pctChange}% Thermal Cooldown` : `${pctChange}% Thermal Spike`;
        const statusColor = diff <= 0 ? "#10b981" : "#ef4444";
        summaryStat.innerHTML = `
            Trajectory: <strong style="color: ${startInfo.color};">${startVal} (${startInfo.label})</strong> &rarr; <strong style="color: ${endInfo.color};">${endVal} (${endInfo.label})</strong> &bull;
            <span style="color: ${statusColor}; font-weight: 700;">${statusText}</span> &bull;
            <span style="color: #94a3b8;">Active Flaws: ${series.current_critical || 0} Critical &bull; ${series.current_high || 0} High &bull; ${series.current_medium || 0} Medium</span>
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

function setEngineFilter(engine) {
    const typeSelect = document.getElementById('filter-type');
    if (typeSelect) {
        typeSelect.value = engine;
    }
    syncEnginePills(engine);
    applyFilters();
}

function syncEnginePills(engine) {
    document.querySelectorAll('.engine-filter-pill').forEach(btn => {
        const btnEngine = btn.getAttribute('data-engine') || '';
        if (btnEngine === engine) {
            btn.classList.add('active');
            btn.style.background = 'var(--accent-indigo, #6366f1)';
            btn.style.color = '#fff';
            btn.style.borderColor = 'var(--accent-indigo, #6366f1)';
            btn.style.boxShadow = '0 0 10px rgba(99, 102, 241, 0.4)';
        } else {
            btn.classList.remove('active');
            btn.style.background = 'rgba(255, 255, 255, 0.05)';
            btn.style.color = 'var(--text-secondary, #94a3b8)';
            btn.style.borderColor = 'rgba(255, 255, 255, 0.12)';
            btn.style.boxShadow = 'none';
        }
    });
}

function onFilterTypeSelectChange(val) {
    syncEnginePills(val);
    applyFilters();
}

function applyFilters() {
    const q = document.getElementById("filter-search")?.value.toLowerCase() || "";
    const type = document.getElementById("filter-type")?.value || "";
    const sev = document.getElementById("filter-severity")?.value || "";
    const quad = document.getElementById("filter-quadrant")?.value || "";
    const std = document.getElementById("filter-standard")?.value || "";
    const dev = document.getElementById("filter-developer")?.value || "";

    syncEnginePills(type);

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

        let engineBadge = `<span class="badge" style="background: rgba(255,255,255,0.06);">${escapeHtml((f.type || 'sast').toUpperCase())}</span>`;
        if (f.type === 'iac') {
            engineBadge = `<span class="badge" style="background: rgba(56, 189, 248, 0.18); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); font-weight: 700;">🏗️ IAC</span>`;
        } else if (f.type === 'sca') {
            engineBadge = `<span class="badge" style="background: rgba(168, 85, 247, 0.18); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.4); font-weight: 700;">📦 SCA</span>`;
        } else if (f.type === 'api') {
            engineBadge = `<span class="badge" style="background: rgba(16, 185, 129, 0.18); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); font-weight: 700;">🌐 API</span>`;
        } else if (f.type === 'secret') {
            engineBadge = `<span class="badge" style="background: rgba(239, 68, 68, 0.18); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); font-weight: 700;">🔑 SECRET</span>`;
        } else if (f.type === 'sast') {
            engineBadge = `<span class="badge" style="background: rgba(99, 102, 241, 0.18); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.4); font-weight: 700;">🛡️ SAST</span>`;
        }

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
                    ${f.entropy ? `<span class="badge" style="background: rgba(236, 72, 153, 0.18); color: #f472b6; border: 1px solid rgba(236, 72, 153, 0.35); font-size: 10px;">🎲 Entropy: ${(typeof f.entropy === 'number' ? f.entropy.toFixed(2) : f.entropy)}</span>` : ''}
                    ${f.dependency_lag_versions ? `<span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; font-size: 10px;">📦 ${escapeHtml(f.dependency_lag_versions)}</span>` : ''}
                </div>
            </td>
            <td>
                <div style="font-weight: 600; color: #fff; font-size: 13px;">${escapeHtml(f.author_name || 'Unknown')}</div>
                <div style="font-size: 11px; color: var(--text-secondary);">${escapeHtml(f.author_email || '')}</div>
                <div style="font-family: var(--font-mono); font-size: 10px; color: var(--accent-cyan);">${f.commit_hash ? '#' + f.commit_hash : ''}</div>
            </td>
            <td>${engineBadge}</td>
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
        const maskedInfo = f.masked_value ? ` | Masked: ${f.masked_value}` : '';
        if (entropyVal) entropyVal.textContent = `${typeof f.entropy === 'number' ? f.entropy.toFixed(2) : f.entropy} bits/char (${f.entropy_level || 'HIGH'})${maskedInfo}`;
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

    openModal("modal-finding-detail");
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

async function applyRemediationPatch() {
    if (!state.activeFinding) return;

    const btn = document.getElementById("btn-apply-patch");
    const btnText = document.getElementById("patch-btn-text");
    const btnSpinner = document.getElementById("patch-btn-spinner");

    if (btn) btn.disabled = true;
    if (btnText) btnText.textContent = "Applying Patch...";
    if (btnSpinner) btnSpinner.style.display = "inline-block";

    try {
        const patchCodeEl = document.getElementById("ai-code-diff");
        const patchCode = patchCodeEl ? patchCodeEl.textContent : "";

        const resp = await fetch(`/api/findings/${state.activeFinding.id}/apply-patch`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ patch_code: patchCode })
        });

        if (resp.status === 403) {
            showToast("Access Restricted: You can only apply patches to code you authored.", "error");
            return;
        }

        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            showToast(err.detail || "Failed to apply security patch", "error");
            return;
        }

        const res = await resp.json();
        showToast(`⚡ ${res.message}! Status updated to Resolved.`, "success");

        state.activeFinding.status = "resolved";
        const statusSelect = document.getElementById("detail-status-select");
        if (statusSelect) statusSelect.value = "resolved";

        await loadFindings();
        await loadDashboardStats();

        const box = document.getElementById("detail-ai-remediation-box");
        if (box) {
            const patchNotice = document.createElement("div");
            patchNotice.style.cssText = "margin-top: 14px; padding: 12px 16px; background: rgba(56, 189, 248, 0.15); border: 1px solid rgba(56, 189, 248, 0.4); border-radius: 8px; color: #38bdf8; font-size: 13px;";
            patchNotice.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="color: #38bdf8;">⚡ Security Patch Applied &amp; Verified</strong>
                    <span class="badge" style="background: rgba(16, 185, 129, 0.3); color: #86efac;">RESOLVED</span>
                </div>
                <div>File Path: <code style="color: #fff; background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">${res.file_path}</code></div>
                <div style="margin-top: 4px; font-size: 12px; color: #cbd5e1;">Patched Lines: <strong>${res.patched_lines ? res.patched_lines.join(' - ') : 'Target Context'}</strong></div>
            `;
            box.appendChild(patchNotice);
        }
    } catch (e) {
        showToast("Error applying security patch", "error");
    } finally {
        if (btn) btn.disabled = false;
        if (btnText) btnText.textContent = "⚡ 1-Click Apply Patch to File";
        if (btnSpinner) btnSpinner.style.display = "none";
    }
}

async function downloadAuditEvidenceBundle() {
    const projId = state.activeProjectId || (state.projects[0] ? state.projects[0].id : "");
    if (!projId) {
        showToast("Please select a project to export evidence bundle", "error");
        return;
    }
    showToast("Packaging Auditor Evidence Bundle (SBOM, SARIF, VEX, Signed Attestations)...", "info");
    window.location.href = `/api/projects/${projId}/export/audit-bundle`;
}

function openBadgeModal(projectId, projectName) {
    const origin = window.location.origin;
    const badgeUrl = `${origin}/api/projects/${projectId}/badge.svg`;
    const projUrl = `${origin}/`;
    const markdown = `[![Sentinel Security](${badgeUrl})](${projUrl})`;

    const preview = document.getElementById("badge-modal-preview");
    const mdInput = document.getElementById("badge-modal-markdown");
    const urlInput = document.getElementById("badge-modal-url");

    if (preview) preview.src = badgeUrl;
    if (mdInput) mdInput.value = markdown;
    if (urlInput) urlInput.value = badgeUrl;

    openModal("modal-project-badge");
}

function copyBadgeMarkdown() {
    const mdInput = document.getElementById("badge-modal-markdown");
    if (mdInput) {
        navigator.clipboard.writeText(mdInput.value).then(() => {
            showToast("Copied Markdown snippet to clipboard!", "success");
        }).catch(() => {
            mdInput.select();
            document.execCommand("copy");
            showToast("Copied Markdown snippet to clipboard!", "success");
        });
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

    const targetProjectId = document.getElementById("nl-rule-project-select")?.value || "";

    try {
        const resp = await fetch("/api/rules/generate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ prompt: promptInput, project_id: targetProjectId || null })
        });

        if (resp.ok) {
            const rule = await resp.json();
            activeGeneratedRule = rule;
            const editor = document.getElementById("rule-yaml-editor");
            if (editor) editor.value = rule.yaml_representation;

            // Auto-populate Live Code Test Bench with synthesized trigger code
            const codeBox = document.getElementById("rule-sandbox-code");
            if (codeBox && rule.sample_trigger_code) {
                codeBox.value = rule.sample_trigger_code;
            }

            const creator = rule.created_by || "Sentinel AI Synthesizer";
            const targetName = (state.projects || []).find(p => p.id === targetProjectId)?.name;
            const scopeNote = targetName ? ` for project '${targetName}'` : " globally";
            showToast(`Rule synthesized successfully${scopeNote} via ${creator}!`, "success");
        } else {
            const errData = await resp.json().catch(() => ({}));
            showToast(errData.detail || "Failed to synthesize rule", "error");
        }
    } catch (e) {
        showToast("Rule synthesis error: " + (e.message || e), "error");
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

    const syncToYaml = document.getElementById("check-sync-to-yaml")?.checked !== false;
    const targetProjectId = document.getElementById("nl-rule-project-select")?.value || "";

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

        ruleObj.project_id = targetProjectId || null;
        if (targetProjectId) {
            const p = (state.projects || []).find(x => x.id === targetProjectId);
            if (p) ruleObj.project_name = p.name;
        }

        const url = `/api/rules?sync_to_yaml=${syncToYaml}${targetProjectId ? `&project_id=${targetProjectId}` : ''}`;
        const resp = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(ruleObj)
        });

        if (resp.ok) {
            const projObj = (state.projects || []).find(x => x.id === targetProjectId);
            const scopeDesc = projObj ? `for project '${projObj.name}'` : "globally across all projects";
            const msg = syncToYaml
                ? `Custom rule saved ${scopeDesc} & synced to .sentinel/rules.yaml!`
                : `Custom rule saved and activated ${scopeDesc}!`;
            showToast(msg, "success");
            await loadCustomRules();
        } else {
            showToast("Failed to save rule", "error");
        }
    } catch (e) {
        showToast("Error saving rule", "error");
    }
}

let currentRulesScopeFilter = "all";

function filterRulesTableByScope(scope) {
    currentRulesScopeFilter = scope;
    ["all", "project", "global"].forEach(s => {
        const btn = document.getElementById(`btn-filter-rules-${s}`);
        if (btn) {
            if (s === scope) {
                btn.classList.add("active");
            } else {
                btn.classList.remove("active");
            }
        }
    });
    renderCustomRulesTable();
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

    let rulesToDisplay = state.customRules || [];
    if (currentRulesScopeFilter === "project") {
        rulesToDisplay = rulesToDisplay.filter(r => r.project_id === state.activeProjectId);
    } else if (currentRulesScopeFilter === "global") {
        rulesToDisplay = rulesToDisplay.filter(r => !r.project_id || r.project_id === "global");
    }

    if (rulesToDisplay.length === 0) {
        const activeProjName = state.projects.find(p => p.id === state.activeProjectId)?.name || "Active Project";
        const emptyMsg = currentRulesScopeFilter === "project"
            ? `No custom rules specifically assigned to ${activeProjName}.`
            : (currentRulesScopeFilter === "global"
                ? "No global custom rules found."
                : 'No custom rules found matching current filter. Click "Synthesize Rule" or "Rule Studio" to create one!');
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 24px;">${escapeHtml(emptyMsg)}</td></tr>`;
        return;
    }

    rulesToDisplay.forEach(r => {
        const tr = document.createElement("tr");

        let projectBadge = `<span class="badge" style="background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.3); font-weight: 500;"><i class="bi bi-globe me-1"></i>Global (All)</span>`;
        if (r.project_id) {
            const pName = r.project_name || state.projects.find(p => p.id === r.project_id)?.name || r.project_id;
            projectBadge = `<span class="badge" style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); font-weight: 500;"><i class="bi bi-folder-check me-1"></i>${escapeHtml(pName)}</span>`;
        }

        tr.innerHTML = `
            <td><code>${escapeHtml(r.id)}</code></td>
            <td>
                <strong>${escapeHtml(r.name)}</strong>
                <div style="font-size: 12px; color: var(--text-muted);">${escapeHtml(r.nl_prompt || r.description || '')}</div>
            </td>
            <td>${projectBadge}</td>
            <td><span class="badge" style="background: rgba(255,255,255,0.06);">${(r.rule_category || 'sast').toUpperCase()}</span></td>
            <td><span class="badge badge-${(r.severity || 'medium').toLowerCase()}">${escapeHtml(r.severity || 'MEDIUM')}</span></td>
            <td><code>${escapeHtml(r.cwe || 'CWE-699')}</code></td>
            <td><span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981;">ACTIVE</span></td>
            <td style="text-align: right;">
                <button class="btn btn-danger btn-sm" onclick="deleteRule('${escapeHtml(r.id)}')">Delete</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function deleteRule(ruleId) {
    if (!confirm(`Are you sure you want to permanently delete rule "${ruleId}" from the database and project .sentinel/rules.yaml?`)) {
        return;
    }

    try {
        const url = `/api/rules/${encodeURIComponent(ruleId)}${state.activeProjectId ? `?project_id=${state.activeProjectId}` : ''}`;
        const resp = await fetch(url, { method: "DELETE" });
        if (resp.ok) {
            showToast(`Rule ${ruleId} permanently purged from catalog and .sentinel/rules.yaml`, "success");

            // Purge active editor & sandbox if the deleted rule was loaded
            const editor = document.getElementById("rule-yaml-editor");
            if (activeGeneratedRule && (activeGeneratedRule.id === ruleId || (activeGeneratedRule.name && activeGeneratedRule.name.includes(ruleId)))) {
                activeGeneratedRule = null;
                if (editor) editor.value = "";
                const codeBox = document.getElementById("rule-sandbox-code");
                if (codeBox) codeBox.value = "";
                const resultsBox = document.getElementById("rule-test-results");
                if (resultsBox) resultsBox.innerHTML = '<span style="color: var(--text-muted);">Awaiting test execution...</span>';
            } else if (editor && editor.value.includes(ruleId)) {
                editor.value = "";
            }

            await loadCustomRules();

            // Refresh open YAML view if modal is open
            const modalYaml = document.getElementById("modal-view-rules-yaml");
            if (modalYaml && modalYaml.classList.contains("active")) {
                await fetchRulesYamlContent();
            }
        } else {
            showToast("Failed to delete rule", "error");
        }
    } catch (e) {
        showToast("Error deleting rule", "error");
    }
}

// --- SonarQube RSPEC & Open Rule Database Functions ---
async function loadSonarRules() {
    try {
        const resp = await fetch("/api/rules/database");
        if (resp.ok) {
            const data = await resp.json();
            state.sonarRules = data.rules || [];
            state.sonarStats = data.stats || {};

            // Update stats cards
            const elSonar = document.getElementById("stat-sonar-rules-count");
            if (elSonar) elSonar.textContent = state.sonarStats.sonarqube_rspec_count ?? state.sonarRules.length;

            const elOpen = document.getElementById("stat-open-rules-count");
            if (elOpen) elOpen.textContent = (state.sonarStats.community_rules_count || 0) + (state.sonarStats.imported_rules_count || 0);

            const elLangs = document.getElementById("stat-sonar-langs-count");
            if (elLangs) elLangs.textContent = (state.sonarStats.languages_supported || []).length || 7;

            const elCwes = document.getElementById("stat-sonar-cwes-count");
            if (elCwes) elCwes.textContent = state.sonarStats.cwe_categories_covered || 18;

            renderSonarRulesTable(state.sonarRules);
        }
    } catch (e) {
        console.error("Failed to load SonarQube & open rules:", e);
    }
}

function renderSonarRulesTable(rules) {
    const tbody = document.getElementById("sonar-rules-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    const list = rules || state.sonarRules || [];
    if (list.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 24px;">No SonarQube or Open Database rules matching filters.</td></tr>';
        return;
    }

    list.forEach(r => {
        const tr = document.createElement("tr");

        const sonarKey = r.sonar_key || r.id;
        const sonarType = r.sonar_type || (r.type ? r.type.toUpperCase() : "VULNERABILITY");
        const sonarSev = r.sonar_severity || r.severity || "MAJOR";
        const sevClass = (r.severity || "medium").toLowerCase();

        // Source badge
        let srcBadge = '';
        if (r.rule_source === "sonarqube_rspec") {
            srcBadge = '<span class="badge" style="background: rgba(168, 85, 247, 0.2); color: #c084fc; font-size: 10px; margin-left: 4px;">RSPEC</span>';
        } else if (r.rule_source === "open_community") {
            srcBadge = '<span class="badge" style="background: rgba(56, 189, 248, 0.2); color: #38bdf8; font-size: 10px; margin-left: 4px;">COMMUNITY</span>';
        } else if (r.rule_source === "sonarqube_imported") {
            srcBadge = '<span class="badge" style="background: rgba(234, 179, 8, 0.2); color: #eab308; font-size: 10px; margin-left: 4px;">IMPORTED</span>';
        }

        // Languages badges
        const langs = (r.languages || []).map(l => `<span class="badge" style="background: rgba(255,255,255,0.06); font-size: 11px;">${escapeHtml(l)}</span>`).join(" ");

        // Active status badge & button
        const isActive = r.is_active !== false;
        const statusBadge = isActive
            ? '<span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981;">ENABLED</span>'
            : '<span class="badge" style="background: rgba(100, 116, 139, 0.2); color: #94a3b8;">DISABLED</span>';

        tr.innerHTML = `
            <td>
                <code>${escapeHtml(sonarKey)}</code>
                ${srcBadge}
            </td>
            <td>
                <strong style="color: #f8fafc;">${escapeHtml(r.name)}</strong>
                <div style="font-size: 12px; color: var(--text-secondary); max-width: 380px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                    ${escapeHtml(r.description || '')}
                </div>
            </td>
            <td>
                <span class="badge" style="background: rgba(255,255,255,0.08); font-size: 11px;">${escapeHtml(sonarType)}</span>
            </td>
            <td>
                <span class="badge badge-${sevClass}">${escapeHtml(sonarSev)}</span>
            </td>
            <td>
                <code>${escapeHtml(r.cwe || 'CWE-699')}</code>
                <div style="font-size: 11px; color: var(--text-muted);">${escapeHtml(r.owasp || '')}</div>
            </td>
            <td>
                <div style="display: flex; gap: 4px; flex-wrap: wrap; max-width: 140px;">
                    ${langs}
                </div>
            </td>
            <td>
                <button class="btn btn-sm ${isActive ? 'btn-outline-success' : 'btn-outline-secondary'}" style="padding: 2px 8px; font-size: 11px;" onclick="toggleSonarRuleStatus('${escapeHtml(r.id)}', ${!isActive})">
                    ${statusBadge}
                </button>
            </td>
            <td style="text-align: right;">
                <button class="btn btn-secondary btn-sm" onclick="inspectSonarRule('${escapeHtml(r.id)}')">
                    <i class="bi bi-eye"></i> Inspect
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function filterSonarRules() {
    const searchVal = (document.getElementById("sonar-search-input")?.value || "").toLowerCase().trim();
    const langVal = document.getElementById("sonar-lang-filter")?.value || "";
    const sevVal = (document.getElementById("sonar-sev-filter")?.value || "").toUpperCase();
    const sourceVal = document.getElementById("sonar-source-filter")?.value || "";

    const filtered = (state.sonarRules || []).filter(r => {
        if (langVal && !(r.languages || []).includes(langVal)) return false;
        if (sevVal && (r.severity || "").toUpperCase() !== sevVal) return false;
        if (sourceVal && r.rule_source !== sourceVal) return false;
        if (searchVal) {
            const haystack = `${r.id} ${r.sonar_key || ''} ${r.name} ${r.description} ${r.cwe || ''} ${r.owasp || ''}`.toLowerCase();
            if (!haystack.includes(searchVal)) return false;
        }
        return true;
    });

    renderSonarRulesTable(filtered);
}

async function syncOpenRulesDatabase() {
    const btn = document.getElementById("btn-sync-open-db");
    const origHtml = btn ? btn.innerHTML : "";
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Syncing...';
    }

    try {
        const resp = await fetch("/api/rules/database/sync", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({})
        });
        if (resp.ok) {
            const data = await resp.json();
            showToast(`Open SAST Database synced! ${data.total_active_rules} rules active.`, "success");
            await loadSonarRules();
        } else {
            showToast("Failed to sync Open SAST Database.", "error");
        }
    } catch (e) {
        showToast("Error connecting to database sync service.", "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = origHtml;
        }
    }
}

function openImportSonarModal() {
    const statusBox = document.getElementById("import-sonar-status");
    if (statusBox) statusBox.classList.add("d-none");
    const textarea = document.getElementById("import-sonar-content");
    if (textarea) textarea.value = "";
    openModal("modal-import-sonar");
}

async function submitImportSonarProfile() {
    const format = document.getElementById("import-sonar-format")?.value || "xml";
    const content = document.getElementById("import-sonar-content")?.value || "";
    const statusBox = document.getElementById("import-sonar-status");

    if (!content.trim()) {
        showToast("Please paste SonarQube profile content or rules.", "error");
        return;
    }

    const btn = document.getElementById("btn-submit-import-sonar");
    if (btn) btn.disabled = true;

    try {
        const resp = await fetch("/api/rules/database/import", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ format, content })
        });
        const data = await resp.json();

        if (resp.ok) {
            showToast(`Successfully imported ${data.imported_count} rule(s) into active SAST catalog!`, "success");
            closeModal("modal-import-sonar");
            await loadSonarRules();
        } else {
            if (statusBox) {
                statusBox.textContent = data.detail || "Import error occurred.";
                statusBox.classList.remove("d-none", "alert-info");
                statusBox.classList.add("alert-danger");
            }
        }
    } catch (e) {
        showToast("Network error submitting rule profile.", "error");
    } finally {
        if (btn) btn.disabled = false;
    }
}

function inspectSonarRule(ruleId) {
    const rule = (state.sonarRules || []).find(r => r.id === ruleId);
    if (!rule) return;

    const elTitle = document.getElementById("inspect-sonar-title");
    if (elTitle) elTitle.textContent = rule.name;

    const elBadge = document.getElementById("inspect-sonar-badge");
    if (elBadge) elBadge.textContent = (rule.rule_source || "SONARQUBE").toUpperCase();

    const elSev = document.getElementById("inspect-sonar-sev");
    if (elSev) {
        elSev.textContent = rule.sonar_severity || rule.severity || "CRITICAL";
        elSev.className = `badge badge-${(rule.severity || 'medium').toLowerCase()}`;
    }

    const elType = document.getElementById("inspect-sonar-type");
    if (elType) elType.textContent = rule.sonar_type || "VULNERABILITY";

    const elKey = document.getElementById("inspect-sonar-key");
    if (elKey) elKey.textContent = rule.sonar_key || rule.id;

    const elCwe = document.getElementById("inspect-sonar-cwe");
    if (elCwe) elCwe.textContent = rule.cwe || "CWE-699";

    const elOwasp = document.getElementById("inspect-sonar-owasp");
    if (elOwasp) elOwasp.textContent = rule.owasp || "OWASP Top 10";

    const elDesc = document.getElementById("inspect-sonar-desc");
    if (elDesc) elDesc.textContent = rule.description || "No description provided.";

    const elRem = document.getElementById("inspect-sonar-remediation");
    if (elRem) elRem.textContent = rule.remediation || "Adhere to secure coding best practices.";

    const elRegex = document.getElementById("inspect-sonar-regex");
    if (elRegex) elRegex.textContent = rule.regex || "# AST / Semantic Rule Pattern";

    openModal("modal-inspect-sonar-rule");
}

async function toggleSonarRuleStatus(ruleId, newStatus) {
    try {
        const resp = await fetch("/api/rules/database/toggle", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ rule_id: ruleId, is_active: newStatus })
        });
        if (resp.ok) {
            showToast(`Rule ${ruleId} is now ${newStatus ? 'enabled' : 'disabled'}.`, "info");
            await loadSonarRules();
        }
    } catch (e) {
        showToast("Error updating rule status.", "error");
    }
}

function openSonarIntegrationModal() {
    const statusBox = document.getElementById("sonar-deploy-status");
    if (statusBox) {
        statusBox.classList.add("d-none");
        statusBox.innerHTML = "";
    }
    const currentProj = (state.projects || []).find(p => p.id === state.activeProjectId);
    const projKey = currentProj ? (currentProj.name || "appsec").toLowerCase().replace(/[^a-zA-Z0-9_\-\.:]/g, "_") : "my-project";
    const argsBox = document.getElementById("sonar-cli-args-box");
    if (argsBox) {
        argsBox.textContent = `sonar-scanner -Dsonar.projectKey=${projKey} -Dsonar.externalIssuesReportPaths=sonar-issues.json -Dsonar.sarifReportPaths=aegissec-sarif.json`;
    }
    openModal("modal-integrate-sonar");
}

async function deploySonarIntegration() {
    if (!state.activeProjectId) {
        showToast("Please select an active project first.", "warning");
        return;
    }
    const btn = document.getElementById("btn-deploy-sonar-integration");
    const statusBox = document.getElementById("sonar-deploy-status");
    const origHtml = btn ? btn.innerHTML : "";
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Deploying...';
    }

    try {
        const resp = await fetch(`/api/projects/${state.activeProjectId}/integrate/sonarqube`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const data = await resp.json();
        if (resp.ok) {
            showToast("SonarQube integration deployed successfully!", "success");
            if (statusBox) {
                const filesList = (data.files_created || []).map(f => `<li><code>${escapeHtml(f)}</code></li>`).join("");
                statusBox.innerHTML = `
                    <div class="fw-bold text-success mb-1">✔ Integration Files Created:</div>
                    <ul class="mb-1 ps-3">${filesList}</ul>
                    <div class="mt-1 text-light">CLI Scan: <code>${escapeHtml(data.instructions?.cli_command || '')}</code></div>
                `;
                statusBox.className = "alert alert-success py-2 px-3 small mt-2 mb-0";
                statusBox.classList.remove("d-none");
            }
        } else {
            showToast(data.detail || "Failed to deploy SonarQube integration", "error");
            if (statusBox) {
                statusBox.textContent = data.detail || "Deployment failed.";
                statusBox.className = "alert alert-danger py-2 px-3 small mt-2 mb-0";
                statusBox.classList.remove("d-none");
            }
        }
    } catch (e) {
        showToast("Network error deploying integration files.", "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = origHtml;
        }
    }
}

// --- rules.yaml Viewer & Editor Functions ---
async function openViewRulesYamlModal() {
    openModal("modal-view-rules-yaml");
    await fetchRulesYamlContent();
}

async function fetchRulesYamlContent() {
    const editor = document.getElementById("view-rules-yaml-editor");
    const pathEl = document.getElementById("view-rules-yaml-path");
    const statusEl = document.getElementById("view-rules-yaml-status");
    const countEl = document.getElementById("view-rules-yaml-count");

    if (editor) editor.value = "# Fetching .sentinel/rules.yaml from server...";

    try {
        const url = `/api/rules/file${state.activeProjectId ? `?project_id=${state.activeProjectId}` : ''}`;
        const resp = await fetch(url);
        if (resp.ok) {
            const data = await resp.json();
            if (editor) editor.value = data.content;
            if (pathEl) pathEl.textContent = data.file_path || ".sentinel/rules.yaml";
            if (statusEl) {
                if (data.found) {
                    statusEl.textContent = "ACTIVE FILE ON DISK";
                    statusEl.style.background = "rgba(16, 185, 129, 0.2)";
                    statusEl.style.color = "#10b981";
                } else {
                    statusEl.textContent = "SYNTHESIZED FROM ACTIVE CATALOG";
                    statusEl.style.background = "rgba(56, 189, 248, 0.2)";
                    statusEl.style.color = "#38bdf8";
                }
            }

            // Count rules defined in YAML
            const matchCount = (data.content.match(/^\s*-\s*id:\s*['"]?[a-zA-Z0-9_-]+/gm) || []).length;
            if (countEl) {
                countEl.textContent = `${matchCount} rule${matchCount === 1 ? '' : 's'} declared`;
            }
        } else {
            if (editor) editor.value = "# Error loading .sentinel/rules.yaml from server";
        }
    } catch (e) {
        if (editor) editor.value = `# Connection error: ${e.message}`;
    }
}

async function saveRulesYamlFile() {
    const editor = document.getElementById("view-rules-yaml-editor");
    if (!editor) return;

    const content = editor.value;
    if (!content.trim()) {
        showToast("rules.yaml cannot be empty", "error");
        return;
    }

    const btn = document.getElementById("btn-save-rules-yaml");
    if (btn) btn.disabled = true;

    try {
        const url = `/api/rules/file${state.activeProjectId ? `?project_id=${state.activeProjectId}` : ''}`;
        const resp = await fetch(url, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ content })
        });

        if (resp.ok) {
            showToast("Successfully saved .sentinel/rules.yaml! Scanners and IDE will reload.", "success");
            await fetchRulesYamlContent();
            await loadCustomRules();
        } else {
            const err = await resp.json();
            showToast(`Save failed: ${err.detail || 'Server error'}`, "error");
        }
    } catch (e) {
        showToast(`Save error: ${e.message}`, "error");
    } finally {
        if (btn) btn.disabled = false;
    }
}

function copyRulesYamlContent() {
    const editor = document.getElementById("view-rules-yaml-editor");
    if (!editor || !editor.value) return;

    navigator.clipboard.writeText(editor.value).then(() => {
        showToast("rules.yaml copied to clipboard!", "success");
        const btn = document.getElementById("btn-copy-rules-yaml");
        if (btn) {
            const originalText = btn.innerHTML;
            btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Copied!`;
            setTimeout(() => { btn.innerHTML = originalText; }, 2000);
        }
    }).catch(() => {
        showToast("Failed to copy to clipboard", "error");
    });
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

        await loadWebhookConfig();
        await loadSchedules();
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

// --- User Management & RBAC ---
let userToDeleteId = null;

async function loadUsers() {
    try {
        const resp = await fetch("/api/users");
        if (resp.ok) {
            const users = await resp.json();
            state.users = users;
            const tbody = document.getElementById("users-tbody");
            if (!tbody) return;
            tbody.innerHTML = "";

            if (!users || users.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 30px;">No users registered.</td></tr>';
                return;
            }

            users.forEach(u => {
                const tr = document.createElement("tr");
                const privMap = {
                    admin: "Full System Access, Integrations, Custom Rules, Project Management",
                    security_engineer: "Scan Execution, Custom Rule Generation, Ticket Dispatch, Project Management",
                    developer: "View Projects, Inspect Findings, Mark False Positives, View Remediation",
                    auditor: "Read-Only Compliance Reports, Standards Matrices, Audit Log Inspection"
                };

                const safeUsername = escapeHtml(u.username);
                const safeEmail = escapeHtml(u.email);
                const safeRole = escapeHtml(u.role);
                const isDefaultAdmin = u.username === "admin";

                let projectsScopeHtml = "";
                if (u.role === "admin") {
                    projectsScopeHtml = `<span class="badge" style="background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); font-weight: 600;">Global (All Projects)</span>`;
                } else if (u.assigned_projects && u.assigned_projects.length > 0) {
                    projectsScopeHtml = u.assigned_projects.map(pid => {
                        const proj = (state.projects || []).find(p => p.id === pid);
                        const name = proj ? proj.name : pid;
                        return `<span class="badge" style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); margin-right: 4px; margin-bottom: 2px;">${escapeHtml(name)}</span>`;
                    }).join("");
                } else {
                    projectsScopeHtml = `<span class="badge" style="background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3);">No Projects Assigned</span>`;
                }

                tr.innerHTML = `
                    <td><strong>${safeUsername}</strong></td>
                    <td>${safeEmail}</td>
                    <td><span class="badge" style="background: rgba(56, 189, 248, 0.15); color: var(--accent-cyan); font-weight: 600;">${safeRole.toUpperCase()}</span></td>
                    <td>${projectsScopeHtml}</td>
                    <td style="font-size: 12px; color: var(--text-secondary);">${privMap[u.role] || 'Standard Access'}</td>
                    <td style="font-size: 13px; color: var(--text-muted);">${new Date(u.created_at).toLocaleDateString()}</td>
                    <td style="text-align: right; white-space: nowrap;">
                        <button class="btn btn-secondary btn-sm" onclick="openUpdateUserModalById('${u.id}')" style="display: inline-flex; align-items: center; gap: 4px; padding: 4px 10px; font-size: 12px; font-weight: 600;">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
                            Update
                        </button>
                        ${!isDefaultAdmin ? `
                        <button class="btn btn-danger btn-sm" onclick="promptDeleteUser('${u.id}', '${safeUsername}')" style="display: inline-flex; align-items: center; gap: 4px; padding: 4px 8px; font-size: 12px; font-weight: 600; margin-left: 4px;">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                            Delete
                        </button>` : ''}
                    </td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            const err = await resp.json().catch(() => ({}));
            showToast(err.detail || "Failed loading users", "error");
        }
    } catch (e) {
        console.error("Failed loading users:", e);
    }
}

function onUserRoleChange(mode) {
    const roleSelect = document.getElementById(mode === "create" ? "new-user-role" : "update-user-role");
    const groupEl = document.getElementById(mode === "create" ? "create-user-projects-group" : "update-user-projects-group");
    const hintEl = document.getElementById(mode === "create" ? "create-user-projects-hint" : "update-user-projects-hint");
    if (!roleSelect || !groupEl) return;

    const role = roleSelect.value;
    if (role === "admin") {
        if (hintEl) {
            hintEl.textContent = "Administrators have global enterprise access across all projects automatically.";
            hintEl.style.color = "#c084fc";
        }
        const checkboxes = groupEl.querySelectorAll("input[type='checkbox']");
        checkboxes.forEach(cb => {
            cb.checked = true;
            cb.disabled = true;
        });
    } else {
        if (hintEl) {
            hintEl.textContent = "Non-admin users will strictly ONLY view, inspect findings, run scans, and export reports for checked projects.";
            hintEl.style.color = "var(--text-muted)";
        }
        const checkboxes = groupEl.querySelectorAll("input[type='checkbox']");
        checkboxes.forEach(cb => {
            cb.disabled = false;
        });
    }
}

async function openCreateUserModal() {
    const form = document.getElementById("form-create-user");
    if (form) form.reset();
    const errBox = document.getElementById("create-user-error");
    if (errBox) {
        errBox.classList.add("d-none");
        errBox.textContent = "";
    }

    if (!state.projects || state.projects.length === 0) {
        await loadProjects();
    }

    const projectsList = document.getElementById("create-user-projects-list");
    if (projectsList) {
        if (!state.projects || state.projects.length === 0) {
            projectsList.innerHTML = `<span style="font-size: 12px; color: var(--text-muted);">No projects available to assign.</span>`;
        } else {
            projectsList.innerHTML = state.projects.map(p => `
                <label class="d-flex align-items-center gap-2 mb-2 p-1" style="font-size: 13px; cursor: pointer;">
                    <input type="checkbox" name="create-user-project" value="${p.id}" class="form-check-input mt-0">
                    <span style="font-weight: 500; color: #fff;">${escapeHtml(p.name)}</span>
                    <span style="font-size: 11px; color: var(--text-muted);">(${escapeHtml(p.git_branch || 'main')})</span>
                </label>
            `).join("");
        }
    }

    onUserRoleChange("create");
    openModal("modal-create-user");
    const userField = document.getElementById("new-user-username");
    if (userField) setTimeout(() => userField.focus(), 60);
}

async function submitCreateUser(event) {
    event.preventDefault();
    const errBox = document.getElementById("create-user-error");
    if (errBox) {
        errBox.classList.add("d-none");
        errBox.textContent = "";
    }

    const username = document.getElementById("new-user-username")?.value.trim();
    let email = document.getElementById("new-user-email")?.value.trim();
    const password = document.getElementById("new-user-password")?.value;
    const role = document.getElementById("new-user-role")?.value;

    if (!username || !email || !password || !role) {
        const msg = "Please fill in all required fields (username, email, password, and role).";
        if (errBox) {
            errBox.textContent = msg;
            errBox.classList.remove("d-none");
        }
        showToast(msg, "error");
        return;
    }

    if (!email.includes("@")) {
        email = `${email}@sentinel.internal`;
    }

    const assigned_projects = [];
    if (role !== "admin") {
        document.querySelectorAll("input[name='create-user-project']:checked").forEach(cb => {
            assigned_projects.push(cb.value);
        });
    }

    const btn = document.getElementById("btn-submit-create-user");
    if (btn) {
        btn.disabled = true;
        btn.innerText = "Creating...";
    }

    try {
        const resp = await fetch("/api/users", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, email, password, role, assigned_projects })
        });

        if (resp.ok) {
            const data = await resp.json();
            showToast(`User '${data.username || username}' created successfully!`, "success");
            closeModal("modal-create-user");
            await loadUsers();
        } else {
            const err = await resp.json().catch(() => ({}));
            const msg = err.detail || "Failed to create user";
            if (errBox) {
                errBox.textContent = msg;
                errBox.classList.remove("d-none");
            }
            showToast(msg, "error");
        }
    } catch (e) {
        const msg = "Network error connecting to authentication server";
        if (errBox) {
            errBox.textContent = msg;
            errBox.classList.remove("d-none");
        }
        showToast(msg, "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerText = "Create User";
        }
    }
}

function openUpdateUserModalById(id) {
    const u = (state.users || []).find(user => user.id === id || user.username === id);
    if (!u) {
        showToast(`User '${id}' not found in system state.`, "error");
        return;
    }
    openUpdateUserModal(u.id, u.username, u.email, u.role, u.assigned_projects || []);
}

async function openUpdateUserModal(id, username, email, role, assignedProjects = []) {
    const errBox = document.getElementById("update-user-error");
    if (errBox) {
        errBox.classList.add("d-none");
        errBox.textContent = "";
    }

    const idField = document.getElementById("update-user-id");
    const userField = document.getElementById("update-user-username");
    const emailField = document.getElementById("update-user-email");
    const roleField = document.getElementById("update-user-role");
    const pwdField = document.getElementById("update-user-password");

    if (idField) idField.value = id;
    if (userField) userField.value = username;
    if (emailField) emailField.value = email || "";
    if (roleField) roleField.value = role || "developer";
    if (pwdField) pwdField.value = "";

    if (!state.projects || state.projects.length === 0) {
        await loadProjects();
    }

    const assignedSet = new Set(assignedProjects || []);
    const projectsList = document.getElementById("update-user-projects-list");
    if (projectsList) {
        if (!state.projects || state.projects.length === 0) {
            projectsList.innerHTML = `<span style="font-size: 12px; color: var(--text-muted);">No projects available.</span>`;
        } else {
            projectsList.innerHTML = state.projects.map(p => `
                <label class="d-flex align-items-center gap-2 mb-2 p-1" style="font-size: 13px; cursor: pointer;">
                    <input type="checkbox" name="update-user-project" value="${p.id}" class="form-check-input mt-0" ${assignedSet.has(p.id) ? 'checked' : ''}>
                    <span style="font-weight: 500; color: #fff;">${escapeHtml(p.name)}</span>
                    <span style="font-size: 11px; color: var(--text-muted);">(${escapeHtml(p.git_branch || 'main')})</span>
                </label>
            `).join("");
        }
    }

    onUserRoleChange("update");
    openModal("modal-update-user");
    if (emailField) setTimeout(() => emailField.focus(), 60);
}

async function submitUpdateUser(event) {
    event.preventDefault();
    const errBox = document.getElementById("update-user-error");
    if (errBox) {
        errBox.classList.add("d-none");
        errBox.textContent = "";
    }

    const userId = document.getElementById("update-user-id")?.value;
    const username = document.getElementById("update-user-username")?.value;
    let email = document.getElementById("update-user-email")?.value.trim();
    const role = document.getElementById("update-user-role")?.value;
    const password = document.getElementById("update-user-password")?.value;

    if (!userId) {
        const msg = "Missing user ID. Please reopen the update modal.";
        if (errBox) {
            errBox.textContent = msg;
            errBox.classList.remove("d-none");
        }
        showToast(msg, "error");
        return;
    }

    if (!email) {
        const msg = "Email address is required.";
        if (errBox) {
            errBox.textContent = msg;
            errBox.classList.remove("d-none");
        }
        showToast(msg, "error");
        return;
    }

    if (!email.includes("@")) {
        email = `${email}@sentinel.internal`;
    }

    const payload = { role, email };
    if (password && password.trim()) {
        payload.password = password.trim();
    }

    if (role !== "admin") {
        const assigned_projects = [];
        document.querySelectorAll("input[name='update-user-project']:checked").forEach(cb => {
            assigned_projects.push(cb.value);
        });
        payload.assigned_projects = assigned_projects;
    } else {
        payload.assigned_projects = [];
    }

    const btn = document.getElementById("btn-submit-update-user");
    if (btn) {
        btn.disabled = true;
        btn.innerText = "Updating...";
    }

    try {
        const resp = await fetch(`/api/users/${userId}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (resp.ok) {
            showToast(`User '${username}' updated successfully!`, "success");
            closeModal("modal-update-user");
            await loadUsers();
        } else {
            const err = await resp.json().catch(() => ({}));
            const msg = err.detail || "Failed to update user";
            if (errBox) {
                errBox.textContent = msg;
                errBox.classList.remove("d-none");
            }
            showToast(msg, "error");
        }
    } catch (e) {
        const msg = "Network error updating user profile";
        if (errBox) {
            errBox.textContent = msg;
            errBox.classList.remove("d-none");
        }
        showToast(msg, "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerText = "Update User";
        }
    }
}

function promptDeleteUser(id, username) {
    userToDeleteId = id;
    const nameEl = document.getElementById("delete-user-name");
    if (nameEl) nameEl.textContent = username;
    openModal("modal-delete-user");
}

async function confirmDeleteUser() {
    if (!userToDeleteId) return;
    const btn = document.getElementById("btn-confirm-delete-user");
    if (btn) {
        btn.disabled = true;
        btn.innerText = "Deleting...";
    }

    try {
        const resp = await fetch(`/api/users/${userToDeleteId}`, { method: "DELETE" });
        if (resp.ok) {
            showToast("User deleted successfully!", "success");
            closeModal("modal-delete-user");
            userToDeleteId = null;
            await loadUsers();
        } else {
            const err = await resp.json().catch(() => ({}));
            showToast(err.detail || "Failed to delete user", "error");
        }
    } catch (e) {
        showToast("Network error deleting user", "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerText = "Delete User";
        }
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
function openModal(id) {
    const el = document.getElementById(id);
    if (!el) {
        console.error("Modal not found:", id);
        return;
    }
    el.classList.add("active");
    el.classList.add("show");
    el.style.setProperty("display", "flex", "important");
    el.style.setProperty("opacity", "1", "important");
    el.style.setProperty("visibility", "visible", "important");
    el.style.setProperty("pointer-events", "auto", "important");
    document.body.classList.add("modal-open");
}

function closeModal(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.remove("active");
    el.classList.remove("show");
    el.style.setProperty("display", "none", "important");
    el.style.setProperty("opacity", "0", "important");
    el.style.setProperty("visibility", "hidden", "important");
    el.style.setProperty("pointer-events", "none", "important");
    if (window.bootstrap && bootstrap.Modal) {
        try {
            const instance = bootstrap.Modal.getInstance(el);
            if (instance) instance.hide();
        } catch (e) {}
    }
    document.querySelectorAll(".modal-backdrop").forEach(b => b.remove());
    document.body.classList.remove("modal-open");
    document.body.style.overflow = "";
    document.body.style.paddingRight = "";
}

// Global dismiss listeners for modal backdrop and Escape key
document.addEventListener("click", (e) => {
    if (e.target && e.target.classList && e.target.classList.contains("modal-overlay")) {
        closeModal(e.target.id);
    }
});

document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
        document.querySelectorAll(".modal-overlay.active, .modal-overlay.show").forEach(m => {
            closeModal(m.id);
        });
    }
});

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

    const series = (trendsData && trendsData.primary) ? trendsData.primary : null;
    const labels = (trendsData && trendsData.labels) ? trendsData.labels : ["Sprint 31", "Sprint 32", "Sprint 33", "Sprint 34", "Sprint 35", "Sprint 36"];

    // Total audited vulnerability count series
    let vulnSeries = [];
    if (series && series.vulnerability_series && series.vulnerability_series.length === labels.length) {
        vulnSeries = series.vulnerability_series;
    } else if (series && (series.critical_series || series.high_series)) {
        const c = series.critical_series || [];
        const h = series.high_series || [];
        const m = series.medium_series || [];
        vulnSeries = labels.map((_, i) => (c[i] || 0) + (h[i] || 0) + (m[i] || 0) + (series.current_low || 0));
    } else {
        // Fallback default audit trajectory
        vulnSeries = [28, 24, 19, 15, 11, 7];
    }

    const width = 880;
    const height = 230;
    const padL = 50;
    const padR = 35;
    const padT = 25;
    const padB = 30;
    const plotW = width - padL - padR;
    const plotH = height - padT - padB;

    const n = labels.length;
    const maxVuln = Math.max(5, Math.ceil(Math.max(...vulnSeries) * 1.25));
    const getX = (i) => padL + (i / (n - 1)) * plotW;
    const getY = (val) => padT + plotH - (val / maxVuln) * plotH;

    let gridLinesSvg = "";
    for (let g = 0; g <= 4; g++) {
        const yPos = padT + (g / 4) * plotH;
        const countVal = Math.round(maxVuln * (1 - g / 4));
        gridLinesSvg += `
            <line x1="${padL}" y1="${yPos}" x2="${width - padR}" y2="${yPos}" stroke="rgba(255,255,255,0.06)" stroke-dasharray="3,3" />
            <text x="${padL - 10}" y="${yPos + 4}" fill="#64748b" font-size="11" text-anchor="end" font-family="var(--font-mono)">${countVal}</text>
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

    const pts = vulnSeries.map((v, i) => `${getX(i)},${getY(v)}`);
    const areaPts = `${getX(0)},${padT + plotH} ` + pts.join(" ") + ` ${getX(n - 1)},${padT + plotH}`;

    // Temperature stops along the timeline
    let tempLineStops = "";
    let tempAreaStops = "";
    vulnSeries.forEach((v, i) => {
        const pct = Math.round((i / (n - 1)) * 100);
        const info = getVulnerabilityTemperature(v, maxVuln);
        tempLineStops += `<stop offset="${pct}%" stop-color="${info.color}"/>`;
        tempAreaStops += `<stop offset="${pct}%" stop-color="${info.color}" stop-opacity="0.32"/>`;
    });

    let nodesSvg = "";
    vulnSeries.forEach((v, i) => {
        const cx = getX(i);
        const cy = getY(v);
        const info = getVulnerabilityTemperature(v, maxVuln);
        nodesSvg += `
            <circle cx="${cx}" cy="${cy}" r="5" fill="${info.color}" stroke="#0f172a" stroke-width="2" style="filter: drop-shadow(0 0 5px ${info.color}); cursor: pointer;">
                <title>${labels[i]}: ${v} Audited Vulnerabilities [${info.label}]</title>
            </circle>
            <text x="${cx}" y="${cy - 9}" fill="${info.lightColor}" font-size="11" font-weight="700" text-anchor="middle" font-family="var(--font-mono)">${v}</text>
        `;
    });

    container.innerHTML = `
        <svg viewBox="0 0 ${width} ${height}" style="width: 100%; height: 100%; overflow: visible;" preserveAspectRatio="none">
            <defs>
                <linearGradient id="auditTempLineGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                    ${tempLineStops}
                </linearGradient>
                <linearGradient id="auditTempAreaGrad" x1="0%" y1="0%" x2="100%" y2="0%">
                    ${tempAreaStops}
                </linearGradient>
                <linearGradient id="auditVerticalFade" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="#ffffff" stop-opacity="1"/>
                    <stop offset="85%" stop-color="#ffffff" stop-opacity="0.3"/>
                    <stop offset="100%" stop-color="#ffffff" stop-opacity="0.0"/>
                </linearGradient>
                <mask id="auditAreaMask">
                    <rect x="0" y="0" width="${width}" height="${height}" fill="url(#auditVerticalFade)" />
                </mask>
                <filter id="glow-audit-temp" x="-20%" y="-20%" width="140%" height="140%">
                    <feDropShadow dx="0" dy="0" stdDeviation="3" flood-color="#f97316" flood-opacity="0.4"/>
                </filter>
            </defs>

            ${gridLinesSvg}
            ${xLabelsSvg}

            <!-- Audited Vulnerabilities Area Gradient with Temperature Spectrum and Vertical Fade -->
            <polygon points="${areaPts}" fill="url(#auditTempAreaGrad)" mask="url(#auditAreaMask)" />

            <!-- Single Audited Vulnerabilities Count Trend Line with Dynamic Temperature Color -->
            <polyline points="${pts.join(" ")}" fill="none" stroke="url(#auditTempLineGrad)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" filter="url(#glow-audit-temp)" />

            ${nodesSvg}
        </svg>
    `;
}

let auditLedgerTypeFilter = "ALL";

function filterAuditLedger() {
    const qEl = document.getElementById("audit-search-input");
    const stdEl = document.getElementById("audit-standard-filter");
    const typeEl = document.getElementById("audit-type-filter");
    auditLedgerSearch = qEl ? qEl.value.trim().toLowerCase() : "";
    auditLedgerFilter = stdEl ? stdEl.value : "ALL";
    auditLedgerTypeFilter = typeEl ? typeEl.value : "ALL";
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
        if (auditLedgerTypeFilter !== "ALL") {
            const fType = (f.scan_type || f.type || '').toLowerCase();
            if (fType !== auditLedgerTypeFilter.toLowerCase()) return false;
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

        const fType = (f.scan_type || f.type || 'sast').toLowerCase();
        let typeBadgeClass = 'badge-medium';
        let typeLabel = fType.toUpperCase();
        if (fType === 'iac') {
            typeBadgeClass = 'badge-high';
            typeLabel = '🏗️ IAC';
        } else if (fType === 'sca') {
            typeBadgeClass = 'badge-high';
            typeLabel = '📦 SCA';
        } else if (fType === 'api') {
            typeBadgeClass = 'badge-medium';
            typeLabel = '🌐 API';
        } else if (fType === 'secret') {
            typeBadgeClass = 'badge-critical';
            typeLabel = '🔑 SECRET';
        } else {
            typeLabel = '🛡️ SAST';
        }
        let typeBadge = `<span class="badge ${typeBadgeClass}">${typeLabel}</span>`;
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

// --- Auto-Configure IDE & Server IP Discovery ---
let currentAutoConfigData = null;

async function openAutoConfigModal() {
    try {
        openModal("modal-auto-config");
        const urlEl = document.getElementById("auto-config-server-url");
        const detailsEl = document.getElementById("auto-config-details");
        const codeEl = document.getElementById("auto-config-code");
        const oneClickBtn = document.getElementById("btn-1click-vscode");

        if (urlEl) urlEl.textContent = "Detecting server IP...";

        const resp = await fetch("/api/system/network-info");
        if (resp.ok) {
            currentAutoConfigData = await resp.json();
            const serverUrl = currentAutoConfigData.client_accessible_url || currentAutoConfigData.server_url;
            if (urlEl) urlEl.textContent = serverUrl;
            if (detailsEl) {
                detailsEl.textContent = `Public IP: ${currentAutoConfigData.public_ip} • LAN IP: ${currentAutoConfigData.lan_ip} • Port: ${currentAutoConfigData.port}`;
            }
            if (oneClickBtn) {
                oneClickBtn.href = currentAutoConfigData.vscode_uri || `vscode://sentinel-security.sentinel-appsec-ide/connect?serverUrl=${encodeURIComponent(serverUrl)}`;
            }
            if (codeEl) {
                codeEl.textContent = JSON.stringify(currentAutoConfigData.vscode_settings, null, 2);
            }
        } else {
            const fallbackUrl = window.location.origin;
            if (urlEl) urlEl.textContent = fallbackUrl;
            if (codeEl) {
                codeEl.textContent = JSON.stringify({ "sentinel.serverUrl": fallbackUrl }, null, 2);
            }
            if (oneClickBtn) {
                oneClickBtn.href = `vscode://sentinel-security.sentinel-appsec-ide/connect?serverUrl=${encodeURIComponent(fallbackUrl)}`;
            }
        }
    } catch (err) {
        console.error("Failed fetching network info:", err);
    }
}

async function applyWorkspaceAutoConfig() {
    try {
        const resp = await fetch("/api/system/auto-configure-workspace", { method: "POST" });
        if (resp.ok) {
            showToast("✅ Auto-configured .sentinel/config.json & .vscode/settings.json with server IP!", "success");
        } else {
            showToast("Failed to write auto-configuration", "error");
        }
    } catch (e) {
        showToast("Error executing auto-configuration", "error");
    }
}

function copyAutoConfigSettings() {
    const codeEl = document.getElementById("auto-config-code");
    if (codeEl && codeEl.textContent) {
        navigator.clipboard.writeText(codeEl.textContent).then(() => {
            showToast("Copied VS Code settings JSON to clipboard!", "success");
        }).catch(() => {
            showToast("Failed to copy to clipboard", "error");
        });
    }
}


// =========================================================================
// ADVANCED CAPABILITIES: BATCH PATCHING, DAST PROBE, DAG & WEBHOOKS
// =========================================================================

// --- 1. Batch Auto-Patch & Coordinated PR Studio ---
function openBatchPatchModal() {
    const checklist = document.getElementById("batch-findings-checklist");
    if (!checklist) return;

    // Filter to open, remediable findings
    const openFindings = (state.findings || []).filter(f => f.status !== "resolved");
    if (openFindings.length === 0) {
        showToast("No unresolved findings available for batch remediation.", "info");
        return;
    }

    checklist.innerHTML = "";
    openFindings.forEach((f, idx) => {
        const item = document.createElement("label");
        item.style.cssText = "display: flex; align-items: flex-start; gap: 8px; font-size: 12px; color: #cbd5e1; cursor: pointer; padding: 6px 8px; border-radius: 4px; background: rgba(255,255,255,0.03);";
        const isChecked = idx < 5 ? "checked" : "";
        const sevColor = f.severity === "CRITICAL" ? "#ef4444" : (f.severity === "HIGH" ? "#f97316" : "#eab308");
        item.innerHTML = `
            <input type="checkbox" class="batch-finding-checkbox" value="${f.id}" ${isChecked} onchange="updateBatchSelectionCount()" style="margin-top: 3px;">
            <div style="flex-grow: 1; min-width: 0;">
                <div style="font-weight: 700; color: #fff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                    <span style="color: ${sevColor}; margin-right: 4px;">●</span>${f.title}
                </div>
                <div style="font-size: 11px; color: var(--text-muted);">${f.file_path || 'unknown'}:${f.line_start || 1} &bull; ${f.cwe_id || 'CWE'}</div>
            </div>
        `;
        checklist.appendChild(item);
    });

    updateBatchSelectionCount();
    document.getElementById("batch-diff-preview").textContent = '# Click "Preview Unified Diff (Dry Run)" to generate multi-file patch diff...';
    document.getElementById("batch-result-alert").style.display = "none";
    openModal("modal-batch-patch");
}

function updateBatchSelectionCount() {
    const checked = document.querySelectorAll(".batch-finding-checkbox:checked");
    const countEl = document.getElementById("batch-selected-count");
    if (countEl) countEl.textContent = checked.length;
}

function selectAllBatchFindings() {
    const checkboxes = document.querySelectorAll(".batch-finding-checkbox");
    const allChecked = Array.from(checkboxes).every(c => c.checked);
    checkboxes.forEach(c => c.checked = !allChecked);
    updateBatchSelectionCount();
}

function getSelectedBatchFindingIds() {
    return Array.from(document.querySelectorAll(".batch-finding-checkbox:checked")).map(c => c.value);
}

async function runBatchPatchDryRun() {
    const fids = getSelectedBatchFindingIds();
    if (fids.length === 0) {
        showToast("Please select at least one finding for batch remediation.", "warning");
        return;
    }

    const previewEl = document.getElementById("batch-diff-preview");
    const filesCountEl = document.getElementById("batch-files-count");
    const alertEl = document.getElementById("batch-result-alert");

    previewEl.textContent = "# Synthesizing AI code diffs across selected files...";
    filesCountEl.textContent = "Synthesizing...";

    try {
        const resp = await fetch("/api/findings/batch-patch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ finding_ids: fids, dry_run: true })
        });
        const data = await resp.json();
        if (resp.ok && data.success) {
            previewEl.textContent = data.unified_diff || "# No diff generated.";
            filesCountEl.textContent = `${(data.files_affected || []).length} Files Affected`;
            alertEl.style.display = "block";
            alertEl.className = "alert alert-info";
            alertEl.textContent = `Dry run successful: ${data.applied_count} patches synthesized cleanly across ${data.files_affected.length} files.`;
        } else {
            previewEl.textContent = `# Error: ${data.detail || 'Failed to simulate batch diff'}`;
            showToast(data.detail || "Batch patch simulation failed", "error");
        }
    } catch (err) {
        previewEl.textContent = `# Error: ${err.message}`;
        showToast("Network error generating diff preview", "error");
    }
}

async function applyBatchPatchNow() {
    const fids = getSelectedBatchFindingIds();
    if (fids.length === 0) {
        showToast("Please select at least one finding to patch.", "warning");
        return;
    }

    const alertEl = document.getElementById("batch-result-alert");
    try {
        const resp = await fetch("/api/findings/batch-patch", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ finding_ids: fids, dry_run: false })
        });
        const data = await resp.json();
        if (resp.ok && data.success) {
            alertEl.style.display = "block";
            alertEl.className = "alert alert-success";
            alertEl.textContent = `✅ Successfully applied ${data.applied_count} patches directly to project files on disk!`;
            showToast(`Applied ${data.applied_count} patches!`, "success");
            await loadFindings();
            await loadDashboardStats();
        } else {
            showToast(data.detail || "Failed to apply batch patches", "error");
        }
    } catch (err) {
        showToast("Error applying batch patches", "error");
    }
}

async function createBatchPRNow() {
    const fids = getSelectedBatchFindingIds();
    if (fids.length === 0) {
        showToast("Please select at least one finding for PR creation.", "warning");
        return;
    }

    try {
        const resp = await fetch("/api/findings/batch-pr", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ finding_ids: fids })
        });
        const data = await resp.json();
        if (resp.ok && data.success) {
            showToast(`🚀 Coordinated Pull Request opened: ${data.pr_branch}`, "success");
            const alertEl = document.getElementById("batch-result-alert");
            alertEl.style.display = "block";
            alertEl.className = "alert alert-success";
            alertEl.innerHTML = `<strong>PR Created:</strong> <a href="${data.pr_url}" target="_blank" style="color: #38bdf8;">${data.pr_branch}</a> (${data.batch_findings_count} vulnerabilities addressed)`;
        } else {
            showToast(data.detail || "Failed to create PR", "error");
        }
    } catch (err) {
        showToast("Error creating coordinated PR", "error");
    }
}


// --- 2. Live DAST & Security Header Probe ---
function openDASTModal() {
    openModal("modal-dast-probe");
}

async function runDASTProbe() {
    const targetUrl = document.getElementById("dast-target-url").value.trim();
    if (!targetUrl) {
        showToast("Please enter a target URL to audit.", "warning");
        return;
    }

    const spinner = document.getElementById("dast-spinner");
    const btnText = document.getElementById("dast-btn-text");
    const resultsBox = document.getElementById("dast-results-box");

    spinner.style.display = "inline-block";
    btnText.textContent = "Auditing...";

    try {
        const resp = await fetch("/api/dast/audit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target_url: targetUrl })
        });
        const data = await resp.json();

        if (resp.ok && data.status === "success") {
            resultsBox.style.display = "block";
            document.getElementById("dast-grade").textContent = data.grade;
            document.getElementById("dast-score").textContent = `Score: ${data.score}/100`;
            document.getElementById("dast-url-display").textContent = data.target_url;

            // Color grade
            const gradeEl = document.getElementById("dast-grade");
            if (data.grade.startsWith("A")) gradeEl.style.color = "#10b981";
            else if (data.grade === "B") gradeEl.style.color = "#38bdf8";
            else if (data.grade === "C") gradeEl.style.color = "#f59e0b";
            else gradeEl.style.color = "#ef4444";

            // Summary pills
            const sumPills = document.getElementById("dast-summary-pills");
            sumPills.innerHTML = `
                <span class="badge" style="background: rgba(239, 68, 68, 0.2); color: #f87171;">Critical: ${data.summary.critical}</span>
                <span class="badge" style="background: rgba(249, 115, 22, 0.2); color: #fb923c;">High: ${data.summary.high}</span>
                <span class="badge" style="background: rgba(234, 179, 8, 0.2); color: #facc15;">Medium: ${data.summary.medium}</span>
                <span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #34d399;">Low: ${data.summary.low}</span>
            `;

            // Findings list
            const findingsList = document.getElementById("dast-findings-list");
            findingsList.innerHTML = "";
            (data.findings || []).forEach(f => {
                const item = document.createElement("div");
                item.style.cssText = "background: rgba(15, 23, 42, 0.6); border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; font-size: 12px;";
                const sevColor = f.severity === "CRITICAL" ? "#ef4444" : (f.severity === "HIGH" ? "#f97316" : "#eab308");
                item.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                        <strong style="color: #fff;"><span style="color: ${sevColor}; margin-right: 6px;">●</span>${f.title}</strong>
                        <span class="badge" style="background: rgba(255,255,255,0.08); color: ${sevColor};">${f.severity}</span>
                    </div>
                    <p style="color: var(--text-secondary); margin: 0 0 6px 0; font-size: 11px;">${f.description}</p>
                    <div style="font-family: var(--font-mono); font-size: 11px; color: #38bdf8; background: rgba(0,0,0,0.3); padding: 4px 8px; border-radius: 4px;">
                        💡 Fix: ${f.remediation}
                    </div>
                `;
                findingsList.appendChild(item);
            });

            showToast(`DAST Audit Complete: Grade ${data.grade} (${data.score}/100)`, "success");
        } else {
            showToast(data.error || "DAST audit failed to connect to URL", "error");
        }
    } catch (err) {
        showToast("Network error executing DAST probe", "error");
    } finally {
        spinner.style.display = "none";
        btnText.textContent = "Audit Endpoint";
    }
}


// --- 3. Interactive SCA Dependency Graph (DAG) ---
async function openDependencyGraphModal() {
    if (!state.activeProjectId) {
        showToast("Please select an active project first.", "warning");
        return;
    }

    try {
        const resp = await fetch(`/api/projects/${state.activeProjectId}/dependencies/graph`);
        if (resp.ok) {
            const data = await resp.json();
            renderDependencyGraph(data);
            openModal("modal-dependency-graph");
        } else {
            showToast("Failed loading dependency graph", "error");
        }
    } catch (e) {
        showToast("Error retrieving dependency topology", "error");
    }
}

function renderDependencyGraph(data) {
    const summary = data.summary || {};
    document.getElementById("dep-stat-total").textContent = summary.total_dependencies || 0;
    document.getElementById("dep-stat-direct").textContent = summary.direct_count || 0;
    document.getElementById("dep-stat-transitive").textContent = summary.transitive_count || 0;
    document.getElementById("dep-stat-vuln").textContent = summary.vulnerable_count || 0;
    document.getElementById("dep-stat-reachable").textContent = summary.reachable_count || 0;

    const container = document.getElementById("dep-graph-container");
    container.innerHTML = "";

    const pkgNodes = (data.nodes || []).filter(n => n.type !== "root");
    pkgNodes.forEach(node => {
        const card = document.createElement("div");
        const isVuln = node.severity && node.severity !== "CLEAN";
        const borderColor = isVuln ? "rgba(239, 68, 68, 0.4)" : "rgba(255, 255, 255, 0.1)";
        const bgGrad = isVuln ? "linear-gradient(135deg, rgba(30, 41, 59, 0.8), rgba(239, 68, 68, 0.08))" : "rgba(15, 23, 42, 0.7)";

        card.style.cssText = `background: ${bgGrad}; border: 1px solid ${borderColor}; border-radius: 8px; padding: 12px; font-size: 12px;`;
        card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <strong style="color: #fff; font-size: 13px;">${node.label}</strong>
                <span class="badge" style="background: rgba(255,255,255,0.06); color: ${node.type === 'direct' ? '#38bdf8' : '#c084fc'};">${node.type}</span>
            </div>
            <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 6px;">
                <span class="badge" style="background: ${isVuln ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)'}; color: ${isVuln ? '#f87171' : '#34d399'};">
                    ${isVuln ? node.severity : 'SAFE'}
                </span>
                ${node.reachable ? '<span class="badge" style="background: rgba(245, 158, 11, 0.2); color: #fbbf24;">⚡ REACHABLE</span>' : ''}
                <span style="font-size: 11px; color: var(--text-muted);">${node.license || 'Unknown'}</span>
            </div>
            ${node.cve_id ? `<div style="font-family: var(--font-mono); font-size: 11px; color: #f87171;">⚠️ ${node.cve_id}</div>` : ''}
        `;
        container.appendChild(card);
    });
}


// --- 4. Webhook Notifications Controller ---
async function loadWebhookConfig() {
    try {
        const resp = await fetch("/api/integrations/webhooks");
        if (resp.ok) {
            const cfg = await resp.json();
            const slackEl = document.getElementById("webhook-slack-url");
            const teamsEl = document.getElementById("webhook-teams-url");
            const discordEl = document.getElementById("webhook-discord-url");
            const genericEl = document.getElementById("webhook-generic-url");
            const secretEl = document.getElementById("webhook-generic-secret");

            if (slackEl && cfg.slack_webhook_url) slackEl.value = cfg.slack_webhook_url;
            if (teamsEl && cfg.teams_webhook_url) teamsEl.value = cfg.teams_webhook_url;
            if (discordEl && cfg.discord_webhook_url) discordEl.value = cfg.discord_webhook_url;
            if (genericEl && cfg.generic_webhook_url) genericEl.value = cfg.generic_webhook_url;
            if (secretEl && cfg.generic_secret) secretEl.value = cfg.generic_secret;

            if (document.getElementById("webhook-notify-scan")) {
                document.getElementById("webhook-notify-scan").checked = cfg.notify_on_scan_completed !== false;
            }
            if (document.getElementById("webhook-notify-critical")) {
                document.getElementById("webhook-notify-critical").checked = cfg.notify_on_critical_finding !== false;
            }
            if (document.getElementById("webhook-notify-cisa")) {
                document.getElementById("webhook-notify-cisa").checked = cfg.notify_on_cisa_kev !== false;
            }
        }
    } catch (e) {}
}

async function saveWebhookConfig(e) {
    e.preventDefault();
    const payload = {
        enabled: true,
        slack_webhook_url: document.getElementById("webhook-slack-url").value,
        teams_webhook_url: document.getElementById("webhook-teams-url").value,
        discord_webhook_url: document.getElementById("webhook-discord-url").value,
        generic_webhook_url: document.getElementById("webhook-generic-url").value,
        generic_secret: document.getElementById("webhook-generic-secret").value,
        notify_on_scan_completed: document.getElementById("webhook-notify-scan").checked,
        notify_on_critical_finding: document.getElementById("webhook-notify-critical").checked,
        notify_on_cisa_kev: document.getElementById("webhook-notify-cisa").checked,
        min_severity: "HIGH"
    };

    try {
        const resp = await fetch("/api/integrations/webhooks", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        if (resp.ok) {
            showToast("Webhook notification settings saved!", "success");
        } else {
            showToast("Failed to save webhook settings", "error");
        }
    } catch (e) {
        showToast("Error saving webhook configuration", "error");
    }
}

async function sendTestWebhookAlert() {
    const slackUrl = document.getElementById("webhook-slack-url").value;
    const teamsUrl = document.getElementById("webhook-teams-url").value;
    const discordUrl = document.getElementById("webhook-discord-url").value;
    const genericUrl = document.getElementById("webhook-generic-url").value;

    let targetType = "slack";
    let targetUrl = slackUrl;
    if (!targetUrl && teamsUrl) { targetType = "teams"; targetUrl = teamsUrl; }
    else if (!targetUrl && discordUrl) { targetType = "discord"; targetUrl = discordUrl; }
    else if (!targetUrl && genericUrl) { targetType = "generic"; targetUrl = genericUrl; }

    if (!targetUrl) {
        showToast("Please enter at least one webhook URL before testing.", "warning");
        return;
    }

    try {
        const resp = await fetch("/api/integrations/webhooks/test", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ webhook_type: targetType, webhook_url: targetUrl })
        });
        const res = await resp.json();
        if (res.success) {
            showToast(`✅ ${res.message}`, "success");
        } else {
            showToast(`Test: ${res.message}`, "info");
        }
    } catch (e) {
        showToast("Error testing webhook alert", "error");
    }
}


// --- 5. Schedules & Threat Intel Controller ---
async function loadSchedules() {
    try {
        const resp = await fetch("/api/schedules");
        if (resp.ok) {
            const schedules = await resp.json();
            const listEl = document.getElementById("schedules-list");
            if (!listEl) return;
            listEl.innerHTML = "";

            schedules.forEach(s => {
                const item = document.createElement("div");
                item.style.cssText = "background: rgba(15, 23, 42, 0.7); border: 1px solid #1e293b; border-radius: 6px; padding: 8px 12px; font-size: 12px; display: flex; justify-content: space-between; align-items: center;";
                item.innerHTML = `
                    <div>
                        <strong style="color: #fff;">${s.name}</strong>
                        <div style="font-size: 11px; color: var(--text-muted);">Every ${s.interval_hours}h &bull; Last: ${s.last_run_date || 'Pending'}</div>
                    </div>
                    <span class="badge" style="background: rgba(16, 185, 129, 0.15); color: #10b981;">ACTIVE</span>
                `;
                listEl.appendChild(item);
            });
        }

        const statResp = await fetch("/api/threat-intel/status");
        if (statResp.ok) {
            const stat = await statResp.json();
            const countEl = document.getElementById("threat-intel-count");
            const epssEl = document.getElementById("threat-epss-version");
            if (countEl && stat.cisa_kev_count) countEl.textContent = `${stat.cisa_kev_count} CISA KEV Exploits`;
            if (epssEl && stat.epss_version) epssEl.textContent = `${stat.epss_version} (FIRST.org)`;
        }
    } catch (e) {}
}

async function syncThreatIntelNow() {
    try {
        showToast("Synchronizing CISA KEV & EPSS feeds...", "info");
        const resp = await fetch("/api/threat-intel/sync", { method: "POST" });
        if (resp.ok) {
            const data = await resp.json();
            showToast(`✅ ${data.message}`, "success");
            await loadSchedules();
        } else {
            showToast("Failed to sync threat intelligence", "error");
        }
    } catch (e) {
        showToast("Error executing threat intelligence sync", "error");
    }
}

// ==============================================================================
// 1. ENTERPRISE SBOM & VEX CONTROLLERS
// ==============================================================================
let currentSBOMFormat = 'cyclonedx';
let currentSBOMData = null;

async function openSBOMModal() {
    openModal("modal-sbom-center");
    await switchSBOMFormat(currentSBOMFormat || 'cyclonedx');
}

async function switchSBOMFormat(format) {
    currentSBOMFormat = format;
    const btnCdx = document.getElementById("btn-tab-cyclonedx");
    const btnSpdx = document.getElementById("btn-tab-spdx");
    const btnVex = document.getElementById("btn-tab-openvex");
    const pre = document.getElementById("sbom-json-preview");

    if (btnCdx) {
        btnCdx.className = `btn btn-secondary btn-sm ${format === 'cyclonedx' ? 'active' : ''}`;
        btnCdx.style.background = format === 'cyclonedx' ? 'rgba(16, 185, 129, 0.25)' : '';
        btnCdx.style.color = format === 'cyclonedx' ? '#34d399' : '';
    }
    if (btnSpdx) {
        btnSpdx.className = `btn btn-secondary btn-sm ${format === 'spdx' ? 'active' : ''}`;
        btnSpdx.style.background = format === 'spdx' ? 'rgba(56, 189, 248, 0.25)' : '';
        btnSpdx.style.color = format === 'spdx' ? '#38bdf8' : '';
    }
    if (btnVex) {
        btnVex.className = `btn btn-secondary btn-sm ${format === 'openvex' ? 'active' : ''}`;
        btnVex.style.background = format === 'openvex' ? 'rgba(245, 158, 11, 0.25)' : '';
        btnVex.style.color = format === 'openvex' ? '#fde047' : '';
    }

    if (pre) pre.textContent = `Fetching ${format.toUpperCase()} document from attestation engine...`;

    try {
        let endpoint = `/api/sbom/${format === 'openvex' ? 'vex' : format}`;
        if (state.activeProjectId) {
            endpoint += `?project_id=${state.activeProjectId}`;
        }
        const resp = await fetch(endpoint);
        if (resp.ok) {
            currentSBOMData = await resp.json();
            if (pre) pre.textContent = JSON.stringify(currentSBOMData, null, 2);

            // Update stats
            const statComp = document.getElementById("sbom-stat-components");
            const statVex = document.getElementById("sbom-stat-vex-flaws");
            if (format === 'cyclonedx') {
                const count = (currentSBOMData.components || []).length;
                const vulns = (currentSBOMData.vulnerabilities || []).length;
                if (statComp) statComp.textContent = `${count} Packages`;
                if (statVex) statVex.textContent = `${vulns} VEX Records`;
            } else if (format === 'spdx') {
                const count = (currentSBOMData.packages || []).length;
                if (statComp) statComp.textContent = `${count} Packages`;
                if (statVex) statVex.textContent = `ExternalRefs Linked`;
            } else if (format === 'openvex') {
                const count = (currentSBOMData.statements || []).length;
                if (statComp) statComp.textContent = `VEX Attestation`;
                if (statVex) statVex.textContent = `${count} Statements`;
            }
        } else {
            if (pre) pre.textContent = "Error fetching SBOM document.";
        }
    } catch (e) {
        if (pre) pre.textContent = `Network error: ${e.message}`;
    }
}

function copySBOMJson() {
    if (!currentSBOMData) return;
    navigator.clipboard.writeText(JSON.stringify(currentSBOMData, null, 2)).then(() => {
        showToast("SBOM JSON copied to clipboard!", "success");
    });
}

function downloadCurrentSBOM() {
    if (!currentSBOMData) return;
    const str = JSON.stringify(currentSBOMData, null, 2);
    const blob = new Blob([str], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${currentSBOMFormat}-sbom.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(`Downloaded ${currentSBOMFormat}-sbom.json`, "success");
}

// ==============================================================================
// 2. RUNTIME APPLICATION SELF-PROTECTION (RASP) CONTROLLERS
// ==============================================================================
async function openRASPModal() {
    openModal("modal-rasp-defense");
    await refreshRASPTelemetry();
}

async function refreshRASPTelemetry() {
    try {
        const resp = await fetch("/api/rasp/telemetry");
        if (!resp.ok) return;
        const data = await resp.json();

        // Update badge and buttons
        const badge = document.getElementById("rasp-mode-badge");
        const btnBlock = document.getElementById("btn-rasp-block");
        const btnMonitor = document.getElementById("btn-rasp-monitor");

        if (badge) {
            badge.textContent = data.mode === "BLOCK" ? "ACTIVE BLOCK (403 Forbidden)" : "PASSIVE MONITOR (Log Only)";
            badge.style.background = data.mode === "BLOCK" ? "rgba(239, 68, 68, 0.25)" : "rgba(245, 158, 11, 0.25)";
            badge.style.color = data.mode === "BLOCK" ? "#fca5a5" : "#fde047";
            badge.style.borderColor = data.mode === "BLOCK" ? "rgba(239, 68, 68, 0.5)" : "rgba(245, 158, 11, 0.5)";
        }
        if (btnBlock) {
            btnBlock.style.background = data.mode === "BLOCK" ? "rgba(239, 68, 68, 0.25)" : "";
            btnBlock.style.color = data.mode === "BLOCK" ? "#f87171" : "";
        }
        if (btnMonitor) {
            btnMonitor.style.background = data.mode === "MONITOR" ? "rgba(245, 158, 11, 0.25)" : "";
            btnMonitor.style.color = data.mode === "MONITOR" ? "#fbbf24" : "";
        }

        // Update counters
        const statTotal = document.getElementById("rasp-stat-total");
        const statBlocked = document.getElementById("rasp-stat-blocked");
        const statMonitored = document.getElementById("rasp-stat-monitored");
        if (statTotal) statTotal.textContent = data.total_incidents || 0;
        if (statBlocked) statBlocked.textContent = data.blocked_count || 0;
        if (statMonitored) statMonitored.textContent = data.monitored_count || 0;

        // Render incident feed
        const tbody = document.getElementById("rasp-incidents-tbody");
        if (tbody) {
            tbody.innerHTML = "";
            (data.recent_incidents || []).forEach(inc => {
                const tr = document.createElement("tr");
                const timeShort = (inc.timestamp || "").split("T")[1]?.slice(0, 8) || "recent";
                const isBlocked = inc.action === "BLOCKED";
                tr.innerHTML = `
                    <td style="color: var(--text-muted); font-family: var(--font-mono);">${timeShort}</td>
                    <td style="font-family: var(--font-mono); color: #38bdf8;">${escapeHtml(inc.attacker_ip || "127.0.0.1")}</td>
                    <td><strong style="color: #fff;">${escapeHtml(inc.vector || "")}</strong></td>
                    <td style="font-family: var(--font-mono); color: #fca5a5; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(inc.payload)}">${escapeHtml(inc.payload)}</td>
                    <td><span class="badge badge-${(inc.severity || 'high').toLowerCase()}">${inc.severity}</span></td>
                    <td>
                        <span class="badge" style="background: ${isBlocked ? 'rgba(239, 68, 68, 0.25)' : 'rgba(245, 158, 11, 0.25)'}; color: ${isBlocked ? '#fca5a5' : '#fde047'}; border: 1px solid ${isBlocked ? 'rgba(239, 68, 68, 0.4)' : 'rgba(245, 158, 11, 0.4)'};">
                            ${isBlocked ? '🛡️ BLOCKED (403)' : '👁️ MONITORED (200)'}
                        </span>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        console.error("Error refreshing RASP telemetry:", e);
    }
}

async function setRASPMode(mode) {
    try {
        const resp = await fetch("/api/rasp/mode", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ mode })
        });
        if (resp.ok) {
            showToast(`RASP mode toggled to: ${mode}`, "success");
            await refreshRASPTelemetry();
        }
    } catch (e) {
        showToast("Error updating RASP mode", "error");
    }
}

async function simulateRASPAttack(vector) {
    try {
        showToast(`Firing simulated ${vector} payload...`, "info");
        const resp = await fetch("/api/rasp/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ vector })
        });
        if (resp.ok) {
            const data = await resp.json();
            const sim = data.simulation;
            if (sim.blocked) {
                showToast(`🛡️ Exploit INTERCEPTED & BLOCKED: ${vector} (HTTP 403 Forbidden)`, "success");
            } else {
                showToast(`⚠️ Exploit DETECTED in MONITOR mode: ${vector} (HTTP 200)`, "warning");
            }
            await refreshRASPTelemetry();
        }
    } catch (e) {
        showToast("Error simulating attack payload", "error");
    }
}

// ==============================================================================
// 3. INTERACTIVE CUSTOM RULE STUDIO & LIVE SANDBOX
// ==============================================================================
function openRuleBuilderModal() {
    renderRuleProjectSelectors();
    const builderSel = document.getElementById("builder-rule-project");
    if (builderSel && state.activeProjectId) {
        builderSel.value = state.activeProjectId;
    }
    openModal("modal-rule-builder");
}

async function testRuleInSandbox() {
    const regex = document.getElementById("builder-rule-regex")?.value;
    const snippet = document.getElementById("builder-sandbox-snippet")?.value;
    const lang = document.getElementById("builder-rule-language")?.value || "python";

    const summaryEl = document.getElementById("sandbox-match-summary");
    const listEl = document.getElementById("sandbox-matches-list");
    const latencyBadge = document.getElementById("sandbox-latency-badge");

    if (!regex || !snippet) {
        showToast("Please provide both a regex pattern and sample code snippet.", "warning");
        return;
    }

    try {
        if (summaryEl) summaryEl.textContent = "Compiling pattern and evaluating AST sandbox...";
        const resp = await fetch("/api/rules/test-sandbox", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ regex, test_snippet: snippet, language: lang })
        });
        if (resp.ok) {
            const data = await resp.json();
            if (latencyBadge) latencyBadge.textContent = `${data.execution_time_ms} ms`;

            if (!data.valid) {
                if (summaryEl) {
                    summaryEl.innerHTML = `<span style="color: #ef4444;">❌ ${escapeHtml(data.error)}</span>`;
                }
                if (listEl) listEl.innerHTML = "";
                return;
            }

            if (data.match_count > 0) {
                if (summaryEl) {
                    summaryEl.innerHTML = `<span style="color: #10b981;">✔ Success: Found ${data.match_count} match(es) in ${data.execution_time_ms}ms!</span>`;
                }
                if (listEl) {
                    listEl.innerHTML = data.matches.map(m => `
                        <div style="padding: 4px 8px; margin-bottom: 4px; background: rgba(239, 68, 68, 0.15); border-left: 3px solid #ef4444; border-radius: 3px;">
                            Line ${m.line}: Matched <strong style="color: #fca5a5;">"${escapeHtml(m.matched_text)}"</strong>
                            <div style="color: #94a3b8; font-size: 10px; margin-top: 2px;">Snippet: <code>${escapeHtml(m.line_snippet)}</code></div>
                        </div>
                    `).join("");
                }
            } else {
                if (summaryEl) {
                    summaryEl.innerHTML = `<span style="color: #94a3b8;">No matches found. Pattern evaluated cleanly with zero triggers.</span>`;
                }
                if (listEl) listEl.innerHTML = "";
            }
        }
    } catch (e) {
        if (summaryEl) summaryEl.textContent = `Evaluation error: ${e.message}`;
    }
}

async function saveCustomRuleFromBuilder() {
    const name = document.getElementById("builder-rule-name")?.value;
    const severity = document.getElementById("builder-rule-severity")?.value || "HIGH";
    const language = document.getElementById("builder-rule-language")?.value || "python";
    const cwe = document.getElementById("builder-rule-cwe")?.value || "CWE-89";
    const owasp = document.getElementById("builder-rule-owasp")?.value || "OWASP:A01:2021";
    const regex = document.getElementById("builder-rule-regex")?.value;
    const remediation = document.getElementById("builder-rule-remediation")?.value || "Review and patch.";
    const targetProjectId = document.getElementById("builder-rule-project")?.value || "";

    if (!name || !regex) {
        showToast("Please provide Rule Title and Regex Pattern", "warning");
        return;
    }

    try {
        const resp = await fetch("/api/rules/custom-builder", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                name,
                type: "sast",
                severity,
                languages: [language],
                cwe,
                owasp,
                standards: [owasp, "ISO-27001:A.8.28"],
                regex,
                description: `Custom inspection rule: ${name}`,
                remediation,
                project_id: targetProjectId || null
            })
        });
        if (resp.ok) {
            const data = await resp.json();
            const projObj = (state.projects || []).find(p => p.id === targetProjectId);
            const scopeNote = projObj ? `for project '${projObj.name}'` : "globally across all projects";
            showToast(`🚀 Rule '${name}' activated ${scopeNote}!`, "success");
            closeModal("modal-rule-builder");
            if (typeof loadCustomRules === 'function') await loadCustomRules();
        } else {
            const err = await resp.json();
            showToast(err.detail || "Error saving custom rule", "error");
        }
    } catch (e) {
        showToast(`Save failed: ${e.message}`, "error");
    }
}

// ==============================================================================
// 4. TWO-WAY JIRA & LINEAR TRACKER CONTROLLERS
// ==============================================================================
async function openTrackersModal() {
    openModal("modal-issue-trackers");
    const resultBox = document.getElementById("tracker-sync-result");
    if (resultBox) resultBox.style.display = "none";
}

async function runTrackerSync() {
    const btn = document.getElementById("btn-sync-trackers");
    const resultBox = document.getElementById("tracker-sync-result");
    if (btn) btn.disabled = true;

    try {
        showToast("Synchronizing with Jira Cloud & Linear...", "info");
        const resp = await fetch("/api/trackers/sync", { method: "POST" });
        if (resp.ok) {
            const data = await resp.json();
            if (resultBox) {
                resultBox.style.display = "block";
                resultBox.innerHTML = `
                    <strong>✔ Two-Way Reconciliation Completed:</strong><br/>
                    • Synced issues: <strong>${data.synced_count}</strong><br/>
                    • Jira/Linear tickets transitioned to Done: <strong>${data.tickets_closed_in_tracker}</strong><br/>
                    • Findings resolved from external tracker: <strong>${data.findings_resolved_from_tracker}</strong>
                `;
            }
            showToast("Two-way issue tracker sync completed successfully!", "success");
            if (typeof loadFindings === 'function') await loadFindings();
        } else {
            showToast("Failed to sync issue trackers", "error");
        }
    } catch (e) {
        showToast(`Sync error: ${e.message}`, "error");
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function exportFindingToTracker(findingId, provider) {
    try {
        const id = findingId || state.activeFinding?.id;
        if (!id) {
            showToast("Please select a finding first", "warning");
            return;
        }
        showToast(`Exporting finding to ${provider.toUpperCase()}...`, "info");
        const resp = await fetch("/api/trackers/create-ticket", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ finding_id: id, provider })
        });
        if (resp.ok) {
            const data = await resp.json();
            showToast(`🎫 Created ${data.ticket.ticket_id} in ${provider.toUpperCase()}`, "success");
            const ticketPill = document.getElementById("detail-ticket-status-pill");
            if (ticketPill) {
                ticketPill.textContent = `${provider.toUpperCase()} #${data.ticket.ticket_id} (${data.ticket.status})`;
                ticketPill.style.background = provider === "jira" ? "rgba(59, 130, 246, 0.2)" : "rgba(168, 85, 247, 0.2)";
                ticketPill.style.color = provider === "jira" ? "#93c5fd" : "#c084fc";
            }
            if (typeof loadFindings === 'function') await loadFindings();
        } else {
            const err = await resp.json().catch(() => ({}));
            showToast(`Failed to create tracker ticket: ${err.detail || 'Error'}`, "error");
        }
    } catch (e) {
        showToast(`Export error: ${e.message}`, "error");
    }
}

// ==========================================
// 1. AI Threat Modeling & Attack Surface (STRIDE)
// ==========================================
let activeThreatModelData = null;

async function loadThreatModelData() {
    try {
        const projId = state.activeProjectId || "";
        const url = projId ? `/api/threat-model?project_id=${encodeURIComponent(projId)}` : "/api/threat-model";
        const resp = await fetch(url);
        if (resp.ok) {
            const data = await resp.json();
            activeThreatModelData = data;
            renderThreatModel(data);
        }
    } catch (e) {
        console.error("Failed to load Threat Model data:", e);
    }
}

async function refreshThreatModel() {
    try {
        const btn = document.getElementById("btn-refresh-threat-model");
        if (btn) btn.disabled = true;
        showToast("Re-analyzing repository architectural attack surface...", "info");
        const projId = state.activeProjectId || "";
        const resp = await fetch("/api/threat-model/generate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ project_id: projId })
        });
        if (resp.ok) {
            const data = await resp.json();
            activeThreatModelData = data;
            renderThreatModel(data);
            showToast(`✅ STRIDE Threat Model refreshed (${data.stride_summary?.total_threats || 0} threats mapped)`, "success");
        }
    } catch (e) {
        showToast(`Threat model error: ${e.message}`, "error");
    } finally {
        const btn = document.getElementById("btn-refresh-threat-model");
        if (btn) btn.disabled = false;
    }
}

function renderThreatModel(data) {
    if (!data) return;
    const summary = data.stride_summary || {};
    const totalEl = document.getElementById("tm-total-threats");
    const dreadEl = document.getElementById("tm-avg-dread");
    const hazardEl = document.getElementById("tm-highest-hazard");
    const tbEl = document.getElementById("tm-trust-boundaries");

    if (totalEl) totalEl.textContent = summary.total_threats || 0;
    if (dreadEl) dreadEl.textContent = summary.average_dread_score || "0.0";
    if (hazardEl) {
        const catMap = { "S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Info Disclosure", "D": "DoS", "E": "Privilege Elevation" };
        hazardEl.textContent = catMap[summary.highest_risk_category] || summary.highest_risk_category || "None";
    }
    if (tbEl) tbEl.textContent = data.data_flow_diagram?.trust_boundaries?.length || 2;

    // Render Data Flow Diagram Nodes
    const dfdContainer = document.getElementById("tm-dfd-container");
    if (dfdContainer && data.components) {
        dfdContainer.innerHTML = data.components.map((comp, idx) => {
            const isStore = comp.type === "data_store";
            const isExt = comp.type === "external_interactor";
            const borderCol = isStore ? "#10b981" : isExt ? "#ec4899" : "#38bdf8";
            const bgCol = isStore ? "rgba(16, 185, 129, 0.12)" : isExt ? "rgba(236, 72, 153, 0.12)" : "rgba(56, 189, 248, 0.12)";
            return `
                <div style="background: ${bgCol}; border: 1px solid ${borderCol}; border-radius: 10px; padding: 14px 18px; min-width: 170px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.3);">
                    <div style="font-size: 10px; text-transform: uppercase; color: ${borderCol}; font-weight: 700; margin-bottom: 2px;">${comp.trust_zone}</div>
                    <div style="font-size: 13px; font-weight: 700; color: #fff; margin-bottom: 4px;">${comp.name}</div>
                    <div style="font-size: 11px; color: var(--text-secondary); max-width: 190px;">${comp.description || ''}</div>
                </div>
                ${idx < data.components.length - 1 ? '<div style="color: #64748b; font-size: 18px;">➔</div>' : ''}
            `;
        }).join("");
    }

    // Render Threats Table
    renderSTRIDETableRows(data.threats || []);
}

function renderSTRIDETableRows(threats) {
    const tbody = document.getElementById("tm-threats-tbody");
    if (!tbody) return;
    if (!threats || threats.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">No STRIDE threats mapped.</td></tr>`;
        return;
    }
    const catColors = { "S": "#f59e0b", "T": "#ef4444", "R": "#8b5cf6", "I": "#ec4899", "D": "#f97316", "E": "#dc2626" };

    tbody.innerHTML = threats.map(t => {
        const col = catColors[t.stride_code] || "#38bdf8";
        return `
            <tr>
                <td><span class="badge" style="background: ${col}25; color: ${col}; border: 1px solid ${col}50; font-weight: 700;">${t.category} (${t.stride_code})</span></td>
                <td>
                    <div style="font-weight: 600; color: #fff;">${t.title}</div>
                    <div style="font-size: 11px; color: var(--text-muted); font-family: monospace;">Target: ${t.target_component}</div>
                </td>
                <td>
                    <span style="font-weight: 700; color: ${t.dread_score >= 8.0 ? '#ef4444' : '#f59e0b'};">${t.dread_score} / 10</span>
                </td>
                <td style="font-size: 12px; color: var(--text-secondary); max-width: 260px;">${t.scenario}</td>
                <td style="font-size: 12px; color: #93c5fd; max-width: 260px;">${t.mitigation}</td>
            </tr>
        `;
    }).join("");
}

function filterSTRIDETable(cat) {
    if (!activeThreatModelData || !activeThreatModelData.threats) return;
    if (cat === "all") {
        renderSTRIDETableRows(activeThreatModelData.threats);
    } else {
        const filtered = activeThreatModelData.threats.filter(t => t.stride_code === cat);
        renderSTRIDETableRows(filtered);
    }
}

function exportThreatModelReport() {
    if (!activeThreatModelData) {
        showToast("Generate threat model first", "warning");
        return;
    }
    const blob = new Blob([JSON.stringify(activeThreatModelData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel-threat-model-stride-${Date.now()}.json`;
    a.click();
    showToast("Exported STRIDE Threat Model JSON report", "success");
}

// ==========================================
// 2. Cloud Vault & Automated Secret Rotation
// ==========================================
function openVaultModal() {
    loadVaultStatus();
    openModal("modal-vault-manager");
}

async function loadVaultStatus() {
    try {
        const resp = await fetch("/api/vault/status");
        if (resp.ok) {
            const data = await resp.json();
            const tbody = document.getElementById("vault-ledger-tbody");
            if (tbody && data.recent_rotations) {
                if (data.recent_rotations.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 12px;">No secrets rotated yet.</td></tr>`;
                } else {
                    tbody.innerHTML = data.recent_rotations.map(r => `
                        <tr>
                            <td><code>${r.rotation_id}</code></td>
                            <td><span class="badge" style="background: rgba(245, 158, 11, 0.2); color: #fbbf24;">${r.provider}</span></td>
                            <td><code>${r.variable_name}</code></td>
                            <td style="font-size: 11px; color: var(--text-muted); font-family: monospace;">${r.vault_uri}</td>
                            <td><span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #34d399;">${r.status}</span></td>
                        </tr>
                    `).join("");
                }
            }
        }
    } catch (e) {
        console.error("Vault status error:", e);
    }
}

async function executeVaultRotation() {
    const provider = document.getElementById("vault-provider-select")?.value || "hashicorp_vault";
    const manualId = document.getElementById("vault-rotate-finding-id")?.value?.trim();
    const findingId = manualId || state.activeFinding?.id;

    if (!findingId) {
        showToast("Select or input a secret finding ID to rotate", "warning");
        return;
    }

    try {
        const btn = document.getElementById("btn-exec-vault-rotate");
        if (btn) btn.disabled = true;
        showToast(`Rotating credential into ${provider}...`, "info");

        const resp = await fetch("/api/vault/rotate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ finding_id: findingId, provider })
        });
        if (resp.ok) {
            const data = await resp.json();
            showToast(`✅ Secret rotated into ${provider}! (${data.rotation?.vault_uri})`, "success");
            const diffBox = document.getElementById("vault-diff-container");
            const diffPre = document.getElementById("vault-diff-preview");
            if (diffBox && diffPre) {
                diffBox.style.display = "block";
                diffPre.textContent = data.secure_code_diff || data.retrieval_code;
            }
            await loadVaultStatus();
            if (typeof loadFindings === 'function') await loadFindings();
        } else {
            const err = await resp.json().catch(() => ({}));
            showToast(`Rotation failed: ${err.detail || 'Error'}`, "error");
        }
    } catch (e) {
        showToast(`Vault error: ${e.message}`, "error");
    } finally {
        const btn = document.getElementById("btn-exec-vault-rotate");
        if (btn) btn.disabled = false;
    }
}

function rotateActiveFindingToVault() {
    if (!state.activeFinding) return;
    openVaultModal();
    const idInput = document.getElementById("vault-rotate-finding-id");
    if (idInput) idInput.value = state.activeFinding.id;
}

// ==========================================
// 3. Container Image & Base OS Scanner
// ==========================================
function openContainerScannerModal() {
    openModal("modal-container-scanner");
}

function loadSampleVulnerableDockerfile() {
    const input = document.getElementById("container-dockerfile-input");
    if (input) {
        input.value = "FROM alpine:3.14\nRUN apk add --no-cache curl openssl zlib busybox\nUSER root\nENTRYPOINT [\"curl\"]";
    }
}

async function runContainerScan() {
    const input = document.getElementById("container-dockerfile-input");
    const content = input ? input.value : "";
    try {
        const btn = document.getElementById("btn-run-container-scan");
        if (btn) btn.disabled = true;
        showToast("Scanning container layers & Base OS CVE database...", "info");

        const resp = await fetch("/api/container-scan/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ dockerfile_content: content, project_id: state.activeProjectId })
        });
        if (resp.ok) {
            const data = await resp.json();
            showToast(`🐳 Container scan complete: ${data.total_vulnerabilities} flaws detected`, "success");
            const resBox = document.getElementById("container-results-box");
            if (resBox) resBox.style.display = "block";

            const baseImgEl = document.getElementById("cnt-base-images");
            const rootEl = document.getElementById("cnt-non-root-status");
            const totalEl = document.getElementById("cnt-total-vulns");

            if (baseImgEl) baseImgEl.textContent = (data.base_images_detected || []).join(", ") || "Custom";
            if (rootEl) {
                rootEl.textContent = data.non_root_enforced ? "YES (Non-Root Enforced)" : "NO (Root Execution)";
                rootEl.style.color = data.non_root_enforced ? "#10b981" : "#ef4444";
            }
            if (totalEl) totalEl.textContent = data.total_vulnerabilities || 0;

            const tbody = document.getElementById("cnt-findings-tbody");
            if (tbody) {
                const combined = [...(data.layer_findings || []), ...(data.os_package_cves || [])];
                if (combined.length === 0) {
                    tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: #10b981; padding: 16px;">Clean container configuration. No OS flaws detected.</td></tr>`;
                } else {
                    tbody.innerHTML = combined.map(item => `
                        <tr>
                            <td><strong>${item.cve || item.id}</strong></td>
                            <td><span class="badge" style="background: ${item.severity === 'CRITICAL' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)'}; color: ${item.severity === 'CRITICAL' ? '#ef4444' : '#f59e0b'};">${item.severity}</span></td>
                            <td><code>${item.package || item.snippet || 'Dockerfile'}</code></td>
                            <td style="font-size: 12px; color: var(--text-secondary); max-width: 320px;">${item.remediation || item.description}</td>
                        </tr>
                    `).join("");
                }
            }
        }
    } catch (e) {
        showToast(`Container scan error: ${e.message}`, "error");
    } finally {
        const btn = document.getElementById("btn-run-container-scan");
        if (btn) btn.disabled = false;
    }
}

// ==========================================
// 4. Policy-as-Code & Quality Gate Studio
// ==========================================
let activePolicyData = null;

async function loadPolicyStudioData() {
    try {
        const resp = await fetch("/api/policy-studio/rules");
        if (resp.ok) {
            const data = await resp.json();
            activePolicyData = data;
            renderPolicyRules(data);
            runPolicyDryRun();
        }
    } catch (e) {
        console.error("Policy Studio load error:", e);
    }
}

function renderPolicyRules(policy) {
    const list = document.getElementById("policy-rules-list");
    if (!list || !policy.rules) return;

    list.innerHTML = policy.rules.map(r => `
        <div style="padding: 12px 14px; background: rgba(30, 41, 59, 0.4); border: 1px solid var(--border); border-radius: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                <div style="font-weight: 700; color: #fff; font-size: 13px;">${r.name}</div>
                <span class="badge" style="background: ${r.severity_on_breach === 'BLOCK' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)'}; color: ${r.severity_on_breach === 'BLOCK' ? '#ef4444' : '#f59e0b'}; font-size: 10px;">${r.severity_on_breach}</span>
            </div>
            <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 6px;">${r.description}</div>
            <div style="font-size: 12px; font-family: monospace; color: #38bdf8;">
                Criteria: <code>${r.field} ${r.operator} ${r.threshold}</code>
            </div>
        </div>
    `).join("");
}

async function savePolicyRules() {
    if (!activePolicyData) return;
    try {
        const btn = document.getElementById("btn-save-policy");
        if (btn) btn.disabled = true;
        const resp = await fetch("/api/policy-studio/rules", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                policy_name: activePolicyData.policy_name,
                rules: activePolicyData.rules,
                description: activePolicyData.description
            })
        });
        if (resp.ok) {
            showToast("✅ Policy-as-Code gate rules successfully persisted", "success");
        }
    } catch (e) {
        showToast(`Save error: ${e.message}`, "error");
    } finally {
        const btn = document.getElementById("btn-save-policy");
        if (btn) btn.disabled = false;
    }
}

async function runPolicyDryRun() {
    const crit = parseInt(document.getElementById("sim-critical-count")?.value || "0", 10);
    const high = parseInt(document.getElementById("sim-high-count")?.value || "0", 10);
    const kev = parseInt(document.getElementById("sim-cisa-kev")?.value || "0", 10);
    const sec = parseInt(document.getElementById("sim-secrets-count")?.value || "0", 10);
    const epss = parseFloat(document.getElementById("sim-max-epss")?.value || "0.0");

    const metrics = {
        critical_count: crit,
        high_count: high,
        cisa_kev_count: kev,
        secrets_count: sec,
        max_epss_score: epss
    };

    try {
        const resp = await fetch("/api/policy-studio/dry-run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ metrics })
        });
        if (resp.ok) {
            const data = await resp.json();
            const verdictTitle = document.getElementById("sim-verdict-title");
            const verdictDetail = document.getElementById("sim-verdict-detail");
            const verdictPill = document.getElementById("sim-verdict-pill");
            const verdictBox = document.getElementById("sim-verdict-box");

            if (verdictTitle) verdictTitle.textContent = `QUALITY GATE ${data.verdict}`;
            if (verdictDetail) {
                verdictDetail.textContent = data.can_merge
                    ? `All gate requirements met (${data.rules_passed_count}/${data.rules_evaluated_count} passed). PR is safe to merge.`
                    : `Quality gate breached (${data.rules_failed_count} violations). Pull request merge is blocked.`;
            }
            if (verdictPill) {
                verdictPill.textContent = data.verdict;
                verdictPill.style.background = data.can_merge ? "rgba(16, 185, 129, 0.25)" : "rgba(239, 68, 68, 0.25)";
                verdictPill.style.color = data.can_merge ? "#34d399" : "#ef4444";
            }
            if (verdictBox) {
                verdictBox.style.background = data.can_merge ? "rgba(16, 185, 129, 0.12)" : "rgba(239, 68, 68, 0.12)";
                verdictBox.style.borderColor = data.can_merge ? "rgba(16, 185, 129, 0.3)" : "rgba(239, 68, 68, 0.3)";
            }
        }
    } catch (e) {
        console.error("Policy dry run error:", e);
    }
}

async function populateCurrentProjectMetrics() {
    try {
        const projId = state.activeProjectId || "";
        const url = projId ? `/api/policy-studio/dry-run?project_id=${encodeURIComponent(projId)}` : "/api/policy-studio/dry-run";
        const resp = await fetch("/api/policy-studio/dry-run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ project_id: projId })
        });
        if (resp.ok) {
            const data = await resp.json();
            const m = data.metrics_evaluated || {};
            const cEl = document.getElementById("sim-critical-count");
            const hEl = document.getElementById("sim-high-count");
            const kEl = document.getElementById("sim-cisa-kev");
            const sEl = document.getElementById("sim-secrets-count");
            const eEl = document.getElementById("sim-max-epss");

            if (cEl) cEl.value = m.critical_count || 0;
            if (hEl) hEl.value = m.high_count || 0;
            if (kEl) kEl.value = m.cisa_kev_count || 0;
            if (sEl) sEl.value = m.secrets_count || 0;
            if (eEl) eEl.value = m.max_epss_score || 0.0;

            runPolicyDryRun();
            showToast("Loaded actual repository findings into simulator", "info");
        }
    } catch (e) {
        showToast("Could not load repo metrics", "warning");
    }
}


// =========================================================================
// 1. ATTACK PATH & BLAST RADIUS GRAPH CONTROLLER
// =========================================================================
let cachedAttackPaths = null;

async function loadAttackPathData() {
    try {
        const resp = await fetch("/api/attack-paths");
        if (!resp.ok) return;
        const data = await resp.json();
        cachedAttackPaths = data;
        renderAttackPaths(data);
    } catch (e) {
        console.error("Failed to load attack paths:", e);
    }
}

async function refreshAttackPaths() {
    showToast("Recomputing multi-stage kill chains...", "info");
    await loadAttackPathData();
    showToast("Attack paths recomputed successfully", "success");
}

function renderAttackPaths(data) {
    const sum = data.summary || {};
    const paths = data.attack_paths || [];

    const pEl = document.getElementById("ap-stat-paths");
    const cEl = document.getElementById("ap-stat-critical");
    const kEl = document.getElementById("ap-stat-chokepoints");
    const rEl = document.getElementById("ap-stat-reachability");

    if (pEl) pEl.textContent = sum.total_paths || 0;
    if (cEl) cEl.textContent = sum.critical_paths || 0;
    if (kEl) kEl.textContent = sum.chokepoints_identified || 0;
    if (rEl) rEl.textContent = sum.overall_adversary_reachability || "HIGH";

    const container = document.getElementById("attack-paths-container");
    const select = document.getElementById("ap-sim-select");
    if (!container) return;

    if (select) {
        select.innerHTML = '<option value="">-- Choose a finding to simulate --</option>';
    }

    if (paths.length === 0) {
        container.innerHTML = '<div style="color: var(--text-muted); font-size: 13px;">No multi-stage attack paths detected.</div>';
        return;
    }

    let html = "";
    const chokeMap = new Map();

    paths.forEach((p, idx) => {
        const sevColor = p.severity === "CRITICAL" ? "#f43f5e" : "#f59e0b";
        const choke = p.chokepoint || {};
        if (choke.finding_id && !chokeMap.has(choke.finding_id)) {
            chokeMap.set(choke.finding_id, choke.label || choke.finding_id);
        }

        let stepsHtml = "";
        (p.steps || []).forEach((st, sIdx) => {
            const isLast = sIdx === (p.steps.length - 1);
            const nodeBadgeColor = st.node_type === "ENTRY_POINT" ? "#38bdf8" : st.node_type === "LATERAL_PIVOT" ? "#f59e0b" : "#f43f5e";
            stepsHtml += `
                <div style="flex: 1; min-width: 160px; background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 8px; padding: 10px; position: relative;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                        <span style="font-size: 10px; text-transform: uppercase; color: ${nodeBadgeColor}; font-weight: 700;">Step ${st.stage}: ${st.node_type}</span>
                        <span style="font-size: 10px; color: var(--text-muted);">${st.tactic}</span>
                    </div>
                    <div style="font-size: 12px; font-weight: 700; color: #fff; margin-bottom: 4px;">${st.name}</div>
                    <div style="font-size: 11px; color: var(--text-secondary); line-height: 1.4;">${st.description}</div>
                    ${st.associated_finding ? `<div style="margin-top: 6px; font-size: 10px; color: #38bdf8;">Linked: <code>${st.associated_finding}</code></div>` : ""}
                </div>
                ${!isLast ? `<div style="display: flex; align-items: center; color: var(--text-muted); font-size: 16px; padding: 0 4px;">➔</div>` : ""}
            `;
        });

        html += `
            <div style="background: rgba(15, 23, 42, 0.5); border: 1px solid rgba(255, 255, 255, 0.1); border-left: 4px solid ${sevColor}; border-radius: 10px; padding: 16px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px; flex-wrap: wrap; gap: 8px;">
                    <div>
                        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
                            <span class="badge" style="background: ${sevColor}22; color: ${sevColor}; border: 1px solid ${sevColor}44; font-size: 11px;">${p.severity} (CVSS ${p.risk_score})</span>
                            <span class="badge" style="background: rgba(244, 63, 94, 0.15); color: #f43f5e; font-size: 11px;">BLAST: ${p.blast_radius}</span>
                        </div>
                        <h4 style="font-size: 15px; font-weight: 700; color: #fff; margin: 0 0 2px 0;">${p.name}</h4>
                        <div style="font-size: 11px; color: var(--text-muted);">Threat Actor: ${p.threat_actor}</div>
                    </div>
                    <button class="btn btn-secondary btn-sm" onclick="runAttackPathSimulation('${choke.finding_id}')" style="font-size: 11px;">
                        ✂️ Sever Kill-Chain
                    </button>
                </div>

                <!-- Kill Chain Stages -->
                <div style="display: flex; align-items: stretch; gap: 6px; overflow-x: auto; padding: 6px 0 10px 0; margin-bottom: 10px;">
                    ${stepsHtml}
                </div>

                <div style="background: rgba(56, 189, 248, 0.08); border: 1px dashed rgba(56, 189, 248, 0.3); border-radius: 6px; padding: 8px 12px; display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-size: 12px; color: #38bdf8;"><strong>Chokepoint:</strong> ${choke.label || "Remediate root flaw"}</span>
                    <span style="font-size: 12px; color: #10b981; font-weight: 700;">-${choke.risk_reduction_pct || 80}% Threat Exposure</span>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;

    if (select) {
        chokeMap.forEach((label, fid) => {
            const opt = document.createElement("option");
            opt.value = fid;
            opt.textContent = `${fid} - ${label}`;
            select.appendChild(opt);
        });
    }
}

async function runAttackPathSimulation(findingId) {
    if (!findingId) return;
    try {
        const resp = await fetch("/api/attack-paths/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ finding_id: findingId })
        });
        if (resp.ok) {
            const data = await resp.json();
            const tEl = document.getElementById("ap-sim-title");
            const dEl = document.getElementById("ap-sim-detail");
            const sEl = document.getElementById("ap-sim-select");

            if (tEl) tEl.textContent = `${data.threat_reduction_percentage}% Threat Neutralization`;
            if (dEl) dEl.textContent = data.impact_summary;
            if (sEl) sEl.value = findingId;
            showToast(`Simulated severing ${findingId}: -${data.threat_reduction_percentage}% risk!`, "success");
        }
    } catch (e) {
        showToast("Simulation failed", "error");
    }
}

function exportAttackPathReport() {
    if (!cachedAttackPaths) return;
    const blob = new Blob([JSON.stringify(cachedAttackPaths, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel-attack-paths-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    showToast("Downloaded Attack Path report", "info");
}


// =========================================================================
// 2. REGULATORY COMPLIANCE & CONTROL MATRIX CONTROLLER
// =========================================================================
let cachedComplianceData = null;
let activeComplianceTab = "soc2";

async function populateComplianceProjectSelect() {
    const sel = document.getElementById("compliance-project-select");
    if (!sel) return;
    if (state.projects && state.projects.length > 0) {
        sel.innerHTML = state.projects.map(p => `
            <option value="${p.id}" ${p.id === state.activeProjectId ? 'selected' : ''}>${escapeHtml(p.name)}</option>
        `).join("");
    } else {
        sel.innerHTML = `<option value="">Default Project</option>`;
    }
}

async function onComplianceProjectChange() {
    const sel = document.getElementById("compliance-project-select");
    const pid = sel ? sel.value : null;
    if (pid) state.activeProjectId = pid;
    await loadRegulatoryComplianceData();
}

function downloadExecutiveComplianceDossier() {
    const sel = document.getElementById("compliance-project-select");
    const pid = (sel && sel.value) || state.activeProjectId || (state.projects[0] && state.projects[0].id) || "default";
    showToast("Generating Executive Compliance Crosswalk Dossier...", "info");
    window.open(`/api/projects/${pid}/compliance/export/html`, "_blank");
}

async function loadRegulatoryComplianceData() {
    await populateComplianceProjectSelect();
    const sel = document.getElementById("compliance-project-select");
    const pid = (sel && sel.value) || state.activeProjectId || "";
    try {
        const url = pid ? `/api/projects/${pid}/compliance/matrix` : "/api/compliance/matrix";
        const resp = await fetch(url);
        if (!resp.ok) return;
        const data = await resp.json();
        cachedComplianceData = data;
        renderRegulatoryComplianceUI(data);
    } catch (e) {
        console.error("Failed to load compliance matrix:", e);
    }
}

function refreshComplianceMatrix() {
    showToast("Evaluating compliance against SOC2, PCI-DSS, ISO27001, HIPAA & NIST...", "info");
    loadRegulatoryComplianceData();
}

function renderRegulatoryComplianceUI(data) {
    const meta = data.meta || {};
    const fws = data.frameworks || {};

    const readinessBadge = document.getElementById("compliance-overall-readiness");
    if (readinessBadge) {
        readinessBadge.textContent = `${meta.compliance_readiness_status || "AUDIT READY"} (${meta.overall_compliance_score || 90}%)`;
        readinessBadge.style.color = meta.overall_compliance_score >= 80 ? "#10b981" : "#f59e0b";
    }

    const cardsContainer = document.getElementById("compliance-framework-cards");
    if (cardsContainer) {
        let cardsHtml = "";
        Object.entries(fws).forEach(([key, fw]) => {
            const isSelected = key === activeComplianceTab;
            const scoreColor = fw.compliance_score >= 85 ? "#10b981" : fw.compliance_score >= 65 ? "#f59e0b" : "#f43f5e";
            cardsHtml += `
                <div class="glass-card" style="padding: 14px; cursor: pointer; border: 1px solid ${isSelected ? 'var(--primary)' : 'rgba(255, 255, 255, 0.08)'}; background: ${isSelected ? 'rgba(56, 189, 248, 0.08)' : 'rgba(15, 23, 42, 0.5)'};" onclick="switchComplianceFrameworkTab('${key}')">
                    <div style="font-size: 11px; text-transform: uppercase; color: var(--text-muted);">${fw.name}</div>
                    <div style="font-size: 24px; font-weight: 800; color: ${scoreColor}; margin: 4px 0;">${fw.compliance_score}%</div>
                    <div style="font-size: 11px; color: var(--text-secondary);">${fw.grade}</div>
                </div>
            `;
        });
        cardsContainer.innerHTML = cardsHtml;
    }

    renderComplianceControlsTable();
}

function switchComplianceFrameworkTab(tabKey) {
    activeComplianceTab = tabKey;
    const tabButtons = document.querySelectorAll("#compliance-tab-buttons button");
    tabButtons.forEach(btn => btn.classList.remove("active"));
    const activeBtn = Array.from(tabButtons).find(btn => btn.getAttribute("onclick")?.includes(tabKey));
    if (activeBtn) activeBtn.classList.add("active");

    if (cachedComplianceData) {
        renderRegulatoryComplianceUI(cachedComplianceData);
    }
}

function renderComplianceControlsTable() {
    if (!cachedComplianceData) return;
    const fw = (cachedComplianceData.frameworks || {})[activeComplianceTab];
    if (!fw) return;

    const descEl = document.getElementById("compliance-active-tab-desc");
    if (descEl) descEl.textContent = `Showing automated controls for ${fw.name} (${fw.version})`;

    const tbody = document.getElementById("compliance-controls-tbody");
    if (!tbody) return;

    const controls = fw.controls || [];
    if (controls.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No controls defined.</td></tr>';
        return;
    }

    tbody.innerHTML = controls.map(c => {
        const stColor = c.status === "COMPLIANT" ? "#10b981" : c.status === "PARTIAL_COMPLIANCE" ? "#f59e0b" : "#f43f5e";
        const sampleFindingsText = (c.sample_findings || []).map(f => `<code>${f.id}</code> (${f.title})`).join(", ") || '<span style="color: #10b981;">✔ No active violations</span>';

        return `
            <tr>
                <td style="font-weight: 700; color: #fff;">${c.control_id}</td>
                <td>
                    <div style="font-weight: 600; color: #fff;">${c.title}</div>
                    <div style="font-size: 11px; color: var(--text-secondary);">${c.description}</div>
                </td>
                <td>
                    <span class="badge" style="background: ${stColor}22; color: ${stColor}; border: 1px solid ${stColor}44; font-size: 11px;">
                        ${c.status.replace("_", " ")}
                    </span>
                </td>
                <td style="font-weight: 700; color: ${c.violations_count > 0 ? '#f43f5e' : '#10b981'}; text-align: center;">
                    ${c.violations_count}
                </td>
                <td style="font-size: 11px; color: var(--text-secondary);">
                    ${sampleFindingsText}
                </td>
            </tr>
        `;
    }).join("");
}

async function exportComplianceAuditPackage(framework) {
    try {
        const resp = await fetch("/api/compliance/export", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ framework: framework || "all" })
        });
        if (resp.ok) {
            const data = await resp.json();
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `sentinel-compliance-audit-${framework}-${new Date().toISOString().slice(0, 10)}.json`;
            a.click();
            showToast("Exported Auditor Compliance Package", "success");
        }
    } catch (e) {
        showToast("Compliance export failed", "error");
    }
}


// =========================================================================
// 3. OWASP API SECURITY TOP 10 FUZZER CONTROLLER
// =========================================================================
let cachedFuzzerData = null;

async function loadAPIFuzzerData() {
    try {
        const resp = await fetch("/api/api-fuzzer/results");
        if (!resp.ok) return;
        const data = await resp.json();
        cachedFuzzerData = data;
        renderAPIFuzzerUI(data);
    } catch (e) {
        console.error("Failed to load API fuzzer data:", e);
    }
}

async function runAPIFuzzerScan() {
    const btn = document.getElementById("btn-run-fuzzer");
    const baseUrlInput = document.getElementById("fuzz-base-url");
    const baseUrl = baseUrlInput ? baseUrlInput.value : "http://127.0.0.1:8000";

    if (btn) btn.disabled = true;
    showToast("Dispatching dynamic API fuzzer probes across BOLA, BFLA & SSRF...", "info");

    try {
        const resp = await fetch("/api/api-fuzzer/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ base_url: baseUrl })
        });
        if (resp.ok) {
            const data = await resp.json();
            cachedFuzzerData = data;
            renderAPIFuzzerUI(data);
            showToast(`API Fuzzing complete: ${data.summary.vulnerabilities_uncovered} vulnerabilities identified!`, "success");
        } else {
            showToast("API Fuzzing failed", "error");
        }
    } catch (e) {
        showToast("Fuzzer execution failed", "error");
    } finally {
        if (btn) btn.disabled = false;
    }
}

function renderAPIFuzzerUI(data) {
    const sum = data.summary || {};
    const findings = data.fuzz_findings || [];

    const epEl = document.getElementById("fuzz-stat-endpoints");
    const pbEl = document.getElementById("fuzz-stat-probes");
    const flEl = document.getElementById("fuzz-stat-flaws");

    if (epEl) epEl.textContent = sum.total_endpoints_discovered || 0;
    if (pbEl) pbEl.textContent = sum.total_fuzz_probes_sent || 0;
    if (flEl) flEl.textContent = sum.vulnerabilities_uncovered || 0;

    const tbody = document.getElementById("fuzz-findings-tbody");
    if (!tbody) return;

    if (findings.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No active API vulnerabilities detected.</td></tr>';
        return;
    }

    tbody.innerHTML = findings.map(f => {
        const sevColor = f.severity === "CRITICAL" ? "#f43f5e" : "#f59e0b";
        const reproSafe = encodeURIComponent(f.reproduction_curl || "");
        return `
            <tr>
                <td style="font-weight: 700; color: #fff;"><code>${f.id}</code></td>
                <td>
                    <div style="font-weight: 600; color: #fff;">${f.owasp_category}</div>
                    <div style="font-size: 11px; color: var(--text-secondary);">${f.payload_description}</div>
                </td>
                <td>
                    <span class="badge" style="background: ${sevColor}22; color: ${sevColor}; border: 1px solid ${sevColor}44; font-size: 11px;">
                        ${f.severity}
                    </span>
                </td>
                <td><code style="color: #38bdf8;">${f.endpoint}</code></td>
                <td style="font-size: 11px; color: var(--text-secondary); max-width: 280px;">${f.evidence}</td>
                <td style="text-align: right;">
                    <button class="btn btn-secondary btn-sm" onclick="copyFuzzCurl('${reproSafe}')" style="font-size: 11px;">
                        📋 Copy cURL
                    </button>
                </td>
            </tr>
        `;
    }).join("");
}

function copyFuzzCurl(encodedCurl) {
    const curl = decodeURIComponent(encodedCurl);
    navigator.clipboard.writeText(curl);
    showToast("Copied cURL reproduction payload to clipboard!", "success");
}


// =========================================================================
// 4. OWASP TOP 10 FOR LLMS & AI GUARD CONTROLLER
// =========================================================================
async function loadLLMSecData() {
    await runLLMScan();
    await runPromptProbes();
}

async function runLLMScan() {
    try {
        const resp = await fetch("/api/llm-scanner/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({})
        });
        if (!resp.ok) return;
        const data = await resp.json();
        renderLLMCodeFindings(data);
    } catch (e) {
        console.error("Failed to scan LLM code:", e);
    }
}

function renderLLMCodeFindings(data) {
    const findings = data.findings || [];
    const badge = document.getElementById("llm-scan-count-badge");
    if (badge) badge.textContent = `${findings.length} Flaws`;

    const container = document.getElementById("llm-code-findings-container");
    if (!container) return;

    if (findings.length === 0) {
        container.innerHTML = '<div style="color: #10b981; font-size: 13px;">✔ No AI/LLM code vulnerabilities detected.</div>';
        return;
    }

    container.innerHTML = findings.map(f => {
        const sevColor = f.severity === "CRITICAL" ? "#f43f5e" : "#f59e0b";
        return `
            <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255, 255, 255, 0.08); border-left: 4px solid ${sevColor}; border-radius: 8px; padding: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <span class="badge" style="background: ${sevColor}22; color: ${sevColor}; border: 1px solid ${sevColor}44; font-size: 10px;">${f.severity}</span>
                    <span style="font-size: 11px; color: var(--text-muted);">${f.file}:${f.line}</span>
                </div>
                <div style="font-size: 13px; font-weight: 700; color: #fff; margin-bottom: 4px;">${f.category}</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 8px;">${f.description}</div>
                <div style="background: #090d16; border-radius: 4px; padding: 6px 10px; font-family: var(--font-mono); font-size: 11px; color: #f43f5e; margin-bottom: 6px;">
                    ${f.snippet}
                </div>
                <div style="font-size: 11px; color: #34d399;">💡 <strong>Fix:</strong> ${f.remediation}</div>
            </div>
        `;
    }).join("");
}

async function runPromptProbes() {
    const promptInput = document.getElementById("llm-test-system-prompt");
    const userInput = document.getElementById("llm-test-user-input");
    const systemPrompt = promptInput ? promptInput.value : "";
    const testInput = userInput ? userInput.value : "";

    try {
        const resp = await fetch("/api/llm-scanner/probe", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                system_prompt: systemPrompt,
                user_test_input: testInput
            })
        });
        if (!resp.ok) return;
        const data = await resp.json();
        renderPromptProbeResults(data);
    } catch (e) {
        showToast("Prompt prober failed", "error");
    }
}

function renderPromptProbeResults(data) {
    const scoreEl = document.getElementById("llm-guardrail-score");
    if (scoreEl) {
        scoreEl.textContent = `${data.guardrail_health_score || 0}%`;
        scoreEl.style.color = (data.guardrail_health_score >= 80) ? "#10b981" : "#f43f5e";
    }

    const container = document.getElementById("llm-probe-results-container");
    if (!container) return;

    const probes = data.probe_details || [];
    container.innerHTML = probes.map(p => {
        const isDefended = p.status === "DEFENDED";
        const stColor = isDefended ? "#10b981" : "#f43f5e";
        return `
            <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid ${isDefended ? 'rgba(16, 185, 129, 0.25)' : 'rgba(244, 63, 94, 0.35)'}; border-radius: 6px; padding: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
                    <span style="font-size: 12px; font-weight: 700; color: #fff;">${p.probe_name}</span>
                    <span class="badge" style="background: ${stColor}22; color: ${stColor}; border: 1px solid ${stColor}44; font-size: 10px;">${p.status}</span>
                </div>
                <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 4px;">Vector: ${p.attack_vector}</div>
                <div style="font-size: 11px; color: var(--text-secondary);">${p.finding_details}</div>
            </div>
        `;
    }).join("");
}


// =========================================================================
// 5. CONTINUOUS SBOM DRIFT & SLSA ATTESTATION CONTROLLER
// =========================================================================
let cachedSLSA = null;

async function loadSBOMDriftData() {
    try {
        const resp = await fetch("/api/sbom/drift");
        if (!resp.ok) return;
        const data = await resp.json();
        renderSBOMDriftUI(data);
    } catch (e) {
        console.error("Failed to load SBOM drift:", e);
    }
}

function refreshSBOMDrift() {
    showToast("Comparing SBOM snapshots against baseline...", "info");
    loadSBOMDriftData();
}

function renderSBOMDriftUI(data) {
    const sum = data.summary || {};
    const drifted = data.drifted_versions || [];
    const added = data.added_dependencies || [];
    const licAlerts = data.license_alerts || [];

    const tEl = document.getElementById("drift-stat-total");
    const dEl = document.getElementById("drift-stat-drifted");
    const cEl = document.getElementById("drift-stat-changes");
    const lEl = document.getElementById("drift-stat-licenses");

    if (tEl) tEl.textContent = sum.total_current_components || 0;
    if (dEl) dEl.textContent = sum.components_drifted_version || 0;
    if (cEl) cEl.textContent = `+${sum.components_added || 0} / -${sum.components_removed || 0}`;
    if (lEl) lEl.textContent = sum.license_compliance_risks || 0;

    const tbody = document.getElementById("drift-tbody");
    if (!tbody) return;

    let rowsHtml = "";

    // Drifted
    drifted.forEach(d => {
        rowsHtml += `
            <tr>
                <td style="font-weight: 700; color: #fff;">${d.package}</td>
                <td><code style="color: var(--text-muted);">${d.old_version}</code></td>
                <td><code style="color: #38bdf8;">${d.new_version}</code></td>
                <td><span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.3); font-size: 11px;">${d.drift_type}</span></td>
                <td style="font-size: 11px; color: var(--text-secondary);">Dependency version bumped; pending CVE scan</td>
            </tr>
        `;
    });

    // Added risky licenses
    licAlerts.forEach(l => {
        rowsHtml += `
            <tr style="background: rgba(244, 63, 94, 0.06);">
                <td style="font-weight: 700; color: #fff;">${l.package}</td>
                <td><span style="color: var(--text-muted);">None (New)</span></td>
                <td><code style="color: #f43f5e;">${l.version}</code></td>
                <td><span class="badge" style="background: rgba(244, 63, 94, 0.2); color: #f43f5e; border: 1px solid rgba(244, 63, 94, 0.4); font-size: 11px;">COPYLEFT CONFLICT</span></td>
                <td style="font-size: 11px; color: #f43f5e;">${l.advisory}</td>
            </tr>
        `;
    });

    if (!rowsHtml) {
        rowsHtml = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No dependency drift detected across build snapshots.</td></tr>';
    }

    tbody.innerHTML = rowsHtml;
}

async function generateSLSAAttestation() {
    showToast("Generating in-toto SLSA Level 3 provenance attestation...", "info");
    try {
        const resp = await fetch("/api/sbom/attestation", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ project_name: state.activeProjectId || "sentinel-appsec" })
        });
        if (resp.ok) {
            const data = await resp.json();
            cachedSLSA = data;
            const pre = document.getElementById("slsa-attestation-json");
            if (pre) pre.textContent = JSON.stringify(data, null, 2);
            showToast("Generated SLSA Level 3 cryptographically signed attestation", "success");
        }
    } catch (e) {
        showToast("SLSA attestation generation failed", "error");
    }
}

function copyAttestationJSON() {
    if (!cachedSLSA) {
        showToast("Generate an attestation first", "warning");
        return;
    }
    navigator.clipboard.writeText(JSON.stringify(cachedSLSA, null, 2));
    showToast("Copied in-toto SLSA attestation predicate to clipboard", "success");
}


// =========================================================================
// 6. INTERACTIVE APPSEC SANDBOX & PLAYGROUND CONTROLLER
// =========================================================================
let sandboxChallenges = [];
let activeChallengeId = "CHAL-SQLI";
let sandboxTotalScore = 0;

async function loadSandboxData() {
    try {
        const resp = await fetch("/api/sandbox/challenges");
        if (!resp.ok) return;
        const data = await resp.json();
        sandboxChallenges = data.challenges || [];
        renderSandboxChallengePills();
        selectSandboxChallenge(activeChallengeId);
    } catch (e) {
        console.error("Failed to load sandbox challenges:", e);
    }
}

function renderSandboxChallengePills() {
    const container = document.getElementById("sandbox-challenge-pills");
    if (!container) return;

    container.innerHTML = sandboxChallenges.map(c => {
        const isSel = c.id === activeChallengeId;
        return `
            <button class="btn btn-secondary btn-sm ${isSel ? 'active' : ''}" onclick="selectSandboxChallenge('${c.id}')" style="white-space: nowrap; ${isSel ? 'background: rgba(56, 189, 248, 0.2); border-color: #38bdf8; color: #38bdf8;' : ''}">
                ${c.title.split('&')[0].trim()}
            </button>
        `;
    }).join("");
}

function selectSandboxChallenge(challengeId) {
    activeChallengeId = challengeId;
    renderSandboxChallengePills();

    const chal = sandboxChallenges.find(c => c.id === challengeId);
    if (!chal) return;

    const tEl = document.getElementById("sandbox-chal-title");
    const cEl = document.getElementById("sandbox-chal-cwe");
    const dEl = document.getElementById("sandbox-chal-desc");
    const hEl = document.getElementById("sandbox-chal-hint");
    const codeEl = document.getElementById("sandbox-code-editor");
    const payEl = document.getElementById("sandbox-payload-input");

    if (tEl) tEl.textContent = chal.title;
    if (cEl) cEl.textContent = `${chal.category} • ${chal.difficulty}`;
    if (dEl) dEl.textContent = chal.description;
    if (hEl) hEl.textContent = chal.solution_hint;
    if (codeEl) codeEl.value = chal.default_code;
    if (payEl) payEl.value = chal.exploit_payload;
}

function resetSandboxChallengeCode() {
    const chal = sandboxChallenges.find(c => c.id === activeChallengeId);
    if (chal) {
        const codeEl = document.getElementById("sandbox-code-editor");
        if (codeEl) codeEl.value = chal.default_code;
        showToast("Restored vulnerable starter code", "info");
    }
}

async function runSandboxTest(isVerifyFix) {
    const codeEl = document.getElementById("sandbox-code-editor");
    const payEl = document.getElementById("sandbox-payload-input");
    const termEl = document.getElementById("sandbox-terminal");
    const badgeEl = document.getElementById("sandbox-status-badge");
    const scoreBadge = document.getElementById("sandbox-score-badge");

    const code = codeEl ? codeEl.value : "";
    const payload = payEl ? payEl.value : "";

    if (termEl) termEl.textContent = "Executing sandbox simulation environment...\nAttaching runtime hooks...\nInjecting test vector...";

    try {
        const resp = await fetch("/api/sandbox/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                challenge_id: activeChallengeId,
                user_code: code,
                test_payload: payload
            })
        });

        if (resp.ok) {
            const data = await resp.json();
            const isSolved = data.solved;

            if (termEl) {
                termEl.innerHTML = `[SANDBOX TEST EXECUTION]
Challenge: ${data.challenge_title}
Payload Dispatched: ${data.tested_payload}
Simulation Status: ${data.status}
Feedback: ${data.feedback}
${isSolved ? '\n[+] VERIFICATION PASSED: Security vulnerability has been successfully remediated!' : '\n[-] TEST FAILED: Exploit succeeded in executing against submitted code.'}`;
                termEl.style.color = isSolved ? "#34d399" : "#f43f5e";
            }

            if (badgeEl) {
                badgeEl.textContent = data.status;
                badgeEl.style.background = isSolved ? "rgba(16, 185, 129, 0.25)" : "rgba(244, 63, 94, 0.25)";
                badgeEl.style.color = isSolved ? "#34d399" : "#f43f5e";
            }

            if (isSolved) {
                sandboxTotalScore += data.points_awarded || 100;
                if (scoreBadge) scoreBadge.textContent = `${sandboxTotalScore} PTS`;
                showToast("🎉 Challenge Solved! Security verification passed (+100 PTS)", "success");
            } else {
                showToast("Exploit succeeded. Review the hint and harden your code.", "warning");
            }
        }
    } catch (e) {
        if (termEl) termEl.textContent = "Execution error in test harness.";
        showToast("Sandbox execution failed", "error");
    }
}


/* ==========================================================================
   INTERACTIVE DEPENDENCY TREE & TRANSITIVE BLAST RADIUS CONTROLLER
   ========================================================================== */
let currentDeptreeFilter = "all";
let cachedDeptreeData = null;

async function populateDeptreeProjectSelect() {
    const sel = document.getElementById("deptree-project-select");
    if (!sel) return;
    if (state.projects && state.projects.length > 0) {
        sel.innerHTML = state.projects.map(p => `
            <option value="${p.id}" ${p.id === state.activeProjectId ? 'selected' : ''}>${escapeHtml(p.name)}</option>
        `).join("");
    } else {
        sel.innerHTML = `<option value="">Default Project</option>`;
    }
}

async function onDeptreeProjectChange() {
    const sel = document.getElementById("deptree-project-select");
    if (sel && sel.value) {
        state.activeProjectId = sel.value;
    }
    await loadDependencyTree();
}

function exportDeptreeSBOM() {
    const sel = document.getElementById("deptree-project-select");
    const pid = (sel && sel.value) || state.activeProjectId || (state.projects[0] && state.projects[0].id) || "default";
    showToast("Exporting CycloneDX Software Bill of Materials...", "info");
    window.open(`/api/projects/${pid}/export/cyclonedx`, "_blank");
}

function setDeptreeFilter(filter) {
    currentDeptreeFilter = filter;
    ["all", "vuln", "direct", "transitive"].forEach(f => {
        const btn = document.getElementById(`deptree-filter-${f}`);
        if (btn) btn.classList.toggle("active", f === filter);
    });
    renderDeptreeView();
}

function filterDeptreeView() {
    renderDeptreeView();
}

async function loadDependencyTree() {
    await populateDeptreeProjectSelect();
    const sel = document.getElementById("deptree-project-select");
    const pid = (sel && sel.value) || state.activeProjectId || (state.projects[0] && state.projects[0].id) || "default";
    try {
        const resp = await fetch(`/api/projects/${pid}/dependencies/tree`);
        if (!resp.ok) {
            showToast("Failed to load dependency tree for project", "error");
            return;
        }
        const data = await resp.json();
        cachedDeptreeData = data;

        // Populate KPIs
        const sum = data.summary || {};
        const totalEl = document.getElementById("deptree-stat-total");
        if (totalEl) totalEl.textContent = sum.total_dependencies || 0;
        const dirEl = document.getElementById("deptree-stat-direct");
        if (dirEl) dirEl.textContent = sum.direct_count || 0;
        const transEl = document.getElementById("deptree-stat-transitive");
        if (transEl) transEl.textContent = sum.transitive_count || 0;
        const vulnEl = document.getElementById("deptree-stat-vuln");
        if (vulnEl) vulnEl.textContent = sum.vulnerable_count || 0;
        const blastEl = document.getElementById("deptree-stat-blast");
        if (blastEl) blastEl.textContent = sum.max_blast_radius || 1;

        renderDeptreeView();
    } catch (e) {
        console.error("Error loading dependency tree:", e);
    }
}

function renderDeptreeView() {
    if (!cachedDeptreeData) return;
    const tree = cachedDeptreeData.tree;
    const canvas = document.getElementById("deptree-tree-canvas");
    const showingCount = document.getElementById("deptree-showing-count");
    const searchVal = (document.getElementById("deptree-search-input")?.value || "").toLowerCase().trim();

    // Render Blast Radius Table
    const blastList = document.getElementById("deptree-blast-list");
    const blastItems = cachedDeptreeData.blast_radius_analysis || [];
    if (blastList) {
        if (!blastItems || blastItems.length === 0) {
            blastList.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 30px 10px;">✅ No vulnerable supply chain libraries detected in active dependency hierarchy.</div>`;
        } else {
            blastList.innerHTML = blastItems.map(item => {
                const sevColor = item.severity === 'CRITICAL' ? '#ef4444' : item.severity === 'HIGH' ? '#f59e0b' : '#38bdf8';
                return `
                <div class="deptree-blast-card">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
                        <div>
                            <span style="font-weight: 700; color: #fff; font-size: 13px;">${escapeHtml(item.package)}</span>
                            <span style="font-size: 11px; color: var(--text-muted); margin-left: 4px;">v${escapeHtml(item.version)}</span>
                        </div>
                        <span class="badge" style="background: ${sevColor}20; color: ${sevColor}; border: 1px solid ${sevColor}; font-size: 10px;">${item.severity}</span>
                    </div>
                    <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 6px;">
                        Exposure Path: <code style="color: #cbd5e1; font-size: 10px;">${escapeHtml(item.path_display)}</code>
                    </div>
                    <div style="display: flex; justify-content: space-between; align-items: center; font-size: 11px;">
                        <span style="color: #f87171; font-weight: 600;">💥 Blast Radius: ${item.blast_radius_score} downstream</span>
                        <span style="color: #38bdf8;">${item.cve_id ? escapeHtml(item.cve_id) : 'Known Flaw'}</span>
                    </div>
                    <div style="margin-top: 6px; font-size: 11px; color: #94a3b8; border-top: 1px dashed rgba(255,255,255,0.08); padding-top: 6px;">
                        💡 <em>${escapeHtml(item.remediation)}</em>
                    </div>
                </div>`;
            }).join("");
        }
    }

    // Render Interactive Tree Nodes
    if (canvas && tree) {
        let renderedNodesCount = 0;
        function renderNodeHtml(node, depth = 0) {
            const isRoot = node.type === 'root';
            const name = node.name || 'component';
            const ver = node.version && node.version !== 'root' ? `v${node.version}` : '';
            const sev = node.severity || 'CLEAN';
            const isVuln = sev !== 'CLEAN';
            const typeLabel = node.type || 'direct';

            // Filter check
            let matchesFilter = true;
            if (currentDeptreeFilter === 'vuln' && !isVuln && !isRoot) matchesFilter = false;
            if (currentDeptreeFilter === 'direct' && node.type !== 'direct' && !isRoot) matchesFilter = false;
            if (currentDeptreeFilter === 'transitive' && node.type !== 'transitive' && !isRoot) matchesFilter = false;

            if (searchVal && !isRoot) {
                const text = `${name} ${ver} ${sev} ${node.cve_id || ''}`.toLowerCase();
                if (!text.includes(searchVal)) matchesFilter = false;
            }

            const sevColor = sev === 'CRITICAL' ? '#ef4444' : sev === 'HIGH' ? '#f59e0b' : sev === 'MEDIUM' ? '#eab308' : '#10b981';
            const sevBg = isVuln ? `${sevColor}15` : 'rgba(255,255,255,0.04)';
            const sevBorder = isVuln ? `${sevColor}60` : 'rgba(255,255,255,0.08)';

            let childrenHtml = '';
            if (node.children && node.children.length > 0) {
                childrenHtml = `
                <div class="deptree-node-wrap">
                    ${node.children.map(child => renderNodeHtml(child, depth + 1)).join('')}
                </div>`;
            }

            if (!matchesFilter && (!childrenHtml || !childrenHtml.includes('deptree-node-card'))) {
                return '';
            }

            renderedNodesCount++;
            return `
            <div style="margin: 4px 0;">
                <div class="deptree-node-card" style="background: ${sevBg}; border-color: ${sevBorder};" onclick="inspectDeptreeNode('${escapeHtml(node.id)}')">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="font-size: 14px;">${isRoot ? '🏢' : isVuln ? '⚠️' : '📦'}</span>
                        <strong style="color: #fff; font-size: 12px;">${escapeHtml(name)}</strong>
                        <span style="font-size: 11px; color: var(--text-muted); font-family: monospace;">${escapeHtml(ver)}</span>
                        ${!isRoot ? `<span class="badge" style="background: rgba(255,255,255,0.08); color: #94a3b8; font-size: 9px;">${typeLabel}</span>` : ''}
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        ${node.blast_radius && node.blast_radius > 1 ? `<span class="badge" style="background: rgba(245, 158, 11, 0.2); color: #f59e0b; font-size: 9px;">💥 Blast: ${node.blast_radius}</span>` : ''}
                        ${node.cve_id ? `<span class="badge" style="background: rgba(239, 68, 68, 0.2); color: #f87171; font-size: 9px;">${escapeHtml(node.cve_id)}</span>` : ''}
                        <span class="badge" style="background: ${sevColor}20; color: ${sevColor}; border: 1px solid ${sevColor}; font-size: 9px;">${sev}</span>
                    </div>
                </div>
                ${childrenHtml}
            </div>`;
        }

        canvas.innerHTML = renderNodeHtml(tree);
        if (showingCount) showingCount.textContent = `Showing ${renderedNodesCount} components in exposure hierarchy`;
    }
}

function inspectDeptreeNode(nodeId) {
    if (!cachedDeptreeData || !cachedDeptreeData.nodes) return;
    const node = cachedDeptreeData.nodes.find(n => n.id === nodeId);
    if (!node) return;
    showToast(`Inspecting ${node.name}: ${node.severity} (${node.type || 'component'})`, "info");
}


/* ==========================================================================
   CONVERSATIONAL SECURITY COPILOT CHATBOT CONTROLLER
   ========================================================================== */
let copilotChatHistory = [];
let isCopilotThinking = false;

function toggleCopilot() {
    const win = document.getElementById("copilot-chat-window");
    if (!win) return;
    const isHidden = win.style.display === "none" || !win.style.display;
    win.style.display = isHidden ? "flex" : "none";
    if (isHidden) {
        updateCopilotActiveProject();
        const input = document.getElementById("copilot-user-input");
        if (input) setTimeout(() => input.focus(), 150);
    }
}

function updateCopilotActiveProject() {
    const lbl = document.getElementById("copilot-active-project-label");
    if (!lbl) return;
    const activeP = state.projects.find(p => p.id === state.activeProjectId);
    lbl.textContent = activeP ? activeP.name : (state.projects[0] ? state.projects[0].name : "Enterprise");
}

function clearCopilotChat() {
    copilotChatHistory = [];
    const container = document.getElementById("copilot-messages");
    if (container) {
        container.innerHTML = `
            <div class="copilot-msg copilot-msg-assistant">
                <div class="copilot-msg-avatar">🛡️</div>
                <div class="copilot-msg-bubble">
                    <p>Conversation reset. How can I assist you with your project security posture or vulnerabilities?</p>
                </div>
            </div>`;
    }
    showToast("Copilot conversation cleared", "info");
}

function handleCopilotKeyDown(e) {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendCopilotMessage();
    }
}

function sendCopilotSuggestedPrompt(promptText) {
    const input = document.getElementById("copilot-user-input");
    if (input) {
        input.value = promptText;
        sendCopilotMessage();
    }
}

async function sendCopilotMessage() {
    const input = document.getElementById("copilot-user-input");
    if (!input || isCopilotThinking) return;
    const text = input.value.trim();
    if (!text) return;

    input.value = "";
    input.style.height = "auto";

    const container = document.getElementById("copilot-messages");
    if (!container) return;

    // Append User Message
    container.innerHTML += `
        <div class="copilot-msg copilot-msg-user">
            <div class="copilot-msg-avatar">👤</div>
            <div class="copilot-msg-bubble">
                <p>${escapeHtml(text)}</p>
            </div>
        </div>`;

    // Append Thinking Indicator
    const thinkingId = `copilot-thinking-${Date.now()}`;
    container.innerHTML += `
        <div class="copilot-msg copilot-msg-assistant" id="${thinkingId}">
            <div class="copilot-msg-avatar">🛡️</div>
            <div class="copilot-msg-bubble" style="display: flex; align-items: center; gap: 8px;">
                <span class="spinner-border spinner-border-sm" style="color: #38bdf8;" role="status"></span>
                <span style="font-size: 12px; color: #94a3b8;">Analyzing security telemetry &amp; generating guidance...</span>
            </div>
        </div>`;
    container.scrollTop = container.scrollHeight;
    isCopilotThinking = true;

    try {
        const activePid = state.activeProjectId || (state.projects[0] && state.projects[0].id) || null;
        const resp = await fetch("/api/copilot/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                message: text,
                project_id: activePid,
                history: copilotChatHistory
            })
        });

        const thinkingEl = document.getElementById(thinkingId);
        if (thinkingEl) thinkingEl.remove();

        if (resp.ok) {
            const data = await resp.json();
            copilotChatHistory.push({ role: "user", content: text });
            copilotChatHistory.push({ role: "assistant", content: data.reply });

            // Render Markdown text & Code
            const formattedReply = renderCopilotMarkdown(data.reply);

            // Render Actions
            let actionsHtml = "";
            if (data.suggested_actions && data.suggested_actions.length > 0) {
                actionsHtml = `<div class="copilot-action-row">` +
                    data.suggested_actions.map(act => `
                        <button class="copilot-action-btn" onclick="executeCopilotAction('${act.action}')">${escapeHtml(act.label)}</button>
                    `).join("") +
                `</div>`;
            }

            container.innerHTML += `
                <div class="copilot-msg copilot-msg-assistant">
                    <div class="copilot-msg-avatar">🛡️</div>
                    <div class="copilot-msg-bubble">
                        ${formattedReply}
                        ${actionsHtml}
                    </div>
                </div>`;
        } else {
            const err = await resp.json().catch(() => ({}));
            container.innerHTML += `
                <div class="copilot-msg copilot-msg-assistant">
                    <div class="copilot-msg-avatar">🛡️</div>
                    <div class="copilot-msg-bubble" style="color: #f87171;">
                        ⚠️ ${escapeHtml(err.detail || "Error connecting to Security Copilot service.")}
                    </div>
                </div>`;
        }
    } catch (e) {
        const thinkingEl = document.getElementById(thinkingId);
        if (thinkingEl) thinkingEl.remove();
        container.innerHTML += `
            <div class="copilot-msg copilot-msg-assistant">
                <div class="copilot-msg-avatar">🛡️</div>
                <div class="copilot-msg-bubble" style="color: #f87171;">
                    ⚠️ Network error querying Security Copilot.
                </div>
            </div>`;
    } finally {
        isCopilotThinking = false;
        container.scrollTop = container.scrollHeight;
    }
}

function renderCopilotMarkdown(md) {
    if (!md) return "";
    let html = escapeHtml(md);

    // Format Code Blocks
    html = html.replace(/```([a-z0-9_-]*)\n([\s\S]*?)```/g, (match, lang, code) => {
        return `<pre><code>${code.trim()}</code></pre>`;
    });

    // Format Inline Code
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Headers
    html = html.replace(/^#### (.*$)/gim, '<h5 style="color: #fff; font-size: 13px; margin: 10px 0 4px 0;">$1</h5>');
    html = html.replace(/^### (.*$)/gim, '<h4 style="color: #38bdf8; font-size: 14px; margin: 12px 0 6px 0;">$1</h4>');
    html = html.replace(/^## (.*$)/gim, '<h3 style="color: #fff; font-size: 15px; margin: 14px 0 6px 0;">$1</h3>');

    // Bold & Italics
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');

    // Lists
    html = html.replace(/^\* (.*$)/gim, '• $1<br>');
    html = html.replace(/^- (.*$)/gim, '• $1<br>');

    // Blockquotes
    html = html.replace(/^> (.*$)/gim, '<div style="border-left: 2px solid #38bdf8; padding-left: 8px; color: #94a3b8; margin: 6px 0;">$1</div>');

    // Newlines to breaks for paragraphs
    html = html.replace(/\n\n/g, '<br><br>');

    return html;
}

function executeCopilotAction(action) {
    if (action === "navigate_triage") navigate("triage");
    else if (action === "navigate_deptree") navigate("deptree");
    else if (action === "navigate_compliance") navigate("compliance");
    else if (action === "navigate_patch") {
        navigate("triage");
        showToast("Open Batch Patching via the Patch Studio button in Vulnerabilities tab", "info");
    }
    else if (action === "download_compliance_dossier") downloadExecutiveComplianceDossier();
    else if (action === "export_sarif") {
        const pid = state.activeProjectId || (state.projects[0] && state.projects[0].id) || "default";
        window.open(`/api/projects/${pid}/export/sarif`, "_blank");
    }
    else if (action === "export_cyclonedx") exportDeptreeSBOM();
    else if (action === "prompt_summary") sendCopilotSuggestedPrompt("Summarize the security posture and critical risks of this project.");
    else if (action === "prompt_dependencies") sendCopilotSuggestedPrompt("Which dependencies have the largest blast radius and known CVEs?");
    else if (action === "prompt_compliance") sendCopilotSuggestedPrompt("What is our compliance readiness score for SOC 2 and ISO 27001?");
}



