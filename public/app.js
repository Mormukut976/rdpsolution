const root = document.querySelector("#app");
const modal = document.querySelector("#modal");
const modalContent = document.querySelector("#modal-content");
const toastRegion = document.querySelector("#toast-region");

const state = {
  user: null,
  csrfToken: "",
  view: "overview",
  dashboard: null,
  applications: [],
  hosts: [],
  users: [],
  events: [],
};

const icons = {
  overview:
    '<svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/></svg>',
  apps:
    '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="15" rx="2"/><path d="M8 22h8M12 19v3M3 9h18"/></svg>',
  hosts:
    '<svg viewBox="0 0 24 24"><rect x="4" y="3" width="16" height="7" rx="2"/><rect x="4" y="14" width="16" height="7" rx="2"/><path d="M8 6.5h.01M8 17.5h.01M12 6.5h4M12 17.5h4"/></svg>',
  users:
    '<svg viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
  security:
    '<svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/></svg>',
  audit:
    '<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M8 13h8M8 17h5"/></svg>',
  monitor:
    '<svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>',
  app:
    '<svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="3"/><path d="M3 9h18M9 21V9"/></svg>',
  plus: '<svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>',
  edit: '<svg viewBox="0 0 24 24"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L8 18l-4 1 1-4Z"/></svg>',
  trash:
    '<svg viewBox="0 0 24 24"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v5M14 11v5"/></svg>',
  key: '<svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="m11 12 8-8M15 8l3 3M17 6l3 3"/></svg>',
  logout:
    '<svg viewBox="0 0 24 24"><path d="M10 17l5-5-5-5M15 12H3M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/></svg>',
  menu: '<svg viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"/></svg>',
  launch:
    '<svg viewBox="0 0 24 24"><path d="M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>',
  close: '<svg viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></svg>',
  check: '<svg viewBox="0 0 24 24"><path d="m5 12 4 4L19 6"/></svg>',
};

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function icon(name, className = "icon") {
  return `<span class="${className}" aria-hidden="true">${icons[name] || icons.app}</span>`;
}

function initials(name) {
  return String(name)
    .split(/\s+/)
    .slice(0, 2)
    .map((part) => part[0])
    .join("")
    .toUpperCase();
}

function formatDate(value) {
  if (!value) return "—";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function relativeTime(value) {
  if (!value) return "Never";
  const seconds = Math.round((value - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (Math.abs(seconds) < 60) return formatter.format(seconds, "second");
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return formatter.format(minutes, "minute");
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return formatter.format(hours, "hour");
  return formatter.format(Math.round(hours / 24), "day");
}

async function api(path, options = {}) {
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (options.body && !(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  if (state.csrfToken && !["GET", "HEAD"].includes(options.method || "GET")) {
    headers["X-CSRF-Token"] = state.csrfToken;
  }

  const response = await fetch(path, { credentials: "same-origin", ...options, headers });
  const data = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 && data?.error?.code === "authentication_required") {
      state.user = null;
      renderLogin();
    }
    const error = new Error(data?.error?.message || `Request failed (${response.status})`);
    error.code = data?.error?.code;
    error.details = data?.error?.details;
    throw error;
  }
  return data;
}

function toast(message, type = "success") {
  const element = document.createElement("div");
  element.className = `toast ${type}`;
  element.innerHTML = `
    <span class="toast-symbol">${type === "success" ? "✓" : "!"}</span>
    <span>${escapeHtml(message)}</span>
    <button type="button" aria-label="Dismiss">×</button>
  `;
  element.querySelector("button").addEventListener("click", () => element.remove());
  toastRegion.append(element);
  setTimeout(() => element.remove(), 5000);
}

function buttonLoading(button, loading) {
  if (!button) return;
  if (loading) {
    button.dataset.originalText = button.innerHTML;
    button.disabled = true;
    button.textContent = "Please wait…";
  } else {
    button.disabled = false;
    button.innerHTML = button.dataset.originalText || button.innerHTML;
  }
}

function authArtwork() {
  return `
    <section class="auth-panel">
      <div class="auth-brand">
        <div class="brand-mark"><span></span><span></span></div>
        OpenRemote
      </div>
      <div class="auth-copy">
        <p class="eyebrow">Remote access, made open</p>
        <h1>Your apps.<br />Everywhere.</h1>
        <p>Securely deliver Windows desktops and applications to any browser—without per-user software fees.</p>
        <div class="feature-list">
          <div class="feature"><span class="feature-icon">✓</span> Browser-based RDP and RemoteApp delivery</div>
          <div class="feature"><span class="feature-icon">✓</span> Role-based access and two-factor authentication</div>
          <div class="feature"><span class="feature-icon">✓</span> Self-hosted, auditable, and open-source</div>
        </div>
      </div>
    </section>
  `;
}

function renderSetup() {
  root.innerHTML = `
    <main class="auth-layout">
      ${authArtwork()}
      <section class="auth-form-wrap">
        <form id="setup-form" class="auth-card">
          <p class="eyebrow">First-run setup</p>
          <h2>Create the owner account</h2>
          <p class="subtle">This account controls hosts, published applications, users, and security policy.</p>
          <div class="form-grid">
            <div class="field">
              <label for="displayName">Your name</label>
              <input id="displayName" name="displayName" required minlength="2" maxlength="80" autocomplete="name" />
            </div>
            <div class="field">
              <label for="email">Admin email</label>
              <input id="email" name="email" required type="email" maxlength="254" autocomplete="username" />
            </div>
            <div class="field">
              <label for="password">Strong password</label>
              <input id="password" name="password" required type="password" minlength="12" autocomplete="new-password" />
              <small>At least 12 characters with uppercase, lowercase, number, and symbol.</small>
            </div>
            <button class="button primary block" type="submit">Create secure workspace</button>
          </div>
        </form>
      </section>
    </main>
  `;

  document.querySelector("#setup-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    const data = Object.fromEntries(new FormData(event.currentTarget));
    buttonLoading(button, true);
    try {
      await api("/api/setup", { method: "POST", body: JSON.stringify(data) });
      toast("Owner account created. Sign in to continue.");
      renderLogin(data.email);
    } catch (error) {
      toast(error.message, "error");
    } finally {
      buttonLoading(button, false);
    }
  });
}

function renderLogin(email = "") {
  state.user = null;
  state.csrfToken = "";
  root.innerHTML = `
    <main class="auth-layout">
      ${authArtwork()}
      <section class="auth-form-wrap">
        <form id="login-form" class="auth-card">
          <p class="eyebrow">OpenRemote console</p>
          <h2>Welcome back</h2>
          <p class="subtle">Sign in to access your remote workspace.</p>
          <div class="form-grid">
            <div class="field">
              <label for="email">Email address</label>
              <input id="email" name="email" value="${escapeHtml(email)}" required type="email" autocomplete="username" />
            </div>
            <div class="field">
              <label for="password">Password</label>
              <input id="password" name="password" required type="password" autocomplete="current-password" />
            </div>
            <div class="field" id="totp-field" hidden>
              <label for="totp">Authenticator code</label>
              <input id="totp" name="totp" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" />
            </div>
            <button class="button primary block" type="submit">Sign in</button>
          </div>
        </form>
      </section>
    </main>
  `;

  document.querySelector("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    const data = Object.fromEntries(new FormData(event.currentTarget));
    buttonLoading(button, true);
    try {
      const result = await api("/api/auth/login", {
        method: "POST",
        body: JSON.stringify(data),
      });
      state.user = result.user;
      state.csrfToken = result.csrfToken;
      state.view = "overview";
      await renderShell();
    } catch (error) {
      if (error.code === "totp_required") {
        const field = document.querySelector("#totp-field");
        field.hidden = false;
        field.querySelector("input").required = true;
        field.querySelector("input").focus();
      }
      toast(error.message, "error");
    } finally {
      buttonLoading(button, false);
    }
  });
}

const viewMeta = {
  overview: ["Overview", "Workspace health and recent activity"],
  applications: ["Applications", "Published desktops and RemoteApps"],
  hosts: ["Hosts", "Remote desktop servers and agent health"],
  users: ["Users", "Accounts, roles, and application access"],
  security: ["Security", "Protect your OpenRemote account"],
  audit: ["Audit trail", "Security and administration events"],
};

function navButton(view, label) {
  return `
    <button class="nav-button ${state.view === view ? "active" : ""}" data-view="${view}" type="button">
      ${icon(view, "nav-icon")}<span>${label}</span>
    </button>
  `;
}

function shellHtml() {
  const admin = state.user.role === "admin";
  const [title, subtitle] = viewMeta[state.view];
  return `
    <div class="app-shell">
      <aside class="sidebar" id="sidebar">
        <div class="sidebar-brand">
          <div class="brand-mark"><span></span><span></span></div>
          <div>OpenRemote<small>Community edition</small></div>
        </div>
        <p class="nav-section">Workspace</p>
        <nav class="nav">
          ${navButton("overview", "Overview")}
          ${navButton("applications", admin ? "Applications" : "My applications")}
          ${admin ? navButton("hosts", "Hosts") : ""}
          ${admin ? navButton("users", "Users") : ""}
        </nav>
        <p class="nav-section">System</p>
        <nav class="nav">
          ${navButton("security", "Security")}
          ${admin ? navButton("audit", "Audit trail") : ""}
        </nav>
        <div class="sidebar-footer">
          <div class="user-chip">
            <div class="avatar">${escapeHtml(initials(state.user.displayName))}</div>
            <div>
              <strong>${escapeHtml(state.user.displayName)}</strong>
              <span>${escapeHtml(state.user.role)}</span>
            </div>
            <button class="logout-button" id="logout" type="button" aria-label="Sign out">${icon("logout")}</button>
          </div>
        </div>
      </aside>
      <main class="main">
        <header class="topbar">
          <button class="action-button mobile-menu" id="mobile-menu" type="button" aria-label="Open menu">${icon("menu")}</button>
          <div>
            <h2>${escapeHtml(title)}</h2>
            <p>${escapeHtml(subtitle)}</p>
          </div>
          <div class="topbar-actions" id="topbar-actions"></div>
        </header>
        <section class="content" id="content">
          <div class="boot-screen"><p>Loading…</p></div>
        </section>
      </main>
    </div>
  `;
}

async function renderShell() {
  root.innerHTML = shellHtml();
  bindShellEvents();
  await renderCurrentView();
}

function bindShellEvents() {
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", async () => {
      state.view = button.dataset.view;
      await renderShell();
    });
  });
  document.querySelector("#logout").addEventListener("click", async () => {
    try {
      await api("/api/auth/logout", { method: "POST" });
    } catch {
      // The local session is cleared either way.
    }
    renderLogin();
  });
  document.querySelector("#mobile-menu").addEventListener("click", () => {
    document.querySelector("#sidebar").classList.toggle("open");
  });
}

function emptyState(title, text, iconName = "apps") {
  return `
    <div class="empty-state">
      <span class="stat-icon">${icon(iconName)}</span>
      <h3>${escapeHtml(title)}</h3>
      <p>${escapeHtml(text)}</p>
    </div>
  `;
}

function statCard(label, value, foot, iconName) {
  return `
    <article class="stat-card">
      <div class="stat-top"><span>${escapeHtml(label)}</span><span class="stat-icon">${icon(iconName)}</span></div>
      <div class="stat-value">${escapeHtml(value)}</div>
      <div class="stat-foot">${escapeHtml(foot)}</div>
    </article>
  `;
}

async function renderOverview() {
  const content = document.querySelector("#content");
  state.dashboard = await api("/api/dashboard");
  const stats = state.dashboard.stats;
  const admin = state.user.role === "admin";
  if (admin && !state.hosts.length) {
    const hostResult = await api("/api/hosts");
    state.hosts = hostResult.hosts;
  }
  const rows = state.dashboard.recentSessions
    .map(
      (session) => `
        <tr>
          <td><span class="table-primary">${escapeHtml(session.applicationName)}</span><span class="table-secondary">${escapeHtml(session.hostName)}</span></td>
          ${admin ? `<td>${escapeHtml(session.userName)}</td>` : ""}
          <td><span class="badge ${escapeHtml(session.status)}">${escapeHtml(session.status)}</span></td>
          <td>${formatDate(session.startedAt)}</td>
        </tr>
      `,
    )
    .join("");
  content.innerHTML = `
    <div class="page-heading">
      <div><p class="eyebrow">${admin ? "Administration" : "Your workspace"}</p><h1>Good to see you, ${escapeHtml(state.user.displayName.split(" ")[0])}.</h1><p>${admin ? "Here is what is happening across your remote workspace." : "Your assigned applications are ready when you are."}</p></div>
    </div>
    <div class="stats-grid">
      ${admin ? statCard("Active users", stats.users, "Accounts allowed to sign in", "users") : ""}
      ${admin ? statCard("Available hosts", stats.hosts, `${stats.onlineHosts} agents online`, "hosts") : ""}
      ${statCard("Applications", stats.applications, admin ? "Published to the workspace" : "Assigned to your account", "apps")}
      ${statCard("Sessions today", stats.sessionsToday, "Launches since midnight", "launch")}
    </div>
    <div class="dashboard-grid">
      <section class="panel">
        <div class="panel-header"><h3>Recent sessions</h3><span>Latest activity</span></div>
        ${
          rows
            ? `<div class="table-wrap"><table><thead><tr><th>Application</th>${admin ? "<th>User</th>" : ""}<th>Status</th><th>Started</th></tr></thead><tbody>${rows}</tbody></table></div>`
            : emptyState("No sessions yet", "Application launches will appear here.", "launch")
        }
      </section>
      <section class="panel">
        <div class="panel-header"><h3>${admin ? "Infrastructure health" : "Account security"}</h3><span>Live summary</span></div>
        <div class="health-list">
          ${
            admin
              ? `
                <div class="health-row"><span>Control plane</span><span class="badge online">Online</span></div>
                <div class="health-row"><span>Registered hosts</span><span class="health-value">${stats.hosts}</span></div>
                <div class="health-row"><span>Online agents</span><span class="health-value">${stats.onlineHosts}</span></div>
                <div class="health-row"><span>Gateway</span><span class="health-value">Check configuration</span></div>
              `
              : `
                <div class="health-row"><span>Account status</span><span class="badge active">Active</span></div>
                <div class="health-row"><span>Two-factor authentication</span><span class="health-value">${state.user.totpEnabled ? "Enabled" : "Not enabled"}</span></div>
                <div class="health-row"><span>Access role</span><span class="health-value">${escapeHtml(state.user.role)}</span></div>
              `
          }
        </div>
      </section>
    </div>
  `;
}

async function loadApplications() {
  state.applications = (await api("/api/applications")).applications;
}

function applicationCard(application) {
  const admin = state.user.role === "admin";
  return `
    <article class="app-card">
      <div class="app-card-head">
        <span class="app-tile-icon">${icon(application.mode === "desktop" ? "monitor" : "app")}</span>
        <span class="badge ${application.enabled ? "active" : "disabled"}">${application.enabled ? application.mode : "disabled"}</span>
      </div>
      <h3>${escapeHtml(application.name)}</h3>
      <p>${escapeHtml(application.description || `${application.mode === "desktop" ? "Full desktop" : "RemoteApp"} on ${application.hostName}`)}</p>
      <div class="app-meta">
        <span class="table-secondary">${escapeHtml(application.hostName)}</span>
        ${
          admin
            ? `<button class="action-button" data-edit-app="${application.id}" type="button" aria-label="Edit">${icon("edit")}</button>
               <button class="action-button danger" data-delete-app="${application.id}" type="button" aria-label="Delete">${icon("trash")}</button>`
            : ""
        }
        <button class="button primary" data-launch-app="${application.id}" type="button">${icon("launch")} Launch</button>
      </div>
    </article>
  `;
}

async function renderApplications() {
  const content = document.querySelector("#content");
  await loadApplications();
  const admin = state.user.role === "admin";
  if (admin && !state.hosts.length) state.hosts = (await api("/api/hosts")).hosts;
  document.querySelector("#topbar-actions").innerHTML = admin
    ? `<button class="button primary" id="add-app" type="button">${icon("plus")} Publish app</button>`
    : "";
  content.innerHTML = `
    <div class="page-heading">
      <div><p class="eyebrow">${admin ? "Application delivery" : "Launchpad"}</p><h1>${admin ? "Published applications" : "My applications"}</h1><p>${admin ? "Control which desktops and apps are available to users." : "Secure access to the tools assigned to your account."}</p></div>
    </div>
    ${
      state.applications.length
        ? `<div class="app-grid">${state.applications.map(applicationCard).join("")}</div>`
        : emptyState(
            admin ? "Nothing published yet" : "No applications assigned",
            admin
              ? "Add a host first, then publish a desktop or RemoteApp."
              : "Ask your administrator to assign an application to your account.",
          )
    }
  `;
  if (admin) {
    document.querySelector("#add-app").addEventListener("click", () => openApplicationModal());
    document.querySelectorAll("[data-edit-app]").forEach((button) =>
      button.addEventListener("click", () =>
        openApplicationModal(state.applications.find((app) => app.id === button.dataset.editApp)),
      ),
    );
    document.querySelectorAll("[data-delete-app]").forEach((button) =>
      button.addEventListener("click", () => deleteApplication(button.dataset.deleteApp)),
    );
  }
  document.querySelectorAll("[data-launch-app]").forEach((button) =>
    button.addEventListener("click", () =>
      openLaunchModal(state.applications.find((app) => app.id === button.dataset.launchApp)),
    ),
  );
}

function openDialog(html) {
  modalContent.innerHTML = html;
  modal.showModal();
  modalContent.querySelectorAll("[data-close-modal]").forEach((button) =>
    button.addEventListener("click", () => modal.close()),
  );
}

function modalHeader(title, subtitle) {
  return `
    <header class="modal-header">
      <div><h2>${escapeHtml(title)}</h2><p>${escapeHtml(subtitle)}</p></div>
      <button class="close-modal" data-close-modal type="button" aria-label="Close">${icon("close")}</button>
    </header>
  `;
}

function openApplicationModal(application = null) {
  if (!state.hosts.length) {
    toast("Add a host before publishing an application.", "error");
    return;
  }
  const current = application || {
    hostId: state.hosts[0].id,
    name: "",
    description: "",
    mode: "desktop",
    remoteApp: "",
    workingDirectory: "",
    arguments: "",
    enablePrinting: true,
    enableFileTransfer: true,
    enableAudio: true,
    enabled: true,
  };
  openDialog(`
    <form id="application-form">
      ${modalHeader(application ? "Edit application" : "Publish application", "Deliver a desktop or RemoteApp through the browser.")}
      <div class="modal-body form-grid two">
        <div class="field"><label for="app-name">Display name</label><input id="app-name" name="name" value="${escapeHtml(current.name)}" required maxlength="80" /></div>
        <div class="field"><label for="app-host">Host</label><select id="app-host" name="hostId">${state.hosts.map((host) => `<option value="${host.id}" ${host.id === current.hostId ? "selected" : ""}>${escapeHtml(host.name)}</option>`).join("")}</select></div>
        <div class="field full"><label for="app-description">Description</label><textarea id="app-description" name="description" maxlength="500">${escapeHtml(current.description)}</textarea></div>
        <div class="field"><label for="app-mode">Delivery mode</label><select id="app-mode" name="mode"><option value="desktop" ${current.mode === "desktop" ? "selected" : ""}>Full desktop</option><option value="remoteapp" ${current.mode === "remoteapp" ? "selected" : ""}>RemoteApp</option></select></div>
        <div class="field" id="remote-app-field"><label for="remote-app">RemoteApp alias</label><input id="remote-app" name="remoteApp" value="${escapeHtml(current.remoteApp)}" maxlength="255" placeholder="notepad" /><small>Alias configured in Windows RemoteApp, with or without ||.</small></div>
        <div class="field"><label for="working-dir">Working directory</label><input id="working-dir" name="workingDirectory" value="${escapeHtml(current.workingDirectory)}" maxlength="500" /></div>
        <div class="field"><label for="arguments">Arguments</label><input id="arguments" name="arguments" value="${escapeHtml(current.arguments)}" maxlength="1000" /></div>
        <div class="field full"><span class="field-label">Session features</span><div class="check-grid">
          <label class="check-row"><input type="checkbox" name="enablePrinting" ${current.enablePrinting ? "checked" : ""} /> PDF printing</label>
          <label class="check-row"><input type="checkbox" name="enableFileTransfer" ${current.enableFileTransfer ? "checked" : ""} /> File transfer</label>
          <label class="check-row"><input type="checkbox" name="enableAudio" ${current.enableAudio ? "checked" : ""} /> Audio output</label>
          <label class="check-row"><input type="checkbox" name="enabled" ${current.enabled ? "checked" : ""} /> Application enabled</label>
        </div></div>
      </div>
      <footer class="modal-footer"><button class="button ghost" data-close-modal type="button">Cancel</button><button class="button primary" type="submit">${application ? "Save changes" : "Publish application"}</button></footer>
    </form>
  `);
  const mode = document.querySelector("#app-mode");
  const remoteField = document.querySelector("#remote-app-field");
  const updateMode = () => {
    const input = remoteField.querySelector("input");
    remoteField.style.opacity = mode.value === "remoteapp" ? "1" : ".45";
    input.required = mode.value === "remoteapp";
    input.disabled = mode.value !== "remoteapp";
  };
  mode.addEventListener("change", updateMode);
  updateMode();
  document.querySelector("#application-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    const form = new FormData(event.currentTarget);
    const body = Object.fromEntries(form);
    for (const key of ["enablePrinting", "enableFileTransfer", "enableAudio", "enabled"]) {
      body[key] = form.has(key);
    }
    if (body.mode === "desktop") body.remoteApp = "";
    buttonLoading(button, true);
    try {
      await api(application ? `/api/applications/${application.id}` : "/api/applications", {
        method: application ? "PUT" : "POST",
        body: JSON.stringify(body),
      });
      modal.close();
      toast(application ? "Application updated." : "Application published.");
      await renderApplications();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      buttonLoading(button, false);
    }
  });
}

async function deleteApplication(id) {
  const application = state.applications.find((item) => item.id === id);
  if (!confirm(`Delete "${application.name}"? User assignments for it will also be removed.`)) return;
  try {
    await api(`/api/applications/${id}`, { method: "DELETE" });
    toast("Application deleted.");
    await renderApplications();
  } catch (error) {
    toast(error.message, "error");
  }
}

function openLaunchModal(application) {
  const selectedHost = state.hosts.find((host) => host.id === application.hostId);
  openDialog(`
    <form id="launch-form">
      ${modalHeader(`Launch ${application.name}`, "Credentials are sent only inside a short-lived encrypted gateway ticket.")}
      <div class="modal-body form-grid">
        <div class="notice">OpenRemote does not store the Windows password entered here. The launch ticket expires in 45 seconds.</div>
        <div class="field"><label for="windows-user">Windows username</label><input id="windows-user" name="username" required autocomplete="username" placeholder="jsmith" /></div>
        <div class="field"><label for="windows-password">Windows password</label><input id="windows-password" name="password" type="password" required autocomplete="current-password" /></div>
        <div class="field"><label for="windows-domain">Domain <span class="subtle">(optional)</span></label><input id="windows-domain" name="domain" value="${escapeHtml(selectedHost?.domain || "")}" autocomplete="organization" /></div>
      </div>
      <footer class="modal-footer"><button class="button ghost" data-close-modal type="button">Cancel</button><button class="button primary" type="submit">${icon("launch")} Open remote session</button></footer>
    </form>
  `);
  document.querySelector("#launch-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const popup = window.open("about:blank", "_blank", "noopener");
    const button = event.submitter;
    const body = Object.fromEntries(new FormData(event.currentTarget));
    buttonLoading(button, true);
    try {
      const result = await api(`/api/applications/${application.id}/launch`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      modal.close();
      if (popup) popup.location = result.launchUrl;
      else window.location.assign(result.launchUrl);
      toast("Remote session ticket created.");
    } catch (error) {
      if (popup) popup.close();
      toast(error.message, "error");
    } finally {
      buttonLoading(button, false);
    }
  });
}

async function renderHosts() {
  const content = document.querySelector("#content");
  state.hosts = (await api("/api/hosts")).hosts;
  document.querySelector("#topbar-actions").innerHTML = `<button class="button primary" id="add-host" type="button">${icon("plus")} Add host</button>`;
  const rows = state.hosts
    .map(
      (host) => `
        <tr>
          <td><span class="table-primary">${escapeHtml(host.name)}</span><span class="table-secondary">${escapeHtml(host.protocol.toUpperCase())} · ${escapeHtml(host.hostname)}:${host.port}</span></td>
          <td><span class="badge ${escapeHtml(host.agentStatus)}">${escapeHtml(host.agentStatus)}</span></td>
          <td>${host.cpuPercent == null ? "—" : `${Math.round(host.cpuPercent)}%`}</td>
          <td>${host.memoryPercent == null ? "—" : `${Math.round(host.memoryPercent)}%`}</td>
          <td>${relativeTime(host.lastSeenAt)}</td>
          <td><div class="actions">
            <button class="action-button" data-token-host="${host.id}" type="button" title="Create agent token">${icon("key")}</button>
            <button class="action-button" data-edit-host="${host.id}" type="button" title="Edit">${icon("edit")}</button>
            <button class="action-button danger" data-delete-host="${host.id}" type="button" title="Delete">${icon("trash")}</button>
          </div></td>
        </tr>
      `,
    )
    .join("");
  content.innerHTML = `
    <div class="page-heading"><div><p class="eyebrow">Infrastructure</p><h1>Remote hosts</h1><p>Register Windows RDP servers and monitor their OpenRemote agents.</p></div></div>
    ${
      rows
        ? `<section class="panel"><div class="table-wrap"><table><thead><tr><th>Host</th><th>Agent</th><th>CPU</th><th>Memory</th><th>Last seen</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></section>`
        : emptyState("No hosts registered", "Add the Windows server that will provide desktops and applications.", "hosts")
    }
  `;
  document.querySelector("#add-host").addEventListener("click", () => openHostModal());
  document.querySelectorAll("[data-edit-host]").forEach((button) =>
    button.addEventListener("click", () =>
      openHostModal(state.hosts.find((host) => host.id === button.dataset.editHost)),
    ),
  );
  document.querySelectorAll("[data-delete-host]").forEach((button) =>
    button.addEventListener("click", () => deleteHost(button.dataset.deleteHost)),
  );
  document.querySelectorAll("[data-token-host]").forEach((button) =>
    button.addEventListener("click", () => createAgentToken(button.dataset.tokenHost)),
  );
}

function openHostModal(host = null) {
  const current = host || {
    name: "",
    hostname: "",
    port: 3389,
    protocol: "rdp",
    domain: "",
    tlsMode: "verify",
    enabled: true,
  };
  openDialog(`
    <form id="host-form">
      ${modalHeader(host ? "Edit host" : "Add remote host", "OpenRemote connects to this server through the private gateway network.")}
      <div class="modal-body form-grid two">
        <div class="field"><label for="host-name">Display name</label><input id="host-name" name="name" value="${escapeHtml(current.name)}" required maxlength="80" placeholder="Production RDS" /></div>
        <div class="field"><label for="host-protocol">Protocol</label><select id="host-protocol" name="protocol"><option value="rdp" ${current.protocol === "rdp" ? "selected" : ""}>RDP</option><option value="vnc" ${current.protocol === "vnc" ? "selected" : ""}>VNC</option><option value="ssh" ${current.protocol === "ssh" ? "selected" : ""}>SSH</option></select></div>
        <div class="field"><label for="hostname">Hostname / private IP</label><input id="hostname" name="hostname" value="${escapeHtml(current.hostname)}" required maxlength="255" placeholder="10.10.0.20" /></div>
        <div class="field"><label for="port">Port</label><input id="port" name="port" value="${current.port}" required type="number" min="1" max="65535" /></div>
        <div class="field"><label for="domain">Default Windows domain</label><input id="domain" name="domain" value="${escapeHtml(current.domain)}" maxlength="255" placeholder="ACME" /></div>
        <div class="field"><label for="tls-mode">Certificate validation</label><select id="tls-mode" name="tlsMode"><option value="verify" ${current.tlsMode === "verify" ? "selected" : ""}>Verify certificate</option><option value="ignore" ${current.tlsMode === "ignore" ? "selected" : ""}>Ignore self-signed certificate</option></select></div>
        <div class="field full"><label class="check-row"><input type="checkbox" name="enabled" ${current.enabled ? "checked" : ""} /> Host enabled for new sessions</label></div>
      </div>
      <footer class="modal-footer"><button class="button ghost" data-close-modal type="button">Cancel</button><button class="button primary" type="submit">${host ? "Save changes" : "Add host"}</button></footer>
    </form>
  `);
  document.querySelector("#host-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    const form = new FormData(event.currentTarget);
    const body = Object.fromEntries(form);
    body.port = Number(body.port);
    body.enabled = form.has("enabled");
    buttonLoading(button, true);
    try {
      await api(host ? `/api/hosts/${host.id}` : "/api/hosts", {
        method: host ? "PUT" : "POST",
        body: JSON.stringify(body),
      });
      modal.close();
      toast(host ? "Host updated." : "Host added.");
      await renderHosts();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      buttonLoading(button, false);
    }
  });
}

async function deleteHost(id) {
  const host = state.hosts.find((item) => item.id === id);
  if (!confirm(`Delete "${host.name}" and all applications published from it?`)) return;
  try {
    await api(`/api/hosts/${id}`, { method: "DELETE" });
    toast("Host deleted.");
    await renderHosts();
  } catch (error) {
    toast(error.message, "error");
  }
}

async function createAgentToken(hostId) {
  if (!confirm("Create a new agent token? Any previous token for this host will stop working.")) return;
  try {
    const result = await api(`/api/hosts/${hostId}/agent-token`, { method: "POST" });
    openDialog(`
      ${modalHeader("Agent token created", "Copy this token now. It cannot be shown again.")}
      <div class="modal-body form-grid">
        <div class="notice">Store this token securely on the matching Windows host.</div>
        <div class="code-box" id="agent-token">${escapeHtml(result.token)}</div>
        <button class="button secondary" id="copy-agent-token" type="button">Copy token</button>
      </div>
      <footer class="modal-footer"><button class="button primary" data-close-modal type="button">Done</button></footer>
    `);
    document.querySelector("#copy-agent-token").addEventListener("click", async () => {
      await navigator.clipboard.writeText(result.token);
      toast("Agent token copied.");
    });
    await renderHosts();
  } catch (error) {
    toast(error.message, "error");
  }
}

async function renderUsers() {
  const content = document.querySelector("#content");
  [state.users, state.applications] = await Promise.all([
    api("/api/users").then((result) => result.users),
    api("/api/applications").then((result) => result.applications),
  ]);
  document.querySelector("#topbar-actions").innerHTML = `<button class="button primary" id="add-user" type="button">${icon("plus")} Add user</button>`;
  const rows = state.users
    .map(
      (user) => `
        <tr>
          <td><span class="table-primary">${escapeHtml(user.displayName)}</span><span class="table-secondary">${escapeHtml(user.email)}</span></td>
          <td><span class="badge ${user.status}">${escapeHtml(user.status)}</span></td>
          <td>${escapeHtml(user.role)}</td>
          <td>${user.totpEnabled ? '<span class="badge active">Enabled</span>' : '<span class="table-secondary">Not enabled</span>'}</td>
          <td>${user.applicationIds.length}</td>
          <td><div class="actions">
            <button class="action-button" data-assign-user="${user.id}" type="button" title="Application access">${icon("apps")}</button>
            <button class="action-button" data-edit-user="${user.id}" type="button" title="Edit">${icon("edit")}</button>
          </div></td>
        </tr>
      `,
    )
    .join("");
  content.innerHTML = `
    <div class="page-heading"><div><p class="eyebrow">Identity and access</p><h1>Workspace users</h1><p>Create accounts, manage roles, and assign applications.</p></div></div>
    <section class="panel"><div class="table-wrap"><table><thead><tr><th>User</th><th>Status</th><th>Role</th><th>2FA</th><th>Apps</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></section>
  `;
  document.querySelector("#add-user").addEventListener("click", () => openUserModal());
  document.querySelectorAll("[data-edit-user]").forEach((button) =>
    button.addEventListener("click", () =>
      openUserModal(state.users.find((user) => user.id === button.dataset.editUser)),
    ),
  );
  document.querySelectorAll("[data-assign-user]").forEach((button) =>
    button.addEventListener("click", () =>
      openAssignmentsModal(state.users.find((user) => user.id === button.dataset.assignUser)),
    ),
  );
}

function openUserModal(user = null) {
  openDialog(`
    <form id="user-form">
      ${modalHeader(user ? "Edit user" : "Add workspace user", user ? "Update role, status, or password." : "Create credentials for a new remote access user.")}
      <div class="modal-body form-grid two">
        <div class="field"><label for="user-name">Display name</label><input id="user-name" name="displayName" value="${escapeHtml(user?.displayName || "")}" required maxlength="80" /></div>
        ${
          user
            ? ""
            : '<div class="field"><label for="user-email">Email</label><input id="user-email" name="email" type="email" required maxlength="254" /></div>'
        }
        <div class="field"><label for="user-role">Role</label><select id="user-role" name="role"><option value="user" ${user?.role !== "admin" ? "selected" : ""}>User</option><option value="admin" ${user?.role === "admin" ? "selected" : ""}>Administrator</option></select></div>
        ${
          user
            ? `<div class="field"><label for="user-status">Status</label><select id="user-status" name="status"><option value="active" ${user.status === "active" ? "selected" : ""}>Active</option><option value="disabled" ${user.status === "disabled" ? "selected" : ""}>Disabled</option></select></div>`
            : ""
        }
        <div class="field full"><label for="user-password">${user ? "New password (optional)" : "Initial password"}</label><input id="user-password" name="password" type="password" minlength="12" ${user ? "" : "required"} autocomplete="new-password" /><small>12+ characters with uppercase, lowercase, number, and symbol.</small></div>
      </div>
      <footer class="modal-footer"><button class="button ghost" data-close-modal type="button">Cancel</button><button class="button primary" type="submit">${user ? "Save changes" : "Create user"}</button></footer>
    </form>
  `);
  document.querySelector("#user-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    const body = Object.fromEntries(new FormData(event.currentTarget));
    if (!body.password) delete body.password;
    buttonLoading(button, true);
    try {
      await api(user ? `/api/users/${user.id}` : "/api/users", {
        method: user ? "PUT" : "POST",
        body: JSON.stringify(body),
      });
      modal.close();
      toast(user ? "User updated." : "User created.");
      await renderUsers();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      buttonLoading(button, false);
    }
  });
}

function openAssignmentsModal(user) {
  openDialog(`
    <form id="assignments-form">
      ${modalHeader("Application access", `Choose what ${user.displayName} can launch.`)}
      <div class="modal-body form-grid">
        ${
          state.applications.length
            ? `<div class="check-grid">${state.applications.map((application) => `<label class="check-row"><input type="checkbox" name="applicationIds" value="${application.id}" ${user.applicationIds.includes(application.id) ? "checked" : ""} /> ${escapeHtml(application.name)}</label>`).join("")}</div>`
            : '<div class="notice">Publish an application before assigning access.</div>'
        }
      </div>
      <footer class="modal-footer"><button class="button ghost" data-close-modal type="button">Cancel</button><button class="button primary" type="submit">Save access</button></footer>
    </form>
  `);
  document.querySelector("#assignments-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    const form = new FormData(event.currentTarget);
    const applicationIds = form.getAll("applicationIds");
    buttonLoading(button, true);
    try {
      await api(`/api/users/${user.id}/assignments`, {
        method: "PUT",
        body: JSON.stringify({ applicationIds }),
      });
      modal.close();
      toast("Application access updated.");
      await renderUsers();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      buttonLoading(button, false);
    }
  });
}

async function renderSecurity() {
  const content = document.querySelector("#content");
  content.innerHTML = `
    <div class="page-heading"><div><p class="eyebrow">Account protection</p><h1>Security settings</h1><p>Strengthen access to your OpenRemote workspace.</p></div></div>
    <div class="security-grid">
      <section class="panel security-card">
        <span class="stat-icon">${icon("security")}</span>
        <h3>Two-factor authentication</h3>
        <p>Use any TOTP-compatible authenticator to protect your account even if your password is exposed.</p>
        <div class="security-state">
          <span class="badge ${state.user.totpEnabled ? "active" : "unregistered"}">${state.user.totpEnabled ? "Enabled" : "Not enabled"}</span>
          <button class="button ${state.user.totpEnabled ? "danger" : "primary"}" id="totp-action" type="button">${state.user.totpEnabled ? "Disable 2FA" : "Set up 2FA"}</button>
        </div>
      </section>
      <section class="panel security-card">
        <span class="stat-icon">${icon("key")}</span>
        <h3>Password security</h3>
        <p>Passwords use salted scrypt hashing. Repeated failures trigger account lockout and audit events.</p>
        <div class="security-state"><span class="badge active">Protected</span><span class="subtle">Session: 12 hours</span></div>
      </section>
    </div>
  `;
  document.querySelector("#totp-action").addEventListener("click", () => {
    if (state.user.totpEnabled) openDisableTotpModal();
    else startTotpSetup();
  });
}

async function startTotpSetup() {
  try {
    const result = await api("/api/me/totp/start", { method: "POST" });
    openDialog(`
      <form id="totp-enable-form">
        ${modalHeader("Set up two-factor authentication", "Add this account to your authenticator app, then verify a code.")}
        <div class="modal-body form-grid">
          <div class="notice">In your authenticator app choose “enter setup key” and use the secret below.</div>
          <div class="field"><span class="field-label">Setup secret</span><div class="code-box">${escapeHtml(result.secret)}</div></div>
          <div class="field"><label for="totp-code">Six-digit code</label><input id="totp-code" name="code" required inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" /></div>
        </div>
        <footer class="modal-footer"><button class="button ghost" data-close-modal type="button">Cancel</button><button class="button primary" type="submit">Verify and enable</button></footer>
      </form>
    `);
    document.querySelector("#totp-enable-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = event.submitter;
      const body = Object.fromEntries(new FormData(event.currentTarget));
      buttonLoading(button, true);
      try {
        await api("/api/me/totp/enable", { method: "POST", body: JSON.stringify(body) });
        state.user.totpEnabled = true;
        modal.close();
        toast("Two-factor authentication enabled.");
        await renderSecurity();
      } catch (error) {
        toast(error.message, "error");
      } finally {
        buttonLoading(button, false);
      }
    });
  } catch (error) {
    toast(error.message, "error");
  }
}

function openDisableTotpModal() {
  openDialog(`
    <form id="totp-disable-form">
      ${modalHeader("Disable two-factor authentication", "Confirm your password to remove authenticator protection.")}
      <div class="modal-body form-grid">
        <div class="notice">Your account will be protected only by its password after this change.</div>
        <div class="field"><label for="confirm-password">Current password</label><input id="confirm-password" name="password" type="password" required autocomplete="current-password" /></div>
      </div>
      <footer class="modal-footer"><button class="button ghost" data-close-modal type="button">Cancel</button><button class="button danger" type="submit">Disable 2FA</button></footer>
    </form>
  `);
  document.querySelector("#totp-disable-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = event.submitter;
    const body = Object.fromEntries(new FormData(event.currentTarget));
    buttonLoading(button, true);
    try {
      await api("/api/me/totp/disable", { method: "POST", body: JSON.stringify(body) });
      state.user.totpEnabled = false;
      modal.close();
      toast("Two-factor authentication disabled.");
      await renderSecurity();
    } catch (error) {
      toast(error.message, "error");
    } finally {
      buttonLoading(button, false);
    }
  });
}

async function renderAudit() {
  const content = document.querySelector("#content");
  state.events = (await api("/api/audit?limit=150")).events;
  const rows = state.events
    .map(
      (event) => `
        <tr>
          <td><span class="table-primary">${escapeHtml(event.action.replaceAll(".", " · "))}</span><span class="table-secondary">${escapeHtml(event.targetType || "system")}</span></td>
          <td>${escapeHtml(event.actorName)}</td>
          <td>${escapeHtml(event.ipAddress || "—")}</td>
          <td>${formatDate(event.createdAt)}</td>
        </tr>
      `,
    )
    .join("");
  content.innerHTML = `
    <div class="page-heading"><div><p class="eyebrow">Accountability</p><h1>Audit trail</h1><p>Review sign-ins, security changes, administration, and session launches.</p></div></div>
    <section class="panel">
      <div class="panel-header"><h3>Recent events</h3><span>${state.events.length} records</span></div>
      <div class="table-wrap"><table><thead><tr><th>Action</th><th>Actor</th><th>IP address</th><th>Time</th></tr></thead><tbody>${rows}</tbody></table></div>
    </section>
  `;
}

async function renderCurrentView() {
  try {
    const renderers = {
      overview: renderOverview,
      applications: renderApplications,
      hosts: renderHosts,
      users: renderUsers,
      security: renderSecurity,
      audit: renderAudit,
    };
    await renderers[state.view]();
  } catch (error) {
    toast(error.message, "error");
    document.querySelector("#content").innerHTML = emptyState(
      "Could not load this page",
      error.message,
    );
  }
}

modal.addEventListener("click", (event) => {
  if (event.target === modal) modal.close();
});

async function bootstrap() {
  try {
    const setup = await api("/api/setup/status");
    if (setup.setupRequired) return renderSetup();
    try {
      const me = await api("/api/me");
      state.user = me.user;
      state.csrfToken = me.csrfToken;
      await renderShell();
    } catch (error) {
      if (error.code !== "authentication_required") throw error;
      renderLogin();
    }
  } catch (error) {
    root.innerHTML = `
      <div class="boot-screen">
        <div class="brand-mark large"><span></span><span></span></div>
        <h2>OpenRemote could not start</h2>
        <p>${escapeHtml(error.message)}</p>
      </div>
    `;
  }
}

bootstrap();
