(function () {
  "use strict";

  const state = {
    lang: localStorage.getItem("vishwas_lang") || "en",
    dict: {},
    user: null,
    token: localStorage.getItem("vishwas_token") || "",
    meta: null,
    pendingMfa: null,
    notifications: [],
    notifOpen: false,
    sidebarOpen: false,
    live: false,
    highContrast: localStorage.getItem("vishwas_hc") === "1",
    emails: [],
    summary: null,
    forensicTab: "overview",
    threatRange: "7d",
  };

  const ROLE_NAV = {
    SUPER_ADMIN: "*",
    SECURITY_ADMIN: ["dashboard", "email", "intel", "incidents", "reports", "audit", "admin", "health"],
    SECURITY_ANALYST: ["dashboard", "email", "intel", "incidents", "reports", "health"],
    INVESTIGATOR: ["dashboard", "email", "intel", "incidents", "audit", "reports"],
    AUDITOR: ["dashboard", "reports", "audit"],
    VIEWER: ["dashboard", "reports"],
  };

  function t(key) {
    return (state.dict && state.dict[key]) || key;
  }

  async function loadI18n() {
    const res = await fetch("/assets/i18n/" + state.lang + ".json");
    state.dict = await res.json();
    document.documentElement.lang = state.lang === "hi" ? "hi" : "en";
  }

  function apiHeaders() {
    const h = { "Content-Type": "application/json" };
    if (state.token) h.Authorization = "Bearer " + state.token;
    return h;
  }

  async function api(path, opts) {
    const res = await fetch(path, Object.assign({ headers: apiHeaders(), credentials: "include" }, opts || {}));
    const data = await res.json().catch(function () { return {}; });
    if (!res.ok) throw new Error(data.detail || res.statusText);
    return data;
  }

  function route() {
    const hash = (location.hash || "#/").replace(/^#/, "");
    const parts = hash.split("/").filter(Boolean);
    return { path: hash, parts: parts };
  }

  function can(module) {
    if (!state.user) return false;
    const allow = ROLE_NAV[state.user.role] || [];
    return allow === "*" || allow.indexOf(module) !== -1;
  }

  function badge(level) {
    const L = String(level || "").toUpperCase();
    let cls = "info";
    if (L.indexOf("PASS") >= 0 || L === "OPERATIONAL" || L === "RESOLVED" || L === "CLOSED" || L === "LOW" || L === "VERIFIED" || L === "ACTIVE") cls = "ok";
    else if (L.indexOf("WARN") >= 0 || L === "MEDIUM" || L === "ASSIGNED" || L === "SOFTFAIL" || L === "NONE") cls = "warn";
    else if (L === "HIGH" || L === "CONTAINED" || L.indexOf("HIGH") >= 0) cls = "high";
    else if (L.indexOf("FAIL") >= 0 || L === "CRITICAL" || L === "NEW") cls = "crit";
    return '<span class="badge ' + cls + '" aria-label="' + esc(L) + '">[ ' + esc(L) + " ]</span>";
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function govHeader(activeTop) {
    return (
      '<header class="gov-top" role="banner">' +
        '<div class="gov-org">' +
          '<div class="emblem" aria-hidden="true">EMBL<br>PH</div>' +
          '<div><strong>' + esc(t("gov")) + "</strong><span>" + esc(t("dept")) + "</span></div>" +
        "</div>" +
        '<nav class="gov-links" aria-label="Utility">' +
          '<a href="#/help">' + esc(t("help")) + "</a>" +
          '<button type="button" class="linkish" id="btnA11y">' + esc(t("accessibility")) + "</button>" +
          '<a href="#/contact">' + esc(t("contact")) + "</a>" +
          '<span>' + esc(t("language")) + ': <a href="#" id="langEn">English</a> | <a href="#" id="langHi">हिन्दी</a></span>' +
          (state.user
            ? '<span>' + esc(state.user.name) + " · " + esc(state.user.role.replace(/_/g, " ")) + ' · <a href="#/logout" id="doLogout">' + esc(t("logout")) + "</a></span>"
            : '<a href="#/login">' + esc(t("login")) + "</a>") +
        "</nav>" +
      "</header>" +
      '<div class="brand-bar">' +
        '<div class="brand-lockup">' +
          '<button type="button" class="btn btn-sec menu-toggle" id="menuBtn" aria-label="Open navigation">Menu</button>' +
          '<div class="logo-mark" aria-hidden="true">V</div>' +
          "<div><h1>VISHWAS</h1><p>" + esc(t("platform")) + "</p></div>" +
        "</div>" +
        '<div class="brand-tools">' +
          (state.user ? '<span class="live-pill' + (state.live ? " on" : "") + '" id="livePill"><span class="dot" aria-hidden="true"></span> ' + esc(t("live")) + "</span>" : "") +
          (state.user ? '<button type="button" class="btn btn-sec" id="notifBtn" aria-label="Notifications">Notifications</button>' : "") +
          (state.user ? '<a class="btn btn-sec" href="#/search">' + esc(t("search")) + "</a>" : "") +
        "</div>" +
      "</div>" +
      (state.meta && state.meta.demo
        ? '<div class="demo-banner" role="status"><strong>' + esc(t("demoData")) + "</strong> — " + esc(t("notOfficial")) + "</div>"
        : "") +
      '<nav class="primary-nav" aria-label="Primary">' +
        navLink("#/", "home", activeTop) +
        (state.user ? navLink("#/dashboard", "dashboard", activeTop) : "") +
        (can("email") ? navLink("#/email/forensics", "emailForensics", activeTop) : "") +
        (can("intel") ? navLink("#/intel/ioc", "threatIntel", activeTop) : "") +
        (can("incidents") ? navLink("#/incidents", "incidents", activeTop) : "") +
        (can("reports") ? navLink("#/reports", "reports", activeTop) : "") +
        (can("dashboard") ? navLink("#/dashboard/executive", "analytics", activeTop) : "") +
        (can("admin") ? navLink("#/admin/users", "administration", activeTop) : "") +
      "</nav>"
    );
  }

  function navLink(href, key, activeTop) {
    const cur = location.hash.indexOf(href.replace("#", "")) >= 0 || (href === "#/" && (location.hash === "" || location.hash === "#/"));
    return '<a href="' + href + '"' + (cur ? ' aria-current="page"' : "") + ">" + esc(t(key)) + "</a>";
  }

  function sidebar() {
    if (!state.user) return "";
    return (
      '<aside class="sidebar" id="sidebar" aria-label="Section navigation">' +
        '<button type="button" class="btn btn-sec collapse-btn" id="collapseSb">Collapse menu</button>' +
        "<h2>VISHWAS</h2>" +
        (can("dashboard") ? '<a href="#/dashboard">' + esc(t("dashboard")) + "</a>" : "") +
        (can("email")
          ? "<h2>Email Security</h2>" +
            '<a class="sub" href="#/email/inbox">Email Inbox</a>' +
            '<a class="sub" href="#/email/threats">Threat Inbox</a>' +
            '<a class="sub" href="#/email/forensics">Email Forensics</a>' +
            '<a class="sub" href="#/email/headers">Header Analysis</a>' +
            '<a class="sub" href="#/email/auth">Authentication Analysis</a>'
          : "") +
        (can("intel")
          ? "<h2>Threat Intelligence</h2>" +
            '<a class="sub" href="#/intel/ioc">IOC Database</a>' +
            '<a class="sub" href="#/intel/domain">Domain Intelligence</a>' +
            '<a class="sub" href="#/intel/ip">IP Intelligence</a>' +
            '<a class="sub" href="#/intel/url">URL Intelligence</a>' +
            '<a class="sub" href="#/intel/geo">GeoIP Analysis</a>'
          : "") +
        (can("incidents")
          ? "<h2>Incident Management</h2>" +
            '<a class="sub" href="#/incidents">Incidents</a>' +
            '<a class="sub" href="#/investigate">Investigations</a>' +
            '<a class="sub" href="#/incidents">Cases</a>' +
            '<a class="sub" href="#/investigate">Timeline</a>'
          : "") +
        (can("reports")
          ? "<h2>Reports</h2>" +
            '<a class="sub" href="#/reports">Security Reports</a>' +
            '<a class="sub" href="#/reports">Forensic Reports</a>' +
            '<a class="sub" href="#/reports">Executive Reports</a>' +
            '<a class="sub" href="#/reports">Export Center</a>'
          : "") +
        (can("audit")
          ? "<h2>Audit &amp; Compliance</h2>" +
            '<a class="sub" href="#/audit">Audit Trail</a>' +
            '<a class="sub" href="#/custody">Chain of Custody</a>' +
            '<a class="sub" href="#/audit">Access Logs</a>'
          : "") +
        (can("admin")
          ? "<h2>Administration</h2>" +
            '<a class="sub" href="#/admin/users">Users</a>' +
            '<a class="sub" href="#/admin/roles">Roles</a>' +
            '<a class="sub" href="#/admin/mailboxes">Mailboxes</a>' +
            '<a class="sub" href="#/admin/settings">System Settings</a>'
          : "") +
        (can("health") ? '<a href="#/health">System Health</a>' : "") +
        '<a href="#/help">Help &amp; Support</a>' +
      "</aside>"
    );
  }

  function footer() {
    const v = (state.meta && state.meta.version) || "VISHWAS v1.0";
    const st = (state.meta && state.meta.status) || t("operational");
    return (
      '<footer class="footer">' +
        '<div class="footer-grid">' +
          "<div><strong>VISHWAS</strong><br>" + esc(t("platform")) + "</div>" +
          "<div><strong>Important Links</strong><br>" +
            '<a href="#/privacy">' + esc(t("privacy")) + "</a><br>" +
            '<a href="#/security">' + esc(t("securityPolicy")) + "</a><br>" +
            '<a href="#/help">' + esc(t("help")) + "</a><br>" +
            '<a href="#/contact">' + esc(t("contact")) + "</a></div>" +
          "<div><strong>System Information</strong><br>" +
            esc(t("version")) + ": " + esc(v) + "<br>" +
            esc(t("lastUpdated")) + ": " + esc((state.meta && state.meta.last_updated) || "") + "<br>" +
            esc(t("systemStatus")) + ": " + badge(st) + "</div>" +
          "<div>" + esc(t("footerCopy")) + "</div>" +
        "</div>" +
        '<p class="disclaimer">' + esc(t("notOfficial")) + "</p>" +
      "</footer>"
    );
  }

  function shell(mainHtml, opts) {
    opts = opts || {};
    const notif = state.notifOpen
      ? '<div class="notif-panel" role="dialog" aria-label="Notifications"><h3>Notification Centre</h3>' +
        (state.notifications.map(function (n) {
          return '<div class="notif-item"><strong>' + esc(n.type) + "</strong><br>" + esc(n.title) +
            '<div class="help">' + esc(n.time) + (n.demo ? " · " + t("demoData") : "") + "</div></div>";
        }).join("") || '<div class="notif-item">No notifications.</div>') +
        "</div>"
      : "";
    return (
      govHeader(opts.top) +
      '<div class="app-shell">' +
        (opts.public ? "" : sidebar()) +
        '<main id="main" class="main" tabindex="-1">' + mainHtml + "</main>" +
      "</div>" +
      notif +
      footer()
    );
  }

  function viewHome() {
    return shell(
      '<article class="home-hero">' +
        "<p class=\"help\">" + esc(t("gov")) + " · VISHWAS</p>" +
        "<h1>VISHWAS</h1>" +
        "<p><strong>Email Forensics &amp; Business Email Compromise Detection</strong></p>" +
        "<p>" + esc(t("tagline")) + "</p>" +
        '<p class="btn-row">' +
          '<a class="btn" href="#/login">' + esc(t("loginHero")) + "</a>" +
          '<a class="btn btn-sec" href="#/help">' + esc(t("sysInfo")) + "</a>" +
          '<a class="btn btn-sec" href="#/help">' + esc(t("help")) + "</a>" +
        "</p>" +
        '<p class="help">' + esc(t("notOfficial")) + "</p>" +
      "</article>" +
      '<section class="section"><h2>' + esc(t("capabilities")) + "</h2>" +
        '<div class="cap-grid">' +
          cap("Email Forensics", "Header, MIME and routing analysis") +
          cap("BEC Detection", "Explainable risk scoring 0–100") +
          cap("Threat Intelligence", "Domains, IPs, URLs and hashes") +
          cap("Incident Management", "Official case workflow") +
          cap("Audit &amp; Compliance", "SHA-256 chain of custody") +
          cap("Real-Time Monitoring", "Authenticated WebSocket events") +
        "</div></section>",
      { public: true, top: "home" }
    );
  }

  function cap(title, d) {
    return '<div class="card"><h3>' + title + "</h3><p class=\"desc\">" + d + "</p></div>";
  }

  function viewLogin() {
    return (
      govHeader("login") +
      '<div class="login-layout">' +
        '<section class="login-left">' +
          '<div class="emblem" style="width:56px;height:56px">EMBL<br>PH</div>' +
          "<h1>VISHWAS</h1>" +
          "<p>Email Forensics &amp; Business Email Compromise Detection System</p>" +
          "<p>" + esc(t("secureDesc")) + "</p>" +
          '<p class="help" style="color:#d7e3f0">' + esc(t("notOfficial")) + "</p>" +
        "</section>" +
        '<section class="login-right"><div class="login-panel">' +
          "<h2>" + esc(t("login")) + "</h2>" +
          '<form id="loginForm">' +
            '<label class="field" for="username">' + esc(t("username")) + "</label>" +
            '<input id="username" name="username" type="text" autocomplete="username" required>' +
            '<label class="field" for="password">' + esc(t("password")) + "</label>" +
            '<input id="password" name="password" type="password" autocomplete="current-password" required>' +
            '<label class="field" for="captcha">' + esc(t("captcha")) + ' <span id="captchaQ"></span></label>' +
            '<input id="captcha" name="captcha" type="text" inputmode="numeric" required>' +
            '<input type="hidden" id="captchaToken">' +
            '<p class="btn-row" style="margin-top:16px">' +
              '<button class="btn" type="submit">' + esc(t("loginBtn")) + "</button>" +
              '<button class="btn btn-sec" type="reset">' + esc(t("reset")) + "</button>" +
            "</p>" +
            '<p class="help"><a href="#/help">' + esc(t("forgot")) + "</a> · <a href=\"#/help\">" + esc(t("help")) + "</a> · <a href=\"#/help\">" + esc(t("sysReq")) + "</a></p>" +
            '<p id="loginErr" class="alert crit" hidden></p>' +
          "</form>" +
          "<hr>" +
          "<p><strong>" + esc(t("authorizedOnly")) + "</strong><br>" + esc(t("monitored")) + "</p>" +
          "<p>" + esc(t("systemStatus")) + ": " + badge("OPERATIONAL") + "<br>" +
            esc(t("version")) + ": VISHWAS v1.0</p>" +
          '<p class="help">Demonstration accounts use password <code>Demo@123</code> (for example analyst@vishwas.local). OTP: 123456.</p>' +
        "</div></section>" +
      "</div>" +
      footer()
    );
  }

  function viewMfa() {
    return (
      govHeader("login") +
      '<main id="main" class="main"><div class="login-panel" style="margin:24px auto">' +
        "<h2>" + esc(t("verifyIdentity")) + "</h2>" +
        "<p>" + esc(t("enterOtp")) + "</p>" +
        '<form id="mfaForm">' +
          '<fieldset><legend>Authentication method</legend>' +
            '<label><input type="radio" name="method" value="OTP" checked> ' + esc(t("otpMethod")) + "</label><br>" +
            '<label><input type="radio" name="method" value="AUTHENTICATOR"> ' + esc(t("authApp")) + "</label><br>" +
            '<label><input type="radio" name="method" value="HARDWARE_KEY"> ' + esc(t("hwKey")) + "</label>" +
          "</fieldset>" +
          '<label class="field" for="hwAssert">Hardware security key assertion (demonstration)</label>' +
          '<input id="hwAssert" type="text" placeholder="DEMO-KEY">' +
          '<div class="otp-row" style="margin:12px 0" id="otpBoxes">' +
            [0,1,2,3,4,5].map(function (i) {
              return '<input class="otp" maxlength="1" inputmode="numeric" aria-label="Digit ' + (i + 1) + '">';
            }).join("") +
          "</div>" +
          '<p class="btn-row">' +
            '<button class="btn" type="submit">' + esc(t("verify")) + "</button>" +
            '<button class="btn btn-sec" type="button" id="resendOtp">' + esc(t("resendOtp")) + "</button>" +
          "</p>" +
          '<p class="alert info">' + esc(t("mfaNote")) + "</p>" +
          '<p id="mfaErr" class="alert crit" hidden></p>' +
        "</form>" +
      "</div></main>" +
      footer()
    );
  }

  function summaryCards(s) {
    const items = [
      [t("totalEmails"), s.total_emails, "Processed this period", "+3%"],
      [t("threatsDetected"), s.threats_detected, "Requiring review", "+1"],
      [t("highRisk"), s.high_risk, "HIGH or CRITICAL", "stable"],
      [t("becIncidents"), s.bec_incidents, "BEC classified", "watch"],
      [t("suspiciousDomains"), s.suspicious_domains, "Unique domains", "—"],
      [t("maliciousUrls"), s.malicious_urls, "Extracted URLs", "—"],
      [t("iocMatches"), s.ioc_matches, "Intelligence hits", "—"],
      [t("openInvestigations"), s.open_investigations, "Active cases", "—"],
    ];
    return '<div class="cards">' + items.map(function (it) {
      return '<article class="card"><h3>' + esc(it[0]) + '</h3><div class="num">' + esc(it[1]) +
        '</div><div class="desc">' + esc(it[2]) + '</div><div class="trend">Trend: ' + esc(it[3]) + "</div></article>";
    }).join("") + "</div>";
  }

  function barRow(label, n, max) {
    const pct = max ? Math.round((n / max) * 100) : 0;
    return '<p>' + esc(label) + " (" + n + ')</p><div class="bar" aria-valuenow="' + n + '" role="img" aria-label="' + esc(label) + '"><span style="width:' + pct + '%"></span></div>';
  }

  async function viewDashboard(kind) {
    const s = await api("/api/v1/dashboard/summary");
    state.summary = s;
    let emails = [];
    let incidents = [];
    try {
      if (can("email")) emails = (await api("/api/v1/emails?page_size=20")).items || [];
    } catch (e) { emails = []; }
    try {
      if (can("incidents")) incidents = (await api("/api/v1/incidents")).items || [];
    } catch (e) { incidents = []; }
    const titles = {
      main: t("socDash"),
      executive: t("execDash"),
      soc: t("socDashTitle"),
      forensics: t("forensicDash"),
      intel: t("tiDash"),
      incidents: t("incDash"),
      admin: t("adminDash"),
    };
    const max = Math.max(s.total_emails, 1);
    let extra = "";
    if (kind === "executive") {
      extra = '<section class="section"><h2>Department-wise statistics (placeholder)</h2>' +
        barRow("Finance", 4, 10) + barRow("IT", 6, 10) + barRow("Procurement", 3, 10) +
        "<h2>Response status</h2>" + barRow("Open", s.open_investigations, 10) + "</section>";
    } else if (kind === "soc") {
      extra = '<section class="section"><h2>Live events / threat queue</h2>' + emailTable(emails, true) + "</section>";
    } else if (kind === "forensics") {
      extra = '<section class="section"><h2>Authentication results</h2>' + authSummary(emails) + "</section>";
    } else if (kind === "intel") {
      let iocs = [];
      try { iocs = (await api("/api/v1/iocs")).items || []; } catch (e) { iocs = []; }
      extra = '<section class="section"><h2>IOC statistics</h2>' + iocTable(iocs) + "</section>";
    } else if (kind === "incidents") {
      extra = incidentTable(incidents);
    } else if (kind === "admin") {
      extra = '<section class="section"><h2>System health snapshot</h2><p>Users: session directory · Mailbox: ' +
        (s.demo ? "DEMO MODE" : "configured") + "</p><p><a href=\"#/health\">Open System Health</a></p></section>";
    } else {
      extra =
        '<div class="chart-row">' +
          '<section class="section"><h2>' + esc(t("emailOverview")) + "</h2>" +
            barRow("Total processed", s.total_emails, max) +
            barRow("Clean", s.clean, max) +
            barRow("Suspicious", s.suspicious, max) +
            barRow("High-risk", s.high, max) +
            barRow("Critical", s.critical, max) +
          "</section>" +
          '<section class="section"><h2>' + esc(t("threatTrend")) + "</h2>" +
            '<p class="btn-row">' + ["24h", "7d", "30d", "90d"].map(function (r) {
              return '<button type="button" class="btn btn-sec rangeBtn" data-r="' + r + '">' + r + "</button>";
            }).join("") + "</p>" +
            "<p class=\"help\">Line indication (prototype): emails analysed, threats detected, BEC attempts for selected window " + esc(state.threatRange) + ".</p>" +
            barRow("Emails analysed", s.total_emails, max) +
            barRow("Threats detected", s.threats_detected, max) +
            barRow("BEC attempts", s.bec_incidents, max) +
          "</section>" +
        "</div>" +
        '<section class="section"><h2>' + esc(t("threatCategories")) + "</h2>" +
          "<ul>" +
            "<li>Business Email Compromise</li><li>Domain Spoofing</li><li>Credential Phishing</li>" +
            "<li>Malicious URL</li><li>Suspicious Attachment</li><li>Header Manipulation</li><li>Authentication Failure</li>" +
          "</ul></section>" +
        '<section class="section"><h2>' + esc(t("recentIncidents")) + "</h2>" + incidentTable(incidents) + "</section>";
    }
    const html =
      '<div class="page-head"><div><h1>' + esc(titles[kind] || titles.main) + "</h1>" +
        '<p class="meta-line">' + esc(t("lastUpdated")) + ": " + esc(s.last_updated) + " · " +
        esc(t("systemStatus")) + ": " + badge(s.system_status) +
        (s.demo ? " · " + badge("DEMO DATA") : "") + "</p></div>" +
        '<p class="btn-row"><a class="btn btn-sec" href="#/dashboard">SOC</a>' +
          '<a class="btn btn-sec" href="#/dashboard/executive">Executive</a>' +
          '<a class="btn btn-sec" href="#/dashboard/soc">Operations</a>' +
          '<a class="btn btn-sec" href="#/dashboard/forensics">Forensics</a>' +
          '<a class="btn btn-sec" href="#/dashboard/intel">Intelligence</a>' +
          '<a class="btn btn-sec" href="#/dashboard/incidents">Incidents</a>' +
          (can("admin") ? '<a class="btn btn-sec" href="#/dashboard/admin">Administration</a>' : "") +
        "</p></div>" +
      summaryCards(s) + extra;
    return shell(html, { top: "dashboard" });
  }

  function emailTable(rows, compact) {
    if (!rows.length) return "<p>No records.</p>";
    return '<div class="table-wrap"><table class="data"><thead><tr>' +
      (compact ? "" : "<th>S.No.</th>") +
      "<th>Date &amp; Time</th><th>Sender</th><th>Recipient</th><th>Subject</th><th>Domain</th><th>Threat Type</th><th>Risk Score</th><th>Severity</th><th>Status</th><th>Action</th>" +
      "</tr></thead><tbody>" +
      rows.map(function (e, i) {
        const domain = String(e.from || "").split("@").pop() || "—";
        return "<tr>" +
          (compact ? "" : "<td>" + (i + 1) + "</td>") +
          "<td>" + esc(e.date) + "</td><td>" + esc(e.from) + "</td><td>" + esc(e.to) + "</td><td>" + esc(e.subject) +
          "</td><td>" + esc(domain) + "</td><td>" + esc(e.threat_type) + "</td><td>" + esc(e.risk_score) +
          "</td><td>" + badge(e.risk_level) + "</td><td>" + badge(e.status) +
          '</td><td><a href="#/email/forensics/' + encodeURIComponent(e.email_id) + '">' + t("view") + "</a></td></tr>";
      }).join("") +
      "</tbody></table></div>";
  }

  function incidentTable(rows) {
    if (!rows.length) return "<p>No incidents.</p>";
    return '<div class="table-wrap"><table class="data"><thead><tr><th>Incident ID</th><th>Date</th><th>Threat Type</th><th>Source</th><th>Risk</th><th>Status</th><th>Assigned Officer</th><th>Action</th></tr></thead><tbody>' +
      rows.map(function (i) {
        return "<tr><td>" + esc(i.incident_id) + "</td><td>" + esc(i.date) + "</td><td>" + esc(i.incident_type) +
          "</td><td>" + esc(i.source) + "</td><td>" + badge(i.severity) + "</td><td>" + badge(i.status) +
          "</td><td>" + esc(i.assigned_officer) + '</td><td><a href="#/incidents/' + i.incident_id + '">Open</a></td></tr>';
      }).join("") + "</tbody></table></div>";
  }

  function iocTable(rows) {
    return '<div class="table-wrap"><table class="data"><thead><tr><th>IOC</th><th>Type</th><th>First Seen</th><th>Last Seen</th><th>Risk</th><th>Confidence</th><th>Source</th><th>Occurrences</th><th>Related Incidents</th></tr></thead><tbody>' +
      rows.map(function (x) {
        return "<tr><td>" + esc(x.ioc) + (x.demo ? " " + badge("DEMO DATA") : "") + "</td><td>" + esc(x.type) +
          "</td><td>" + esc(x.first_seen) + "</td><td>" + esc(x.last_seen) + "</td><td>" + badge(x.risk) +
          "</td><td>" + esc(x.confidence) + "</td><td>" + esc(x.source) + "</td><td>" + esc(x.occurrences) +
          "</td><td>" + esc((x.related_incidents || []).join(", ")) + "</td></tr>";
      }).join("") + "</tbody></table></div>";
  }

  function authSummary(emails) {
    return '<div class="table-wrap"><table class="data"><thead><tr><th>Email</th><th>SPF</th><th>DKIM</th><th>DMARC</th></tr></thead><tbody>' +
      emails.map(function (e) {
        const a = e.auth || {};
        return "<tr><td>" + esc(e.subject) + "</td><td>" + badge(a.spf) + "</td><td>" + badge(a.dkim) + "</td><td>" + badge(a.dmarc) + "</td></tr>";
      }).join("") + "</tbody></table></div>";
  }

  async function viewThreatInbox() {
    const data = await api("/api/v1/emails?page_size=50");
    return shell(
      '<div class="page-head"><h1>Threat Inbox</h1></div>' +
      '<form class="toolbar" id="inboxFilter">' +
        '<div class="grow"><label class="field" for="q">Search</label><input id="q" name="q" type="search"></div>' +
        '<div><label class="field" for="severity">Severity</label><select id="severity"><option value="">All</option><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></div>' +
        '<div><label class="field" for="ttype">Threat type</label><input id="ttype" type="text"></div>' +
        '<button class="btn" type="submit">Apply</button>' +
        '<button class="btn btn-sec" type="button" id="exportCsv">Export CSV</button>' +
      "</form>" +
      emailTable(data.items || [], false),
      { top: "emailForensics" }
    );
  }

  async function viewForensic(id) {
    const list = (await api("/api/v1/emails?page_size=50")).items || [];
    const rec = id ? await api("/api/v1/emails/" + encodeURIComponent(id)) : list[0];
    if (!rec) return shell("<p>No email selected. Open an item from Threat Inbox.</p>", { top: "emailForensics" });
    const tab = state.forensicTab;
    const tabs = ["overview", "headers", "authentication", "body", "urls", "attachments", "intel", "timeline", "raw", "custody"];
    const labels = {
      overview: "Overview", headers: "Headers", authentication: "Authentication", body: "Body",
      urls: "URLs", attachments: "Attachments", intel: "Threat Intelligence", timeline: "Timeline",
      raw: "Raw Email", custody: "Chain of Custody",
    };
    let body = "";
    if (tab === "overview") {
      const mismatch = rec.reply_to && rec.from && rec.reply_to.toLowerCase() !== rec.from.toLowerCase();
      body =
        '<table class="data"><tbody>' +
        row("Sender", rec.from, mismatch) + row("Recipient", rec.to) + row("CC", rec.cc) +
        row("Reply-To", rec.reply_to, mismatch) + row("Subject", rec.subject) + row("Date", rec.date) +
        row("Message ID", rec.message_id) + row("Return Path", rec.return_path) +
        "</tbody></table>" +
        (mismatch ? '<p class="alert crit" role="alert">Reply-To mismatch detected. The Reply-To address does not match the From address. Treat reply routing as untrusted until verified.</p>' : "");
    } else if (tab === "headers") {
      body = '<h3>Email Routing Analysis</h3>' + hopTable(rec.geo_hops) +
        '<div class="flow"><div class="step">Origin</div><div class="arrow">↓</div><div class="step">Mail Server</div><div class="arrow">↓</div><div class="step">Intermediate Server</div><div class="arrow">↓</div><div class="step">Destination</div></div>';
    } else if (tab === "authentication") {
      const a = rec.auth || {};
      body = '<h3>Email Authentication Status</h3>' +
        '<div class="cards">' +
          authCard("SPF", a.spf, a.domain, a.spf_alignment, a.dmarc_policy, a.spf_reason, a.evidence) +
          authCard("DKIM", a.dkim, a.domain, a.dkim_alignment, a.dmarc_policy, a.dkim_reason, a.evidence) +
          authCard("DMARC", a.dmarc, a.domain, a.spf_alignment, a.dmarc_policy, a.dmarc_reason, a.evidence) +
        "</div>";
    } else if (tab === "body") {
      body = "<pre>" + esc(rec.body_text) + "</pre>";
    } else if (tab === "urls") {
      body = "<ul>" + (rec.urls || []).map(function (u) { return "<li>" + esc(u) + "</li>"; }).join("") + "</ul>";
    } else if (tab === "attachments") {
      body = '<table class="data"><thead><tr><th>File</th><th>Type</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>' +
        (rec.attachments || []).map(function (f) {
          return "<tr><td>" + esc(f.filename) + "</td><td>" + esc(f.content_type) + "</td><td>" + esc(f.size) + "</td><td>" + esc(f.sha256) + "</td></tr>";
        }).join("") + "</tbody></table>";
    } else if (tab === "intel") {
      body = "<p>Related IOC extraction from this message. Records may be labelled DEMO DATA.</p><ul>" +
        (rec.urls || []).map(function (u) { return "<li>URL: " + esc(u) + "</li>"; }).join("") +
        "<li>Sender domain: " + esc(String(rec.from || "").split("@").pop()) + "</li></ul>";
    } else if (tab === "timeline") {
      body = '<div class="flow">' +
        ["Email Received", "Authentication Check", "BEC Detection", "IOC Extraction", "Threat Intelligence Match", "Incident Created", "Analyst Review", "Resolution"]
          .map(function (s, i, arr) { return '<div class="step">' + s + "</div>" + (i < arr.length - 1 ? '<div class="arrow">↓</div>' : ""); }).join("") +
        "</div>";
    } else if (tab === "raw") {
      body = "<pre>" + esc(rec.raw_preview) + "</pre>";
    } else {
      body = "<p>Evidence ID: " + esc(rec.email_id) + "</p><p>SHA-256:</p><pre>" + esc(rec.hash) + "</pre>" +
        '<button class="btn" type="button" id="verifyHash">VERIFY INTEGRITY</button><p id="verifyOut"></p>';
    }
    const bec = becPanel(rec);
    const html =
      '<div class="page-head"><div><h1>Email Forensic Analysis</h1>' +
        '<p class="meta-line">Case ID: ' + esc(rec.case_id) + " · Email ID: " + esc(rec.email_id) +
        " · Analysis Date: " + esc(rec.date) + " · Analyst: " + esc(state.user.name) +
        " · Risk Score: " + esc(rec.risk_score) + " · Classification: " + badge(rec.classification) +
        (rec.demo ? " · " + badge("DEMO DATA") : "") + "</p></div></div>" +
      '<div class="tabs" role="tablist">' + tabs.map(function (tb) {
        return '<button type="button" role="tab" class="tabBtn" data-tab="' + tb + '" aria-selected="' + (tab === tb) + '">' + labels[tb] + "</button>";
      }).join("") + "</div>" +
      '<section class="section">' + body + "</section>" + bec +
      '<p class="btn-row"><a class="btn" href="#/incidents">Create / open incident</a> <a class="btn btn-sec" href="#/intel/geo">GeoIP map</a></p>';
    const out = shell(html, { top: "emailForensics" });
    return { html: out, after: function () { drawMapIfNeeded(tab, rec); } };
  }

  function row(k, v, warn) {
    return "<tr><th>" + esc(k) + "</th><td" + (warn ? ' style="background:#fdecec"' : "") + ">" + esc(v || "—") + "</td></tr>";
  }

  function hopTable(hops) {
    hops = hops || [];
    return '<div class="table-wrap"><table class="data"><thead><tr><th>Hop Number</th><th>IP Address</th><th>Hostname</th><th>Timestamp</th><th>Country</th><th>ASN</th><th>Provider</th><th>Risk</th></tr></thead><tbody>' +
      hops.map(function (h) {
        return "<tr><td>" + esc(h.hop) + "</td><td>" + esc(h.ip) + "</td><td>" + esc(h.hostname) + "</td><td>" + esc(h.timestamp) +
          "</td><td>" + esc(h.country) + "</td><td>" + esc(h.asn) + "</td><td>" + esc(h.provider || h.isp) + "</td><td>" + badge(h.risk) + "</td></tr>";
      }).join("") + "</tbody></table></div>";
  }

  function authCard(name, status, domain, align, policy, reason, evidence) {
    return '<article class="card"><h3>' + name + "</h3><p>" + badge(status) + "</p>" +
      "<p class=\"desc\">Domain: " + esc(domain) + "<br>Alignment: " + esc(align) + "<br>Policy: " + esc(policy) +
      "<br>Reason: " + esc(reason) + "<br>Evidence: " + esc(evidence) + "</p></article>";
  }

  function becPanel(rec) {
    const factors = rec.risk_factors || [];
    const flags = {
      urgency: factors.some(function (f) { return f.indicator === "urgency"; }),
      financial_request: factors.some(function (f) { return f.indicator === "financial_request"; }),
      credential_request: factors.some(function (f) { return f.indicator === "credential_request"; }),
      reply_to_mismatch: factors.some(function (f) { return f.indicator === "reply_to_mismatch"; }),
      authentication_failure: factors.some(function (f) { return f.indicator === "authentication_failure"; }),
      suspicious_url: factors.some(function (f) { return f.indicator === "suspicious_url"; }),
    };
    return '<section class="section"><h2>Business Email Compromise Assessment</h2>' +
      "<p>Risk Score: <strong>" + esc(rec.risk_score) + "</strong> / 100 · Classification: " + badge(rec.classification) + "</p>" +
      "<ul>" +
        "<li>Urgency indicators: " + (flags.urgency ? "Present" : "Not observed") + "</li>" +
        "<li>Financial request: " + (flags.financial_request ? "Present" : "Not observed") + "</li>" +
        "<li>Credential request: " + (flags.credential_request ? "Present" : "Not observed") + "</li>" +
        "<li>Reply-To mismatch: " + (flags.reply_to_mismatch ? "Detected" : "Not observed") + "</li>" +
        "<li>Domain similarity: Review display name versus mailbox domain</li>" +
        "<li>Authentication failure: " + (flags.authentication_failure ? "Present" : "Not observed") + "</li>" +
        "<li>Suspicious URL: " + (flags.suspicious_url ? "Present" : "Not observed") + "</li>" +
        "<li>Known IOC: Cross-check Threat Intelligence</li>" +
      "</ul>" +
      "<details><summary>Reason for Classification — evidence panel</summary><ul>" +
        factors.map(function (f) {
          return "<li><strong>" + esc(f.label) + "</strong> (+" + esc(f.score) + ") — " + esc(f.evidence) + "</li>";
        }).join("") +
      "</ul></details></section>";
  }

  function drawMapIfNeeded(tab, rec) {
    if (tab !== "headers" && location.hash.indexOf("/intel/geo") < 0) return;
    const el = document.getElementById("geoMap");
    if (!el || typeof L === "undefined") return;
    const map = L.map(el).setView([20, 78], 3);
    L.tileLayer("https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png", {
      attribution: "&copy; OpenStreetMap, &copy; CARTO",
    }).addTo(map);
    const hops = rec.geo_hops || [];
    const latlngs = [];
    hops.forEach(function (h) {
      if (h.lat && h.lng) {
        const pt = [h.lat, h.lng];
        latlngs.push(pt);
        L.marker(pt).addTo(map).bindPopup("Hop " + h.hop + "<br>" + esc(h.ip) + "<br>" + esc(h.country) + "<br>ASN " + esc(h.asn) + "<br>ISP " + esc(h.isp));
      }
    });
    if (latlngs.length > 1) L.polyline(latlngs, { color: "#0b3a6e", weight: 2 }).addTo(map);
  }

  async function viewGeo() {
    const emails = (await api("/api/v1/emails?page_size=5")).items || [];
    const rec = emails[0] || { geo_hops: [] };
    const html = shell(
      '<h1>GeoIP Analysis</h1><div id="geoMap"></div><p class="notice-map">' + esc(t("geoNotice")) + "</p>" + hopTable(rec.geo_hops),
      { top: "threatIntel" }
    );
    return { html: html, after: function () { state.forensicTab = "headers"; drawMapIfNeeded("headers", rec); } };
  }

  async function viewIncident(id) {
    if (!id) {
      const data = await api("/api/v1/incidents");
      return shell('<div class="page-head"><h1>Incident Management</h1></div>' + incidentTable(data.items || []), { top: "incidents" });
    }
    const i = await api("/api/v1/incidents/" + id);
    return shell(
      '<h1>' + esc(i.incident_id) + (i.demo ? " " + badge("DEMO DATA") : "") + "</h1>" +
      '<table class="data"><tbody>' +
        row("Incident Type", i.incident_type) + row("Severity", i.severity) + row("Date", i.date) +
        row("Source", i.source) + row("Affected Account", i.affected_account) +
        row("Assigned Officer", i.assigned_officer) +
      "</tbody></table>" +
      "<p>Status: " + badge(i.status) + "</p>" +
      "<p>" + esc(i.description) + "</p>" +
      '<form id="incForm" data-id="' + esc(i.incident_id) + '">' +
        '<label class="field" for="incStatus">Update status</label>' +
        '<select id="incStatus"><option>New</option><option>Assigned</option><option>Under Investigation</option><option>Contained</option><option>Resolved</option><option>Closed</option></select>' +
        '<label class="field" for="incOfficer">Assign officer</label><input id="incOfficer" value="' + esc(i.assigned_officer) + '">' +
        '<label class="field" for="incNote">Add note</label><textarea id="incNote" rows="3"></textarea>' +
        '<p class="btn-row"><button class="btn" type="submit">Update</button>' +
          '<a class="btn btn-sec" href="#/investigate/' + i.incident_id + '">Investigation workspace</a>' +
          '<a class="btn btn-sec" href="#/reports">Generate Report</a></p>' +
      "</form>",
      { top: "incidents" }
    );
  }

  async function viewInvestigate(id) {
    const incidents = (await api("/api/v1/incidents")).items || [];
    const i = id ? incidents.filter(function (x) { return x.incident_id === id; })[0] : incidents[0];
    if (!i) return shell("<p>No investigation selected.</p>", { top: "incidents" });
    return shell(
      '<h1>Investigation Workspace</h1>' +
      '<div class="workspace">' +
        '<section class="section"><h2>Case information</h2><p>' + esc(i.incident_id) + "</p><p>" + badge(i.status) + "</p><p>" + esc(i.description) + "</p></section>" +
        '<section class="section"><h2>Evidence and forensic analysis</h2>' +
          "<p>Evidence count: 1 · IOC count: related · Related email: " + esc(i.related_email) + "</p>" +
          '<h3>Investigation Timeline</h3><div class="flow">' +
          ["Email Received", "Authentication Check", "BEC Detection", "IOC Extraction", "Threat Intelligence Match", "Incident Created", "Analyst Review", "Resolution"]
            .map(function (s, n, a) { return '<div class="step">' + s + "</div>" + (n < a.length - 1 ? '<div class="arrow">↓</div>' : ""); }).join("") +
          "</div></section>" +
        '<section class="section"><h2>Investigation actions</h2>' +
          '<p class="btn-row"><a class="btn" href="#/incidents/' + i.incident_id + '">Assign / Update</a>' +
          '<a class="btn btn-sec" href="#/custody">Attach evidence</a></p></section>' +
      "</div>",
      { top: "incidents" }
    );
  }

  async function viewIntel(kind) {
    const typeMap = { domain: "Domain", ip: "IP", url: "URL", hash: "Hash", email: "Email" };
    const q = typeMap[kind] ? "?ioc_type=" + typeMap[kind] : "";
    const data = await api("/api/v1/iocs" + q);
    const titles = { ioc: "IOC Database", domain: "Domain Intelligence", ip: "IP Intelligence", url: "URL Intelligence", hash: "Hash Intelligence", email: "Email Intelligence" };
    return shell("<h1>" + (titles[kind] || "Threat Intelligence") + "</h1>" + iocTable(data.items || []), { top: "threatIntel" });
  }

  async function viewReports() {
    const data = await api("/api/v1/reports");
    return shell(
      "<h1>Reports &amp; Documents</h1>" +
      '<div class="table-wrap"><table class="data"><thead><tr><th>Report ID</th><th>Category</th><th>Date</th><th>Classification</th><th>Prepared By</th><th>Actions</th></tr></thead><tbody>' +
      (data.items || []).map(function (r) {
        return "<tr><td>" + esc(r.report_id) + "</td><td>" + esc(r.category) + "</td><td>" + esc(r.date) +
          "</td><td>" + esc(r.classification) + "</td><td>" + esc(r.prepared_by) +
          '</td><td><a href="#/reports/' + r.report_id + '">View</a> · Generate · Download · Export (PDF / CSV / JSON)</td></tr>';
      }).join("") + "</tbody></table></div>",
      { top: "reports" }
    );
  }

  async function viewReport(id) {
    const r = await api("/api/v1/reports/" + id);
    return shell(
      '<article class="section"><h1>' + esc(r.report_id) + "</h1>" +
        "<p>VISHWAS · " + esc(r.department) + "<br>" + esc(r.organisation) + "</p>" +
        "<p>Date: " + esc(r.date) + " · Classification: " + esc(r.classification) + " · Prepared By: " + esc(r.prepared_by) + "</p>" +
        "<h2>Summary</h2><p>" + esc(r.summary) + "</p>" +
        "<h2>Findings</h2><pre>" + esc(JSON.stringify(r.findings, null, 2)) + "</pre>" +
        "<h2>Evidence</h2><pre>" + esc(JSON.stringify(r.evidence, null, 2)) + "</pre>" +
        "<h2>Conclusion</h2><p>" + esc(r.conclusion) + "</p>" +
        '<p class="alert info">' + esc(r.disclaimer) + "</p></article>",
      { top: "reports" }
    );
  }

  async function viewAudit() {
    const data = await api("/api/v1/audit");
    return shell(
      "<h1>System Audit Trail</h1>" +
      '<form class="toolbar" id="auditFilter"><input name="user" placeholder="User"><input name="action" placeholder="Action"><input name="module" placeholder="Module"><button class="btn" type="submit">Filter</button></form>' +
      '<div class="table-wrap"><table class="data"><thead><tr><th>Date &amp; Time</th><th>User</th><th>Action</th><th>Module</th><th>Object</th><th>IP Address</th><th>Result</th></tr></thead><tbody>' +
      (data.items || []).map(function (a) {
        return "<tr><td>" + esc(a.datetime) + "</td><td>" + esc(a.user) + "</td><td>" + esc(a.action) +
          "</td><td>" + esc(a.module) + "</td><td>" + esc(a.object) + "</td><td>" + esc(a.ip) + "</td><td>" + badge(a.result) + "</td></tr>";
      }).join("") + "</tbody></table></div>",
      { top: "administration" }
    );
  }

  async function viewCustody() {
    const data = await api("/api/v1/custody");
    return shell(
      "<h1>Chain of Custody</h1>" +
      '<div class="table-wrap"><table class="data"><thead><tr><th>Evidence ID</th><th>File/Email</th><th>SHA-256</th><th>Created</th><th>Collected By</th><th>Processed By</th><th>Verification Status</th><th>Action</th></tr></thead><tbody>' +
      (data.items || []).map(function (c) {
        return "<tr><td>" + esc(c.evidence_id) + "</td><td>" + esc(c.file_or_email) + "</td><td>" + esc(c.sha256) +
          "</td><td>" + esc(c.created) + "</td><td>" + esc(c.collected_by) + "</td><td>" + esc(c.processed_by) +
          "</td><td>" + badge(c.verification_status) +
          '</td><td><button type="button" class="btn btn-sec verifyBtn" data-id="' + esc(c.evidence_id) + '" data-hash="' + esc(c.sha256) + '">VERIFY INTEGRITY</button></td></tr>';
      }).join("") + "</tbody></table></div><p id=" + '"verifyOut"' + "></p>",
      { top: "administration" }
    );
  }

  async function viewUsers() {
    const data = await api("/api/v1/users");
    return shell(
      "<h1>User Management</h1>" +
      '<div class="table-wrap"><table class="data"><thead><tr><th>Employee/User ID</th><th>Name</th><th>Department</th><th>Role</th><th>Status</th><th>Last Login</th><th>Actions</th></tr></thead><tbody>' +
      (data.items || []).map(function (u) {
        return "<tr><td>" + esc(u.user_id) + "</td><td>" + esc(u.name) + "</td><td>" + esc(u.department) +
          "</td><td>" + esc(u.role.replace(/_/g, " ")) + "</td><td>" + badge(u.status) + "</td><td>" + esc(u.last_login) +
          "</td><td>View</td></tr>";
      }).join("") + "</tbody></table></div>",
      { top: "administration" }
    );
  }

  function viewRoles() {
    return shell(
      "<h1>Role Management</h1><p>SUPER ADMIN, SECURITY ADMIN, SECURITY ANALYST, INVESTIGATOR, AUDITOR, VIEWER. Navigation is filtered by role.</p>",
      { top: "administration" }
    );
  }

  function viewMailboxes() {
    return shell(
      "<h1>Mailbox Management</h1>" +
      '<form id="imapForm" class="section"><p>Credentials are submitted to the server only and are not stored in page source.</p>' +
        '<label class="field">IMAP host</label><input name="imap_server" value="imap.gmail.com">' +
        '<label class="field">Mailbox</label><input name="email_address" type="email">' +
        '<label class="field">App password</label><input name="password" type="password" autocomplete="off">' +
        '<p><button class="btn" type="submit">Connect mailbox</button></p><p id="imapMsg" class="help"></p></form>' +
      '<form id="emlForm" class="section"><label class="field">Upload .eml</label><input type="file" name="file" accept=".eml">' +
        '<p><button class="btn" type="submit">Analyse</button></p></form>',
      { top: "administration" }
    );
  }

  function viewSettings() {
    return shell(
      "<h1>System Configuration</h1>" +
      "<p>Session timeout, security headers, CORS allow-list and WebSocket authentication are enforced on the server.</p>" +
      (can("admin")
        ? '<p class="btn-row"><button class="btn" type="button" id="loadDemo">' + t("loadDemo") + '</button>' +
          '<button class="btn btn-sec" type="button" id="resetDemo">' + t("resetDemo") + "</button></p>"
        : ""),
      { top: "administration" }
    );
  }

  async function viewHealth() {
    const h = await api("/api/v1/health");
    return shell(
      "<h1>System Health &amp; Monitoring</h1>" +
      '<div class="table-wrap"><table class="data"><thead><tr><th>Service</th><th>Status</th></tr></thead><tbody>' +
      h.services.map(function (s) { return "<tr><td>" + esc(s.name) + "</td><td>" + badge(s.status) + "</td></tr>"; }).join("") +
      "</tbody></table></div>" +
      "<p>CPU: " + esc(h.metrics.cpu) + "% · Memory: " + esc(h.metrics.memory) + "% · Queue: " + esc(h.metrics.queue) +
      " · Emails/Minute: " + esc(h.metrics.emails_minute) + " · Average processing: " + esc(h.metrics.avg_processing_ms) +
      " ms · Error rate: " + esc(h.metrics.error_rate) + "%</p>",
      { top: "administration" }
    );
  }

  async function viewSearch() {
    return shell(
      "<h1>Advanced Search</h1>" +
      '<form id="searchForm" class="section">' +
        '<label class="field">Query</label><input name="query" type="search">' +
        '<label class="field">Email</label><input name="email">' +
        '<label class="field">Domain</label><input name="domain">' +
        '<label class="field">IP</label><input name="ip">' +
        '<label class="field">URL</label><input name="url">' +
        '<label class="field">Hash</label><input name="hash">' +
        '<label class="field">Message ID</label><input name="message_id">' +
        '<label class="field">Incident ID</label><input name="incident_id">' +
        '<label class="field">Case ID</label><input name="case_id">' +
        '<p><button class="btn" type="submit">Search</button></p>' +
      "</form><div id=" + '"searchOut"' + "></div>",
      { top: "dashboard" }
    );
  }

  function viewStatic(title, body) {
    return shell("<h1>" + title + "</h1><section class=\"section\"><p>" + body + "</p></section>", { public: !state.user, top: "help" });
  }

  async function render() {
    try { state.meta = await api("/api/v1/meta"); } catch (e) { state.meta = { version: "VISHWAS v1.0", demo: true, status: "Operational" }; }
    if (state.highContrast) document.body.classList.add("high-contrast");
    else document.body.classList.remove("high-contrast");

    const r = route();
    const p = r.parts;
    let after = null;
    let html = "";

    if (p[0] === "logout") {
      try { await api("/api/v1/auth/logout", { method: "POST", body: "{}" }); } catch (e) {}
      state.user = null; state.token = ""; localStorage.removeItem("vishwas_token");
      location.hash = "#/"; return;
    }

    if (!p.length) html = viewHome();
    else if (p[0] === "login") html = viewLogin();
    else if (p[0] === "mfa") html = viewMfa();
    else if (p[0] === "help") html = viewStatic(t("help"), t("sysReqText") + " " + t("forgotMsg"));
    else if (p[0] === "contact") html = viewStatic(t("contact"), "Contact the designated information security officer of your organisation. This prototype does not publish a real government helpdesk number.");
    else if (p[0] === "privacy") html = viewStatic(t("privacy"), "Placeholder privacy notice for the demonstration portal.");
    else if (p[0] === "security") html = viewStatic(t("securityPolicy"), "Placeholder security policy. Sessions expire, actions are audited, and secrets must not be placed in frontend code.");
    else {
      if (!state.user) {
        try {
          const me = await api("/api/v1/auth/me");
          state.user = me.user;
        } catch (e) {
          location.hash = "#/login";
          return;
        }
      }
      try {
        if (can("dashboard")) state.notifications = (await api("/api/v1/notifications")).items || [];
      } catch (e) { state.notifications = []; }

      if (p[0] === "dashboard" && p[1] === "executive") html = await viewDashboard("executive");
      else if (p[0] === "dashboard" && p[1] === "soc") html = await viewDashboard("soc");
      else if (p[0] === "dashboard" && p[1] === "forensics") html = await viewDashboard("forensics");
      else if (p[0] === "dashboard" && p[1] === "intel") html = await viewDashboard("intel");
      else if (p[0] === "dashboard" && p[1] === "incidents") html = await viewDashboard("incidents");
      else if (p[0] === "dashboard" && p[1] === "admin") html = await viewDashboard("admin");
      else if (p[0] === "dashboard") html = await viewDashboard("main");
      else if (p[0] === "email" && (p[1] === "threats" || p[1] === "inbox")) html = await viewThreatInbox();
      else if (p[0] === "email" && p[1] === "forensics") {
        const pack = await viewForensic(p[2]);
        if (typeof pack === "string") html = pack;
        else { html = pack.html; after = pack.after; }
      } else if (p[0] === "email") html = await viewThreatInbox();
      else if (p[0] === "intel" && p[1] === "geo") {
        const pack = await viewGeo(); html = pack.html; after = pack.after;
      } else if (p[0] === "intel") html = await viewIntel(p[1] || "ioc");
      else if (p[0] === "incidents") html = await viewIncident(p[1]);
      else if (p[0] === "investigate") html = await viewInvestigate(p[1]);
      else if (p[0] === "reports" && p[1]) html = await viewReport(p[1]);
      else if (p[0] === "reports") html = await viewReports();
      else if (p[0] === "audit") html = await viewAudit();
      else if (p[0] === "custody") html = await viewCustody();
      else if (p[0] === "admin" && p[1] === "users") html = await viewUsers();
      else if (p[0] === "admin" && p[1] === "roles") html = viewRoles();
      else if (p[0] === "admin" && p[1] === "mailboxes") html = viewMailboxes();
      else if (p[0] === "admin") html = viewSettings();
      else if (p[0] === "health") html = await viewHealth();
      else if (p[0] === "search") html = await viewSearch();
      else html = viewHome();
    }

    document.getElementById("app").innerHTML = html;
    bindChrome();
    if (after) after();
    if (p[0] === "login") setupLogin();
    if (p[0] === "mfa") setupMfa();
  }

  function bindChrome() {
    const le = document.getElementById("langEn");
    const lh = document.getElementById("langHi");
    if (le) le.onclick = function (e) { e.preventDefault(); state.lang = "en"; localStorage.setItem("vishwas_lang", "en"); loadI18n().then(render); };
    if (lh) lh.onclick = function (e) { e.preventDefault(); state.lang = "hi"; localStorage.setItem("vishwas_lang", "hi"); loadI18n().then(render); };
    const a11y = document.getElementById("btnA11y");
    if (a11y) a11y.onclick = function () {
      state.highContrast = !state.highContrast;
      localStorage.setItem("vishwas_hc", state.highContrast ? "1" : "0");
      render();
    };
    const nb = document.getElementById("notifBtn");
    if (nb) nb.onclick = function () { state.notifOpen = !state.notifOpen; render(); };
    const mb = document.getElementById("menuBtn");
    const sb = document.getElementById("sidebar");
    if (mb && sb) mb.onclick = function () { sb.classList.toggle("open"); };
    const cs = document.getElementById("collapseSb");
    if (cs && sb) cs.onclick = function () { sb.hidden = !sb.hidden; };
    document.querySelectorAll(".tabBtn").forEach(function (b) {
      b.onclick = function () { state.forensicTab = b.getAttribute("data-tab"); render(); };
    });
    document.querySelectorAll(".rangeBtn").forEach(function (b) {
      b.onclick = function () { state.threatRange = b.getAttribute("data-r"); render(); };
    });
    const inc = document.getElementById("incForm");
    if (inc) inc.onsubmit = function (e) {
      e.preventDefault();
      api("/api/v1/incidents/" + inc.getAttribute("data-id"), {
        method: "PATCH",
        body: JSON.stringify({
          status: document.getElementById("incStatus").value,
          assigned_officer: document.getElementById("incOfficer").value,
          note: document.getElementById("incNote").value,
        }),
      }).then(function () { render(); }).catch(function (err) { alert(err.message); });
    };
    document.querySelectorAll(".verifyBtn").forEach(function (b) {
      b.onclick = function () {
        api("/api/v1/custody/verify", {
          method: "POST",
          body: JSON.stringify({ evidence_id: b.getAttribute("data-id"), sha256: b.getAttribute("data-hash") }),
        }).then(function (r) {
          const el = document.getElementById("verifyOut");
          if (el) el.innerHTML = r.verified ? badge("INTEGRITY VERIFIED") : badge("INTEGRITY VERIFICATION FAILED");
        });
      };
    });
    const vh = document.getElementById("verifyHash");
    if (vh) vh.onclick = function () {
      const hashEl = vh.previousElementSibling;
      api("/api/v1/custody/verify", { method: "POST", body: JSON.stringify({ sha256: (hashEl && hashEl.textContent) || "" }) })
        .then(function (r) {
          document.getElementById("verifyOut").innerHTML = r.verified ? badge("INTEGRITY VERIFIED") : badge("INTEGRITY VERIFICATION FAILED");
        });
    };
    const imap = document.getElementById("imapForm");
    if (imap) imap.onsubmit = function (e) {
      e.preventDefault();
      const fd = new FormData(imap);
      api("/api/v1/connect-email", {
        method: "POST",
        body: JSON.stringify({
          imap_server: fd.get("imap_server"),
          email_address: fd.get("email_address"),
          password: fd.get("password"),
        }),
      }).then(function (r) { document.getElementById("imapMsg").textContent = r.message; })
        .catch(function (err) { document.getElementById("imapMsg").textContent = err.message; });
    };
    const eml = document.getElementById("emlForm");
    if (eml) eml.onsubmit = function (e) {
      e.preventDefault();
      const file = eml.querySelector('input[type=file]').files[0];
      const fd = new FormData();
      if (file) fd.append("file", file);
      fetch("/api/v1/analyze", { method: "POST", body: fd, headers: state.token ? { Authorization: "Bearer " + state.token } : {}, credentials: "include" })
        .then(function (res) { return res.json(); })
        .then(function (d) { location.hash = "#/email/forensics/" + encodeURIComponent(d.email_id || ""); });
    };
    const ld = document.getElementById("loadDemo");
    const rd = document.getElementById("resetDemo");
    if (ld) ld.onclick = function () { api("/api/v1/demo/load", { method: "POST", body: "{}" }).then(render); };
    if (rd) rd.onclick = function () { api("/api/v1/demo/reset", { method: "POST", body: "{}" }).then(render); };
    const sf = document.getElementById("searchForm");
    if (sf) sf.onsubmit = function (e) {
      e.preventDefault();
      const o = {};
      new FormData(sf).forEach(function (v, k) { o[k] = v; });
      api("/api/v1/search", { method: "POST", body: JSON.stringify(o) }).then(function (d) {
        document.getElementById("searchOut").innerHTML =
          "<h2>Emails</h2>" + emailTable(d.emails || [], true) +
          "<h2>Incidents</h2>" + incidentTable(d.incidents || []) +
          "<h2>IOCs</h2>" + iocTable(d.iocs || []);
      });
    };
    const inf = document.getElementById("inboxFilter");
    if (inf) inf.onsubmit = function (e) {
      e.preventDefault();
      const q = document.getElementById("q").value;
      const sev = document.getElementById("severity").value;
      const tt = document.getElementById("ttype").value;
      location.hash = "#/email/threats";
      api("/api/v1/emails?q=" + encodeURIComponent(q) + "&severity=" + encodeURIComponent(sev) + "&threat_type=" + encodeURIComponent(tt) + "&page_size=50")
        .then(function (d) {
          document.querySelector("#main").insertAdjacentHTML("beforeend", "");
          const wrap = document.querySelector("#main .table-wrap") || document.querySelector("#main");
          wrap.outerHTML = emailTable(d.items || [], false);
        });
    };
    const ex = document.getElementById("exportCsv");
    if (ex) ex.onclick = function () {
      const rows = [["subject", "from", "risk"]];
      document.querySelectorAll("table.data tbody tr").forEach(function (tr) {
        rows.push(Array.from(tr.cells).map(function (td) { return '"' + td.innerText.replace(/"/g, '""') + '"'; }));
      });
      const blob = new Blob([rows.map(function (r) { return r.join(","); }).join("\n")], { type: "text/csv" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = "vishwas-export.csv"; a.click();
    };
  }

  async function setupLogin() {
    const cap = await api("/api/v1/captcha");
    document.getElementById("captchaQ").textContent = cap.challenge;
    document.getElementById("captchaToken").value = cap.token;
    document.getElementById("loginForm").onsubmit = async function (e) {
      e.preventDefault();
      const err = document.getElementById("loginErr");
      err.hidden = true;
      try {
        const data = await api("/api/v1/auth/login", {
          method: "POST",
          body: JSON.stringify({
            username: document.getElementById("username").value,
            password: document.getElementById("password").value,
            captcha_token: document.getElementById("captchaToken").value,
            captcha_answer: document.getElementById("captcha").value,
          }),
        });
        if (data.mfa_required) {
          state.pendingMfa = data.pending_token;
          location.hash = "#/mfa";
        } else {
          finishLogin(data);
        }
      } catch (ex) {
        err.hidden = false;
        err.textContent = ex.message;
      }
    };
  }

  function finishLogin(data) {
    state.token = data.token;
    state.user = data.user;
    localStorage.setItem("vishwas_token", data.token);
    connectWs();
    const dest = {
      SUPER_ADMIN: "#/dashboard/admin",
      SECURITY_ADMIN: "#/dashboard/soc",
      SECURITY_ANALYST: "#/dashboard/soc",
      INVESTIGATOR: "#/dashboard/forensics",
      AUDITOR: "#/audit",
      VIEWER: "#/dashboard/executive",
    };
    location.hash = dest[data.user.role] || "#/dashboard";
  }

  function setupMfa() {
    const inputs = document.querySelectorAll(".otp");
    inputs.forEach(function (inp, i) {
      inp.addEventListener("input", function () {
        if (inp.value && inputs[i + 1]) inputs[i + 1].focus();
      });
    });
    document.getElementById("mfaForm").onsubmit = async function (e) {
      e.preventDefault();
      const method = (document.querySelector('input[name=method]:checked') || {}).value || "OTP";
      const code = method === "HARDWARE_KEY"
        ? (document.getElementById("hwAssert").value || "")
        : Array.from(inputs).map(function (i) { return i.value; }).join("");
      try {
        const data = await api("/api/v1/auth/mfa", {
          method: "POST",
          body: JSON.stringify({ pending_token: state.pendingMfa, otp: code || document.querySelector(".otp").value, method: method }),
        });
        finishLogin(data);
      } catch (ex) {
        const err = document.getElementById("mfaErr");
        err.hidden = false;
        err.textContent = ex.message;
      }
    };
    document.getElementById("resendOtp").onclick = function () {
      const fd = new FormData();
      fd.append("pending_token", state.pendingMfa);
      fetch("/api/v1/auth/mfa/resend", { method: "POST", body: fd, credentials: "include" });
    };
  }

  function connectWs() {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const q = state.token ? "?token=" + encodeURIComponent(state.token) : "";
    try {
      const ws = new WebSocket(proto + "//" + location.host + "/ws/events" + q);
      ws.onopen = function () { state.live = true; const el = document.getElementById("livePill"); if (el) el.classList.add("on"); };
      ws.onclose = function () { state.live = false; };
      ws.onmessage = function (ev) {
        const msg = JSON.parse(ev.data);
        if (msg.type === "pong") return;
        state.notifications.unshift({
          id: String(Date.now()),
          type: msg.type === "THREAT_DETECTED" ? "Security Alert" : "System Alert",
          title: msg.type.replace(/_/g, " "),
          time: new Date().toISOString(),
          read: false,
        });
        const pill = document.getElementById("livePill");
        if (pill) { pill.classList.add("on"); }
      };
    } catch (e) {}
  }

  window.addEventListener("hashchange", render);
  loadI18n().then(function () {
    if (state.token) {
      api("/api/v1/auth/me").then(function (me) {
        state.user = me.user;
        connectWs();
        render();
      }).catch(function () {
        state.token = "";
        render();
      });
    } else render();
  });
})();
