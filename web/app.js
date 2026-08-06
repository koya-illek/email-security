(() => {
  "use strict";

  const API_BASE = (window.EMAIL_CHECKER_CONFIG?.API_BASE || "").replace(/\/$/, "");
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => [...document.querySelectorAll(sel)];

  let lastHeaderAnalysis = null;
  let lastDomainReport = null;
  let spfValidationSequence = 0;
  let dmarcValidationSequence = 0;

  // ─── Tab Navigation ──────────────────────────────────────────────
  function selectTool(name, pushHash = true) {
    $$(".tool-tab").forEach((x) => {
      const active = x.dataset.tool === name;
      x.classList.toggle("active", active);
      x.setAttribute("aria-selected", String(active));
      x.tabIndex = active ? 0 : -1;
    });
    $$(".tool-panel").forEach((x) => {
      const active = x.id === "panel-" + name;
      x.classList.toggle("active", active);
      x.hidden = !active;
    });
    if (pushHash) history.replaceState(null, "", "#" + name);
    if (name === "domain") $("#domain-input")?.focus();
    if (name === "spf") $("#spf-domain-input")?.focus();
    if (name === "headers") $("#header-input")?.focus();
  }

  $$(".tool-tab").forEach((x) =>
    x.addEventListener("click", () => selectTool(x.dataset.tool))
  );

  $(".tool-nav")?.addEventListener("keydown", (e) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(e.key)) return;
    const tabs = $$(".tool-tab");
    const current = tabs.indexOf(document.activeElement);
    let next =
      e.key === "Home" ? 0 :
      e.key === "End" ? tabs.length - 1 :
      e.key === "ArrowRight" ? (current + 1) % tabs.length :
      (current - 1 + tabs.length) % tabs.length;
    e.preventDefault();
    selectTool(tabs[next].dataset.tool);
    tabs[next].focus();
  });

  // Restore tab from hash
  const initialTab = ["domain", "spf", "builder", "headers"].includes(
    location.hash.slice(1)
  )
    ? location.hash.slice(1)
    : "domain";
  selectTool(initialTab, false);

  // ─── Builder sub-tabs ────────────────────────────────────────────
  $$(".builder-tab").forEach((x) =>
    x.addEventListener("click", () => {
      $$(".builder-tab").forEach((y) => y.classList.toggle("active", y === x));
      $$(".builder-pane").forEach((y) =>
        y.classList.toggle("active", y.id === "builder-" + x.dataset.builder)
      );
    })
  );

  // ─── Methodology dialog ──────────────────────────────────────────
  const methodDialog = $("#method-dialog");
  $("#method-button")?.addEventListener("click", () => methodDialog.showModal());
  $("#footer-method-button")?.addEventListener("click", () => methodDialog.showModal());
  $("#dialog-close")?.addEventListener("click", () => methodDialog.close());
  methodDialog?.addEventListener("click", (e) => {
    if (e.target === methodDialog) methodDialog.close();
  });

  // ─── Utility ─────────────────────────────────────────────────────
  function esc(v) {
    return String(v ?? "").replace(/[&<>"']/g, (ch) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;",
      '"': "&quot;", "'": "&#39;",
    }[ch]));
  }

  function copyText(value) {
    navigator.clipboard.writeText(value).then(() => {}).catch(() => {
      const t = document.createElement("textarea");
      t.value = value;
      document.body.appendChild(t);
      t.select();
      document.execCommand("copy");
      t.remove();
    });
  }

  // ─── Domain Check ────────────────────────────────────────────────
  const checkForm = $("#check-form");
  const domainInput = $("#domain-input");
  const checkButton = $("#check-button");
  const domainLoading = $("#domain-loading");
  const domainError = $("#domain-error");
  const domainErrorMsg = $("#domain-error-msg");
  const domainReport = $("#domain-report");
  const domainMetrics = $("#domain-metrics");
  const domainResults = $("#domain-results");

  checkForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const domain = domainInput.value.trim();
    if (!domain) return;
    domainLoading.classList.remove("hidden");
    domainError.classList.add("hidden");
    domainReport.classList.add("hidden");
    checkButton.disabled = true;
    try {
      const r = await fetch(`${API_BASE}/api/check`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      const d = await r.json();
      if (d.error) showDomainError(d.error);
      else showDomainResults(d);
    } catch {
      showDomainError("Failed to analyze domain");
    } finally {
      domainLoading.classList.add("hidden");
      checkButton.disabled = false;
    }
  });

  $("#new-check")?.addEventListener("click", () => {
    domainReport.classList.add("hidden");
    domainInput.focus();
  });

  $("#inspect-from-report")?.addEventListener("click", () => {
    if (lastDomainReport) {
      $("#spf-domain-input").value = lastDomainReport.domain;
      selectTool("spf");
      $("#spf-form").requestSubmit();
    }
  });

  $("#build-from-report")?.addEventListener("click", () => {
    if (lastDomainReport) {
      prefillBuilders(lastDomainReport);
      selectTool("builder");
    }
  });

  function showDomainError(msg) {
    domainErrorMsg.textContent = msg;
    domainError.classList.remove("hidden");
  }

  function showDomainResults(d) {
    lastDomainReport = d;
    $("#report-domain").textContent = d.domain;

    // Metrics
    const scoreClass = d.overall_score >= 85 ? "good" : d.overall_score >= 70 ? "good" : d.overall_score >= 50 ? "warn" : "poor";
    domainMetrics.innerHTML = `
      <div class="metric"><small>Security Score</small><strong class="${scoreClass}">${d.overall_score}/100</strong></div>
      <div class="metric"><small>SPF</small><strong class="${statusClass(d.spf.status)}">${esc(d.spf.status)}</strong></div>
      <div class="metric"><small>DKIM</small><strong class="${statusClass(d.dkim.status)}">${esc(d.dkim.status)}</strong></div>
      <div class="metric"><small>DMARC</small><strong class="${statusClass(d.dmarc.status)}">${esc(d.dmarc.status)}</strong></div>
      <div class="metric"><small>MX</small><strong class="${statusClass(d.mx.status)}">${esc(d.mx.status)}</strong></div>
    `;

    // Results accordion
    let html = "";
    html += createResultSection("SPF", "SPF Record", d.spf);
    html += createResultSection("DKIM", "DKIM Configuration", d.dkim);
    html += createResultSection("DMARC", "DMARC Policy", d.dmarc);
    html += createMXSection(d.mx);
    html += createResultSection("TRSPT", "Transport Security", d.transport);
    html += createResultSection("CAA", "CAA Records", d.caa);
    html += createPTRSection(d.ptr);
    domainResults.innerHTML = html;

    // Auto-open first section
    domainResults.querySelector("details")?.open = true;

    domainReport.classList.remove("hidden");
    domainReport.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function statusClass(status) {
    return status === "pass" ? "good" : status === "warn" ? "warn" : "poor";
  }

  function createResultSection(icon, title, d) {
    const checks = (d.checks || [])
      .map(
        (x) => `<div class="check-item ${x.status}">
          <div class="check-dot"></div>
          <div class="check-content">
            <div class="check-title">${esc(x.title)}</div>
            <div class="check-detail">${esc(x.detail)}</div>
            ${x.recommendation ? `<div class="check-recommendation"><strong>Recommendation</strong>${esc(x.recommendation)}</div>` : ""}
          </div>
        </div>`
      )
      .join("");

    const record = d.record
      ? `<div class="record-box"><strong>DNS Record</strong>${esc(d.record)}</div>`
      : "";

    const selectors =
      d.selectors && d.selectors.length
        ? `<div class="record-box"><strong>Found DKIM Selectors</strong>${d.selectors
            .map((x) => `<div style="margin-bottom:8px"><code>${esc(x.selector)}</code></div>`)
            .join("")}</div>`
        : "";

    return `<details class="collapsible-section">
      <summary>
        <span class="cs-icon">${icon}</span>
        <span class="cs-title">${title}</span>
        <span class="cs-count ${d.status}">${d.status}</span>
      </summary>
      <div class="cs-body">
        ${record}${selectors}${checks}
      </div>
    </details>`;
  }

  function createMXSection(d) {
    if (!d.records || !d.records.length) {
      return `<details class="collapsible-section">
        <summary>
          <span class="cs-icon">MX</span>
          <span class="cs-title">MX Records</span>
          <span class="cs-count warn">none</span>
        </summary>
        <div class="cs-body"><p class="muted" style="padding:16px 0">No MX records found.</p></div>
      </details>`;
    }
    const rows = d.records
      .map(
        (x) =>
          `<tr><td>${x.priority}</td><td><code>${esc(x.host)}</code></td></tr>`
      )
      .join("");
    return `<details class="collapsible-section">
      <summary>
        <span class="cs-icon">MX</span>
        <span class="cs-title">MX Records</span>
        <span class="cs-count pass">${d.records.length} found</span>
      </summary>
      <div class="cs-body">
        <table class="mx-table"><thead><tr><th>Priority</th><th>Mail Server</th></tr></thead><tbody>${rows}</tbody></table>
      </div>
    </details>`;
  }

  function createPTRSection(d) {
    const checks = (d.checks || [])
      .map(
        (x) => `<div class="check-item ${x.status}">
          <div class="check-dot"></div>
          <div class="check-content">
            <div class="check-title">${esc(x.title)}</div>
            <div class="check-detail">${esc(x.detail)}</div>
            ${x.recommendation ? `<div class="check-recommendation"><strong>Recommendation</strong>${esc(x.recommendation)}</div>` : ""}
          </div>
        </div>`
      )
      .join("");
    return `<details class="collapsible-section">
      <summary>
        <span class="cs-icon">PTR</span>
        <span class="cs-title">Reverse DNS (PTR)</span>
        <span class="cs-count ${d.status}">${d.status}</span>
      </summary>
      <div class="cs-body">${checks}</div>
    </details>`;
  }

  // ─── SPF Inspector ───────────────────────────────────────────────
  const spfForm = $("#spf-form");
  const spfInput = $("#spf-domain-input");
  const spfButton = $("#spf-button");
  const spfLoading = $("#spf-loading");
  const spfError = $("#spf-error");
  const spfErrorMsg = $("#spf-error-msg");
  const spfReport = $("#spf-report");

  spfForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const domain = spfInput.value.trim();
    if (!domain) return;
    spfLoading.classList.remove("hidden");
    spfError.classList.add("hidden");
    spfReport.classList.add("hidden");
    spfButton.disabled = true;
    try {
      const r = await fetch(`${API_BASE}/api/spf/inspect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      const d = await r.json();
      if (d.error) showSpfError(d.error);
      else showSpfInspector(d);
    } catch {
      showSpfError("Failed to inspect SPF");
    } finally {
      spfLoading.classList.add("hidden");
      spfButton.disabled = false;
    }
  });

  function showSpfError(msg) {
    spfErrorMsg.textContent = msg;
    spfError.classList.remove("hidden");
  }

  function showSpfInspector(d) {
    const f = d.flatten;
    if (!f || !f.available) {
      showSpfError("No SPF record was found for " + d.domain);
      return;
    }

    const recursive = d.spf?.lookupCount ?? f.originalLookups;

    $("#spf-summary").innerHTML = `
      <div class="metric"><small>Recursive lookups</small><strong>${recursive}/10</strong></div>
      <div class="metric"><small>After preview</small><strong>${f.flattenedLookups}/10</strong></div>
      <div class="metric"><small>Record length</small><strong>${f.characterCount}</strong></div>
    `;

    let html = "";
    html += `<div class="output-card">
      <div class="output-head"><strong>Current SPF record</strong><button class="copy-btn" data-copy="original">Copy</button></div>
      <div class="dns-value">${esc(f.originalRecord)}</div>
    </div>`;

    html += `<div class="output-card">
      <div class="output-head"><strong>Flattened preview</strong><button class="copy-btn" data-copy="flattened" ${f.safeToPublish ? "" : "disabled"}>${f.safeToPublish ? "Copy validated preview" : "Review required"}</button></div>
      <div class="dns-value">${esc(f.record)}</div>
    </div>`;

    html += `<div class="notice ${f.safeToPublish ? "good" : ""}">
      <strong>${f.safeToPublish ? "Validated point-in-time preview" : "Copy blocked — manual review required"}</strong>
      ${[...(f.validation?.errors || []), ...f.warnings].map(esc).join("<br>")}
    </div>`;

    html += `<details class="collapsible-section" open>
      <summary>
        <span class="cs-icon">SRC</span>
        <span class="cs-title">Expanded sources</span>
        <span class="cs-count info">${f.sources.length} records</span>
      </summary>
      <div class="cs-body">
        ${f.sources
          .map(
            (x) =>
              `<div class="source-group"><code>${esc(x.source)}</code><span>${esc(x.mechanisms.join(" "))}</span></div>`
          )
          .join("")}
      </div>
    </details>`;

    html += `<div class="header-actions">
      <button class="secondary-button" data-action="use-spf">Use in Record Builder</button>
    </div>`;

    $("#spf-detail").innerHTML = html;
    spfReport.classList.remove("hidden");

    // Bind buttons
    $("#spf-detail [data-copy='original']").onclick = () => copyText(f.originalRecord);
    if (f.safeToPublish) {
      $("#spf-detail [data-copy='flattened']").onclick = () => copyText(f.record);
    }
    $("#spf-detail [data-action='use-spf']").onclick = () => {
      $("#builder-domain").value = d.domain;
      $("#spf-custom").value = f.record
        .replace(/^v=spf1\s+/, "")
        .replace(/\s+[?~+-]all\s*$/, "");
      $("#spf-policy").value =
        (f.record.match(/([?~+-]all)\s*$/) || [])[1] || "~all";
      renderSpfBuilder();
      selectTool("builder");
    };
  }

  // ─── Record Builder ──────────────────────────────────────────────
  function outputCard(title, host, value, warning) {
    return `<div class="output-card">
      <div class="output-head"><strong>${esc(title)}</strong><button class="copy-btn" disabled>Validating…</button></div>
      <div class="field-help" style="margin-bottom:6px">Host: ${esc(host)}</div>
      <div class="dns-value">${esc(value)}</div>
      ${warning ? `<div class="notice">${esc(warning)}</div>` : ""}
      <div class="validation-result"></div>
    </div>`;
  }

  function validSpfMechanism(value) {
    return /^(?:ip4:[0-9./]+|ip6:[0-9a-f:/]+|include:[a-z0-9_.-]+|a(?::[a-z0-9_.-]+)?(?:\/\d+)?|mx(?::[a-z0-9_.-]+)?(?:\/\d+)?)$/i.test(
      value
    );
  }

  function validBuilderDomain(value) {
    return /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(value);
  }

  function showValidation(root, validation, extraErrors, record, type) {
    const errors = [...(extraErrors || []), ...(validation.errors || [])];
    const warnings = validation.warnings || [];
    const box = root.querySelector(".validation-result");
    const button = root.querySelector(".copy-btn");

    if (errors.length) {
      box.innerHTML = `<div class="notice"><strong>Cannot copy this record</strong><br>${errors.map(esc).join("<br>")}</div>`;
      button.textContent = "Invalid record";
      button.disabled = true;
      return;
    }

    const metrics =
      type === "spf"
        ? ` · ${validation.lookupCount} SPF DNS lookups · ${validation.characterCount} characters`
        : ` · ${validation.characterCount} characters`;

    box.innerHTML = `<div class="notice good"><strong>Valid record</strong>${metrics}${warnings.length ? "<br>" + warnings.map(esc).join("<br>") : ""}</div>`;
    button.textContent = "Copy value";
    button.disabled = false;
    button.onclick = () => copyText(record);
  }

  async function renderSpfBuilder() {
    const sequence = ++spfValidationSequence;
    const selected = [...$$("#provider-options input:checked")].map((x) => x.value);
    const raw = $("#spf-custom").value.trim().split(/\s+/).filter(Boolean);
    const valid = raw.filter(validSpfMechanism);
    const invalid = raw.filter((x) => !validSpfMechanism(x));
    const policy = $("#spf-policy").value;
    const stage = $("#spf-stage").value;
    const domain = $("#builder-domain").value.trim();
    const record = ["v=spf1", ...new Set([...selected, ...valid]), policy].join(" ");

    const warning =
      stage !== "confirmed" && policy === "-all"
        ? "Use ~all until every legitimate sender is confirmed."
        : !selected.length && !valid.length
        ? "No sending service is authorised by this record."
        : "";

    const root = $("#spf-builder-output");
    root.innerHTML = outputCard("Proposed SPF TXT record", domain || "your domain", record, warning);

    const extra = [];
    if (!validBuilderDomain(domain)) extra.push("Enter a valid domain before copying.");
    if (invalid.length) extra.push("Correct unsupported terms: " + invalid.join(", "));

    try {
      const r = await fetch(`${API_BASE}/api/records/validate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "spf", domain, record }),
      });
      const validation = await r.json();
      if (sequence !== spfValidationSequence) return;
      showValidation(root, validation, extra, record, "spf");
    } catch {
      if (sequence === spfValidationSequence)
        showValidation(root, { errors: ["Validation service could not confirm this record."], warnings: [] }, extra, record, "spf");
    }
  }

  async function renderDmarcBuilder() {
    const sequence = ++dmarcValidationSequence;
    const domain = $("#dmarc-domain").value.trim();
    const policy = $("#dmarc-stage").value;
    const testing = $("#dmarc-testing").value;
    const rua = $("#dmarc-rua").value.trim();
    const sub = $("#dmarc-subdomain").value;
    const strict = $("#dmarc-alignment").value === "strict";

    const parts = ["v=DMARC1", "p=" + policy, "t=" + testing];
    if (rua) parts.push("rua=mailto:" + rua.replace(/^mailto:/i, ""));
    if (sub) parts.push("sp=" + sub);
    parts.push("adkim=" + (strict ? "s" : "r"), "aspf=" + (strict ? "s" : "r"));
    const record = parts.join("; ") + ";";

    let warning = "";
    if (!rua) warning = "Add a controlled aggregate-report mailbox before publishing.";
    else if (testing === "y") warning = "Testing mode is temporary; review reports before changing to t=n.";
    else if (policy !== "none" && !lastDomainReport) warning = "Review DMARC reports before enforcing quarantine or rejection.";

    const root = $("#dmarc-builder-output");
    root.innerHTML = outputCard("Proposed DMARC TXT record", "_dmarc." + (domain || "your-domain"), record, warning);

    const extra = [];
    if (!validBuilderDomain(domain)) extra.push("Enter a valid domain before copying.");

    try {
      const r = await fetch(`${API_BASE}/api/records/validate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "dmarc", domain, record }),
      });
      const validation = await r.json();
      if (sequence !== dmarcValidationSequence) return;
      showValidation(root, validation, extra, record, "dmarc");
    } catch {
      if (sequence === dmarcValidationSequence)
        showValidation(root, { errors: ["Validation service could not confirm this record."], warnings: [] }, extra, record, "dmarc");
    }
  }

  function prefillBuilders(d) {
    $("#builder-domain").value = d.domain;
    $("#dmarc-domain").value = d.domain;
    $("#dmarc-rua").value = (d.dmarc.rua && d.dmarc.rua[0]) || "dmarc@" + d.domain;
    $("#dmarc-stage").value = d.dmarc.policy || "none";
    $("#spf-policy").value = d.spf.record && /-all(?:\s|$)/.test(d.spf.record) ? "-all" : "~all";
    renderSpfBuilder();
    renderDmarcBuilder();
  }

  $$("#builder-spf input, #builder-spf select").forEach((x) =>
    x.addEventListener("input", renderSpfBuilder)
  );
  $$("#builder-dmarc input, #builder-dmarc select").forEach((x) =>
    x.addEventListener("input", renderDmarcBuilder)
  );
  renderSpfBuilder();
  renderDmarcBuilder();

  // ─── Header Analyzer ─────────────────────────────────────────────
  const headerInput = $("#header-input");
  const headerResults = $("#header-results");
  const analyzeHeadersBtn = $("#analyze-headers-btn");
  const enrichHeadersBtn = $("#enrich-headers-btn");
  const clearHeadersBtn = $("#clear-headers-btn");
  const headerError = $("#header-error");
  const headerErrorMsg = $("#header-error-msg");

  headerInput?.addEventListener("input", () => {
    headerResults.innerHTML = "";
    lastHeaderAnalysis = null;
    enrichHeadersBtn.disabled = true;
  });

  analyzeHeadersBtn?.addEventListener("click", runHeaderAnalysis);

  async function runHeaderAnalysis() {
    const raw = headerInput.value.trim();
    if (!raw) {
      showHeaderError("Paste the complete message headers first.");
      return;
    }
    analyzeHeadersBtn.disabled = true;
    analyzeHeadersBtn.textContent = "Analyzing…";
    headerResults.innerHTML =
      '<div class="loading-panel" style="padding:32px"><span class="spinner"></span><p>Interpreting receiver results and delivery hops…</p></div>';
    try {
      const r = await fetch(`${API_BASE}/api/header/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ headers: raw }),
      });
      const d = await r.json();
      if (!r.ok || d.error) throw new Error(d.error || "Header analysis failed");
      lastHeaderAnalysis = d;
      showHeaderAnalysis(d);
      enrichHeadersBtn.disabled = !d.ips.length;
    } catch (err) {
      showHeaderError(err.message || "Header analysis failed");
    } finally {
      analyzeHeadersBtn.disabled = false;
      analyzeHeadersBtn.textContent = "Analyze Headers";
    }
  }

  clearHeadersBtn?.addEventListener("click", () => {
    headerInput.value = "";
    headerResults.innerHTML = "";
    lastHeaderAnalysis = null;
    enrichHeadersBtn.disabled = true;
  });

  enrichHeadersBtn?.addEventListener("click", async () => {
    if (!lastHeaderAnalysis || !lastHeaderAnalysis.ips.length) return;
    enrichHeadersBtn.disabled = true;
    enrichHeadersBtn.textContent = "Enriching…";
    try {
      const r = await fetch(`${API_BASE}/api/header/enrich`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ips: lastHeaderAnalysis.ips }),
      });
      const d = await r.json();
      if (!r.ok || d.error) throw new Error(d.error || "PTR lookup failed");
      lastHeaderAnalysis.enrichment = d.enriched || [];
      showHeaderAnalysis(lastHeaderAnalysis);
    } catch (err) {
      showHeaderError(err.message || "Hop enrichment failed");
    } finally {
      enrichHeadersBtn.textContent = "Enrich Hops";
      enrichHeadersBtn.disabled = false;
    }
  });

  function showHeaderError(msg) {
    headerErrorMsg.textContent = msg;
    headerError.classList.remove("hidden");
  }

  function showHeaderAnalysis(d) {
    if (d.error) {
      showHeaderError(d.error);
      return;
    }

    const summary = d.summary;
    let html = `<div class="trust-banner ${esc(summary.status)}">
      <strong>${esc(summary.verdict)}</strong>
      <span>${esc(summary.confidence)}${summary.authservId ? " · Receiver ID: " + esc(summary.authservId) : ""}. Authentication outcomes are reported by the pasted headers, not independently re-run.</span>
    </div>`;

    html += `<div class="header-summary">
      <div class="metric"><small>Reported authentication</small><strong>${summary.passCount}/3 pass</strong></div>
      <div class="metric"><small>Delivery chain</small><strong>${d.hops.length} hops</strong></div>
      <div class="metric"><small>Enrichable addresses</small><strong>${d.ips.length}</strong></div>
    </div>`;

    // Header findings
    html += `<details class="collapsible-section" open>
      <summary>
        <span class="cs-icon">HDR</span>
        <span class="cs-title">Header Findings</span>
        <span class="cs-count ${esc(summary.status)}">${esc(summary.status)}</span>
      </summary>
      <div class="cs-body">
        ${d.checks.map((x) => `<div class="check-item ${x.status}">
          <div class="check-dot"></div>
          <div class="check-content">
            <div class="check-title">${esc(x.title)}</div>
            <div class="check-detail">${esc(x.detail)}</div>
            ${x.recommendation ? `<div class="check-recommendation"><strong>Recommended next step</strong>${esc(x.recommendation)}</div>` : ""}
          </div>
        </div>`).join("")}
      </div>
    </details>`;

    // Message details
    html += `<details class="collapsible-section">
      <summary>
        <span class="cs-icon">MSG</span>
        <span class="cs-title">Message Details</span>
        <span class="cs-count info">parsed</span>
      </summary>
      <div class="cs-body">
        <div class="record-box"><strong>From</strong>${esc(summary.from || "Not found")}</div>
        <div class="record-box"><strong>Return-Path</strong>${esc(summary.returnPath || "Not found")}</div>
        <div class="record-box"><strong>Reply-To</strong>${esc(summary.replyTo || "Not found")}</div>
        <div class="record-box"><strong>Subject</strong>${esc(summary.subject || "Not found")}</div>
        <div class="record-box"><strong>Date</strong>${esc(summary.date || "Not found")}</div>
        <div class="record-box"><strong>Message-ID</strong>${esc(summary.messageId || "Not found")}</div>
      </div>
    </details>`;

    // Received chain
    html += `<details class="collapsible-section">
      <summary>
        <span class="cs-icon">RCV</span>
        <span class="cs-title">Received Chain</span>
        <span class="cs-count info">${d.hops.length} hops</span>
      </summary>
      <div class="cs-body">
        <p class="muted" style="padding-top:16px">Hop 1 is the newest, topmost Received header. Later numbers move toward the earliest recorded sender-side hop.</p>
        <div class="hop-list">
          ${d.hops.length ? d.hops.map((h) => renderHop(h, d.enrichment)).join("") : '<p class="muted">No Received headers found. Use the complete post-delivery message source.</p>'}
        </div>
      </div>
    </details>`;

    headerResults.innerHTML = html;
    headerError.classList.add("hidden");
  }

  function renderHop(h, enrichment) {
    const addresses = (h.ips || [])
      .map((ip) => {
        const e = (enrichment || []).find((x) => x.ip === ip);
        return `<div><code>${esc(ip)}</code>${e ? `<span class="muted"> · PTR: ${esc(e.ptr || "none found")}</span>` : ""}</div>`;
      })
      .join("");

    const route = `<div class="hop-route"><code>${esc(h.from || "unknown source")}</code><span class="muted">→</span><code>${esc(h.by || "unknown receiver")}</code></div>`;
    const meta = [h.protocol && "Protocol: " + h.protocol, h.id && "ID: " + h.id, h.date && "Time: " + h.date]
      .filter(Boolean)
      .map((x) => `<span>${esc(x)}</span>`)
      .join("");

    return `<div class="hop-item">
      <strong>Hop ${h.index} · ${esc(h.position)}</strong>
      ${route}
      <div class="hop-meta">${meta}</div>
      ${addresses ? `<div style="margin-top:9px">${addresses}</div>` : ""}
      <details style="margin-top:9px"><summary class="muted">Raw Received header</summary><div class="muted" style="margin-top:6px;word-break:break-word">${esc(h.value)}</div></details>
    </div>`;
  }

  // ─── Init ────────────────────────────────────────────────────────
  domainInput?.focus();
})();
