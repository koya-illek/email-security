(() => {
  "use strict";

  const API_BASE = (window.EMAIL_CHECKER_CONFIG?.API_BASE || "").replace(/\/$/, "");
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => [...document.querySelectorAll(sel)];

  let lastHeaderAnalysis = null;
  let lastDomainReport = null;
  let spfValidationSequence = 0;
  let dmarcValidationSequence = 0;
  let importedSpf = null;
  let lastSpfSafetyKey = null;

  // ─── Tab Navigation ──────────────────────────────────────────────
  function selectTool(name, pushHash = true, focusPanel = true) {
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
    if (focusPanel && name === "domain") $("#domain-input")?.focus();
    if (focusPanel && name === "spf") $("#spf-domain-input")?.focus();
    if (focusPanel && name === "headers") $("#header-input")?.focus();
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

  // Restore tab from hash, checking for a report ID first
  const knownTabs = ["domain", "batch", "spf", "builder", "headers"];
  const hashVal = location.hash.slice(1);
  let initialTab = "domain";

  // If hash looks like a report ID (16 chars), load it
  if (/^[A-Za-z0-9_-]{16}$/.test(hashVal)) {
    // DOM references used by loadSharedReport are declared below. Queue the
    // boot read until this script has finished initializing them.
    queueMicrotask(() => loadSharedReport(hashVal));
  } else if (knownTabs.includes(hashVal)) {
    initialTab = hashVal;
  }
  selectTool(initialTab, false, false);

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

  // ─── Share + Export buttons ──────────────────────────────────
  $("#copy-share-link")?.addEventListener("click", () => {
    if (lastDomainReport?.id) {
      const url = `${location.origin}/#${lastDomainReport.id}`;
      copyText(url);
      const btn = $("#copy-share-link");
      const orig = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(() => { btn.textContent = orig; }, 2000);
    } else {
      setShareUnavailable($("#domain-share-note"), $("#copy-share-link"));
    }
  });

  $("#export-json")?.addEventListener("click", () => {
    if (lastDomainReport?.id) {
      window.open(`${API_BASE}/api/reports/${lastDomainReport.id}/export`, "_blank");
    } else if (lastDomainReport) {
      const blob = new Blob([JSON.stringify(lastDomainReport, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `email-security-${lastDomainReport.domain}.json`;
      a.click();
      URL.revokeObjectURL(url);
    }
  });

  // ─── Load shared report from D1 ───────────────────────────────
  async function loadSharedReport(reportId) {
    domainLoading.classList.remove("hidden");
    domainError.classList.add("hidden");
    domainReport.classList.add("hidden");
    try {
      const r = await fetch(`${API_BASE}/api/reports/${reportId}`);
      const d = await r.json();
      if (!r.ok || d.error) {
        showDomainError(d.error);
        selectTool("domain", false);
      } else if (d._reportType === "batch") {
        // Share links may lose their #batch- prefix; dispatch on the stored
        // report type instead of assuming a bare hash is a domain report.
        lastBatchReport = d;
        updateBatchShareState(d);
        renderBatchTable(d.results);
        batchReport.classList.remove("hidden");
        selectTool("batch", false);
      } else {
        showDomainResults(d);
      }
    } catch {
      showDomainError("Failed to load shared report");
      selectTool("domain", false);
    } finally {
      domainLoading.classList.add("hidden");
    }
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
    const shareNote = $("#domain-share-note");
    const shareButton = $("#copy-share-link");
    const confidenceNote = $("#domain-confidence");
    const unknownControls = Array.isArray(d.unknown_controls) ? d.unknown_controls : [];
    confidenceNote.textContent = `Score confidence: ${d.score_confidence || "unknown"}. ${unknownControls.length ? `Inconclusive controls: ${unknownControls.join(", ")}. Retry before changing DNS.` : "All scored controls returned a determinate observation."}`;
    confidenceNote.classList.toggle("warning", unknownControls.length > 0);
    if (d.share?.available && d.share.expiresAt) {
      shareNote.textContent = `Public bearer link. Anyone with the link can view this report until ${new Date(d.share.expiresAt).toLocaleDateString()}; report responses are not cached by browsers or intermediaries.`;
      shareNote.classList.remove("warning");
      shareButton.disabled = false;
      shareButton.textContent = "Copy share link";
    } else {
      setShareUnavailable(shareNote, shareButton);
    }

    // Metrics
    const scoreClass = scoreClassFor(d.overall_score);
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
    const firstDetails = domainResults.querySelector("details");
    if (firstDetails) firstDetails.open = true;

    domainReport.classList.remove("hidden");
    domainReport.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function setShareUnavailable(note, button) {
    if (note) {
      note.textContent = "Share link unavailable because report storage did not complete. Export the result locally if needed.";
      note.classList.add("warning");
    }
    if (button) {
      button.disabled = true;
      button.textContent = "Share unavailable";
    }
  }

  function statusClass(status) {
    return status === "pass" ? "good" : status === "warn" ? "warn" : "poor";
  }

  function scoreClassFor(score) {
    return score >= 70 ? "good" : score >= 50 ? "warn" : "poor";
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
    const spf = d.spf || {};
    if (spf.unknown || (spf.status === "info" && !spf.record)) {
      // DNS trouble is not absence. Publishing a record based on this state
      // could duplicate a working policy once DNS recovers.
      const reason = spf.checks?.[0]?.detail || "the lookup could not be completed";
      showSpfError(`SPF lookup for ${d.domain} was inconclusive (${reason}). Retry after DNS recovers; absence cannot be concluded.`);
      return;
    }
    const f = d.flatten;
    if (!f || !f.available) {
      if (spf.record) {
        showSpfError(`An SPF record exists for ${d.domain}, but the flattening preview is unavailable right now.`);
        return;
      }
      showSpfError("No SPF record was found for " + d.domain);
      return;
    }

    const recursive = d.spf?.lookupCount ?? f.originalLookups;
    const safePreview = f.safeToPublish === true;

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
      <div class="output-head"><strong>Flattened preview</strong><button class="copy-btn" data-copy="flattened" ${safePreview ? "" : "disabled"}>${safePreview ? "Copy validated preview" : "Review required"}</button></div>
      <div class="dns-value">${esc(f.record)}</div>
    </div>`;

    html += `<div class="notice ${safePreview ? "good" : ""}">
      <strong>${safePreview ? "Validated point-in-time preview" : "Copy blocked; manual review required"}</strong>
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
      <button class="secondary-button" data-action="use-spf">${safePreview ? "Use preview in Record Builder" : "Use original in Record Builder"}</button>
    </div>`;

    $("#spf-detail").innerHTML = html;
    spfReport.classList.remove("hidden");

    // Bind buttons
    $("#spf-detail [data-copy='original']").onclick = () => copyText(f.originalRecord);
    if (safePreview) {
      $("#spf-detail [data-copy='flattened']").onclick = () => copyText(f.record);
    }
    $("#spf-detail [data-action='use-spf']").onclick = () => {
      // An unsafe flattened preview is evidence for review, not a proposed
      // replacement. Seed the builder with the imported source record so the
      // preview cannot silently become its trusted baseline.
      prefillSpfBuilder(d.domain, safePreview ? f.record : f.originalRecord);
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
    const bare = String(value || "").replace(/^[+?~-]/, "");
    return /^(?:ip4:[0-9./]+|ip6:[0-9a-f:/]+|include:[a-z0-9_.-]+|a(?::[a-z0-9_.-]+)?(?:\/\d+)?(?:\/\/\d+)?|mx(?::[a-z0-9_.-]+)?(?:\/\d+)?(?:\/\/\d+)?|exists:[a-z0-9_.-]+|ptr(?::[a-z0-9_.-]+)?|redirect=[a-z0-9_.-]+|exp=[a-z0-9_.-]+)$/i.test(bare) || bare === "a" || bare === "mx";
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

  function renderSpfBuilder() {
    const sequence = ++spfValidationSequence;
    const selected = [...$$("#provider-options input:checked")].map((x) => x.value);
    const raw = $("#spf-custom").value.trim().split(/\s+/).filter(Boolean);
    const invalid = raw.filter((x) => !validSpfMechanism(x));
    const policy = $("#spf-policy").value;
    const stage = $("#spf-stage").value;
    const domain = $("#builder-domain").value.trim();
    const terms = [...selected, ...raw];
    const generatedRecord = ["v=spf1", ...terms, policy].filter(Boolean).join(" ");
    // An imported record is displayed verbatim until the user edits one of
    // the SPF controls. This keeps evaluation order, qualifiers, modifiers,
    // and the absence of an all mechanism intact even when known providers
    // are represented by fixed-order checkboxes.
    const record = importedSpf?.preserve ? importedSpf.originalRecord : generatedRecord;
    const spfChange = importedSpf && !importedSpf.preserve
      ? describeSpfChange(importedSpf.originalRecord, record)
      : null;
    const noSenders = !selected.length && !raw.length;
    const noSenderHardFail = noSenders && policy === "-all";
    const safetyKey = JSON.stringify({
      record: normalizeSpfRecord(record),
      stage,
      domain: domain.toLowerCase(),
    });
    if (lastSpfSafetyKey !== null && lastSpfSafetyKey !== safetyKey) {
      $("#spf-safety-confirm").checked = false;
    }
    lastSpfSafetyKey = safetyKey;

    const warning =
      stage !== "confirmed" && policy === "-all"
        ? "Use ~all until every legitimate sender is confirmed."
        : noSenders
        ? "No sending service is authorised by this record. Do not publish an empty hard-fail record unless this domain sends no mail."
        : "";

    const root = $("#spf-builder-output");
    root.innerHTML = outputCard("Proposed SPF TXT record", domain || "your domain", record, warning);

    const extra = [];
    if (!validBuilderDomain(domain)) extra.push("Enter a valid domain before copying.");
    if (invalid.length) extra.push("Correct unsupported terms: " + invalid.join(", "));
    if (spfChange && !$("#spf-safety-confirm").checked) {
      extra.push("The proposed SPF record differs from the imported record. Review the before/after safety context and explicitly confirm the change before copying.");
    }
    if (noSenderHardFail && !$("#spf-safety-confirm").checked) {
      extra.push("This empty -all record authorizes no senders. Explicitly confirm that the domain sends no mail before copying.");
    }
    if (noSenderHardFail && stage !== "confirmed") {
      extra.push("Select ‘All senders confirmed’ before copying an empty -all record.");
    }

    const safetyNotice = $("#spf-safety-notice");
    const safetyConfirmation = $("#spf-safety-confirmation");
    const safetyLabel = $("#spf-safety-confirm-label");
    const requiresConfirmation = Boolean(spfChange) || noSenderHardFail;
    safetyConfirmation.classList.toggle("hidden", !requiresConfirmation);
    safetyNotice.classList.toggle("hidden", !requiresConfirmation);
    safetyNotice.innerHTML = "";
    if (spfChange) {
      safetyLabel.textContent = "I have reviewed and intentionally changed the imported SPF record";
      safetyNotice.innerHTML = `<strong>Review required before copying this SPF change.</strong>
        <div><strong>Before (imported)</strong><code>${esc(spfChange.before)}</code></div>
        <div><strong>After (proposed)</strong><code>${esc(spfChange.after)}</code></div>
        <div>${spfChange.changes.map(esc).join(" ")}</div>`;
    } else if (noSenderHardFail) {
      safetyLabel.textContent = "I confirm this domain sends no mail and an empty -all record is intentional";
      safetyNotice.textContent = "No sending mechanisms are selected. An empty -all record rejects every sender.";
    }

    scheduleSpfValidation(sequence, root, extra, domain, record);
  }

  const VALIDATION_DEBOUNCE_MS = 500;
  let spfValidationTimer = 0;
  let dmarcValidationTimer = 0;

  function scheduleSpfValidation(sequence, root, extra, domain, record) {
    // Only the validation POST is debounced; the rest of the render stays
    // synchronous so safety-state resets keep their event ordering.
    clearTimeout(spfValidationTimer);
    spfValidationTimer = setTimeout(async () => {
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
    }, VALIDATION_DEBOUNCE_MS);
  }

  function renderDmarcBuilder() {
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

    clearTimeout(dmarcValidationTimer);
    dmarcValidationTimer = setTimeout(async () => {
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
    }, VALIDATION_DEBOUNCE_MS);
  }

  function prefillSpfBuilder(domain, record) {
    $("#builder-domain").value = domain;
    const original = String(record || "").trim();
    const parsed = parseSpfRecord(original);
    importedSpf = parsed
      ? {
          originalRecord: original,
          existingTerms: parsed.terms,
          normalizedRecord: normalizeSpfRecord(original),
          preserve: true,
        }
      : null;
    $$("#provider-options input").forEach((input) => {
      input.checked = Boolean(parsed?.terms.some((term) => term.toLowerCase() === input.value.toLowerCase()));
    });
    const selectedProviderValues = new Set(
      $$("#provider-options input:checked").map((input) => input.value.toLowerCase()),
    );
    $("#spf-custom").value = (parsed?.terms || [])
      .filter((term) => !isTerminalSpfTerm(term) && !selectedProviderValues.has(term.toLowerCase()))
      .join(" ");
    $("#spf-policy").value = parsed ? parsed.terminal : "~all";
    // Never turn a stored -all record into implicit confirmation.
    $("#spf-stage").value = "testing";
    $("#spf-safety-confirm").checked = false;
    lastSpfSafetyKey = null;
    renderSpfBuilder();
  }

  function prefillBuilders(d) {
    $("#builder-domain").value = d.domain;
    $("#dmarc-domain").value = d.domain;
    $("#dmarc-rua").value = (d.dmarc.rua && d.dmarc.rua[0]) || "dmarc@" + d.domain;
    $("#dmarc-stage").value = d.dmarc.policy || "none";
    prefillSpfBuilder(d.domain, d.spf?.record);
    renderDmarcBuilder();
  }

  function parseSpfRecord(record) {
    const tokens = String(record || "").trim().split(/\s+/).filter(Boolean);
    if (!tokens.length || !/^v=spf1$/i.test(tokens[0])) return null;
    const terms = tokens.slice(1);
    const terminal = terms.find((term) => isTerminalSpfTerm(term));
    return {
      terms,
      terminal: terminal ? terminal.toLowerCase() : "",
    };
  }

  function isTerminalSpfTerm(term) {
    return /^[+?~-]?all$/i.test(String(term || ""));
  }

  function normalizeSpfRecord(record) {
    return String(record || "").trim().split(/\s+/).filter(Boolean).map((term) => term.toLowerCase()).join(" ");
  }

  function isSpfModifier(term) {
    return /^[+?~-]?(?:redirect|exp)=/i.test(String(term || ""));
  }

  function terminalPolicy(record) {
    const parsed = parseSpfRecord(record);
    return parsed?.terminal || "(none)";
  }

  function sameTerms(left, right) {
    return left.length === right.length && left.every((term, index) => term === right[index]);
  }

  function sameTermMultiset(left, right) {
    if (left.length !== right.length) return false;
    return [...left].sort().every((term, index) => term === [...right].sort()[index]);
  }

  function describeSpfChange(before, after) {
    if (normalizeSpfRecord(before) === normalizeSpfRecord(after)) return null;
    const beforeParsed = parseSpfRecord(before);
    const afterParsed = parseSpfRecord(after);
    const beforeTerms = (beforeParsed?.terms || []).map((term) => term.toLowerCase());
    const afterTerms = (afterParsed?.terms || []).map((term) => term.toLowerCase());
    const changes = [];
    if (beforeParsed && afterParsed) {
      if (!sameTerms(beforeTerms, afterTerms)) {
        changes.push(sameTermMultiset(beforeTerms, afterTerms)
          ? "SPF mechanism order changed."
          : "SPF mechanisms or qualifiers changed.");
      }
      if (terminalPolicy(before) !== terminalPolicy(after)) {
        changes.push(`Terminal policy changed from ${terminalPolicy(before)} to ${terminalPolicy(after)}.`);
      }
      const beforeModifiers = beforeTerms.filter(isSpfModifier).sort();
      const afterModifiers = afterTerms.filter(isSpfModifier).sort();
      if (!sameTerms(beforeModifiers, afterModifiers)) changes.push("SPF modifiers changed.");
    } else {
      changes.push("The proposed value is not shaped like the imported SPF record.");
    }
    return { before, after, changes: changes.length ? changes : ["SPF record content changed."] };
  }

  $$("#builder-spf input:not(#spf-safety-confirm), #builder-spf select").forEach((x) => {
    // "change" duplicates "input" for these controls; binding both doubled
    // every validation request. The POST itself is debounced so typing does
    // not burn the per-minute API quota.
    x.addEventListener("input", (event) => {
      if (importedSpf && event.target.id !== "spf-safety-confirm") importedSpf.preserve = false;
      renderSpfBuilder();
    });
  });
  $("#spf-safety-confirm")?.addEventListener("input", renderSpfBuilder);
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

  // ─── Batch Check ────────────────────────────────────────────────
  const batchForm = $("#batch-form");
  const batchInput = $("#batch-input");
  const batchButton = $("#batch-button");
  const batchLoading = $("#batch-loading");
  const batchError = $("#batch-error");
  const batchErrorMsg = $("#batch-error-msg");
  const batchReport = $("#batch-report");
  const batchTable = $("#batch-table");
  const batchCount = $("#batch-count");
  // Must match BATCH_MAX_DOMAINS in worker.js: each domain gets an equal
  // slice of one 45-subrequest DNS budget, so larger batches would return
  // truncated analyses rather than comparable scores.
  const BATCH_MAX_DOMAINS_UI = 3;
  let lastBatchReport = null;
  let batchSortCol = null;
  let batchSortDir = 1;

  batchInput?.addEventListener("input", () => {
    const lines = batchInput.value.split("\n").map(l => l.trim()).filter(Boolean);
    batchCount.textContent = `${Math.min(lines.length, BATCH_MAX_DOMAINS_UI)} / ${BATCH_MAX_DOMAINS_UI} domains`;
  });

  $("#batch-clear-btn")?.addEventListener("click", () => {
    batchInput.value = "";
    batchReport.classList.add("hidden");
    batchError.classList.add("hidden");
    batchCount.textContent = `0 / ${BATCH_MAX_DOMAINS_UI} domains`;
    lastBatchReport = null;
  });

  batchForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const domains = batchInput.value.split("\n").map(l => l.trim()).filter(Boolean);
    if (!domains.length) return;

    batchLoading.classList.remove("hidden");
    batchError.classList.add("hidden");
    batchReport.classList.add("hidden");
    batchButton.disabled = true;

    try {
      const r = await fetch(`${API_BASE}/api/batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domains })
      });
      const d = await r.json();
      if (d.error) {
        batchErrorMsg.textContent = d.error;
        batchError.classList.remove("hidden");
      } else {
        lastBatchReport = d;
        updateBatchShareState(d);
        renderBatchTable(d.results);
        batchReport.classList.remove("hidden");
        batchReport.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    } catch {
      batchErrorMsg.textContent = "Failed to run batch check";
      batchError.classList.remove("hidden");
    } finally {
      batchLoading.classList.add("hidden");
      batchButton.disabled = false;
    }
  });

  $("#batch-copy-link")?.addEventListener("click", () => {
    if (lastBatchReport?.id) {
      const url = `${location.origin}/#batch-${lastBatchReport.id}`;
      copyText(url);
      const btn = $("#batch-copy-link");
      const orig = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(() => { btn.textContent = orig; }, 2000);
    } else {
      updateBatchShareState(lastBatchReport);
    }
  });

  $("#batch-export")?.addEventListener("click", () => {
    if (lastBatchReport?.id) {
      window.open(`${API_BASE}/api/reports/${lastBatchReport.id}/export`, "_blank");
    } else if (lastBatchReport) {
      const blob = new Blob([JSON.stringify(lastBatchReport, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "email-security-batch.json";
      a.click();
      URL.revokeObjectURL(url);
    }
  });

  function renderBatchTable(results) {
    const sorted = batchSortCol ? [...results].sort((a, b) => {
      let va, vb;
      if (batchSortCol === "domain") { va = a.domain; vb = b.domain; }
      else if (batchSortCol === "score") { va = a.overall_score; vb = b.overall_score; }
      else { va = (a[batchSortCol]?.status || ""); vb = (b[batchSortCol]?.status || ""); }
      if (va < vb) return -1 * batchSortDir;
      if (va > vb) return 1 * batchSortDir;
      return 0;
    }) : results;

    const headers = [
      { key: "domain", label: "Domain" },
      { key: "score", label: "Score" },
      { key: "spf", label: "SPF" },
      { key: "dkim", label: "DKIM" },
      { key: "dmarc", label: "DMARC" },
      { key: "mx", label: "MX" },
      { key: "transport", label: "Transport" }
    ];

    let html = "<thead><tr>";
    headers.forEach(h => {
      const cls = batchSortCol === h.key ? (batchSortDir > 0 ? "sort-asc" : "sort-desc") : "";
      const sort = batchSortCol === h.key ? (batchSortDir > 0 ? "ascending" : "descending") : "none";
      html += '<th class="' + cls + '" aria-sort="' + sort + '"><button class="sort-button" type="button" data-col="' + h.key + '" aria-label="Sort by ' + esc(h.label) + '">' + esc(h.label) + '</button></th>';
    });
    html += "</tr></thead><tbody>";

    sorted.forEach(r => {
      const scoreCls = scoreClassFor(r.overall_score);
      const truncated = Boolean(r.request_budget?.exhausted);
      html += `<tr data-domain="${esc(r.domain)}">`;
      html += '<td class="domain-cell"><button class="batch-domain-button" type="button" data-domain="' + esc(r.domain) + '">' + esc(r.domain) + '</button></td>';
      html += `<td class="score-cell"><strong class="${scoreCls}">${r.overall_score}/100</strong>${truncated ? ' <span class="batch-status info">partial</span>' : ""}</td>`;
      html += `<td>${batchStatusCell(r.spf)}</td>`;
      html += `<td>${batchStatusCell(r.dkim)}</td>`;
      html += `<td>${batchStatusCell(r.dmarc)}</td>`;
      html += `<td>${batchStatusCell(r.mx)}</td>`;
      html += `<td>${batchStatusCell(r.transport)}</td>`;
      html += "</tr>";
    });
    html += "</tbody>";
    batchTable.innerHTML = html;
    updateBatchBudgetNote(results);

    // Sort handlers
    batchTable.querySelectorAll(".sort-button[data-col]").forEach(button => {
      button.addEventListener("click", () => {
        const col = button.dataset.col;
        if (batchSortCol === col) batchSortDir = -batchSortDir;
        else { batchSortCol = col; batchSortDir = 1; }
        renderBatchTable(lastBatchReport.results);
      });
    });

    // Use a real button for keyboard and assistive-technology access.
    batchTable.querySelectorAll(".batch-domain-button").forEach(button => {
      button.addEventListener("click", () => {
        const domain = button.dataset.domain;
        if (domain) {
          domainInput.value = domain;
          selectTool("domain");
          checkForm.requestSubmit();
        }
      });
    });
  }

  function updateBatchBudgetNote(results) {
    const note = $("#batch-budget-note");
    if (!note) return;
    const truncated = (results || []).filter(r => r.request_budget?.exhausted);
    if (truncated.length) {
      const who = truncated.length === 1
        ? truncated[0].domain
        : `${truncated.length} domains`;
      note.textContent = `${who} hit the DNS subrequest budget. Scores marked "partial" are incomplete and can look lower than reality; re-run them as single checks for full evidence.`;
      note.classList.remove("hidden");
    } else {
      note.classList.add("hidden");
    }
  }

  function updateBatchShareState(report) {
    const note = $("#batch-share-note");
    const button = $("#batch-copy-link");
    if (report?.share?.available && report.share.expiresAt) {
      note.textContent = `Public bearer link. Anyone with the link can view this batch report until ${new Date(report.share.expiresAt).toLocaleDateString()}; report responses are not cached by browsers or intermediaries.`;
      note.classList.remove("warning");
      button.disabled = false;
      button.textContent = "Copy share link";
    } else {
      note.textContent = "Share link unavailable because report storage did not complete. Export the result locally if needed.";
      note.classList.add("warning");
      button.disabled = true;
      button.textContent = "Share unavailable";
    }
  }

  function batchStatusCell(cat) {
    if (!cat || !cat.status) return '<span class="batch-status info">Unavailable</span>';
    const status = cat.status;
    const text = status === "pass" ? "Pass" : status === "warn" ? "Warn" : status === "fail" ? "Fail" : status === "info" ? "Info" : status;
    return `<span class="batch-status ${status}">${text}</span>`;
  }

  // Check for batch report in URL hash (#batch-<id>)
  const batchHashMatch = location.hash.match(/^#batch-([A-Za-z0-9_-]{16})$/);
  if (batchHashMatch) {
    (async () => {
      selectTool("batch", false);
      batchLoading.classList.remove("hidden");
      try {
        const r = await fetch(`${API_BASE}/api/reports/${batchHashMatch[1]}`);
        const d = await r.json();
        if (!d.error) {
          lastBatchReport = d;
          updateBatchShareState(d);
          renderBatchTable(d.results);
          batchReport.classList.remove("hidden");
        }
      } catch {}
      finally { batchLoading.classList.add("hidden"); }
    })();
  }

})();
