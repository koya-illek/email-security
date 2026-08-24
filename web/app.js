(() => {
  "use strict";

  const API_BASE = (window.EMAIL_CHECKER_CONFIG?.API_BASE || "").replace(/\/$/, "");
  // Mirrors HEADER_JSON_BODY_MAX_BYTES in worker.js so an impossible paste is
  // refused before spending its upload instead of failing at the server.
  const HEADER_PASTE_MAX_BYTES = 256 * 1024;
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => [...document.querySelectorAll(sel)];

  let lastHeaderAnalysis = null;
  let lastDomainReport = null;
  let spfValidationSequence = 0;
  let dmarcValidationSequence = 0;
  let importedSpf = null;
  let lastSpfSafetyKey = null;

  // Async answers must never resurrect state the user discarded (Clear,
  // New check, editing the input) or double-render after a re-trigger. Each
  // flow captures the generation before its first await and bails when a
  // user action advanced it meanwhile.
  function createGeneration() {
    let value = 0;
    return {
      next: () => ++value,
      current: () => value
    };
  }

  // Server-derived status strings land in class attributes; only the closed
  // set below may style a sink there, so an unexpected value can never
  // smuggle attacker-chosen tokens into the document.
  function safeStatusClass(status) {
    return ["pass", "warn", "fail", "info"].includes(status) ? status : "info";
  }

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
  function selectBuilder(name) {
    $$(".builder-tab").forEach((tab) => {
      const active = tab.dataset.builder === name;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
    });
    $$(".builder-pane").forEach((pane) => {
      const active = pane.id === "builder-" + name;
      pane.classList.toggle("active", active);
      pane.hidden = !active;
    });
  }

  $$(".builder-tab").forEach((tab) =>
    tab.addEventListener("click", () => selectBuilder(tab.dataset.builder))
  );

  $(".builder-tabs")?.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    const tabs = $$(".builder-tab");
    const current = tabs.indexOf(document.activeElement);
    const next = event.key === "Home" ? 0
      : event.key === "End" ? tabs.length - 1
      : event.key === "ArrowRight" ? (current + 1) % tabs.length
      : (current - 1 + tabs.length) % tabs.length;
    event.preventDefault();
    selectBuilder(tabs[next].dataset.builder);
    tabs[next].focus();
  });

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

  // Resolves true only when a copy path actually reported success; the
  // execCommand fallback covers non-secure origins where
  // navigator.clipboard is undefined rather than throwing before it runs.
  async function copyText(value) {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
        return true;
      }
      throw new Error("Async clipboard unavailable");
    } catch {
      try {
        const t = document.createElement("textarea");
        t.value = value;
        t.setAttribute("readonly", "");
        t.style.position = "fixed";
        t.style.opacity = "0";
        document.body.appendChild(t);
        t.select();
        const ok = document.execCommand("copy");
        t.remove();
        return ok;
      } catch {
        return false;
      }
    }
  }

  // Feedback reads from the pre-click label stored on the element, so rapid
  // re-clicks cannot capture the transient "Copied!" as the restore target.
  function flashCopyState(button, ok) {
    if (!button) return;
    if (!button.dataset.label) button.dataset.label = button.textContent;
    clearTimeout(button._copyTimer);
    button.textContent = ok ? "Copied!" : "Copy failed";
    button._copyTimer = setTimeout(() => { button.textContent = button.dataset.label; }, 2000);
  }

  // An edge or proxy failure can answer any API call with a non-JSON page;
  // surfacing the parser's syntax error would describe our tooling, not the
  // user's problem.
  async function parseApiResponse(response, serviceLabel) {
    try {
      return await response.json();
    } catch {
      throw new Error(`The ${serviceLabel} service returned an unreadable response. Try again shortly.`);
    }
  }

  // Explicit "smooth" bypasses the CSS prefers-reduced-motion override, so
  // programmatic scrolls consult the media query themselves.
  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  function revealResults(el) {
    el.scrollIntoView({ behavior: prefersReducedMotion.matches ? "auto" : "smooth", block: "start" });
  }

  // Completed analyses swap whole report sections into the page; announcing
  // those containers verbatim buries screen-reader users in markup. The
  // hidden status region carries one short completion line instead, and the
  // clear-then-set dance re-announces identical retry messages.
  const analysisStatusRegion = $("#analysis-status");
  function announceAnalysis(message) {
    if (!analysisStatusRegion) return;
    analysisStatusRegion.textContent = "";
    setTimeout(() => { analysisStatusRegion.textContent = message; }, 50);
  }

  // Numeric-only dates ("9/5/2026") are ambiguous across locales; a bearer
  // link's expiry must read the same way for everyone.
  function longDate(value) {
    const date = new Date(value);
    return Number.isNaN(date.getTime())
      ? ""
      : date.toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric" });
  }

  // Live payloads are still external-shaped data: a count that arrives as a
  // string or goes missing reads as "unavailable", never as "undefined/10".
  function asCount(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
  }

  function countLabel(count, limit) {
    return count === null ? "unavailable" : `${count}/${limit}`;
  }

  // ─── Share + Export buttons ──────────────────────────────────
  $("#copy-share-link")?.addEventListener("click", async () => {
    const btn = $("#copy-share-link");
    if (lastDomainReport?.id) {
      const url = `${location.origin}/#${lastDomainReport.id}`;
      flashCopyState(btn, await copyText(url));
    } else {
      setShareUnavailable($("#domain-share-note"), btn);
    }
  });

  $("#export-json")?.addEventListener("click", () => {
    if (lastDomainReport?.id) {
      window.open(`${API_BASE}/api/reports/${lastDomainReport.id}/export`, "_blank", "noopener,noreferrer");
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
  // A second link opened while one is loading must win; the loser's panels
  // and render are abandoned when its sequence number is stale.
  let sharedReportSequence = 0;
  async function loadSharedReport(reportId, options = {}) {
    const sequence = ++sharedReportSequence;
    const stale = () => sequence !== sharedReportSequence;
    // The #batch- prefix is a hint for which panel owns failures and the
    // loading spinner; success always dispatches on the stored _reportType.
    const preferBatch = options.prefer === "batch";
    const loadingPanel = preferBatch ? batchLoading : domainLoading;
    const errorPanel = preferBatch ? batchError : domainError;
    const reportPanel = preferBatch ? batchReport : domainReport;
    errorPanel.classList.add("hidden");
    reportPanel.classList.add("hidden");
    loadingPanel.classList.remove("hidden");
    if (preferBatch) selectTool("batch", false);
    try {
      const r = await fetch(`${API_BASE}/api/reports/${reportId}`);
      const d = await parseApiResponse(r, "report");
      if (stale()) return;
      if (!r.ok || d.error) throw new Error(d.error || "Report not found or expired");
      if (d._reportType === "batch") {
        // Share links may lose their #batch- prefix; dispatch on the stored
        // report type instead of assuming a bare hash is a domain report.
        lastBatchReport = d;
        updateBatchShareState(d);
        renderBatchTable(d.results);
        updateBatchRejectedNote(d.validation);
        batchReport.classList.remove("hidden");
        selectTool("batch", false);
      } else {
        showDomainResults(d);
      }
    } catch (err) {
      if (stale()) return;
      const message = err?.message || "Failed to load shared report";
      if (preferBatch) {
        batchErrorMsg.textContent = message;
        batchError.classList.remove("hidden");
        selectTool("batch", false);
      } else {
        showDomainError(message);
        selectTool("domain", false);
      }
    } finally {
      if (!stale()) loadingPanel.classList.add("hidden");
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

  const domainGeneration = createGeneration();
  let domainCheckInFlight = false;
  let domainCheckPromise = null;

  // Editing the field orphans the in-flight answer: when the response lands,
  // the generation mismatch stops it from rendering under a different domain.
  domainInput?.addEventListener("input", () => domainGeneration.next());

  checkForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const domain = domainInput.value.trim();
    if (!domain || domainCheckInFlight) return;
    // Trigger paths (batch-row buttons) call requestSubmit(), which runs this
    // handler even with the submit button disabled; the flag keeps those
    // activations serial and exposes the running request so triggers can
    // queue behind it instead of being dropped.
    domainCheckInFlight = true;
    const generation = domainGeneration.current();
    domainLoading.classList.remove("hidden");
    domainError.classList.add("hidden");
    domainReport.classList.add("hidden");
    checkButton.disabled = true;
    domainCheckPromise = (async () => {
      try {
        const r = await fetch(`${API_BASE}/api/check`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain }),
        });
        const d = await parseApiResponse(r, "domain check");
        if (generation !== domainGeneration.current()) return;
        if (d.error) showDomainError(d.error);
        else showDomainResults(d);
      } catch (err) {
        if (generation === domainGeneration.current()) {
          showDomainError(err.message || "Failed to analyze domain");
        }
      } finally {
        domainCheckInFlight = false;
        domainLoading.classList.add("hidden");
        checkButton.disabled = false;
        domainCheckPromise = null;
      }
    })();
  });

  $("#new-check")?.addEventListener("click", () => {
    domainGeneration.next();
    domainReport.classList.add("hidden");
    domainInput.focus();
  });

  // Programmatic seeding (these buttons and the batch-table rows) never fires
  // the field's input listener, so the trigger advances its flow's generation
  // itself, waits out any request still running under the serial in-flight
  // guard, and only submits while the seeded value is still what the field
  // holds. Without this, a click during an active check silently dropped the
  // new request and the stale answer rendered beneath the new domain.
  $("#inspect-from-report")?.addEventListener("click", async () => {
    if (!lastDomainReport) return;
    const domain = lastDomainReport.domain;
    spfInput.value = domain;
    spfInspectGeneration.next();
    selectTool("spf");
    const pending = spfInspectPromise;
    if (pending) await pending.catch(() => {});
    if (spfInput.value !== domain) return;
    $("#spf-form").requestSubmit();
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
      shareNote.textContent = `Public bearer link. Anyone with the link can view this report until ${longDate(d.share.expiresAt)}; report responses are not cached by browsers or intermediaries.`;
      shareNote.classList.remove("warning");
      shareButton.disabled = false;
      shareButton.textContent = "Copy share link";
    } else {
      setShareUnavailable(shareNote, shareButton);
    }

    // Metrics
    const score = Number.isFinite(d.overall_score) ? d.overall_score : null;
    domainMetrics.innerHTML = `
      <div class="metric"><small>Security Score</small><strong class="${score === null ? "info" : scoreClassFor(score)}">${score === null ? "unavailable" : `${score}/100`}</strong></div>
      ${metricCell("SPF", d.spf)}
      ${metricCell("DKIM", d.dkim)}
      ${metricCell("DMARC", d.dmarc)}
      ${metricCell("MX", d.mx)}
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
    revealResults(domainReport);
    announceAnalysis(
      `Analysis of ${d.domain || "the domain"} complete. Security score ${score === null ? "unavailable" : `${score} out of 100`}, confidence ${d.score_confidence || "unknown"}.`
    );
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

  function scoreClassFor(score) {
    return score >= 70 ? "good" : score >= 50 ? "warn" : "poor";
  }

  // Share links replay stored D1 rows verbatim for 14 days regardless of
  // analysis schema version, so every category below is treated as external
  // input: a missing or shape-drifted value reads as an inconclusive metric,
  // never as a failing one and never as a render crash.
  function metricCell(label, cat) {
    const status = typeof cat?.status === "string" ? cat.status : "";
    return `<div class="metric"><small>${label}</small><strong class="${safeStatusClass(status)}">${esc(status || "unavailable")}</strong></div>`;
  }

  function sectionChip(d) {
    const status = typeof d?.status === "string" ? d.status : "";
    return `<span class="cs-count ${safeStatusClass(status)}">${esc(status || "unavailable")}</span>`;
  }

  function createResultSection(icon, title, d) {
    const checks = (d?.checks || []).map(checkItem).join("");

    const record = d?.record
      ? `<div class="record-box"><strong>DNS Record</strong>${esc(d.record)}</div>`
      : "";

    const selectors =
      d?.selectors && d.selectors.length
        ? `<div class="record-box"><strong>Found DKIM Selectors</strong>${d.selectors
            .map((x) => `<code>${esc(x.selector)}</code>`)
            .join("<br>")}
        </div>`
        : "";

    return `<details class="collapsible-section">
      <summary>
        <span class="cs-icon">${icon}</span>
        <span class="cs-title">${title}</span>
        ${sectionChip(d)}
      </summary>
      <div class="cs-body">
        ${record}${selectors}${checks}
      </div>
    </details>`;
  }

  function checkItem(x) {
    return `<div class="check-item ${safeStatusClass(x.status)}">
      <div class="check-dot"></div>
      <div class="check-content">
        <div class="check-title">${esc(x.title)}</div>
        <div class="check-detail">${esc(x.detail)}</div>
        ${x.recommendation ? `<div class="check-recommendation"><strong>${x.recommendationLabel || "Recommendation"}</strong>${esc(x.recommendation)}</div>` : ""}
      </div>
    </div>`;
  }

  function mxCheckItems(d) {
    return (d?.checks || []).map(checkItem).join("");
  }

  function createMXSection(d) {
    // The chip must reflect the analyzed status: the mixed Null-MX failure
    // arrives with records present, so "N found" alone would style a failing
    // lookup as healthy.
    const status = typeof d?.status === "string" ? d.status : (d?.records?.length ? "pass" : "");
    const chip = `<span class="cs-count ${safeStatusClass(status)}">${esc(status || (d?.records?.length ? "pass" : "unavailable"))}</span>`;
    if (!d?.records || !d.records.length) {
      const body = mxCheckItems(d)
        || (d
          ? '<p class="muted">No MX records found.</p>'
          : '<p class="muted">MX evidence is not present in this stored report.</p>');
      return `<details class="collapsible-section">
        <summary>
          <span class="cs-icon">MX</span>
          <span class="cs-title">MX Records</span>
          ${chip}
        </summary>
        <div class="cs-body">${body}</div>
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
        ${chip}
      </summary>
      <div class="cs-body">
        <table class="mx-table"><thead><tr><th>Priority</th><th>Mail Server</th></tr></thead><tbody>${rows}</tbody></table>
        ${mxCheckItems(d)}
      </div>
    </details>`;
  }

  function createPTRSection(d) {
    const checks = (d?.checks || []).map(checkItem).join("");
    return `<details class="collapsible-section">
      <summary>
        <span class="cs-icon">PTR</span>
        <span class="cs-title">Reverse DNS (PTR)</span>
        ${sectionChip(d)}
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

  const spfInspectGeneration = createGeneration();
  let spfInspectInFlight = false;
  let spfInspectPromise = null;

  spfInput?.addEventListener("input", () => spfInspectGeneration.next());

  spfForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const domain = spfInput.value.trim();
    if (!domain || spfInspectInFlight) return;
    // requestSubmit() from "Inspect SPF" runs this handler even while the
    // submit button is disabled; the flag stops duplicate racing requests and
    // exposes the running one so the trigger path can queue behind it.
    spfInspectInFlight = true;
    const generation = spfInspectGeneration.current();
    spfLoading.classList.remove("hidden");
    spfError.classList.add("hidden");
    spfReport.classList.add("hidden");
    spfButton.disabled = true;
    spfInspectPromise = (async () => {
      try {
        const r = await fetch(`${API_BASE}/api/spf/inspect`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain }),
        });
        const d = await parseApiResponse(r, "SPF inspection");
        if (generation !== spfInspectGeneration.current()) return;
        if (d.error) showSpfError(d.error);
        else showSpfInspector(d);
      } catch (err) {
        if (generation === spfInspectGeneration.current()) {
          showSpfError(err.message || "Failed to inspect SPF");
        }
      } finally {
        spfInspectInFlight = false;
        spfLoading.classList.add("hidden");
        spfButton.disabled = false;
        spfInspectPromise = null;
      }
    })();
  });

  function showSpfError(msg) {
    spfErrorMsg.textContent = msg;
    spfError.classList.remove("hidden");
  }

  function showSpfInspector(d) {
    try {
      renderSpfInspector(d);
    } catch {
      // Inspection answers arrive over the network even though they share the
      // deployment; a drifted payload must degrade to readable copy, never to
      // a raw TypeError surfaced through the error panel.
      spfReport.classList.add("hidden");
      showSpfError("The SPF inspection returned evidence this page could not render. Run the inspection again.");
    }
  }

  function renderSpfInspector(d) {
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

    const recursive = asCount(d.spf?.lookupCount ?? f.originalLookups);
    const flattened = asCount(f.flattenedLookups);
    const characters = asCount(f.characterCount);
    const safePreview = f.safeToPublish === true;

    $("#spf-summary").innerHTML = `
      <div class="metric"><small>Recursive lookups</small><strong>${countLabel(recursive, 10)}</strong></div>
      <div class="metric"><small>After preview</small><strong>${countLabel(flattened, 10)}</strong></div>
      <div class="metric"><small>Record length</small><strong>${characters === null ? "unavailable" : characters}</strong></div>
    `;

    let html = "";
    // Qualitative findings from the inspection itself (multiple records,
    // ptr mechanisms, permissive all) are easy to miss when the flattening
    // preview below looks healthy. Render them first when they matter.
    if ((spf.status === "fail" || spf.status === "warn") && Array.isArray(spf.checks) && spf.checks.length) {
      html += `<details class="collapsible-section" open>
        <summary>
          <span class="cs-icon">SPF</span>
          <span class="cs-title">Inspection findings</span>
          <span class="cs-count ${safeStatusClass(spf.status)}">${esc(spf.status)}</span>
        </summary>
        <div class="cs-body">
          ${spf.checks.map(checkItem).join("")}
        </div>
      </details>`;
    }
    html += `<div class="output-card">
      <div class="output-head"><strong>Current SPF record</strong><button class="copy-btn" data-copy="original">Copy</button></div>
      <div class="dns-value">${esc(f.originalRecord)}</div>
    </div>`;

    html += `<div class="output-card">
      <div class="output-head"><strong>Flattened preview</strong><button class="copy-btn" data-copy="flattened" ${safePreview ? "" : "disabled"}>${safePreview ? "Copy validated preview" : "Review required"}</button></div>
      <div class="dns-value">${esc(f.record)}</div>
    </div>`;

    const flatWarnings = [
      ...(Array.isArray(f.validation?.errors) ? f.validation.errors : []),
      ...(Array.isArray(f.warnings) ? f.warnings : []),
    ];
    html += `<div class="notice ${safePreview ? "good" : ""}">
      <strong>${safePreview ? "Validated point-in-time preview" : "Copy blocked; manual review required"}</strong>
      ${flatWarnings.map(esc).join("<br>")}
    </div>`;

    const sources = Array.isArray(f.sources) ? f.sources : [];
    if (sources.length) {
      html += `<details class="collapsible-section" open>
        <summary>
          <span class="cs-icon">SRC</span>
          <span class="cs-title">Expanded sources</span>
          <span class="cs-count info">${sources.length} records</span>
        </summary>
        <div class="cs-body">
          ${sources
            .map(
              (x) =>
                `<div class="source-group"><code>${esc(x.source)}</code><span>${esc((Array.isArray(x.mechanisms) ? x.mechanisms : []).join(" "))}</span></div>`
            )
            .join("")}
        </div>
      </details>`;
    }

    html += `<div class="header-actions">
      <button class="secondary-button" data-action="use-spf">${safePreview ? "Use preview in Record Builder" : "Use original in Record Builder"}</button>
    </div>`;

    $("#spf-detail").innerHTML = html;
    spfReport.classList.remove("hidden");
    // The inspector renders below the form; on a phone the finished report is
    // off-screen, so completion scrolls it into view like the domain flow.
    revealResults(spfReport);

    // Bind buttons
    $("#spf-detail [data-copy='original']").onclick = async (event) =>
      flashCopyState(event.currentTarget, await copyText(f.originalRecord));
    if (safePreview) {
      $("#spf-detail [data-copy='flattened']").onclick = async (event) =>
        flashCopyState(event.currentTarget, await copyText(f.record));
    }
    $("#spf-detail [data-action='use-spf']").onclick = () => {
      // An unsafe flattened preview is evidence for review, not a proposed
      // replacement. Seed the builder with the imported source record so the
      // preview cannot silently become its trusted baseline.
      prefillSpfBuilder(d.domain, safePreview ? f.record : f.originalRecord);
      selectTool("builder");
    };

    announceAnalysis(
      `SPF inspection of ${d.domain} complete. ${recursive === null ? "Lookup counts unavailable" : `${recursive} recursive lookups`}, preview uses ${flattened === null ? "an unavailable lookup count" : flattened}.`
    );
  }

  // ─── Record Builder ──────────────────────────────────────────────
  function outputCard(title, host, value, warning) {
    return `<div class="output-card">
      <div class="output-head"><strong>${esc(title)}</strong><button class="copy-btn" disabled>Validating…</button></div>
      <div class="field-help output-host">Host: ${esc(host)}</div>
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
    button.onclick = async () => flashCopyState(button, await copyText(record));
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

    // A pristine builder (no domain, no mechanisms, no import) has nothing to
    // validate. Skipping the POST here stops every page view from spending
    // validation quota and two daily-counter writes before the Record Builder
    // is ever opened; the first input resumes the normal debounced flow.
    if (!domain && !terms.length && !importedSpf) {
      // Also cancel a validation scheduled before this render emptied the
      // builder; firing it would spend quota on a record that no longer exists.
      clearTimeout(spfValidationTimer);
      const button = root.querySelector(".copy-btn");
      if (button) {
        button.textContent = "Enter a domain to validate";
        button.disabled = true;
      }
      return;
    }

    scheduleSpfValidation(sequence, root, extra, domain, record);
  }

  const VALIDATION_DEBOUNCE_MS = 500;
  let spfValidationTimer = 0;
  let dmarcValidationTimer = 0;

  // A validation answer is only trustworthy when it carries the validation
  // shape. HTTP-error envelopes ({error}, e.g. a record body over the API's
  // 16 KiB cap) and non-JSON pages must land in showValidation's blocked
  // branch, never in its "Valid record" branch with copying enabled.
  async function requestRecordValidation(type, domain, record) {
    const response = await fetch(`${API_BASE}/api/records/validate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type, domain, record }),
    });
    let payload = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    if (!response.ok || !payload || typeof payload !== "object" || payload.error || !Array.isArray(payload.errors)) {
      const reason = payload?.error || `HTTP ${response.status}`;
      return { errors: [`This record could not be validated (${reason}).`], warnings: [] };
    }
    return payload;
  }

  function scheduleSpfValidation(sequence, root, extra, domain, record) {
    // Only the validation POST is debounced; the rest of the render stays
    // synchronous so safety-state resets keep their event ordering.
    clearTimeout(spfValidationTimer);
    spfValidationTimer = setTimeout(async () => {
      try {
        const validation = await requestRecordValidation("spf", domain, record);
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

    if (!domain && !rua) {
      // Idle DMARC planner: same quota rationale as the idle SPF builder,
      // including cancelling anything scheduled before this render.
      clearTimeout(dmarcValidationTimer);
      const button = root.querySelector(".copy-btn");
      if (button) {
        button.textContent = "Enter a domain to validate";
        button.disabled = true;
      }
      return;
    }

    clearTimeout(dmarcValidationTimer);
    dmarcValidationTimer = setTimeout(async () => {
      try {
        const validation = await requestRecordValidation("dmarc", domain, record);
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
    const domain = typeof d?.domain === "string" ? d.domain : "";
    $("#builder-domain").value = domain;
    $("#dmarc-domain").value = domain;
    const rua = Array.isArray(d?.dmarc?.rua) ? d.dmarc.rua[0] : null;
    $("#dmarc-rua").value = rua || (domain ? "dmarc@" + domain : "");
    $("#dmarc-stage").value = d?.dmarc?.policy || "none";
    prefillSpfBuilder(domain, d?.spf?.record);
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
  const headerLoading = $("#header-loading");
  const analyzeHeadersBtn = $("#analyze-headers-btn");
  const enrichHeadersBtn = $("#enrich-headers-btn");
  const clearHeadersBtn = $("#clear-headers-btn");
  const headerError = $("#header-error");
  const headerErrorMsg = $("#header-error-msg");

  // Editing the textarea invalidates both the stored analysis and any
  // in-flight answer; a response that lands after this must not render.
  const headerGeneration = createGeneration();

  function resetHeaderState() {
    headerGeneration.next();
    lastHeaderAnalysis = null;
    enrichHeadersBtn.disabled = true;
  }

  headerInput?.addEventListener("input", () => {
    resetHeaderState();
    headerResults.innerHTML = "";
    headerError.classList.add("hidden");
  });

  analyzeHeadersBtn?.addEventListener("click", runHeaderAnalysis);

  async function runHeaderAnalysis() {
    const raw = headerInput.value.trim();
    if (!raw) {
      showHeaderError("Paste the complete message headers first.");
      return;
    }
    if (new TextEncoder().encode(raw).byteLength > HEADER_PASTE_MAX_BYTES) {
      showHeaderError(`These headers exceed the ${HEADER_PASTE_MAX_BYTES / 1024} KiB analysis limit. Paste the headers of one complete message, without the body, and retry.`);
      return;
    }
    const generation = headerGeneration.current();
    analyzeHeadersBtn.disabled = true;
    analyzeHeadersBtn.textContent = "Analyzing…";
    headerLoading.classList.remove("hidden");
    try {
      const r = await fetch(`${API_BASE}/api/header/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ headers: raw }),
      });
      const d = await parseApiResponse(r, "header analysis");
      if (!r.ok || d.error) throw new Error(d.error || "Header analysis failed");
      if (generation !== headerGeneration.current()) return;
      lastHeaderAnalysis = d;
      showHeaderAnalysis(d);
      enrichHeadersBtn.disabled = !d.ips.length;
    } catch (err) {
      if (generation === headerGeneration.current()) {
        showHeaderError(err.message || "Header analysis failed");
      }
    } finally {
      analyzeHeadersBtn.disabled = false;
      analyzeHeadersBtn.textContent = "Analyze Headers";
      headerLoading.classList.add("hidden");
    }
  }

  clearHeadersBtn?.addEventListener("click", () => {
    resetHeaderState();
    headerInput.value = "";
    headerResults.innerHTML = "";
    headerError.classList.add("hidden");
  });

  enrichHeadersBtn?.addEventListener("click", async () => {
    if (!lastHeaderAnalysis || !lastHeaderAnalysis.ips.length) return;
    const generation = headerGeneration.current();
    const analysis = lastHeaderAnalysis;
    enrichHeadersBtn.disabled = true;
    enrichHeadersBtn.textContent = "Enriching…";
    try {
      const r = await fetch(`${API_BASE}/api/header/enrich`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ips: analysis.ips }),
      });
      const d = await parseApiResponse(r, "hop enrichment");
      if (!r.ok || d.error) throw new Error(d.error || "PTR lookup failed");
      if (generation !== headerGeneration.current() || lastHeaderAnalysis !== analysis) return;
      analysis.enrichment = d.enriched || [];
      showHeaderAnalysis(analysis);
    } catch (err) {
      if (generation === headerGeneration.current()) {
        showHeaderError(err.message || "Hop enrichment failed");
      }
    } finally {
      enrichHeadersBtn.textContent = "Enrich Hops";
      enrichHeadersBtn.disabled = !(lastHeaderAnalysis?.ips.length);
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
    let html = `<div class="trust-banner ${safeStatusClass(summary.status)}">
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
        <span class="cs-count ${safeStatusClass(summary.status)}">${esc(summary.status)}</span>
      </summary>
      <div class="cs-body">
        ${d.checks.map((x) => checkItem({ ...x, recommendationLabel: "Recommended next step" })).join("")}
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
        <p class="muted hop-chain-note">Hop 1 is the newest, topmost Received header. Later numbers move toward the earliest recorded sender-side hop.</p>
        <div class="hop-list">
          ${d.hops.length ? d.hops.map((h) => renderHop(h, d.enrichment)).join("") : '<p class="muted">No Received headers found. Use the complete post-delivery message source.</p>'}
        </div>
      </div>
    </details>`;

    headerResults.innerHTML = html;
    headerError.classList.add("hidden");
    // Same below-the-fold completion as the SPF inspector: bring the verdict
    // to the user instead of hoping they scroll past the paste field.
    revealResults(headerResults);
    announceAnalysis(`Header analysis complete. Verdict: ${summary.verdict}.`);
  }

  function renderHop(h, enrichment) {
    const addresses = (h.ips || [])
      .map((ip) => {
        const e = (enrichment || []).find((x) => x.ip === ip);
        if (!e) return `<div><code>${esc(ip)}</code></div>`;
        // A PTR answer we could not read is not the same as a host with no
        // reverse DNS; say which one happened.
        const ptrText = e.dns
          ? "PTR inconclusive (DNS trouble)"
          : `PTR: ${e.ptr || "none found"}`;
        return `<div><code>${esc(ip)}</code><span class="muted"> · ${esc(ptrText)}</span></div>`;
      })
      .join("");

    const route = `<div class="hop-route"><code>${esc(h.from || "unknown source")}</code><span class="muted">→</span><code>${esc(h.by || "unknown receiver")}</code></div>`;
    const meta = [h.protocol && "Protocol: " + h.protocol, h.id && "ID: " + h.id, h.date && "Time: " + h.date]
      .filter(Boolean)
      .map((x) => `<span>${esc(x)}</span>`)
      .join("");

    return `<div class="hop-item">
      <strong>Hop ${esc(h.index)} · ${esc(h.position)}</strong>
      ${route}
      <div class="hop-meta">${meta}</div>
      ${addresses ? `<div class="hop-addresses">${addresses}</div>` : ""}
      <details class="hop-raw"><summary class="muted">Raw Received header</summary><div class="muted hop-raw-value">${esc(h.value)}</div></details>
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

  const batchGeneration = createGeneration();

  batchInput?.addEventListener("input", () => {
    // Like the single-domain input, editing orphans any in-flight batch so a
    // response for discarded lines cannot render afterwards.
    batchGeneration.next();
    const lines = batchInput.value.split("\n").map(l => l.trim()).filter(Boolean);
    updateBatchCount(lines.length);
  });

  function updateBatchCount(count) {
    const extra = count - BATCH_MAX_DOMAINS_UI;
    const over = extra > 0;
    batchCount.textContent = `${Math.min(count, BATCH_MAX_DOMAINS_UI)} / ${BATCH_MAX_DOMAINS_UI} domains` +
      (over ? ` — ${extra} extra line${extra === 1 ? "" : "s"} rejected` : "");
    batchCount.classList.toggle("over-limit", over);
  }

  $("#batch-clear-btn")?.addEventListener("click", () => {
    // A response landing after this click belongs to a discarded batch.
    batchGeneration.next();
    batchInput.value = "";
    batchTable.innerHTML = "";
    batchReport.classList.add("hidden");
    batchError.classList.add("hidden");
    $("#batch-rejected-note")?.classList.add("hidden");
    updateBatchCount(0);
    lastBatchReport = null;
  });

  batchForm?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const domains = batchInput.value.split("\n").map(l => l.trim()).filter(Boolean);
    if (!domains.length) {
      // An empty submit must read as refused input, not as a dead button.
      batchErrorMsg.textContent = "Paste at least one domain, one per line, then run the check.";
      batchError.classList.remove("hidden");
      return;
    }
    if (domains.length > BATCH_MAX_DOMAINS_UI) {
      // Rejecting here avoids spending rate-limit quota on a request the
      // server is guaranteed to refuse.
      batchErrorMsg.textContent = `A batch may contain at most ${BATCH_MAX_DOMAINS_UI} domains; trim the list and retry.`;
      batchError.classList.remove("hidden");
      return;
    }

    const generation = batchGeneration.current();
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
      const d = await parseApiResponse(r, "batch check");
      if (generation !== batchGeneration.current()) return;
      if (d.error) {
        batchErrorMsg.textContent = d.error;
        batchError.classList.remove("hidden");
      } else {
        lastBatchReport = d;
        updateBatchShareState(d);
        renderBatchTable(d.results);
        updateBatchRejectedNote(d.validation);
        batchReport.classList.remove("hidden");
        revealResults(batchReport);
        announceAnalysis(
          `Batch comparison complete. ${Array.isArray(d.results) ? d.results.length : 0} domains compared.`
        );
      }
    } catch (err) {
      if (generation === batchGeneration.current()) {
        batchErrorMsg.textContent = err.message || "Failed to run batch check";
        batchError.classList.remove("hidden");
      }
    } finally {
      batchLoading.classList.add("hidden");
      batchButton.disabled = false;
    }
  });

  $("#batch-copy-link")?.addEventListener("click", async () => {
    const btn = $("#batch-copy-link");
    if (lastBatchReport?.id) {
      const url = `${location.origin}/#batch-${lastBatchReport.id}`;
      flashCopyState(btn, await copyText(url));
    } else {
      updateBatchShareState(lastBatchReport);
    }
  });

  $("#batch-export")?.addEventListener("click", () => {
    if (lastBatchReport?.id) {
      window.open(`${API_BASE}/api/reports/${lastBatchReport.id}/export`, "_blank", "noopener,noreferrer");
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
    // Stored batch reports replay through here as external data; a missing
    // results array renders an empty table rather than crashing the panel.
    const rows = Array.isArray(results) ? results : [];
    const sorted = batchSortCol ? [...rows].sort((a, b) => {
      let va, vb;
      if (batchSortCol === "domain") { va = a.domain; vb = b.domain; }
      else if (batchSortCol === "score") { va = a.overall_score; vb = b.overall_score; }
      else { va = (a[batchSortCol]?.status || ""); vb = (b[batchSortCol]?.status || ""); }
      if (va < vb) return -1 * batchSortDir;
      if (va > vb) return 1 * batchSortDir;
      return 0;
    }) : rows;

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
      const truncated = Boolean(r.request_budget?.exhausted);
      html += `<tr data-domain="${esc(r.domain)}">`;
      html += '<td class="domain-cell"><button class="batch-domain-button" type="button" data-domain="' + esc(r.domain) + '">' + esc(r.domain) + '</button></td>';
      // An errored row is not a scored row; showing 0/100 would present an
      // internal failure as a failing domain.
      const scoreCell = r.overall_status === "error"
        ? `<span class="batch-status info" title="${esc(r.error || "Analysis failed")}">error</span>`
        : Number.isFinite(r.overall_score)
          ? `<strong class="${scoreClassFor(r.overall_score)}">${r.overall_score}/100</strong>${truncated ? ' <span class="batch-status info">partial</span>' : ""}`
          : `<span class="batch-status info" title="This stored report predates the current score format">unavailable</span>`;
      html += `<td class="score-cell">${scoreCell}</td>`;
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
        renderBatchTable(lastBatchReport?.results);
      });
    });

    // Use a real button for keyboard and assistive-technology access.
    batchTable.querySelectorAll(".batch-domain-button").forEach(button => {
      button.addEventListener("click", async () => {
        const domain = button.dataset.domain;
        if (!domain) return;
        domainInput.value = domain;
        // Orphan any in-flight answer for the previously checked domain, let
        // its request drain so the serial guard releases, then submit only
        // while the seeded value still stands.
        domainGeneration.next();
        selectTool("domain");
        const pending = domainCheckPromise;
        if (pending) await pending.catch(() => {});
        if (domainInput.value !== domain) return;
        checkForm.requestSubmit();
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

  function updateBatchRejectedNote(validation) {
    // The API refuses invalid, duplicate, or over-limit lines while still
    // scoring the rest; without this note those lines vanish silently.
    const note = $("#batch-rejected-note");
    if (!note) return;
    const rejected = Array.isArray(validation?.rejected) ? validation.rejected : [];
    if (!rejected.length) {
      note.classList.add("hidden");
      return;
    }
    const items = rejected.map(item => `"${item.input ?? "(blank)"}" (${item.error || "rejected"})`);
    note.textContent = `${rejected.length} line${rejected.length === 1 ? " was" : "s were"} not checked: ${items.join("; ")}. The table below covers the accepted domains only.`;
    note.classList.remove("hidden");
  }

  function updateBatchShareState(report) {
    const note = $("#batch-share-note");
    const button = $("#batch-copy-link");
    if (report?.share?.available && report.share.expiresAt) {
      note.textContent = `Public bearer link. Anyone with the link can view this batch report until ${longDate(report.share.expiresAt)}; report responses are not cached by browsers or intermediaries.`;
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
    // Stored reports replay through this sink, so the text is escaped like
    // every other server-derived string.
    return `<span class="batch-status ${safeStatusClass(status)}">${esc(text)}</span>`;
  }

  // Check for batch report in URL hash (#batch-<id>)
  const batchHashMatch = location.hash.match(/^#batch-([A-Za-z0-9_-]{16})$/);
  if (batchHashMatch) {
    queueMicrotask(() => loadSharedReport(batchHashMatch[1], { prefer: "batch" }));
  }

  // Share links are meant to be pasted into a tab that is already open, so
  // hash changes route exactly like the boot dispatch: report ids load their
  // stored report, tab names switch panels, everything else is ignored (the
  // in-page #principles anchor among it). replaceState from tab clicks never
  // fires this event, so the two paths cannot loop.
  window.addEventListener("hashchange", () => {
    const h = location.hash.slice(1);
    const batchMatch = h.match(/^batch-([A-Za-z0-9_-]{16})$/);
    if (batchMatch) {
      loadSharedReport(batchMatch[1], { prefer: "batch" });
      return;
    }
    if (/^[A-Za-z0-9_-]{16}$/.test(h)) {
      loadSharedReport(h);
      return;
    }
    if (knownTabs.includes(h)) selectTool(h, false);
  });

})();
