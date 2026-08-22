# Improvement Plan — Round 2 (2026-08-22)

Fresh-eyes review of the working tree after round 1 (`fix/review-2026-08-22`).
Round 1 fixed the batch budget starvation, SPF Inspector inconclusive states,
builder debounce, D1 fail-closed coupling, bare-hash batch dispatch, `--panel`,
touch targets, contrast, dead `_headers`, MCP streaming cap, and duplicate
`scoreClass`. This plan covers what a second pass found. No High-severity
issues remain; items below are Medium/Low.

## Technical

### T1 — Conformance harness collides with stale dev servers on its fixed port
- **What:** `test/conformance.mjs` hard-codes port 8797. A leftover
  `wrangler dev`/`workerd` from any previous or crashed run keeps serving that
  port; `waitForWorker()` then talks to the zombie, which may run old code, and
  assertions fail with confusing statuses (reproduced today: a 500 on
  `/api/records/validate` from a stale process while the current code returns
  200).
- **Where:** `test/conformance.mjs`.
- **Why:** Verification tooling must not depend on machine leftovers; a red
  suite caused by a zombie wastes triage time and can mask real regressions.
- **How:** Before spawning, pick a free port by listening on `127.0.0.1:0`
  with `net.createServer`, close it, and use the assigned port for both the
  spawn args and `base`. Keep everything else unchanged.

### T2 — Batch UI hides over-limit input until the server rejects it
- **What:** Pasting more than 3 domains shows a clamped counter (`3 / 3`)
  with no hint anything is wrong; only after submit does the API return 413
  for the whole batch.
- **Where:** `web/app.js` (`batchInput` listener, `batchForm` submit),
  `web/index.html` (form meta), `web/styles.css` (warning style).
- **Why:** The honest-data principle applies to the form too: silent clamping
  misrepresents what will be checked, and a guaranteed-failing request burns
  rate-limit quota.
- **How:** When line count exceeds `BATCH_MAX_DOMAINS_UI`, show an inline
  warning next to the counter ("extra lines are rejected — trim to 3") and
  block submission client-side with the same message in `#batch-error-msg`,
  without a network call.

### T3 — Batch share links fail silently; report loading is duplicated
- **What:** The `#batch-<id>` boot path (app.js bottom) duplicates the fetch/
  render logic of `loadSharedReport` and swallows all failures — an expired or
  deleted batch link leaves an empty panel with no message. Round 1 already
  taught `loadSharedReport` to dispatch on `_reportType`, so the second copy
  is pure liability.
- **Where:** `web/app.js` (`loadSharedReport`, `#batch-<id>` boot block).
- **Why:** Every failure mode should surface in the right panel; two copies of
  the same loader will drift again.
- **How:** Delete the duplicated IIFE; route `#batch-<id>` through
  `loadSharedReport(id, { prefer: "batch" })`. Add a `prefer` option so a
  failed batch-prefixed load shows `#batch-error-msg` in the batch panel
  instead of the domain panel's generic error.

## UI / UX

### U1 — Hero copy still advertises "twenty-five at once"
- **What:** index.html:46 says "one domain or twenty-five at once" while the
  product now caps batches at 3 (round-1 fix updated every other mention).
- **Where:** `web/index.html` hero `<p>`.
- **Why:** False advertising in the first sentence of the page.
- **How:** Reword to number-free "one domain or a small batch at once" so the
  copy cannot go stale if the cap changes again.

### U2 — Dead "5 concurrent checks" meta in batch form
- **What:** index.html:133 claims "5 concurrent checks"; `BATCH_CONCURRENCY`
  is 5 but the max is 3 domains, so the claim is meaningless now.
- **Where:** `web/index.html` batch form meta.
- **How:** Replace with "Equal DNS budget per domain", matching the section
  heading.

### U3 — Inconclusive states render as red failures in domain metrics
- **What:** `statusClass()` maps everything that isn't pass/warn to `poor`
  (critical red), including `info`/inconclusive statuses produced by DNS
  trouble or budget exhaustion. A truncated check looks like a failing check.
- **Where:** `web/app.js` (`statusClass`), `web/styles.css`
  (`.metric strong.info`).
- **Why:** Contradicts the product's core honesty rule: unknown ≠ failure.
  The batch table already colours info blue; the domain tiles should too.
- **How:** Return `"info"` for `info`/unknown statuses and add
  `.metric strong.info { color: var(--info) }`.

### U4 — SPF Inspector loading panel is invisible to assistive tech
- **What:** `#spf-loading` lacks `role="status"`/`aria-live`, unlike the other
  three loading panels.
- **Where:** `web/index.html:194`.
- **How:** Add `role="status" aria-live="polite"`.

### U5 — SPF safety confirmation renders unstyled
- **What:** `.auth-checkbox` and `.deps-toggle-text` are referenced by the
  critical "I have reviewed this change" confirmation (index.html:270-272) but
  defined nowhere in styles.css — the most important safety control on the
  page falls back to raw inline label layout.
- **Where:** `web/styles.css`.
- **How:** Style as a bordered, padded clickable row (flex, gap, min-height
  44px, `--bg` background like `.provider-option`); stack `strong` above
  `small` help text inside `.deps-toggle-text`.

### U6 — Builder sub-tabs below the 44px touch target
- **What:** `.builder-tab` computes to roughly 33px tall.
- **Where:** `web/styles.css` (`.builder-tab`).
- **How:** `min-height: 44px`.

### U7 — Programmatic scrolling ignores prefers-reduced-motion
- **What:** `scrollIntoView({ behavior: "smooth" })` forces smooth scrolling
  regardless of CSS overrides (explicit `smooth` does not defer to computed
  `scroll-behavior`), so vestibular users get animated jumps after results.
- **Where:** `web/app.js` (`showDomainResults`, batch submit).
- **How:** Shared helper reading `matchMedia("(prefers-reduced-motion: reduce)")`
  and passing `"auto"` when set.

### U8 — No-JS visitors get a silent app shell
- **What:** The tool is JS-only; with scripts blocked the page shows marketing
  content and non-functional forms with no explanation.
- **Where:** `web/index.html`.
- **How:** Small `<noscript>` notice above the tool panels.

## Other / maintainability

### O1 — Dead ternary in `analyzeMX`
- **What:** `unknown ? 'info' : 'info'` (worker.js, no-MX branch) — both arms
  identical; suggests a lost distinction that no longer exists.
- **Where:** `worker.js`.
- **How:** Collapse to plain `'info'` values; behaviour unchanged.

### O2 — `window.open` export tabs lack `noopener`
- **What:** Export buttons open `/api/reports/:id/export` with `_blank` and no
  `noopener,noreferrer`.
- **Where:** `web/app.js` (domain + batch export handlers).
- **How:** Pass `"noopener,noreferrer"` as the third argument.

### O3 — Batch table rows fake clickability
- **What:** `.batch-table tbody tr { cursor: pointer }` but only the domain
  button inside the row is interactive; pointer + hover tint over cells reads
  as row-level actions that don't exist.
- **Where:** `web/styles.css`.
- **How:** Drop `cursor: pointer` from `tbody tr`; keep the hover tint for
  readability and the button affordances.

## Explicitly skipped (with reasons)

- **SOURCE_REVISION deploy-time injection** — release-process change, no CI in
  repo (same reason as round 1).
- **Asset minification/hashed immutable caching** — build pipeline addition;
  round-1 skip stands.
- **Tab-click focus behaviour** (clicking a tab focuses its input): deliberate
  UX choice, covered indirectly by browser tests; churn risk outweighs gain.
- **Large `aria-live` regions on result containers** — accepted tradeoff from
  round 1; changing announcement scope risks regressions in the axe suite for
  marginal benefit.
- Historical docs (`IMPLEMENTATION_REPORT.md`, `PRODUCT_REVIEW.md`) mentioning
  25-domain batches remain period records.

## Verification

`npm test`, `npm run test:browser`, `npm run check` must stay green after each
commit.
