# Improvement Plan — Round 3 (2026-08-22)

Fresh-eyes review of the tree after rounds 1–2 (`fix/review-2026-08-22`,
`improve/review-2026-08-22`). No High-severity issues found. This pass looks at
what earlier rounds missed or introduced: quota spent before any user
interaction, invisible server-side rejections, transient failures pinned into
the edge cache, HEAD requests falling out of the app, and a few error-state and
clarity gaps in the frontend.

## Technical

### T1 — Builders spend validation quota on every page load before any input
- **What:** `renderSpfBuilder()` and `renderDmarcBuilder()` run at script boot
  (app.js bottom) and each schedules a debounced `POST /api/records/validate`,
  even though both panels are hidden and every control is pristine (`v=spf1
  ~all`, empty DMARC). Every homepage view burns 2 of the 60/min standard
  requests and 2 of the 500/day D1-counter budget per visitor, plus a server
  round trip, before the Record Builder is ever opened.
- **Where:** `web/app.js` (`renderSpfBuilder`, `renderDmarcBuilder`, boot calls).
- **Why:** Quota and counters should reflect work the visitor asked for; idle
  renders are not work. Also removes two pointless D1 writes per page view.
- **How:** Treat "no domain, no terms/mechanisms, no import" (SPF) and "no
  domain, no rua" (DMARC) as idle: skip scheduling the validation POST and set
  the card's copy button to an honest disabled label ("Enter a domain to
  validate"). Any user input leaves the idle state and resumes the normal
  debounced flow. Existing browser tests all interact before asserting, so the
  gated POST still fires in every tested path.

### T2 — Batch results silently drop lines the API refused
- **What:** `/api/batch` returns `validation.rejected` entries (invalid domain,
  duplicate) alongside `results`; the UI renders only `results`. Paste
  `example.com` plus an invalid line and the table shows one row with no
  explanation of what happened to the other line. Conformance tests assert the
  rejected payload exists; nothing in the UI consumes it.
- **Where:** `web/app.js` (`batchForm` submit, `loadSharedReport` batch branch,
  clear handler), `web/index.html` (new note element), browser spec coverage.
- **Why:** Silent partial application contradicts the product's honesty
  standard; users cannot tell whether a domain was skipped or scored.
- **How:** Add `#batch-rejected-note` (same warning styling as
  `#batch-budget-note`) listing each refused line with its reason; populate it
  in the direct-submit path and the shared-report loader, hide it on Clear.

### T3 — Transient MTA-STS fetch failures are pinned in the edge cache for 24h
- **What:** `fetchMtaStsPolicy` ends with an unconditional `cache.put`. A
  timeout, abort, or network error (all recorded with `status: null`) is cached
  for `POLICY_CACHE_TTL` (24h), so "MTA-STS policy not reachable … timed out"
  keeps being served long after the origin recovers. Definitive outcomes (a
  fetched policy, or an HTTP answer such as 404) are legitimately cacheable;
  transport-level failures are not observations at all.
- **Where:** `worker.js` (`fetchMtaStsPolicy`), `test/worker-security.test.mjs`
  (pattern assertion), `ARCHITECTURE.md` cache wording.
- **Why:** A cached transient failure turns one bad moment into a day of wrong
  transport findings, contradicting the absence-vs-inconclusive distinction the
  rest of the tool maintains.
- **How:** Only `cache.put` when `result.fetched` or (`result.status !== null`
  and no `result.error`). Timeout/abort/network errors stay uncached and retry
  on the next request.

### T4 — HEAD requests to any page return 404
- **What:** The static-serving branch requires `request.method === 'GET'`;
  `HEAD /` falls through to the plain-text 404. Uptime monitors, link checkers,
  and some crawlers probe with HEAD and currently see the whole site as dead.
- **Where:** `worker.js` static branch, `test/conformance.mjs` (new assertion).
- **How:** Allow `GET` or `HEAD` through to `env.ASSETS.fetch(request)` (the
  runtime strips the body for HEAD), and assert `HEAD /` returns 200 in the
  conformance harness.

## UI-UX

### U1 — Shared-report loader shows raw JSON-parse errors
- **What:** `loadSharedReport` calls `r.json()` outside its error mapping; a
  non-JSON failure response (for example an HTML 502 page) surfaces as
  "Unexpected token '<' …" in the report panel instead of a human message.
- **Where:** `web/app.js` (`loadSharedReport`).
- **How:** Wrap the parse and throw "The report service returned an unreadable
  response." so both domain and batch error paths show something actionable.

### U2 — Share-link expiry dates render as ambiguous numeric dates
- **What:** Both share notes use bare `toLocaleDateString()` ("9/5/2026"),
  ambiguous across locales, for a trust-critical detail (when a bearer link
  dies). Also, the `<noscript>` note claims the tools run checks "from your
  browser", but DNS/header analysis runs on the Worker API.
- **Where:** `web/app.js` (two share notes), `web/index.html` (noscript copy).
- **How:** Format expiry as an unambiguous long date ("5 September 2026") via a
  shared helper; reword the noscript note to say inputs are sent to this site's
  API.

### U3 — SPF Inspector never shows qualitative findings
- **What:** `showSpfInspector` renders metrics, records, flatten preview, and
  flatten warnings, but never `d.spf.checks`. Inspection-time failures such as
  multiple SPF records, a ptr mechanism, or a permissive `+all` are invisible;
  the inspector can even present a clean-looking preview for the first of two
  conflicting records without mentioning the conflict.
- **Where:** `web/app.js` (`showSpfInspector`).
- **How:** When `spf.status` is fail/warn and `spf.checks` exists, render the
  standard check-item list above the record cards. Guarded on array presence so
  minimal/mock payloads render nothing new.

## Other (considered, not changed)

- **Edge-cached domain reports reuse the first requester's share id/expiry for
  the 24h TTL.** The link shown is truthful (it is the same stored row and the
  displayed expiry matches its real expiry); observation age is disclosed via
  `provenance.generatedAt`. Changing this would trade one D1 insert per
  cache-hit request for cosmetic freshness. Skipped as churn.
- **IDN/unicode domains are rejected** by `normalizeDomain` rather than
  punycode-encoded. Adding IDN mapping is real scope; the rejection message is
  immediate and accurate. Skipped.
- **Copy-button feedback is optimistic** ("Copied!" regardless of clipboard
  result). Cosmetic; skipped.

Verification planned: `npm test`, `npm run test:browser`, `npm run check`.
