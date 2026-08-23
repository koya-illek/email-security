# Production Iteration 8 Plan (2026-08-22)

Branch: `production/iteration-8` (from `production/iteration-7`). Scope settled after a
read-only live probe of https://email.illek.ie (unchanged: `HEAD /` → 404, health still
`working-tree-2026-08-15`, so production runs pre-round-3 code), a fully green baseline
(`npm test` all suites, conformance corpus 17 cases, `wrangler deploy --dry-run`; the one
parallel-load browser flake passes solo), and an independent line-by-line review of every
source file by two focused review passes whose findings were each re-verified against the
code before acceptance.

## Audience, core job, primary path

Mail administrators and senders auditing a domain's SPF/DKIM/DMARC/MX/transport posture,
plus REST/MCP agents importing the same capability. Primary path: submit a domain, read
score + per-control evidence, act on recommendations. Distinctive identity: evidence-first
honesty — absence, transient DNS failure, and budget exhaustion are never conflated from
DNS lookup to score confidence to UI copy. This final round applies that invariant to two
RFC-correctness gaps in policy interpretation, one cached-absence bug, and the frontend's
remaining unsynchronised async flows.

## Confirmed findings

1. **Inherited DMARC policies ignore `sp=`, scoring subdomains by the parent's `p=`
   (High, RFC correctness / data honesty).** `analyzeDMARC` reads `const policy =
   tags.p || null` (worker.js:1939) even when discovery explicitly walked up to an
   ancestor (`discovery.inherited`, worker.js:1929). Per RFC 7489 §6.6.3 (and the RFC
   9989 tree-walk this code implements at worker.js:1157-1200), receivers apply `sp=` to
   the author domain when the record was found at an ancestor and `sp=` is present.
   `sub.corp.example` with parent `v=DMARC1; p=reject; sp=none` — a deliberately
   subdomain-exempting record — is scored "Reject policy … Maximum protection", status
   pass, +35/100 while real receivers enforce nothing for it.
2. **SPF terminal-strength analysis ignores `redirect=` (Medium-High, RFC correctness /
   data honesty).** The strength check maps this record's own `all` token only
   (worker.js:1485-1507); a `v=spf1 redirect=_spf.example.com` record has no `all`, so no
   strength check fires and the verdict rides lookup-count health to status pass (+25).
   If the redirect target ends in `+all`/`?all` (anyone-can-spoof) or `~all`, the tool
   reports a clean pass where enforcement is weak or absent. The recursion already fetches
   the target's record (worker.js:1668-1677) and `validateSpfRecord` concedes redirect
   substitutes for `all` (worker.js:880) — the analyzer just never looks at the target.
3. **Hop enrichment conflates transient DNS failure with definitive PTR absence, then
   caches the indeterminate result for 24 h (Medium, honesty/reliability).** `enrichIp`
   discards `queryDNS`'s `dnsStatus` (worker.js:1064-1077): SERVFAIL/timeout renders
   `ptr: null` exactly like authoritative "no PTR", then `cache.put` pins it for a day
   (`max-age=86400, stale-while-revalidate=86400`). One resolver hiccup reports "PTR: none
   found" for a mail host for 24 hours. Violates the same discipline round 3 applied to
   MTA-STS caching.
4. **`/api/records/validate` and `/api/v2/record-build` run recursive DNS under the
   standard limiter (Medium, abuse resistance).** Both handlers invoke
   `countSpfDnsLookupsRecursive` (up to ~30 TXT queries × provider retries) plus a full
   mailauth evaluation (routes at worker.js:513-543), yet `EXPENSIVE_POST_PATHS`
   (worker.js:54-63) omits them while strictly lighter `/api/spf/inspect` is expensive.
   An abuser sustains ~1,800 DoH subrequests/min through the cheap bucket vs 450/min for
   inspect.
5. **API catch-all answers break the `{error}` JSON envelope; wrong-method requests get
   neither 405 nor Allow (Low-Medium, API contract).** Unmatched paths and verbs fall
   through to plain-text `Not found` 404 (worker.js:619) after rate-limit quota was spent;
   `GET /api/check` or `PUT /api/reports/x` answer text/plain without API security
   headers, unlike every routed failure. openapi.yaml documents only JSON envelopes.
6. **Static SPF counter produces false "invalid" verdicts on legal records (Low,
   validator accuracy).** (a) `countVisibleSpfLookups` counts `redirect=` toward the
   10-lookup limit even when an `all` term makes it unreachable (RFC 7208 §4.6.4 counts
   only evaluated terms; §6.1 ignores redirect when `all` is present), so a valid record
   fails builder validation with "requires 11 DNS lookups". (b) Macro-bearing targets
   (`include:_spf.%{d2}.esp.com`) are queried literally, land in `voidLookups`, and tell
   the user to "Remove stale includes" for a syntactically valid record.
7. **Failed header analysis leaves an infinite spinner and destroys prior results
   (High, frontend error state).** The Header Analyzer injects its spinner into
   `#header-results` (app.js:930-931); on the error path `showHeaderError` shows the alert
   panel but never clears the results container — every failed paste leaves a perpetual
   "Interpreting receiver results…" animation beside the red error, and any previous
   successful analysis wiped before the request is gone for good. All four other panels
   use dedicated loading elements toggled in `finally`.
8. **In-flight requests are not invalidated by Clear/New/input actions (High, frontend
   state machine).** Three instances re-verified in source:
   (a) Enrich Hops → Clear mid-flight: response executes `lastHeaderAnalysis.enrichment =
   …` on `null` (app.js:970 after app.js:954), throwing into the alert panel as raw
   "Cannot read properties of null (reading 'enrichment')"; typing in the textarea has the
   same race via app.js:914-918.
   (b) Batch Clear mid-flight: response still renders the table, share note, rejected-note
   and auto-scrolls to a report the user discarded (app.js:1148-1154 after 1112-1119).
   (c) "+ New check" during a domain flight: `showDomainResults` unhides the dismissed
   report and scrolls to it (app.js:307-308 after 239-242).
9. **Trigger-path submits bypass disabled-button protection (Low, quota/correctness).**
   `#inspect-from-report` and batch-row buttons call `form.requestSubmit()`
   (app.js:248, 1259); double activation runs the handler concurrently because
   `spfButton.disabled` does not stop programmatic submission — duplicate `/api/spf/inspect`
   requests race for the same panel and burn quota twice.
10. **No print stylesheet; printed/PDF'd dark-theme pages are near-blank (Low-Medium,
    UX).** styles.css carries only width and reduced-motion media queries; browsers strip
    backgrounds when printing, so white-on-dark text vanishes — embarrassing for a tool
    whose share links exist to be read and filed.
11. **Small accessibility/markup defects (Low).** `.report-header h2` lacks any break rule,
    so long stored domains clip silently at 390 px under `body{overflow-x:clip}`;
    `<main id="main-content">` is not focusable, so skip-link focus restarts at document
    top in some browsers; the six "Authorised email services" checkboxes have an orphan
    `<label>` and no group semantics; server-derived status strings interpolate unescaped
    into `class` attributes (app.js:338, 500-503, 1315) — safe today only because every
    current value is from a closed set; three anchors carry invalid `type="application/yaml"`.

## Intended changes

| # | Change | Files | User impact | Risk |
| --- | --- | --- | --- | --- |
| 1 | Inherited records resolve the effective policy through a new pure `effectiveDmarcPolicy(tags, inherited)` helper: valid `sp=` wins when inherited; checks/status/score/returned `policy` use the effective value with explicit copy naming what was applied and why | `worker.js` | Subdomains under `p=reject; sp=none` parents now honestly report monitoring-mode reality instead of a false maximum-protection pass | Low |
| 2 | Recursion tracks the redirect chain's terminal term (`state.finalAll`, last write belongs to the deepest followed redirect); `analyzeSPF` emits the strength check from the target's terminal when the local record has none; unresolved targets fail toward uncertainty (void → fail check per RFC 7208 §6.1 permerror semantics; transient → info via existing unknown path; truncated → info, never a fabricated pass) | `worker.js` | Redirected SPF records are judged by the policy receivers actually apply | Medium |
| 3 | `enrichIp` carries `dnsState()` in non-definitive results and caches only definitive outcomes (`ok`/`nodata`/`nxdomain`), mirroring the MTA-STS discipline; frontend hop rendering says "PTR inconclusive (DNS trouble)" instead of "none found" when the state says so | `worker.js`, `web/app.js` | A resolver hiccup no longer pins false PTR absence onto mail hosts for a day | Low |
| 4 | Add `/api/records/validate` and `/api/v2/record-build` to `EXPENSIVE_POST_PATHS` | `worker.js`, `README-WORKERS.md` | Builder validation abuse costs 10/min like every other DNS-heavy endpoint | Low |
| 5 | Known-API-path/wrong-method requests return 405 `{error}` + `Allow`; unknown `/api/*` paths return JSON 404 `{error}` with API security headers; static catch-all unchanged | `worker.js`, `web/openapi.yaml` | Machine clients get parseable failures matching the documented envelope | Low |
| 6 | `countVisibleSpfLookups` skips `redirect=` when an `all` term exists; macro-bearing include/redirect targets skip the literal DNS query and classify as their own honest info finding ("contains macros; not statically verifiable") instead of void/stale | `worker.js` | Builder stops rejecting legal records; budget no longer wasted querying `%{…}` literally | Low |
| 7 | Dedicated hidden `#header-loading` element (role=status) toggled like the other four panels; results container untouched until a response renders | `web/index.html`, `web/app.js` | Failed pastes show error + preserved prior results; no infinite spinner | Low |
| 8 | Small generation-counter helper guards domain/batch/header flows: Clear, New-check, and header input increment the generation; responses captured before `await` bail when stale (still resetting buttons/loading in finally) | `web/app.js` | Discarded results can no longer resurrect, auto-scroll, or throw raw TypeErrors | Medium |
| 9 | In-flight flags around the domain and SPF-inspect submit flows so `requestSubmit()` trigger paths cannot run concurrent duplicates | `web/app.js` | Double activation spends quota once; no racing panels | Low |
| 10 | Compact print stylesheet: light scheme forced, chrome/forms/nav hidden, content colours readable, page-break hygiene | `web/styles.css` | Ctrl+P / Save-as-PDF of a report is legible | Low |
| 11 | `.report-header h2 { overflow-wrap: anywhere }`; `tabindex="-1"` on main; fieldset/legend around provider checkboxes (with reset styling); `safeStatusClass()` whitelist for class sinks; drop invalid `type` attributes | `web/styles.css`, `web/index.html`, `web/app.js` | Long domains wrap visibly; keyboard skip works everywhere; checkbox group announced correctly; class injection surface closed | Low |
| 12 | Bump `CACHE_VERSION` to `v9-dmarc-sp-spf-redirect` so edge-cached rows carrying superseded DMARC/SPF verdicts regenerate immediately after deploy | `worker.js` | No 24 h tail of pre-fix evidence post-deploy | Low |

## Regression coverage

- New unit suite importing named exports from worker.js (module keeps single-file layout):
  `effectiveDmarcPolicy` truth table (own p=; inherited sp= none/quarantine/reject;
  inherited without sp; invalid sp falls back to p); `countVisibleSpfLookups`
  redirect-with-all exclusion; macro-target detection.
- Structural tests pinning: `state.finalAll` threading and the void/transient/truncated
  branches; enrichIp definitive-only caching pattern; EXPENSIVE_POST_PATHS membership;
  JSON 404/405 fallback; CACHE_VERSION v9.
- Conformance additions: `GET /api/check` → 405 JSON with Allow; `POST /api/nope` → 404
  JSON.
- Browser regressions: failed header analysis leaves no spinner and preserves prior
  results; batch Clear during a delayed response does not resurrect the report; double-
  activated inspect-from-report sends exactly one request.

## Non-goals

- No deployment/push/publish; production stays on pre-round-3 code until the owner runs
  `npm run deploy`.
- PTR partial-observation disclosure after ≥1 completed observation: considered-and-
  skipped in iteration 7 (unscored supplementary evidence, first observation labelled as
  one observation); position unchanged.
- Cached domain reports reusing the first requester's share id/expiry within the TTL:
  considered-and-rejected rounds 3–7; unchanged.
- Asset minification/hashed caching, worker.js module split, mailauth/js-yaml majors,
  IDN punycode: carried exclusions with no new driver.
- Print expansion of closed `<details>` sections (not force-openable via CSS);
  historical docs remain period records.

## Verification

- `npm test` including the new unit suite and structural assertions.
- `npm run test:integration`: corpus green plus new 405/404 cases.
- `npm run test:browser` per-project (desktop, then mobile): prior suites plus new
  regressions, axe clean.
- `npm run check` and `npm run deploy -- --dry-run`.
- `npm run audit:html -- http://127.0.0.1:<port>/` (local build 11/11) and against the
  live site read-only.
- Playwright state sweep at 390/768/1440 CSS px: primary path, new header error state,
  print-emulated rendering, long-domain wrapping, keyboard operability, reduced-motion,
  axe zero violations.
- `npm audit` stays at zero vulnerabilities.
