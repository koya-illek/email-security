# Production Iteration 6 Plan (2026-08-22)

Branch: `production/iteration-6` (from `production/iteration-5`). Scope settled after a
read-only live probe of https://email.illek.ie (still running pre-round-3 code:
`HEAD /` → 404, `source_revision: working-tree-2026-08-15`, cached HIT reports carrying
`request_budget.used: 0`), a line-by-line pass over every source file, a full green
baseline (`npm test`, 36 browser tests, conformance corpus, `npm run check`,
`npm outdated`/`npm audit` clean), and reproduction attempts against the current tree
for each finding below. Rounds 1–5 closed the reported backlog; this round fixes the
residual correctness/honesty gaps that survived those rounds plus verification debt,
rather than adding features.

## Audience, core job, primary path

Mail administrators and senders auditing a domain's SPF/DKIM/DMARC/MX/transport
posture, plus REST/MCP agents importing the same capability. Primary path: paste a
domain, read score plus per-control evidence, act on recommendations. Distinctive
identity: evidence-first honesty — absence, transient failure, and budget exhaustion
are never conflated, and the record builders must never hand the user a record the
service did not validate. Anything that shows a failed validation as success, or a
storage outage as absence, is a production bug regardless of how small the diff is.

## Confirmed findings

1. **Record Builder renders failed validation as "Valid record" and enables Copy
   (Medium, correctness/data honesty).** The debounced validation callbacks
   (`scheduleSpfValidation` and the DMARC twin in `web/app.js`) pass the parsed body
   straight to `showValidation` without checking `response.ok` or the payload shape.
   A request whose JSON exceeds the 16 KiB body cap gets 413 `{error:"Request body
   exceeds the 16 KiB limit."}` (the exact behaviour the conformance suite asserts);
   `validation.errors` is then undefined, so `showValidation` takes the good branch:
   the output card shows "Valid record · undefined SPF DNS lookups · undefined
   characters" and the copy button enables on a record the service refused to judge.
   The same hole swallows any `{error}`-shaped answer. Reachable by pasting a large
   mechanism blob into "Additional mechanisms" — precisely the oversized-input case.
   Reproduction: Playwright interception returning 413 `{error}` shows the enabled
   copy button today.
2. **Header Analyzer surfaces raw JSON-parse noise for non-JSON failures (Low-Medium,
   error states).** `runHeaderAnalysis` and the enrich handler rethrow inside their
   catch with `err.message`; a Cloudflare-level HTML/plain-text error page makes
   `r.json()` throw `SyntaxError: Unexpected token '<' …`, displayed verbatim in the
   alert panel. Round 3 fixed this exact class for share links (`loadSharedReport`)
   but left these two sites. The domain/batch/spf/builder panels already catch
   generically and do not leak parser messages.
3. **`#spf-report` is the only result panel without `aria-live` (Low, a11y
   consistency).** Domain, batch, and header result containers announce politely;
   round 2 gave all four loading panels `role="status"`. SPF inspection results still
   replace the announced loading state silently.
4. **Report retrieval maps a missing D1 binding to absence through MCP (Low,
   honesty).** `loadReport` returns null whenever `env.DB` is absent, so the MCP
   `get_email_security_report` tool answers "Report not found or expired" while
   storage is merely unavailable. The HTTP routes are shielded because their daily-
   counter guard throws first (503), but the module contradicts the iteration-5
   contract ("null only for absent/expired rows or malformed ids"), which the unit
   suite currently pins instead of enforces.
5. **The HTML/metadata audit cited by iterations 4–5 is not reproducible from the
   repository (Low, verification debt).** `scripts/audit-html.mjs` does not exist in
   any commit; the claim traces to uncommitted scratch. Canonical metadata, JSON-LD,
   robots/sitemap/canonical consistency, and OpenAPI/MCP YAML validity should be a
   committed one-command check.
6. **`web/openapi.yaml` omits enforced 413 responses (Low, contract accuracy).** All
   POST routes cap bodies before parsing (16 KiB standard, 256 KiB headers) and
   conformance asserts 413 for oversized bodies and over-limit batches; most paths
   document only 400/429 (header-analysis carries a lone inline 413).
7. **Dependency drift (Nit).** In-range updates exist for `tldts` 7.4.10 (patch),
   `wrangler` 4.125.0 and `@playwright/test` 1.62.1 (minors); `npm audit`: 0
   vulnerabilities.

## Intended changes

| # | Change | Files | User impact | Risk |
| --- | --- | --- | --- | --- |
| 1 | Treat any non-validation-shaped response (HTTP error, `{error}`, unreadable body) from `/api/records/validate` as a validation failure rendered in the existing "Cannot copy" notice; keep the idle-builder quota gate untouched | `web/app.js` | Oversized or rejected records can no longer display "Valid record" with a working Copy button | Low |
| 2 | Parse API responses through one guarded helper (shared with `loadSharedReport`) in the header analyze/enrich handlers so non-JSON bodies produce "The service returned an unreadable response…" instead of parser syntax errors | `web/app.js` | Readable error state during edge/proxy failures on the header panels | Low |
| 3 | Give `#spf-report` `aria-live="polite"` like the other three result panels | `web/index.html` | Screen readers hear SPF inspection results | Low |
| 4 | Browser regression tests: 413-shaped validate response disables copy and names the reason; HTML 502 on analyze/enrich renders the readable message and never "Unexpected token" | `test/browser/header-ui.spec.cjs` | Pins both fixes | Low |
| 5 | `loadReport`: missing DB binding with a well-formed id throws `ReportStorageError` (503) instead of null; malformed ids still return null; update the unit suite to enforce rather than pin the old behaviour | `report-store.js`, `test/report-store.test.mjs` | MCP report retrieval says "temporarily unavailable" during storage outages instead of claiming the report is gone | Low |
| 6 | Commit `scripts/audit-html.mjs`: fetches a base URL and verifies title/description/canonical/OG/Twitter/JSON-LD, charset+viewport+lang, skip-link target, noscript note, favicon/social-card resolution, robots↔sitemap↔canonical consistency, and parses openapi.yaml + mcp-copilot.yaml (route spot-checks); wire `npm run audit:html` | `scripts/audit-html.mjs` (new), `package.json` | The audit earlier rounds claimed becomes a rerunnable repo command | Low |
| 7 | Document the enforced 413 on POST endpoints via one shared response component (replacing the inline header-analysis entry) | `web/openapi.yaml` | API consumers see the real body-cap behaviour | Low |
| 8 | Refresh in-range dependencies (`tldts`, `wrangler`, `@playwright/test`) and the lockfile after licence/maintenance check | `package-lock.json` | Current toolchain; no behavioural change expected | Low |

## Non-goals

- No deployment, push, or publish; production keeps running pre-round-3 code until the
  owner runs `npm run deploy`.
- Asset minification and hashed immutable caching stay out of scope (sixth round):
  payloads remain modest (app.js ≈ 55 KB raw), and cache-TTL extensions without content
  hashing risk serving stale UI copy against newer API limits after deploys.
- mailauth 5.x and js-yaml 5.x major upgrades: no functional driver; the RFC 7208
  evaluator passes its 177-case corpus on 4.13.3, and late-cycle engine majors trade
  proven behaviour for version currency.
- Cached domain reports reusing the first requester's share id/expiry within the 24h
  TTL stays considered-and-rejected (rounds 3–5).
- No scoring changes, batch-limit changes, worker.js restructuring (structural tests
  pin the module layout deliberately), or historical-document rewrites.

## Verification

- `npm test` including updated `test/report-store.test.mjs`.
- `npm run test:integration` (conformance corpus unchanged and green).
- `npm run test:browser`: prior 36 plus new regression tests, axe clean, desktop +
  mobile projects.
- `npm run check` and `npm run deploy -- --dry-run`.
- `npm run audit:html` against the local build and https://email.illek.ie/.
- Playwright state sweep at 390/768/1440 CSS px covering the new error states
  (unreadable-response panel, blocked-copy builder), keyboard operability, 200% zoom,
  reduced-motion reveal; no horizontal overflow; axe zero violations.
