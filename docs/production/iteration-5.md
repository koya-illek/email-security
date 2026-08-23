# Production Iteration 5 Plan (2026-08-22)

Branch: `production/iteration-5` (from `production/iteration-4`). Scope settled after a
read-only live probe of https://email.illek.ie, a full pass over the current source,
and a green baseline of every existing suite (`npm test`, 36 browser tests,
`npm run check`). Rounds 1-4 fixed the previously reported findings; this round targets
the remaining honesty and release-operations gaps rather than new features.

## Audience, core job, primary path

Mail administrators and senders auditing a domain's SPF/DKIM/DMARC/MX/transport
posture, plus API/MCP agents importing the same capability. Primary path: paste a
domain on Check Domain, read score plus per-control evidence, act on recommendations.
Trust boundary: public DNS observations in, honest verdicts out; shareable reports are
14-day bearer links. The distinctive identity is evidence-first honesty: absence,
transient failure, and budget exhaustion are never conflated. Anything that makes a
stored verdict less truthful than the observation behind it is a production bug.

## Confirmed findings

1. **Report retrieval conflates storage failure with absence (Medium, honesty/reliability).**
   `loadReport` (worker.js:108-121) catches every D1 error and returns null, so
   `GET /api/reports/:id`, the JSON export, and the MCP `get_email_security_report`
   tool all answer "Report not found or expired" (404) while storage is merely down.
   During a D1 outage every live share link lies that its report is gone or expired.
   The same route's daily-counter guard (worker.js:600-607) answers 503 with the copy
   "Rate limiting is unavailable.", which misdescribes a report read that failed in
   storage accounting. The product distinguishes absence from trouble everywhere else;
   retrieval must too.
2. **HEAD /api/health returns 404 (Low, reliability).** Round 3 taught the static
   branch to serve HEAD so uptime monitors stop seeing the site as dead, but the
   health endpoint still requires GET. Probes that HEAD health URLs (a common
   monitor default) get 404 on an otherwise healthy service.
3. **Deployed provenance is false until someone remembers to edit wrangler.toml
   (Medium, observability/release operations).** Production reports
   `source_revision: "working-tree-2026-08-15"` in `/api/health`, the API directory,
   and every stored report's provenance while running four iterations of newer code.
   Deferred for four rounds as release-pipeline scope; a repo-local mechanism exists:
   `wrangler deploy --var SOURCE_REVISION:<rev>` overrides the variable at deploy time
   without touching files (verified against `wrangler deploy --dry-run --var ...`).
4. **Dead code (Nit, maintainability).** worker.js:2470 carries the same dead ternary
   pattern round 2 removed elsewhere (`status: transientMtaDns ? 'info' : 'info'`);
   styles.css ships ~40 unused lines (`.section-label`, `.score-card`/
   `.score-value`/`.score-label`, marked "legacy compat", referenced by no HTML or JS);
   batch chunking (`BATCH_CONCURRENCY = 5`) is unreachable generality now that
   `BATCH_MAX_DOMAINS = 3`.

## Intended changes

| # | Change | Files | User impact | Risk |
| --- | --- | --- | --- | --- |
| 1 | Extract report storage into `report-store.js` (id generation, expiry, share metadata, store/load) following the `retention.js` pattern so it is unit-testable in Node | `report-store.js` (new), `worker.js` | None at runtime | Low |
| 2 | Make `loadReport` throw a controlled error (status 503, message "The report could not be read from storage.") on DB failure or unreadable stored JSON; return null only for absent/expired rows or malformed ids. Map it to 503 in `/api/reports/:id` and export routes via `requestErrorResponse`; MCP surfaces the message as `isError` text | `report-store.js`, `worker.js` | Share links during a storage outage say "temporarily unavailable" instead of falsely declaring the report gone | Low |
| 3 | Replace the misleading counter-guard copy on report reads with "Report retrieval is temporarily unavailable." | `worker.js` | Accurate error state during partial outages | Low |
| 4 | Regression coverage: unit suite for load/store semantics (absent, expired, valid, id backfill, DB failure, corrupt JSON), structural assertions tying the routes to the 503 mapping | `test/report-store.test.mjs` (new), `test/worker-security.test.mjs` | Guards the absence-vs-failure distinction | Low |
| 5 | Serve HEAD like GET on `/api/health`; assert it in the conformance corpus; document the method in openapi.yaml | `worker.js`, `test/conformance.mjs`, `web/openapi.yaml` | Uptime probes see a healthy service | Low |
| 6 | Add `scripts/deploy.mjs`: resolve `git rev-parse --short HEAD` (append `-dirty` when the worktree is unclean; fall back to "unpinned"), print it, and run `wrangler deploy --var SOURCE_REVISION:<rev>` with passthrough args. Wire `npm run deploy`. Change the wrangler.toml fallback to the honest `"unpinned"` marker. Document the release flow in README-WORKERS.md | `scripts/deploy.mjs` (new), `package.json`, `wrangler.toml`, `README-WORKERS.md`, `test/worker-security.test.mjs` | Next deploy pins truthful provenance in health, directory, and every report; no deploy happens in this iteration | Low |
| 7 | Delete dead code: collapse the transport ternary to `'info'`, remove unused `.section-label`/`.score-*` CSS rules, drop `BATCH_CONCURRENCY` chunking in favour of one `Promise.all` (max 3 domains make chunking unreachable) | `worker.js`, `web/styles.css` | Smaller payload, less reader load; no behaviour change | Low |

## Non-goals

- No deployment, push, or publish; production keeps running iteration-3-era code until
  the owner runs the new release flow.
- Asset minification and hashed immutable caching stay out of scope (no build pipeline).
- Cached domain reports reusing the first requester's share id stays rejected (rounds 3+4).
- No scoring changes, no new features, no cosmetic churn beyond the deletions above.

## Verification

- `npm test` including the new `test/report-store.test.mjs`.
- `npm run test:integration` (conformance corpus incl. the new HEAD health case).
- `npm run test:browser` (36 prior tests, axe clean, desktop + mobile).
- `npm run check` (wrangler deploy --dry-run).
- `npm run deploy -- --dry-run`: proves the release script injects `SOURCE_REVISION`
  end-to-end without deploying.
- `node scripts/audit-html.mjs https://email.illek.ie/` plus the local shell, and a
  Playwright state sweep at 390/768/1440 CSS px (loading/error/report states, keyboard,
  zoom, reduced motion) as applicable to touched surfaces.
