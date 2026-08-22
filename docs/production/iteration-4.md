# Production Iteration 4 Plan (2026-08-22)

Branch: `production/iteration-4` (from `ox-round3-baseline`). Scope settled after a live
probe of https://email.illek.ie and a full source pass; rounds 1-3 already fixed the
previously reported findings, so this round targets the strongest remaining defect class:
budget allocation between scored controls.

## Audience, core job, primary path

Mail administrators and senders auditing a domain's SPF/DKIM/DMARC/MX/transport posture.
Primary path: paste a domain on the Check Domain tab, read score plus per-control
evidence, act on recommendations. Trust boundary: public DNS observations in, honest
verdicts out. The product's distinctive identity is evidence-first honesty (absence vs
inconclusive is always distinguished). Anything that makes the headline verdict less
truthful than the per-control detail is a production bug.

## Confirmed findings

1. **Analysis order starves core controls behind PTR observation (High, honesty/correctness).**
   `analyzeDomain` runs `checkPTR` (worker.js:1140) before `analyzeSPF` (:1146) and
   `checkDKIMSelectors` (:1148). PTR is supplementary and unbounded: up to 8 MX hosts,
   up to 8 addresses each, one PTR query plus one forward-confirmation query per address.
   Live evidence (2026-08-22):
   - `POST /api/check {"domain":"gmail.com"}` returned `request_budget {used:45, exhausted:true}`
     with DKIM `info`, zero selectors discovered; overall 50 "fair". gmail.com is not a
     "fair" domain; DKIM simply never got budget.
   - A 3-domain batch scored gmail.com 25 "poor" and redhat.com 40 "poor" with SPF itself
     inconclusive, because each row's 15-subrequest slice was consumed by the initial six
     lookups plus PTR before SPF recursion or DKIM discovery ran.
   The batch UI marks such rows "partial", but single-domain reports present the starved
   result as an ordinary score with no partial marker beyond the confidence note.

2. **PTR fan-out is disproportionate to its displayed value (Medium, efficiency).**
   `analyzePTR` renders exactly one representative observation (`observations[0]`), yet
   `checkPTR` may issue dozens of queries. Stored report JSON carries every observation.

3. **Errored batch rows fabricate control failures (Low-Medium, honesty).**
   `createBatchReport`'s catch path returns fabricated `spf:{status:'fail'}`,
   `dmarc:{status:'fail'}`, `mx:{status:'fail'}`, `dkim:{status:'warn'}` for rows that
   threw. The table renders these as red Fail cells under a red "0/100"; nothing shows
   that the row errored. An internal error is not evidence about the domain.

4. **Every MTA-STS policy fetch fails in production (High, correctness).** Reproduced
   live against https://email.illek.ie and locally: the Workers runtime rejects
   `redirect: 'error'` ("won't be implemented at the edge"), so `fetchMtaStsPolicy`
   throws before any request is sent. Every domain publishing MTA-STS has received a
   permanent false "MTA-STS policy not reachable", `transport.unknown = true`, lost
   transport score points, and polluted confidence. Verified healthy upstream policy
   (mta-sts.gmail.com serves 200 text/plain). Fix per Cloudflare guidance:
   `redirect: 'manual'` plus an explicit fail-closed guard that refuses any 3xx status
   or off-origin final URL, preserving the never-follow-redirects rule.

## Intended changes

| # | Change | Files | User impact | Risk |
| --- | --- | --- | --- | --- |
| 1 | Reorder `analyzeDomain`: SPF analysis first, then DKIM selector discovery and MTA-STS policy fetch in parallel, PTR observation last so it spends only what remains | `worker.js` | Core controls verified within the same platform limits; large-MX domains stop scoring falsely low | Low: pure scheduling change, no new queries |
| 2 | Cap PTR observations globally (`MAX_PTR_OBSERVATIONS = 4`) instead of 8 addresses per host | `worker.js` | Snappier reports, smaller stored JSON, identical rendered content | Low: renderer uses only the first observation |
| 3 | Errored batch rows report `{ status: 'info' }` controls with the real `error`; no fabricated failures | `worker.js` | Error rows can't masquerade as failing domains | Low |
| 4 | Batch table renders error rows as "error" (with the API message as tooltip) instead of "0/100" | `web/app.js` | Truthful error state at a glance | Low |
| 5 | Fetch MTA-STS policies with `redirect: 'manual'` plus a fail-closed 3xx/off-origin guard (workerd cannot run `redirect: 'error'`) | `worker.js` | Transport evidence becomes observable for every MTA-STS domain; recovers lost score points and confidence | Low: never-follow rule preserved |
| 6 | Regression tests: conformance case proving a worst-case domain (gmail.com) verifies SPF+DKIM and fetches its MTA-STS policy within budget; structural assertion that PTR is scheduled after DKIM; browser test for the errored-row rendering; security-test coverage of the manual-redirect guard | `test/conformance.mjs`, `test/worker-security.test.mjs`, `test/browser/header-ui.spec.cjs` | Guards the ordering and redirect invariants against future regressions | Low |
| 7 | Document the phase-priority rule, PTR bound, and manual-redirect fetch | `ARCHITECTURE.md`, this plan | Maintainer clarity | None |

## Non-goals

- No change to `BATCH_MAX_DOMAINS` (3 stays honest) or to scoring thresholds/formula;
  confidence disclosure remains the mechanism for uncertainty.
- Cached domain reports reusing the first requester's share ID stays rejected (round 3).
- `SOURCE_REVISION` deploy-time injection and asset minification stay out of scope
  (no build/deploy pipeline exists in-repo).
- No new features; no cosmetic churn.

## Verification

- `npm test` (RFC 7208 corpus, headers, local-D1 conformance incl. the new ordering case, retention, security, MCP).
- `npm run test:browser` (34 prior + new errored-batch-row test, axe clean, desktop + mobile projects).
- `npm run check` (wrangler deploy --dry-run).
- Local spot-check through `wrangler dev`: `/api/check` on a multi-MX domain must show
  non-empty DKIM selectors and a budget snapshot where exhaustion (if any) occurs during PTR.
