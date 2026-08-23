# Production Iteration 7 Plan (2026-08-22)

Branch: `production/iteration-7` (from `production/iteration-6`). Scope settled after a
read-only live probe of https://email.illek.ie (still running pre-round-3 code:
`HEAD /` → 404, `source_revision: working-tree-2026-08-15`), a line-by-line pass over
every source file against the six prior logs, a fully green baseline (`npm test` 220
assertions across six suites), and a local reproduction of the headline finding below
against `wrangler dev`.

## Audience, core job, primary path

Mail administrators and senders auditing a domain's SPF/DKIM/DMARC/MX/transport
posture, plus REST/MCP agents importing the same capability. Primary path: submit a
domain, read score + per-control evidence, act on recommendations. Distinctive
identity: evidence-first honesty — absence, transient DNS failure, and budget
exhaustion are never conflated anywhere from DNS lookup to score confidence to UI.
Anything that presents an incomplete observation as determinate is a production bug.

## Confirmed findings

1. **A budget-exhausted DKIM scan with findings present is reported as complete
   evidence (Medium, data honesty).** `checkDKIMSelectors` sets the scan's
   `dnsStatus` to `budget_exceeded` when the request budget ran out mid-scan, but
   `analyzeDKIM` consults that status only in the zero-findings branch. When at
   least one selector was found before exhaustion, the truncation is silently
   dropped: `dkim.unknown` stays false, `unknown_controls` stays empty,
   `score_confidence` reads "high", and DKIM earns full points — although the
   remaining catalogue selectors were never checked and their absence cannot be
   concluded. Reproduced locally on microsoft.com: budget 45/45 exhausted, only
   `selector2` discovered (Microsoft also publishes `selector1`), yet the report
   scored **93 "excellent", high confidence, `unknown_controls: []`**. The same
   scan truncated by *transient* DNS failures (`dnsStatus: partial`) is already
   handled honestly; only the budget case falls through the gap. Batch rows carry
   the same defect inside each row's slice.
2. **PTR forward confirmation compares textual IP representations (Low,
   correctness).** `checkPTR` decides `matches` via `forward.includes(ip)` where
   both sides are raw DoH answer strings. Two lookups may return equivalent IPv6
   addresses in different canonical forms (`2001:db8::1` vs `2001:db8:0:0:0:0:0:1`),
   which would report a correctly configured MX host as "not forward-confirmed".
3. **The DKIM key-size estimator misclassifies RSA-3072 keys as 2048-bit (Low,
   evidence accuracy).** `estimateDkimKeyBits` bucket boundaries place a 3072-bit
   SPKI (~533 base64 characters) under the 550 cutoff, so the report emits
   "Estimated public key length: 2048 bits" plus a false "rotate to a 2048-bit
   DKIM key" warning for a key already stronger than that. The estimate would
   also mislead any consumer comparing reported strength across selectors.
4. **Three frontend handlers bypass the shared unreadable-response helper (Low,
   error states).** Iteration 6 routed header analysis, hop enrichment, and share
   links through `parseApiResponse`, but the domain check, batch check, and SPF
   inspector still call bare `r.json()`; an edge/proxy HTML failure page throws a
   SyntaxError that their generic catches convert to vague copy ("Failed to
   analyze domain") instead of the accurate service-trouble message every other
   panel now shows.
5. **`.icon-button` misses the repo's own 44px touch-target standard (Nit).**
   Round 1 raised `.copy-btn`, `.sort-button`, and `.dialog-close` to 44×44; the
   "+" new-check icon button remained 42×42 (styles.css:372,392).

## Intended changes

| # | Change | Files | User impact | Risk |
| --- | --- | --- | --- | --- |
| 1 | `analyzeDKIM` treats a `budget_exceeded` selector scan exactly like a `partial` one when findings exist: push an inconclusive info check naming the cause, set `unknown=true`, so the control lands in `unknown_controls`, drops score confidence, and earns no points until re-run complete | `worker.js` | Truncated DKIM scans can no longer back an "excellent" high-confidence score; microsoft.com-style reports read fair/medium with an explicit retry instruction | Low |
| 2 | Normalize both sides of the PTR forward-confirmation comparison through `ipaddr.parse(...).toString()` | `worker.js` | Equivalent IPv6 spellings confirm instead of falsely warning | Low |
| 3 | Rebucket the estimator at 300/450/650 base64 characters so RSA-3072 reports as 3072 (2048 ≈ 360–392 chars, 3072 ≈ 533, 4096 ≈ 707 stay correct) | `worker.js` | No false rotation warning on 3072-bit keys | Low |
| 4 | Route domain/batch/SPF-inspect responses through `parseApiResponse` and surface its message in each existing catch | `web/app.js` | Accurate "unreadable response" error state during edge failures on the three remaining panels | Low |
| 5 | Raise `.icon-button` to 44×44 | `web/styles.css` | Consistent touch targets | Low |
| 6 | Regression coverage: structural assertions pinning the incomplete-scan branch, normalized PTR comparison, and estimator buckets; browser tests proving an HTML 502 on `/api/check`, `/api/batch`, and `/api/spf/inspect` renders the readable message and never parser noise or the old generic copy | `test/worker-security.test.mjs`, `test/browser/header-ui.spec.cjs` | Fixes stay fixed | Low |

## Non-goals

- No deployment, push, or publish; production keeps running pre-round-3 code until
  the owner runs `npm run deploy`.
- Asset minification and hashed immutable caching stay out of scope (seventh round):
  payloads remain modest and edge-compressed; cache-TTL extensions without content
  hashing risk stale UI copy against newer API limits after deploys.
- Cached domain reports reusing the first requester's share id/expiry within the 24h
  TTL stays considered-and-rejected (rounds 3–6).
- mailauth 5.x / js-yaml 5.x majors: no functional driver; the RFC 7208 corpus is
  green on current versions.
- No worker.js restructuring (structural tests pin the module layout), no scoring
  model changes beyond finding 1's honesty correction, no historical-document edits.
- Boundary case accepted: if the budget happens to hit its limit exactly as the last
  selector probe completes, the scan is conservatively marked incomplete rather than
  silently trusted — the same fail-toward-uncertainty bias used everywhere else.

## Verification

- `npm test` (unit suites incl. new structural assertions).
- `npm run test:integration` (conformance corpus incl. gmail.com budget-priority case
  must stay green — gmail.com finishes its scan within budget, so it must NOT gain a
  dkim unknown flag).
- `npm run test:browser`: prior 44 plus new regression tests, axe clean, desktop +
  mobile projects.
- `npm run check` and `npm run deploy -- --dry-run`.
- `npm run audit:html -- http://127.0.0.1:<port>/` (local build must pass 11/11) and
  against https://email.illek.ie/ read-only.
- Local reproduction re-run: microsoft.com must report `dkim` in `unknown_controls`
  with reduced confidence; a fully-scanned control set must keep high confidence.
- Playwright state sweep at 390/768/1440 CSS px: primary path, new error states,
  keyboard operability, no horizontal overflow; axe zero violations; reduced-motion
  reveal intact.
- `npm audit` stays at zero vulnerabilities.
