# Email Security Analyzer product review

Review date: 2026-08-14

Scope: source tree at /home/koya/email-security-checker, the deployed service at https://email.illek.ie, local automated tests, the current Cloudflare configuration and the live D1 metadata visible to the configured Wrangler account. This was a review only. No product code, configuration, deployment, D1 data, DNS or other external state was changed.

## Executive verdict

The product is a credible technical prototype with a good foundation for an evidence-first email diagnostics tool. The standards-oriented SPF work, header analyzer, transport checks, batch reports, REST surface and MCP surface are useful. The Worker is small enough to operate, the local test suite is green, the current deployment is on the intended custom domain, and the desktop and 390px layouts are clean with no measured horizontal overflow.

The current release should be held from broad promotion until several correctness and security-boundary issues are fixed. The most visible production defect is that a single-domain share link throws a ReferenceError and leaves the user with no report. More seriously, transient DNS failures are collapsed into missing records, the SPF flatten preview can label a semantically unsafe rewrite as safe to publish, and the MTA-STS fetch follows redirects from a domain-controlled endpoint without an explicit final-origin check. These defects can produce a wrong security conclusion or make the Worker fetch an unintended destination.

There was no confirmed credential exposure, arbitrary code execution, D1 data loss or critical authentication bypass in this review. The principal risk is false confidence: a polished score can be wrong when DNS is incomplete, a record uses legal case variation, CAA has a non-issuance property, or a generated SPF replacement changes terminal behavior.

Recommended release posture:

* Keep the service available as a constrained diagnostic preview.
* Fix the five high-severity correctness and boundary issues before marketing it as standards-grade or using it for DNS change decisions.
* Position it as a developer, MSP and agent-friendly diagnostic primitive. Do not compete directly with established continuous DMARC monitoring platforms until there is evidence of demand for that workflow.

## Evidence and tests run

### Local source and repository

The current tree contains a Cloudflare Worker architecture with:

* worker.js at approximately 2,318 lines, including routing, domain analysis, scoring, D1 persistence, cache handling, retention and scheduled cleanup.
* header-analyzer.js for stateless message-header analysis.
* mcp.js for the Streamable HTTP MCP endpoint.
* web/app.js, web/index.html and web/styles.css for the client.
* schema.sql, D1 binding email-security-reports, and custom-domain configuration in wrangler.toml.
* Cloudflare DoH lookups, bounded SPF recursion, DKIM selector discovery, MX, PTR, CAA, DMARC, MTA-STS and TLS-RPT checks.

The worktree was already dirty before this review. The relevant current files were modified or untracked, including worker.js, web/app.js, web/index.html, web/styles.css, wrangler.toml, mcp.js, redirects.js, retention.js, OpenAPI/MCP documents and several tests. The latest committed change is 1a9f97a dated 2026-08-07, while Wrangler reports a newer deployment on 2026-08-14. The source commit or tag for that deployment is not identified by wrangler deployments list. This makes release reproduction and rollback attribution weaker than they should be.

The deployed static bytes for web/app.js, web/styles.css, web/openapi.yaml and web/mcp-copilot.yaml matched the local files by SHA-256. The root HTML served through / also matched the local source. This is useful evidence that the reviewed UI is the deployed UI. Worker source cannot be compared through HTTP, so the API findings below are based on both the current source and live behavior.

### Automated checks

The following completed successfully:

* npm test: SPF OpenSPF/RFC corpus, header tests, local D1 conformance, retention, redirect/security and MCP tests. The SPF corpus reported 177 pass and 0 fail. The Worker conformance suite reported 16 cases plus request-boundary and rate-limit checks.
* npm run check: Wrangler dry run completed. It reported nine assets, 1,880.10 KiB total and 514.06 KiB gzip, with the expected D1, rate limiter, assets and environment bindings.
* npm audit --omit=dev: zero vulnerabilities.
* npm run test:browser: 22 Chromium tests passed across desktop and mobile configurations.

The green suite is valuable, but it does not cover production share-link boot, transient DNS status, case-variant SPF analysis, null JSON payloads, MTA-STS redirects, CAA property semantics, IPv6 PTR coverage or SPF terminal-equivalence proofs. The browser suite uses a local server and therefore did not catch the live share-link failure.

### Live production checks

Read-only live checks on 2026-08-14 included:

* GET /: 200, correct title and security headers. The page loaded without console errors or failed requests in desktop and 390px Chromium runs.
* GET /api/health: 200 with {"ok":true,"service":"email-security-checker","version":"2.0.0"}.
* GET /api: 200 endpoint directory.
* HTTP to HTTPS redirects for the custom host, plus the checker.illek.ie alias redirect.
* Unknown route: 404 with security headers.
* POST /api/v2/domain-check, legacy POST /api/check, header analysis, record validation, SPF inspection and batch endpoints all returned representative successful responses.
* POST /api/batch returned 200 for batches of 2, 5 and 25 domains, including 25 uncached .invalid names. This did not reproduce a subrequest failure, but it does not prove that worst-case chained DNS and redirect paths fit every Workers plan limit.
* MCP initialize and tools/list returned successfully. The server advertised protocol 2025-11-25 and nine tools.
* A read-only remote D1 query showed 16 rows, with 0 rows written: six batch reports, eight domain reports and two rate-limit rows. Domain and batch rows expire from 2026-08-20; rate-limit rows expire from 2026-08-17.
* npx wrangler deployments list showed a latest deployment at 2026-08-14T17:39:47.254Z, version d7df83f5-07e8-4b82-9b9b-dc0a2ece563c, with no source message or tag.

### UI and responsive behavior

At 1440px and 390px:

* The home view, report view, batch view and tab navigation rendered without measured horizontal overflow.
* Native details sections and the main tabs were usable.
* The batch share link #batch-45f24e552e7f4df0 loaded five rows successfully.
* The single report share link https://email.illek.ie/#67a727b8008b4851 failed in production. Chromium recorded ReferenceError: Cannot access 'domainLoading' before initialization; no report or error panel became visible.

The failure is directly explained by web/app.js: the initial hash boot block around lines 52-63 calls loadSharedReport(hashVal) before the const declarations around lines 158-166. loadSharedReport accesses domainLoading before its initialization. The batch hash path runs later, after initialization, which explains the different result.

## Findings

No Critical finding was confirmed. High findings are release-blocking for a standards or security decision tool.

### High

#### H-01. Single-domain share links are broken in production

Evidence:

* Production navigation to https://email.illek.ie/#67a727b8008b4851 returned HTTP 200 but produced ReferenceError: Cannot access 'domainLoading' before initialization.
* web/app.js calls loadSharedReport in the startup hash branch around lines 52-63.
* The domainLoading and related DOM constants are declared later around lines 158-166, and loadSharedReport uses them around lines 136-154.
* A batch hash link worked, so this is a path-specific defect rather than a general production outage.

Impact: the principal share and collaboration path for an individual result fails silently. A user can copy a link that opens a blank analyzer and may assume the recipient cannot access the result.

Action: initialize all DOM references before any hash boot call, or defer hash processing until initialization is complete. Add a production-like browser test for a fresh navigation to both a domain report and a batch report, with an assertion that a report title and result panel become visible.

#### H-02. DNS transient and error states are treated as absent records

Evidence:

* worker.js gathers provider results with explicit state information, but analyzer functions such as analyzeSPF, DKIM discovery, MX, CAA and transport scoring primarily inspect the resulting record arrays.
* An empty array after SERVFAIL, timeout or provider failure follows the same scoring path as a genuine NODATA response. The report exposes DNS state, but the score and status can still be presented as a definitive missing-record conclusion.
* The existing conformance tests exercise successful and request-boundary behavior. They do not assert that a transient DNS state produces an inconclusive result and prevents a misleading penalty.

Impact: an outage at a DoH provider or authoritative DNS server can make a correctly configured domain appear insecure. This is the most important data-semantics risk because the UI presents a single score that users may act on.

Action: preserve a three-way result for every lookup: present, confirmed absent and unknown/error. Do not award a definitive fail or publishable remediation for unknown. Show provider disagreement and retry state separately, and include a score confidence indicator.

#### H-03. SPF flatten preview does not prove terminal behavior is preserved

Evidence:

* worker.js functions buildSpfFlattenPreview and expandSpfForFlatten expand positive include mechanisms and synthesize a root terminal mechanism.
* The safety decision checks dynamic or qualified mechanisms and expansion limits, but it does not establish that the nested policy's terminal result is equivalent for every input.
* A nested include can have ~all, ?all, +all, redirect or another terminal outcome. Replacing it with its IP mechanisms and a root -all can change the result for senders that do not match the expanded addresses.
* The live Google SPF preview returned safeToPublish: true for a normal case. That confirms the feature is exposed to users; it does not validate the proof for adversarial terminal policies.

Impact: a user can copy a preview labelled safe and change mail authentication behavior, causing legitimate mail to softfail, neutral or pass differently. This is a correctness and operational safety issue.

Action: either restrict the feature to a formally proven subset or mark every unsupported terminal/redirect/qualifier case unsafe. Preserve and compare the effective result of each nested policy, include terminal-policy evidence in the preview, and add fixtures where nested ~all, ?all, +all and redirect differ from the synthesized root policy. Never use safeToPublish without a proof that covers terminal semantics.

#### H-04. MTA-STS policy fetch follows domain-controlled redirects without an origin check

Evidence:

* worker.js function fetchMtaStsPolicy fetches https://mta-sts.<domain>/.well-known/mta-sts.txt.
* The fetch options set an abort signal and Cloudflare fetch options, but do not set redirect: "error" and do not compare the final URL with the expected mta-sts.<domain> origin.
* Fetch follows redirects by default. A domain owner controls the initial endpoint and can return a redirect to another public host or an internal address.
* The UI describes the check as a public policy fetch and does not communicate a final-origin policy.

Impact: the Worker becomes a remotely directed HTTP client. Depending on Cloudflare fetch protections and the target, this can consume resources, leak request metadata or probe an unintended address. It conflicts with the product's stated boundary that it does not probe private infrastructure.

Action: use redirect: "error" unless redirects are required. If redirects are intentionally supported, resolve and enforce the final origin, reject IP literals and private/link-local destinations, cap redirect count, and make the tested URL explicit in the report. Add tests for cross-origin and loop redirects.

#### H-05. SPF version and policy parsing is case-sensitive despite SPF case-insensitivity

Evidence:

* worker.js validateSpfRecord accepts only a token beginning exactly with v=spf1.
* analyzeSPF filters records with startsWith('v=spf1') and checks -all, ~all, ?all and +all with case-sensitive string operations.
* The OpenSPF/RFC corpus includes a case-insensitive version fixture, while the live validator rejected V=SpF1 -all with SPF record must begin with v=spf1.
* The live validator accepted v=spf1 -ALL as structurally valid, while the analyzer's case-sensitive policy checks would not recognize the uppercase terminal in the same way.

Impact: legal DNS record casing can be marked invalid or scored incorrectly. This is especially damaging in a standards-focused product because the false negative is deterministic and easy to reproduce.

Action: normalize directive and mechanism keywords for comparison while retaining the original record for display. Route all structural validation and scoring through the same parser and add case-variant fixtures to both endpoint and Worker tests.

### Medium

#### M-01. CAA analysis treats any CAA record as issuance authorization

Evidence:

* worker.js analyzeCAA maps the final token of each CAA record into an issuer list and returns a pass when records exist.
* CAA properties such as iodef provide incident-reporting information. They do not authorize a CA to issue a certificate. A record with no issue or issuewild authorization is not equivalent to an allow-list.
* The live API exposes CAA evidence as a simple pass/issuer result, with no property distinction in the user-facing conclusion.

Impact: a domain with only reporting or unrelated CAA properties can be presented as having a certificate issuance policy. This weakens the transport and domain-security conclusion.

Action: parse CAA tag/value pairs, distinguish issue, issuewild, iodef and unknown tags, and report “present but no issuance restriction” when appropriate. Link the interpretation to RFC 8659.

#### M-02. No MX is reported as inability to receive mail without RFC 5321 fallback handling

Evidence:

* The MX analyzer describes an empty MX result as “No MX record. This domain cannot receive email.”
* RFC 5321 permits fallback to the domain's address records when no MX record exists. The Null MX signal in RFC 7505 is the explicit way to state that a domain does not accept mail.
* The analyzer handles a sole Null MX record, but the no-MX message is too categorical and mixed Null MX plus real MX behavior is not clearly validated.

Impact: the report can advise a domain owner that inbound delivery is impossible when SMTP fallback may still apply.

Action: distinguish no MX, Null MX, valid MX and malformed/mixed MX. Explain fallback behavior and avoid a categorical failure unless a Null MX or equivalent policy is present.

#### M-03. Domain validation accepts malformed DNS names and endpoint normalization is inconsistent

Evidence:

* worker.js isValidDomain uses /^[a-z0-9][a-z0-9-_.]*\.[a-z]{2,}$/.
* The expression permits underscores, consecutive dots, labels longer than 63 octets, and labels with a trailing or leading hyphen after the first character. It does not enforce the 253-octet total or label boundaries.
* normalizeDomain strips a scheme/path and one trailing dot, while the legacy /api/check route lowercases its input without applying the same normalization.
* Error text refers to a public domain, but validation does not implement a public-suffix or reserved-name policy.

Impact: malformed queries can reach multiple DNS branches and produce confusing or false reports. The same domain can behave differently between modern and legacy endpoints.

Action: use one normalization and validation function, validate each DNS label and total length, define handling for IDNs and trailing dots, reject credentials/paths, and make “public domain” wording match the actual policy.

#### M-04. Header-analysis documentation promises checks the implementation does not perform

Evidence:

* The method dialog in web/index.html around line 399 says header analysis reflects Authentication-Results, Received-SPF and DKIM-Signature.
* header-analyzer.js parses Authentication-Results, Return-Path, Reply-To and Received-related data. It does not provide equivalent independent parsing or verification for Received-SPF and DKIM-Signature.
* The live header endpoint correctly reported a supplied Authentication-Results sample, but no evidence was found that the other named fields are independently evaluated.

Impact: users may believe a pasted header has been cryptographically or syntactically checked when the result primarily reflects provider assertions. This creates a trust and copy problem.

Action: either implement the promised field-level checks or change the copy to describe exactly what is parsed and what is trusted. Label provider assertions as evidence, not proof, and test contradictory and malformed headers.

#### M-05. Public APIs, bearer report links and public caching need a clearer privacy boundary

Evidence:

* The API has wildcard CORS and no authentication, which is reasonable for a public diagnostic tool.
* Domain reports are retrievable by an opaque identifier and served with public caching. The report includes the domain's authentication and transport posture. Batch reports include a domain inventory.
* D1 metadata shows domain and batch rows retained for roughly 14 days, but the UI and API do not make “anyone with the link” and cache behavior prominent.
* storeReport catches D1 failures and can leave the UI with a copied-looking share link even when no durable report ID exists.

Impact: a user can share more domain inventory than intended, and a report may remain in intermediary caches after a user assumes it is gone. Operational failures can produce a link that does not work.

Action: show an explicit public-link warning, state retention and cache duration, support a user-visible “share unavailable” state, avoid caching where a private result is expected, and add a purge/revocation decision. Keep the no-login model only while this boundary is clearly documented.

#### M-06. Request-wide Workers subrequest budget is not enforced

Evidence:

* A single domain can perform parallel SPF, DMARC, MX, CAA, PTR, MTA-STS, TLS-RPT and DKIM work. SPF recursion and DKIM CNAME discovery add bounded nested lookups.
* Batch requests analyze up to 25 domains. The source has per-IP rate limits and per-operation limits but no request-wide external-subrequest counter or early budget admission check.
* The 25-domain live batch tests returned 200, including uncached .invalid names. That is a passing sample, not proof for worst-case domains with long SPF chains, CNAME chains and redirect behavior.
* Cloudflare documents plan-specific Workers subrequest limits and counts redirects as subrequests: https://developers.cloudflare.com/workers/platform/limits/.

Impact: a carefully chosen batch can hit a plan limit, timeout, or produce a partial response. The same code may behave differently after cache expiry or under a different account plan.

Action: count and cap external fetches per request, reserve budget before fan-out, return per-domain “budget exceeded” evidence, and make batch size adapt to remaining budget. Remove duplicate MX work in the PTR path.

#### M-07. MCP protocol behavior and tool metadata are inaccurate

Evidence:

* mcp.js hardcodes MCP_PROTOCOL_VERSION = "2025-11-25" and returns it without negotiating the version supplied in initialize.params.protocolVersion.
* The endpoint does not clearly validate the required Accept and protocol headers for Streamable HTTP.
* Successful MCP responses did not carry the same CORS/security-header baseline as the general API response path.
* Purely read-only analyze, validate, build and evaluate tools are marked with readOnlyHint: false.

Impact: strict clients can fail negotiation, browser-based integrations can behave differently from REST clients, and agents receive misleading safety metadata.

Action: implement explicit version negotiation and rejection for unsupported versions, validate transport headers, apply the same response policy, and mark read-only tools accurately. Add an MCP client compatibility test.

#### M-08. API input errors are inconsistent with the published contract

Evidence:

* Several handlers destructure request JSON without first rejecting null. A JSON null payload can therefore produce a 500 instead of the documented 400 for invalid input in routes such as /api/check, /api/batch, /api/records/validate and /api/header/enrich.
* /api/header/enrich accepts a non-array string through new Set(ips) and can return an empty successful result instead of a type error.
* Batch input silently filters invalid domains and truncates to 25 rather than explaining every rejected item. The OpenAPI contract describes a maximum but does not make truncation behavior clear.

Impact: clients cannot reliably distinguish malformed input from service failure, and a caller can believe every requested domain was analyzed when some were discarded.

Action: centralize schema validation, reject null and wrong types with stable 400 errors, return per-item batch validation results, and document truncation or reject over-limit requests.

#### M-09. Successful JSON responses do not consistently receive the security-header baseline

Evidence:

* Static pages, health and unknown-route responses include HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy and Permissions-Policy.
* Representative successful API JSON responses carried CORS and content type but did not carry the same baseline.
* The CSP contains unsafe-inline for scripts and styles even though the served application can use same-origin external assets.

Impact: browser callers get different protection depending on the response path, and the relaxed CSP leaves less room to contain an accidental injection. HSTS learned from the homepage helps ordinary browser navigation, but response policy should still be consistent.

Action: apply a deliberate API security-header policy to every response, remove unsafe-inline where feasible, and test headers by route class. Do not add analytics or third-party script origins without a separate review.

#### M-10. PTR evidence is incomplete and can be mistaken for a general mail-server conclusion

Evidence:

* checkPTR around worker.js lines 1237-1262 queries only the first MX host and its IPv4 addresses.
* The source contains an IPv6 reverse-name helper, but the check does not cover all MX hosts or AAAA addresses.
* PTR is labelled as an observation and is excluded from the main score, which limits the damage, but the report can still look comprehensive beside the other transport checks.

Impact: a multi-server or IPv6 deployment can receive incomplete reverse-DNS evidence.

Action: inspect every relevant MX host, both A and AAAA, with explicit limits and per-address evidence. Keep PTR informational unless the product defines a clear deliverability interpretation.

#### M-11. Accessibility semantics are incomplete on the report and batch interactions

Evidence:

* Batch table rows are clickable but are not exposed as keyboard-focusable links or buttons with an accessible name.
* Sortable table headers use click behavior without reliable keyboard handling or aria-sort.
* Domain result injection lacks the same live-region treatment used by some header/report status elements.
* The method dialog has descriptive text but no clear aria-labelledby association.
* The 390px run showed no overflow and the initial page had no browser errors, so this is a semantics issue rather than a layout failure.

Impact: keyboard and assistive-technology users may not discover or operate the same report navigation and sorting controls.

Action: use real links/buttons, expose sort state, add focus-visible styles and live status updates, label the dialog, and add keyboard-only browser assertions.

### Low

#### L-01. CSS and documentation have drift that increases maintenance risk

Evidence:

* web/styles.css closes a mobile media block around lines 970-993, places rules intended for the batch table and input outside the block around lines 994-996, then contains a stray closing brace around line 997. Browsers recover, and current widths render without overflow, but the intended scope is unclear.
* README-WORKERS.md describes an edge cache of five minutes, while the source constant and UI describe 24 hours (CACHE_TTL=86400).
* The Worker README includes your-worker.workers.dev as a deployment example. The production configuration correctly uses custom domains with workers_dev=false and preview_urls=false, but the placeholder encourages a deployment style that is explicitly out of policy for this product.
* The uncommitted worktree and unattributed latest deployment make it difficult to know which source was approved.

Action: repair the CSS block, make cache documentation match code, remove workers.dev examples, and require a clean commit SHA or release tag in deployment notes.

#### L-02. Health is a liveness signal, not a readiness signal

Evidence:

* /api/health returns ok: true without checking D1 or rate-limit bindings.
* A later write can still fail with a 503 while health remains green.

Action: name this endpoint liveness, or add a separately protected readiness check that verifies required bindings without exposing operational details.

#### L-03. OpenAPI and endpoint documentation are incomplete

Evidence:

* web/openapi.yaml documents the main REST analysis operations but omits the health and endpoint-directory routes, the legacy /api/check route and the MCP transport.
* The MCP connector document is separate, so a client using only OpenAPI cannot discover the full supported surface.

Action: document the supported public contract, mark legacy endpoints explicitly, and link REST and MCP schemas together. Include error examples, retention and public-link semantics.

#### L-04. Batch orchestration and domain analysis are duplicated

Evidence:

* Batch processing logic is present in more than one route path, with separate validation, result assembly and persistence handling.
* The PTR path repeats an MX lookup already performed by domain analysis.

Action: create one bounded analysis service and one batch coordinator with a shared request budget. This is a maintainability and performance improvement after the correctness fixes.

## Technical correctness assessment

The current scoring model is understandable and sums the principal dimensions across SPF, DKIM, DMARC, MX, CAA and transport. The report preserves useful raw DNS evidence and has strong beginnings in RFC-oriented SPF evaluation. The 177-case corpus is a meaningful asset.

The score should be treated as a confidence-weighted diagnostic rather than a conformance verdict until unknown DNS states, case handling, CAA property semantics and SPF flatten terminal behavior are corrected. SPF lookup limits are bounded, which is good, but bounds alone do not make a generated policy equivalent. DMARC inheritance and Null MX detection worked in representative live checks. The main gap is consistent separation of authoritative absence from lookup failure.

The MTA-STS and TLS-RPT checks are valuable differentiators for a lightweight tool. They need explicit redirect and final-origin policy. The product should also state that DNS and policy observations are time-dependent and do not prove delivery, mailbox acceptance or cryptographic validity of a pasted provider assertion.

## Security, privacy and operational assessment

The public, unauthenticated design is coherent for a no-login diagnostic tool. Request bodies are bounded, rate limiting exists, D1 retention is finite, and the product does not ask for mailbox credentials. The security boundary is weakened by the MTA-STS redirect behavior, open expensive fetch surface and bearer report URLs.

Recommended boundary language:

* The service reads public DNS and public policy URLs.
* It does not log in to mailboxes or send mail.
* A report link is a bearer capability and may be cached publicly for its configured lifetime.
* Results are observations at lookup time, not proof of delivery or a replacement for controlled DNS change review.

Cloudflare configuration is directionally sound: custom domains are configured, Workers Dev and preview URLs are disabled, node compatibility is explicit, D1 and rate limits are bound, and a scheduled retention job exists. The deployment process needs a clean source identifier, a reproducible artifact check and a release gate that includes a production share-link smoke test.

## Product and market assessment

The generic email DNS checker market is crowded. MXToolbox already advertises an Email Health Monitor with more than 30 tests and recurring alerting: https://api.mxtoolbox.com/emailhealth. dmarcian offers account progress, reporting, multi-domain management and continuous DMARC operations: https://dmarcian.com/account-progress-report/ and https://dmarcian.com/dmarc-management-platform/. EasyDMARC covers managed DKIM, SPF flattening, reputation, investigation and aggregate-report workflows: https://support.easydmarc.com/knowledge-base/easydmarc-features-guideline/ and https://developers.easydmarc.com/.

The product has a plausible narrower position:

* Evidence-first, standards-aware diagnostics for engineers and MSP operators.
* A safe, inspectable SPF evaluator and guarded flatten preview rather than a black-box score.
* Header interpretation alongside DNS and transport evidence.
* A REST/OpenAPI surface and agent-native MCP tools that can be called from incident or onboarding workflows.
* No account required for a quick public-domain check.

The product currently lacks the lifecycle features that buyers expect from monitoring platforms: DMARC aggregate ingestion and normalization, sender inventory, historical trends, alerting, reputation and blocklist telemetry, domain ownership/team workflow, and controlled DNS change management. Adding those all at once would place it in a large and already well-served category. The defensible near-term value is a trustworthy diagnostic primitive that other tools and agents can call, with unusually clear evidence and failure states.

Success should be validated with real trials before broad expansion. The first useful trial is an MSP or platform engineer using the API/MCP tool during domain onboarding and an incident, measuring time to a defensible remediation and the rate of false recommendations. A static traffic count is insufficient evidence of product value.

## Recommended implementation plan

| Order | Change | Impact | Effort | Release gate |
| --- | --- | --- | --- | --- |
| P0 | Fix single-report hash boot and add fresh-navigation production-like test | High | Small | Domain and batch share links render a report |
| P0 | Preserve DNS present/absent/unknown states and make score confidence explicit | High | Medium | SERVFAIL, timeout, provider disagreement and NODATA fixtures |
| P0 | Constrain SPF flattening to proven terminal-equivalent cases | High | Medium to large | Adversarial nested policy corpus and no unsafe safeToPublish result |
| P0 | Block or strictly validate MTA-STS redirects and private/unexpected final origins | High | Small to medium | Cross-origin, loop and private-target tests |
| P0 | Make SPF parsing and policy comparisons case-insensitive | High | Small | Endpoint, analyzer and corpus case-variant tests |
| P1 | Correct CAA tags, MX fallback, mixed Null MX and domain validation | Medium | Medium | RFC-linked semantic fixtures and consistent legacy/v2 behavior |
| P1 | Add request-wide subrequest budgets and remove duplicate MX lookups | Medium | Medium | Worst-case chained-domain batch tests stay within declared limit |
| P1 | Normalize API error handling, null/type validation and batch rejection semantics | Medium | Small to medium | Stable 400/413/429/503 contract tests |
| P1 | State bearer-link visibility, retention and cache behavior; handle D1 failure visibly | Medium | Small | UI and API privacy-copy review plus failure test |
| P1 | Negotiate MCP protocol versions, correct annotations and align response headers | Medium | Small to medium | Strict MCP client test |
| P2 | Repair accessibility semantics and add keyboard/screen-reader-oriented browser checks | Medium | Medium | Keyboard-only report, sorting, dialog and live-region tests |
| P2 | Apply consistent security headers, tighten CSP, repair CSS and update docs/OpenAPI | Medium | Small to medium | Route-header matrix and clean static check |
| P2 | Consolidate analysis and batch orchestration; add structured error and budget telemetry | Medium | Medium | No behavior regression and useful production diagnostics |
| P3 | Run a measured MSP/engineer trial and choose one lifecycle extension based on observed demand | High product impact | Medium | Trial evidence, retained-user workflow and willingness-to-pay signal |

## Explicit do-not-implement list

Do not implement these in the next release:

* Automatic DNS writes, automatic SPF publication or “one-click fix” actions. The current proof and DNS-state handling are not strong enough for a write-capable workflow.
* A generic uptime, blacklist or deliverability dashboard. Established products already cover this, and it would dilute the evidence-first position.
* DMARC aggregate ingestion, team roles, billing and multi-tenant administration before a real trial establishes demand, retention and privacy requirements.
* AI-generated remediation narratives as a substitute for raw evidence and standards-aware explanations.
* Unbounded DNS recursion, selector scanning or arbitrary URL probing to make the report look more comprehensive.
* A monitoring promise such as “checks every few minutes” without an implemented scheduler, alerting, ownership model and retention policy.
* pages.dev or workers.dev production deployments. Keep the custom-domain configuration and workers_dev=false policy.
* More visual polish before the share-link, DNS-state, SPF, redirect and input-contract gates pass.

## Final disposition

This is worth keeping and tightening. It has a better technical angle than another generic scorecard, especially if MCP and inspectable SPF evidence become first-class integration points. The release is not ready to make authoritative security recommendations until the high findings are closed and tested in production-like conditions. After that, a focused trial can establish whether the agent/API workflow is a real differentiator before the product grows into monitoring SaaS.

### References

* RFC 7208, Sender Policy Framework: https://www.rfc-editor.org/rfc/rfc7208
* RFC 5321, Simple Mail Transfer Protocol: https://www.rfc-editor.org/rfc/rfc5321
* RFC 7489, DMARC: https://www.rfc-editor.org/rfc/rfc7489
* RFC 7505, Null MX: https://www.rfc-editor.org/rfc/rfc7505
* RFC 8460, TLS Reporting: https://www.rfc-editor.org/rfc/rfc8460
* RFC 8461, SMTP MTA Strict Transport Security: https://www.rfc-editor.org/rfc/rfc8461
* RFC 8659, Certification Authority Authorization: https://www.rfc-editor.org/rfc/rfc8659
* RFC 9989, DMARCbis: https://www.rfc-editor.org/rfc/rfc9989
* Cloudflare Workers limits: https://developers.cloudflare.com/workers/platform/limits/
