# Email Security Analyzer architecture

Last reviewed: 2026-08-15

Email Security Analyzer is an evidence-first diagnostic service for public email-domain posture and pasted message headers. It combines standards-aware DNS analysis, bounded policy retrieval, local header interpretation, shareable reports, REST APIs, and MCP tools in one Cloudflare Worker.

![Email Security Analyzer architecture infographic](docs/assets/email-security-architecture.png)

The infographic is a conceptual overview. The tables and flows below describe the implemented system.

## What the product does

The service supports four related workflows:

- Domain posture analysis covering SPF, DKIM discovery, DMARC, MX, CAA, PTR observations, MTA-STS, and TLS-RPT
- SPF inspection, sender evaluation, recursion accounting, and guarded flattening previews
- SPF and DMARC record validation plus review-ready record construction
- Stateless interpretation of pasted message headers with optional public-IP hop enrichment

It also compares up to 25 domains, stores optional shareable reports, exports JSON, and exposes its complete read-only capability through REST and nine MCP tools.

## System context

```mermaid
flowchart LR
    Caller[Browser, REST client, or MCP agent]
    Worker[Cloudflare Worker and static assets]
    Router[Validation, rate control, and routing]
    Domain[Domain analysis orchestrator]
    Header[Local header analyzer]
    DNS[DNS observation layer]
    Policy[SPF, DMARC, MTA-STS, and TLS-RPT engines]
    Report[Evidence, score, confidence, and recommendations]
    Cache[Cloudflare Cache API]
    DB[(Cloudflare D1)]

    Caller --> Worker --> Router
    Router --> Domain --> DNS --> Policy --> Report
    Router --> Header --> Report
    DNS <--> Cache
    Policy <--> Cache
    Report --> DB
    Report --> Caller
```

## Runtime components

| Component | Responsibility | Primary source |
| --- | --- | --- |
| Worker router | Serves the site, validates requests, applies security headers and rate controls, dispatches APIs and MCP, retrieves reports, and runs retention cleanup | `worker.js` |
| Domain analyzer | Coordinates DNS, SPF, DKIM, DMARC, MX, CAA, PTR, MTA-STS, TLS-RPT, scoring, confidence, and budget evidence | `worker.js` |
| Header analyzer | Parses Received, Authentication-Results, Received-SPF, DKIM-Signature, alignment, conflicts, and delivery hops without network access | `header-analyzer.js` |
| MCP adapter | Maps nine typed MCP tools to the same core functions used by REST | `mcp.js` |
| Redirect policy | Constrains MTA-STS retrieval and final origin handling | `redirects.js` |
| Retention module | Defines expiry and cleanup behavior for bearer-link reports | `retention.js` |
| Browser application | Provides domain, batch, SPF, record-building, and header-analysis workflows | `web/app.js`, `web/index.html` |
| Persistence | Stores domain and batch reports with expiry metadata | `schema.sql`, D1 binding `DB` |

The core is currently a single Worker module. The internal separation is logical rather than a set of independently deployed services.

## Domain-analysis flow

1. The caller submits a normalized public domain.
2. The router validates method, content type, request size, origin, domain syntax, and batch bounds.
3. A request-wide budget reserves at most 45 outbound subrequests.
4. DNS queries run through structured DNS over HTTPS. NODATA, NXDOMAIN, timeout, SERVFAIL, provider error, and budget exhaustion remain distinct states.
5. SPF records are parsed case-insensitively. Includes and redirects are traversed within lookup, void, cycle, depth, and request budgets.
6. DMARC discovery follows the implemented organisational-domain tree walk and validates external reporting authorisation.
7. DKIM checks use a bounded selector catalogue. Absence outside that catalogue is reported as limited coverage.
8. MX, Null MX, implicit MX fallback, CAA, PTR, TLS-RPT, and MTA-STS evidence is collected.
9. MTA-STS is fetched only from the expected HTTPS origin with redirects rejected, bounded body reads, and an explicit timeout.
10. Findings feed a deterministic score. Unknown observations reduce confidence rather than receiving definitive failure points.
11. The response includes raw evidence, checks, recommendations, score confidence, unknown controls, source revision, and request-budget use.
12. If sharing is requested, the report is stored in D1 under an opaque 14-day bearer identifier.

## Header-analysis flow

1. The caller pastes message headers, capped at 256 KiB.
2. `header-analyzer.js` parses fields locally without DNS or HTTP calls.
3. Authentication-Results and related fields are presented as receiver-provided evidence. They are not cryptographically re-verified.
4. The analyzer builds structured hops, detects conflicting results, and evaluates visible SPF, DKIM, and DMARC alignment claims.
5. If the caller separately requests enrichment, up to ten globally routable hop addresses receive bounded PTR and forward-confirmation observations.

## Interfaces

| Interface | Capability |
| --- | --- |
| `POST /api/v2/domain-check` | Complete domain posture analysis |
| `POST /api/v2/header-analysis` | Stateless header interpretation |
| `POST /api/batch` | Compare up to 25 domains |
| `POST /api/spf/inspect` | Recursive SPF inspection and flattening proof |
| `POST /api/spf/evaluate` | SPF evaluation for client IP, sender, and HELO |
| `POST /api/records/validate` | Validate proposed SPF or DMARC |
| `POST /api/v2/record-build` | Construct a review-ready record |
| `POST /api/header/enrich` | Enrich bounded delivery-hop IP addresses |
| `GET /api/reports/{reportId}` | Retrieve an unexpired report |
| `POST /mcp` and `POST /mcp/v2` | Stateless Streamable HTTP MCP |

MCP publishes `analyze_email_domain`, `analyze_email_headers`, `analyze_email_domains_batch`, `inspect_spf`, `evaluate_spf`, `validate_email_record`, `build_email_record`, `enrich_email_hops`, and `get_email_security_report`.

## Third-party services and libraries

| Service or library | Use | Data sent | Required |
| --- | --- | --- | --- |
| Cloudflare Workers and Assets | Runtime, custom domains, static site, request handling, and Cron | Normal service request metadata | Yes |
| Cloudflare D1 | Shareable report storage and durable fallback quota state | Report JSON, expiry metadata, opaque IDs, one-way client fingerprints | Required for sharing |
| Cloudflare Rate Limiting bindings | Edge abuse controls for standard and expensive routes | Cloudflare-managed request keys and counters | Production control |
| Cloudflare Cache API | Caches repeated domain, PTR, and MTA-STS observations | Internal cache keys and processed responses | Performance optimization |
| Cloudflare DNS over HTTPS | Primary DNS observations | Domain or address and record type | Yes |
| Google Public DNS | Transient-error fallback and provider evidence | Domain or address and record type | Fallback |
| Quad9 DNS over HTTPS | Additional transient-error fallback | Domain or address and record type | Fallback |
| Analysed domain DNS | Published email records | Standard DNS queries via the named resolvers | Core subject |
| `mta-sts.<domain>` | Published MTA-STS policy retrieval | HTTPS request for `/.well-known/mta-sts.txt` | Conditional |
| `mailauth` | Local RFC 7208 SPF evaluation | No external service call | Local dependency |
| `tldts` | Local public-suffix and organisational-domain handling | No external service call | Local dependency |

The application has no mailbox connection, DMARC aggregate-report ingestion, sender reputation feed, or automatic DNS-write integration.

## Storage, privacy, and retention

- Domain and batch reports can be saved in D1 under opaque bearer identifiers.
- Stored reports expire after 14 days and are removed by an hourly Cron Trigger.
- Report retrieval and export use `Cache-Control: private, no-store`.
- Header analysis is stateless unless the caller explicitly uses a report-producing workflow.
- The system stores analysis evidence and recommendations. It does not need mailbox credentials or domain DNS credentials.
- Clients should avoid placing sensitive content in pasted headers because the headers are processed by the service even when they are not retained.

## Security and correctness boundaries

- Request bodies are bounded before JSON parsing.
- Only public domains and public enrichment IPs are accepted.
- DNS absence, provider disagreement, transient failure, and budget exhaustion remain distinguishable.
- Unknown controls do not receive confident pass or fail scoring.
- MTA-STS redirects fail closed and the final origin is validated.
- SPF flattening becomes copy-enabled only for the restricted terminal-equivalent subset that the analyzer can prove.
- Header results describe pasted receiver claims and never imply cryptographic verification.
- Record generation produces review-ready text. The service does not publish DNS changes.

## Deployment topology

One Cloudflare Worker serves the frontend and API on `email.illek.ie` and the compatibility hostname `checker.illek.ie`. Static files come from `web/`; the Worker runs first for all requests. D1 is bound as `DB`, two Cloudflare rate-limit bindings protect standard and expensive calls, and the retention Cron runs at minute 17 of every hour. Development and preview hostnames are disabled.

## Failure model

An individual provider or record failure becomes unknown or unavailable evidence. Batch results preserve per-domain validation and errors. Budget exhaustion returns an incomplete result with explicit budget metadata. D1 failure makes sharing unavailable while leaving the analysis result visible where possible.

## Non-goals

The analyzer does not prove mail delivery, inspect mailbox contents, monitor ongoing posture, ingest DMARC aggregate reports, discover every DKIM selector, validate a pasted DKIM signature cryptographically, alter DNS, or replace provider-specific delivery and abuse tooling.

## Verification map

- Full unit and conformance suite: `npm test`
- Browser workflows: `npm run test:browser`
- Worker packaging: `npm run check`
- REST schema: `web/openapi.yaml`
- MCP connector schema: `web/mcp-copilot.yaml`
- RFC corpus: `test/fixtures/rfc7208-tests.yml`
