# Email Security Checker — Cloudflare Workers

Serverless email security analyzer for SPF, DKIM, RFC 9989 DMARC, MX,
MTA-STS, TLS-RPT, CAA, and inbound MX reverse-DNS observations.

## Features

- **SPF Analysis** — Mailauth RFC 7208 evaluation with lookup/void limits, plus static policy inspection
- **DKIM Check** — Common selector discovery
- **DMARC Analysis** — RFC 9989 tree-walk discovery and RFC 9990 external-report authorisation
- **MX Records** — Mail server enumeration
- **CAA Records** — Certificate authority restrictions
- **PTR Observation** — Forward-confirmed reverse DNS for an inbound MX IP (not a sending reputation claim)
- **Transport Security** — MTA-STS policy and MX coverage checks plus TLS-RPT validation
- **SPF Inspector** — Recursive include tracing, lookup-budget analysis, and guarded flattening previews
- **Record Builder** — Review-ready SPF records and staged DMARC policy planning
- **Header Analyzer** — Stateless receiver-report interpretation, organisational-domain alignment, conflicting-result detection, structured delivery hops, and opt-in PTR enrichment

## Optimizations for Workers

- **Parallel DNS lookups** — All queries run concurrently
- **Edge caching** — 5-minute cache for repeated checks
- **Minimal CPU usage** — Efficient parsing, no regex backtracking
- **Structured DoH** — Separates NODATA, NXDOMAIN, SERVFAIL, timeout, and other errors with transient-provider fallback

## Deployment

### Prerequisites

```bash
npm install -g wrangler
wrangler login
```

### Deploy

```bash
cd email-security-checker
wrangler deploy
```

### Custom Domain (Optional)

```bash
wrangler custom-domain add email-checker.yourdomain.com
```

## Usage

1. Open the deployed URL
2. Enter a domain (e.g., `example.com`)
3. View comprehensive email security report

## API

```bash
curl -X POST https://your-worker.workers.dev/api/check \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}'
```

Inspect and preview SPF flattening:

```bash
curl -X POST https://your-worker.workers.dev/api/spf/inspect \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}'
```

Flattened records are point-in-time previews. Dynamic, qualified, cyclic, or
unresolved mechanisms are preserved and flagged for manual review. Copying is
enabled only for the restricted positive-IP/include subset for which the tool
can preserve the original terminal result; redirects are never flattened.

Evaluate a sender using the standards engine:

```bash
curl -X POST https://your-worker.workers.dev/api/spf/evaluate \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","sender":"user@example.com","helo":"mail.example.com","ip":"192.0.2.1"}'
```

Validate a proposed SPF or DMARC record:

```bash
curl -X POST https://your-worker.workers.dev/api/records/validate \
  -H "Content-Type: application/json" \
  -d '{"type":"spf","domain":"example.com","record":"v=spf1 include:_spf.google.com ~all"}'
```

The UI keeps copy actions disabled until the validator confirms the record.

Interpret complete message headers:

```bash
curl -X POST https://your-worker.workers.dev/api/header/analyze \
  -H "Content-Type: application/json" \
  -d '{"headers":"From: sender@example.com\r\nAuthentication-Results: mx.example; spf=pass; dkim=pass header.d=example.com; dmarc=pass"}'
```

Header analysis is stateless and capped at 256 KB. Results describe claims made
by the pasted `Authentication-Results` fields; they are not a cryptographic
re-evaluation. PTR enrichment is a separate, explicit request for up to ten
globally routable IPv4 or IPv6 addresses.

## Response Format

```json
{
  "domain": "example.com",
  "timestamp": "2026-07-22T21:00:00.000Z",
  "spf": { "status": "pass", "record": "...", "checks": [...] },
  "dkim": { "status": "warn", "selectors": [...], "checks": [...] },
  "dmarc": { "status": "pass", "policy": "reject", "checks": [...] },
  "mx": { "status": "pass", "records": [...] },
  "caa": { "status": "warn", "checks": [...] },
  "ptr": { "status": "pass", "checks": [...] },
  "overall_score": 85,
  "overall_status": "excellent"
}
```

## Limits

- **Workers Free**: 100,000 requests/day, 10 ms CPU time, 128 MB memory, 3 MB compressed Worker size, and 50 external subrequests per invocation
- **Worker header analysis**: zero external subrequests; local worst-case 256 KB parsing benchmark averages below 1 ms (hardware-dependent)
- **API rate limits**: standard POST `/api` routes allow 60 requests per client per 60 seconds; expensive routes allow 10 requests per client per 60 seconds. Cloudflare Rate Limiting counters are shared across Worker isolates but scoped to the serving location, so these are not strict global quotas.

## Local Development

```bash
npm install
npm test
npm run test:browser
wrangler dev
```

Opens at `http://localhost:8787`
