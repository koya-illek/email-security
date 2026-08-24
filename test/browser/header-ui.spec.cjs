'use strict';

const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const { analyzeEmailHeaders } = require('../../header-analyzer');

const goodHeaders = [
  'From: Example Billing <billing@example.com>',
  'Return-Path: <bounce@mail.example.com>',
  'Reply-To: support@example.com',
  'Authentication-Results: mx.receiver.example; spf=pass smtp.mailfrom=bounce@mail.example.com; dkim=pass header.d=mail.example.com; dmarc=pass header.from=example.com',
  'Received: from sender.example (sender.example [8.8.8.8]) by mx.receiver.example with ESMTPS; Thu, 23 Jul 2026 20:00:00 +0100'
].join('\r\n');

function domainReport(record) {
  return {
    domain: 'example.com',
    overall_score: 80,
    overall_status: 'good',
    spf: { status: 'pass', record, checks: [], mechanisms: [], providers: [] },
    dkim: { status: 'warn', selectors: [], checks: [] },
    dmarc: { status: 'warn', policy: 'none', rua: [], checks: [] },
    mx: { status: 'pass', records: [{ priority: 10, host: 'mx.example.com' }] },
    transport: { status: 'pass', checks: [] },
    ptr: { status: 'info', checks: [] },
    caa: { status: 'info', checks: [] },
  };
}

async function openBuilderWithRecord(page, record) {
  await page.route('**/api/check', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(domainReport(record)),
  }));
  await page.route('**/api/records/validate', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ valid: true, errors: [], warnings: [], lookupCount: 2, characterCount: record.length }),
  }));

  await page.goto('/');
  await page.getByLabel('Domain to check').fill('example.com');
  await page.getByRole('button', { name: 'Check security' }).click();
  await expect(page.locator('#domain-report')).toBeVisible();
  await page.getByRole('button', { name: 'Build records' }).click();
  await expect(page.locator('#spf-builder-output .dns-value')).toBeVisible();
}

test('renders accurate reported-authentication feedback and accessible sections', async ({ page }) => {
  await page.goto('/#headers');
  await page.getByLabel('Complete message headers').fill(goodHeaders);
  await page.getByRole('button', { name: 'Analyze Headers' }).click();

  await expect(page.locator('.trust-banner')).toContainText('All three methods reported pass');
  await expect(page.locator('#header-results')).toContainText('Reported by pasted headers');
  await expect(page.locator('#header-results')).toContainText('Envelope sender relaxed alignment');
  await expect(page.locator('#header-results')).toContainText('DKIM signing domain relaxed alignment');
  await expect(page.locator('#header-results')).not.toContainText('does not align');

  const receivedSection = page.locator('#header-results details').filter({ hasText: 'Received Chain' });
  const receivedSummary = receivedSection.locator(':scope > summary');
  await expect(receivedSection).not.toHaveAttribute('open', '');
  await receivedSummary.click();
  await expect(receivedSection).toHaveAttribute('open', '');
  await expect(page.locator('.hop-item')).toContainText('Final receiving hop');
});

test('does not present forged-looking pasted claims as an unqualified success', async ({ page }) => {
  await page.goto('/#headers');
  await page.getByLabel('Complete message headers').fill([
    'From: Accounts <accounts@example.com>',
    'Return-Path: <attacker@evil.test>',
    'Authentication-Results: attacker.invalid; spf=pass; dkim=pass header.d=notexample.com; dmarc=pass'
  ].join('\r\n'));
  await page.getByRole('button', { name: 'Analyze Headers' }).click();

  const findingsSection = page.locator('#header-results details').filter({ hasText: 'Header Findings' });
  await expect(findingsSection).toContainText('warn');
  await expect(page.locator('#header-results')).toContainText('Pasted headers can be forged or incomplete');
  await expect(page.locator('#header-results')).toContainText('DKIM signing domain does not align');
  await expect(page.locator('#header-results')).toContainText('No Received chain found');
});

test('puts a multi-domain From warning ahead of reported authentication passes', async ({ page }) => {
  await page.goto('/#headers');
  await page.getByLabel('Complete message headers').fill([
    'From: Accounts <accounts@example.com>, Payments <payments@evil.test>',
    'Authentication-Results: mx.receiver.example; spf=pass; dkim=pass header.d=example.com; dmarc=pass'
  ].join('\r\n'));
  await page.getByRole('button', { name: 'Analyze Headers' }).click();

  await expect(page.locator('.trust-banner')).toHaveClass(/fail/);
  await expect(page.locator('.trust-banner strong')).toHaveText('Suspicious header structure found');
  await expect(page.locator('#header-results')).toContainText('DMARC validation is not normally possible');
});

test('keeps every tool tab visible on narrow screens', async ({ page }) => {
  await page.goto('/#headers');
  const viewport = page.viewportSize();
  for (const tab of await page.getByRole('tab').all()) {
    const box = await tab.boundingBox();
    expect(box).not.toBeNull();
    expect(box.x).toBeGreaterThanOrEqual(0);
    expect(box.x + box.width).toBeLessThanOrEqual(viewport.width);
  }
  await expect(page.getByRole('tab', { name: 'Header Analyzer' })).toHaveAttribute('aria-selected', 'true');
});

test('keeps the product introduction visible on a fresh mobile visit', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  expect(await page.evaluate(() => scrollY)).toBe(0);
  await expect(page.locator('h1')).toBeInViewport();
  await expect(page.getByLabel('Domain to check')).not.toBeFocused();
  for (const tab of await page.getByRole('tab').all()) {
    const box = await tab.boundingBox();
    expect(box.height).toBeGreaterThanOrEqual(44);
  }
});

test('exposes labelled inputs, keyboard tabs, metadata and privacy guidance', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle(/SPF, DKIM, DMARC/);
  await expect(page.locator('link[rel="canonical"]')).toHaveAttribute('href', 'https://email.illek.ie/');
  await expect(page.getByLabel('Domain to check')).toBeVisible();
  await page.getByRole('tab', { name: 'Check Domain' }).focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'Batch Check' })).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'SPF Inspector' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('link', { name: 'Privacy' })).toHaveAttribute('href', 'https://tools.illek.ie/privacy');
});

test('has no automated accessibility violations on the main checker', async ({ page }) => {
  await page.goto('/');
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});

test('has no automated accessibility violations on the tool panels', async ({ page }) => {
  // Each panel is a top-level section under the page h1; its title must not
  // skip heading levels (h1 -> h3 was an axe violation on every non-default
  // tab, invisible while axe only scanned the landing view).
  await page.goto('/?panel=audit-builder#builder');
  let results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);

  await page.route('**/api/header/analyze', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(analyzeEmailHeaders(goodHeaders))
  }));
  await page.goto('/?panel=audit-headers#headers');
  await page.getByLabel('Complete message headers').fill(goodHeaders);
  await page.getByRole('button', { name: 'Analyze Headers' }).click();
  await expect(page.locator('.trust-banner')).toBeVisible();
  results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});

test('record-builder tabs expose selection and support arrow-key navigation', async ({ page }) => {
  await page.goto('/#builder');
  const spfTab = page.getByRole('tab', { name: 'SPF Builder' });
  const dmarcTab = page.getByRole('tab', { name: 'DMARC Planner' });

  await expect(spfTab).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#builder-spf')).toBeVisible();
  await expect(page.locator('#builder-dmarc')).toBeHidden();

  await spfTab.focus();
  await page.keyboard.press('ArrowRight');
  await expect(dmarcTab).toBeFocused();
  await expect(dmarcTab).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#builder-spf')).toBeHidden();
  await expect(page.locator('#builder-dmarc')).toBeVisible();
});

test('fresh share-link navigation renders domain and batch reports after DOM boot', async ({ page }) => {
  const report = domainReport('v=spf1 -all');
  report.id = '1234567890abcdef';
  report.share = { available: true, id: report.id, retentionDays: 14, expiresAt: '2026-08-28T00:00:00.000Z', bearer: true };
  const batch = { _reportType: 'batch', id: 'abcdef1234567890', domains: ['example.com'], results: [{ domain: 'example.com', overall_score: 80, overall_status: 'good', spf: { status: 'pass' }, dkim: { status: 'warn' }, dmarc: { status: 'warn' }, mx: { status: 'pass' }, transport: { status: 'info' } }], created_at: '2026-08-14T00:00:00.000Z', share: { available: true, id: 'abcdef1234567890', retentionDays: 14, expiresAt: '2026-08-28T00:00:00.000Z', bearer: true } };
  await page.route('**/api/reports/1234567890abcdef', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(report) }));
  await page.route('**/api/reports/abcdef1234567890', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(batch) }));

  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/#1234567890abcdef');
  await expect(page.locator('#domain-report')).toBeVisible();
  await expect(page.locator('#report-domain')).toHaveText('example.com');
  await expect(page.locator('#domain-share-note')).toContainText('Public bearer link');

  await page.goto('/?fresh=batch#batch-abcdef1234567890');
  await expect(page.locator('#batch-report')).toBeVisible();
  await expect(page.locator('#batch-table')).toContainText('example.com');
  expect(errors).toEqual([]);

  // A pasted batch share link can lose its #batch- prefix; it must still land
  // on the batch renderer instead of crashing in the domain renderer.
  await page.goto('/?fresh=batch-bare#abcdef1234567890');
  await expect(page.locator('#batch-report')).toBeVisible();
  await expect(page.locator('#batch-table')).toContainText('example.com');
  expect(errors).toEqual([]);
});

test('an oversized header paste is refused locally without spending an upload', async ({ page }) => {
  // The API caps header bodies at 256 KiB; the client names that limit
  // immediately instead of uploading a body the server must refuse.
  let analyzeRequests = 0;
  await page.route('**/api/header/analyze', route => {
    analyzeRequests++;
    return route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
  });
  await page.goto('/#headers');
  const oversizedPaste = 'Subject: oversized\n' + ('X-Filler: ' + 'a'.repeat(200) + '\n').repeat(1400);
  await page.getByLabel('Complete message headers').fill(oversizedPaste);
  await page.getByRole('button', { name: 'Analyze Headers' }).click();

  await expect(page.locator('#header-error')).toBeVisible();
  const msg = page.locator('#header-error-msg');
  await expect(msg).toContainText('256 KiB');
  await expect(msg).not.toContainText('fetch');
  await page.waitForTimeout(300);
  expect(analyzeRequests).toBe(0);
});

test('completed analyses announce one concise summary instead of the whole report', async ({ page }) => {
  await page.route('**/api/check', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(domainReport('v=spf1 -all'))
  }));
  await page.goto('/');
  await page.getByLabel('Domain to check').fill('example.com');
  await page.getByRole('button', { name: 'Check security' }).click();

  const status = page.locator('#analysis-status');
  await expect(status).toContainText('Analysis of example.com complete');
  await expect(status).toContainText('80 out of 100');
  // The report containers themselves must stay outside the live-region tree.
  for (const id of ['#domain-results', '#spf-report', '#header-results']) {
    await expect(page.locator(id)).not.toHaveAttribute('aria-live');
  }
});

test('a shape-drifted stored report degrades to unavailable evidence instead of crashing', async ({ page }) => {
  // Share links replay any D1 row written within the 14-day retention,
  // regardless of which analysis schema produced it. Missing or drifted
  // categories must render as inconclusive evidence, never throw mid-render.
  const drifted = {
    id: 'drft0000drft0000',
    domain: 'legacy.example',
    overall_score: 'eighty',
    overall_status: 'good',
    score_confidence: 'medium',
    unknown_controls: [],
    share: { available: true, id: 'drft0000drft0000', retentionDays: 14, expiresAt: '2026-09-06T00:00:00.000Z', bearer: true }
    // spf/dkim/dmarc/mx/transport/caa/ptr are all absent on purpose.
  };
  await page.route('**/api/reports/drft0000drft0000', route => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(drifted)
  }));

  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/#drft0000drft0000');
  await expect(page.locator('#domain-report')).toBeVisible();
  await expect(page.locator('#report-domain')).toHaveText('legacy.example');
  const metrics = page.locator('#domain-metrics');
  await expect(metrics).toContainText('unavailable');
  await expect(metrics).not.toContainText('/100');

  // The degraded report must still hand off to the Record Builder.
  await page.getByRole('button', { name: 'Build records' }).click();
  await expect(page.locator('#spf-builder-output .dns-value')).toBeVisible();
  expect(errors).toEqual([]);
});

test('a dead #batch- share link explains itself inside the batch panel', async ({ page }) => {  await page.route('**/api/reports/dead0000dead0000', route => route.fulfill({
    status: 404,
    contentType: 'application/json',
    body: JSON.stringify({ error: 'Report not found or expired' })
  }));

  await page.goto('/#batch-dead0000dead0000');
  await expect(page.locator('#batch-error')).toBeVisible();
  await expect(page.locator('#batch-error-msg')).toContainText('Report not found or expired');
});

test('batch results disclose lines the API refused', async ({ page }) => {
  await page.route('**/api/batch', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      _reportType: 'batch',
      domains: ['example.com'],
      results: [{ domain: 'example.com', overall_score: 70, overall_status: 'good', spf: { status: 'pass' }, dkim: { status: 'warn' }, dmarc: { status: 'warn' }, mx: { status: 'pass' }, transport: { status: 'info' } }],
      created_at: '2026-08-22T00:00:00.000Z',
      validation: {
        accepted: ['example.com'],
        rejected: [{ index: 1, input: 'bad..example.com', error: 'Invalid public domain' }]
      },
      request_budget: { limit: 45, per_domain_limit: 15, used: 5, exhausted: false },
      share: { available: false }
    })
  }));

  await page.goto('/#batch');
  await page.getByLabel('Domains (one per line, max 3)').fill('example.com\nbad..example.com');
  await page.getByRole('button', { name: 'Check All Domains' }).click();

  await expect(page.locator('#batch-report')).toBeVisible();
  const note = page.locator('#batch-rejected-note');
  await expect(note).toBeVisible();
  await expect(note).toContainText('1 line was not checked');
  await expect(note).toContainText('"bad..example.com" (Invalid public domain)');
});

test('an errored batch row reads as an error, not as a failing domain', async ({ page }) => {
  await page.route('**/api/batch', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      _reportType: 'batch',
      domains: ['broken.example'],
      results: [{
        domain: 'broken.example',
        overall_score: 0,
        overall_status: 'error',
        error: 'Analysis failed unexpectedly',
        // An error is not evidence; controls arrive inconclusive.
        spf: { status: 'info' }, dkim: { status: 'info' }, dmarc: { status: 'info' },
        mx: { status: 'info' }, transport: { status: 'info' }
      }],
      created_at: '2026-08-22T00:00:00.000Z',
      validation: { accepted: ['broken.example'], rejected: [] },
      request_budget: { limit: 45, per_domain_limit: 15, used: 0, exhausted: false },
      share: { available: false }
    })
  }));

  await page.goto('/#batch');
  await page.getByLabel('Domains (one per line, max 3)').fill('broken.example');
  await page.getByRole('button', { name: 'Check All Domains' }).click();

  const row = page.locator('#batch-table tbody tr').filter({ hasText: 'broken.example' });
  await expect(row).toBeVisible();
  const scoreCell = row.locator('.score-cell');
  await expect(scoreCell).toContainText('error');
  await expect(scoreCell).not.toContainText('/100');
  // The reason is visible text, not a hover-only title.
  await expect(scoreCell.locator('.cell-note')).toContainText('Analysis failed unexpectedly');
  await expect(row).not.toContainText('Fail');
});

test('crossing the batch line limit is announced once, not per keystroke', async ({ page }) => {
  await page.goto('/#batch');
  const input = page.getByLabel('Domains (one per line, max 3)');
  await input.fill('example.com\nexample.org');
  const status = page.locator('#batch-count-status');
  await expect(status).toHaveText('');

  await input.fill('example.com\nexample.org\nexample.net\nfour.example');
  await expect(status).toContainText('1 line exceeds the 3-domain limit');

  // Staying over the limit must not re-announce on every keystroke.
  await input.fill('example.com\nexample.org\nexample.net\nfour.example\nfive.example');
  await expect(status).toHaveText('2 lines exceed the 3-domain limit and will be rejected.');

  await input.fill('example.com');
  await expect(status).toHaveText('');
});

test('an untouched Record Builder spends no validation quota until input arrives', async ({ page }) => {
  let validateCalls = 0;
  await page.route('**/api/records/validate', route => {
    validateCalls++;
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ valid: true, errors: [], warnings: [], lookupCount: 0, characterCount: 12 })
    });
  });

  await page.goto('/#builder');
  const copyButton = page.locator('#spf-builder-output .copy-btn');
  await expect(copyButton).toHaveText('Enter a domain to validate');
  await expect(copyButton).toBeDisabled();
  await page.waitForTimeout(700); // outlasts the 500ms validation debounce

  await page.locator('#builder-domain').fill('example.com');
  await expect.poll(() => validateCalls).toBeGreaterThan(0);
});

test('mechanisms typed without a valid domain spend no validation quota', async ({ page }) => {
  // Typing mechanisms ahead of their domain used to fire debounced
  // {domain: ""} validations that the server could only refuse, burning the
  // expensive limiter while typing.
  let validateCalls = 0;
  await page.route('**/api/records/validate', route => {
    validateCalls++;
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ valid: true, errors: [], warnings: [], lookupCount: 0, characterCount: 12 })
    });
  });

  await page.goto('/#builder');
  await page.locator('#spf-custom').fill('ip4:192.0.2.1');
  await expect(page.locator('#spf-builder-output .copy-btn')).toHaveText('Enter a domain to validate');
  await page.waitForTimeout(700); // outlasts the validation debounce

  await page.locator('#builder-domain').fill('bad..example.com');
  await expect(page.locator('#spf-builder-output .copy-btn')).toHaveText('Enter a valid domain to validate');
  await page.waitForTimeout(700);

  expect(validateCalls).toBe(0);
  await page.locator('#builder-domain').fill('example.com');
  await expect.poll(() => validateCalls).toBe(1);
});

test('Build records preserves imported SPF providers and blocks unconfirmed removal', async ({ page }) => {
  const report = {
    domain: 'example.com',
    overall_score: 80,
    overall_status: 'good',
    spf: {
      status: 'pass',
      record: 'v=spf1 include:provider-a.example include:provider-b.example -all',
      checks: [],
      mechanisms: [],
      providers: []
    },
    dkim: { status: 'warn', selectors: [], checks: [] },
    dmarc: { status: 'warn', policy: 'none', rua: [], checks: [] },
    mx: { status: 'pass', records: [{ priority: 10, host: 'mx.example.com' }] },
    transport: { status: 'pass', checks: [] },
    ptr: { status: 'info', checks: [] },
    caa: { status: 'info', checks: [] }
  };

  await page.route('**/api/check', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(report)
  }));
  await page.route('**/api/records/validate', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ valid: true, errors: [], warnings: [], lookupCount: 2, characterCount: 78 })
  }));

  await page.goto('/');
  await page.getByLabel('Domain to check').fill('example.com');
  await page.getByRole('button', { name: 'Check security' }).click();
  await expect(page.locator('#domain-report')).toBeVisible();
  await page.getByRole('button', { name: 'Build records' }).click();

  const proposed = page.locator('#spf-builder-output .dns-value');
  await expect(proposed).toContainText('include:provider-a.example');
  await expect(proposed).toContainText('include:provider-b.example');
  await expect(proposed).not.toHaveText('v=spf1 -all');

  const custom = page.locator('#spf-custom');
  await custom.fill('include:provider-a.example');
  const copyButton = page.locator('#spf-builder-output .copy-btn');
  await expect(copyButton).toBeDisabled();
  await expect(page.locator('#spf-safety-notice')).toContainText('provider-b.example');

  await page.locator('#spf-safety-confirm').check();
  await expect(copyButton).toBeEnabled();
});

test('empty SPF hard-fail requires confirmed no-sender state', async ({ page }) => {
  await page.route('**/api/records/validate', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ valid: true, errors: [], warnings: [], lookupCount: 0, characterCount: 12 })
  }));

  await page.goto('/#builder');
  await page.locator('#builder-domain').fill('example.com');
  await page.locator('#spf-policy').selectOption('-all');

  const copyButton = page.locator('#spf-builder-output .copy-btn');
  await expect(page.locator('#spf-safety-notice')).toContainText('No sending mechanisms');
  await expect(copyButton).toBeDisabled();

  await page.locator('#spf-stage').selectOption('confirmed');
  await expect(copyButton).toBeDisabled();
  await page.locator('#spf-safety-confirm').check();
  await expect(copyButton).toBeEnabled();
});

test('round-trips exact order for multiple known SPF providers', async ({ page }) => {
  const record = 'v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all';
  await openBuilderWithRecord(page, record);

  await expect(page.locator('#spf-builder-output .dns-value')).toHaveText(record);
  await expect(page.locator('#spf-policy')).toHaveValue('-all');
  await expect(page.locator('#spf-safety-confirmation')).toHaveClass(/hidden/);
});

test('shows qualified mechanism order changes before allowing an SPF copy', async ({ page }) => {
  const record = 'v=spf1 ~include:provider-a.example +include:provider-b.example -all';
  await openBuilderWithRecord(page, record);

  await expect(page.locator('#spf-builder-output .dns-value')).toHaveText(record);
  await page.locator('#spf-custom').fill('+include:provider-b.example ~include:provider-a.example');

  await expect(page.locator('#spf-safety-notice')).toContainText('Before (imported)');
  await expect(page.locator('#spf-safety-notice')).toContainText('After (proposed)');
  await expect(page.locator('#spf-safety-notice')).toContainText('mechanism order changed');
  await expect(page.locator('#spf-builder-output .copy-btn')).toBeDisabled();
});

test('round-trips redirect-only SPF without inventing an all mechanism', async ({ page }) => {
  const record = 'v=spf1 redirect=_spf.example';
  await openBuilderWithRecord(page, record);

  await expect(page.locator('#spf-builder-output .dns-value')).toHaveText(record);
  await expect(page.locator('#spf-builder-output .dns-value')).not.toContainText('~all');
  await expect(page.locator('#spf-policy')).toHaveValue('');
  await expect(page.locator('#spf-builder-output .copy-btn')).toBeEnabled();
});

test('does not promote an unsafe SPF flattening preview into a copyable builder replacement', async ({ page }) => {
  const original = 'v=spf1 include:provider.example ~all';
  const unsafeFlattened = 'v=spf1 ip4:192.0.2.1 -all';

  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: async value => { window.__copiedSpf = value; } }
    });
  });

  await page.route('**/api/spf/inspect', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      domain: 'example.com',
      spf: { lookupCount: 2 },
      flatten: {
        available: true,
        safeToPublish: false,
        record: unsafeFlattened,
        originalRecord: original,
        originalLookups: 2,
        flattenedLookups: 1,
        characterCount: unsafeFlattened.length,
        sources: [{ source: 'example.com', mechanisms: ['include:provider.example'] }],
        warnings: ['Flattening requires manual review.'],
        validation: { valid: true, errors: [], warnings: [] }
      }
    })
  }));
  await page.route('**/api/records/validate', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ valid: true, errors: [], warnings: [], lookupCount: 1, characterCount: original.length })
  }));

  await page.goto('/#spf');
  await page.getByLabel('Domain whose SPF record should be inspected').fill('example.com');
  await page.getByRole('button', { name: 'Inspect SPF' }).click();

  await expect(page.locator('#spf-detail .dns-value').nth(1)).toHaveText(unsafeFlattened);
  await expect(page.locator('#spf-detail [data-copy="flattened"]')).toBeDisabled();
  await page.getByRole('button', { name: 'Use original in Record Builder' }).click();

  await expect(page.locator('#spf-builder-output .dns-value')).toHaveText(original);
  await expect(page.locator('#spf-builder-output .dns-value')).not.toHaveText(unsafeFlattened);
  const builderCopy = page.locator('#spf-builder-output .copy-btn');
  await expect(builderCopy).toBeEnabled();
  await builderCopy.click();
  await expect.poll(() => page.evaluate(() => window.__copiedSpf)).toBe(original);
  expect(await page.evaluate(() => window.__copiedSpf)).not.toBe(unsafeFlattened);
});

test('resets SPF change confirmation after every subsequent record change', async ({ page }) => {
  await openBuilderWithRecord(page, 'v=spf1 include:provider-a.example ~all');
  const copyButton = page.locator('#spf-builder-output .copy-btn');

  await page.locator('#spf-custom').fill('include:provider-b.example');
  await expect(copyButton).toBeDisabled();
  await page.locator('#spf-safety-confirm').check();
  await expect(copyButton).toBeEnabled();

  await page.locator('#spf-policy').selectOption('-all');
  await expect(page.locator('#spf-safety-confirm')).not.toBeChecked();
  await expect(copyButton).toBeDisabled();
  await expect(page.locator('#spf-safety-notice')).toContainText('Terminal policy changed');
});

test('an HTTP-error validation answer blocks copying in both builders', async ({ page }) => {
  // An oversized record body crosses the API's 16 KiB cap and is answered
  // with a bare {error} envelope; the builders must never read that as a
  // successful validation.
  await page.route('**/api/records/validate', route => route.fulfill({
    status: 413,
    contentType: 'application/json',
    body: JSON.stringify({ error: 'Request body exceeds the 16 KiB limit.' })
  }));

  await page.goto('/#builder');
  await page.locator('#builder-domain').fill('example.com');

  const spfCopy = page.locator('#spf-builder-output .copy-btn');
  await expect(spfCopy).toBeDisabled();
  await expect(spfCopy).toHaveText('Invalid record');
  const spfNotice = page.locator('#spf-builder-output .validation-result .notice');
  await expect(spfNotice).toContainText('Cannot copy this record');
  await expect(spfNotice).toContainText('16 KiB limit');
  await expect(page.locator('#spf-builder-output')).not.toContainText('Valid record');
  await expect(page.locator('#spf-builder-output')).not.toContainText('undefined');

  await page.getByRole('tab', { name: 'DMARC Planner' }).click();
  await page.locator('#dmarc-domain').fill('example.com');
  const dmarcCopy = page.locator('#dmarc-builder-output .copy-btn');
  await expect(dmarcCopy).toBeDisabled();
  await expect(dmarcCopy).toHaveText('Invalid record');
  await expect(page.locator('#dmarc-builder-output .validation-result .notice')).toContainText('Cannot copy this record');
});

test('an unreadable analysis answer reads as service trouble, never parser noise', async ({ page }) => {
  await page.route('**/api/header/analyze', route => route.fulfill({
    status: 502,
    contentType: 'text/html',
    body: '<!DOCTYPE html><html><body>bad gateway</body></html>'
  }));
  await page.goto('/#headers');
  await page.getByLabel('Complete message headers').fill(goodHeaders);
  await page.getByRole('button', { name: 'Analyze Headers' }).click();

  await expect(page.locator('#header-error')).toBeVisible();
  const msg = page.locator('#header-error-msg');
  await expect(msg).toContainText('unreadable');
  await expect(msg).not.toContainText('Unexpected');
});

test('hop enrichment also reports an unreadable service answer readably', async ({ page }) => {
  // Only enrichment is stubbed; analysis runs against the real local worker
  // so the Enrich Hops button enables from genuine parsed hops.
  await page.route('**/api/header/enrich', route => route.fulfill({
    status: 502,
    contentType: 'text/html',
    body: '<html>bad gateway</html>'
  }));
  await page.goto('/#headers');
  await page.getByLabel('Complete message headers').fill(goodHeaders);
  await page.getByRole('button', { name: 'Analyze Headers' }).click();
  const enrich = page.getByRole('button', { name: 'Enrich Hops' });
  await expect(enrich).toBeEnabled();
  await enrich.click();

  const msg = page.locator('#header-error-msg');
  await expect(msg).toContainText('unreadable');
  await expect(msg).not.toContainText('Unexpected');
});

test('domain, batch, and SPF panels describe an unreadable service answer instead of generic failure copy', async ({ page }) => {
  // The same edge/HTML-failure shape as the header panels, but on the three
  // handlers that used to swallow it into "Failed to …" catch-all copy.
  const htmlFailure = {
    status: 502,
    contentType: 'text/html',
    body: '<!DOCTYPE html><html><body>bad gateway</body></html>'
  };
  await page.route('**/api/check', route => route.fulfill(htmlFailure));
  await page.route('**/api/batch', route => route.fulfill(htmlFailure));
  await page.route('**/api/spf/inspect', route => route.fulfill(htmlFailure));

  await page.goto('/');
  await page.getByLabel('Domain to check').fill('example.com');
  await page.getByRole('button', { name: 'Check security' }).click();
  const domainMsg = page.locator('#domain-error-msg');
  await expect(domainMsg).toContainText('unreadable');
  await expect(domainMsg).not.toContainText('Unexpected');
  await expect(domainMsg).not.toContainText('Failed to analyze domain');

  await page.goto('/?fresh=batch#batch');
  await page.getByLabel('Domains (one per line, max 3)').fill('example.com');
  await page.getByRole('button', { name: 'Check All Domains' }).click();
  const batchMsg = page.locator('#batch-error-msg');
  await expect(batchMsg).toContainText('unreadable');
  await expect(batchMsg).not.toContainText('Unexpected');
  await expect(batchMsg).not.toContainText('Failed to run batch check');

  await page.goto('/?fresh=spf#spf');
  await page.getByLabel('Domain whose SPF record should be inspected').fill('example.com');
  await page.getByRole('button', { name: 'Inspect SPF' }).click();
  const spfMsg = page.locator('#spf-error-msg');
  await expect(spfMsg).toContainText('unreadable');
  await expect(spfMsg).not.toContainText('Unexpected');
  await expect(spfMsg).not.toContainText('Failed to inspect SPF');
});

test('a failed re-analysis keeps prior results and never strands a spinner', async ({ page }) => {
  // The header panel used to inject its spinner into #header-results and
  // only clear it on success: any failed paste left an eternal "Analyzing…"
  // animation and destroyed the previous analysis.
  await page.goto('/#headers');
  await page.getByLabel('Complete message headers').fill(goodHeaders);
  await page.getByRole('button', { name: 'Analyze Headers' }).click();
  await expect(page.locator('.trust-banner')).toContainText('All three methods reported pass');

  await page.route('**/api/header/analyze', route => route.fulfill({
    status: 502,
    contentType: 'text/html',
    body: '<!DOCTYPE html><html><body>bad gateway</body></html>'
  }));
  await page.getByRole('button', { name: 'Analyze Headers' }).click();

  await expect(page.locator('#header-error')).toBeVisible();
  await expect(page.locator('#header-error-msg')).toContainText('unreadable');
  await expect(page.locator('#header-loading')).toBeHidden();
  await expect(page.locator('#panel-headers .spinner')).not.toBeVisible();
  await expect(page.locator('.trust-banner')).toContainText('All three methods reported pass');
});

test('clearing the batch during a delayed response does not resurrect the report', async ({ page }) => {
  const batchReport = {
    results: [{
      domain: 'example.com', overall_score: 80, overall_status: 'good',
      spf: { status: 'pass' }, dkim: { status: 'warn' }, dmarc: { status: 'pass' },
      mx: { status: 'pass' }, transport: { status: 'pass' },
      request_budget: { exhausted: false }
    }],
    validation: { rejected: [] },
    share: { available: false }
  };
  await page.route('**/api/batch', async route => {
    await new Promise(resolve => setTimeout(resolve, 400));
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(batchReport) });
  });

  await page.goto('/#batch');
  await page.getByLabel('Domains (one per line, max 3)').fill('example.com');
  await page.getByRole('button', { name: 'Check All Domains' }).click();
  await expect(page.locator('#batch-loading')).toBeVisible();
  await page.getByRole('button', { name: 'Clear' }).click();
  await expect(page.locator('#batch-report')).toBeHidden();

  // The answer arrives after the clear; it must stay discarded.
  await expect(page.locator('#batch-loading')).toBeHidden();
  await expect(page.locator('#batch-report')).toBeHidden();
  await expect(page.locator('#batch-table')).not.toContainText('example.com');
  await expect(page.locator('#batch-error')).toBeHidden();
});

test('clearing during hop enrichment reports nothing and throws no internal error', async ({ page }) => {
  // Clearing mid-enrichment used to dereference a nulled analysis and print
  // "Cannot read properties of null" in the alert panel.
  await page.route('**/api/header/enrich', async route => {
    await new Promise(resolve => setTimeout(resolve, 400));
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ enriched: [{ ip: '8.8.8.8', ptr: 'dns.google' }], limit: 10 })
    });
  });
  await page.goto('/#headers');
  await page.getByLabel('Complete message headers').fill(goodHeaders);
  await page.getByRole('button', { name: 'Analyze Headers' }).click();
  const enrich = page.getByRole('button', { name: 'Enrich Hops' });
  await expect(enrich).toBeEnabled();
  await enrich.click();
  await page.getByRole('button', { name: 'Clear' }).click();

  await expect(enrich).toBeDisabled();
  await expect(page.locator('#header-error')).toBeHidden();
  await expect(page.locator('#header-error-msg')).not.toContainText('Cannot read properties');
  await expect(page.locator('#header-results')).not.toContainText('dns.google');
});

test('re-triggering SPF inspection from a report sends exactly one request', async ({ page }) => {
  // "Inspect SPF" calls requestSubmit(), which ignores the disabled submit
  // button; duplicate activations used to fire racing inspections. Drive
  // extra synthetic submits inside the flight window: only the first may
  // reach the network.
  let inspectRequests = 0;
  await page.route('**/api/check', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(domainReport('v=spf1 ip4:192.0.2.1 -all'))
  }));
  await page.route('**/api/spf/inspect', async route => {
    inspectRequests++;
    await new Promise(resolve => setTimeout(resolve, 600));
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        domain: 'example.com',
        spf: {
          status: 'pass', record: 'v=spf1 ip4:192.0.2.1 -all',
          checks: [{ status: 'pass', title: 'Hard fail (-all)', detail: 'ok', recommendation: '' }],
          mechanisms: []
        },
        flatten: {
          available: true, safeToPublish: false,
          record: 'v=spf1 ip4:192.0.2.1 -all', originalRecord: 'v=spf1 ip4:192.0.2.1 -all',
          originalLookups: 1, flattenedLookups: 1, characterCount: 24,
          sources: [{ source: 'example.com', mechanisms: [] }],
          warnings: [], validation: { errors: [] },
          equivalence: { proven: false }
        }
      })
    });
  });

  await page.goto('/');
  await page.getByLabel('Domain to check').fill('example.com');
  await page.getByRole('button', { name: 'Check security' }).click();
  await expect(page.locator('#domain-report')).toBeVisible();
  await page.getByRole('button', { name: 'Inspect SPF' }).first().click();
  await expect(page.locator('#spf-loading')).toBeVisible();

  await page.evaluate(() => {
    document.querySelector('#spf-form').requestSubmit();
    document.querySelector('#spf-form').requestSubmit();
  });
  await page.waitForTimeout(100);
  await expect.poll(() => inspectRequests).toBe(1);

  await expect(page.locator('#spf-report')).toBeVisible({ timeout: 5_000 });
  await expect.poll(() => inspectRequests, { timeout: 2_000 }).toBe(1);
});

test('pasting a share link into an open tab loads the report without a reload', async ({ page }) => {
  const report = domainReport('v=spf1 -all');
  report.id = '1234567890abcdef';
  await page.route('**/api/reports/1234567890abcdef', route => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(report)
  }));

  let loads = 0;
  await page.goto('/');
  await page.evaluate(() => {
    window.__reloadGuard = true;
  });
  page.on('load', () => { loads++; });

  await page.evaluate(() => { location.hash = '#1234567890abcdef'; });
  await expect(page.locator('#domain-report')).toBeVisible();
  await expect(page.locator('#report-domain')).toHaveText('example.com');
  // Same-document navigation must not reload the page.
  await page.waitForTimeout(200);
  expect(await page.evaluate(() => window.__reloadGuard)).toBe(true);
  expect(loads).toBe(0);

  // A batch-prefixed link routes to the batch panel from the live tab too.
  const batch = { _reportType: 'batch', id: 'abcdef1234567890', domains: ['example.com'], results: [{ domain: 'example.com', overall_score: 80, overall_status: 'good', spf: { status: 'pass' }, dkim: { status: 'warn' }, dmarc: { status: 'warn' }, mx: { status: 'pass' }, transport: { status: 'info' } }], created_at: '2026-08-14T00:00:00.000Z', share: { available: false } };
  await page.route('**/api/reports/abcdef1234567890', route => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(batch)
  }));
  await page.evaluate(() => { location.hash = '#batch-abcdef1234567890'; });
  await expect(page.locator('#batch-report')).toBeVisible();
  await expect(page.locator('#batch-table')).toContainText('example.com');
});

test('an empty batch submit explains itself instead of silently doing nothing', async ({ page }) => {
  await page.goto('/#batch');
  await page.getByRole('button', { name: 'Check All Domains' }).click();
  await expect(page.locator('#batch-error')).toBeVisible();
  await expect(page.locator('#batch-error-msg')).toContainText('at least one domain');
});

test('a drifted SPF inspection degrades to readable copy instead of a TypeError', async ({ page }) => {
  // The flatten payload is network data; missing sources, missing warnings,
  // and string counts must render as unavailable evidence, never surface the
  // parser's error text in the alert panel.
  await page.route('**/api/spf/inspect', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      domain: 'example.com',
      spf: { status: 'pass', lookupCount: 'two' },
      flatten: {
        available: true,
        safeToPublish: false,
        record: 'v=spf1 -all',
        originalRecord: 'v=spf1 -all'
        // sources, warnings, validation, flattenedLookups, characterCount all absent.
      }
    })
  }));

  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/#spf');
  await page.getByLabel('Domain whose SPF record should be inspected').fill('example.com');
  await page.getByRole('button', { name: 'Inspect SPF' }).click();

  const summary = page.locator('#spf-summary');
  await expect(summary).toContainText('unavailable');
  await expect(summary).not.toContainText('undefined');
  await expect(page.locator('#spf-error')).toBeHidden();
  await expect(page.locator('#spf-error-msg')).not.toContainText('Cannot read properties');
  await expect(page.locator('#spf-detail')).toContainText('Review required');
  expect(errors).toEqual([]);
});

test('a batch-row click during an active domain check queues instead of dropping', async ({ page }) => {
  // The row button seeds #domain-input programmatically, which fires no input
  // event; the older request must drain and the newer one must still run and
  // render under its own domain rather than being silently discarded.
  const requests = [];
  let releaseFirst;
  const firstGate = new Promise(resolve => { releaseFirst = resolve; });
  await page.route('**/api/check', async route => {
    const body = JSON.parse(route.request().postData());
    requests.push(body.domain);
    if (requests.length === 1) await firstGate;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ...domainReport('v=spf1 -all'), domain: body.domain })
    });
  });
  await page.route('**/api/batch', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      _reportType: 'batch',
      domains: ['slow.example', 'fast.example'],
      results: [
        { domain: 'slow.example', overall_score: 50, overall_status: 'fair', spf: { status: 'pass' }, dkim: { status: 'info' }, dmarc: { status: 'info' }, mx: { status: 'info' }, transport: { status: 'info' } },
        { domain: 'fast.example', overall_score: 60, overall_status: 'fair', spf: { status: 'pass' }, dkim: { status: 'info' }, dmarc: { status: 'info' }, mx: { status: 'info' }, transport: { status: 'info' } }
      ],
      created_at: '2026-08-23T00:00:00.000Z',
      validation: { accepted: ['slow.example', 'fast.example'], rejected: [] },
      share: { available: false }
    })
  }));

  await page.goto('/#batch');
  await page.getByLabel('Domains (one per line, max 3)').fill('slow.example\nfast.example');
  await page.getByRole('button', { name: 'Check All Domains' }).click();
  await expect(page.locator('#batch-table')).toBeVisible();

  // Start a slow check, return to the batch table, then click the
  // fast.example row while the first check is still in flight.
  await page.locator('.batch-domain-button', { hasText: 'slow.example' }).click();
  await expect(page.locator('#domain-loading')).toBeVisible();
  await page.getByRole('tab', { name: 'Batch Check' }).click();
  await page.locator('.batch-domain-button', { hasText: 'fast.example' }).click();

  releaseFirst();
  await expect(page.locator('#report-domain')).toHaveText('fast.example');
  await expect(page.locator('#domain-input')).toHaveValue('fast.example');
  await expect.poll(() => requests).toEqual(['slow.example', 'fast.example']);
});
