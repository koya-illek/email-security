'use strict';

const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

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

test('a dead #batch- share link explains itself inside the batch panel', async ({ page }) => {
  await page.route('**/api/reports/dead0000dead0000', route => route.fulfill({
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
  await expect(scoreCell.locator('[title="Analysis failed unexpectedly"]')).toBeVisible();
  await expect(row).not.toContainText('Fail');
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
