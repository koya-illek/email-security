'use strict';

const { test, expect } = require('@playwright/test');

const goodHeaders = [
  'From: Example Billing <billing@example.com>',
  'Return-Path: <bounce@mail.example.com>',
  'Reply-To: support@example.com',
  'Authentication-Results: mx.receiver.example; spf=pass smtp.mailfrom=bounce@mail.example.com; dkim=pass header.d=mail.example.com; dmarc=pass header.from=example.com',
  'Received: from sender.example (sender.example [8.8.8.8]) by mx.receiver.example with ESMTPS; Thu, 23 Jul 2026 20:00:00 +0100'
].join('\r\n');

test('renders accurate reported-authentication feedback and accessible sections', async ({ page }) => {
  await page.goto('/#headers');
  await page.getByLabel('Complete message headers').fill(goodHeaders);
  await page.getByRole('button', { name: 'Analyze Headers' }).click();

  await expect(page.locator('.trust-banner')).toContainText('All three methods reported pass');
  await expect(page.locator('#headerResults')).toContainText('Reported by pasted headers');
  await expect(page.locator('#headerResults')).toContainText('Envelope sender relaxed alignment');
  await expect(page.locator('#headerResults')).toContainText('DKIM signing domain relaxed alignment');
  await expect(page.locator('#headerResults')).not.toContainText('does not align');

  const receivedButton = page.getByRole('button', { name: /Received Chain/ });
  await expect(receivedButton).toHaveAttribute('aria-expanded', 'false');
  await receivedButton.click();
  await expect(receivedButton).toHaveAttribute('aria-expanded', 'true');
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

  await expect(page.getByRole('button', { name: /Header Findings/ })).toContainText('warn');
  await expect(page.locator('#headerResults')).toContainText('Pasted headers can be forged or incomplete');
  await expect(page.locator('#headerResults')).toContainText('DKIM signing domain does not align');
  await expect(page.locator('#headerResults')).toContainText('No Received chain found');
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

test('exposes labelled inputs, keyboard tabs, metadata and privacy guidance', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle(/SPF, DKIM, DMARC/);
  await expect(page.locator('link[rel="canonical"]')).toHaveAttribute('href', 'https://email.illek.ie/');
  await expect(page.getByLabel('Domain to check')).toBeVisible();
  await page.getByRole('tab', { name: 'Check Domain' }).focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'SPF Inspector' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('link', { name: 'Privacy' })).toHaveAttribute('href', 'https://tools.illek.ie/privacy');
});
