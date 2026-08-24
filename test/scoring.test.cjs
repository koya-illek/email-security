const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const { generateKeyPairSync } = require('crypto');
const { calculateScore, estimateDkimKeyBits } = require('../scoring');

const baseCategories = {
  spf: { status: 'pass', unknown: false },
  dkim: { status: 'pass', unknown: false, selectors: [], checks: [] },
  dmarc: { status: 'pass', unknown: false, policy: 'reject' },
  mx: { status: 'pass', unknown: false },
  caa: { status: 'pass', unknown: false },
  transport: { status: 'pass', unknown: false },
  ptr: { unknown: false }
};

function categories(overrides) {
  const merged = { ...baseCategories };
  for (const [key, patch] of Object.entries(overrides)) {
    merged[key] = { ...baseCategories[key], ...patch };
  }
  return merged;
}

function spkiBase64(bits) {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: bits });
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
}

const strongDkim = () => ({
  status: 'pass',
  unknown: false,
  selectors: [{ selector: 'selector1', record: 'v=DKIM1; k=rsa; p=' + spkiBase64(2048) }],
  checks: []
});

describe('calculateScore', () => {
  it('scores a fully determinate strong posture at the maximum', () => {
    const cats = categories({ dkim: strongDkim() });
    const result = calculateScore(
      cats.spf, cats.dkim, cats.dmarc, cats.mx, cats.caa, cats.transport, cats.ptr
    );
    assert.equal(result.score, 100);
    assert.equal(result.status, 'excellent');
    assert.equal(result.confidence, 'high');
    assert.deepEqual(result.unknown, []);
  });

  it('awards DKIM key points even when the selector scan stopped early', () => {
    // A partial scan with one confirmed active key used to score 0 of 25:
    // evidence in hand was erased by DNS trouble elsewhere in the scan.
    const dkim = {
      status: 'pass',
      unknown: true,
      selectors: [{ selector: 'selector2', record: 'v=DKIM1; k=rsa; p=' + spkiBase64(2048) }],
      checks: []
    };
    const result = calculateScore(
      categories({}).spf, dkim, categories({}).dmarc,
      categories({}).mx, categories({}).caa, categories({}).transport, categories({}).ptr
    );
    assert.equal(result.score, 100);
    assert.ok(result.unknown.includes('dkim'), 'the partial scan stays disclosed');
    assert.equal(result.confidence, 'medium');
  });

  it('keeps the weak-key deduction when confirmed keys are weak despite an unknown scan', () => {
    const dkim = {
      status: 'warn',
      unknown: true,
      selectors: [{ selector: 's1', record: 'v=DKIM1; k=rsa; p=' + spkiBase64(1024) }],
      checks: [{ status: 'warn', title: 'Selector s1 uses RSA' }]
    };
    const result = calculateScore(
      categories({}).spf, dkim, categories({}).dmarc,
      categories({}).mx, categories({}).caa, categories({}).transport, categories({}).ptr
    );
    assert.equal(result.score, 95);
  });

  it('still scores zero DKIM points when no key was found and the scan warned', () => {
    const dkim = { status: 'warn', unknown: false, selectors: [], checks: [] };
    const result = calculateScore(
      categories({}).spf, dkim, categories({}).dmarc,
      categories({}).mx, categories({}).caa, categories({}).transport, categories({}).ptr
    );
    assert.equal(result.score, 85);
  });

  it('awards transport points for a fetched enforce policy even if TLS-RPT lookup was inconclusive', () => {
    // The definitive-absence path (TLS-RPT nodata) already earned these
    // points; transient lookup trouble must not erase fetched policy
    // evidence either.
    const transport = { status: 'pass', unknown: true };
    const cats = categories({ dkim: strongDkim() });
    const result = calculateScore(
      cats.spf, cats.dkim, cats.dmarc, cats.mx, cats.caa, transport, cats.ptr
    );
    assert.equal(result.score, 100);
    assert.ok(result.unknown.includes('transport'));
  });

  it('discloses an inconclusive PTR observation in unknown_controls and confidence', () => {
    // PTR is unscored, but its inconclusiveness still means the evidence set
    // was not fully gathered; high confidence over an incomplete sweep was
    // misleading.
    const ptr = { unknown: true };
    const cats = categories({ dkim: strongDkim() });
    const result = calculateScore(
      cats.spf, cats.dkim, cats.dmarc, cats.mx, cats.caa, cats.transport, ptr
    );
    assert.equal(result.score, 100);
    assert.deepEqual(result.unknown, ['ptr']);
    assert.equal(result.confidence, 'medium');
  });
});

describe('estimateDkimKeyBits', () => {
  it('reads exact modulus sizes from generated RSA SPKIs', () => {
    assert.equal(estimateDkimKeyBits(spkiBase64(1024)), 1024);
    assert.equal(estimateDkimKeyBits(spkiBase64(1536)), 1536);
    assert.equal(estimateDkimKeyBits(spkiBase64(2048)), 2048);
    assert.equal(estimateDkimKeyBits(spkiBase64(3072)), 3072);
    assert.equal(estimateDkimKeyBits(spkiBase64(4096)), 4096);
  });

  it('answers null instead of a plausible wrong number for non-RSA payloads', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const ecSpki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    assert.equal(estimateDkimKeyBits(ecSpki), null);
    assert.equal(estimateDkimKeyBits('not-base64-!!!'), null);
    assert.equal(estimateDkimKeyBits(''), null);
    assert.equal(estimateDkimKeyBits(null), null);
  });

  it('tolerates whitespace inside the base64 payload like real TXT records ship it', () => {
    const key = spkiBase64(2048);
    const chunked = (key.match(/.{1,70}/g) || []).join('"  "');
    assert.equal(estimateDkimKeyBits(chunked), 2048);
  });
});
