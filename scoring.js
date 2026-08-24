// Pure scoring helpers shared by the Worker and its unit tests.
// calculateScore maps per-control evidence onto the 0-100 posture score;
// estimateDkimKeyBits reads key strength from a DKIM p= value.

const { parseTagRecord } = require('./policy-tags');

// Confirmed evidence earns its points even when other probes in the same
// category were inconclusive: unknown_controls carries the incompleteness
// and score_confidence drops, so zeroing evidence in hand would punish
// transient DNS trouble as if the control were missing.
function calculateScore(spf, dkim, dmarc, mx, caa, transport, ptr) {
  let score = 0;
  const unknown = [];
  if (spf.unknown || spf.status === 'info') unknown.push('spf');
  if (dkim.unknown || dkim.status === 'info') unknown.push('dkim');
  if (dmarc.unknown || dmarc.status === 'info') unknown.push('dmarc');
  if (mx.unknown || mx.status === 'info' && mx.records?.length === 0 && mx.checks?.some(check => /inconclusive/i.test(check.title))) unknown.push('mx');
  if (caa.unknown) unknown.push('caa');
  if (transport?.unknown) unknown.push('transport');
  // PTR is an unscored observation, but an inconclusive one still means the
  // evidence set was not fully gathered; it belongs in the disclosure list
  // like every other control rather than leaving confidence at high.
  if (ptr?.unknown) unknown.push('ptr');

  // SPF: 0-25. A conventional ~all policy is a modest deduction, not a
  // category-level failure; structural errors remain heavily penalised.
  if (spf.status === 'pass' && !spf.unknown) {
    score += 25;
  } else if (spf.status === 'warn' && !spf.unknown) {
    // Covers both a local ~all and one reached through a redirect target.
    const softFailOnly = spf.checks?.some(c => c.title.startsWith('Soft fail')) &&
      !spf.checks.some(c => c.status === 'fail');
    score += softFailOnly ? 21 : 18;
  }

  // DKIM: 0-25. Selector discovery is best-effort, so an undiscovered selector
  // is unknown rather than proof that DKIM is disabled. One active key earns
  // most points even when another selector is weak, testing, or retired —
  // including when the scan stopped early (partial DNS or budget exhaustion):
  // keys already confirmed are evidence in hand, and the partial scan is
  // disclosed through unknown_controls instead of a silent 25-point swing
  // between two runs minutes apart.
  const usableDkimKeys = (dkim.selectors || []).filter(result => {
    const tags = parseTagRecord(result.record || '');
    return Boolean(tags.p && tags.p.trim());
  }).length;
  if (usableDkimKeys) {
    const hasWeakKey = dkim.checks?.some(c =>
      c.status === 'warn' &&
      (c.title.includes('uses RSA') || c.title.includes('test mode'))
    );
    score += hasWeakKey ? 20 : 25;
  } else if (dkim.status === 'warn' && !dkim.unknown) {
    score += 10;
  }

  // DMARC: 0-35
  if (dmarc.status === 'pass' && !dmarc.unknown) {
    score += dmarc.policy === 'reject' ? 35 : 30;
  } else if (dmarc.status === 'warn' && !dmarc.unknown) score += 15;

  // MX: 0-8
  if (mx.status === 'pass' && !mx.unknown) score += 8;

  // CAA: 0-2. Useful certificate protection, but not email authentication.
  if (caa.status === 'pass' && !caa.unknown) score += 2;

  // MTA-STS/TLS-RPT: 0-5. A fetched enforce/testing policy with covered MX is
  // evidence in hand; TLS-RPT lookup trouble must not erase it, matching the
  // definitive-absence path (TLS-RPT nodata) that already earns these points.
  if (transport?.status === 'pass') score += 5;
  else if (transport?.status === 'warn') score += 2;

  let status;
  if (score >= 85) status = 'excellent';
  else if (score >= 70) status = 'good';
  else if (score >= 50) status = 'fair';
  else status = 'poor';

  const confidence = unknown.length === 0 ? 'high' : unknown.length <= 2 ? 'medium' : 'low';
  return { score, status, confidence, unknown: [...new Set(unknown)] };
}

// Reads the exact RSA modulus bit length from a DKIM p= value holding a DER
// SubjectPublicKeyInfo. Length-band guessing misclassified real keys (a
// 1536-bit SPKI reads longer than 1024's band but shorter than 2048's), so
// the wrapper is parsed instead; anything that does not decode as an RSA
// key answers null rather than a plausible wrong number.
function rsaModulusBits(spkiBase64) {
  try {
    const der = Buffer.from(String(spkiBase64 || ''), 'base64');
    let offset = 0;
    // Reads one DER element and leaves `offset` at its next sibling. Children
    // of a container are visited by resetting `offset` to the container's
    // own start afterwards.
    const readElement = () => {
      if (offset >= der.length) throw new RangeError('truncated');
      const tag = der[offset++];
      let length = der[offset++];
      if (length & 0x80) {
        const count = length & 0x7f;
        if (!count || count > 4 || offset + count > der.length) throw new RangeError('bad length');
        length = 0;
        for (let index = 0; index < count; index++) length = length * 256 + der[offset++];
      }
      const start = offset;
      const end = start + length;
      if (end > der.length) throw new RangeError('overrun');
      offset = end;
      return { tag, start, end };
    };
    // SPKI ::= SEQUENCE { AlgorithmIdentifier, subjectPublicKey BIT STRING }
    const spki = readElement();
    offset = spki.start; // descend into the wrapper's children
    readElement();
    const bitString = readElement();
    if (bitString.tag !== 0x03 || bitString.end - bitString.start < 2) return null;
    offset = bitString.start + 1; // step over the unused-bits count byte
    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    const key = readElement();
    if (key.tag !== 0x30) return null;
    offset = key.start;
    const modulus = readElement();
    if (modulus.tag !== 0x02 || modulus.end <= modulus.start) return null;
    // A DER positive INTEGER may carry a leading 0x00 padding byte; otherwise
    // the first byte's leading zero bits are not part of the number.
    let bytes = modulus.end - modulus.start;
    const first = der[modulus.start];
    if (first === 0) {
      bytes -= 1;
    } else {
      bytes -= (Math.clz32(first) - 24) / 8;
    }
    return bytes > 0 ? Math.round(bytes * 8) : null;
  } catch {
    return null;
  }
}

function estimateDkimKeyBits(publicKey) {
  const clean = String(publicKey || '').replace(/[^a-z0-9+/=]/gi, '');
  if (!clean) return null;
  return rsaModulusBits(clean);
}

module.exports = {
  calculateScore,
  estimateDkimKeyBits
};
