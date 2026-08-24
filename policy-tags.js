// Pure SPF/DMARC policy helpers shared by the Worker and its unit tests.
// Kept free of runtime dependencies so Node can load the file directly.

const DMARC_POLICY_VALUES = ['none', 'quarantine', 'reject'];

// RFC 9989 section 4.8 allows whitespace around the first v= tag but makes
// the DMARC1 value case-sensitive. A case-insensitive whole-record regex
// accepts records that receivers must ignore.
function isDmarcVersionRecord(record) {
  return /^\s*[vV]\s*=\s*DMARC1(?:\s*;|\s*$)/.test(String(record || ''));
}

function stripSpfQualifier(part) {
  return String(part || '').replace(/^[+?~-]/, '').toLowerCase();
}

function spfTerminalTerm(term) {
  const clean = stripSpfQualifier(term);
  return clean === 'all' ? String(term || '').toLowerCase() : null;
}

function countVisibleSpfLookups(mechanisms) {
  // RFC 7208 §6.1: redirect is ignored when an all mechanism is present, so
  // it consumes no evaluation lookup and must not count toward the limit.
  const hasAll = mechanisms.some(part => stripSpfQualifier(part) === 'all');
  return mechanisms.reduce((count, part) => {
    const clean = stripSpfQualifier(part);
    if (
      clean === 'a' ||
      clean.startsWith('a:') ||
      clean.startsWith('a/') ||
      clean === 'mx' ||
      clean.startsWith('mx:') ||
      clean.startsWith('mx/') ||
      clean === 'ptr' ||
      clean.startsWith('ptr:') ||
      clean.startsWith('include:') ||
      clean.startsWith('exists:') ||
      (clean.startsWith('redirect=') && !hasAll)
    ) {
      return count + 1;
    }
    return count;
  }, 0);
}

// Sender macros (%{d}, %{i}, …) resolve per message, so their targets cannot
// be confirmed by a static TXT query; querying them literally would only
// produce false void-lookup verdicts.
function hasSpfMacro(value) {
  return /%\{[^}]*\}/.test(String(value || ''));
}

// RFC 9989: when discovery finds the record at an ancestor policy
// domain, receivers apply its sp= value to this author domain when present,
// falling back to p=. Scoring a subdomain by the parent's p= would report
// enforcement that does not exist (for example p=reject; sp=none parents).
function effectiveDmarcPolicy(tags, inherited) {
  if (inherited && DMARC_POLICY_VALUES.includes(tags.sp)) return tags.sp;
  return tags.p || null;
}

// Generic lowercase tag=value parser shared by DMARC records, DKIM
// signatures, MTA-STS/TLS-RPT records, and scoring's key inspection.
function parseTagRecord(record) {
  return Object.fromEntries(
    String(record || '')
      .split(';')
      .map(part => part.trim())
      .filter(Boolean)
      .map(part => {
        const idx = part.indexOf('=');
        return idx > 0 ? [part.slice(0, idx).trim().toLowerCase(), part.slice(idx + 1).trim().toLowerCase()] : [part.toLowerCase(), ''];
      })
  );
}

module.exports = {
  DMARC_POLICY_VALUES,
  isDmarcVersionRecord,
  parseTagRecord,
  stripSpfQualifier,
  spfTerminalTerm,
  countVisibleSpfLookups,
  hasSpfMacro,
  effectiveDmarcPolicy
};
