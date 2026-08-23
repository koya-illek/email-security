// Pure SPF/DMARC policy helpers shared by the Worker and its unit tests.
// Kept free of runtime dependencies so Node can load the file directly.

const DMARC_POLICY_VALUES = ['none', 'quarantine', 'reject'];

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

// RFC 7489 §6.6.3: when discovery finds the record at an ancestor policy
// domain, receivers apply its sp= value to this author domain when present,
// falling back to p=. Scoring a subdomain by the parent's p= would report
// enforcement that does not exist (for example p=reject; sp=none parents).
function effectiveDmarcPolicy(tags, inherited) {
  if (inherited && DMARC_POLICY_VALUES.includes(tags.sp)) return tags.sp;
  return tags.p || null;
}

module.exports = {
  DMARC_POLICY_VALUES,
  stripSpfQualifier,
  spfTerminalTerm,
  countVisibleSpfLookups,
  hasSpfMacro,
  effectiveDmarcPolicy
};
