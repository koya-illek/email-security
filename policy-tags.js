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
  // A QUALIFIED modifier ("+redirect=") matches no production at all —
  // receivers permerror before evaluating — so it consumes no lookup either.
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
      (clean.startsWith('redirect=') && !hasAll && !/^[+?~-]/.test(part))
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

// RFC 7208 §7 macro-expression: macro-letter, optional decimal transformers,
// optional "r", and optional delimiters. c/r/t exist only inside exp=
// explanation text (§7.3), never in a domain-spec.
function isValidSpfMacroExpression(expression, allowExplanationLetters) {
  const match = String(expression || '').match(/^([a-z])(\d*)(r?)([.\-+,/_=]*)$/i);
  if (!match) return false;
  const [, letter, digits, , ] = match;
  const letters = allowExplanationLetters ? 'slodipvhcrt' : 'slodipvh';
  return letters.includes(letter.toLowerCase()) && digits.length <= 10;
}

// RFC 7208 §7: a domain-spec is plain visible characters, the escapes %% %_
// %-, or well-formed macro expressions. The previous character-class check
// admitted "%foo" and "%{k}" (k is not a macro letter) that receivers
// permerror.
function isValidSpfDomainSpec(value) {
  const source = String(value || '');
  if (!source || /\s/.test(source)) return false;
  let index = 0;
  while (index < source.length) {
    if (source[index] !== '%') {
      index += 1;
      continue;
    }
    const next = source[index + 1];
    if (next === '%' || next === '_' || next === '-') {
      index += 2;
      continue;
    }
    if (next === '{') {
      const close = source.indexOf('}', index + 2);
      if (close === -1) return false;
      if (!isValidSpfMacroExpression(source.slice(index + 2, close), false)) return false;
      index = close + 1;
      continue;
    }
    return false;
  }
  if (source.includes('%')) return true;
  // Label-wise plain domain: consecutive dots ("bad..example.com") are as
  // unacceptable here as they are everywhere else a domain enters this tool.
  if (source.length > 254) return false;
  return /^(?:[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)(?:\.(?:[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?))*\.?$/i.test(source);
}

// Modifier shape per RFC 7208 §6: name=value. A qualifier may only precede a
// mechanism — "+redirect=_x.example" matches no production, so receivers
// permerror the whole record instead of following the target.
function isSpfModifierShape(lowercasedTerm) {
  return /^[a-z][a-z0-9_.-]*=/.test(String(lowercasedTerm || ''));
}

// Grammar gate for one SPF term. Returns null when the term's shape is one
// receivers accept (value-level checks such as CIDR ranges stay with the
// callers), or a short reason they would reject it. Mirrors the validator's
// term table: all/ip4/ip6/include/a/mx/ptr/exists mechanisms plus
// unqualified name=value modifiers.
function spfTermSyntaxError(term) {
  const raw = String(term || '');
  if (!raw) return 'an empty term';
  const qualifier = /^[+?~-]/.test(raw) ? raw[0] : '';
  const body = qualifier ? raw.slice(1) : raw;
  const clean = body.toLowerCase();
  if (!clean) return 'a lone qualifier';
  if (isSpfModifierShape(clean)) {
    return qualifier
      ? `the ${qualifier} qualifier cannot precede the modifier "${body}" (RFC 7208 §6)`
      : null;
  }
  const mechanismShape = /^(?:(?:ip4:[0-9./]+)|(?:ip6:[0-9a-f:.]+(?:\/\d{1,3})?)|(?:include:\S+)|(?:exists:\S+)|(?:a(?::[^\s/]+)?(?:\/\d{1,3})?(?:\/\/\d{1,3})?)|(?:mx(?::[^\s/]+)?(?:\/\d{1,3})?(?:\/\/\d{1,3})?)|(?:ptr(?::\S+)?)|(?:all))$/;
  // NOTE: every alternative must live inside the single anchored group —
  // "^a|b$" would anchor only the first and last branches.
  if (!mechanismShape.test(clean)) return `"${raw}" matches no RFC 7208 mechanism or modifier`;
  return null;
}

// RFC 9989: when discovery finds the record at an ancestor policy
// domain, receivers apply its sp= value to this author domain when present,
// falling back to p=. Values are normalized here so the returned policy is
// always one of the lowercase literals the scorer and frontend compare
// against, whatever casing the published record used.
function effectiveDmarcPolicy(tags, inherited) {
  const sp = String(tags.sp || '').toLowerCase();
  if (inherited && DMARC_POLICY_VALUES.includes(sp)) return sp;
  return String(tags.p || '').toLowerCase() || null;
}

// Generic tag=value parser shared by DMARC records, DKIM signatures,
// MTA-STS/TLS-RPT records, and scoring's key inspection. Tag names are
// lowercased for lookup; values keep their original casing — a DKIM p=
// base64 payload is case-sensitive (lowercasing it silently corrupts the
// DER parse), and RFC 7489/8460 tag values are literal ABNF strings.
// Comparison sites normalize explicitly, exactly like validateDmarcRecord.
function parseTagRecord(record) {
  return Object.fromEntries(
    String(record || '')
      .split(';')
      .map(part => part.trim())
      .filter(Boolean)
      .map(part => {
        const idx = part.indexOf('=');
        return idx > 0 ? [part.slice(0, idx).trim().toLowerCase(), part.slice(idx + 1).trim()] : [part.toLowerCase(), ''];
      })
  );
}

// RFC 7208 §4.6.4 defines a void lookup as NXDOMAIN or an answer with no
// records of the queried type. A name publishing OTHER TXT records (site
// verification, DKIM at the apex, …) is NOT a void lookup: receivers treat
// an include with no SPF record as a plain no-match (§5.2) — though a
// REDIRECT to such a name still ends evaluation in permerror (§6.1).
// Callers must treat the two classes alike when judging redirects.
function missingSpfTargetClass(records) {
  if (records?.dnsStatus === 'ok' && records.length > 0) return 'empty';
  return 'void';
}

module.exports = {
  DMARC_POLICY_VALUES,
  isDmarcVersionRecord,
  parseTagRecord,
  stripSpfQualifier,
  spfTerminalTerm,
  countVisibleSpfLookups,
  hasSpfMacro,
  isValidSpfMacroExpression,
  isValidSpfDomainSpec,
  isSpfModifierShape,
  spfTermSyntaxError,
  missingSpfTargetClass,
  effectiveDmarcPolicy
};
