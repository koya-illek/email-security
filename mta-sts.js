// Pure MTA-STS policy helpers shared by the Worker and its unit tests.
// Kept free of runtime dependencies so Node can load the file directly.

// Parses "key: value" / "key=value" lines from an MTA-STS policy document.
// Repeated keys (mx:) collect into arrays; the colon form takes precedence
// only when no equals sign competes on the same line.
function parsePolicyLines(policy) {
  const tags = {};
  String(policy || '').split(/\r?\n/).forEach(line => {
    const clean = line.trim();
    if (!clean || clean.startsWith('#')) return;
    const idx = clean.indexOf(':') > -1 && clean.indexOf('=') === -1 ? clean.indexOf(':') : clean.indexOf('=');
    if (idx < 1) return;
    const key = clean.slice(0, idx).trim().toLowerCase().replace('-', '_');
    const value = clean.slice(idx + 1).trim();
    if (tags[key]) tags[key] = Array.isArray(tags[key]) ? [...tags[key], value] : [tags[key], value];
    else tags[key] = value;
  });
  return tags;
}

function isValidMtaStsMxPattern(value) {
  return /^(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(String(value || '')) && !String(value).includes('..');
}

// RFC 8461 §4.1: "the mx pattern '*.example.com' matches 'mail.example.com'
// but not 'example.com' or 'foo.bar.example.com'" — a wildcard expands to
// exactly one label, so the host prefix between the start and the suffix
// must be dot-free.
function mtaStsMxMatches(host, pattern) {
  const cleanHost = String(host || '').toLowerCase().replace(/\.$/, '');
  const cleanPattern = String(pattern || '').toLowerCase().replace(/\.$/, '');
  if (!cleanPattern.startsWith('*.')) return cleanHost === cleanPattern;
  const suffix = cleanPattern.slice(1);
  if (!cleanHost.endsWith(suffix)) return false;
  const prefix = cleanHost.slice(0, cleanHost.length - suffix.length);
  return prefix.length > 0 && !prefix.includes('.');
}

module.exports = {
  isValidMtaStsMxPattern,
  mtaStsMxMatches,
  parsePolicyLines
};
