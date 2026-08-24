// Pure boundary validators shared by every surface: domain acceptance and
// normalization, public-IP admission, quota identity, and the daily reset
// countdown. No I/O, no worker runtime dependencies — unit-testable as-is.
const ipaddr = require('ipaddr.js');

function isValidDomain(domain) {
  const value = String(domain || '');
  if (!value || value.length > 253 || value.includes('..') || ipaddr.isValid(value)) return false;
  const labels = value.split('.');
  if (labels.length < 2) return false;
  return labels.every((label, index) =>
    label.length >= 1 && label.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label) &&
    (index !== labels.length - 1 || /^[a-z0-9-]{2,63}$/i.test(label))
  );
}

function normalizeDomain(value) {
  if (typeof value !== 'string') return '';
  let input = value.trim();
  if (!input || /[\s@?#]/.test(input)) return '';
  if (/^https?:\/\//i.test(input)) {
    try {
      const parsed = new URL(input);
      if (parsed.username || parsed.password || parsed.port || parsed.pathname !== '/' || parsed.search || parsed.hash) return '';
      input = parsed.hostname;
    } catch {
      return '';
    }
  }
  if (input.includes('/') || input.includes(':')) return '';
  input = input.toLowerCase().replace(/\.$/, '');
  return isValidDomain(input) ? input : '';
}

function isPublicIpAddress(ip) {
  try {
    return ipaddr.parse(String(ip)).range() === 'unicast';
  } catch {
    return false;
  }
}

// Daily counters reset at UTC midnight; a Retry-After that names the real
// wait is honest near midnight where a flat 86400 overshoots by hours.
function secondsUntilDailyReset() {
  const now = new Date();
  const next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
  return Math.max(1, Math.ceil((next.getTime() - now.getTime()) / 1000));
}

// Quota identity must be as stable as the client is: an IPv6 user controls
// a whole /64 and can otherwise mint fresh per-minute and daily counters by
// rotating addresses within it. Accounting keys normalize IPv6 to its /64
// while full precision stays in logs; IPv4 spellings are canonicalized so
// leading zeros cannot fragment one host across several buckets.
function quotaClientKey(rawIp) {
  const value = String(rawIp || '').trim();
  try {
    const parsed = ipaddr.parse(value);
    if (parsed.kind() === 'ipv6') {
      const prefixParts = parsed.parts.slice(0, 4).concat([0, 0, 0, 0]);
      return new ipaddr.IPv6(prefixParts).toNormalizedString() + '/64';
    }
    return parsed.toString();
  } catch {
    return value;
  }
}

module.exports = {
  isPublicIpAddress,
  isValidDomain,
  normalizeDomain,
  quotaClientKey,
  secondsUntilDailyReset
};
