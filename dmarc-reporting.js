const { getDomain } = require('tldts');
const { isDmarcVersionRecord } = require('./policy-tags');

const DEFINITIVE_DNS_STATES = new Set(['ok', 'nodata', 'nxdomain']);

function organisationalDomain(domain) {
  const clean = String(domain || '').trim().toLowerCase().replace(/\.$/, '');
  return getDomain(clean, { allowPrivateDomains: true }) || clean;
}

function reportDestinationDomain(address) {
  return String(address || '').trim().split('@').pop()?.toLowerCase().replace(/\.$/, '') || '';
}

function isExternalReportDestination(policyDomain, address) {
  const destination = reportDestinationDomain(address);
  return Boolean(destination) && organisationalDomain(destination) !== organisationalDomain(policyDomain);
}

function reportAuthorisationName(policyDomain, address) {
  return `${String(policyDomain || '').toLowerCase()}._report._dmarc.${reportDestinationDomain(address)}`;
}

function assessReportAuthorisation(policyDomain, address, records) {
  const dnsStatus = records?.dnsStatus || (records?.length ? 'ok' : 'nodata');
  const common = {
    address,
    destination: reportDestinationDomain(address),
    query: reportAuthorisationName(policyDomain, address),
    dnsStatus
  };
  if (!DEFINITIVE_DNS_STATES.has(dnsStatus)) return { ...common, status: 'unknown' };
  return records.some(isDmarcVersionRecord)
    ? { ...common, status: 'authorised' }
    : { ...common, status: 'unauthorised' };
}

module.exports = {
  assessReportAuthorisation,
  isExternalReportDestination,
  organisationalDomain,
  reportAuthorisationName,
  reportDestinationDomain
};
