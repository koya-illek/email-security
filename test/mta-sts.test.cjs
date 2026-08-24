const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const {
  isValidMtaStsMxPattern,
  mtaStsMxMatches,
  parsePolicyLines
} = require('../mta-sts');

describe('mtaStsMxMatches', () => {
  it('matches a wildcard against exactly one extra label (RFC 8461 §4.1)', () => {
    assert.equal(mtaStsMxMatches('mail.example.com', '*.example.com'), true);
  });

  it('does not let a wildcard swallow multi-label subdomains', () => {
    // RFC 8461 §4.1 names foo.bar.example.com explicitly as NOT matched by
    // *.example.com; the previous endsWith check blessed mail-loss configs.
    assert.equal(mtaStsMxMatches('foo.bar.example.com', '*.example.com'), false);
    assert.equal(mtaStsMxMatches('a.b.c.example.com', '*.example.com'), false);
  });

  it('never matches the bare domain itself through a wildcard', () => {
    assert.equal(mtaStsMxMatches('example.com', '*.example.com'), false);
  });

  it('requires a non-empty label before the wildcard suffix', () => {
    assert.equal(mtaStsMxMatches('.example.com', '*.example.com'), false);
  });

  it('matches plain patterns exactly, ignoring one trailing dot on either side', () => {
    assert.equal(mtaStsMxMatches('mx1.example.com', 'mx1.example.com'), true);
    assert.equal(mtaStsMxMatches('mx1.example.com.', 'mx1.example.com'), true);
    assert.equal(mtaStsMxMatches('mx1.example.com', 'mx2.example.com'), false);
    assert.equal(mtaStsMxMatches('other.example.com', 'example.com'), false);
  });
});

describe('isValidMtaStsMxPattern', () => {
  it('accepts plain hosts and single-wildcard labels', () => {
    assert.equal(isValidMtaStsMxPattern('mx1.example.com'), true);
    assert.equal(isValidMtaStsMxPattern('*.example.com'), true);
    assert.equal(isValidMtaStsMxPattern('Example.COM'), true);
  });

  it('rejects malformed shapes', () => {
    assert.equal(isValidMtaStsMxPattern('*..example.com'), false);
    assert.equal(isValidMtaStsMxPattern('mx1..example.com'), false);
    assert.equal(isValidMtaStsMxPattern('-mx1.example.com'), false);
    assert.equal(isValidMtaStsMxPattern(''), false);
  });
});

describe('parsePolicyLines', () => {
  it('parses colon and equals forms into tags', () => {
    const tags = parsePolicyLines('version: STSv1\nmode: enforce\nmx: *.example.com\nmx: mx1.example.com\nmax_age=604800');
    assert.equal(tags.version, 'STSv1');
    assert.equal(tags.mode, 'enforce');
    assert.deepEqual(tags.mx, ['*.example.com', 'mx1.example.com']);
    assert.equal(tags.max_age, '604800');
  });

  it('ignores comments, blanks, and malformed lines', () => {
    const tags = parsePolicyLines('# comment\n\nno-separator-here\nversion: STSv1');
    assert.equal(tags.version, 'STSv1');
    assert.equal(tags['no-separator-here'], undefined);
  });
});
