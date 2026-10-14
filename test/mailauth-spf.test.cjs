'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const { spf } = require('mailauth/lib/spf');
const { publicSpfEvaluation } = require('../policy-tags');

function resolverFor(records) {
  return async (domain, type) => {
    const name = String(domain || '').toLowerCase().replace(/\.$/, '');
    const row = records[name];
    if (type === 'TXT' && row) return [[row]];
    const err = new Error('none');
    err.code = 'ENOTFOUND';
    throw err;
  };
}

function evaluate(record, ip, extra = {}) {
  return spf({
    ip,
    sender: extra.sender || 'sender@fixture.example',
    helo: 'helo.fixture.example',
    mta: 'email-security-checker',
    resolver: resolverFor({
      'fixture.example': record,
      ...(extra.txt || {})
    }),
    maxResolveCount: 10,
    maxVoidCount: 2
  });
}

describe('mailauth 7.1.1 SPF results this app returns', () => {
  it('keeps a clean pass free of warnings and explanation', async () => {
    const result = publicSpfEvaluation(await evaluate('v=spf1 ip4:192.0.2.0/24 -all', '192.0.2.44'));
    assert.equal(result.status.result, 'pass');
    assert.equal(result.warnings, undefined);
    assert.equal(result.explanation, undefined);
    assert.equal(result.pct, undefined);
    assert.match(result.header, /envelope-from="sender@fixture\.example"/);
    assert.match(result.header, /helo=helo\.fixture\.example/);
    assert.match(result.info, /^spf=pass /);
  });

  it('warns when leading whitespace is the only reason the record was selected', async () => {
    const result = publicSpfEvaluation(await evaluate(' v=spf1 ip4:192.0.2.1 -all', '192.0.2.1'));
    assert.equal(result.status.result, 'pass');
    assert.deepEqual(result.warnings, ['syntax-error']);
  });

  it('warns when a syntax error sits after the matching term', async () => {
    const result = publicSpfEvaluation(await evaluate('v=spf1 ip4:192.0.2.1 -all ip4:not-an-ip', '192.0.2.1'));
    assert.equal(result.status.result, 'pass');
    assert.deepEqual(result.warnings, ['syntax-error']);
  });

  it('returns the published explanation only for a fail', async () => {
    const result = publicSpfEvaluation(await evaluate('v=spf1 -all exp=explain.fixture.example', '198.51.100.7', {
      txt: { 'explain.fixture.example': 'Connections from %{i} not authorized.' }
    }));
    assert.equal(result.status.result, 'fail');
    assert.equal(result.explanation, 'Connections from 198.51.100.7 not authorized.');
    assert.equal(result.warnings, undefined);
  });

  it('treats an unparseable client IP as temperror', async () => {
    const result = publicSpfEvaluation(await evaluate('v=spf1 -all', 'not-an-ip'));
    assert.equal(result.status.result, 'temperror');
    assert.match(result.status.comment, /invalid client IP address/);
    assert.equal(result.explanation, undefined);
  });

  it('does not attach warnings to a permerror', async () => {
    const result = publicSpfEvaluation(await evaluate('v=spf1 madeup:example.test -all', '192.0.2.1'));
    assert.equal(result.status.result, 'permerror');
    assert.equal(result.warnings, undefined);
  });
});
