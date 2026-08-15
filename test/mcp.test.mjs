import assert from 'node:assert/strict';
import { test } from 'node:test';
import mcp from '../mcp.js';

const { handleMcp } = mcp;

function rpcRequest(method, params = {}, id = 1) {
  return new Request('https://email.illek.ie/mcp/v2', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
  });
}

test('email MCP negotiates Streamable HTTP and publishes every backend capability', async () => {
  const initialized = await handleMcp(rpcRequest('initialize', { protocolVersion: '2025-11-25' }), async () => ({}));
  assert.equal(initialized.status, 200);
  assert.equal(initialized.headers.get('MCP-Protocol-Version'), '2025-11-25');
  const initBody = await initialized.json();
  assert.equal(initBody.result.serverInfo.version, '2.0.0');

  const listed = await handleMcp(rpcRequest('tools/list'), async () => ({}));
  const listBody = await listed.json();
  assert.deepEqual(listBody.result.tools.map(tool => tool.name), [
    'analyze_email_domain', 'analyze_email_headers', 'analyze_email_domains_batch',
    'inspect_spf', 'evaluate_spf', 'validate_email_record', 'build_email_record', 'enrich_email_hops',
    'get_email_security_report'
  ]);
  assert.ok(listBody.result.tools.every(tool => tool.inputSchema && tool.outputSchema));
});

test('email MCP returns structured tool output', async () => {
  let call;
  const response = await handleMcp(rpcRequest('tools/call', {
    name: 'analyze_email_domain', arguments: { domain: 'example.com' }
  }), async (name, args) => {
    call = { name, args };
    return { domain: args.domain, overall_score: 90 };
  });
  const body = await response.json();
  assert.deepEqual(call, { name: 'analyze_email_domain', args: { domain: 'example.com' } });
  assert.equal(body.result.structuredContent.overall_score, 90);
  assert.equal(body.result.isError, false);
});

test('email MCP accepts notifications and rejects its optional GET stream', async () => {
  const notification = await handleMcp(rpcRequest('notifications/initialized', {}, undefined), async () => ({}));
  assert.equal(notification.status, 202);
  const get = await handleMcp(new Request('https://email.illek.ie/mcp'), async () => ({}));
  assert.equal(get.status, 405);
  assert.equal(get.headers.get('x-content-type-options'), 'nosniff');
});

test('email MCP negotiates supported versions and rejects unsupported Accept/version headers', async () => {
  const older = await handleMcp(rpcRequest('initialize', { protocolVersion: '2025-06-18' }), async () => ({}));
  assert.equal(older.status, 200);
  assert.equal((await older.json()).result.protocolVersion, '2025-06-18');

  const unsupported = await handleMcp(rpcRequest('initialize', { protocolVersion: '1999-01-01' }), async () => ({}));
  assert.equal(unsupported.status, 200);
  assert.equal((await unsupported.json()).error.code, -32602);

  const badAccept = new Request('https://email.illek.ie/mcp/v2', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' })
  });
  assert.equal((await handleMcp(badAccept, async () => ({}))).status, 406);
});
