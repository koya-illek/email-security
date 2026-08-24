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

test('email MCP accepts id-less notifications and rejects its optional GET stream', async () => {
  // A missing id makes the message a notification regardless of method name;
  // it is acknowledged with 202 and no body.
  const notification = new Request('https://email.illek.ie/mcp/v2', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
  });
  const accepted = await handleMcp(notification, async () => ({}));
  assert.equal(accepted.status, 202);
  const get = await handleMcp(new Request('https://email.illek.ie/mcp'), async () => ({}));
  assert.equal(get.status, 405);
  assert.equal(get.headers.get('x-content-type-options'), 'nosniff');
});

test('email MCP negotiates supported versions, downgrades unknown ones, and rejects unsupported Accept/version headers', async () => {
  const older = await handleMcp(rpcRequest('initialize', { protocolVersion: '2025-06-18' }), async () => ({}));
  assert.equal(older.status, 200);
  assert.equal((await older.json()).result.protocolVersion, '2025-06-18');

  // Lifecycle spec: a server that does not support the requested version
  // MUST reply with another version it supports so the client can negotiate
  // down. Hard-failing with -32602 used to strand future-versioned clients
  // that would happily have accepted an older revision.
  const future = await handleMcp(rpcRequest('initialize', { protocolVersion: '2999-01-01' }), async () => ({}));
  assert.equal(future.status, 200);
  const futureBody = await future.json();
  assert.equal(futureBody.result.protocolVersion, '2025-11-25');
  assert.equal(future.headers.get('MCP-Protocol-Version'), '2025-11-25');

  const badAccept = new Request('https://email.illek.ie/mcp/v2', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' })
  });
  assert.equal((await handleMcp(badAccept, async () => ({}))).status, 406);

  // A JSON-derived media type is still not the advertised one.
  const patchType = new Request('https://email.illek.ie/mcp/v2', {
    method: 'POST', headers: { 'Content-Type': 'application/json-patch+json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' })
  });
  assert.equal((await handleMcp(patchType, async () => ({}))).status, 415);

  // An unsupported MCP-Protocol-Version header on later requests MUST be
  // answered with HTTP 400 per the versioning spec.
  const staleHeader = new Request('https://email.illek.ie/mcp/v2', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '1999-01-01' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping' })
  });
  const staleResponse = await handleMcp(staleHeader, async () => ({}));
  assert.equal(staleResponse.status, 400);
  assert.equal((await staleResponse.json()).error.code, -32602);
});

test('unknown methods and tools answer distinct JSON-RPC errors', async () => {
  const unknownMethod = await handleMcp(rpcRequest('resources/list'), async () => ({}));
  const methodBody = await unknownMethod.json();
  assert.equal(methodBody.error.code, -32601);
  assert.match(methodBody.error.message, /resources\/list/);

  const unknownTool = await handleMcp(rpcRequest('tools/call', { name: 'no_such_tool', arguments: {} }), async () => ({}));
  const toolBody = await unknownTool.json();
  assert.equal(toolBody.error.code, -32602);
  assert.match(toolBody.error.message, /Unknown tool name: no_such_tool/);

  // A missing name must not render as the string "undefined".
  const missingName = await handleMcp(rpcRequest('tools/call', { arguments: {} }), async () => ({}));
  assert.match((await missingName.json()).error.message, /\(missing\)/);

  // ping stays a plain empty result.
  const ping = await handleMcp(rpcRequest('ping'), async () => ({}));
  const pingBody = await ping.json();
  assert.deepEqual(pingBody.result, {});
});

test('an unexpected tool fault answers an opaque isError result without engine text', async () => {
  const response = await handleMcp(rpcRequest('tools/call', {
    name: 'analyze_email_domain', arguments: { domain: 'example.com' }
  }), async () => {
    throw new TypeError('Cannot read properties of undefined (reading map)');
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.result.isError, true);
  assert.doesNotMatch(body.result.content[0].text, /TypeError|Cannot read properties/);
  assert.match(body.result.content[0].text, /failed internally \(\w{8}\)/);
  void body;
});

test('email MCP separates parse errors from structurally invalid requests', async () => {
  const garbage = new Request('https://email.illek.ie/mcp/v2', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: '{"jsonrpc":"2.0",not json'
  });
  const parseResponse = await handleMcp(garbage, async () => ({}));
  assert.equal(parseResponse.status, 400);
  assert.equal((await parseResponse.json()).error.code, -32700);

  // A syntactically valid batch is well-formed JSON but not a supported
  // request object; that is -32600 Invalid Request, and its only member's id
  // is echoed so the client can correlate the failure.
  const batch = new Request('https://email.illek.ie/mcp/v2', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify([{ jsonrpc: '2.0', id: 7, method: 'ping' }])
  });
  const batchResponse = await handleMcp(batch, async () => ({}));
  assert.equal(batchResponse.status, 400);
  const batchBody = await batchResponse.json();
  assert.equal(batchBody.error.code, -32600);
  assert.equal(batchBody.id, 7);
});

test('a notification-shaped method carrying an id is answered, never orphaned', async () => {
  // JSON-RPC requires every request (any message with an id) to receive a
  // response; answering 202 left strict clients waiting on the id forever.
  const response = await handleMcp(rpcRequest('notifications/initialized', {}, 9), async () => ({}));
  assert.equal(response.status, 400);
  const body = await response.json();
  assert.equal(body.error.code, -32600);
  assert.equal(body.id, 9);
});

test('oversized MCP bodies answer 413 instead of a fake parse error', async () => {
  const oversized = new Request('https://email.illek.ie/mcp/v2', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'x', arguments: { pad: 'y'.repeat(290 * 1024) } } })
  });
  const response = await handleMcp(oversized, async () => ({}));
  assert.equal(response.status, 413);
  assert.match((await response.json()).error.message, /280 KiB/);
});
