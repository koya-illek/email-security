import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const worker = await readFile(new URL("../worker.js", import.meta.url), "utf8");

test("public UI has hardened headers and explicit discovery routes", () => {
  assert.match(worker, /Content-Security-Policy/);
  assert.match(worker, /Strict-Transport-Security/);
  assert.ok(worker.includes("static.cloudflareinsights.com"));
  assert.ok(worker.includes("url.pathname === '/robots.txt'"));
  assert.ok(worker.includes("url.pathname === '/sitemap.xml'"));
});

test("unknown routes do not fall through to the application HTML", () => {
  assert.ok(worker.includes("url.pathname === '/' && request.method === 'GET'"));
  assert.ok(worker.includes("new Response('Not found', { status: 404"));
});
