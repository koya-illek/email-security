import assert from 'node:assert/strict';
import test from 'node:test';
import { beginRateLimitWindow, rateLimitWindowAt } from './rate-limit-window.mjs';

test('a burst near the minute reset waits into the next limiter window', async () => {
  let time = 119_900;
  const waits = [];
  const epoch = await beginRateLimitWindow({ now: () => time, sleep: async ms => { waits.push(ms); time += ms; } });
  assert.deepEqual(waits, [125]);
  assert.equal(epoch, 2);
  assert.equal(rateLimitWindowAt(time + 14_000), epoch);
});

test('a burst with enough remaining budget starts without sleeping', async () => {
  assert.equal(await beginRateLimitWindow({ now: () => 90_000, sleep: () => assert.fail('unexpected sleep') }), 1);
});

test('a delayed wakeup checks the window again instead of assuming its timing', async () => {
  let time = 119_900;
  const waits = [];
  const epoch = await beginRateLimitWindow({ now: () => time, sleep: async ms => { waits.push(ms); time += waits.length === 1 ? 60_000 : ms; } });
  assert.deepEqual(waits, [125, 125]);
  assert.equal(epoch, 3);
  assert.notEqual(rateLimitWindowAt(time + 60_000), epoch);
});
