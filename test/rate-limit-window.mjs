// Miniflare's limiter uses wall-clock-aligned windows, not a sliding window
// starting at this client's first request. Keep burst assertions away from a
// reset; do not turn a legitimate next-window 200 into an apparent failure.
export const RATE_LIMIT_WINDOW_MS = 60_000;

export async function beginRateLimitWindow({ now = Date.now, sleep = ms => new Promise(resolve => setTimeout(resolve, ms)) } = {}) {
  const minimumRemainingMs = 15_000;
  let time = now();
  while (RATE_LIMIT_WINDOW_MS - time % RATE_LIMIT_WINDOW_MS < minimumRemainingMs) {
    await sleep(RATE_LIMIT_WINDOW_MS - time % RATE_LIMIT_WINDOW_MS + 25);
    time = now();
  }
  return Math.floor(time / RATE_LIMIT_WINDOW_MS);
}

export function rateLimitWindowAt(time = Date.now()) {
  return Math.floor(time / RATE_LIMIT_WINDOW_MS);
}
