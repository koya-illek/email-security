import assert from "node:assert/strict";
import { test } from "node:test";

// This file is not a Worker HTTP-boundary suite. Request validation, CORS,
// rate limits, and content-type contracts live in test/conformance.mjs;
// redirect policy lives in test/redirects.test.cjs. The case below is a
// policy-tag helper for SPF void-lookup accounting.

test("an include target publishing unrelated TXT is a no-match, never a void lookup", async () => {
  // §5.2: an include whose target has no SPF record simply does not match.
  // Counting TXT-bearing targets as void lookups warned healthy records
  // (pass→warn) and errored validators at the two-void permerror threshold.
  const { missingSpfTargetClass } = await import("../policy-tags.js");
  const okNoSpf = ["site-verification-token"];
  Object.defineProperty(okNoSpf, "dnsStatus", { value: "ok" });
  const nxdomain = [];
  Object.defineProperty(nxdomain, "dnsStatus", { value: "nxdomain" });
  const nodata = [];
  Object.defineProperty(nodata, "dnsStatus", { value: "nodata" });
  assert.equal(missingSpfTargetClass(okNoSpf), "empty");
  assert.equal(missingSpfTargetClass(nxdomain), "void");
  assert.equal(missingSpfTargetClass(nodata), "void");
});
