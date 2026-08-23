import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const {
  DMARC_POLICY_VALUES,
  stripSpfQualifier,
  spfTerminalTerm,
  countVisibleSpfLookups,
  hasSpfMacro,
  isDmarcVersionRecord,
  effectiveDmarcPolicy
} = require("../policy-tags.js");

test("inherited DMARC records apply sp= instead of the parent's p=", () => {
  // RFC 7489 §6.6.3: receivers enforce sp= against subdomains when present.
  assert.equal(effectiveDmarcPolicy({ p: "reject", sp: "none" }, true), "none");
  assert.equal(effectiveDmarcPolicy({ p: "none", sp: "quarantine" }, true), "quarantine");
  assert.equal(effectiveDmarcPolicy({ p: "quarantine", sp: "reject" }, true), "reject");
});

test("non-inherited records and absent or invalid sp= fall back to p=", () => {
  assert.equal(effectiveDmarcPolicy({ p: "reject", sp: "none" }, false), "reject");
  assert.equal(effectiveDmarcPolicy({ p: "reject" }, true), "reject");
  assert.equal(effectiveDmarcPolicy({ p: "reject", sp: "sometimes" }, true), "reject");
  assert.equal(effectiveDmarcPolicy({}, true), null);
});

test("the policy value whitelist stays closed", () => {
  assert.deepEqual(DMARC_POLICY_VALUES, ["none", "quarantine", "reject"]);
});

test("DMARC version discovery accepts RFC whitespace but keeps DMARC1 case-sensitive", () => {
  assert.ok(isDmarcVersionRecord("v=DMARC1; p=reject"));
  assert.ok(isDmarcVersionRecord(" V = DMARC1 ; p=reject"));
  assert.ok(!isDmarcVersionRecord("v=dmarc1; p=reject"));
  assert.ok(!isDmarcVersionRecord("x=DMARC1; p=reject"));
});

test("redirect is not counted toward the SPF lookup limit when an all term makes it unreachable", () => {
  assert.equal(countVisibleSpfLookups(["include:_spf.example.com", "-all", "redirect=_spf2.example.net"]), 1);
  assert.equal(countVisibleSpfLookups(["~all", "redirect=_spf2.example.net"]), 0);
});

test("ip4 and ip6 mechanisms assert addresses directly and never consume lookups", () => {
  assert.equal(countVisibleSpfLookups(["ip4:192.0.2.1", "ip6:2001:db8::1"]), 0);
});

test("redirect still counts when no all term exists, because evaluation follows it", () => {
  assert.equal(countVisibleSpfLookups(["include:_spf.example.com", "redirect=_spf2.example.net"]), 2);
});

test("every other DNS-consuming mechanism keeps counting", () => {
  assert.equal(
    countVisibleSpfLookups(["a", "a:_a.example.com", "mx/24", "mx:_m.example.com", "ptr", "ptr:_p.example.com", "include:_i.example.com", "exists:_e.example.com"]),
    8
  );
});

test("qualifier and case variations do not change counting", () => {
  assert.equal(stripSpfQualifier("+Include:_A.Example.com"), "include:_a.example.com");
  assert.equal(spfTerminalTerm("-ALL"), "-all");
  assert.equal(spfTerminalTerm("include:_spf.example.com"), null);
});

test("sender-macro targets are detected for every legal macro expression", () => {
  assert.ok(hasSpfMacro("include:_spf.%{d2}.esp.com"));
  assert.ok(hasSpfMacro("exists:%{ir}.%{v}.arb.example.com"));
  assert.ok(hasSpfMacro("redirect=%{l}._spf.example.com"));
  assert.ok(!hasSpfMacro("include:_spf.esp.com"));
  assert.ok(!hasSpfMacro("redirect=_spf.example.com"));
});
