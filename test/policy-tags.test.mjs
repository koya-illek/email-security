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
  effectiveDmarcPolicy,
  isValidSpfDomainSpec,
  spfTermSyntaxError,
  parseTagRecord
} = require("../policy-tags.js");
const { estimateDkimKeyBits } = require("../scoring.js");

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

test("qualified modifiers are syntax errors, never live redirect targets", () => {
  // RFC 7208 §6: modifiers are name=value and cannot carry a qualifier.
  // "+redirect=" used to be stripped into a live redirect the engine
  // followed, reporting a policy the record never expressed.
  assert.match(spfTermSyntaxError("+redirect=_r.example"), /qualifier cannot precede/);
  assert.equal(spfTermSyntaxError("redirect=_r.example"), null);
  assert.equal(spfTermSyntaxError("exp=explain.example.com"), null);
  assert.equal(spfTermSyntaxError("+include:_spf.example.com"), null, "mechanisms may carry qualifiers");
});

test("terms matching no RFC 7208 production are named instead of silently ignored", () => {
  assert.match(spfTermSyntaxError("foo:bar"), /matches no RFC 7208/);
  // "v=spf2" is a legal UNKNOWN modifier receivers ignore (RFC 7208 §6),
  // not a syntax error — the validator warns and retains it.
  assert.equal(spfTermSyntaxError("v=spf2"), null);
  for (const term of ["all", "-all", "ip4:192.0.2.0/24", "ip6:2001:db8::/32", "a", "a/24", "a:example.com//64", "mx:example.com", "ptr", "ptr:example.com", "include:_spf.example.com", "exists:%{ir}.example.com"]) {
    assert.equal(spfTermSyntaxError(term), null, term);
  }
});

test("the domain-spec validator enforces the RFC 7208 §7 macro grammar", () => {
  for (const spec of ["_spf.example.com", "%{ir}.%{v}._spf.%{d2}.example.com", "%{l}.%{o}.example.com", "%{d}._spf.example", "smtp.%{i}.example.com"]) {
    assert.ok(isValidSpfDomainSpec(spec), spec);
  }
  // k is not a macro letter; bare % and %x are not macro escapes.
  for (const spec of ["%foo.example.com", "%{k}.example.com", "%{s%.example.com", "bad..example.com"]) {
    assert.equal(isValidSpfDomainSpec(spec), false, spec);
  }
});

test("qualified redirects consume no evaluation lookup", () => {
  assert.equal(countVisibleSpfLookups(["+redirect=_x.example"]), 0);
  assert.equal(countVisibleSpfLookups(["redirect=_x.example"]), 1);
});

test("parseTagRecord lowercases tag names but preserves value casing", () => {
  const tags = parseTagRecord("v=DKIM1; K=RSA; p=MIIBIgJj/ABC+def=");
  assert.equal(tags.v, "DKIM1");
  assert.equal(tags.k, "RSA");
  // Base64 is case-sensitive: lowercasing the p= value silently corrupts
  // every byte-exact consumer (the DER modulus parse).
  assert.equal(tags.p, "MIIBIgJj/ABC+def=");
});

test("a real DKIM key keeps its exact bit length through parseTagRecord", () => {
  // Regression: values were lowercased before estimateDkimKeyBits ran, so
  // every RSA key read as null and weak-key detection never fired.
  const { generateKeyPairSync } = require("node:crypto");
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const record = "v=DKIM1; k=rsa; p=" + publicKey.export({ type: "spki", format: "der" }).toString("base64");
  const parsed = parseTagRecord(record);
  assert.equal(estimateDkimKeyBits(parsed.p), 1024);
});
