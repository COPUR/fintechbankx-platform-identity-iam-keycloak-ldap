// Screening facts computed by their owners (CRC plan 2026-10-18, owner's
// answers to the 10-08 cards): compliance reads a customer's screening profile
// (GET /api/v1/customers/{id}/screening-profile, customer's
// SERVICE_CALLERS_SCREENING), risk reads a customer's credit standing
// (GET /api/v1/customers/{id}/credit-standing, SERVICE_CALLERS_CREDIT_STANDING)
// and decides loan eligibility, which loan asks for
// (POST /api/v1/risk/loan-eligibility, risk's SERVICE_CALLERS_ELIGIBILITY).
// Their client-credentials tokens need the callee's service id in aud; the
// mesh edges are in the mesh repository's contract.
import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { checkRealm, loadFromRepo } from "../../ci/check-realm.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const input = loadFromRepo(root);
const registryEntry = (id) => input.registry.clients.find((c) => c.clientId === id);
const realmClient = (id) => input.realm.clients.find((c) => c.clientId === id);
const audienceMappers = (id) =>
  (realmClient(id).protocolMappers || [])
    .filter((m) => m.protocolMapper === "oidc-audience-mapper")
    .map((m) => m.config["included.client.audience"])
    .sort();

const EDGES = [
  ["svc-rsk-decisioning", ["svc-cus-profile-kyc"]],
  ["svc-cmp-evidence", ["svc-cus-profile-kyc"]],
  ["svc-ln-loan-lifecycle", ["svc-cus-profile-kyc", "svc-rsk-decisioning"]],
];

test("risk and compliance may call customer, and loan may call risk", () => {
  for (const [id, mappers] of EDGES) {
    for (const a of mappers) assert.ok(registryEntry(id).audiences.includes(a), `${id}: registry audience ${a}`);
    // Every audience but the ledger's (an optional scope) is an always-on mapper.
    assert.deepEqual(audienceMappers(id), mappers, `${id}: audience mappers`);
  }
  // Risk and compliance call nothing else; payments keeps its two audiences.
  assert.deepEqual(registryEntry("svc-rsk-decisioning").audiences, ["svc-cus-profile-kyc"]);
  assert.deepEqual(registryEntry("svc-cmp-evidence").audiences, ["svc-cus-profile-kyc"]);
  for (const a of ["svc-rsk-decisioning", "svc-cmp-evidence"]) {
    assert.ok(registryEntry("svc-pay-initiation-settlement").audiences.includes(a), `payments: ${a}`);
  }
  // Customer calls neither of them back.
  assert.deepEqual(registryEntry("svc-cus-profile-kyc").audiences, []);
});

test("the rendered realm passes check-realm with the new audiences", () => {
  assert.deepEqual(checkRealm(input), []);
});

test("the audience table says the callees still have to admit the new callers", () => {
  // An audience lets the token reach the callee; the callee's own azp check decides.
  // Loan has no azp check and is no callee of these edges, so the doc must not lean on it.
  const doc = readFileSync(path.join(root, "docs/identity/REALM_AS_CODE.md"), "utf8");
  const note = doc.split("\n").find((l) => l.includes("Screening-facts callers"));
  assert.ok(note, "a note on the screening-facts callers follows the audience table");
  for (const s of [
    "svc-rsk-decisioning",
    "svc-cmp-evidence",
    "svc-ln-loan-lifecycle",
    "SERVICE_CALLERS_CREDIT_STANDING",
    "GET /api/v1/customers/{id}/credit-standing",
    "SERVICE_CALLERS_SCREENING",
    "GET /api/v1/customers/{id}/screening-profile",
    "SERVICE_CALLERS_ELIGIBILITY",
    "POST /api/v1/risk/loan-eligibility",
    "realm role `service`",
    "`<env>/risk-decisioning-service/oidc-client`",
    "`<env>/compliance-evidence-service/oidc-client`",
  ]) {
    assert.ok(note.includes(s), `note names ${s}`);
  }
  // The earlier plan's reads are gone: neither caller reads the customer record, /credit or /kyc-status.
  for (const s of ["SERVICE_CALLERS_PROFILE", "SERVICE_CALLERS_KYC", "/kyc-status", "/credit`", "svc-client"]) {
    assert.ok(!note.includes(s), `note no longer names ${s}`);
  }
});

test("the customer audience provenance names the endpoint and caller list each caller is on", () => {
  const prov = (id) => registryEntry(id).audienceProvenance["svc-cus-profile-kyc"];
  assert.match(prov("svc-rsk-decisioning"), /GET \/api\/v1\/customers\/\{id\}\/credit-standing\b.*SERVICE_CALLERS_CREDIT_STANDING/);
  assert.match(prov("svc-cmp-evidence"), /GET \/api\/v1\/customers\/\{id\}\/screening-profile\b.*SERVICE_CALLERS_SCREENING/);
  for (const id of ["svc-rsk-decisioning", "svc-cmp-evidence"]) {
    assert.doesNotMatch(prov(id), /SERVICE_CALLERS_PROFILE|SERVICE_CALLERS_KYC|kyc-status|\/credit\b(?!-)/, id);
  }
  assert.match(registryEntry("svc-ln-loan-lifecycle").audienceProvenance["svc-rsk-decisioning"], /POST \/api\/v1\/risk\/loan-eligibility.*SERVICE_CALLERS_ELIGIBILITY/);
});
