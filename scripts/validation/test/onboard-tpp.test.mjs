import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as onboarding from "../../realm/onboard-tpp.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const realmJson = JSON.parse(fs.readFileSync(path.join(root, "realm/fintechbankx-realm.json"), "utf8"));
const template = realmJson.clients.find((c) => c.clientId === "of-tpp-conformance-template");
const TYPE_SCOPE = "fbx-client-type-open-finance-tpp";
const BASE = "http://kc.test:8080";
const R = `${BASE}/admin/realms/fintechbankx`;

const spec = (over = {}) => ({
  clientId: "of-tpp-acme-pay",
  name: "Acme Pay (test)",
  redirectUris: ["https://acme.example/callback"],
  jwksUri: "https://acme.example/.well-known/jwks.json",
  paymentServices: { authorised: true, reference: "AUTH-REF-0001" },
  ...over
});

// Stateful fake of the Keycloak admin API (only the calls the script makes).
// Keycloak gives a new client the realm default scopes plus the built-in
// optional ones when the request does not name them; the fake does the same,
// so the script has to reconcile the lists itself.
function fakeKeycloak({ clients = [], scopes = ["basic", "acr", "roles", "web-origins", "profile", "email", "customer-id", "offline_access", "address", "phone", "payments", TYPE_SCOPE], rejectUpdate = null } = {}) {
  const scopeIds = new Map(scopes.map((s) => [s, `scope-${s}`]));
  const scopeName = new Map([...scopeIds].map(([n, id]) => [id, n]));
  const state = new Map();
  let seq = 0;
  for (const c of clients) state.set(c.id, structuredClone(c));
  const calls = [];
  const json = (status, body) => new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const fetch = async (url, init = {}) => {
    const method = init.method || "GET";
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ method, url, body, auth: init.headers?.Authorization });
    const u = new URL(url);
    const p = u.pathname.replace("/admin/realms/fintechbankx", "");
    let m;
    if (method === "GET" && p === "/client-scopes") return json(200, [...scopeIds].map(([name, id]) => ({ id, name })));
    if (method === "GET" && p === "/clients") return json(200, [...state.values()].filter((c) => c.clientId === u.searchParams.get("clientId")));
    if (method === "POST" && p === "/clients") {
      const id = `uuid-${++seq}`;
      state.set(id, { ...body, id, defaultClientScopes: ["web-origins", "acr", "profile", "roles", "email", "basic", "customer-id"], optionalClientScopes: ["offline_access", "address", "phone"] });
      return new Response(null, { status: 201, headers: { location: `${R}/clients/${id}` } });
    }
    if ((m = p.match(/^\/clients\/([^/]+)$/))) {
      const c = state.get(m[1]);
      if (!c) return json(404, { error: "not found" });
      if (method === "GET") return json(200, c);
      if (method === "PUT") {
        if (rejectUpdate && rejectUpdate(body)) return json(400, { error: "invalid_client_metadata", error_description: "policy" });
        state.set(m[1], { ...c, ...body, defaultClientScopes: c.defaultClientScopes, optionalClientScopes: c.optionalClientScopes });
        return json(204);
      }
      if (method === "DELETE") { state.delete(m[1]); return json(204); }
    }
    if ((m = p.match(/^\/clients\/([^/]+)\/(default|optional)-client-scopes(?:\/([^/]+))?$/))) {
      const c = state.get(m[1]);
      const key = m[2] === "default" ? "defaultClientScopes" : "optionalClientScopes";
      if (method === "GET") return json(200, c[key].map((n) => ({ id: scopeIds.get(n), name: n })));
      const n = scopeName.get(m[3]);
      if (method === "PUT") { if (!c[key].includes(n)) c[key].push(n); return json(204); }
      if (method === "DELETE") { c[key] = c[key].filter((x) => x !== n); return json(204); }
    }
    return json(404, { error: `unexpected ${method} ${p}` });
  };
  return { fetch, calls, state, writes: () => calls.filter((c) => c.method !== "GET") };
}

const run = (kc, s = spec()) => onboarding.onboardTpp({ fetch: kc.fetch, baseUrl: BASE, token: "t0k", realm: "fintechbankx", client: onboarding.buildTppClient({ template, spec: s }), paymentsAuthorised: s.paymentServices?.authorised === true });

test("spec validation: identity decides scopes and attributes, the spec only names the TPP", () => {
  assert.deepEqual(onboarding.validateTppSpec(spec()), []);
  const bad = (over, expected) => {
    const errors = onboarding.validateTppSpec(spec(over));
    assert.ok(errors.includes(expected), `${expected} not in ${errors.join("; ")}`);
  };
  bad({ clientId: "acme" }, "clientId must match of-tpp-<kebab> (max 64 characters)");
  bad({ clientId: "of-tpp-conformance-template" }, "clientId of-tpp-conformance-template is the realm template");
  bad({ redirectUris: ["http://acme.example/cb"] }, "redirect URI http://acme.example/cb must be an absolute https URL without wildcard or fragment");
  bad({ redirectUris: ["https://acme.example/*"] }, "redirect URI https://acme.example/* must be an absolute https URL without wildcard or fragment");
  bad({ redirectUris: [] }, "redirectUris must list at least one URI");
  bad({ jwks: { keys: [{ kty: "RSA", n: "x", e: "AQAB" }] } }, "give exactly one of jwksUri or jwks");
  bad({ jwksUri: undefined, jwks: { keys: [{ kty: "RSA", n: "x", e: "AQAB", d: "private" }] } }, "jwks key 0 carries private key member d");
  bad({ paymentServices: { authorised: true } }, "paymentServices.reference is required when payment services are authorised");
  bad({ defaultClientScopes: ["payments"] }, "unknown field defaultClientScopes (scopes and attributes are set by identity, not by the spec)");
  bad({ attributes: { "fbx.client-type": "service" } }, "unknown field attributes (scopes and attributes are set by identity, not by the spec)");
});

test("the client built from the realm template carries the client type, DPoP and the default client-type scope", () => {
  const c = onboarding.buildTppClient({ template, spec: spec() });
  assert.equal(c.clientId, "of-tpp-acme-pay");
  assert.equal(c.enabled, true);
  assert.equal(c.attributes["fbx.client-type"], "open-finance-tpp");
  assert.equal(c.attributes["fbx.tpp.token-binding"], "dpop");
  assert.equal(c.attributes["dpop.bound.access.tokens"], "true");
  assert.equal(c.attributes["jwks.url"], "https://acme.example/.well-known/jwks.json");
  assert.equal(c.attributes["fbx.tpp.payment-services-reference"], "AUTH-REF-0001");
  assert.deepEqual(c.defaultClientScopes, template.defaultClientScopes);
  assert.ok(c.defaultClientScopes.includes(TYPE_SCOPE));
  assert.deepEqual(c.optionalClientScopes, ["payments"]);
  assert.deepEqual(c.protocolMappers.map((m) => m.config["included.client.audience"]), template.protocolMappers.map((m) => m.config["included.client.audience"]));
  const noPay = onboarding.buildTppClient({ template, spec: spec({ paymentServices: undefined }) });
  assert.deepEqual(noPay.optionalClientScopes, []);
  assert.equal(noPay.attributes["fbx.tpp.payment-services-reference"], undefined);
  const inline = onboarding.buildTppClient({ template, spec: spec({ jwksUri: undefined, jwks: { keys: [{ kty: "RSA", kid: "k1", n: "x", e: "AQAB" }] } }) });
  assert.equal(inline.attributes["use.jwks.url"], "false");
  assert.equal(inline.attributes["use.jwks.string"], "true");
  assert.equal(inline.attributes["jwks.url"], undefined);
  assert.throws(() => onboarding.buildTppClient({ template, spec: spec({ clientId: "nope" }) }), /refusing to build/);
});

test("refuses, with no admin API call, a TPP client without the client type, the default scope or DPoP, or with payments as a default", async () => {
  const cases = [
    [(c) => { delete c.attributes["fbx.client-type"]; }, "attribute fbx.client-type must be open-finance-tpp"],
    [(c) => { c.attributes["fbx.tpp.token-binding"] = "mtls"; }, "open-finance-tpp clients must set fbx.tpp.token-binding=dpop"],
    [(c) => { c.defaultClientScopes = c.defaultClientScopes.filter((s) => s !== TYPE_SCOPE); }, `open-finance-tpp clients must carry client scope ${TYPE_SCOPE} as a default scope`],
    [(c) => { c.defaultClientScopes.push("payments"); }, "payments must be an optional scope of open-finance-tpp clients, never a default scope"],
    [(c) => { c.optionalClientScopes = []; }, "payments must be an optional scope when payment services are authorised"]
  ];
  for (const [mutate, expected] of cases) {
    const kc = fakeKeycloak();
    const c = onboarding.buildTppClient({ template, spec: spec() });
    mutate(c);
    await assert.rejects(onboarding.onboardTpp({ fetch: kc.fetch, baseUrl: BASE, token: "t", realm: "fintechbankx", client: c, paymentsAuthorised: true }), (e) => e.message.includes(expected), expected);
    assert.equal(kc.calls.length, 0, expected);
  }
  const kc = fakeKeycloak();
  const c = onboarding.buildTppClient({ template, spec: spec({ paymentServices: undefined }) });
  c.optionalClientScopes = ["payments"];
  await assert.rejects(onboarding.onboardTpp({ fetch: kc.fetch, baseUrl: BASE, token: "t", realm: "fintechbankx", client: c, paymentsAuthorised: false }), /payments is only for TPPs authorised for payment services/);
  assert.equal(kc.calls.length, 0);
});

test("fresh realm: creates the client disabled, lets Keycloak's update policies check it, sets the exact scopes, verifies, then enables", async () => {
  const kc = fakeKeycloak();
  const result = await run(kc);
  assert.equal(result.action, "created");
  const writes = kc.writes().map((c) => `${c.method} ${c.url.replace(R, "")}`);
  assert.equal(writes[0], "POST /clients");
  assert.equal(kc.writes()[0].body.enabled, false);
  assert.equal(writes[1], "PUT /clients/uuid-1");
  assert.equal(kc.writes()[1].body.enabled, false);
  assert.equal(writes.at(-1), "PUT /clients/uuid-1");
  assert.equal(kc.writes().at(-1).body.enabled, true);
  const created = kc.state.get("uuid-1");
  assert.deepEqual([...created.defaultClientScopes].sort(), [...template.defaultClientScopes].sort());
  assert.deepEqual(created.optionalClientScopes, ["payments"]);
  assert.equal(created.enabled, true);
  assert.equal(created.attributes["fbx.client-type"], "open-finance-tpp");
  // Removals before additions, so payments is never default and optional at once.
  const scopeWrites = writes.filter((w) => w.includes("-client-scopes/"));
  const firstAdd = scopeWrites.findIndex((w) => w.startsWith("PUT"));
  assert.ok(scopeWrites.slice(firstAdd).every((w) => w.startsWith("PUT")), scopeWrites.join(", "));
  assert.ok(kc.calls.every((c) => c.auth === "Bearer t0k"));
});

test("second run is idempotent: one update, no scope change, no duplicate", async () => {
  const kc = fakeKeycloak();
  await run(kc);
  const before = kc.calls.length;
  const again = await run(kc);
  assert.equal(again.action, "updated");
  assert.deepEqual(again.scopeChanges, []);
  const writes = kc.calls.slice(before).filter((c) => c.method !== "GET");
  assert.deepEqual(writes.map((c) => `${c.method} ${c.url.replace(R, "")}`), ["PUT /clients/uuid-1"]);
  assert.equal(kc.state.size, 1);
});

test("an existing TPP losing payment authorisation loses the payments scope; an existing drifted client is repaired", async () => {
  const kc = fakeKeycloak();
  await run(kc);
  const c = kc.state.get("uuid-1");
  c.defaultClientScopes = c.defaultClientScopes.filter((s) => s !== TYPE_SCOPE).concat("payments");
  c.optionalClientScopes = [];
  const repaired = await run(kc);
  assert.ok(kc.state.get("uuid-1").defaultClientScopes.includes(TYPE_SCOPE));
  assert.ok(!kc.state.get("uuid-1").defaultClientScopes.includes("payments"));
  assert.deepEqual(kc.state.get("uuid-1").optionalClientScopes, ["payments"]);
  assert.ok(repaired.scopeChanges.length >= 3, JSON.stringify(repaired.scopeChanges));
  const revoked = await run(kc, spec({ paymentServices: undefined }));
  assert.deepEqual(kc.state.get("uuid-1").optionalClientScopes, []);
  assert.deepEqual(revoked.scopeChanges, ["optional -payments"]);
});

test("refuses to turn an existing client of another type into a TPP", async () => {
  const kc = fakeKeycloak({ clients: [{ id: "svc-1", clientId: "of-tpp-acme-pay", attributes: { "fbx.client-type": "service" }, defaultClientScopes: [], optionalClientScopes: [] }] });
  await assert.rejects(run(kc), /of-tpp-acme-pay exists with fbx.client-type=service; refusing to change its type/);
  assert.equal(kc.writes().length, 0);
});

test("a realm without the client-type scope is refused before any write", async () => {
  const kc = fakeKeycloak({ scopes: ["basic", "acr", "roles", "customer-id", "payments"] });
  await assert.rejects(run(kc), new RegExp(`client scope ${TYPE_SCOPE} not found in realm fintechbankx`));
  assert.equal(kc.writes().length, 0);
});

test("a new client that Keycloak's client policies reject on update is deleted again (never left half-made)", async () => {
  const kc = fakeKeycloak({ rejectUpdate: () => true });
  await assert.rejects(run(kc), /rolled back/);
  assert.deepEqual(kc.writes().map((c) => `${c.method} ${c.url.replace(R, "")}`), ["POST /clients", "PUT /clients/uuid-1", "DELETE /clients/uuid-1"]);
  assert.equal(kc.state.size, 0);
});

test("CLI dry run prints the client without calling Keycloak", async () => {
  const { execFileSync } = await import("node:child_process");
  const os = await import("node:os");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tpp-"));
  const f = path.join(dir, "tpp.json");
  fs.writeFileSync(f, JSON.stringify(spec()));
  const out = execFileSync(process.execPath, [path.join(root, "scripts/realm/onboard-tpp.mjs"), "--tpp", f, "--dry-run"], { env: { PATH: process.env.PATH }, encoding: "utf8" });
  const printed = JSON.parse(out);
  assert.equal(printed.clientId, "of-tpp-acme-pay");
  assert.ok(printed.defaultClientScopes.includes(TYPE_SCOPE));
  fs.writeFileSync(f, JSON.stringify(spec({ redirectUris: ["http://x"] })));
  assert.throws(() => execFileSync(process.execPath, [path.join(root, "scripts/realm/onboard-tpp.mjs"), "--tpp", f, "--dry-run"], { env: { PATH: process.env.PATH }, stdio: "pipe" }), /refusing/);
  fs.rmSync(dir, { recursive: true });
});

test("committed TPP list: every spec is valid, built from the template and listed once", () => {
  const list = JSON.parse(fs.readFileSync(path.join(root, "realm/tpp-clients.json"), "utf8"));
  assert.ok(Array.isArray(list.tpps));
  const ids = list.tpps.map((s) => s.clientId);
  assert.equal(new Set(ids).size, ids.length);
  for (const s of list.tpps) {
    assert.deepEqual(onboarding.validateTppSpec(s), [], s.clientId);
    const c = onboarding.buildTppClient({ template, spec: s });
    assert.ok(c.defaultClientScopes.includes(TYPE_SCOPE));
  }
});
