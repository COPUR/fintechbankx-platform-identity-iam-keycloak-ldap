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
function fakeKeycloak({ clients = [], scopes = ["basic", "acr", "roles", "web-origins", "profile", "email", "customer-id", "offline_access", "address", "phone", "payments", TYPE_SCOPE], rejectUpdate = null, sessions = {}, noConsent = [] } = {}) {
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
    // Sessions of a client (sessions: {clientUuid: {online: [userId], offline: [userId]}})
    // and per-client consent revocation (DELETE /users/{id}/consents/{clientId}).
    if (method === "GET" && (m = p.match(/^\/clients\/([^/]+)\/(user|offline)-sessions$/))) {
      const first = Number(u.searchParams.get("first") || 0);
      const max = Number(u.searchParams.get("max") || 100);
      const users = sessions[m[1]]?.[m[2] === "user" ? "online" : "offline"] || [];
      return json(200, users.slice(first, first + max).map((userId, i) => ({ id: `s-${m[2]}-${first + i}`, userId })));
    }
    if (method === "DELETE" && (m = p.match(/^\/users\/([^/]+)\/consents\/([^/]+)$/))) {
      const c = [...state.values()].find((x) => x.clientId === decodeURIComponent(m[2]));
      const s = c && sessions[c.id];
      if (!s || noConsent.includes(m[1]) || ![...(s.online || []), ...(s.offline || [])].includes(m[1])) return json(404, { error: "Consent nor offline token not found" });
      for (const k of ["online", "offline"]) s[k] = (s[k] || []).filter((x) => x !== m[1]);
      return json(204);
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

const run = (kc, s = spec(), extra = {}) => onboarding.onboardTpp({ fetch: kc.fetch, baseUrl: BASE, token: "t0k", realm: "fintechbankx", client: onboarding.buildTppClient({ template, spec: s }), paymentsAuthorised: s.paymentServices?.authorised === true, status: onboarding.statusOf(s), ...extra });

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
  bad({ status: "disabled" }, "status must be active or suspended (default active)");
  bad({ status: true }, "status must be active or suspended (default active)");
  assert.deepEqual(onboarding.validateTppSpec(spec({ status: "active" })), []);
  assert.deepEqual(onboarding.validateTppSpec(spec({ status: "suspended" })), []);
  assert.equal(onboarding.statusOf(spec()), "active");
  assert.equal(onboarding.statusOf(spec({ status: "suspended" })), "suspended");
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

test("an existing client an operator disabled stays disabled on the next sync, with a warning (never silently re-enabled)", async () => {
  const kc = fakeKeycloak();
  await run(kc);
  assert.equal(kc.state.get("uuid-1").enabled, true);
  kc.state.get("uuid-1").enabled = false; // operator disables it in the admin console
  const warnings = [];
  const before = kc.calls.length;
  const again = await run(kc, spec(), { warn: (m) => warnings.push(m) });
  assert.equal(kc.state.get("uuid-1").enabled, false);
  assert.ok(kc.calls.slice(before).filter((c) => c.method === "PUT" && c.url === `${R}/clients/uuid-1`).every((c) => c.body.enabled === false));
  assert.deepEqual(warnings, ["of-tpp-acme-pay: listed active but disabled in Keycloak; leaving disabled — set status in Git"]);
  assert.equal(again.enabled, false);
  // An enabled, active client stays enabled and no session is touched.
  kc.state.get("uuid-1").enabled = true;
  const ok = await run(kc);
  assert.equal(kc.state.get("uuid-1").enabled, true);
  assert.equal(ok.enabled, true);
  assert.ok(!kc.calls.some((c) => c.url.includes("/consents/") || c.url.includes("-sessions")));
});

test("status suspended disables an enabled client, sets notBefore and revokes its user and offline sessions", async () => {
  const kc = fakeKeycloak({ sessions: { "uuid-1": { online: ["user-a", "user-b", "user-n"], offline: ["user-b", "user-c"] } }, noConsent: ["user-n"] });
  await run(kc);
  assert.equal(kc.state.get("uuid-1").enabled, true);
  const before = kc.calls.length;
  const t0 = Math.floor(Date.now() / 1000);
  const res = await run(kc, spec({ status: "suspended" }));
  const c = kc.state.get("uuid-1");
  assert.equal(c.enabled, false);
  assert.ok(Number.isInteger(c.notBefore) && c.notBefore >= t0, `notBefore ${c.notBefore}`);
  const writes = kc.calls.slice(before).filter((x) => x.method !== "GET").map((x) => `${x.method} ${x.url.replace(R, "")}`);
  // Disabled before any session is revoked, so no new token is issued meanwhile.
  assert.equal(writes[0], "PUT /clients/uuid-1");
  assert.deepEqual(writes.filter((w) => w.includes("/consents/")).sort(), ["DELETE /users/user-a/consents/of-tpp-acme-pay", "DELETE /users/user-b/consents/of-tpp-acme-pay", "DELETE /users/user-c/consents/of-tpp-acme-pay", "DELETE /users/user-n/consents/of-tpp-acme-pay"]);
  // user-n has a session but neither consent nor offline token (Keycloak 404): tolerated, not counted.
  assert.deepEqual(res.revokedUsers, ["user-a", "user-b", "user-c"]);
  assert.equal(res.enabled, false);
  // Idempotent while suspended: no session left, notBefore not moved again.
  const nb = c.notBefore;
  const again = await run(kc, spec({ status: "suspended" }));
  assert.equal(kc.state.get("uuid-1").enabled, false);
  assert.equal(kc.state.get("uuid-1").notBefore, nb);
  assert.deepEqual(again.revokedUsers, []);
  // Any other admin API failure during revocation fails the run.
  const bad = fakeKeycloak({ sessions: { "uuid-1": { online: ["user-a"] } } });
  await run(bad);
  const failing = async (url, init = {}) => (init.method === "DELETE" && url.includes("/consents/") ? new Response("{}", { status: 500 }) : bad.fetch(url, init));
  await assert.rejects(onboarding.onboardTpp({ fetch: failing, baseUrl: BASE, token: "t", realm: "fintechbankx", client: onboarding.buildTppClient({ template, spec: spec({ status: "suspended" }) }), paymentsAuthorised: true, status: "suspended" }), /-> 500/);
});

test("a TPP listed suspended before it exists is created and left disabled", async () => {
  const kc = fakeKeycloak();
  const res = await run(kc, spec({ status: "suspended" }));
  assert.equal(res.action, "created");
  assert.equal(kc.state.get("uuid-1").enabled, false);
  assert.ok(kc.writes().every((w) => w.body === undefined || w.body.enabled === false));
});

test("verify-live listing check: flags enabled TPP clients not in the list and listed-suspended clients that are enabled", () => {
  const tpp = (clientId, enabled) => ({ clientId, enabled, attributes: { "fbx.client-type": "open-finance-tpp" } });
  const clients = [
    tpp("of-tpp-acme-pay", true), // listed active, enabled: fine
    tpp("of-tpp-rogue", true), // not listed, enabled: error
    tpp("of-tpp-gone", false), // not listed, disabled (off-boarded): fine
    tpp("of-tpp-paused", true), // listed suspended, enabled: error
    tpp("of-tpp-held", false), // listed active, disabled by an operator: warning
    { clientId: "svc-pay-request-to-pay", enabled: true, attributes: { "fbx.client-type": "service" } }
  ];
  const specs = [spec(), spec({ clientId: "of-tpp-paused", status: "suspended" }), spec({ clientId: "of-tpp-held" })];
  const { errors, warnings } = onboarding.tppListingFindings(clients, specs);
  assert.deepEqual(errors, [
    "of-tpp-rogue: enabled open-finance-tpp client not listed in realm/tpp-clients.json (add it, or disable and off-board it)",
    "of-tpp-paused: listed suspended in realm/tpp-clients.json but enabled in Keycloak"
  ]);
  assert.deepEqual(warnings, ["of-tpp-held: listed active but disabled in Keycloak; leaving disabled — set status in Git"]);
});
