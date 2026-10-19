import test from "node:test";
import assert from "node:assert/strict";
import { applyAdminPermissions, fetchAdminToken, reconcileScopeMappings } from "../../realm/apply-admin-permissions.mjs";

const BASE = "http://kc.test:8080";
const R = `${BASE}/admin/realms/fintechbankx`;
const RS = `${R}/clients/ap-uuid/authz/resource-server`;
const spec = {
  realm: "fintechbankx",
  permissions: [{
    name: "fbx-customers-customer-service",
    description: "Customer service: view and update members of /customers only.",
    resourceType: "Groups",
    groupPaths: ["/customers"],
    scopes: ["view-members", "manage-members"],
    decisionStrategy: "UNANIMOUS",
    policy: { name: "fbx-customer-service-client", type: "client", logic: "POSITIVE", clients: ["svc-cus-profile-kyc"] },
    reason: "identity link"
  }]
};

// Fake Keycloak admin API: routes keyed by "METHOD url"; records every call.
function fakeFetch(routes) {
  const calls = [];
  const fetch = async (url, init = {}) => {
    const method = init.method || "GET";
    const key = `${method} ${url}`;
    calls.push({ method, url, body: init.body && init.headers?.["Content-Type"] === "application/json" ? JSON.parse(init.body) : init.body, headers: init.headers });
    if (!(key in routes)) return new Response(JSON.stringify({ error: `unexpected ${key}` }), { status: 404 });
    const r = routes[key];
    const [status, body] = typeof r === "function" ? r(init) : r;
    return new Response(status === 204 ? null : JSON.stringify(body ?? {}), { status, headers: { "content-type": "application/json" } });
  };
  return { fetch, calls, writes: () => calls.filter((c) => c.method !== "GET") };
}

const lookups = {
  [`GET ${R}/clients?clientId=admin-permissions`]: [200, [{ id: "ap-uuid", clientId: "admin-permissions" }]],
  [`GET ${R}/clients?clientId=svc-cus-profile-kyc`]: [200, [{ id: "kyc-uuid", clientId: "svc-cus-profile-kyc" }]],
  [`GET ${R}/group-by-path/customers`]: [200, { id: "grp-customers", path: "/customers" }]
};

test("fresh realm: creates the client policy, then the scope permission on /customers", async () => {
  const f = fakeFetch({
    ...lookups,
    [`GET ${RS}/policy?name=fbx-customer-service-client&first=0&max=100`]: [200, []],
    [`GET ${RS}/policy?name=fbx-customers-customer-service&first=0&max=100`]: [200, []],
    [`POST ${RS}/policy/client`]: [201, { id: "pol-1" }],
    [`POST ${RS}/permission/scope`]: [201, { id: "perm-1" }]
  });
  const result = await applyAdminPermissions({ fetch: f.fetch, baseUrl: BASE, token: "t0k", spec });
  assert.deepEqual(f.writes().map((c) => `${c.method} ${c.url}`), [`POST ${RS}/policy/client`, `POST ${RS}/permission/scope`]);
  const [policy, permission] = f.writes().map((c) => c.body);
  assert.deepEqual(policy, { name: "fbx-customer-service-client", description: "Client policy: service account of svc-cus-profile-kyc (fine-grained admin permissions v2).", type: "client", logic: "POSITIVE", decisionStrategy: "UNANIMOUS", clients: ["kyc-uuid"] });
  assert.deepEqual(permission, {
    name: "fbx-customers-customer-service",
    description: "Customer service: view and update members of /customers only.",
    type: "scope",
    logic: "POSITIVE",
    decisionStrategy: "UNANIMOUS",
    resourceType: "Groups",
    resources: ["grp-customers"],
    scopes: ["view-members", "manage-members"],
    policies: ["pol-1"]
  });
  assert.ok(f.calls.every((c) => c.headers.Authorization === "Bearer t0k"));
  assert.deepEqual(result, [
    { kind: "policy", name: "fbx-customer-service-client", action: "created", id: "pol-1" },
    { kind: "permission", name: "fbx-customers-customer-service", action: "created", id: "perm-1" }
  ]);
});

test("second run: updates the existing policy and permission in place (no duplicates)", async () => {
  const f = fakeFetch({
    ...lookups,
    // name search is a substring match: the exact name must be picked.
    [`GET ${RS}/policy?name=fbx-customer-service-client&first=0&max=100`]: [200, [{ id: "pol-x", name: "fbx-customer-service-client-old", type: "client" }, { id: "pol-1", name: "fbx-customer-service-client", type: "client" }]],
    [`GET ${RS}/policy?name=fbx-customers-customer-service&first=0&max=100`]: [200, [{ id: "perm-1", name: "fbx-customers-customer-service", type: "scope" }]],
    [`PUT ${RS}/policy/client/pol-1`]: [201, undefined],
    [`PUT ${RS}/permission/scope/perm-1`]: [201, undefined]
  });
  const result = await applyAdminPermissions({ fetch: f.fetch, baseUrl: BASE, token: "t0k", spec });
  assert.deepEqual(f.writes().map((c) => `${c.method} ${c.url}`), [`PUT ${RS}/policy/client/pol-1`, `PUT ${RS}/permission/scope/perm-1`]);
  assert.equal(f.writes()[0].body.id, "pol-1");
  assert.deepEqual(f.writes()[1].body.resources, ["grp-customers"]);
  assert.deepEqual(f.writes()[1].body.policies, ["pol-1"]);
  assert.deepEqual(result.map((r) => r.action), ["updated", "updated"]);
});

test("an existing object of another type under the same name is an error, not overwritten", async () => {
  const f = fakeFetch({
    ...lookups,
    [`GET ${RS}/policy?name=fbx-customer-service-client&first=0&max=100`]: [200, [{ id: "pol-1", name: "fbx-customer-service-client", type: "role" }]]
  });
  await assert.rejects(applyAdminPermissions({ fetch: f.fetch, baseUrl: BASE, token: "t", spec }), /fbx-customer-service-client exists with type role/);
  assert.deepEqual(f.writes(), []);
});

test("fails without writing when FGAP v2 is off (no admin-permissions client)", async () => {
  const f = fakeFetch({ ...lookups, [`GET ${R}/clients?clientId=admin-permissions`]: [200, []] });
  await assert.rejects(applyAdminPermissions({ fetch: f.fetch, baseUrl: BASE, token: "t", spec }), /adminPermissionsEnabled/);
  assert.deepEqual(f.writes(), []);
});

test("fails without writing when the group or the client is missing", async () => {
  const g = fakeFetch({ ...lookups, [`GET ${R}/group-by-path/customers`]: [404, { error: "Group path does not exist" }] });
  await assert.rejects(applyAdminPermissions({ fetch: g.fetch, baseUrl: BASE, token: "t", spec }), /group \/customers not found/);
  assert.deepEqual(g.writes(), []);
  const c = fakeFetch({ ...lookups, [`GET ${R}/clients?clientId=svc-cus-profile-kyc`]: [200, []] });
  await assert.rejects(applyAdminPermissions({ fetch: c.fetch, baseUrl: BASE, token: "t", spec }), /client svc-cus-profile-kyc not found/);
  assert.deepEqual(c.writes(), []);
});

test("a failed write surfaces the HTTP status", async () => {
  const f = fakeFetch({
    ...lookups,
    [`GET ${RS}/policy?name=fbx-customer-service-client&first=0&max=100`]: [200, []],
    [`POST ${RS}/policy/client`]: [403, { error: "unknown_error" }]
  });
  await assert.rejects(applyAdminPermissions({ fetch: f.fetch, baseUrl: BASE, token: "t", spec }), /POST .*policy\/client -> 403/);
});

test("admin token: client credentials against the login realm, password grant when configured", async () => {
  const f = fakeFetch({ [`POST ${BASE}/realms/master/protocol/openid-connect/token`]: [200, { access_token: "abc" }] });
  const token = await fetchAdminToken({ fetch: f.fetch, env: { KEYCLOAK_URL: BASE + "/", KEYCLOAK_CLIENTID: "boot", KEYCLOAK_CLIENTSECRET: "s", KEYCLOAK_GRANTTYPE: "client_credentials" } });
  assert.equal(token, "abc");
  assert.equal(f.calls[0].headers["Content-Type"], "application/x-www-form-urlencoded");
  const g = fakeFetch({ [`POST ${BASE}/realms/other/protocol/openid-connect/token`]: [200, { access_token: "def" }] });
  const calls = [];
  const spy = async (url, init) => { calls.push(String(init.body)); return g.fetch(url, init); };
  await fetchAdminToken({ fetch: spy, env: { KEYCLOAK_URL: BASE, KEYCLOAK_LOGINREALM: "other", KEYCLOAK_GRANTTYPE: "password", KEYCLOAK_USER: "u", KEYCLOAK_PASSWORD: "<admin-password>" } });
  assert.match(calls[0], /grant_type=password/);
  assert.match(calls[0], /client_id=admin-cli/);
  await assert.rejects(fetchAdminToken({ fetch: spy, env: { KEYCLOAK_URL: BASE } }), /KEYCLOAK_CLIENTID/);
});

test("realm import Job: config-cli first, then the admin-permissions step with only the bootstrap admin credential", async () => {
  const fs = await import("node:fs");
  const YAML = (await import("yaml")).default;
  const job = YAML.parse(fs.readFileSync(new URL("../../../deploy/kustomize/base/realm-import/job.yaml", import.meta.url), "utf8"));
  const pod = job.spec.template.spec;
  // Init containers run in order; the TPP onboarding step comes last.
  assert.deepEqual(pod.initContainers.map((c) => c.name), ["keycloak-config-cli", "admin-permissions"]);
  assert.deepEqual(pod.containers.map((c) => c.name), ["tpp-onboarding"]);
  const step = pod.initContainers[1];
  assert.match(step.image, /^docker\.io\/library\/node:22\.[0-9.]+-alpine[0-9.]*@sha256:[0-9a-f]{64}$/);
  assert.equal(step.envFrom, undefined);
  assert.deepEqual(step.command.slice(-4), ["--spec", "/opt/fbx/spec/admin-permissions.json", "--realm", "/config/fintechbankx-realm.json"]);
  assert.deepEqual(step.env.filter((e) => e.valueFrom.secretKeyRef).map((e) => e.valueFrom.secretKeyRef.key).sort(), ["KEYCLOAK_CLIENTID", "KEYCLOAK_CLIENTSECRET"]);
  assert.equal(step.securityContext.readOnlyRootFilesystem, true);
});

test("scope mappings: realm roles the realm file no longer lists are removed (config-cli never removes them)", async () => {
  const realm = { realm: "fintechbankx", scopeMappings: [
    { client: "fintechbankx-web", roles: ["customer"] },
    { client: "svc-ln-loan-lifecycle", roles: ["service"] },
    { clientScope: "some-scope", roles: ["customer"] }
  ] };
  const f = fakeFetch({
    [`GET ${R}/clients?clientId=fintechbankx-web`]: [200, [{ id: "web-uuid", clientId: "fintechbankx-web" }]],
    [`GET ${R}/clients?clientId=svc-ln-loan-lifecycle`]: [200, [{ id: "ln-uuid", clientId: "svc-ln-loan-lifecycle" }]],
    [`GET ${R}/clients/web-uuid/scope-mappings/realm`]: [200, [{ id: "r1", name: "customer" }, { id: "r2", name: "admin" }, { id: "r3", name: "banker" }]],
    [`GET ${R}/clients/ln-uuid/scope-mappings/realm`]: [200, [{ id: "r4", name: "service" }]],
    [`DELETE ${R}/clients/web-uuid/scope-mappings/realm`]: [204, undefined]
  });
  const result = await reconcileScopeMappings({ fetch: f.fetch, baseUrl: BASE, token: "t0k", realm });
  assert.deepEqual(f.writes().map((c) => `${c.method} ${c.url}`), [`DELETE ${R}/clients/web-uuid/scope-mappings/realm`]);
  assert.deepEqual(f.writes()[0].body, [{ id: "r2", name: "admin" }, { id: "r3", name: "banker" }]);
  assert.deepEqual(result, [{ client: "fintechbankx-web", removed: ["admin", "banker"] }]);
});

test("scope mappings: a client of the realm file missing in Keycloak is an error", async () => {
  const f = fakeFetch({ [`GET ${R}/clients?clientId=fintechbankx-web`]: [200, []] });
  await assert.rejects(reconcileScopeMappings({ fetch: f.fetch, baseUrl: BASE, token: "t", realm: { realm: "fintechbankx", scopeMappings: [{ client: "fintechbankx-web", roles: ["customer"] }] } }), /client fintechbankx-web not found/);
});

// Review finding (minor): with --realm <file> the scope mappings were
// reconciled in that file's realm and the admin permissions written to the
// spec's realm. The CLI now refuses (exit 2) before any request when the two
// differ. Run as the Job runs it, against the fake admin API above served on a
// local port, with routes that would let both steps write.
async function runCli(routes, files) {
  const os = await import("node:os");
  const fs = await import("node:fs");
  const path = await import("node:path");
  const http = await import("node:http");
  const { execFile } = await import("node:child_process");
  const { promisify } = await import("node:util");
  const f = fakeFetch(routes);
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const body = chunks.length ? Buffer.concat(chunks).toString() : undefined;
      const r = await f.fetch(`${BASE}${req.url}`, { method: req.method, headers: { "Content-Type": req.headers["content-type"], Authorization: req.headers.authorization }, body });
      res.writeHead(r.status, { "content-type": "application/json" });
      res.end(await r.text());
    });
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "admin-permissions-"));
  try {
    const args = [new URL("../../realm/apply-admin-permissions.mjs", import.meta.url).pathname];
    for (const [flag, json] of files) {
      const file = path.join(dir, `${flag.slice(2)}.json`);
      fs.writeFileSync(file, JSON.stringify(json));
      args.push(flag, file);
    }
    const env = { PATH: process.env.PATH, KEYCLOAK_URL: `http://127.0.0.1:${server.address().port}`, KEYCLOAK_CLIENTID: "boot", KEYCLOAK_CLIENTSECRET: "s" };
    try {
      const { stdout, stderr } = await promisify(execFile)(process.execPath, args, { env, encoding: "utf8" });
      return { code: 0, stdout, stderr, f };
    } catch (e) {
      return { code: e.code, stdout: e.stdout, stderr: e.stderr, f };
    }
  } finally {
    server.close();
    fs.rmSync(dir, { recursive: true });
  }
}

test("--realm naming another realm than the spec is refused (exit 2) before any request, so nothing is written", async () => {
  const OTHER = `${BASE}/admin/realms/other`;
  const routes = {
    [`POST ${BASE}/realms/master/protocol/openid-connect/token`]: [200, { access_token: "t0k" }],
    [`GET ${OTHER}/clients?clientId=fintechbankx-web`]: [200, [{ id: "web-uuid", clientId: "fintechbankx-web" }]],
    [`GET ${OTHER}/clients/web-uuid/scope-mappings/realm`]: [200, [{ id: "r1", name: "customer" }, { id: "r2", name: "admin" }]],
    [`DELETE ${OTHER}/clients/web-uuid/scope-mappings/realm`]: [204, undefined],
    ...lookups,
    [`GET ${RS}/policy?name=fbx-customer-service-client&first=0&max=100`]: [200, []],
    [`GET ${RS}/policy?name=fbx-customers-customer-service&first=0&max=100`]: [200, []],
    [`POST ${RS}/policy/client`]: [201, { id: "pol-1" }],
    [`POST ${RS}/permission/scope`]: [201, { id: "perm-1" }]
  };
  const realmFile = { realm: "other", scopeMappings: [{ client: "fintechbankx-web", roles: ["customer"] }] };
  const r = await runCli(routes, [["--spec", spec], ["--realm", realmFile]]);
  assert.deepEqual(r.f.writes().map((c) => `${c.method} ${c.url}`), [], `writes sent: ${r.stdout}`);
  assert.equal(r.code, 2, r.stdout + r.stderr);
  assert.match(r.stderr, /admin-permissions: --realm file is realm other but the spec is realm fintechbankx/);
  assert.deepEqual(r.f.calls, []);
  // The same realm in both: both steps run.
  const ok = await runCli(routes, [["--spec", spec], ["--realm", { ...realmFile, realm: "fintechbankx" }]]);
  assert.equal(ok.code, 1, ok.stdout + ok.stderr); // the fake answers realm other only
  assert.match(ok.stderr, /GET .*\/admin\/realms\/fintechbankx\/clients\?clientId=fintechbankx-web -> 404/);
});

test("realm import Job: last step onboards the TPP list and fails on any non-conforming open-finance-tpp client or service-client rule, with only the bootstrap admin credential", async () => {
  const fs = await import("node:fs");
  const YAML = (await import("yaml")).default;
  const read = (p) => fs.readFileSync(new URL(`../../../${p}`, import.meta.url), "utf8");
  const pod = YAML.parse(read("deploy/kustomize/base/realm-import/job.yaml")).spec.template.spec;
  const step = pod.containers.find((c) => c.name === "tpp-onboarding");
  assert.equal(step.image, pod.initContainers.find((c) => c.name === "admin-permissions").image);
  assert.deepEqual(step.command, ["node", "/opt/fbx/script/onboard-tpp.mjs", "--tpps", "/opt/fbx/tpps/tpp-clients.json", "--realm", "/config/fintechbankx-realm.json", "--verify-live", "--registry", "/opt/fbx/registry/service-clients.json"]);
  assert.equal(step.envFrom, undefined);
  assert.deepEqual(step.env.filter((e) => e.valueFrom.secretKeyRef).map((e) => e.valueFrom.secretKeyRef.key).sort(), ["KEYCLOAK_CLIENTID", "KEYCLOAK_CLIENTSECRET"]);
  assert.equal(step.securityContext.readOnlyRootFilesystem, true);
  const mounts = Object.fromEntries(step.volumeMounts.map((m) => [m.mountPath, m.name]));
  assert.deepEqual(mounts, { "/opt/fbx/script": "admin-permissions-script", "/opt/fbx/tpps": "tpp-clients", "/opt/fbx/registry": "service-clients", "/config": "realm" });
  const vols = Object.fromEntries(pod.volumes.filter((v) => v.configMap).map((v) => [v.name, v.configMap.name]));
  assert.equal(vols["tpp-clients"], "fintechbankx-realm-tpp-clients");
  assert.equal(vols["service-clients"], "fintechbankx-realm-service-clients");
  // The script ConfigMap carries the onboarding script and its dependency-free rules and live view.
  const scripts = YAML.parse(read("scripts/realm/kustomization.yaml")).configMapGenerator[0];
  assert.equal(scripts.name, vols["admin-permissions-script"]);
  assert.deepEqual([...scripts.files].sort(), ["apply-admin-permissions.mjs", "live-view.mjs", "onboard-tpp.mjs", "service-client-rules.mjs", "tpp-rules.mjs"]);
  const realmCm = YAML.parse(read("realm/kustomization.yaml")).configMapGenerator.find((g) => g.name === "fintechbankx-realm-tpp-clients");
  assert.deepEqual(realmCm.files, ["tpp-clients.json"]);
  // The node:alpine image has no node_modules: the Job's scripts import Node built-ins and each other only.
  for (const f of scripts.files) {
    for (const m of read(`scripts/realm/${f}`).matchAll(/^import .* from "([^"]+)";$/gm)) assert.ok(m[1].startsWith("node:") || m[1].startsWith("./"), `${f} imports ${m[1]}`);
  }
});
