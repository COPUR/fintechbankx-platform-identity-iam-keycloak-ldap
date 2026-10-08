import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkRealm, loadFromRepo, secretEnvName } from "../../ci/check-realm.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const fresh = () => structuredClone(loadFromRepo(root));
const client = (input, id) => input.realm.clients.find((c) => c.clientId === id);

test("committed realm passes the gate", () => {
  assert.deepEqual(checkRealm(fresh()), []);
});

test("every service client from the registry is in the realm", () => {
  const input = fresh();
  input.realm.clients = input.realm.clients.filter((c) => c.clientId !== "svc-rsk-decisioning");
  assert.ok(checkRealm(input).some((e) => e.includes("svc-rsk-decisioning missing")));
});

test("a literal client secret is rejected", () => {
  const input = fresh();
  client(input, "svc-ln-loan-lifecycle").secret = "s3cr3t-value-in-git";
  const errors = checkRealm(input);
  assert.ok(errors.some((e) => e.includes("clients.0.secret must be a $(env:NAME) placeholder")));
});

test("a literal LDAP bind credential is rejected", () => {
  const input = fresh();
  input.realm.components["org.keycloak.storage.UserStorageProvider"][0].config.bindCredential = ["plain"];
  assert.ok(checkRealm(input).some((e) => e.includes("LDAP bindCredential")));
});

test("service clients must stay client-credentials only", () => {
  const input = fresh();
  client(input, "svc-cmp-evidence").directAccessGrantsEnabled = true;
  assert.ok(checkRealm(input).some((e) => e.includes("svc-cmp-evidence: directAccessGrantsEnabled must be false")));
});

test("audience mappers must match the registry", () => {
  const input = fresh();
  client(input, "svc-ln-loan-lifecycle").protocolMappers = [];
  assert.ok(checkRealm(input).some((e) => e.startsWith("svc-ln-loan-lifecycle: audience mappers <none>")));
  const input2 = fresh();
  client(input2, "fintechbankx-web").protocolMappers.pop();
  assert.ok(checkRealm(input2).some((e) => e.startsWith("fintechbankx-web: audience mappers")));
});

test("roles must be exactly the contract set", () => {
  const input = fresh();
  input.realm.roles.realm.push({ name: "superuser" });
  assert.ok(checkRealm(input).some((e) => e.startsWith("realm roles must be")));
});

test("FAPI 2.0 TPP policies are required", () => {
  const input = fresh();
  input.realm.clientPolicies.policies = input.realm.clientPolicies.policies.filter((p) => !p.profiles.includes("fapi-2-dpop-security-profile"));
  assert.ok(checkRealm(input).some((e) => e.includes("fapi-2-dpop-security-profile")));
});

test("each placeholder must be supplied by the import Job", () => {
  const input = fresh();
  input.importSecretKeys = input.importSecretKeys.filter((k) => k !== secretEnvName("svc-of-atm-directory"));
  const errors = checkRealm(input);
  assert.ok(errors.some((e) => e.includes("FBX_OIDC_SECRET_SVC_OF_ATM_DIRECTORY is not supplied")));
});

test("LDAP federation must stay read-only", () => {
  const input = fresh();
  input.realm.components["org.keycloak.storage.UserStorageProvider"][0].config.editMode = ["WRITABLE"];
  assert.ok(checkRealm(input).some((e) => e.includes("READ_ONLY")));
});

test("the import Job reads each credential from <env>/<service-slug>/oidc-client", () => {
  const input = fresh();
  input.importSecretRefs[secretEnvName("svc-cus-profile-kyc")] = "ENVIRONMENT/customer/oidc-client";
  assert.ok(checkRealm(input).some((e) => e.includes("must read ENVIRONMENT/customer-profile-kyc-service/oidc-client")));
});

test("the committed realm JSON is the render of the registry", async () => {
  const { execFileSync } = await import("node:child_process");
  execFileSync(process.execPath, [path.join(root, "scripts/realm/render-realm.mjs"), "--check"], { stdio: "pipe" });
});

test("the Grafana SSO client exposes roles in userinfo and stays code + PKCE", () => {
  const input = fresh();
  const g = client(input, "svc-obs-grafana");
  g.protocolMappers = [];
  g.directAccessGrantsEnabled = true;
  const errors = checkRealm(input);
  assert.ok(errors.some((e) => e.includes("svc-obs-grafana: realm_access.roles mapper")));
  assert.ok(errors.some((e) => e.includes("svc-obs-grafana: directAccessGrantsEnabled must be false")));
  const input2 = fresh();
  input2.importSecretRefs[secretEnvName("svc-obs-grafana")] = "ENVIRONMENT/grafana/oidc-client";
  assert.ok(checkRealm(input2).some((e) => e.includes("must read ENVIRONMENT/observability-grafana/oidc-client")));
});

test("no service client holds a realm-management role", () => {
  const input = fresh();
  for (const u of input.realm.users) assert.equal(u.clientRoles?.["realm-management"], undefined, u.username);
  assert.equal(input.realm.clientScopeMappings?.["realm-management"], undefined);
  for (const c of input.registry.clients) assert.equal(c.adminRoles, undefined, c.clientId);
});

test("a realm-management role on a service client is rejected", () => {
  const input = fresh();
  input.realm.users.find((u) => u.serviceAccountClientId === "svc-cus-profile-kyc").clientRoles = { "realm-management": ["view-users"] };
  assert.ok(checkRealm(input).some((e) => e.includes("svc-cus-profile-kyc: service account must not hold realm-management roles")));
  const input2 = fresh();
  input2.realm.clientScopeMappings = { "realm-management": [{ client: "svc-ln-loan-lifecycle", roles: ["query-users"] }] };
  assert.ok(checkRealm(input2).some((e) => e.includes("svc-ln-loan-lifecycle: realm-management scope mapping is not allowed")));
  const input3 = fresh();
  input3.registry.clients.find((c) => c.clientId === "svc-cus-profile-kyc").adminRoles = ["manage-users"];
  assert.ok(checkRealm(input3).some((e) => e.includes("svc-cus-profile-kyc: registry adminRoles are not allowed")));
});

test("fine-grained admin permissions v2 are on and the realm has no default groups", () => {
  const input = fresh();
  assert.equal(input.realm.adminPermissionsEnabled, true);
  input.realm.adminPermissionsEnabled = false;
  input.realm.defaultGroups = ["/customers"];
  const errors = checkRealm(input);
  assert.ok(errors.some((e) => e.includes("adminPermissionsEnabled must be true")));
  assert.ok(errors.some((e) => e.includes("defaultGroups must be empty")));
});

test("the customer service may only view and manage members of /customers", () => {
  const input = fresh();
  const [p] = input.adminPermissions.permissions;
  assert.equal(p.name, "fbx-customers-customer-service");
  assert.deepEqual(p.groupPaths, ["/customers"]);
  assert.deepEqual(p.policy, { name: "fbx-customer-service-client", type: "client", logic: "POSITIVE", clients: ["svc-cus-profile-kyc"] });
  assert.ok(input.realm.groups.some((g) => g.path === "/customers"));
  const mutate = (fn, expected) => {
    const i = fresh();
    fn(i.adminPermissions.permissions[0]);
    const errors = checkRealm(i);
    assert.ok(errors.some((e) => e.includes(expected)), `${expected} not in ${errors.join("; ")}`);
  };
  mutate((x) => { x.groupPaths = ["/staff"]; }, "fbx-customers-customer-service: group /staff must not be a staff group");
  mutate((x) => { x.groupPaths = ["/nobody"]; }, "fbx-customers-customer-service: group /nobody is not in the realm");
  mutate((x) => { x.resourceType = "Users"; }, "fbx-customers-customer-service: resourceType must be Groups");
  mutate((x) => { x.scopes.push("impersonate-members"); }, "fbx-customers-customer-service: scope impersonate-members is not allowed");
  mutate((x) => { x.policy.clients = ["fintechbankx-web"]; }, "fbx-customers-customer-service: policy client fintechbankx-web is not a service client");
  mutate((x) => { x.decisionStrategy = "AFFIRMATIVE"; }, "fbx-customers-customer-service: decisionStrategy must be UNANIMOUS");
  mutate((x) => { delete x.reason; }, "fbx-customers-customer-service: reason required");
});

test("payment initiation tokens carry the customer audience (kyc-status call)", () => {
  const input = fresh();
  const auds = client(input, "svc-pay-initiation-settlement").protocolMappers
    .filter((m) => m.protocolMapper === "oidc-audience-mapper")
    .map((m) => m.config["included.client.audience"]);
  assert.ok(auds.includes("svc-cus-profile-kyc"), auds.join(","));
  const entry = input.registry.clients.find((c) => c.clientId === "svc-pay-initiation-settlement");
  assert.match(entry.audienceProvenance["svc-cus-profile-kyc"], /^confirmed by customer thread 2026-10-08/);
});

const STAFF = ["admin", "auditor", "banker", "compliance_officer", "loan_officer"];
const scopeRoles = (input, id) => [...(input.realm.scopeMappings.find((s) => s.client === id)?.roles || [])].sort();
const auds = (input, id) => client(input, id).protocolMappers.filter((m) => m.protocolMapper === "oidc-audience-mapper").map((m) => m.config["included.client.audience"]).sort();

test("customer channels map only customer; the staff web client maps only staff roles", () => {
  const input = fresh();
  assert.deepEqual(scopeRoles(input, "fintechbankx-web"), ["customer"]);
  assert.deepEqual(scopeRoles(input, "fintechbankx-mobile"), ["customer"]);
  assert.deepEqual(scopeRoles(input, "fintechbankx-staff-web"), STAFF);
  input.realm.scopeMappings.find((s) => s.client === "fintechbankx-web").roles.push("admin");
  assert.ok(checkRealm(input).some((e) => e.includes("fintechbankx-web: scope mapping admin,customer != customer")));
  const input2 = fresh();
  input2.realm.scopeMappings.find((s) => s.client === "fintechbankx-staff-web").roles.push("customer");
  assert.ok(checkRealm(input2).some((e) => e.startsWith("fintechbankx-staff-web: scope mapping")));
});

test("risk and compliance audiences moved from the customer web client to staff web", () => {
  const input = fresh();
  for (const a of ["svc-rsk-decisioning", "svc-cmp-evidence"]) {
    assert.ok(!auds(input, "fintechbankx-web").includes(a));
    assert.ok(!auds(input, "fintechbankx-mobile").includes(a));
    assert.ok(auds(input, "fintechbankx-staff-web").includes(a));
  }
  for (const a of ["svc-ln-loan-lifecycle", "svc-cus-profile-kyc", "svc-pay-initiation-settlement"]) assert.ok(auds(input, "fintechbankx-staff-web").includes(a));
  input.registry.channelClients.find((c) => c.clientId === "fintechbankx-web").audiences.push("svc-cmp-evidence");
  assert.ok(checkRealm(input).some((e) => e.includes("fintechbankx-web: staff-only audience svc-cmp-evidence on a customer client")));
});

test("staff web: short sessions, no optional scopes, no customer-id scope", () => {
  const input = fresh();
  const c = client(input, "fintechbankx-staff-web");
  assert.deepEqual(c.optionalClientScopes, []);
  assert.ok(!c.defaultClientScopes.includes("customer-id"));
  assert.equal(c.attributes["client.session.idle.timeout"], "900");
  assert.equal(c.attributes["client.session.max.lifespan"], "28800");
  assert.equal(c.publicClient, true);
  assert.equal(c.attributes["pkce.code.challenge.method"], "S256");
  c.optionalClientScopes = ["offline_access"];
  c.defaultClientScopes.push("customer-id");
  c.attributes["client.session.idle.timeout"] = "3600";
  const errors = checkRealm(input);
  assert.ok(errors.some((e) => e.includes("fintechbankx-staff-web: offline_access is not allowed")));
  assert.ok(errors.some((e) => e.includes("fintechbankx-staff-web: staff clients must not carry the customer-id scope")));
  assert.ok(errors.some((e) => e.includes("fintechbankx-staff-web: client.session.idle.timeout must be 1..900")));
});

test("offline tokens: mobile only, 14 days idle, 30 days max", () => {
  const input = fresh();
  assert.deepEqual(client(input, "fintechbankx-web").optionalClientScopes, []);
  assert.ok(!client(input, "fintechbankx-web").defaultClientScopes.includes("offline_access"));
  const m = client(input, "fintechbankx-mobile");
  assert.deepEqual(m.optionalClientScopes, ["offline_access"]);
  assert.equal(m.attributes["client.offline.session.idle.timeout"], "1209600");
  assert.equal(m.attributes["client.offline.session.max.lifespan"], "2592000");
  assert.equal(input.realm.offlineSessionIdleTimeout, 1209600);
  assert.equal(input.realm.offlineSessionMaxLifespan, 2592000);
  assert.equal(input.realm.offlineSessionMaxLifespanEnabled, true);
  client(input, "fintechbankx-web").optionalClientScopes = ["offline_access"];
  input.realm.offlineSessionMaxLifespan = 5184000;
  const errors = checkRealm(input);
  assert.ok(errors.some((e) => e.includes("fintechbankx-web: offline_access is not allowed")));
  assert.ok(errors.some((e) => e.includes("offlineSessionMaxLifespan must be 1..2592000")));
});

test("every overlay sets the staff web redirect, origin and post-logout URIs", async () => {
  const fs = await import("node:fs");
  const env = fresh().importEnv;
  for (const k of ["FBX_STAFF_WEB_REDIRECT_URI", "FBX_STAFF_WEB_ORIGIN", "FBX_STAFF_WEB_POST_LOGOUT_REDIRECT_URI"]) {
    assert.ok(k in env, k);
    for (const o of ["dev", "staging", "prod"]) {
      const text = fs.readFileSync(path.join(root, `deploy/kustomize/overlays/${o}/kustomization.yaml`), "utf8");
      assert.ok(text.includes(`path: /data/${k}`), `${o} lacks ${k}`);
    }
  }
});
