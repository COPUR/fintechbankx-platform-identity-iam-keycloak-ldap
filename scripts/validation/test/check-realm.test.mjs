import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import * as realmCheck from "../../ci/check-realm.mjs";
const { checkRealm, loadFromRepo, secretEnvName } = realmCheck;
const tppClientErrors = (...args) => realmCheck.tppClientErrors(...args);

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
  // Explicit empty lists, not absent keys: keycloak-config-cli only removes a
  // user's client roles for clients listed in clientRoles, and skips
  // client-scope-mapping cleanup when clientScopeMappings is absent.
  for (const u of input.realm.users) assert.deepEqual(u.clientRoles, { "realm-management": [] }, u.username);
  assert.deepEqual(input.realm.clientScopeMappings, {});
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

test("service accounts list realm-management: [] and the realm lists clientScopeMappings, so removals reach existing realms", () => {
  const input = fresh();
  delete input.realm.users.find((u) => u.serviceAccountClientId === "svc-ln-loan-lifecycle").clientRoles;
  delete input.realm.clientScopeMappings;
  const errors = checkRealm(input);
  assert.ok(errors.some((e) => e.includes("svc-ln-loan-lifecycle: service account must list clientRoles realm-management: []")));
  assert.ok(errors.some((e) => e.includes("clientScopeMappings must be present")));
});

test("TPP tokens are DPoP-bound only: no mTLS-bound policy, profile or client", () => {
  const input = fresh();
  const policies = input.realm.clientPolicies.policies;
  assert.ok(!policies.some((p) => p.name === "fbx-open-finance-tpp-fapi2-mtls"));
  assert.ok(!policies.some((p) => (p.profiles || []).includes("fapi-2-security-profile")));
  assert.ok(!JSON.stringify(input.realm).includes('"value":"mtls"'));
  const mutate = (fn, expected) => {
    const i = fresh();
    fn(i);
    const errors = checkRealm(i);
    assert.ok(errors.some((e) => e.includes(expected)), `${expected} not in ${errors.join("; ")}`);
  };
  mutate((i) => { client(i, "of-tpp-conformance-template").attributes["fbx.tpp.token-binding"] = "mtls"; }, "of-tpp-conformance-template: fbx.tpp.token-binding must be dpop");
  mutate((i) => { client(i, "of-tpp-conformance-template").attributes["tls.client.certificate.bound.access.tokens"] = "true"; }, "of-tpp-conformance-template: certificate-bound tokens are not supported");
  mutate((i) => { client(i, "svc-ln-loan-lifecycle").attributes["tls.client.certificate.bound.access.tokens"] = "true"; }, "svc-ln-loan-lifecycle: certificate-bound tokens are not supported");
  mutate((i) => { i.realm.clientPolicies.policies.push({ name: "x", enabled: true, conditions: [{ condition: "client-attributes", configuration: { attributes: JSON.stringify([{ key: "fbx.tpp.token-binding", value: "mtls" }]) } }], profiles: ["fapi-2-security-profile"] }); }, "client policy x: mTLS-bound tokens are not supported");
  mutate((i) => { i.realm.clientPolicies.policies.push({ name: "y", enabled: true, conditions: [{ condition: "client-attributes", configuration: { attributes: JSON.stringify([{ key: "fbx.tpp.token-binding", value: "mtls" }]) } }], profiles: ["fapi-2-dpop-security-profile"] }); }, "client policy y: mTLS-bound tokens are not supported");
  mutate((i) => { i.realm.clientPolicies.policies.push({ name: "z", enabled: true, conditions: [], profiles: ["fapi-2-security-profile"] }); }, "client policy z: mTLS-bound tokens are not supported");
});

test("no client may authenticate with client-x509 (TLS ends before Keycloak)", () => {
  const input = fresh();
  const authenticators = input.realm.clientProfiles.profiles.flatMap((p) => p.executors)
    .filter((e) => e.executor === "secure-client-authenticator")
    .flatMap((e) => e.configuration["allowed-client-authenticators"]);
  assert.ok(!authenticators.includes("client-x509"));
  input.realm.clientProfiles.profiles[0].executors[0].configuration["allowed-client-authenticators"].push("client-x509");
  client(input, "svc-cmp-evidence").clientAuthenticatorType = "client-x509";
  const errors = checkRealm(input);
  assert.ok(errors.some((e) => e.includes("client profile fbx-service-client-baseline: client-x509 is not allowed")));
  assert.ok(errors.some((e) => e.includes("svc-cmp-evidence: clientAuthenticatorType client-x509 is not allowed")));
});

test("TPP policies add a private_key_jwt-only client authentication profile", () => {
  const input = fresh();
  const prof = input.realm.clientProfiles.profiles.find((p) => p.name === "fbx-open-finance-tpp-client-auth");
  assert.deepEqual(prof.executors[0].configuration["allowed-client-authenticators"], ["client-jwt"]);
  for (const name of ["fbx-open-finance-tpp-fapi2-dpop", "fbx-open-finance-tpp-dynamic-registration"]) {
    const p = input.realm.clientPolicies.policies.find((x) => x.name === name);
    assert.deepEqual(p.profiles, ["fapi-2-dpop-security-profile", "fbx-open-finance-tpp-client-auth"]);
  }
});

test("only callers with a consent mesh edge carry the consent audience (bulk and mandates)", () => {
  const input = fresh();
  const callers = input.registry.clients
    .filter((c) => (c.audiences || []).includes("svc-of-consent-authorization"))
    .map((c) => c.clientId)
    .sort();
  assert.deepEqual(callers, ["svc-pay-bulk-orchestration", "svc-pay-recurring-mandates"]);
});

test("the TPP DPoP policy matches every open-finance TPP client, not only those tagged with the binding", () => {
  const input = fresh();
  const policies = input.realm["client-policies"]?.policies || input.realm.clientPolicies?.policies || [];
  const tpp = policies.filter((p) => JSON.stringify(p.conditions || []).includes("open-finance-tpp"));
  assert.ok(tpp.length > 0);
  for (const p of tpp) {
    for (const c of p.conditions.filter((x) => x.condition === "client-attributes")) {
      const attrs = JSON.parse(c.configuration.attributes);
      assert.deepEqual(attrs.map((a) => a.key), ["fbx.client-type"], p.name);
    }
  }
});

// Request-to-pay PR #14 (runbook section 2, ADR-030 open question 2): TPP
// calls need scope payments in the token; the client type may travel as claim
// fbx_client_type so the service can require open-finance-tpp.
const scope = (input, name) => (input.realm.clientScopes || []).find((s) => s.name === name);

test("realm defines client scope payments, named in the token scope claim", () => {
  const s = scope(fresh(), "payments");
  assert.ok(s, "client scope payments missing");
  assert.equal(s.protocol, "openid-connect");
  assert.equal(s.attributes["include.in.token.scope"], "true");
  assert.deepEqual(s.protocolMappers || [], [], "payments grants a scope value only, no claims");
});

test("TPP clients carry payments as an optional scope; it is never a realm default", () => {
  const input = fresh();
  const tpp = client(input, "of-tpp-conformance-template");
  assert.ok(tpp.optionalClientScopes.includes("payments"));
  assert.ok(!tpp.defaultClientScopes.includes("payments"), "payments is requested by the TPP, not granted by default");
  assert.ok(!(input.realm.defaultDefaultClientScopes || []).includes("payments"));
  assert.ok(!(input.realm.defaultOptionalClientScopes || []).includes("payments"));
  for (const c of input.realm.clients) {
    if (c.attributes?.["fbx.client-type"] === "open-finance-tpp") continue;
    assert.ok(![...(c.defaultClientScopes || []), ...(c.optionalClientScopes || [])].includes("payments"), `${c.clientId} must not carry payments`);
  }
  const missing = fresh();
  client(missing, "of-tpp-conformance-template").optionalClientScopes = [];
  assert.ok(checkRealm(missing).some((e) => e === "of-tpp-conformance-template: TPP clients must carry the payments scope (optional)"));
  const onWeb = fresh();
  client(onWeb, "fintechbankx-web").optionalClientScopes.push("payments");
  assert.ok(checkRealm(onWeb).some((e) => e === "fintechbankx-web: scope payments is for open-finance TPP clients only"));
});

test("TPP tokens carry fbx_client_type equal to the client attribute fbx.client-type", () => {
  const input = fresh();
  const s = scope(input, "fbx-client-type-open-finance-tpp");
  assert.ok(s, "client scope fbx-client-type-open-finance-tpp missing");
  assert.equal(s.attributes["include.in.token.scope"], "false");
  const [m] = s.protocolMappers;
  assert.equal(s.protocolMappers.length, 1);
  assert.equal(m.protocolMapper, "oidc-hardcoded-claim-mapper");
  assert.equal(m.config["claim.name"], "fbx_client_type");
  assert.equal(m.config["claim.value"], "open-finance-tpp");
  assert.equal(m.config["access.token.claim"], "true");
  assert.equal(m.config["introspection.token.claim"], "true");
  assert.equal(m.config["id.token.claim"], "false");
  const tpp = client(input, "of-tpp-conformance-template");
  assert.ok(tpp.defaultClientScopes.includes("fbx-client-type-open-finance-tpp"));
  assert.equal(tpp.attributes["fbx.client-type"], m.config["claim.value"]);
  // A client of another type must never carry it (it would claim to be a TPP).
  const wrong = fresh();
  client(wrong, "svc-pay-request-to-pay").defaultClientScopes.push("fbx-client-type-open-finance-tpp");
  assert.ok(checkRealm(wrong).some((e) => e === "svc-pay-request-to-pay: scope fbx-client-type-open-finance-tpp emits fbx_client_type=open-finance-tpp but the client is fbx.client-type=service"));
  const realmDefault = fresh();
  realmDefault.realm.defaultDefaultClientScopes.push("fbx-client-type-open-finance-tpp");
  assert.ok(checkRealm(realmDefault).some((e) => e === "client scope fbx-client-type-open-finance-tpp must not be a realm default scope"));
  const drift = fresh();
  scope(drift, "fbx-client-type-open-finance-tpp").protocolMappers[0].config["claim.value"] = "service";
  assert.ok(checkRealm(drift).some((e) => e.startsWith("of-tpp-conformance-template: scope fbx-client-type-open-finance-tpp emits fbx_client_type=service")));
});

// Review re-check: the claim is mandatory on every TPP client, so the service
// can fail closed when fbx_client_type is absent.
const emitsClientType = (input, c) => {
  const scopes = new Map((input.realm.clientScopes || []).map((s) => [s.name, s]));
  const viaScopes = (c.defaultClientScopes || []).flatMap((n) => scopes.get(n)?.protocolMappers || []);
  return [...viaScopes, ...(c.protocolMappers || [])].some(
    (m) => m.config?.["claim.name"] === "fbx_client_type" && m.config?.["claim.value"] === c.attributes?.["fbx.client-type"] && m.config?.["access.token.claim"] === "true"
  );
};

test("every client tagged fbx.client-type=open-finance-tpp emits fbx_client_type by default", () => {
  const input = fresh();
  const tpps = input.realm.clients.filter((c) => c.attributes?.["fbx.client-type"] === "open-finance-tpp");
  assert.ok(tpps.length >= 1, "the TPP template must exist");
  for (const c of tpps) assert.ok(emitsClientType(input, c), `${c.clientId} must emit fbx_client_type`);
  // Any further TPP client (e.g. one added to the realm by hand) without the scope fails the gate.
  const extra = fresh();
  const copy = structuredClone(client(extra, "of-tpp-conformance-template"));
  copy.clientId = "of-tpp-extra";
  copy.defaultClientScopes = copy.defaultClientScopes.filter((s) => s !== "fbx-client-type-open-finance-tpp");
  extra.realm.clients.push(copy);
  extra.registry.channelClients.push({ ...extra.registry.channelClients.find((c) => c.clientId === "of-tpp-conformance-template"), clientId: "of-tpp-extra" });
  assert.ok(checkRealm(extra).some((e) => e === "of-tpp-extra: TPP clients must carry a default scope emitting fbx_client_type=open-finance-tpp"));
  // As an optional scope it would only appear when requested: not enough.
  const optional = fresh();
  const t = client(optional, "of-tpp-conformance-template");
  t.defaultClientScopes = t.defaultClientScopes.filter((s) => s !== "fbx-client-type-open-finance-tpp");
  t.optionalClientScopes.push("fbx-client-type-open-finance-tpp");
  assert.ok(checkRealm(optional).some((e) => e === "of-tpp-conformance-template: TPP clients must carry a default scope emitting fbx_client_type=open-finance-tpp"));
});

// TPP client-type guarantee (identity owns TPP onboarding): every client
// tagged fbx.client-type=open-finance-tpp carries the named client-type
// scope as a default scope, payments only as an optional scope, and DPoP as
// its token binding; no client may emit fbx_client_type through its own mapper.
const TYPE_SCOPE = "fbx-client-type-open-finance-tpp";
const extraTpp = (input, id, registryType) => {
  const copy = structuredClone(client(input, "of-tpp-conformance-template"));
  copy.clientId = id;
  input.realm.clients.push(copy);
  input.registry.channelClients.push({ ...input.registry.channelClients.find((c) => c.clientId === "of-tpp-conformance-template"), clientId: id, type: registryType });
  return copy;
};
const failsWith = (input, expected) => {
  const errors = checkRealm(input);
  assert.ok(errors.includes(expected), `${expected} not in ${errors.join("; ")}`);
};

test("TPP guarantee: payments is optional only, never a default scope of a TPP client", () => {
  const input = fresh();
  client(input, "of-tpp-conformance-template").defaultClientScopes.push("payments");
  failsWith(input, "of-tpp-conformance-template: payments must be an optional scope of open-finance-tpp clients, never a default scope");
});

test("TPP guarantee: the client-type scope is required by name, not only by an equivalent claim", () => {
  const input = fresh();
  const alias = structuredClone(scope(input, TYPE_SCOPE));
  alias.name = "fbx-tpp-alias";
  input.realm.clientScopes.push(alias);
  const t = client(input, "of-tpp-conformance-template");
  t.defaultClientScopes = t.defaultClientScopes.map((s) => (s === TYPE_SCOPE ? "fbx-tpp-alias" : s));
  failsWith(input, `of-tpp-conformance-template: open-finance-tpp clients must carry client scope ${TYPE_SCOPE} as a default scope`);
});

test("TPP guarantee: DPoP binding is required on every client tagged open-finance-tpp, whatever its registry type", () => {
  const input = fresh();
  const c = extraTpp(input, "of-tpp-partner", "partner");
  delete c.attributes["fbx.tpp.token-binding"];
  failsWith(input, "of-tpp-partner: open-finance-tpp clients must set fbx.tpp.token-binding=dpop");
});

test("TPP guarantee: a registry TPP entry must be tagged fbx.client-type=open-finance-tpp", () => {
  const input = fresh();
  delete client(input, "of-tpp-conformance-template").attributes["fbx.client-type"];
  failsWith(input, "of-tpp-conformance-template: registry type open-finance-tpp requires attribute fbx.client-type=open-finance-tpp");
});

test("TPP guarantee: no client emits fbx_client_type through its own protocol mapper", () => {
  const input = fresh();
  client(input, "fintechbankx-web").protocolMappers.push({
    name: "forged", protocol: "openid-connect", protocolMapper: "oidc-hardcoded-claim-mapper",
    config: { "claim.name": "fbx_client_type", "claim.value": "open-finance-tpp", "access.token.claim": "true" }
  });
  failsWith(input, `fintechbankx-web: fbx_client_type may only come from a client scope (found client mapper forged)`);
});

test("TPP guarantee: the committed TPP template satisfies the shared onboarding rules", () => {
  const input = fresh();
  assert.deepEqual(tppClientErrors(client(input, "of-tpp-conformance-template")), []);
});

// Dynamic Client Registration is closed: the onboarding script is the only
// runtime path for TPP clients (Keycloak 26.7.5, checked locally: an initial
// access token could otherwise register a client tagged open-finance-tpp
// without the client-type scope).
const DCR = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy";
const dcrPolicies = (input) => input.realm.components[DCR] || [];

test("DCR: a client policy rejects every registration by initial access token, registration access token or anonymously", () => {
  const input = fresh();
  const p = input.realm.clientPolicies.policies.find((x) => x.name === "fbx-dynamic-client-registration-closed");
  assert.ok(p, "policy fbx-dynamic-client-registration-closed missing");
  assert.equal(p.enabled, true);
  assert.deepEqual(p.conditions, [{ condition: "client-updater-context", configuration: { is_negative_logic: false, "update-client-source": ["ByAnonymous", "ByInitialAccessToken", "ByRegistrationAccessToken"] } }]);
  assert.deepEqual(p.profiles, ["fbx-reject-request"]);
  const prof = input.realm.clientProfiles.profiles.find((x) => x.name === "fbx-reject-request");
  assert.deepEqual(prof.executors, [{ executor: "reject-request", configuration: {} }]);
  const off = fresh();
  off.realm.clientPolicies.policies.find((x) => x.name === "fbx-dynamic-client-registration-closed").enabled = false;
  failsWith(off, "client policy rejecting Dynamic Client Registration (client-updater-context ByAnonymous, ByInitialAccessToken, ByRegistrationAccessToken -> reject-request) missing");
  const narrow = fresh();
  narrow.realm.clientPolicies.policies.find((x) => x.name === "fbx-dynamic-client-registration-closed").conditions[0].configuration["update-client-source"] = ["ByAnonymous"];
  failsWith(narrow, "client policy rejecting Dynamic Client Registration (client-updater-context ByAnonymous, ByInitialAccessToken, ByRegistrationAccessToken -> reject-request) missing");
});

test("DCR: registration policies are declared; anonymous closed, TPP scopes and claim mappers never allowed", () => {
  const input = fresh();
  const anon = dcrPolicies(input).filter((c) => c.subType === "anonymous");
  const th = anon.find((c) => c.providerId === "trusted-hosts");
  assert.ok(th, "anonymous trusted-hosts policy missing");
  assert.deepEqual(th.config["trusted-hosts"] || [], []);
  for (const c of dcrPolicies(input).filter((x) => x.providerId === "allowed-client-templates")) {
    assert.deepEqual(c.config["allowed-client-scopes"] || [], [], `${c.subType}`);
  }
  const mutate = (fn, expected) => { const i = fresh(); fn(dcrPolicies(i)); failsWith(i, expected); };
  mutate((ps) => { ps.find((c) => c.subType === "anonymous" && c.providerId === "trusted-hosts").config["trusted-hosts"] = ["tpp.example"]; }, "DCR policy Trusted Hosts (anonymous): anonymous registration must stay closed (no trusted hosts, both checks on)");
  mutate((ps) => { const i = ps.findIndex((c) => c.subType === "anonymous" && c.providerId === "trusted-hosts"); ps.splice(i, 1); }, "DCR policy Trusted Hosts (anonymous): anonymous registration must stay closed (no trusted hosts, both checks on)");
  mutate((ps) => { ps.find((c) => c.subType === "authenticated" && c.providerId === "allowed-client-templates").config["allowed-client-scopes"] = [TYPE_SCOPE]; }, `DCR policy Allowed Client Scopes (authenticated): must not allow ${TYPE_SCOPE}`);
  mutate((ps) => { ps.find((c) => c.subType === "authenticated" && c.providerId === "allowed-client-templates").config["allowed-client-scopes"] = ["payments"]; }, "DCR policy Allowed Client Scopes (authenticated): must not allow payments");
  mutate((ps) => { ps.find((c) => c.subType === "authenticated" && c.providerId === "allowed-protocol-mappers").config["allowed-protocol-mapper-types"].push("oidc-hardcoded-claim-mapper"); }, "DCR policy Allowed Protocol Mapper Types (authenticated): oidc-hardcoded-claim-mapper is not allowed (it could emit fbx_client_type)");
});

// A running realm as the admin API returns it (and as a partial export holds
// it): the realm file's clients and client scopes with ids, plus Keycloak's
// built-in clients and scopes. The built-in clients are neither in the
// registry nor tagged fbx.client-type, so their fullScopeAllowed (true for
// some of them here) is not checked.
const LIVE_ENV = { KEYCLOAK_URL: "http://kc.test", KEYCLOAK_CLIENTID: "x", KEYCLOAK_CLIENTSECRET: "y" };
function liveRealm() {
  const { realm } = fresh();
  const builtIn = [["account", false], ["account-console", false], ["admin-cli", true], ["broker", false], ["realm-management", false], ["security-admin-console", true]]
    .map(([clientId, fullScopeAllowed]) => ({ clientId, fullScopeAllowed, attributes: {}, protocolMappers: [], defaultClientScopes: ["basic", "roles"], optionalClientScopes: [] }));
  const builtInScopes = [
    { name: "basic", protocol: "openid-connect", attributes: {}, protocolMappers: [] },
    { name: "roles", protocol: "openid-connect", attributes: {}, protocolMappers: [{ name: "audience resolve", protocol: "openid-connect", protocolMapper: "oidc-audience-resolve-mapper", config: {} }] },
    { name: "offline_access", protocol: "openid-connect", attributes: {}, protocolMappers: [] }
  ];
  return {
    realm: "fintechbankx",
    clients: [...realm.clients, ...builtIn].map((c) => ({ id: `id-${c.clientId}`, ...c })),
    clientScopes: [...realm.clientScopes, ...builtInScopes].map((sc) => ({ id: `id-${sc.name}`, ...sc })),
    defaultDefaultClientScopes: [...realm.defaultDefaultClientScopes],
    defaultOptionalClientScopes: ["offline_access"],
    roles: { realm: structuredClone(realm.roles.realm), client: {} },
    clientScopeMappings: {}
  };
}
// The admin API of that realm: token, paged clients, client scopes, realm
// default scopes, a client's roles, and the effective (composite) client-role
// scope mappings of a client or client scope.
function adminApi(live) {
  const urls = [];
  const json = (body) => new Response(JSON.stringify(body), { status: 200 });
  const byId = (list, id) => list.find((x) => x.id === decodeURIComponent(id));
  const fetch = async (url) => {
    urls.push(String(url));
    const u = new URL(url);
    if (u.pathname.endsWith("/protocol/openid-connect/token")) return json({ access_token: "t" });
    const p = u.pathname.replace(/^\/admin\/realms\/fintechbankx/, "");
    if (p === "/clients") {
      const first = Number(u.searchParams.get("first"));
      return json(live.clients.slice(first, first + Number(u.searchParams.get("max"))));
    }
    if (p === "/client-scopes") return json(live.clientScopes);
    if (p === "/default-default-client-scopes") return json(live.defaultDefaultClientScopes.map((name) => ({ id: `id-${name}`, name })));
    if (p === "/default-optional-client-scopes") return json(live.defaultOptionalClientScopes.map((name) => ({ id: `id-${name}`, name })));
    let m = p.match(/^\/clients\/([^/]+)\/roles$/);
    if (m) return json(live.roles.client[byId(live.clients, m[1]).clientId] || []);
    m = p.match(/^\/(clients|client-scopes)\/([^/]+)\/scope-mappings\/clients\/([^/]+)\/composite$/);
    if (m) {
      const holder = m[1] === "clients" ? { client: byId(live.clients, m[2]).clientId } : { clientScope: byId(live.clientScopes, m[2]).name };
      const callee = byId(live.clients, m[3]).clientId;
      const roles = (live.clientScopeMappings[callee] || [])
        .filter((x) => (holder.client ? x.client === holder.client : x.clientScope === holder.clientScope))
        .flatMap((x) => x.roles);
      return json(roles.map((name) => ({ name })));
    }
    return new Response("not found", { status: 404 });
  };
  return { fetch, urls };
}
function withExportFile(exported, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "live-"));
  const file = path.join(dir, "partial-export.json");
  fs.writeFileSync(file, JSON.stringify(exported));
  const done = () => fs.rmSync(dir, { recursive: true });
  let r;
  try { r = fn(file); } catch (e) { done(); throw e; }
  if (r instanceof Promise) return r.finally(done);
  done();
  return r;
}
const liveFromFile = (exported) => withExportFile(exported, (file) => realmCheck.checkLive({ argv: ["node", "check-realm.mjs", "--live-export", file] }));
const runLiveExport = (exported) => withExportFile(exported, (file) => execFileSync(process.execPath, [path.join(root, "scripts/ci/check-realm.mjs"), "--live-export", file], { encoding: "utf8", stdio: "pipe" }));

// Live drift check: runtime TPP clients are not in the realm file.
test("live: a client tagged open-finance-tpp without the default client-type scope fails (e.g. one registered by DCR before it was closed)", async () => {
  const input = fresh();
  const tpl = client(input, "of-tpp-conformance-template");
  // Shape read back from Keycloak 26.7.5 for a client registered with an
  // initial access token: realm defaults, built-in optional scopes.
  const dcrMade = { clientId: "of-tpp-dcr2", publicClient: false, clientAuthenticatorType: "client-jwt", protocolMappers: [],
    attributes: { "fbx.client-type": "open-finance-tpp", "fbx.tpp.token-binding": "dpop", "dpop.bound.access.tokens": "true", "require.pushed.authorization.requests": "true" },
    defaultClientScopes: ["web-origins", "acr", "customer-id", "roles", "profile", "basic", "email"], optionalClientScopes: ["address", "phone", "organization", "offline_access", "microprofile-jwt"] };
  const onboarded = { ...structuredClone(tpl), clientId: "of-tpp-acme-pay", enabled: true };
  const svc = client(input, "svc-pay-request-to-pay");
  assert.deepEqual(realmCheck.liveTppErrors([onboarded, svc, tpl]), []);
  assert.deepEqual(realmCheck.liveTppErrors([dcrMade]), ["of-tpp-dcr2: open-finance-tpp clients must carry client scope fbx-client-type-open-finance-tpp as a default scope"]);
  const sneaky = { ...structuredClone(svc), defaultClientScopes: [...svc.defaultClientScopes, "fbx-client-type-open-finance-tpp"] };
  assert.deepEqual(realmCheck.liveTppErrors([sneaky]), ["svc-pay-request-to-pay: scope fbx-client-type-open-finance-tpp on a client that is not fbx.client-type=open-finance-tpp"]);

  // --live-export: the TPP rules run next to the service-client rules on a
  // partial export of the running realm.
  const base = liveRealm();
  // The DCR-made client has no fullScopeAllowed, which Keycloak reads as true.
  const dcrErrors = ["of-tpp-dcr2: open-finance-tpp clients must carry client scope fbx-client-type-open-finance-tpp as a default scope",
    "of-tpp-dcr2: fullScopeAllowed must be false (Keycloak treats a missing value as true)"];
  const out = await liveFromFile({ ...base, clients: [...base.clients, onboarded, dcrMade] });
  assert.deepEqual(out.errors, dcrErrors);
  assert.throws(() => runLiveExport({ ...base, clients: [...base.clients, onboarded, dcrMade] }), /of-tpp-dcr2: open-finance-tpp clients must carry client scope/);
  assert.match(runLiveExport({ ...base, clients: [...base.clients, onboarded] }), new RegExp(`realm-check --live: OK \\(${base.clients.length + 1} clients, 2 open-finance-tpp, 16 service clients\\)`));

  // --live: admin token, then GET /clients page by page.
  const filler = Array.from({ length: 100 - base.clients.length }, (_, i) => ({ id: `c${i}`, clientId: `c${i}`, attributes: {} }));
  const api = adminApi({ ...base, clients: [...base.clients, ...filler, dcrMade] });
  const live = await realmCheck.checkLive({ argv: ["node", "check-realm.mjs", "--live"], env: LIVE_ENV, fetch: api.fetch });
  assert.equal(live.clients.length, 101);
  assert.deepEqual(live.errors, dcrErrors);
  assert.ok(api.urls.includes("http://kc.test/admin/realms/fintechbankx/clients?first=100&max=100"), api.urls.join(" "));
});

// Accounts ledger (accounts ledger thread 2026-10-17; service repository
// neo-fintechbankx-corebanking-accounts-ledger-service PR #1): service id
// svc-acc-accounts-ledger in namespace corebanking. The chart's service
// account and app.kubernetes.io/name are accounts-ledger-service, which is
// also the Secrets Manager slug (<env>/accounts-ledger-service/...).
const LEDGER = "svc-acc-accounts-ledger";

test("the accounts ledger has a confidential client-credentials client in namespace corebanking", () => {
  const input = fresh();
  const entry = input.registry.clients.find((c) => c.clientId === LEDGER);
  assert.ok(entry, `registry entry ${LEDGER} missing`);
  assert.equal(entry.serviceSlug, "accounts-ledger-service");
  assert.equal(entry.namespace, "corebanking");
  assert.equal(entry.serviceAccount, "accounts-ledger-service");
  assert.deepEqual(entry.audiences, [], "the ledger calls no other service yet");
  assert.deepEqual(entry.audienceProvenance, {});
  const c = client(input, LEDGER);
  assert.ok(c, `realm client ${LEDGER} missing`);
  assert.equal(c.publicClient, false);
  assert.equal(c.serviceAccountsEnabled, true);
  for (const f of ["standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled"]) assert.equal(c[f], false, f);
  assert.equal(c.secret, `$(env:${secretEnvName(LEDGER)})`);
  assert.equal(c.attributes["fbx.client-type"], "service");
  assert.equal(c.attributes["fbx.service-slug"], "accounts-ledger-service");
  assert.equal(c.attributes["fbx.namespace"], "corebanking");
  assert.deepEqual(auds(input, LEDGER), []);
  assert.deepEqual(scopeRoles(input, LEDGER), ["service"]);
  assert.deepEqual(input.realm.users.find((u) => u.serviceAccountClientId === LEDGER)?.realmRoles, ["service"]);
  assert.equal(input.importSecretRefs[secretEnvName(LEDGER)], "ENVIRONMENT/accounts-ledger-service/oidc-client");
});

// The ledger's SERVICE_CALLERS (its chart values and README, and
// docs/CONSUMER_CONTRACT.md) call it with client-credentials tokens whose aud
// must contain svc-acc-accounts-ledger. Channel clients (web, mobile, staff
// web, TPP template) and the staff SSO client do not get the audience here:
// customer and staff reads through them are a separate decision.
//
// The ledger is reached only through the optional client scope
// aud-svc-acc-accounts-ledger (registry audienceByScope; Platform decision
// 2026-10-17 on Lending's shared-client question): one client per service
// stays, and a caller's token carries the ledger audience only when it asks
// for that scope, so the tokens it sends to customer or consent never do.
const LEDGER_CALLERS = ["svc-ln-loan-lifecycle", "svc-pay-bulk-orchestration", "svc-pay-initiation-settlement", "svc-pay-recurring-mandates"];
const LEDGER_PROVENANCE = "confirmed by accounts ledger thread 2026-10-17 (docs/CONSUMER_CONTRACT.md, SERVICE_CALLERS)";
const LEDGER_SCOPE = "aud-svc-acc-accounts-ledger";
const withAudience = (input, aud) => input.realm.clients
  .filter((c) => (c.protocolMappers || []).some((m) => m.protocolMapper === "oidc-audience-mapper" && m.config?.["included.client.audience"] === aud))
  .map((c) => c.clientId)
  .sort();
const withOptionalScope = (input, name) => input.realm.clients
  .filter((c) => (c.optionalClientScopes || []).includes(name))
  .map((c) => c.clientId)
  .sort();

test("the four SERVICE_CALLERS of the accounts ledger reach it only through the optional scope aud-svc-acc-accounts-ledger, with provenance", () => {
  const input = fresh();
  assert.equal(input.registry.clients.find((c) => c.clientId === LEDGER).audienceByScope, true);
  for (const id of LEDGER_CALLERS) {
    const entry = input.registry.clients.find((c) => c.clientId === id);
    assert.ok(entry.audiences.includes(LEDGER), `${id}: registry audience ${LEDGER} missing`);
    assert.equal(entry.audienceProvenance[LEDGER], LEDGER_PROVENANCE, id);
    assert.ok(!auds(input, id).includes(LEDGER), `${id}: ${LEDGER} must not be an always-on audience mapper`);
    assert.ok(client(input, id).optionalClientScopes.includes(LEDGER_SCOPE), `${id}: optional scope ${LEDGER_SCOPE} missing`);
    assert.ok(!client(input, id).defaultClientScopes.includes(LEDGER_SCOPE), `${id}: ${LEDGER_SCOPE} must not be a default scope`);
  }
  // The callers' other audiences stay always-on mappers, as before.
  assert.deepEqual(auds(input, "svc-ln-loan-lifecycle"), ["svc-cus-profile-kyc"]);
  assert.deepEqual(auds(input, "svc-pay-recurring-mandates"), ["svc-of-consent-authorization"]);
  assert.deepEqual(auds(input, "svc-pay-bulk-orchestration"), ["svc-of-consent-authorization"]);
  assert.deepEqual(auds(input, "svc-pay-initiation-settlement"), ["svc-cmp-evidence", "svc-cus-profile-kyc", "svc-of-payee-verification", "svc-rsk-decisioning"]);
});

test("the scope aud-svc-acc-accounts-ledger adds only the ledger audience to access tokens and is never a default scope", () => {
  const input = fresh();
  const s = (input.realm.clientScopes || []).find((x) => x.name === LEDGER_SCOPE);
  assert.ok(s, `client scope ${LEDGER_SCOPE} missing`);
  assert.equal(s.protocol, "openid-connect");
  assert.equal(s.protocolMappers.length, 1);
  const [m] = s.protocolMappers;
  assert.equal(m.protocolMapper, "oidc-audience-mapper");
  assert.equal(m.config["included.client.audience"], LEDGER);
  assert.equal(m.config["access.token.claim"], "true");
  assert.equal(m.config["id.token.claim"], "false");
  assert.ok(!(input.realm.defaultDefaultClientScopes || []).includes(LEDGER_SCOPE));
  for (const c of input.realm.clients) assert.ok(!(c.defaultClientScopes || []).includes(LEDGER_SCOPE), `${c.clientId}: ${LEDGER_SCOPE} as default scope`);
});

test("no client carries the ledger audience as an always-on mapper, and only its four callers may request the scope", () => {
  const input = fresh();
  assert.deepEqual(withAudience(input, LEDGER), []);
  assert.deepEqual(withOptionalScope(input, LEDGER_SCOPE), LEDGER_CALLERS);
  for (const c of input.registry.channelClients) assert.ok(!c.audiences.includes(LEDGER), `${c.clientId} must not carry ${LEDGER}`);
  for (const c of input.registry.ssoClients || []) assert.ok(!(c.audiences || []).includes(LEDGER), `${c.clientId} must not carry ${LEDGER}`);
});

test("the gate refuses the ledger audience as a mapper, a missing, extra or default ledger scope, and a scope with another audience", () => {
  const ledgerMapper = { name: `aud-${LEDGER}`, protocol: "openid-connect", protocolMapper: "oidc-audience-mapper", consentRequired: false,
    config: { "included.client.audience": LEDGER, "access.token.claim": "true", "id.token.claim": "false", "introspection.token.claim": "true", "lightweight.claim": "false" } };
  const asMapper = fresh();
  client(asMapper, "svc-ln-loan-lifecycle").protocolMappers.push(ledgerMapper);
  assert.ok(checkRealm(asMapper).some((e) => e.startsWith("svc-ln-loan-lifecycle: audience mappers")), checkRealm(asMapper).join("\n"));

  const missing = fresh();
  const bulk = client(missing, "svc-pay-bulk-orchestration");
  bulk.optionalClientScopes = bulk.optionalClientScopes.filter((x) => x !== LEDGER_SCOPE);
  assert.ok(checkRealm(missing).some((e) => e.startsWith(`svc-pay-bulk-orchestration: optional audience scopes <none> != registry ${LEDGER_SCOPE}`)), checkRealm(missing).join("\n"));

  const extra = fresh();
  client(extra, "svc-cus-profile-kyc").optionalClientScopes.push(LEDGER_SCOPE);
  assert.ok(checkRealm(extra).some((e) => e.startsWith(`svc-cus-profile-kyc: optional audience scopes ${LEDGER_SCOPE} != registry <none>`)), checkRealm(extra).join("\n"));

  const asDefault = fresh();
  client(asDefault, "svc-pay-recurring-mandates").defaultClientScopes.push(LEDGER_SCOPE);
  assert.ok(checkRealm(asDefault).some((e) => e === `svc-pay-recurring-mandates: audience scope ${LEDGER_SCOPE} must be optional, not default`), checkRealm(asDefault).join("\n"));

  const realmDefault = fresh();
  realmDefault.realm.defaultDefaultClientScopes.push(LEDGER_SCOPE);
  assert.ok(checkRealm(realmDefault).some((e) => e === `realm: audience scope ${LEDGER_SCOPE} must not be a realm default scope`), checkRealm(realmDefault).join("\n"));

  const otherAud = fresh();
  otherAud.realm.clientScopes.find((x) => x.name === LEDGER_SCOPE).protocolMappers[0].config["included.client.audience"] = "svc-cus-profile-kyc";
  assert.ok(checkRealm(otherAud).some((e) => e === `client scope ${LEDGER_SCOPE}: must carry exactly one access-token audience mapper for ${LEDGER}`), checkRealm(otherAud).join("\n"));

  const gone = fresh();
  gone.realm.clientScopes = gone.realm.clientScopes.filter((x) => x.name !== LEDGER_SCOPE);
  assert.ok(checkRealm(gone).some((e) => e === `client scope ${LEDGER_SCOPE} missing (registry ${LEDGER} has audienceByScope)`), checkRealm(gone).join("\n"));

  const stale = fresh();
  stale.realm.clientScopes.push({ name: "aud-svc-cus-profile-kyc", protocol: "openid-connect", attributes: {}, protocolMappers: [] });
  assert.ok(checkRealm(stale).some((e) => e === "client scope aud-svc-cus-profile-kyc: no registry client with audienceByScope is named svc-cus-profile-kyc"), checkRealm(stale).join("\n"));

  const onChannel = fresh();
  onChannel.registry.channelClients.find((c) => c.clientId === "fintechbankx-staff-web").audiences.push(LEDGER);
  client(onChannel, "fintechbankx-staff-web").protocolMappers.push(ledgerMapper);
  assert.ok(checkRealm(onChannel).some((e) => e.startsWith(`fintechbankx-staff-web: audience ${LEDGER} is reached only through the optional scope ${LEDGER_SCOPE}`)), checkRealm(onChannel).join("\n"));
});

// DevSecOps review (should-fix 1): a by-scope callee's audience reaches a
// token only through its aud- scope. Another client scope (customer-id,
// payments, the client-type scope, a new scope, a realm default scope) with an
// audience mapper naming it, as client or custom audience, is refused; so is a
// client role of the callee in another client's or scope's role scope, which
// Keycloak's audience resolve mapper (built-in scope roles) turns into aud.
const ledgerAudMapper = (key = "included.client.audience") => ({ name: "ledger", protocol: "openid-connect", protocolMapper: "oidc-audience-mapper", consentRequired: false,
  config: { [key]: LEDGER, "access.token.claim": "true", "id.token.claim": "false" } });
const viaOtherScope = (name) => `client scope ${name}: audience ${LEDGER} is reached only through the optional scope ${LEDGER_SCOPE} (registry audienceByScope), never through another client scope`;
const viaRealmDefault = (name) => `realm: default scope ${name} carries audience ${LEDGER} (registry audienceByScope); a client created without explicit scopes would get it`;

test("by-scope audience: the customer-id, payments and client-type scopes carry no ledger audience, as client or custom audience", () => {
  for (const name of ["customer-id", "payments", "fbx-client-type-open-finance-tpp"]) {
    for (const key of ["included.client.audience", "included.custom.audience"]) {
      const input = fresh();
      scope(input, name).protocolMappers.push(ledgerAudMapper(key));
      failsWith(input, viaOtherScope(name));
    }
  }
  // customer-id is also a realm default scope.
  const input = fresh();
  scope(input, "customer-id").protocolMappers.push(ledgerAudMapper());
  failsWith(input, viaRealmDefault("customer-id"));
});

test("by-scope audience: a new client scope given to a client as a default scope carries no ledger audience", () => {
  const input = fresh();
  input.realm.clientScopes.push({ name: "ledger-reader", protocol: "openid-connect", attributes: {}, protocolMappers: [ledgerAudMapper("included.custom.audience")] });
  client(input, "svc-cus-profile-kyc").defaultClientScopes.push("ledger-reader");
  failsWith(input, viaOtherScope("ledger-reader"));
  // Another aud- scope is another scope too.
  const stale = fresh();
  stale.realm.clientScopes.push({ name: "aud-svc-cus-profile-kyc", protocol: "openid-connect", attributes: {}, protocolMappers: [ledgerAudMapper()] });
  failsWith(stale, viaOtherScope("aud-svc-cus-profile-kyc"));
});

test("by-scope audience: a realm default scope (default or optional) carries no ledger audience", () => {
  const input = fresh();
  input.realm.clientScopes.push({ name: "ledger-everywhere", protocol: "openid-connect", attributes: {}, protocolMappers: [ledgerAudMapper()] });
  input.realm.defaultOptionalClientScopes = ["ledger-everywhere"];
  failsWith(input, viaRealmDefault("ledger-everywhere"));
  failsWith(input, viaOtherScope("ledger-everywhere"));
});

test("by-scope audience: a client mapper with the ledger as custom audience is refused", () => {
  const input = fresh();
  client(input, "svc-cus-profile-kyc").protocolMappers.push(ledgerAudMapper("included.custom.audience"));
  failsWith(input, `svc-cus-profile-kyc: audience ${LEDGER} is reached only through the optional scope ${LEDGER_SCOPE} (registry audienceByScope), never through a mapper`);
  failsWith(input, `svc-cus-profile-kyc: audience mappers custom:${LEDGER} != registry <none>`);
});

test("by-scope audience: ledger client roles may exist, but none may sit in another client's or scope's role scope (audience resolve)", () => {
  const base = fresh();
  // Read from the realm: the ledger has no client roles today and no client
  // role is scope-mapped anywhere.
  assert.equal(base.realm.roles.client, undefined);
  assert.deepEqual(base.realm.clientScopeMappings, {});
  base.realm.roles.client = { [LEDGER]: [{ name: "ledger-reader", composite: false, clientRole: true }] };
  assert.deepEqual(checkRealm(base), [], "a role of the ledger's own is not a route");
  const tail = `, so tokens issued with it would carry aud=${LEDGER} (audience resolve); ${LEDGER} is reached only through the optional scope ${LEDGER_SCOPE} (registry audienceByScope)`;

  const toClient = structuredClone(base);
  toClient.realm.clientScopeMappings = { [LEDGER]: [{ client: "svc-cus-profile-kyc", roles: ["ledger-reader"] }] };
  failsWith(toClient, `${LEDGER}: client roles ledger-reader are in the role scope of client svc-cus-profile-kyc${tail}`);

  const toScope = structuredClone(base);
  toScope.realm.clientScopeMappings = { [LEDGER]: [{ clientScope: "roles", roles: ["ledger-reader"] }] };
  failsWith(toScope, `${LEDGER}: client roles ledger-reader are in the role scope of client scope roles${tail}`);

  const composite = structuredClone(base);
  Object.assign(composite.realm.roles.realm.find((r) => r.name === "service"), { composite: true, composites: { client: { [LEDGER]: ["ledger-reader"] } } });
  failsWith(composite, `role service: composite of ${LEDGER} client roles ledger-reader${tail}`);
});

// DevSecOps review (should-fix 2): fullScopeAllowed is false on every client
// of the realm file (service, first-party public, TPP template, staff SSO);
// Keycloak's default when the key is absent is true.
test("fullScopeAllowed must be false on every client, absent counts as true", () => {
  for (const c of fresh().realm.clients) assert.equal(c.fullScopeAllowed, false, c.clientId);
  const cases = [
    [LEDGER, (c) => { delete c.fullScopeAllowed; }],
    ["svc-pay-request-to-pay", (c) => { c.fullScopeAllowed = true; }],
    ["fintechbankx-mobile", (c) => { delete c.fullScopeAllowed; }],
    ["of-tpp-conformance-template", (c) => { c.fullScopeAllowed = true; }],
    ["svc-obs-grafana", (c) => { delete c.fullScopeAllowed; }]
  ];
  for (const [id, mutate] of cases) {
    const input = fresh();
    mutate(client(input, id));
    failsWith(input, `${id}: fullScopeAllowed must be false (Keycloak treats a missing value as true)`);
  }
});

// DevSecOps review (should-fix 3): the live drift check holds a running
// Keycloak to the same service-client rules, through the admin API and
// through a partial export.
const liveClient = (live, id) => live.clients.find((c) => c.clientId === id);
const liveScope = (live, name) => live.clientScopes.find((x) => x.name === name);
const liveErrors = async (live) => {
  const viaApi = await realmCheck.checkLive({ argv: ["node", "check-realm.mjs", "--live"], env: LIVE_ENV, fetch: adminApi(live).fetch });
  const viaFile = await liveFromFile(live);
  assert.deepEqual(viaFile.errors, viaApi.errors, "--live and --live-export disagree");
  return viaApi.errors;
};

test("live: a running realm that matches the realm-as-code passes, through the admin API and a partial export", async () => {
  const live = liveRealm();
  assert.deepEqual(await liveErrors(live), []);
  assert.match(runLiveExport(live), new RegExp(`realm-check --live: OK \\(${live.clients.length} clients, 1 open-finance-tpp, 16 service clients\\)`));
  const api = adminApi(live);
  await realmCheck.checkLive({ argv: ["node", "check-realm.mjs", "--live"], env: LIVE_ENV, fetch: api.fetch });
  for (const p of ["/client-scopes", "/default-default-client-scopes", "/default-optional-client-scopes", `/clients/id-${LEDGER}/roles`]) {
    assert.ok(api.urls.includes(`http://kc.test/admin/realms/fintechbankx${p}`), `${p} not fetched: ${api.urls.join(" ")}`);
  }
  // No ledger roles: no scope-mapping lookups needed.
  assert.ok(!api.urls.some((u) => u.includes("/scope-mappings/")), api.urls.join(" "));
});

test("live: drift from the service-client rules fails, through the admin API and a partial export", async () => {
  const kycMapper = () => structuredClone(client(fresh(), "svc-ln-loan-lifecycle").protocolMappers[0]);
  const ledgerRole = (l, mapping) => { l.roles.client[LEDGER] = [{ name: "ledger-reader", composite: false, clientRole: true }]; l.clientScopeMappings[LEDGER] = [mapping]; };
  const tail = `, so tokens issued with it would carry aud=${LEDGER} (audience resolve); ${LEDGER} is reached only through the optional scope ${LEDGER_SCOPE} (registry audienceByScope)`;
  const cases = [
    ["ledger audience as a caller's mapper", (l) => liveClient(l, "svc-ln-loan-lifecycle").protocolMappers.push(ledgerAudMapper()),
      ["svc-ln-loan-lifecycle: audience mappers svc-acc-accounts-ledger,svc-cus-profile-kyc != registry svc-cus-profile-kyc",
        `svc-ln-loan-lifecycle: audience ${LEDGER} is reached only through the optional scope ${LEDGER_SCOPE} (registry audienceByScope), never through a mapper`]],
    ["registry audience mapper removed", (l) => { liveClient(l, "svc-ln-loan-lifecycle").protocolMappers = []; },
      ["svc-ln-loan-lifecycle: audience mappers <none> != registry svc-cus-profile-kyc"]],
    ["ledger scope removed from a caller", (l) => { liveClient(l, "svc-pay-bulk-orchestration").optionalClientScopes = []; },
      [`svc-pay-bulk-orchestration: optional audience scopes <none> != registry ${LEDGER_SCOPE}`]],
    ["ledger scope on a client that does not call the ledger", (l) => liveClient(l, "svc-cus-profile-kyc").optionalClientScopes.push(LEDGER_SCOPE),
      [`svc-cus-profile-kyc: optional audience scopes ${LEDGER_SCOPE} != registry <none>`]],
    ["ledger scope as a client default", (l) => liveClient(l, "svc-pay-recurring-mandates").defaultClientScopes.push(LEDGER_SCOPE),
      [`svc-pay-recurring-mandates: audience scope ${LEDGER_SCOPE} must be optional, not default`]],
    ["ledger scope deleted", (l) => { l.clientScopes = l.clientScopes.filter((x) => x.name !== LEDGER_SCOPE); },
      [`client scope ${LEDGER_SCOPE} missing (registry ${LEDGER} has audienceByScope)`]],
    ["second mapper in the ledger scope", (l) => liveScope(l, LEDGER_SCOPE).protocolMappers.push(kycMapper()),
      [`client scope ${LEDGER_SCOPE}: must carry exactly one access-token audience mapper for ${LEDGER}`]],
    ["ledger audience in customer-id (a realm default)", (l) => liveScope(l, "customer-id").protocolMappers.push(ledgerAudMapper()),
      [viaOtherScope("customer-id"), viaRealmDefault("customer-id")]],
    ["ledger audience in a new realm-default optional scope", (l) => {
      l.clientScopes.push({ id: "id-ledger-everywhere", name: "ledger-everywhere", protocol: "openid-connect", attributes: {}, protocolMappers: [ledgerAudMapper("included.custom.audience")] });
      l.defaultOptionalClientScopes.push("ledger-everywhere");
    }, [viaOtherScope("ledger-everywhere"), viaRealmDefault("ledger-everywhere")]],
    ["ledger scope as a realm default", (l) => l.defaultDefaultClientScopes.push(LEDGER_SCOPE),
      [`realm: audience scope ${LEDGER_SCOPE} must not be a realm default scope`]],
    ["fullScopeAllowed true on the ledger client", (l) => { liveClient(l, LEDGER).fullScopeAllowed = true; },
      [`${LEDGER}: fullScopeAllowed must be false (Keycloak treats a missing value as true)`]],
    ["fullScopeAllowed true on a runtime TPP client", (l) => l.clients.push({ ...structuredClone(liveClient(l, "of-tpp-conformance-template")), id: "id-of-tpp-acme-pay", clientId: "of-tpp-acme-pay", fullScopeAllowed: true }),
      ["of-tpp-acme-pay: fullScopeAllowed must be false (Keycloak treats a missing value as true)"]],
    ["ledger client role scope-mapped to a client", (l) => ledgerRole(l, { client: "svc-cus-profile-kyc", roles: ["ledger-reader"] }),
      [`${LEDGER}: client roles ledger-reader are in the role scope of client svc-cus-profile-kyc${tail}`]],
    ["ledger client role scope-mapped to a client scope", (l) => ledgerRole(l, { clientScope: "roles", roles: ["ledger-reader"] }),
      [`${LEDGER}: client roles ledger-reader are in the role scope of client scope roles${tail}`]],
    ["service client missing", (l) => { l.clients = l.clients.filter((c) => c.clientId !== LEDGER); },
      [`service client ${LEDGER} missing from realm`]]
  ];
  for (const [name, mutate, expected] of cases) {
    const live = liveRealm();
    mutate(live);
    const errors = await liveErrors(live);
    for (const e of expected) assert.ok(errors.includes(e), `${name}: ${e} not in\n${errors.join("\n")}`);
  }
  // A ledger role of its own, mapped nowhere, passes (and is looked up).
  const own = liveRealm();
  own.roles.client[LEDGER] = [{ name: "ledger-reader", composite: false, clientRole: true }];
  assert.deepEqual(await liveErrors(own), []);
  const api = adminApi(own);
  await realmCheck.checkLive({ argv: ["node", "check-realm.mjs", "--live"], env: LIVE_ENV, fetch: api.fetch });
  assert.ok(api.urls.includes(`http://kc.test/admin/realms/fintechbankx/clients/id-svc-cus-profile-kyc/scope-mappings/clients/id-${LEDGER}/composite`), api.urls.join(" "));
  assert.ok(api.urls.includes(`http://kc.test/admin/realms/fintechbankx/client-scopes/id-roles/scope-mappings/clients/id-${LEDGER}/composite`), api.urls.join(" "));
});

test("live: --live-export needs a partial export with clients, client scopes, realm default scopes and roles", async () => {
  const live = liveRealm();
  await assert.rejects(liveFromFile(live.clients), /--live-export: a GET \/clients array covers the TPP rules only/);
  assert.throws(() => runLiveExport(live.clients), /realm-check --live: FAILED: --live-export: a GET \/clients array covers the TPP rules only/);
  for (const key of ["clients", "clientScopes", "defaultDefaultClientScopes", "defaultOptionalClientScopes", "roles"]) {
    const partial = liveRealm();
    delete partial[key];
    await assert.rejects(liveFromFile(partial), new RegExp(`--live-export: the export lacks ${key}`), key);
  }
  // clientScopeMappings may be absent only while the ledger has no client roles.
  const noMappings = liveRealm();
  delete noMappings.clientScopeMappings;
  assert.deepEqual((await liveFromFile(noMappings)).errors, []);
  noMappings.roles.client[LEDGER] = [{ name: "ledger-reader", composite: false, clientRole: true }];
  await assert.rejects(liveFromFile(noMappings), new RegExp(`--live-export: the export lacks clientScopeMappings, needed because ${LEDGER} has client roles`));
});
