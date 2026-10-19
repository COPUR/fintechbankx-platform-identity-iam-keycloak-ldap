import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import YAML from "yaml";
import * as realmCheck from "../../ci/check-realm.mjs";
import { STOCK_PROTOCOL_MAPPERS, STAFF_ROLES as FLOW_STAFF_ROLES } from "../../realm/service-client-rules.mjs";
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

// Review finding (major): the gate looked up the first group-ldap-mapper only,
// so a hardcoded-ldap-role-mapper (a fixed realm role for every federated
// user), a role-ldap-mapper granting a staff role or a second group mapper
// passed. One LDAP provider, its mappers on an allow-list (the attribute
// mappers and one read-only group mapper), and the group mapper pinned so
// LDAP groups land only in /staff/fbx-*. Static only: --live and
// --live-export do not read user storage providers.
const USER_STORAGE = "org.keycloak.storage.UserStorageProvider";
const LDAP_MAPPER = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper";
const ldapMappers = (r) => r.components[USER_STORAGE][0].subComponents[LDAP_MAPPER];
const staffGroupMapper = (r) => ldapMappers(r).find((m) => m.name === "staff-groups");
const ldapMapper = (name, providerId, config) => ({ name, providerId, subComponents: {}, config });
const grantsRoles = (name, providerId) => `LDAP mapper ${name} (${providerId}) grants roles or groups to federated users`;
const groupMapperPin = (key, want) => `LDAP group mapper staff-groups: ${key} must be ${JSON.stringify([want])}`;

test("LDAP: only user-attribute mappers and one read-only group mapper landing in /staff/fbx-*; role- and group-granting mappers are refused", () => {
  assert.deepEqual([...new Set(ldapMappers(fresh().realm).map((m) => m.providerId))].sort(), ["group-ldap-mapper", "user-attribute-ldap-mapper"]);
  const cases = [
    ["a hardcoded role mapper granting banker", (r) => ldapMappers(r).push(ldapMapper("every-user-banker", "hardcoded-ldap-role-mapper", { role: ["banker"] })),
      grantsRoles("every-user-banker", "hardcoded-ldap-role-mapper")],
    ["a role mapper", (r) => ldapMappers(r).push(ldapMapper("directory-roles", "role-ldap-mapper", { "roles.dn": ["ou=roles,dc=fintechbankx,dc=internal"], "role.name.ldap.attribute": ["cn"], "use.realm.roles.mapping": ["true"], mode: ["READ_ONLY"] })),
      grantsRoles("directory-roles", "role-ldap-mapper")],
    ["a hardcoded group mapper", (r) => ldapMappers(r).push(ldapMapper("every-user-admin", "hardcoded-ldap-group-mapper", { group: ["/staff/fbx-admin"] })),
      grantsRoles("every-user-admin", "hardcoded-ldap-group-mapper")],
    ["a second group mapper", (r) => ldapMappers(r).push({ ...structuredClone(staffGroupMapper(r)), name: "more-groups" }),
      "LDAP group mappers: one allowed (found 2: staff-groups, more-groups)"],
    ["a custom SPI mapper", (r) => ldapMappers(r).push(ldapMapper("custom", "fbx-custom-ldap-mapper", {})),
      "LDAP mapper custom (fbx-custom-ldap-mapper) is not allowed"],
    ["a full name mapper", (r) => ldapMappers(r).push(ldapMapper("full name", "full-name-ldap-mapper", { "ldap.full.name.attribute": ["cn"] })),
      "LDAP mapper full name (full-name-ldap-mapper) is not allowed"],
    ["groups imported to the root", (r) => { staffGroupMapper(r).config["groups.path"] = ["/"]; }, groupMapperPin("groups.path", "/staff")],
    ["every directory group", (r) => { staffGroupMapper(r).config["groups.ldap.filter"] = ["(cn=*)"]; }, groupMapperPin("groups.ldap.filter", "(cn=fbx-*)")],
    ["group names from another attribute", (r) => { staffGroupMapper(r).config["group.name.ldap.attribute"] = ["description"]; }, groupMapperPin("group.name.ldap.attribute", "cn")],
    ["nested directory groups", (r) => { staffGroupMapper(r).config["preserve.group.inheritance"] = ["true"]; }, groupMapperPin("preserve.group.inheritance", "false")],
    ["group mapper missing", (r) => { r.components[USER_STORAGE][0].subComponents[LDAP_MAPPER] = ldapMappers(r).filter((m) => m.providerId !== "group-ldap-mapper"); }, "LDAP group mapper missing"],
    ["a second LDAP provider with a hardcoded role mapper", (r) => r.components[USER_STORAGE].push({ name: "second-directory", providerId: "ldap", config: structuredClone(r.components[USER_STORAGE][0].config),
      subComponents: { [LDAP_MAPPER]: [ldapMapper("every-user-admin", "hardcoded-ldap-role-mapper", { role: ["admin"] })] } }),
      "LDAP providers: one allowed (found 2: fbx-directory, second-directory)"],
    ["the role mapper of a second LDAP provider", (r) => r.components[USER_STORAGE].push({ name: "second-directory", providerId: "ldap", config: structuredClone(r.components[USER_STORAGE][0].config),
      subComponents: { [LDAP_MAPPER]: [ldapMapper("every-user-admin", "hardcoded-ldap-role-mapper", { role: ["admin"] })] } }),
      grantsRoles("every-user-admin", "hardcoded-ldap-role-mapper")],
    ["another user storage provider", (r) => r.components[USER_STORAGE].push({ name: "corp-kerberos", providerId: "kerberos", subComponents: {}, config: {} }),
      "user storage provider corp-kerberos (kerberos) is not allowed"],
    ["an LDAP mapper at the realm's top level", (r) => { r.components[LDAP_MAPPER] = [ldapMapper("top-banker", "hardcoded-ldap-role-mapper", { role: ["banker"] })]; },
      "LDAP mapper top-banker (hardcoded-ldap-role-mapper) must sit under the LDAP provider"]
  ];
  for (const [name, mutate, expected] of cases) {
    const input = fresh();
    mutate(input.realm);
    const errors = checkRealm(input);
    assert.ok(errors.some((e) => e.startsWith(expected)), `${name}: ${expected} not in\n${errors.join("\n")}`);
  }
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

// Every registry audience says where it comes from: confirmed by the owning
// service thread, or derived by the platform pillar, followed by the source.
// A provenance without its audience is stale.
const PROVENANCE = /^(confirmed by|derived) \S/;
const registryEntries = (registry) => [...registry.clients, ...(registry.channelClients || []), ...(registry.ssoClients || [])];

test("every registry audience has a provenance \"confirmed by <source>\" or \"derived <source>\", and no provenance lacks its audience", () => {
  const { registry } = fresh();
  for (const e of registryEntries(registry)) {
    for (const a of e.audiences || []) assert.match(e.audienceProvenance?.[a] ?? "", PROVENANCE, `${e.clientId}: audience ${a}`);
    for (const k of Object.keys(e.audienceProvenance || {})) assert.ok((e.audiences || []).includes(k), `${e.clientId}: audienceProvenance ${k} without its audience`);
  }
  const want = (id, a) => `${id}: audience ${a} needs an audienceProvenance "confirmed by <source>" or "derived <source>"`;
  const entry = (input, id) => registryEntries(input.registry).find((e) => e.clientId === id);
  const missing = fresh();
  delete entry(missing, "svc-ln-loan-lifecycle").audienceProvenance["svc-cus-profile-kyc"];
  failsWith(missing, want("svc-ln-loan-lifecycle", "svc-cus-profile-kyc"));
  const vague = fresh();
  entry(vague, "fintechbankx-web").audienceProvenance["svc-pay-request-to-pay"] = "assumed";
  failsWith(vague, want("fintechbankx-web", "svc-pay-request-to-pay"));
  const noKey = fresh();
  delete entry(noKey, "of-tpp-conformance-template").audienceProvenance;
  failsWith(noKey, want("of-tpp-conformance-template", "svc-of-atm-directory"));
  for (const v of ["derivedXYZ", "derived", "derived ", "confirmed by", "confirmed by  ", "confirmedby x", "", 42, { derived: "x" }, ["derived x"]]) {
    const prefixOnly = fresh();
    entry(prefixOnly, "svc-ln-loan-lifecycle").audienceProvenance["svc-cus-profile-kyc"] = v;
    failsWith(prefixOnly, want("svc-ln-loan-lifecycle", "svc-cus-profile-kyc"));
  }
  const sso = fresh();
  entry(sso, "svc-obs-grafana").audiences = ["svc-cmp-evidence"];
  failsWith(sso, want("svc-obs-grafana", "svc-cmp-evidence"));
  const stale = fresh();
  entry(stale, "svc-cus-profile-kyc").audienceProvenance["svc-rsk-decisioning"] = "derived (platform pillar)";
  failsWith(stale, "svc-cus-profile-kyc: audienceProvenance svc-rsk-decisioning names no registry audience of this client");
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

test("staff web: short sessions, no optional scopes but the ledger audience scope, no customer-id scope", () => {
  const input = fresh();
  const c = client(input, "fintechbankx-staff-web");
  assert.deepEqual(c.optionalClientScopes, [LEDGER_SCOPE]);
  const other = fresh();
  client(other, "fintechbankx-staff-web").optionalClientScopes.push("phone");
  failsWith(other, "fintechbankx-staff-web: staff clients may have no optional scopes but their registry audience scopes");
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
// registry nor tagged fbx.client-type, so fullScopeErrors does not apply to
// them. admin-cli and security-admin-console are created by Keycloak 26.7.5
// with fullScopeAllowed=true and lightweight access tokens (no aud).
const LIVE_ENV = { KEYCLOAK_URL: "http://kc.test", KEYCLOAK_CLIENTID: "x", KEYCLOAK_CLIENTSECRET: "y" };
const SAML_ECP = "saml ecp";
const LIGHTWEIGHT = "client.use.lightweight.access.token.enabled";
function liveRealm() {
  const { realm } = fresh();
  const builtIn = [["account", false], ["account-console", false], ["admin-cli", true], ["broker", false], ["realm-management", false], ["security-admin-console", true]]
    .map(([clientId, fullScopeAllowed]) => ({ clientId, fullScopeAllowed, attributes: fullScopeAllowed ? { [LIGHTWEIGHT]: "true" } : {}, protocolMappers: [], defaultClientScopes: ["basic", "roles"], optionalClientScopes: [] }));
  // FGAP v2 (adminPermissionsEnabled) adds the client admin-permissions,
  // the resource server of the admin permissions, with Authorization Services.
  builtIn.push({ clientId: "admin-permissions", fullScopeAllowed: false, serviceAccountsEnabled: true, authorizationServicesEnabled: true, attributes: { realm_client: "false" },
    authorizationSettings: { policyEnforcementMode: "ENFORCING", decisionStrategy: "UNANIMOUS", resources: [], policies: [], scopes: [] }, protocolMappers: [], defaultClientScopes: ["basic", "roles"], optionalClientScopes: [] });
  // Keycloak's built-in browser flow (26.7.5, as the admin API lists it); the
  // export and the admin API name a client's flow override by flow id. And
  // its built-in flow saml ecp, which a partial export lists and GET
  // /authentication/flows leaves out (adminApi below).
  const builtInFlows = [{ alias: "browser", description: "Browser based authentication", providerId: "basic-flow", topLevel: true, builtIn: true,
    authenticationExecutions: [{ authenticator: "auth-cookie", authenticatorFlow: false, requirement: "ALTERNATIVE", priority: 10, userSetupAllowed: false }] },
  { alias: SAML_ECP, description: "SAML ECP Profile Authentication Flow", providerId: "basic-flow", topLevel: true, builtIn: true,
    authenticationExecutions: [{ authenticator: "http-basic-authenticator", authenticatorFlow: false, requirement: "REQUIRED", priority: 10, userSetupAllowed: false }] }];
  const flows = [...realm.authenticationFlows, ...builtInFlows].map((f) => ({ id: `id-${f.alias}`, ...f }));
  const flowId = (alias) => flows.find((f) => f.alias === alias)?.id ?? alias;
  const builtInScopes = [
    { name: "basic", protocol: "openid-connect", attributes: {}, protocolMappers: [] },
    { name: "roles", protocol: "openid-connect", attributes: {}, protocolMappers: [{ name: "audience resolve", protocol: "openid-connect", protocolMapper: "oidc-audience-resolve-mapper", config: {} }] },
    { name: "offline_access", protocol: "openid-connect", attributes: {}, protocolMappers: [] }
  ];
  return {
    realm: "fintechbankx",
    clients: [...realm.clients, ...builtIn].map((c) => ({ id: `id-${c.clientId}`, ...c,
      ...(c.authenticationFlowBindingOverrides ? { authenticationFlowBindingOverrides: Object.fromEntries(Object.entries(c.authenticationFlowBindingOverrides).map(([k, v]) => [k, flowId(v)])) } : {}) })),
    authenticationFlows: flows,
    authenticatorConfig: realm.authenticatorConfig.map((c) => ({ id: `id-${c.alias}`, ...c })),
    resetCredentialsFlow: realm.resetCredentialsFlow,
    registrationAllowed: realm.registrationAllowed,
    editUsernameAllowed: realm.editUsernameAllowed,
    identityProviders: [],
    clientScopes: [...realm.clientScopes, ...builtInScopes].map((sc) => ({ id: `id-${sc.name}`, ...sc })),
    defaultDefaultClientScopes: [...realm.defaultDefaultClientScopes],
    defaultOptionalClientScopes: ["offline_access"],
    // Keycloak adds offline_access, uma_authorization and the default role
    // default-roles-<realm> (every user holds it), with the account client's
    // roles, to a realm imported from this file.
    roles: { realm: [...structuredClone(realm.roles.realm), { name: "offline_access", composite: false, clientRole: false }, { name: "uma_authorization", composite: false, clientRole: false },
      { name: "default-roles-fintechbankx", composite: true, clientRole: false, composites: { realm: ["offline_access", "uma_authorization"], client: { account: ["view-profile", "manage-account"] } } }],
    client: { account: [{ name: "view-profile", composite: false, clientRole: true }, { name: "manage-account", composite: true, clientRole: true, composites: { client: { account: ["manage-account-links"] } } },
      { name: "manage-account-links", composite: false, clientRole: true }] } },
    defaultRole: { name: "default-roles-fintechbankx", composite: true, clientRole: false },
    scopeMappings: structuredClone(realm.scopeMappings),
    clientScopeMappings: {}
  };
}
// What Keycloak's hasScope gives for a callee's client roles (ClientAdapter
// and ClientScopeAdapter, 26.7.5): a client with fullScopeAllowed (absent
// counts as true) has all of them; otherwise a role is in scope when an
// explicit realm-role or client-role scope mapping, or (for a client) one of
// its own client roles, is that role or a composite containing it, at any
// depth.
function keycloakScope(live, holder, callee) {
  const calleeRoles = (live.roles.client[callee] || []).map((r) => r.name);
  if (holder.clientId !== undefined && holder.fullScopeAllowed !== false) return calleeRoles;
  const matches = (m) => (holder.clientId !== undefined ? m.client === holder.clientId : m.clientScope === holder.name);
  const todo = [
    ...(live.scopeMappings || []).filter(matches).flatMap((m) => m.roles.map((n) => [null, n])),
    ...Object.entries(live.clientScopeMappings || {}).flatMap(([owner, ms]) => ms.filter(matches).flatMap((m) => m.roles.map((n) => [owner, n]))),
    ...(holder.clientId !== undefined ? (live.roles.client[holder.clientId] || []).map((r) => [holder.clientId, r.name]) : [])
  ];
  const seen = new Set();
  while (todo.length) {
    const [owner, name] = todo.pop();
    const key = JSON.stringify([owner, name]);
    if (seen.has(key)) continue;
    seen.add(key);
    const def = (owner === null ? live.roles.realm : live.roles.client[owner] || []).find((r) => r.name === name);
    for (const n of def?.composites?.realm || []) todo.push([null, n]);
    for (const [id, ns] of Object.entries(def?.composites?.client || {})) for (const n of ns) todo.push([id, n]);
  }
  return calleeRoles.filter((n) => seen.has(JSON.stringify([callee, n])));
}
// The admin API of that realm: token, paged clients, client scopes, realm
// default scopes, a client's roles, and the effective (composite) client-role
// scope mappings of a client or client scope, answered as Keycloak does
// (keycloakScope), not from the explicit mappings alone.
function adminApi(live) {
  const urls = [];
  const json = (body) => new Response(JSON.stringify(body), { status: 200 });
  const byId = (list, id) => list.find((x) => x.id === decodeURIComponent(id));
  const roleId = (owner, r) => (owner === null ? `id-${r.name}` : `id-${owner}-role-${r.name}`);
  const roleRep = (owner, r) => ({ id: roleId(owner, r), name: r.name, composite: !!r.composite, clientRole: owner !== null, containerId: owner === null ? "id-realm" : `id-${owner}` });
  const roleById = (id) => [...live.roles.realm.map((r) => [null, r]), ...Object.entries(live.roles.client).flatMap(([owner, rs]) => rs.map((r) => [owner, r]))]
    .find(([owner, r]) => roleId(owner, r) === id)?.[1];
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
    if (p === "") return json({ realm: "fintechbankx", resetCredentialsFlow: live.resetCredentialsFlow, registrationAllowed: live.registrationAllowed, editUsernameAllowed: live.editUsernameAllowed, defaultRole: live.defaultRole });
    if (p === "/identity-provider/instances") return json(live.identityProviders || []);
    if (p === "/roles") return json(live.roles.realm.map((r) => roleRep(null, r)));
    // Keycloak 26.7.5 lists the top-level flows but saml ecp
    // (AuthenticationManagementResource.getFlows); its executions are still
    // read by alias below.
    if (p === "/authentication/flows") return json(live.authenticationFlows.filter((f) => f.topLevel && f.alias !== SAML_ECP));
    let m = p.match(/^\/authentication\/flows\/([^/]+)\/executions$/);
    if (m) {
      const f = live.authenticationFlows.find((x) => x.alias === decodeURIComponent(m[1]));
      return f ? json(flattenFlow(live, f, 0)) : new Response("not found", { status: 404 });
    }
    m = p.match(/^\/authentication\/(flows|config)\/([^/]+)$/);
    if (m) {
      const x = byId(m[1] === "flows" ? live.authenticationFlows : live.authenticatorConfig, m[2]);
      return x ? json(x) : new Response("not found", { status: 404 });
    }
    // A role's own composites (GET /roles-by-id/{id}/composites), realm and
    // client roles alike, a client role naming its client's id.
    m = p.match(/^\/roles-by-id\/([^/]+)\/composites$/);
    if (m) {
      const role = roleById(decodeURIComponent(m[1]));
      if (!role) return new Response("not found", { status: 404 });
      const def = (owner, name) => (owner === null ? live.roles.realm : live.roles.client[owner] || []).find((r) => r.name === name) || { name };
      return json([...(role.composites?.realm || []).map((n) => roleRep(null, def(null, n))),
        ...Object.entries(role.composites?.client || {}).flatMap(([owner, ns]) => ns.map((n) => roleRep(owner, def(owner, n))))]);
    }
    m = p.match(/^\/clients\/([^/]+)\/roles$/);
    if (m) return json(live.roles.client[byId(live.clients, m[1]).clientId] || []);
    m = p.match(/^\/(clients|client-scopes)\/([^/]+)\/scope-mappings\/clients\/([^/]+)\/composite$/);
    if (m) {
      const holder = byId(m[1] === "clients" ? live.clients : live.clientScopes, m[2]);
      return json(keycloakScope(live, holder, byId(live.clients, m[3]).clientId).map((name) => ({ name })));
    }
    return new Response("not found", { status: 404 });
  };
  return { fetch, urls };
}
// GET /authentication/flows/{alias}/executions (Keycloak 26.7.5): the flow's
// executions depth first, ordered by priority, a subflow row followed by its
// own; a subflow row carries flowId, an authenticator row its providerId and
// the id of its authenticator config.
function flattenFlow(live, flow, level) {
  const ordered = [...flow.authenticationExecutions].sort((a, b) => a.priority - b.priority);
  return ordered.flatMap((e, index) => {
    const base = { id: `exec-${flow.alias}-${index}`, requirement: e.requirement, level, index, priority: e.priority };
    if (e.authenticatorFlow) {
      const sub = live.authenticationFlows.find((f) => f.alias === e.flowAlias);
      return [{ ...base, displayName: e.flowAlias, authenticationFlow: true, flowId: sub?.id }, ...(sub ? flattenFlow(live, sub, level + 1) : [])];
    }
    // An execution names its config by alias in the flow representation and
    // by id here; configId (test only) picks one of two configs with one alias.
    const config = live.authenticatorConfig.find((c) => e.configId !== undefined && c.id === e.configId) || live.authenticatorConfig.find((c) => c.alias === e.authenticatorConfig);
    return [{ ...base, displayName: e.authenticator, providerId: e.authenticator, ...(config ? { authenticationConfig: config.id, alias: config.alias } : {}) }];
  });
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
// must contain svc-acc-accounts-ledger. Of the channel clients only staff web
// gets the audience (staff-only decision 2026-10-17, below); customer web,
// mobile, the TPP template and the staff SSO client do not: customer reads
// through them are a separate decision.
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
  assert.deepEqual(auds(input, "svc-ln-loan-lifecycle"), ["svc-cus-profile-kyc", "svc-rsk-decisioning"]);
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

test("no client carries the ledger audience as an always-on mapper, and only its four callers and staff web may request the scope", () => {
  const input = fresh();
  assert.deepEqual(withAudience(input, LEDGER), []);
  assert.deepEqual(withOptionalScope(input, LEDGER_SCOPE), [...LEDGER_CALLERS, STAFF_WEB].sort());
  for (const c of input.registry.channelClients.filter((x) => x.clientId !== STAFF_WEB)) assert.ok(!c.audiences.includes(LEDGER), `${c.clientId} must not carry ${LEDGER}`);
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
  client(onChannel, STAFF_WEB).protocolMappers.push(ledgerMapper);
  assert.ok(checkRealm(onChannel).some((e) => e.startsWith(`${STAFF_WEB}: audience ${LEDGER} is reached only through the optional scope ${LEDGER_SCOPE}`)), checkRealm(onChannel).join("\n"));
});

// Staff web and the ledger (user decision 2026-10-17, option "Staff only"):
// the staff SPA reaches the ledger's staff endpoints with the optional scope
// aud-svc-acc-accounts-ledger, which it names in its authorization request.
// Customer web, mobile, the TPP template, the staff SSO client and Keycloak's
// built-ins stay without it. Endpoints read from the ledger repository
// (AccountController, JournalEntryController @PreAuthorize).
const STAFF_WEB = "fintechbankx-staff-web";
const STAFF_LEDGER_PROVENANCE = "derived (platform pillar, staff-only decision 2026-10-17): staff endpoints of the accounts ledger (GET /api/v1/accounts/{accountId}, account open, freeze, unfreeze and close for banker and admin; GET /api/v1/journal-entries/{journalEntryId} for banker and admin; POST /api/v1/journal-entries for admin), not yet confirmed by the accounts ledger thread";
const NOT_LEDGER_CHANNELS = ["fintechbankx-web", "fintechbankx-mobile", "of-tpp-conformance-template"];
const notRegistryScope = (id) => `${id}: optional audience scopes ${LEDGER_SCOPE} are only for the registry clients (service, channel or staff SSO) whose registry audiences list the callee`;
const staffLedgerMapper = () => ({ name: `aud-${LEDGER}`, protocol: "openid-connect", protocolMapper: "oidc-audience-mapper", consentRequired: false,
  config: { "included.client.audience": LEDGER, "access.token.claim": "true", "id.token.claim": "false", "introspection.token.claim": "true", "lightweight.claim": "false" } });

test("staff web reaches the ledger only through the optional scope aud-svc-acc-accounts-ledger (staff-only decision 2026-10-17)", () => {
  const input = fresh();
  const entry = input.registry.channelClients.find((c) => c.clientId === STAFF_WEB);
  assert.ok(entry.audiences.includes(LEDGER), `registry audience ${LEDGER} missing on ${STAFF_WEB}`);
  assert.equal(entry.audienceProvenance[LEDGER], STAFF_LEDGER_PROVENANCE);
  const c = client(input, STAFF_WEB);
  assert.deepEqual(c.optionalClientScopes, [LEDGER_SCOPE]);
  assert.ok(!c.defaultClientScopes.includes(LEDGER_SCOPE));
  assert.ok(!auds(input, STAFF_WEB).includes(LEDGER), `${STAFF_WEB}: ${LEDGER} must not be an always-on audience mapper`);
  for (const id of NOT_LEDGER_CHANNELS) {
    assert.ok(!input.registry.channelClients.find((x) => x.clientId === id).audiences.includes(LEDGER), id);
    assert.ok(![...client(input, id).defaultClientScopes, ...client(input, id).optionalClientScopes].includes(LEDGER_SCOPE), id);
  }
  for (const s of input.registry.ssoClients) assert.ok(!(client(input, s.clientId).optionalClientScopes || []).includes(LEDGER_SCOPE), s.clientId);
});

// The gate cases, applied to the realm file (static) and to a running realm
// (--live through the admin API and --live-export, which must agree).
const STAFF_LEDGER_CASES = [
  ["staff web without the scope", (clients) => { clients(STAFF_WEB).optionalClientScopes = []; },
    [`${STAFF_WEB}: optional audience scopes <none> != registry ${LEDGER_SCOPE}`]],
  ["the scope as a default scope of staff web", (clients) => { const c = clients(STAFF_WEB); c.optionalClientScopes = []; c.defaultClientScopes.push(LEDGER_SCOPE); },
    [`${STAFF_WEB}: audience scope ${LEDGER_SCOPE} must be optional, not default`, `${STAFF_WEB}: optional audience scopes <none> != registry ${LEDGER_SCOPE}`]],
  ["a ledger mapper on staff web", (clients) => clients(STAFF_WEB).protocolMappers.push(staffLedgerMapper()),
    [`${STAFF_WEB}: audience ${LEDGER} is reached only through the optional scope ${LEDGER_SCOPE} (registry audienceByScope), never through a mapper`]],
  ...NOT_LEDGER_CHANNELS.map((id) => [`the scope on ${id}`, (clients) => clients(id).optionalClientScopes.push(LEDGER_SCOPE),
    [`${id}: optional audience scopes ${LEDGER_SCOPE} != registry <none>`]]),
  ["the scope on svc-obs-grafana", (clients) => clients("svc-obs-grafana").optionalClientScopes.push(LEDGER_SCOPE), [`svc-obs-grafana: optional audience scopes ${LEDGER_SCOPE} != registry <none>`]]
];

test("staff web: the gate requires the ledger scope there as optional, refuses it as default or as a mapper, and on any other channel or SSO client", () => {
  for (const [name, mutate, expected] of STAFF_LEDGER_CASES) {
    const input = fresh();
    mutate((id) => client(input, id));
    for (const e of expected) failsWith(input, e);
    assert.ok(checkRealm(input).length > 0, name);
  }
  // A ledger mapper on staff web also breaks the mapper list.
  const mapped = fresh();
  client(mapped, STAFF_WEB).protocolMappers.push(staffLedgerMapper());
  assert.ok(checkRealm(mapped).some((e) => e.startsWith(`${STAFF_WEB}: audience mappers `) && e.includes(LEDGER)), checkRealm(mapped).join("\n"));
  // A client outside the registry (a Keycloak built-in) with the scope.
  const builtIn = fresh();
  builtIn.realm.clients.push({ clientId: "admin-cli", fullScopeAllowed: false, attributes: {}, protocolMappers: [], defaultClientScopes: [], optionalClientScopes: [LEDGER_SCOPE] });
  failsWith(builtIn, notRegistryScope("admin-cli"));
});

test("live: staff web holds the ledger scope exactly there, the same through the admin API and a partial export", async () => {
  const cases = [
    ...STAFF_LEDGER_CASES,
    ["the scope on admin-cli", (clients) => clients("admin-cli").optionalClientScopes.push(LEDGER_SCOPE), [notRegistryScope("admin-cli")]],
    ["the scope on a runtime TPP client", (clients, l) => l.clients.push({ ...structuredClone(clients("of-tpp-conformance-template")), id: "id-of-tpp-acme-pay", clientId: "of-tpp-acme-pay", optionalClientScopes: ["payments", LEDGER_SCOPE] }),
      [notRegistryScope("of-tpp-acme-pay")]],
    ["staff web missing", (_clients, l) => { l.clients = l.clients.filter((c) => c.clientId !== STAFF_WEB); }, [`channel client ${STAFF_WEB} missing from realm`]]
  ];
  for (const [name, mutate, expected] of cases) {
    const live = liveRealm();
    mutate((id) => liveClient(live, id), live);
    const errors = await liveErrors(live);
    for (const e of expected) assert.ok(errors.includes(e), `${name}: ${e} not in\n${errors.join("\n")}`);
  }
});

// Staff sign-in (DevSecOps 2026-10-17, REALM_AS_CODE gap 5): staff web binds
// its browser flow to fbx-staff-browser, which signs the user in as the
// built-in browser flow does (cookie, else username and password, then OTP if
// the user has one) and then denies every user who holds none of the staff
// roles. Keycloak's role condition (conditional-user-role, 26.7.5) is false
// for a role name it cannot find, whatever negate says, so one unknown role
// lets every user through: the gate requires the exact flow, negate "true" and
// every staff role to exist.
const STAFF_FLOW = "fbx-staff-browser";
const flowOf = (realm, alias) => realm.authenticationFlows.find((f) => f.alias === alias);
const staffOnly = (realm) => flowOf(realm, `${STAFF_FLOW} staff only`);
const staffConfig = (realm, role) => realm.authenticatorConfig.find((c) => c.alias === `${STAFF_FLOW} not ${role}`);
const flowDiffers = `flow ${STAFF_FLOW}: differs from the realm-as-code`;
const overrideRefused = `${STAFF_WEB}: authenticationFlowBindingOverrides.browser must be the flow ${STAFF_FLOW}`;
// "Forgot password" ends in a sign-in to the client it started from, through
// the realm's reset credentials flow, which no client override reaches: a
// customer reset from staff web's login page and got a staff web token with
// the ledger audience (local Keycloak 26.7.5, SMTP sink). The realm's reset
// flow fbx-reset-credentials is the built-in one plus the same staff check
// after the e-mail step (before the password is set), limited by a
// client-scope condition to clients with the marker scope fbx-staff-channel
// (a default scope of every staff channel client). Self-registration and
// identity providers would sign users in without either flow; direct grant
// would use the realm's direct grant flow.
const RESET_FLOW = "fbx-reset-credentials";
const MARKER = "fbx-staff-channel";
const resetDiffers = `flow ${RESET_FLOW}: differs from the realm-as-code`;
const resetBinding = `realm: resetCredentialsFlow must be the flow ${RESET_FLOW}`;
const markerMissing = `${STAFF_WEB}: client scope ${MARKER} must be a default scope`;

test("staff web signs in only users with a staff role: browser flow fbx-staff-browser, sign-in first, then deny without a staff role", () => {
  const { realm, registry } = fresh();
  const staffClients = registry.channelClients.filter((c) => c.userType === "staff").map((c) => c.clientId);
  assert.deepEqual(staffClients, [STAFF_WEB]);
  assert.deepEqual(client({ realm }, STAFF_WEB).authenticationFlowBindingOverrides, { browser: STAFF_FLOW });
  for (const id of ["fintechbankx-web", "fintechbankx-mobile"]) assert.equal(client({ realm }, id).authenticationFlowBindingOverrides, undefined, id);
  const steps = (alias) => flowOf(realm, alias).authenticationExecutions.map((e) => `${e.requirement} ${e.authenticatorFlow ? `flow:${e.flowAlias}` : e.authenticator}`);
  assert.equal(flowOf(realm, STAFF_FLOW).topLevel, true);
  assert.deepEqual(steps(STAFF_FLOW), [`REQUIRED flow:${STAFF_FLOW} sign-in`, `CONDITIONAL flow:${STAFF_FLOW} staff only`,
    `CONDITIONAL flow:${STAFF_FLOW} sod cmp`, `CONDITIONAL flow:${STAFF_FLOW} sod pay`]);
  assert.deepEqual(steps(`${STAFF_FLOW} sign-in`), ["ALTERNATIVE auth-cookie", `ALTERNATIVE flow:${STAFF_FLOW} forms`]);
  assert.deepEqual(steps(`${STAFF_FLOW} forms`), ["REQUIRED auth-username-password-form", `CONDITIONAL flow:${STAFF_FLOW} OTP`]);
  assert.deepEqual(steps(`${STAFF_FLOW} OTP`), ["REQUIRED conditional-user-configured", "REQUIRED auth-otp-form"]);
  assert.deepEqual(steps(`${STAFF_FLOW} staff only`), [...STAFF.map(() => "REQUIRED conditional-user-role"), "REQUIRED deny-access-authenticator"]);
  // One negated condition per role staff web maps (its role scope), so the
  // deny runs only for a user who has none of them.
  const conditions = staffOnly(realm).authenticationExecutions.filter((e) => e.authenticator === "conditional-user-role")
    .map((e) => realm.authenticatorConfig.find((c) => c.alias === e.authenticatorConfig).config);
  assert.deepEqual(conditions.map((c) => c.condUserRole).sort(), scopeRoles({ realm }, STAFF_WEB));
  // One staff role list: the LDAP groups of check-realm.mjs and the flow's.
  assert.deepEqual(Object.values(realmCheck.STAFF_ROLE_GROUPS), FLOW_STAFF_ROLES);
  for (const c of conditions) assert.deepEqual(c, { condUserRole: c.condUserRole, negate: "true" });
  for (const f of realm.authenticationFlows) assert.equal(f.providerId, "basic-flow", f.alias);
  // A forgotten password resets through the built-in reset credentials flow plus the staff check
  // for staff channel clients after the e-mail step, before the new password.
  assert.equal(realm.resetCredentialsFlow, RESET_FLOW);
  assert.equal(flowOf(realm, RESET_FLOW).topLevel, true);
  assert.deepEqual(steps(RESET_FLOW), ["REQUIRED reset-credentials-choose-user", "REQUIRED reset-credential-email", `CONDITIONAL flow:${RESET_FLOW} staff only`,
    `CONDITIONAL flow:${RESET_FLOW} sod cmp`, `CONDITIONAL flow:${RESET_FLOW} sod pay`, "REQUIRED reset-password", `CONDITIONAL flow:${RESET_FLOW} OTP`]);
  assert.deepEqual(steps(`${RESET_FLOW} OTP`), ["REQUIRED conditional-user-configured", "REQUIRED reset-otp"]);
  assert.deepEqual(steps(`${RESET_FLOW} staff only`), ["REQUIRED conditional-client-scope", ...STAFF.map(() => "REQUIRED conditional-user-role"), "REQUIRED deny-access-authenticator"]);
  const cfg = (e) => realm.authenticatorConfig.find((c) => c.alias === e.authenticatorConfig).config;
  const resetChecks = flowOf(realm, `${RESET_FLOW} staff only`).authenticationExecutions;
  assert.deepEqual(cfg(resetChecks[0]), { client_scope: MARKER, negate: "false" });
  assert.deepEqual(resetChecks.slice(1, -1).map(cfg), conditions);
  // The marker: a default scope of staff web only, no mappers, not in the
  // token's scope claim, never a realm default.
  const marker = realm.clientScopes.find((x) => x.name === MARKER);
  assert.deepEqual(marker.protocolMappers || [], []);
  assert.equal(marker.attributes["include.in.token.scope"], "false");
  assert.deepEqual(realm.clients.filter((c) => (c.defaultClientScopes || []).includes(MARKER)).map((c) => c.clientId), [STAFF_WEB]);
  assert.ok(![...realm.defaultDefaultClientScopes, ...(realm.defaultOptionalClientScopes || [])].includes(MARKER));
  assert.equal(realm.registrationAllowed, false);
  assert.equal(realm.identityProviders, undefined);
  assert.equal(client({ realm }, STAFF_WEB).directAccessGrantsEnabled, false);
});

test("the gate refuses staff web without the staff flow, and any flow that lets a user without a staff role through", () => {
  const cases = [
    ["no override", (r) => { delete client({ realm: r }, STAFF_WEB).authenticationFlowBindingOverrides; }, overrideRefused],
    ["override to the built-in browser flow", (r) => { client({ realm: r }, STAFF_WEB).authenticationFlowBindingOverrides = { browser: "browser" }; }, overrideRefused],
    ["override to an unknown flow id", (r) => { client({ realm: r }, STAFF_WEB).authenticationFlowBindingOverrides = { browser: "0b1c" }; }, overrideRefused],
    ["flow missing", (r) => { r.authenticationFlows = r.authenticationFlows.filter((f) => f.alias !== STAFF_FLOW); }, `flow ${STAFF_FLOW} missing`],
    ["negate false", (r) => { staffConfig(r, "auditor").config.negate = "false"; }, flowDiffers],
    ["negate missing", (r) => { delete staffConfig(r, "banker").config.negate; }, flowDiffers],
    ["a role name that is not a realm role", (r) => { staffConfig(r, "banker").config.condUserRole = "bankers"; }, flowDiffers],
    ["a client role instead of the realm role", (r) => { staffConfig(r, "admin").config.condUserRole = "realm-management.realm-admin"; }, flowDiffers],
    ["a condition dropped", (r) => { staffOnly(r).authenticationExecutions.splice(0, 1); }, flowDiffers],
    ["a condition disabled", (r) => { staffOnly(r).authenticationExecutions[2].requirement = "DISABLED"; }, flowDiffers],
    ["deny disabled", (r) => { staffOnly(r).authenticationExecutions.at(-1).requirement = "DISABLED"; }, flowDiffers],
    ["deny replaced", (r) => { staffOnly(r).authenticationExecutions.at(-1).authenticator = "allow-access-authenticator"; }, flowDiffers],
    ["staff check alternative", (r) => { flowOf(r, STAFF_FLOW).authenticationExecutions[1].requirement = "ALTERNATIVE"; }, flowDiffers],
    ["staff check before sign-in", (r) => { const e = flowOf(r, STAFF_FLOW).authenticationExecutions; [e[0].priority, e[1].priority] = [e[1].priority, e[0].priority]; }, flowDiffers],
    ["an alternative next to sign-in", (r) => { flowOf(r, STAFF_FLOW).authenticationExecutions.push({ authenticator: "auth-cookie", authenticatorFlow: false, requirement: "ALTERNATIVE", priority: 5, userSetupAllowed: false }); }, flowDiffers],
    ["an extra sign-in route", (r) => { flowOf(r, `${STAFF_FLOW} sign-in`).authenticationExecutions.push({ authenticator: "identity-provider-redirector", authenticatorFlow: false, requirement: "ALTERNATIVE", priority: 50, userSetupAllowed: false }); }, flowDiffers],
    ["two executions with one priority", (r) => { const e = staffOnly(r).authenticationExecutions; e[1].priority = e[0].priority; }, `flow ${STAFF_FLOW} staff only: two executions share priority`],
    ["two configs with one alias", (r) => { r.authenticatorConfig.push({ alias: `${STAFF_FLOW} not banker`, config: { condUserRole: "customer", negate: "true" } }); }, `flow ${STAFF_FLOW}: authenticator config alias ${STAFF_FLOW} not banker is not unique`],
    ["a staff role removed from the realm", (r) => { r.roles.realm = r.roles.realm.filter((x) => x.name !== "auditor"); },
      `flow ${STAFF_FLOW}: realm role auditor does not exist; Keycloak's role condition is then false for every user and the flow lets everyone through`],
    // Forgot password, self-registration, identity providers, direct grant.
    ["built-in reset flow", (r) => { delete r.resetCredentialsFlow; }, resetBinding],
    ["reset flow bound to another flow", (r) => { r.resetCredentialsFlow = "reset credentials"; }, resetBinding],
    ["reset flow missing", (r) => { r.authenticationFlows = r.authenticationFlows.filter((f) => f.alias !== RESET_FLOW); }, `flow ${RESET_FLOW} missing`],
    ["reset staff check after the new password", (r) => { const e = flowOf(r, RESET_FLOW).authenticationExecutions; [e[2].priority, e[3].priority] = [e[3].priority, e[2].priority]; [e[2], e[3]] = [e[3], e[2]]; }, resetDiffers],
    ["reset staff check for every client", (r) => { flowOf(r, `${RESET_FLOW} staff only`).authenticationExecutions.shift(); }, resetDiffers],
    ["reset marker condition negated", (r) => { r.authenticatorConfig.find((c) => c.config.client_scope === MARKER).config.negate = "true"; }, resetDiffers],
    ["reset marker condition on another scope", (r) => { r.authenticatorConfig.find((c) => c.config.client_scope === MARKER).config.client_scope = "roles"; }, resetDiffers],
    ["reset role condition not negated", (r) => { r.authenticatorConfig.find((c) => c.alias === `${RESET_FLOW} not admin`).config.negate = "false"; }, resetDiffers],
    ["marker not on staff web", (r) => { const c = client({ realm: r }, STAFF_WEB); c.defaultClientScopes = c.defaultClientScopes.filter((x) => x !== MARKER); }, markerMissing],
    ["marker optional on staff web", (r) => { const c = client({ realm: r }, STAFF_WEB); c.defaultClientScopes = c.defaultClientScopes.filter((x) => x !== MARKER); c.optionalClientScopes.push(MARKER); }, markerMissing],
    ["marker scope missing", (r) => { r.clientScopes = r.clientScopes.filter((x) => x.name !== MARKER); }, `client scope ${MARKER} missing`],
    ["marker scope with a mapper", (r) => { r.clientScopes.find((x) => x.name === MARKER).protocolMappers = [{ name: "x", protocol: "openid-connect", protocolMapper: "oidc-hardcoded-claim-mapper", config: { "claim.name": "x", "claim.value": "y" } }]; },
      `client scope ${MARKER}: must have no protocol mappers`],
    ["self-registration on", (r) => { r.registrationAllowed = true; }, "realm: registrationAllowed must be false"],
    // Jackson trims and reads "true", "True" and "TRUE" as true; anything but
    // false, absent or a string Jackson reads as false is refused.
    ...[" true", "TRUE", "True ", 1, "yes", "", null].map((v) => [`registrationAllowed ${JSON.stringify(v)}`, (r) => { r.registrationAllowed = v; }, "realm: registrationAllowed must be false"]),
    ["executions listed out of priority order", (r) => { flowOf(r, `${STAFF_FLOW} OTP`).authenticationExecutions.reverse(); },
      `flow ${STAFF_FLOW} OTP: executions are not listed in priority order`],
    ["an identity provider", (r) => { r.identityProviders = [{ alias: "corp-idp", providerId: "oidc", enabled: true }]; }, "realm: identity provider corp-idp"],
    ["direct grant on staff web", (r) => { client({ realm: r }, STAFF_WEB).directAccessGrantsEnabled = true; }, `${STAFF_WEB}: directAccessGrantsEnabled must be false`]
  ];
  for (const [name, mutate, expected] of cases) {
    const input = fresh();
    mutate(input.realm);
    const errors = checkRealm(input);
    assert.ok(errors.some((e) => e.startsWith(expected)), `${name}: ${expected} not in\n${errors.join("\n")}`);
  }
  for (const v of [false, undefined, "false", " FALSE ", "False"]) {
    const input = fresh();
    input.realm.registrationAllowed = v;
    assert.deepEqual(checkRealm(input), [], `registrationAllowed ${JSON.stringify(v)}`);
  }
  // The override may name the flow by alias (realm file) or by id (export).
  const byId = fresh();
  flowOf(byId.realm, STAFF_FLOW).id = "4d2f3c1e-0000-4000-8000-000000000001";
  client(byId, STAFF_WEB).authenticationFlowBindingOverrides = { browser: "4d2f3c1e-0000-4000-8000-000000000001" };
  assert.deepEqual(checkRealm(byId), []);
});

// Review finding (minor): Jackson (Keycloak 26.7.5 and keycloak-config-cli
// 6.5.1) reads a JSON string as a Boolean only as true, True, TRUE, false,
// False or FALSE after Java's trim (characters up to U+0020); any other case
// or padding fails the import. The gate passed "fAlse", which the import
// rejects; it now passes only the spellings Jackson reads as false.
test("registrationAllowed: only false, absent or a string Jackson reads as false passes", () => {
  for (const v of ["fAlse", " fAlSe ", "FALSe", "\u00a0false", "false\u2003"]) {
    const input = fresh();
    input.realm.registrationAllowed = v;
    assert.ok(checkRealm(input).some((e) => e.startsWith("realm: registrationAllowed must be false")), `registrationAllowed ${JSON.stringify(v)} passed`);
  }
  for (const v of [false, undefined, "false", "False", "FALSE", " FALSE ", "\tfalse\n", "\u0001False\u0020"]) {
    const input = fresh();
    input.realm.registrationAllowed = v;
    assert.deepEqual(checkRealm(input), [], `registrationAllowed ${JSON.stringify(v)}`);
  }
});

test("live: staff web's sign-in flow, the same through the admin API and a partial export", async () => {
  const liveFlow = (l, alias) => l.authenticationFlows.find((f) => f.alias === alias);
  const cases = [
    ["override removed", (l) => { delete liveClient(l, STAFF_WEB).authenticationFlowBindingOverrides; }, overrideRefused],
    ["override to the built-in browser flow", (l) => { liveClient(l, STAFF_WEB).authenticationFlowBindingOverrides = { browser: "id-browser" }; }, overrideRefused],
    ["override to a subflow", (l) => { liveClient(l, STAFF_WEB).authenticationFlowBindingOverrides = { browser: `id-${STAFF_FLOW} sign-in` }; }, overrideRefused],
    ["staff flow deleted", (l) => { l.authenticationFlows = l.authenticationFlows.filter((f) => !f.alias.startsWith(STAFF_FLOW)); }, `flow ${STAFF_FLOW} missing`],
    ["negate flipped", (l) => { l.authenticatorConfig.find((c) => c.alias === `${STAFF_FLOW} not admin`).config.negate = "false"; }, flowDiffers],
    ["deny disabled", (l) => { liveFlow(l, `${STAFF_FLOW} staff only`).authenticationExecutions.at(-1).requirement = "DISABLED"; }, flowDiffers],
    ["staff check alternative", (l) => { liveFlow(l, STAFF_FLOW).authenticationExecutions[1].requirement = "ALTERNATIVE"; }, flowDiffers],
    ["realm role deleted", (l) => { l.roles.realm = l.roles.realm.filter((r) => r.name !== "compliance_officer"); },
      `flow ${STAFF_FLOW}: realm role compliance_officer does not exist; Keycloak's role condition is then false for every user and the flow lets everyone through`],
    ["reset flow back to the built-in", (l) => { l.resetCredentialsFlow = "reset credentials"; }, resetBinding],
    ["reset marker negated", (l) => { l.authenticatorConfig.find((c) => c.config.client_scope === MARKER).config.negate = "true"; }, resetDiffers],
    ["marker removed from staff web", (l) => { const c = liveClient(l, STAFF_WEB); c.defaultClientScopes = c.defaultClientScopes.filter((x) => x !== MARKER); }, markerMissing],
    ["self-registration on", (l) => { l.registrationAllowed = true; }, "realm: registrationAllowed must be false"],
    ["an identity provider", (l) => { l.identityProviders = [{ alias: "corp-idp", providerId: "oidc", enabled: true }]; }, "realm: identity provider corp-idp"]
  ];
  for (const [name, mutate, expected] of cases) {
    const live = liveRealm();
    mutate(live);
    const errors = await liveErrors(live);
    assert.ok(errors.some((e) => e.startsWith(expected)), `${name}: ${expected} not in\n${errors.join("\n")}`);
  }
  // The admin API answers the override with a flow id; the check reads the
  // flow tree, its configs and the realm roles.
  const api = adminApi(liveRealm());
  const ok = await realmCheck.checkLive({ argv: ["node", "check-realm.mjs", "--live"], env: LIVE_ENV, fetch: api.fetch });
  assert.deepEqual(ok.errors, []);
  for (const p of ["/roles", "/authentication/flows", `/authentication/flows/${STAFF_FLOW}/executions`, `/authentication/flows/${encodeURIComponent(`id-${STAFF_FLOW} staff only`)}`,
    `/authentication/config/${encodeURIComponent(`id-${STAFF_FLOW} not banker`)}`, `/authentication/flows/${RESET_FLOW}/executions`, "/identity-provider/instances"]) {
    assert.ok(api.urls.some((u) => u.startsWith(`http://kc.test/admin/realms/fintechbankx${p}`)), `${p} not fetched: ${api.urls.join(" ")}`);
  }
});

// Review finding (blocker): the flow trees were compared as joined strings,
// so the one-key config {condUserRole: "banker,negate=true"} read like the
// expected {condUserRole: "banker", negate: "true"} while Keycloak looked up
// the unknown role "banker,negate=true", found none and skipped the deny
// (local Keycloak 26.7.5). The trees compare as structures: every config an
// exact key set with exact string values, and the error names the step.
const roleStep = (cfg) => `REQUIRED conditional-user-role ${JSON.stringify(Object.fromEntries(Object.entries(cfg).sort()))}`;
const STAFF_CONFIG_SPOOFS = [
  ["a value holding ',negate=true'", { condUserRole: "banker,negate=true" }],
  ["a key holding '=' and ','", { "condUserRole=banker,negate": "true" }],
  ["an extra key", { condUserRole: "banker", negate: "true", extra: "x" }],
  ["a value holding '='", { condUserRole: "banker", negate: "true=true" }]
];
const spoofDiff = (cfg) => `${STAFF_FLOW} staff only step 1: got ${roleStep(cfg)}, want ${roleStep({ condUserRole: "banker", negate: "true" })}`;
const MARKER_SPOOF = { client_scope: `${MARKER},negate=false` };
const markerDiff = `${RESET_FLOW} staff only step 1: got REQUIRED conditional-client-scope ${JSON.stringify(MARKER_SPOOF)}, want REQUIRED conditional-client-scope ${JSON.stringify({ client_scope: MARKER, negate: "false" })}`;

test("the staff flows compare as structures: a config value or key holding ',' or '=', or an extra key, is refused and named", () => {
  for (const [name, cfg] of STAFF_CONFIG_SPOOFS) {
    const input = fresh();
    staffConfig(input.realm, "banker").config = structuredClone(cfg);
    const errors = checkRealm(input);
    const e = errors.find((x) => x.startsWith(flowDiffers));
    assert.ok(e, `${name}: ${flowDiffers} not in\n${errors.join("\n")}`);
    assert.ok(e.endsWith(`: ${spoofDiff(cfg)}`), `${name}: ${e}`);
  }
  const input = fresh();
  input.realm.authenticatorConfig.find((c) => c.config.client_scope === MARKER).config = structuredClone(MARKER_SPOOF);
  const errors = checkRealm(input);
  assert.ok(errors.some((x) => x.startsWith(resetDiffers) && x.includes(`: ${markerDiff}`)), errors.join("\n"));
});

test("live: the staff flows compare as structures, the same through the admin API and a partial export", async () => {
  for (const [name, cfg] of STAFF_CONFIG_SPOOFS) {
    const live = liveRealm();
    live.authenticatorConfig.find((c) => c.alias === `${STAFF_FLOW} not banker`).config = structuredClone(cfg);
    const errors = await liveErrors(live);
    assert.ok(errors.some((x) => x.startsWith(flowDiffers) && x.endsWith(`: ${spoofDiff(cfg)}`)), `${name}:\n${errors.join("\n")}`);
  }
  const live = liveRealm();
  live.authenticatorConfig.find((c) => c.config.client_scope === MARKER).config = structuredClone(MARKER_SPOOF);
  const errors = await liveErrors(live);
  assert.ok(errors.some((x) => x.startsWith(resetDiffers) && x.includes(`: ${markerDiff}`)), errors.join("\n"));
});

// Review finding (major): Keycloak's role condition asks hasRole, which counts
// composites and the default role default-roles-<realm> that every user
// holds. A staff role in the composites of customer, of the default role or
// of a client role they reach let customers (or every user) through the deny
// (local Keycloak 26.7.5). Staff roles come only from the /staff/fbx-* groups.
const viaComposite = (holder, staffRole) => `realm role ${holder} reaches staff role ${staffRole} through its composites`;
const viaDefaultRole = (staffRole) => `realm: default role default-roles-fintechbankx reaches staff role ${staffRole} through its composites`;
const viaGroup = (group, staffRole) => `group ${group} grants staff role ${staffRole}`;
const realmRoleOf = (r, name) => r.roles.realm.find((x) => x.name === name);
const STAFF_ROLE_ROUTES = [
  ["customer a composite of auditor", (r) => Object.assign(realmRoleOf(r, "customer"), { composite: true, composites: { realm: ["auditor"] } }), viaComposite("customer", "auditor")],
  ["customer reaches banker through a client role", (r) => {
    r.roles.client = { ...(r.roles.client || {}), "fintechbankx-web": [{ name: "bundle", composite: true, clientRole: true, composites: { realm: ["banker"] } }] };
    Object.assign(realmRoleOf(r, "customer"), { composite: true, composites: { client: { "fintechbankx-web": ["bundle"] } } });
  }, viaComposite("customer", "banker")],
  ["admin a composite of loan_officer", (r) => Object.assign(realmRoleOf(r, "admin"), { composite: true, composites: { realm: ["loan_officer"] } }), viaComposite("admin", "loan_officer")]
];

test("a staff role is refused in another role's composites, in the default role and on a group outside /staff/fbx-*", () => {
  const cases = [
    ...STAFF_ROLE_ROUTES,
    ["the default role reaches auditor", (r) => { r.roles.realm.push({ name: "default-roles-fintechbankx", composite: true, clientRole: false, composites: { realm: ["offline_access", "auditor"] } }); }, viaDefaultRole("auditor")],
    ["/customers grants auditor", (r) => { r.groups.find((g) => g.path === "/customers").realmRoles.push("auditor"); }, viaGroup("/customers", "auditor")],
    ["/staff grants admin", (r) => { r.groups.find((g) => g.path === "/staff").realmRoles.push("admin"); }, viaGroup("/staff", "admin")],
    ["a subgroup of /staff/fbx-banker grants compliance_officer", (r) => {
      r.groups.find((g) => g.path === "/staff").subGroups.find((g) => g.name === "fbx-banker").subGroups.push({ name: "x", path: "/staff/fbx-banker/x", realmRoles: ["compliance_officer"], subGroups: [] });
    }, viaGroup("/staff/fbx-banker/x", "compliance_officer")],
    ["/customers reaches banker through a client role", (r) => {
      r.roles.client = { "fintechbankx-web": [{ name: "bundle", composite: true, clientRole: true, composites: { realm: ["banker"] } }] };
      r.groups.find((g) => g.path === "/customers").clientRoles = { "fintechbankx-web": ["bundle"] };
    }, viaGroup("/customers", "banker")]
  ];
  for (const [name, mutate, expected] of cases) {
    const input = fresh();
    mutate(input.realm);
    const errors = checkRealm(input);
    assert.ok(errors.some((e) => e.startsWith(expected)), `${name}: ${expected} not in\n${errors.join("\n")}`);
  }
});

// Review finding (major): Keycloak 26.7.5 still reads the legacy
// RealmRepresentation field defaultRoles, and each client's defaultRoles,
// when the realm file has no defaultRole: it adds those roles to the default
// role default-roles-<realm>, which every user holds
// (DefaultExportImportManager.convertDeprecatedDefaultRoles). "defaultRoles":
// ["auditor"] passed the gate and let every user through the staff check.
const legacyDefaultRoles = (holder) => `${holder}: legacy key defaultRoles is not allowed`;

test("the legacy defaultRoles key is refused on the realm and on any client of the realm file", () => {
  const cases = [
    ["realm defaultRoles [auditor]", (r) => { r.defaultRoles = ["auditor"]; }, legacyDefaultRoles("realm")],
    ["realm defaultRoles []", (r) => { r.defaultRoles = []; }, legacyDefaultRoles("realm")],
    ["client defaultRoles on fintechbankx-web", (r) => { client({ realm: r }, "fintechbankx-web").defaultRoles = ["bundle"]; }, legacyDefaultRoles("fintechbankx-web")]
  ];
  for (const [name, mutate, expected] of cases) {
    const input = fresh();
    mutate(input.realm);
    const errors = checkRealm(input);
    assert.ok(errors.some((e) => e.startsWith(expected)), `${name}: ${expected} not in\n${errors.join("\n")}`);
  }
});

// Review finding (minor): "staff roles reach users only through the LDAP
// groups /staff/fbx-*" held for groups and roles but not for the users of the
// realm file: a user with realmRoles ["admin"] passed. A realm-file user other
// than a service account holds no staff role, directly, through a client
// role's composites or through any group (/staff/fbx-* included: realm-file
// users are local, not from the directory).
const userHoldsStaff = (user, staffRole) => `user ${user} holds staff role ${staffRole}`;

test("a realm-file user other than a service account holds no staff role: directly, through a client role's composites or through a group", () => {
  const user = (username, extra) => ({ username, enabled: true, realmRoles: [], clientRoles: {}, groups: [], ...extra });
  const cases = [
    ["a staff realm role", (r) => r.users.push(user("alice", { realmRoles: ["admin"] })), userHoldsStaff("alice", "admin")],
    ["a client role reaching banker", (r) => {
      r.roles.client = { "fintechbankx-web": [{ name: "bundle", composite: true, clientRole: true, composites: { realm: ["banker"] } }] };
      r.users.push(user("bob", { clientRoles: { "fintechbankx-web": ["bundle"] } }));
    }, userHoldsStaff("bob", "banker")],
    ["a realm role reaching compliance_officer", (r) => {
      Object.assign(realmRoleOf(r, "customer"), { composite: true, composites: { realm: ["compliance_officer"] } });
      r.users.push(user("frank", { realmRoles: ["customer"] }));
    }, userHoldsStaff("frank", "compliance_officer")],
    ["a staff group", (r) => r.users.push(user("carol", { groups: ["/staff/fbx-auditor"] })), userHoldsStaff("carol", "auditor")],
    ["a group outside /staff/fbx-* reaching loan_officer", (r) => {
      r.groups.push({ name: "ops", path: "/ops", realmRoles: ["loan_officer"], attributes: {}, subGroups: [] });
      r.users.push(user("dave", { groups: ["/ops"] }));
    }, userHoldsStaff("dave", "loan_officer")],
    ["a subgroup of a group granting admin", (r) => {
      r.groups.push({ name: "ops", path: "/ops", realmRoles: ["admin"], attributes: {}, subGroups: [{ name: "night", path: "/ops/night", realmRoles: [], attributes: {}, subGroups: [] }] });
      r.users.push(user("erin", { groups: ["/ops/night"] }));
    }, userHoldsStaff("erin", "admin")]
  ];
  for (const [name, mutate, expected] of cases) {
    const input = fresh();
    mutate(input.realm);
    const errors = checkRealm(input);
    assert.ok(errors.some((e) => e.startsWith(expected)), `${name}: ${expected} not in\n${errors.join("\n")}`);
  }
  // A customer in /customers and the service accounts pass.
  const ok = fresh();
  ok.realm.users.push(user("cust1", { realmRoles: ["customer"], groups: ["/customers"] }));
  assert.deepEqual(checkRealm(ok), []);
  const sa = fresh();
  sa.realm.users.find((u) => u.serviceAccountClientId === "svc-cus-profile-kyc").realmRoles.push("auditor");
  assert.deepEqual(checkRealm(sa).filter((e) => e.startsWith("user ")), []);
});

test("live: a staff role in another role's composites or in the default role is refused, the same through the admin API and a partial export", async () => {
  const cases = [
    ...STAFF_ROLE_ROUTES,
    ["the default role reaches auditor", (l) => realmRoleOf(l, "default-roles-fintechbankx").composites.realm.push("auditor"), viaDefaultRole("auditor")],
    ["the default role reaches banker through the account client's manage-account", (l) => {
      l.roles.client.account.find((x) => x.name === "manage-account").composites.realm = ["banker"];
    }, viaDefaultRole("banker")]
  ];
  for (const [name, mutate, expected] of cases) {
    const live = liveRealm();
    mutate(live);
    const errors = await liveErrors(live);
    assert.ok(errors.some((e) => e.startsWith(expected)), `${name}: ${expected} not in\n${errors.join("\n")}`);
  }
  // --live reads a composite role's composites by id, and a composite client
  // role's too; the default role reaches only offline_access,
  // uma_authorization and account roles.
  const api = adminApi(liveRealm());
  const ok = await realmCheck.checkLive({ argv: ["node", "check-realm.mjs", "--live"], env: LIVE_ENV, fetch: api.fetch });
  assert.deepEqual(ok.errors, []);
  for (const p of ["/roles-by-id/id-default-roles-fintechbankx/composites", "/roles-by-id/id-account-role-manage-account/composites"]) {
    assert.ok(api.urls.includes(`http://kc.test/admin/realms/fintechbankx${p}`), `${p} not fetched: ${api.urls.join(" ")}`);
  }
  assert.ok(!api.urls.some((u) => u.includes("/roles-by-id/id-customer/")), "a role that is not composite is read by id");
});

// Review finding: --live read only the configs of the staff flows, a partial
// export lists every config, so a config of another flow reusing a staff
// config's alias (Keycloak 26.7.5 accepts that through PUT
// /authentication/config/{id}) failed --live-export only. --live now reads
// the executions of every top-level flow, so both refuse it alike.
test("live: a config of another flow that reuses a staff config's alias is refused alike through the admin API and a partial export", async () => {
  const live = liveRealm();
  live.authenticationFlows.push({ id: "id-rv copy", alias: "rv copy", description: "copy", providerId: "basic-flow", topLevel: true, builtIn: false,
    authenticationExecutions: [{ authenticator: "conditional-user-role", authenticatorFlow: false, requirement: "REQUIRED", priority: 10, userSetupAllowed: false,
      authenticatorConfig: `${STAFF_FLOW} not banker`, configId: "id-rv copy config" }] });
  live.authenticatorConfig.push({ id: "id-rv copy config", alias: `${STAFF_FLOW} not banker`, config: { condUserRole: "customer", negate: "false" } });
  const errors = await liveErrors(live);
  assert.ok(errors.includes(`flow ${STAFF_FLOW}: authenticator config alias ${STAFF_FLOW} not banker is not unique`), errors.join("\n"));
  const api = adminApi(live);
  await realmCheck.checkLive({ argv: ["node", "check-realm.mjs", "--live"], env: LIVE_ENV, fetch: api.fetch });
  for (const p of ["/authentication/flows/rv%20copy/executions", "/authentication/flows/browser/executions", `/authentication/config/${encodeURIComponent("id-rv copy config")}`]) {
    assert.ok(api.urls.includes(`http://kc.test/admin/realms/fintechbankx${p}`), `${p} not fetched: ${api.urls.join(" ")}`);
  }
});

// Review finding (minor): GET /authentication/flows (Keycloak 26.7.5) leaves
// out the top-level flow saml ecp, and --live read configs only through the
// executions of the listed flows, while a partial export lists every flow and
// every config, orphans included. Both views now hold the same: the
// top-level flows the admin API lists, and the subflows and configs named by
// the executions of every top-level flow, saml ecp included (read by alias).
const notUnique = (alias) => `flow ${STAFF_FLOW}: authenticator config alias ${alias} is not unique`;
const liveFlowOf = (l, alias) => l.authenticationFlows.find((f) => f.alias === alias);

test("live: --live and --live-export read the same flows and configs (saml ecp, orphan configs and flows, a subflow used twice)", async () => {
  assert.deepEqual(await liveErrors(liveRealm()), []);
  const cases = [
    ["a config in saml ecp that reuses a staff config's alias", (l) => {
      liveFlowOf(l, SAML_ECP).authenticationExecutions[0].authenticatorConfig = `${STAFF_FLOW} not banker`;
      liveFlowOf(l, SAML_ECP).authenticationExecutions[0].configId = "id-saml config";
      l.authenticatorConfig.push({ id: "id-saml config", alias: `${STAFF_FLOW} not banker`, config: { condUserRole: "customer", negate: "false" } });
    }, [notUnique(`${STAFF_FLOW} not banker`)]],
    ["a config in saml ecp with an alias of its own", (l) => {
      liveFlowOf(l, SAML_ECP).authenticationExecutions[0].authenticatorConfig = "saml basic";
      l.authenticatorConfig.push({ id: "id-saml basic", alias: "saml basic", config: {} });
    }, []],
    ["an orphan config with an alias of its own", (l) => { l.authenticatorConfig.push({ id: "id-orphan", alias: "orphan", config: { condUserRole: "customer" } }); }, []],
    ["the staff browser flow no longer top-level (an orphan subflow)", (l) => { liveFlowOf(l, STAFF_FLOW).topLevel = false; }, [overrideRefused, `flow ${STAFF_FLOW} missing`]],
    ["a staff subflow also used by another top-level flow", (l) => {
      l.authenticationFlows.push({ id: "id-rv share", alias: "rv share", description: "share", providerId: "basic-flow", topLevel: true, builtIn: false,
        authenticationExecutions: [{ authenticatorFlow: true, flowAlias: `${STAFF_FLOW} OTP`, requirement: "CONDITIONAL", priority: 10, userSetupAllowed: false }] });
    }, []]
  ];
  for (const [name, mutate, expected] of cases) {
    const live = liveRealm();
    mutate(live);
    const errors = await liveErrors(live);
    for (const e of expected) assert.ok(errors.some((x) => x.startsWith(e)), `${name}: ${e} not in\n${errors.join("\n")}`);
    if (!expected.length) assert.deepEqual(errors, [], name);
  }
  // --live reads saml ecp's executions by alias although GET
  // /authentication/flows does not list it.
  const api = adminApi(liveRealm());
  await realmCheck.checkLive({ argv: ["node", "check-realm.mjs", "--live"], env: LIVE_ENV, fetch: api.fetch });
  assert.ok(api.urls.includes("http://kc.test/admin/realms/fintechbankx/authentication/flows/saml%20ecp/executions"), api.urls.join(" "));
});

// Known limit: the export names a config by alias in the flow representation,
// so an orphan config that shares its alias with a config an execution uses
// cannot be told apart from it; --live-export refuses the alias as not unique,
// --live reads configs by id and never sees the orphan.
test("live: known limit: an orphan config that reuses a staff config's alias fails --live-export only", async () => {
  const live = liveRealm();
  live.authenticatorConfig.push({ id: "id-orphan banker", alias: `${STAFF_FLOW} not banker`, config: { condUserRole: "customer", negate: "false" } });
  const viaApi = await realmCheck.checkLive({ argv: ["node", "check-realm.mjs", "--live"], env: LIVE_ENV, fetch: adminApi(live).fetch });
  assert.deepEqual(viaApi.errors, []);
  const viaFile = (await liveFromFile(live)).errors;
  assert.ok(viaFile.includes(notUnique(`${STAFF_FLOW} not banker`)), viaFile.join("\n"));
});

// Review finding (minor): a top-level flow aliased . or .. made --live request
// /authentication/flows/./executions, which the URL parser collapses, so
// every --live and --verify-live run failed. Both modes report it by name.
test("live: a top-level flow aliased . or .. is named as an error in both modes, never requested", async () => {
  for (const alias of [".", ".."]) {
    const live = liveRealm();
    live.authenticationFlows.push({ id: `id-dots-${alias.length}`, alias, description: "dots", providerId: "basic-flow", topLevel: true, builtIn: false,
      authenticationExecutions: [{ authenticator: "auth-cookie", authenticatorFlow: false, requirement: "ALTERNATIVE", priority: 10, userSetupAllowed: false }] });
    const errors = await liveErrors(live);
    assert.deepEqual(errors, [`flow alias ${JSON.stringify(alias)} cannot be read through the admin API (URL paths collapse . and .. segments); rename it`], alias);
    const api = adminApi(live);
    await realmCheck.checkLive({ argv: ["node", "check-realm.mjs", "--live"], env: LIVE_ENV, fetch: api.fetch });
    assert.ok(!api.urls.some((u) => u.endsWith(`/authentication/flows/${alias}/executions`)), api.urls.join(" "));
  }
});

// Review finding (minor): nothing pinned the composite cycle guard of
// fetchLiveView. A composite realm role and a composite client role that
// reach each other: checkLive finishes, both modes give the same errors, and
// --live reads each role's composites once. The fake answers a second read of
// one roles-by-id URL with 500, so without the guard the test fails instead of
// looping.
test("live: a composite realm role and a composite client role that reach each other are read once each, the same through the admin API and a partial export", { timeout: 20000 }, async () => {
  const live = liveRealm();
  live.roles.client["fintechbankx-web"] = [{ name: "bundle", composite: true, clientRole: true, composites: { realm: ["customer", "banker"] } }];
  Object.assign(realmRoleOf(live, "customer"), { composite: true, composites: { client: { "fintechbankx-web": ["bundle"] } } });
  const api = adminApi(live);
  const counted = new Map();
  const fetch = async (url, init) => {
    const u = String(url);
    if (u.includes("/roles-by-id/")) {
      counted.set(u, (counted.get(u) || 0) + 1);
      if (counted.get(u) > 1) return new Response("read twice", { status: 500 });
    }
    return api.fetch(url, init);
  };
  const viaApi = await realmCheck.checkLive({ argv: ["node", "check-realm.mjs", "--live"], env: LIVE_ENV, fetch });
  const viaFile = await liveFromFile(live);
  assert.deepEqual(viaApi.errors, viaFile.errors);
  assert.equal(viaApi.errors.length, 1, viaApi.errors.join("\n"));
  assert.ok(viaApi.errors[0].startsWith(viaComposite("customer", "banker")), viaApi.errors[0]);
  const R = "http://kc.test/admin/realms/fintechbankx/roles-by-id";
  for (const id of ["id-customer", "id-fintechbankx-web-role-bundle", "id-default-roles-fintechbankx"]) assert.equal(counted.get(`${R}/${id}/composites`), 1, id);
  assert.ok([...counted.values()].every((n) => n === 1), JSON.stringify([...counted]));
});

// The staff SSO client (svc-obs-grafana) is a registry client like the
// service and channel clients: its audience mappers and optional audience
// scopes are its registry audiences (none today), in all three modes.
const audMapperFor = (aud) => ({ name: aud, protocol: "openid-connect", protocolMapper: "oidc-audience-mapper", consentRequired: false,
  config: { "included.client.audience": aud, "access.token.claim": "true", "id.token.claim": "false" } });

test("staff SSO client audiences: mappers and audience scopes equal its registry audiences, in all three modes", async () => {
  const GRAFANA = "svc-obs-grafana";
  const mapped = fresh();
  client(mapped, GRAFANA).protocolMappers.push(audMapperFor("svc-pay-initiation-settlement"));
  assert.deepEqual(checkRealm(mapped), [`${GRAFANA}: audience mappers svc-pay-initiation-settlement != registry <none>`]);
  const listed = fresh();
  const entry = listed.registry.ssoClients.find((c) => c.clientId === GRAFANA);
  entry.audiences = ["svc-cmp-evidence"];
  entry.audienceProvenance = { "svc-cmp-evidence": "derived (test)" };
  assert.deepEqual(checkRealm(listed), [`${GRAFANA}: audience mappers <none> != registry svc-cmp-evidence`]);
  client(listed, GRAFANA).protocolMappers.push(audMapperFor("svc-cmp-evidence"));
  assert.deepEqual(checkRealm(listed), []);
  const missing = fresh();
  missing.realm.clients = missing.realm.clients.filter((c) => c.clientId !== GRAFANA);
  assert.deepEqual(checkRealm(missing).filter((e) => e.includes(`${GRAFANA} missing`)), [`staff SSO client ${GRAFANA} missing from realm`]);
  const live = liveRealm();
  liveClient(live, GRAFANA).protocolMappers.push(audMapperFor("svc-pay-initiation-settlement"));
  assert.deepEqual(await liveErrors(live), [`${GRAFANA}: audience mappers svc-pay-initiation-settlement != registry <none>`]);
  const gone = liveRealm();
  gone.clients = gone.clients.filter((c) => c.clientId !== GRAFANA);
  assert.deepEqual(await liveErrors(gone), [`staff SSO client ${GRAFANA} missing from realm`]);
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

// Review finding (other audience routes): besides oidc-audience-mapper, three
// mapper kinds put the ledger into aud on Keycloak 26.7.5: any mapper writing
// claim aud (OIDCAttributeMapperHelper sets the real audience), and a
// hardcoded role or role name mapper yielding a ledger client role, which the
// audience resolve mapper (built-in scope roles) turns into aud even though the
// ledger has no such role. Refused on every client and every client scope.
const audClaimMapper = (type = "oidc-hardcoded-claim-mapper", claimName = "aud") => ({ name: claimName === "aud" ? "aud-claim" : `aud-claim ${claimName}`, protocol: "openid-connect", protocolMapper: type, consentRequired: false,
  config: { "claim.name": claimName, "claim.value": LEDGER, "user.attribute": "x", "jsonType.label": "String", "access.token.claim": "true" } });
// Keycloak 26.7.5 reads claim.name as a claim path (JsonUtils.splitClaimPath:
// unescaped dots split, a backslash escapes the next character) and sets the
// token's aud when the first component is aud. A client-credentials token of
// svc-cus-profile-kyc with a hardcoded-claim mapper spelled "aud.", "\aud" or
// "a\ud" carried aud=svc-acc-accounts-ledger; "Aud", "aud " and "aud\" did
// not. "aud.x" (a path under aud) did not either, but is refused as well.
const AUD_SPELLINGS = { "aud.": '["aud"]', "\\aud": '["aud"]', "a\\ud": '["aud"]', "aud.x": '["aud","x"]' };
const NOT_AUD_SPELLINGS = ["Aud", "aud ", "aud\\", "a\\.ud", "x.aud", "resource_access.aud"];
// Keycloak's client role mapper (oidc-usermodel-client-role-mapper) replaces
// ${client_id} in claim.name with the role's client id before reading the claim
// path: with a client named aud holding a role named svc-acc-accounts-ledger,
// claim.name "${client_id}" gave svc-cus-profile-kyc's client-credentials token
// aud=["svc-acc-accounts-ledger"] (Keycloak 26.7.5). Only the built-in form
// resource_access.${client_id}.roles is allowed.
const CLIENT_ID_CLAIMS = ["${client_id}", "${client_id}.roles", "x.${client_id}"];
const clientIdClaimMapper = (claimName) => ({ name: `client-id-claim ${claimName}`, protocol: "openid-connect", protocolMapper: "oidc-usermodel-client-role-mapper", consentRequired: false,
  config: { "claim.name": claimName, "usermodel.clientRoleMapping.clientId": "aud", multivalued: "true", "access.token.claim": "true" } });
const hardcodedRole = (role = `${LEDGER}.anything`) => ({ name: "hardcoded-role", protocol: "openid-connect", protocolMapper: "oidc-hardcoded-role-mapper", consentRequired: false, config: { role } });
const roleName = (to = `${LEDGER}.service`) => ({ name: "role-name", protocol: "openid-connect", protocolMapper: "oidc-role-name-mapper", consentRequired: false, config: { role: "service", "new.role.name": to } });
const audRouteErrors = (holder, m) => {
  const via = `${LEDGER} is reached only through the optional scope ${LEDGER_SCOPE} (registry audienceByScope)`;
  if (m.protocolMapper === "oidc-hardcoded-role-mapper") return `${holder}: mapper ${m.name} (oidc-hardcoded-role-mapper) adds role ${m.config.role}, a client role of ${LEDGER}, so tokens would carry aud=${LEDGER} (audience resolve); ${via}`;
  if (m.protocolMapper === "oidc-role-name-mapper") return `${holder}: mapper ${m.name} (oidc-role-name-mapper) renames a role to ${m.config["new.role.name"]}, a client role of ${LEDGER}, so tokens would carry aud=${LEDGER} (audience resolve); ${via}`;
  const n = m.config["claim.name"];
  if (CLIENT_ID_CLAIMS.includes(n)) return `${holder}: mapper ${m.name} (${m.protocolMapper}) has \${client_id} in claim.name ${JSON.stringify(n)}; the client role mapper replaces it with a client id, so a client named aud would write claim aud; only resource_access.\${client_id}.roles is allowed`;
  const how = n === "aud" ? "writes claim aud" : `writes ${AUD_SPELLINGS[n] === '["aud"]' ? "claim" : "under claim"} aud (claim.name ${JSON.stringify(n)}, Keycloak claim path ${AUD_SPELLINGS[n]})`;
  return `${holder}: mapper ${m.name} (${m.protocolMapper}) ${how}; this realm sets audiences only through oidc-audience-mapper`;
};
const AUD_ROUTES = [audClaimMapper(), audClaimMapper("oidc-usermodel-attribute-mapper"), ...Object.keys(AUD_SPELLINGS).map((n) => audClaimMapper(undefined, n)), ...CLIENT_ID_CLAIMS.map(clientIdClaimMapper), hardcodedRole(), roleName()];

test("by-scope audience: an aud claim mapper, a hardcoded ledger role and a role renamed to a ledger role are refused on every client and client scope", () => {
  // The realm file has none of these mappers ("committed realm passes the
  // gate"). Next to each route the holder gets mappers that are no ledger
  // route (a realm role, another client's role, a longer client id), which
  // must not be reported.
  const harmless = [hardcodedRole("service"), hardcodedRole("svc-cus-profile-kyc.x"), roleName(`${LEDGER}-two.x`), clientIdClaimMapper("resource_access.${client_id}.roles"), ...NOT_AUD_SPELLINGS.map((n) => audClaimMapper(undefined, n))].map((m, i) => ({ ...m, name: `harmless-${i}` }));
  const holders = [
    ["svc-cus-profile-kyc", (i) => client(i, "svc-cus-profile-kyc")],
    ["svc-ln-loan-lifecycle", (i) => client(i, "svc-ln-loan-lifecycle")],
    ["fintechbankx-staff-web", (i) => client(i, "fintechbankx-staff-web")],
    ["of-tpp-conformance-template", (i) => client(i, "of-tpp-conformance-template")],
    ["console-made", (i) => { const c = { clientId: "console-made", protocol: "openid-connect", fullScopeAllowed: false, attributes: {}, protocolMappers: [] }; i.realm.clients.push(c); return c; }],
    ["client scope customer-id", (i) => scope(i, "customer-id")],
    ["client scope payments", (i) => scope(i, "payments")],
    ["client scope ledger-everywhere", (i) => { const s = { name: "ledger-everywhere", protocol: "openid-connect", attributes: {}, protocolMappers: [] }; i.realm.clientScopes.push(s); i.realm.defaultOptionalClientScopes = ["ledger-everywhere"]; return s; }]
  ];
  for (const [label, holderOf] of holders) {
    for (const m of AUD_ROUTES) {
      const input = fresh();
      holderOf(input).protocolMappers.push(structuredClone(m), ...structuredClone(harmless));
      assert.deepEqual(checkRealm(input).filter((e) => e.startsWith(`${label}: mapper `)), [audRouteErrors(label, m)], `${label} ${m.protocolMapper} ${m.config["claim.name"] ?? ""}`);
    }
  }
  // On the ledger's own client a hardcoded or renamed ledger role is no route:
  // the audience resolve mapper never puts the token's own client into aud
  // (Keycloak 26.7.5: the ledger's client-credentials token then had
  // resource_access.svc-acc-accounts-ledger and no aud). A mapper writing claim
  // aud is refused there too.
  for (const m of [hardcodedRole(`${LEDGER}.ledger-reader`), roleName(`${LEDGER}.x`)]) {
    const input = fresh();
    client(input, LEDGER).protocolMappers.push(structuredClone(m));
    assert.deepEqual(checkRealm(input), [], `${LEDGER} itself: ${m.protocolMapper}`);
  }
  for (const m of [audClaimMapper(), audClaimMapper(undefined, "aud.")]) {
    const input = fresh();
    client(input, LEDGER).protocolMappers.push(structuredClone(m));
    assert.deepEqual(checkRealm(input), [audRouteErrors(LEDGER, m)], `${LEDGER} itself: claim.name ${m.config["claim.name"]}`);
  }
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

  // A composite role counts where it is in a role scope: realm role service
  // is scope-mapped to every service client.
  const composite = structuredClone(base);
  Object.assign(composite.realm.roles.realm.find((r) => r.name === "service"), { composite: true, composites: { client: { [LEDGER]: ["ledger-reader"] } } });
  failsWith(composite, `${LEDGER}: client roles ledger-reader are in the role scope of client svc-cus-profile-kyc${tail}`);
  failsWith(composite, `${LEDGER}: client roles ledger-reader are in the role scope of client svc-ln-loan-lifecycle${tail}`);
  // A composite role in no client's or scope's role scope is not a route
  // (the extra realm role only breaks the contract role set).
  const unmapped = structuredClone(base);
  unmapped.realm.roles.realm.push({ name: "ledger-bundle", composite: true, clientRole: false, composites: { client: { [LEDGER]: ["ledger-reader"] } } });
  assert.deepEqual(checkRealm(unmapped).filter((e) => e.includes(LEDGER)), [], checkRealm(unmapped).join("\n"));
  // A client with fullScopeAllowed absent (Keycloak reads true) holds every
  // ledger role, whether or not it is registered or tagged.
  const fullScope = structuredClone(base);
  fullScope.realm.clients.push({ clientId: "console-made", protocol: "openid-connect", attributes: {}, protocolMappers: [] });
  failsWith(fullScope, `${LEDGER}: client roles ledger-reader are in the role scope of client console-made${tail}`);
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
      ["svc-ln-loan-lifecycle: audience mappers svc-acc-accounts-ledger,svc-cus-profile-kyc,svc-rsk-decisioning != registry svc-cus-profile-kyc,svc-rsk-decisioning",
        `svc-ln-loan-lifecycle: audience ${LEDGER} is reached only through the optional scope ${LEDGER_SCOPE} (registry audienceByScope), never through a mapper`]],
    ["registry audience mapper removed", (l) => { liveClient(l, "svc-ln-loan-lifecycle").protocolMappers = []; },
      ["svc-ln-loan-lifecycle: audience mappers <none> != registry svc-cus-profile-kyc,svc-rsk-decisioning"]],
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
      [`service client ${LEDGER} missing from realm`]],
    // Other audience routes, on a client, a realm default scope and a
    // built-in scope of the running realm.
    ...AUD_ROUTES.flatMap((m) => [
      [`${m.name} (${m.protocolMapper}) on a client`, (l) => liveClient(l, "svc-cus-profile-kyc").protocolMappers.push(structuredClone(m)), [audRouteErrors("svc-cus-profile-kyc", m)]],
      [`${m.name} (${m.protocolMapper}) on customer-id`, (l) => liveScope(l, "customer-id").protocolMappers.push(structuredClone(m)), [audRouteErrors("client scope customer-id", m)]],
      [`${m.name} (${m.protocolMapper}) on roles`, (l) => liveScope(l, "roles").protocolMappers.push(structuredClone(m)), [audRouteErrors("client scope roles", m)]],
      [`${m.name} (${m.protocolMapper}) on admin-cli`, (l) => liveClient(l, "admin-cli").protocolMappers.push(structuredClone(m)), [audRouteErrors("admin-cli", m)]]
    ])
  ];
  for (const [name, mutate, expected] of cases) {
    const live = liveRealm();
    mutate(live);
    const errors = await liveErrors(live);
    for (const e of expected) assert.ok(errors.includes(e), `${name}: ${e} not in\n${errors.join("\n")}`);
  }
  // No route: a hardcoded or renamed ledger role on the ledger's own client,
  // and claim names Keycloak does not read as aud.
  const noRoute = [
    ...[hardcodedRole(`${LEDGER}.ledger-reader`), roleName(`${LEDGER}.x`)].map((m) => [`${m.protocolMapper} on ${LEDGER} itself`, (l) => liveClient(l, LEDGER).protocolMappers.push(structuredClone(m))]),
    ...NOT_AUD_SPELLINGS.map((n) => [`claim.name ${JSON.stringify(n)} on customer-id`, (l) => liveScope(l, "customer-id").protocolMappers.push(audClaimMapper(undefined, n))]),
    ["client role mapper resource_access.${client_id}.roles on a client", (l) => liveClient(l, "svc-cus-profile-kyc").protocolMappers.push(clientIdClaimMapper("resource_access.${client_id}.roles"))]
  ];
  for (const [name, mutate] of noRoute) {
    const live = liveRealm();
    mutate(live);
    assert.deepEqual(await liveErrors(live), [], name);
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

test("live: --live-export needs a partial export with clients, client scopes, realm default scopes, roles and authentication flows", async () => {
  const live = liveRealm();
  await assert.rejects(liveFromFile(live.clients), /--live-export: a GET \/clients array covers the TPP rules only/);
  assert.throws(() => runLiveExport(live.clients), /realm-check --live: FAILED: --live-export: a GET \/clients array covers the TPP rules only/);
  for (const key of ["clients", "clientScopes", "defaultDefaultClientScopes", "defaultOptionalClientScopes", "roles", "authenticationFlows"]) {
    const partial = liveRealm();
    delete partial[key];
    await assert.rejects(liveFromFile(partial), new RegExp(`--live-export: the export lacks ${key}`), key);
  }
  // Keycloak's export leaves out clientScopeMappings and scopeMappings when
  // they are empty (ExportUtils); a realm deployed from this realm file has no
  // client-role scope mapping at all. Absent counts as empty, also once the
  // ledger has client roles.
  const noMappings = liveRealm();
  delete noMappings.clientScopeMappings;
  delete noMappings.scopeMappings;
  assert.deepEqual((await liveFromFile(noMappings)).errors, []);
  noMappings.roles.client[LEDGER] = [{ name: "ledger-reader", composite: false, clientRole: true }];
  assert.deepEqual((await liveFromFile(noMappings)).errors, []);
  assert.match(runLiveExport(noMappings), /realm-check --live: OK/);
});

// Review finding (one model for both modes): a client X other than the
// ledger holds a ledger client role in its role scope when fullScopeAllowed is
// not false, when its explicit client-role scope mappings name it, or when an
// explicit realm-role or client-role scope mapping, or one of X's own client
// roles, is a composite containing it at any depth (Keycloak's hasScope). A
// client scope holds one through its own scope mappings. admin-cli and
// security-admin-console are exempt only while their access tokens are
// lightweight (no aud). --live asks Keycloak (/composite); --live-export
// computes the same from the export.
test("live: ledger client roles in a role scope, the same through the admin API and a partial export", async () => {
  const tail = `, so tokens issued with it would carry aud=${LEDGER} (audience resolve); ${LEDGER} is reached only through the optional scope ${LEDGER_SCOPE} (registry audienceByScope)`;
  const held = (target) => `${LEDGER}: client roles ledger-reader are in the role scope of ${target}${tail}`;
  const bundle = (name = "ledger-bundle") => ({ name, composite: true, clientRole: false, composites: { client: { [LEDGER]: ["ledger-reader"] } } });
  const audienceResolve = (config) => ({ name: "x-audience-resolve", protocol: "openid-connect", protocolMapper: "oidc-audience-resolve-mapper", config: { "access.token.claim": "true", "introspection.token.claim": "true", ...config } });
  const consoleMade = (extra) => ({ id: "id-console-made", clientId: "console-made", protocol: "openid-connect", attributes: {}, protocolMappers: [], defaultClientScopes: ["basic", "roles"], optionalClientScopes: [], ...extra });
  const cases = [
    ["ledger role mapped nowhere", () => {}, []],
    ["ledger role mapped to a client that does not call the ledger", (l) => { l.clientScopeMappings[LEDGER] = [{ client: "svc-cus-profile-kyc", roles: ["ledger-reader"] }]; },
      [held("client svc-cus-profile-kyc")]],
    ["ledger role mapped to a caller", (l) => { l.clientScopeMappings[LEDGER] = [{ client: "svc-ln-loan-lifecycle", roles: ["ledger-reader"] }]; },
      [held("client svc-ln-loan-lifecycle")]],
    ["untagged client with fullScopeAllowed true", (l) => l.clients.push(consoleMade({ fullScopeAllowed: true })), [held("client console-made")]],
    ["untagged client without fullScopeAllowed", (l) => l.clients.push(consoleMade({})), [held("client console-made")]],
    ["untagged client with fullScopeAllowed false", (l) => l.clients.push(consoleMade({ fullScopeAllowed: false })), []],
    ["built-ins with lightweight access tokens", (l) => { liveClient(l, "admin-cli").attributes[LIGHTWEIGHT] = "true"; }, []],
    ["built-ins with lightweight access tokens off", (l) => { for (const id of ["admin-cli", "security-admin-console"]) liveClient(l, id).attributes[LIGHTWEIGHT] = "false"; },
      [held("client admin-cli"), held("client security-admin-console")]],
    ["admin-cli without the lightweight attribute", (l) => { delete liveClient(l, "admin-cli").attributes[LIGHTWEIGHT]; }, [held("client admin-cli")]],
    // A mapper with lightweight.claim "true" reaches lightweight tokens too.
    // Keycloak 26.7.5, user holding ledger-reader, password grant on
    // admin-cli: an audience resolve mapper so configured, on admin-cli or in
    // its default scope roles, gave aud=["svc-acc-accounts-ledger","account"];
    // the client roles mapper so configured gave resource_access and no aud.
    ["admin-cli with an audience resolve mapper in lightweight tokens", (l) => liveClient(l, "admin-cli").protocolMappers.push(audienceResolve({ "lightweight.claim": "true" })),
      [held("client admin-cli")]],
    ["audience resolve of scope roles in lightweight tokens", (l) => { liveScope(l, "roles").protocolMappers[0].config["lightweight.claim"] = "true"; },
      [held("client admin-cli"), held("client security-admin-console")]],
    ["audience resolve in lightweight tokens in an optional scope of admin-cli", (l) => {
      liveScope(l, "offline_access").protocolMappers.push(audienceResolve({ "lightweight.claim": "true" }));
      liveClient(l, "admin-cli").optionalClientScopes.push("offline_access");
    }, [held("client admin-cli")]],
    ["audience resolve in lightweight tokens in a scope the built-ins do not have", (l) => liveScope(l, "payments").protocolMappers.push(audienceResolve({ "lightweight.claim": "true" })), []],
    ["audience resolve on admin-cli, not in lightweight tokens", (l) => liveClient(l, "admin-cli").protocolMappers.push(audienceResolve({ "lightweight.claim": "false" })), []],
    ["client roles mapper in lightweight tokens (resource_access, no aud)", (l) => liveClient(l, "admin-cli").protocolMappers.push({ name: "client roles", protocol: "openid-connect", protocolMapper: "oidc-usermodel-client-role-mapper", config: { "claim.name": "resource_access.${client_id}.roles", multivalued: "true", "access.token.claim": "true", "lightweight.claim": "true" } }), []],
    ["another client named like no built-in, lightweight, fullScopeAllowed", (l) => l.clients.push(consoleMade({ fullScopeAllowed: true, attributes: { [LIGHTWEIGHT]: "true" } })), [held("client console-made")]],
    ["composite realm role mapped into a client's role scope", (l) => { l.roles.realm.push(bundle()); l.scopeMappings.push({ client: "svc-cus-profile-kyc", roles: ["ledger-bundle"] }); },
      [held("client svc-cus-profile-kyc")]],
    ["composite realm role, two levels deep, mapped into a client's role scope", (l) => {
      l.roles.realm.push(bundle(), { name: "outer", composite: true, clientRole: false, composites: { realm: ["ledger-bundle"] } });
      l.scopeMappings.find((m) => m.client === "svc-cus-profile-kyc").roles.push("outer");
    }, [held("client svc-cus-profile-kyc")]],
    ["composite client role of another client mapped into a client's role scope", (l) => {
      l.roles.client["svc-cmp-evidence"] = [{ ...bundle("evidence-bundle"), clientRole: true }];
      l.clientScopeMappings["svc-cmp-evidence"] = [{ client: "svc-cus-profile-kyc", roles: ["evidence-bundle"] }];
    }, [held("client svc-cus-profile-kyc"), held("client svc-cmp-evidence")]],
    ["composite role in no role scope", (l) => { l.roles.realm.push(bundle()); }, []],
    ["client scope with a ledger role", (l) => { l.clientScopeMappings[LEDGER] = [{ clientScope: "payments", roles: ["ledger-reader"] }]; }, [held("client scope payments")]],
    ["client scope with a composite holding a ledger role", (l) => { l.roles.realm.push(bundle()); l.scopeMappings.push({ clientScope: "customer-id", roles: ["ledger-bundle"] }); },
      [held("client scope customer-id")]]
  ];
  for (const [name, mutate, expected] of cases) {
    const live = liveRealm();
    live.roles.client[LEDGER] = [{ name: "ledger-reader", composite: false, clientRole: true }];
    mutate(live);
    assert.deepEqual(await liveErrors(live), expected, name);
  }
});

// Known gap (1), closed: a script mapper (provider id script-<file>.js, from a
// deployed script provider) or a custom SPI mapper can write any claim, aud
// included. Every protocol mapper on a client or client scope (Keycloak's
// built-ins included) must be a stock Keycloak 26.7.5 mapper, in all three
// modes. The list is GET /admin/serverinfo protocolMapperTypes of a local
// Keycloak 26.7.5 (openid-connect 24, saml 14).
const scriptMapper = (protocolMapper) => ({ name: "scripted", protocol: "openid-connect", protocolMapper, consentRequired: false, config: { "claim.name": "x", "access.token.claim": "true" } });
const notStock = (holder, m) => `${holder}: mapper ${m.name} (${m.protocolMapper}) is not a stock Keycloak 26.7.5 protocol mapper; script and custom SPI mappers can write any claim, aud included`;
const NOT_STOCK = ["script-aud.js", "script-mappers/aud.js", "fbx-custom-audience-mapper", "docker-v2-allow-all-mapper", "OIDC-AUDIENCE-MAPPER", ""];

test("stock protocol mappers only: script and custom SPI mappers are refused on every client and client scope, in all three modes", async () => {
  assert.equal(STOCK_PROTOCOL_MAPPERS["openid-connect"].length, 24);
  assert.equal(STOCK_PROTOCOL_MAPPERS.saml.length, 14);
  // Every stock mapper passes (in a client scope no client uses).
  const all = fresh();
  all.realm.clientScopes.push({ name: "all-stock", protocol: "openid-connect", attributes: {},
    protocolMappers: Object.values(STOCK_PROTOCOL_MAPPERS).flat().map((protocolMapper) => ({ name: `stock ${protocolMapper}`, protocolMapper, config: {} })) });
  assert.deepEqual(checkRealm(all), []);
  for (const id of NOT_STOCK) {
    const m = scriptMapper(id);
    for (const [label, holderOf] of [["svc-cus-profile-kyc", (i) => client(i, "svc-cus-profile-kyc")], ["client scope customer-id", (i) => scope(i, "customer-id")]]) {
      const input = fresh();
      holderOf(input).protocolMappers.push(structuredClone(m));
      assert.deepEqual(checkRealm(input), [notStock(label, m)], `${label} ${id}`);
    }
    for (const [label, holderOf] of [["svc-cus-profile-kyc", (l) => liveClient(l, "svc-cus-profile-kyc")], ["admin-cli", (l) => liveClient(l, "admin-cli")], ["client scope roles", (l) => liveScope(l, "roles")], ["client scope customer-id", (l) => liveScope(l, "customer-id")]]) {
      const live = liveRealm();
      holderOf(live).protocolMappers.push(structuredClone(m));
      assert.deepEqual(await liveErrors(live), [notStock(label, m)], `live ${label} ${id}`);
    }
  }
});

// Known gap (2), closed: standard token exchange (Keycloak 26.7.5 feature
// token-exchange-standard, on by default) is enabled per client by the
// attribute standard.token.exchange.enabled, read with Boolean.parseBoolean
// (any case of "true"). No client of this realm uses it; it is refused on
// every client, built-in and runtime clients included, in all three modes.
const TOKEN_EXCHANGE = "standard.token.exchange.enabled";
const exchangeRefused = (id, v) => `${id}: attribute ${TOKEN_EXCHANGE} is ${JSON.stringify(v)}; standard token exchange is not used in this realm (a client could trade a token it received for a new one with other audiences)`;

test("standard token exchange is refused on every client, in all three modes", async () => {
  for (const c of fresh().realm.clients) assert.equal(c.attributes?.[TOKEN_EXCHANGE], undefined, c.clientId);
  for (const v of ["true", "TRUE", "True"]) {
    for (const id of ["svc-cus-profile-kyc", "svc-ln-loan-lifecycle", "fintechbankx-staff-web", "of-tpp-conformance-template", "svc-obs-grafana"]) {
      const input = fresh();
      client(input, id).attributes[TOKEN_EXCHANGE] = v;
      assert.deepEqual(checkRealm(input), [exchangeRefused(id, v)], `${id} ${v}`);
    }
    for (const id of ["svc-ln-loan-lifecycle", "admin-cli", "account", "of-tpp-acme-pay"]) {
      const live = liveRealm();
      if (id === "of-tpp-acme-pay") live.clients.push({ ...structuredClone(liveClient(live, "of-tpp-conformance-template")), id: "id-of-tpp-acme-pay", clientId: id });
      liveClient(live, id).attributes[TOKEN_EXCHANGE] = v;
      assert.deepEqual(await liveErrors(live), [exchangeRefused(id, v)], `live ${id} ${v}`);
    }
  }
  // A JSON boolean in the realm file: Keycloak and keycloak-config-cli store
  // true as the attribute "true", which Boolean.parseBoolean reads as on.
  const asBoolean = fresh();
  client(asBoolean, "svc-cus-profile-kyc").attributes[TOKEN_EXCHANGE] = true;
  assert.deepEqual(checkRealm(asBoolean), [exchangeRefused("svc-cus-profile-kyc", true)], "JSON true");
  for (const v of ["false", "FALSE", "", false, " true"]) {
    const input = fresh();
    client(input, "svc-cus-profile-kyc").attributes[TOKEN_EXCHANGE] = v;
    assert.deepEqual(checkRealm(input), [], JSON.stringify(v));
  }
});

// Authorization Services (UMA): on a client with authorizationServicesEnabled
// and a granting policy, any client's token buys an RPT with that client in
// aud (grant type urn:ietf:params:oauth:grant-type:uma-ticket, audience=<it>),
// carrying the realm roles of its role scope: svc-cus-profile-kyc got an RPT
// with aud svc-acc-accounts-ledger and realm role service (Keycloak 26.7.5).
// No client of this realm uses it; Keycloak's FGAP v2 client
// admin-permissions is the only exception, in all three modes.
const UMA = (id) => `${id}: Authorization Services are enabled (authorizationServicesEnabled or authorizationSettings); they are not used in this realm (any client could trade its token for an RPT with aud=${id} through grant type uma-ticket)`;

test("Authorization Services (UMA) are refused on every client but Keycloak's admin-permissions, in all three modes", async () => {
  for (const c of fresh().realm.clients) {
    assert.notEqual(c.authorizationServicesEnabled, true, c.clientId);
    assert.equal(c.authorizationSettings, undefined, c.clientId);
  }
  const settings = { policyEnforcementMode: "ENFORCING", resources: [{ name: "all", uris: ["/*"] }], policies: [], decisionStrategy: "UNANIMOUS" };
  for (const [what, set] of [["authorizationServicesEnabled", (c) => { c.authorizationServicesEnabled = true; }], ["authorizationSettings", (c) => { c.authorizationSettings = structuredClone(settings); }],
    ["both", (c) => { c.authorizationServicesEnabled = true; c.authorizationSettings = structuredClone(settings); }]]) {
    for (const id of [LEDGER, "svc-cus-profile-kyc", "fintechbankx-staff-web", "svc-obs-grafana"]) {
      const input = fresh();
      set(client(input, id));
      assert.deepEqual(checkRealm(input), [UMA(id)], `${id} ${what}`);
    }
    for (const id of [LEDGER, "svc-rsk-decisioning", "admin-cli", "realm-management"]) {
      const live = liveRealm();
      set(liveClient(live, id));
      assert.deepEqual(await liveErrors(live), [UMA(id)], `live ${id} ${what}`);
    }
  }
  // Keycloak and keycloak-config-cli read the JSON string "true" as true, so
  // the realm file is refused for any value but absent, false or "false" (any
  // case).
  for (const v of ["true", "TRUE", 1]) {
    const input = fresh();
    client(input, LEDGER).authorizationServicesEnabled = v;
    assert.deepEqual(checkRealm(input), [UMA(LEDGER)], JSON.stringify(v));
  }
  // Keycloak's admin-permissions client (liveRealm) passes; false passes.
  assert.equal(liveClient(liveRealm(), "admin-permissions").authorizationServicesEnabled, true);
  for (const v of [false, "false", "FALSE"]) {
    const off = fresh();
    client(off, LEDGER).authorizationServicesEnabled = v;
    assert.deepEqual(checkRealm(off), [], JSON.stringify(v));
  }
});

// Known gap (4), closed: the realm import Job applies the service-client
// rules to the running realm, not only the TPP rules. Its last step
// (container tpp-onboarding) runs onboard-tpp.mjs --verify-live with the
// registry realm/service-clients.json, through the same live view as
// check-realm.mjs --live (scripts/realm/live-view.mjs). Read from the Job and
// the kustomize ConfigMap generators it mounts, so a module or file missing
// from a ConfigMap fails here, not in the cluster.
const BASE_DIR = path.join(root, "deploy/kustomize/base");
const job = YAML.parse(fs.readFileSync(path.join(BASE_DIR, "realm-import/job.yaml"), "utf8"));
const jobPod = job.spec.template.spec;
const jobContainer = (name) => [...(jobPod.initContainers || []), ...jobPod.containers].find((c) => c.name === name);
// configMapGenerator entries of the base and its components: name -> { dir, files: key -> source path }.
function configMapGenerators() {
  const out = new Map();
  const k = YAML.parse(fs.readFileSync(path.join(BASE_DIR, "kustomization.yaml"), "utf8"));
  for (const dir of [BASE_DIR, ...(k.components || []).map((c) => path.resolve(BASE_DIR, c))]) {
    const kz = YAML.parse(fs.readFileSync(path.join(dir, "kustomization.yaml"), "utf8"));
    for (const g of kz.configMapGenerator || []) {
      const files = new Map((g.files || []).map((f) => { const [key, src] = f.includes("=") ? f.split("=") : [path.basename(f), f]; return [key, path.join(dir, src)]; }));
      out.set(g.name, { dir, files });
    }
  }
  return out;
}
// The files a container sees under each mount of a generated ConfigMap: absolute container path -> repo file.
function mountedFiles(container) {
  const gens = configMapGenerators();
  const out = new Map();
  for (const m of container.volumeMounts || []) {
    const v = jobPod.volumes.find((x) => x.name === m.name);
    if (!v?.configMap) continue;
    const g = gens.get(v.configMap.name);
    assert.ok(g, `volume ${m.name}: ConfigMap ${v.configMap.name} has no configMapGenerator in the base or its components`);
    assert.equal(v.configMap.items, undefined, `volume ${m.name}: items would hide keys`);
    for (const [key, src] of g.files) out.set(path.posix.join(m.mountPath, key), src);
  }
  return out;
}
// Relative imports of an ES module (static, re-export and dynamic), resolved.
const relativeImports = (file) => [...fs.readFileSync(file, "utf8").matchAll(/(?:\bimport\s*(?:[\w*{}\s,]+from\s*)?|\bexport\s*[\w*{}\s,]+from\s*|\bimport\s*\(\s*)["']([^"']+)["']/g)]
  .map((m) => m[1]);

test("the realm import Job runs the service-client rules: onboard-tpp.mjs --verify-live with the registry", () => {
  const c = jobContainer("tpp-onboarding");
  assert.deepEqual(c.command.slice(0, 2), ["node", "/opt/fbx/script/onboard-tpp.mjs"]);
  assert.ok(c.command.includes("--verify-live"), c.command.join(" "));
  const registry = c.command[c.command.indexOf("--registry") + 1];
  assert.ok(c.command.includes("--registry"), c.command.join(" "));
  const files = mountedFiles(c);
  assert.equal(files.get(registry), path.join(root, "realm/service-clients.json"), `${registry} is not realm/service-clients.json`);
  assert.ok(!registry.startsWith("/config/"), "keycloak-config-cli imports every *.json in /config");
});

test("every module a script of the Job imports, transitively, is in the ConfigMap mounted next to it", () => {
  for (const c of [...(jobPod.initContainers || []), ...jobPod.containers].filter((x) => x.command?.[0] === "node")) {
    const files = mountedFiles(c);
    const todo = [c.command[1]];
    const seen = new Set();
    while (todo.length) {
      const at = todo.pop();
      if (seen.has(at)) continue;
      seen.add(at);
      assert.ok(files.has(at), `${c.name}: ${at} is not in a ConfigMap the container mounts`);
      for (const spec of relativeImports(files.get(at))) {
        if (spec.startsWith("node:")) continue;
        assert.ok(spec.startsWith("./") || spec.startsWith("../"), `${c.name}: ${at} imports ${spec}; the node image has no node_modules`);
        todo.push(path.posix.join(path.posix.dirname(at), spec));
      }
    }
    // Every absolute path argument is a mounted file.
    for (const a of c.command.slice(2).filter((x) => x.startsWith("/"))) assert.ok(files.has(a), `${c.name}: argument ${a} is not a mounted file`);
  }
  // The import parser sees the imports this repo uses.
  assert.deepEqual(relativeImports(path.join(root, "scripts/realm/onboard-tpp.mjs")).filter((s) => !s.startsWith("node:")).sort(), ["./apply-admin-permissions.mjs", "./live-view.mjs", "./tpp-rules.mjs"]);
});

// The Job's tpp-onboarding command, run as the Job runs it: the files of each
// mounted ConfigMap copied to their container paths under a temporary root,
// the same env names, and an admin API that answers like Keycloak (adminApi).
async function runJobStep(live, name = "tpp-onboarding") {
  const c = jobContainer(name);
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "realm-import-job-"));
  const api = adminApi(live);
  const server = http.createServer(async (req, res) => {
    req.resume();
    const r = await api.fetch(`http://kc.test${req.url}`);
    res.writeHead(r.status, { "content-type": "application/json" });
    res.end(await r.text());
  });
  await new Promise((ok) => server.listen(0, "127.0.0.1", ok));
  try {
    for (const [to, from] of mountedFiles(c)) {
      fs.mkdirSync(path.join(sandbox, path.dirname(to)), { recursive: true });
      fs.copyFileSync(from, path.join(sandbox, to));
    }
    const importEnv = YAML.parse(fs.readFileSync(path.join(BASE_DIR, "realm-import/env.yaml"), "utf8")).data;
    const env = { PATH: process.env.PATH };
    for (const e of c.env) {
      if (e.name === "KEYCLOAK_URL") env[e.name] = `http://127.0.0.1:${server.address().port}`;
      else if (e.valueFrom?.configMapKeyRef) env[e.name] = importEnv[e.valueFrom.configMapKeyRef.key];
      else env[e.name] = `test-${e.name.toLowerCase()}`;
    }
    const args = c.command.slice(1).map((a) => (a.startsWith("/") ? path.join(sandbox, a) : a));
    try {
      const { stdout, stderr } = await promisify(execFile)(process.execPath, args, { env, encoding: "utf8" });
      return { code: 0, stdout, stderr, urls: api.urls };
    } catch (e) {
      return { code: e.code, stdout: e.stdout, stderr: e.stderr, urls: api.urls };
    }
  } finally {
    server.close();
    fs.rmSync(sandbox, { recursive: true });
  }
}

test("the Job's tpp-onboarding step against a mock admin API passes the compliant realm and fails a ledger bypass", async () => {
  const ok = await runJobStep(liveRealm());
  assert.equal(ok.code, 0, ok.stderr);
  assert.match(ok.stdout, /onboard-tpp: live check OK \(\d+ clients, 1 open-finance-tpp, 16 service clients\)/);
  assert.ok(ok.urls.some((u) => u.endsWith("/admin/realms/fintechbankx/default-default-client-scopes")), ok.urls.join(" "));
  const bypasses = [
    ["ledger audience mapper on svc-cus-profile-kyc", (l) => liveClient(l, "svc-cus-profile-kyc").protocolMappers.push(ledgerAudMapper()),
      `svc-cus-profile-kyc: audience ${LEDGER} is reached only through the optional scope ${LEDGER_SCOPE} (registry audienceByScope), never through a mapper`],
    ["ledger scope on fintechbankx-web", (l) => liveClient(l, "fintechbankx-web").optionalClientScopes.push(LEDGER_SCOPE),
      `fintechbankx-web: optional audience scopes ${LEDGER_SCOPE} != registry <none>`],
    ["aud claim mapper in the built-in scope roles", (l) => liveScope(l, "roles").protocolMappers.push(audClaimMapper()), audRouteErrors("client scope roles", audClaimMapper())],
    ["script mapper on admin-cli", (l) => liveClient(l, "admin-cli").protocolMappers.push(scriptMapper("script-aud.js")), notStock("admin-cli", scriptMapper("script-aud.js"))],
    ["standard token exchange on svc-ln-loan-lifecycle", (l) => { liveClient(l, "svc-ln-loan-lifecycle").attributes[TOKEN_EXCHANGE] = "true"; }, exchangeRefused("svc-ln-loan-lifecycle", "true")],
    ["Authorization Services on the ledger client", (l) => { liveClient(l, LEDGER).authorizationServicesEnabled = true; }, UMA(LEDGER)],
    ["staff web signs in any realm user", (l) => { delete liveClient(l, STAFF_WEB).authenticationFlowBindingOverrides; }, overrideRefused],
    ["staff flow lets a customer through", (l) => { l.authenticatorConfig.find((c) => c.alias === `${STAFF_FLOW} not banker`).config.negate = "false"; }, flowDiffers]
  ];
  for (const [name, mutate, expected] of bypasses) {
    const live = liveRealm();
    mutate(live);
    const r = await runJobStep(live);
    assert.equal(r.code, 1, `${name}: ${r.stdout}`);
    assert.ok(r.stderr.includes(`onboard-tpp: live: ${expected}`), `${name}: ${r.stderr}`);
    assert.match(r.stderr, /onboard-tpp: FAILED/, name);
  }
});

// Separation of duties (G-S1; decision recorded in the bpo repository,
// docs/identity-requests.md): a member of a maker queue group must not also
// be in a checker queue group of the same rule.
// Queue groups grant marker roles; one deny subflow per rule runs after the
// staff check at sign-in and, for staff channel clients, at password reset.
const SOD = { cmp: ["sod_cmp_maker", "sod_cmp_checker"], pay: ["sod_pay_maker", "sod_pay_checker"] };
const staffGroup = (r, name) => r.groups.find((g) => g.name === "staff").subGroups.find((g) => g.name === name);

test("separation of duties: maker and checker queue groups grant marker roles, and one deny subflow per rule runs at sign-in and reset", () => {
  const { realm } = fresh();
  const roleNames = realm.roles.realm.map((r) => r.name);
  for (const roles of Object.values(SOD)) for (const r of roles) assert.ok(roleNames.includes(r), r);
  const grants = Object.fromEntries(realm.groups.find((g) => g.name === "staff").subGroups.map((g) => [g.name, g.realmRoles]));
  for (const g of ["fbx-cmp-ae-onboarding-l1", "fbx-cmp-tr-onboarding-l1", "fbx-cmp-review-l1"]) assert.deepEqual(grants[g], ["sod_cmp_maker"], g);
  for (const g of ["fbx-cmp-ae-mlro", "fbx-cmp-tr-compliance-officer", "fbx-cmp-review-l2"]) assert.deepEqual(grants[g], ["sod_cmp_checker"], g);
  for (const g of ["fbx-pay-tr-fast-ops", "fbx-pay-ops-l1"]) assert.deepEqual(grants[g], ["sod_pay_maker"], g);
  for (const g of ["fbx-pay-tr-fast-supervisor", "fbx-pay-ops-l2"]) assert.deepEqual(grants[g], ["sod_pay_checker"], g);
  const cfg = (e) => realm.authenticatorConfig.find((c) => c.alias === e.authenticatorConfig)?.config;
  const shape = (alias) => flowOf(realm, alias).authenticationExecutions.map((e) => [e.requirement, e.authenticator, cfg(e)]);
  for (const [id, [maker, checker]] of Object.entries(SOD)) {
    assert.deepEqual(shape(`${STAFF_FLOW} sod ${id}`), [
      ["REQUIRED", "conditional-user-role", { condUserRole: maker, negate: "false" }],
      ["REQUIRED", "conditional-user-role", { condUserRole: checker, negate: "false" }],
      ["REQUIRED", "deny-access-authenticator", undefined]]);
    assert.deepEqual(shape(`${RESET_FLOW} sod ${id}`), [
      ["REQUIRED", "conditional-client-scope", { client_scope: MARKER, negate: "false" }],
      ["REQUIRED", "conditional-user-role", { condUserRole: maker, negate: "false" }],
      ["REQUIRED", "conditional-user-role", { condUserRole: checker, negate: "false" }],
      ["REQUIRED", "deny-access-authenticator", undefined]]);
  }
  assert.equal(realm.editUsernameAllowed, false);
});

test("separation of duties: the gate refuses a missing marker role, a queue group without its marker, a group with both markers, a weakened deny subflow and editable usernames", () => {
  const cases = [
    ["marker role missing", (r) => { r.roles.realm = r.roles.realm.filter((x) => x.name !== "sod_pay_checker"); }, `flow ${STAFF_FLOW}: realm role sod_pay_checker does not exist`],
    ["checker queue without its marker", (r) => { staffGroup(r, "fbx-cmp-ae-mlro").realmRoles = []; }, "group /staff/fbx-cmp-ae-mlro is one of the compliance maker and checker queues and must grant realm role sod_cmp_checker"],
    ["a new maker queue without its marker", (r) => { r.groups.find((g) => g.name === "staff").subGroups.push({ name: "fbx-cmp-sa-onboarding-l1", path: "/staff/fbx-cmp-sa-onboarding-l1", realmRoles: [], subGroups: [] }); },
      "group /staff/fbx-cmp-sa-onboarding-l1 is one of the compliance maker and checker queues and must grant realm role sod_cmp_maker"],
    ["a group with both markers", (r) => { staffGroup(r, "fbx-pay-ops-l1").realmRoles = ["sod_pay_maker", "sod_pay_checker"]; }, "group /staff/fbx-pay-ops-l1 grants both sod_pay_maker and sod_pay_checker"],
    ["sod subflow dropped", (r) => { const f = flowOf(r, STAFF_FLOW); f.authenticationExecutions = f.authenticationExecutions.filter((e) => e.flowAlias !== `${STAFF_FLOW} sod cmp`); }, flowDiffers],
    ["sod subflow disabled", (r) => { flowOf(r, STAFF_FLOW).authenticationExecutions.find((e) => e.flowAlias === `${STAFF_FLOW} sod pay`).requirement = "DISABLED"; }, flowDiffers],
    ["sod deny disabled", (r) => { flowOf(r, `${STAFF_FLOW} sod cmp`).authenticationExecutions.at(-1).requirement = "DISABLED"; }, flowDiffers],
    ["sod condition negated", (r) => { r.authenticatorConfig.find((c) => c.alias === `${STAFF_FLOW} has sod_cmp_checker`).config.negate = "true"; }, flowDiffers],
    ["sod condition on another role", (r) => { r.authenticatorConfig.find((c) => c.alias === `${STAFF_FLOW} has sod_pay_maker`).config.condUserRole = "banker"; }, flowDiffers],
    // Queue names outside the patterns would carry no marker demand (fail-open).
    ["an unknown group under fbx-cmp-", (r) => { r.groups.find((g) => g.name === "staff").subGroups.push({ name: "fbx-cmp-ae-reviewer", path: "/staff/fbx-cmp-ae-reviewer", realmRoles: [], subGroups: [] }); },
      "group /staff/fbx-cmp-ae-reviewer is under the fbx-cmp-* prefix but matches neither side"],
    ["an unknown group under fbx-pay-", (r) => { r.groups.find((g) => g.name === "staff").subGroups.push({ name: "fbx-pay-sepa-ops", path: "/staff/fbx-pay-sepa-ops", realmRoles: ["sod_pay_maker"], subGroups: [] }); },
      "group /staff/fbx-pay-sepa-ops is under the fbx-pay-* prefix but matches neither side"],
    ...["fbx-cmp-sa2-mlro", "fbx-cmp-ae-dxb-mlro"].map((n) => [`checker queue ${n} without its marker`, (r) => { r.groups.find((g) => g.name === "staff").subGroups.push({ name: n, path: `/staff/${n}`, realmRoles: [], subGroups: [] }); },
      `group /staff/${n} is one of the compliance maker and checker queues and must grant realm role sod_cmp_checker`]),
    // Markers come only from their queue groups.
    ["a realm role with a marker in its composites", (r) => { Object.assign(r.roles.realm.find((x) => x.name === "auditor"), { composite: true, composites: { realm: ["sod_cmp_maker"] } }); },
      "realm role auditor reaches marker role sod_cmp_maker through its composites"],
    ["the default role reaches a marker", (r) => { r.roles.realm.push({ name: "default-roles-fintechbankx", composite: true, clientRole: false, composites: { realm: ["offline_access", "sod_pay_checker"] } }); },
      "realm: default role default-roles-fintechbankx reaches marker role sod_pay_checker through its composites"],
    ["a non-queue staff group grants a marker", (r) => { staffGroup(r, "fbx-banker").realmRoles = ["banker", "sod_cmp_checker"]; }, "group /staff/fbx-banker reaches marker role sod_cmp_checker"],
    ["a queue group grants the other side's marker", (r) => { staffGroup(r, "fbx-pay-ops-l2").realmRoles = ["sod_pay_checker", "sod_cmp_maker"]; }, "group /staff/fbx-pay-ops-l2 reaches marker role sod_cmp_maker"],
    ["a group outside /staff grants a marker", (r) => { r.groups.find((g) => g.name === "customers").realmRoles.push("sod_pay_maker"); }, "group /customers reaches marker role sod_pay_maker"],
    ["a realm-file user holds a marker", (r) => { r.users.push({ username: "local1", enabled: true, realmRoles: ["sod_cmp_checker"] }); }, "user local1 holds marker role sod_cmp_checker"],
    ["a realm-file user in a queue group", (r) => { r.users.push({ username: "local2", enabled: true, groups: ["/staff/fbx-pay-ops-l1"] }); }, "user local2 holds marker role sod_pay_maker"],
    ["reset sod subflow dropped", (r) => { const f = flowOf(r, RESET_FLOW); f.authenticationExecutions = f.authenticationExecutions.filter((e) => e.flowAlias !== `${RESET_FLOW} sod pay`); }, resetDiffers],
    ...[true, "true", " TRUE", 1].map((v) => [`editUsernameAllowed ${JSON.stringify(v)}`, (r) => { r.editUsernameAllowed = v; }, "realm: editUsernameAllowed must be false"])
  ];
  for (const [name, mutate, expected] of cases) {
    const input = fresh();
    mutate(input.realm);
    const errors = checkRealm(input);
    assert.ok(errors.some((e) => e.startsWith(expected)), `${name}: ${expected} not in\n${errors.join("\n")}`);
  }
  for (const v of [false, undefined, "False"]) {
    const input = fresh();
    input.realm.editUsernameAllowed = v;
    assert.deepEqual(checkRealm(input), [], `editUsernameAllowed ${JSON.stringify(v)}`);
  }
});

test("live: a marker role in the default role's or another role's composites is refused through the admin API and a partial export", async () => {
  const live = liveRealm();
  realmRoleOf(live, "default-roles-fintechbankx").composites.realm.push("sod_cmp_checker");
  const errors = await liveErrors(live);
  assert.ok(errors.some((x) => x.startsWith("realm: default role default-roles-fintechbankx reaches marker role sod_cmp_checker")), errors.join("\n"));
});

test("live: editUsernameAllowed true is refused through the admin API and a partial export", async () => {
  const live = liveRealm();
  live.editUsernameAllowed = true;
  const errors = await liveErrors(live);
  assert.ok(errors.some((x) => x.startsWith("realm: editUsernameAllowed must be false")), errors.join("\n"));
});
