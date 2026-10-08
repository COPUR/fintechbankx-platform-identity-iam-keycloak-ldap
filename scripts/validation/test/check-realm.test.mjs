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
