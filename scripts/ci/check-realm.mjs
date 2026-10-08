#!/usr/bin/env node
// Sanity gate for realm-as-code (realm/fintechbankx-realm.json).
// Checks the realm against the platform contract and the client registry
// (realm/service-clients.json), that it carries no credential values, and
// that every $(env:NAME) placeholder is supplied by the realm import Job.
//
// usage: node scripts/ci/check-realm.mjs [--root <repo-root>]
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

export const CONTRACT_ROLES = ["customer", "banker", "loan_officer", "admin", "service", "auditor", "compliance_officer"];
export const STAFF_ROLE_GROUPS = {
  "fbx-banker": "banker",
  "fbx-loan-officer": "loan_officer",
  "fbx-admin": "admin",
  "fbx-auditor": "auditor",
  "fbx-compliance-officer": "compliance_officer"
};
const PLACEHOLDER = /^\$\(env:[A-Z0-9_]+\)$/;
const SECRET_KEY = /(secret|credential|password|passwd|private.?key)/i;

export const secretEnvName = (clientId) => "FBX_OIDC_SECRET_" + clientId.toUpperCase().replace(/-/g, "_");

function audiences(client) {
  return (client.protocolMappers || [])
    .filter((m) => m.protocolMapper === "oidc-audience-mapper")
    .map((m) => m.config?.["included.client.audience"])
    .sort();
}

function walk(value, visit, trail = []) {
  if (Array.isArray(value)) {
    value.forEach((v, i) => walk(v, visit, [...trail, i]));
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      visit(k, v, [...trail, k]);
      walk(v, visit, [...trail, k]);
    }
  }
}

export function checkRealm({ realm, registry, importEnv = null, importSecretKeys = null, importSecretRefs = null }) {
  const errors = [];
  const err = (m) => errors.push(m);

  if (realm.realm !== "fintechbankx") err(`realm name must be fintechbankx (found ${realm.realm})`);

  // Roles: exactly the contract set (lower-case; services map to ROLE_*).
  const roleNames = (realm.roles?.realm || []).map((r) => r.name).sort();
  const expectedRoles = [...CONTRACT_ROLES].sort();
  if (JSON.stringify(roleNames) !== JSON.stringify(expectedRoles)) {
    err(`realm roles must be ${expectedRoles.join(",")} (found ${roleNames.join(",")})`);
  }

  // Security baseline.
  if (realm.bruteForceProtected !== true) err("bruteForceProtected must be true");
  if (!(realm.failureFactor > 0 && realm.failureFactor <= 10)) err("failureFactor must be 1..10");
  if (!/length\((1[2-9]|[2-9]\d)\)/.test(realm.passwordPolicy || "")) err("passwordPolicy must require length >= 12");
  if (realm.eventsEnabled !== true) err("eventsEnabled must be true");
  if (realm.adminEventsEnabled !== true) err("adminEventsEnabled must be true");
  if (!(realm.accessTokenLifespan > 0 && realm.accessTokenLifespan <= 900)) err("accessTokenLifespan must be 1..900 seconds");
  if (realm.sslRequired === "none") err("sslRequired must not be none");

  // No credential values anywhere: secret-like keys hold placeholders only.
  walk(realm, (key, value, trail) => {
    if (!SECRET_KEY.test(key)) return;
    if (key === "passwordPolicy" || key === "clientAuthenticatorType") return;
    const values = Array.isArray(value) ? value : [value];
    for (const v of values) {
      if (typeof v !== "string") continue;
      if (v === "" || PLACEHOLDER.test(v) || v === "true" || v === "false") continue;
      err(`credential-like value at ${trail.join(".")} must be a $(env:NAME) placeholder`);
    }
  });
  for (const u of realm.users || []) {
    if (u.credentials && u.credentials.length > 0) err(`user ${u.username} must not carry credentials`);
  }

  const clients = new Map((realm.clients || []).map((c) => [c.clientId, c]));
  const knownIds = new Set(clients.keys());

  // Service clients: one per registry entry, client credentials only.
  for (const entry of registry.clients) {
    const c = clients.get(entry.clientId);
    if (!c) { err(`service client ${entry.clientId} missing from realm`); continue; }
    if (c.publicClient !== false) err(`${c.clientId}: must be confidential`);
    if (c.serviceAccountsEnabled !== true) err(`${c.clientId}: service account must be enabled`);
    for (const f of ["standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled"]) {
      if (c[f] !== false) err(`${c.clientId}: ${f} must be false (client credentials only)`);
    }
    if (c.secret !== `$(env:${secretEnvName(c.clientId)})`) err(`${c.clientId}: secret must be $(env:${secretEnvName(c.clientId)})`);
    if (c.attributes?.["fbx.client-type"] !== "service") err(`${c.clientId}: attribute fbx.client-type must be service`);
    if (c.attributes?.["fbx.service-slug"] !== entry.serviceSlug) err(`${c.clientId}: attribute fbx.service-slug must be ${entry.serviceSlug}`);
    const sa = (realm.users || []).find((u) => u.serviceAccountClientId === c.clientId);
    if (!sa || !(sa.realmRoles || []).includes("service")) err(`${c.clientId}: service account must hold realm role service`);
    if (c.fullScopeAllowed === false) {
      const sm = (realm.scopeMappings || []).find((s) => s.client === c.clientId);
      if (!sm || !(sm.roles || []).includes("service")) err(`${c.clientId}: scope mapping for role service missing`);
    }
    const want = [...(entry.audiences || [])].sort();
    if (JSON.stringify(audiences(c)) !== JSON.stringify(want)) {
      err(`${c.clientId}: audience mappers ${audiences(c).join(",") || "<none>"} != registry ${want.join(",") || "<none>"}`);
    }
  }

  // Channel clients: web, mobile, TPP template.
  for (const entry of registry.channelClients || []) {
    const c = clients.get(entry.clientId);
    if (!c) { err(`channel client ${entry.clientId} missing from realm`); continue; }
    const want = [...(entry.audiences || [])].sort();
    if (want.length === 0) err(`${entry.clientId}: registry must list at least one audience`);
    if (JSON.stringify(audiences(c)) !== JSON.stringify(want)) {
      err(`${c.clientId}: audience mappers ${audiences(c).join(",") || "<none>"} != registry ${want.join(",")}`);
    }
    if (entry.type === "first-party-public") {
      if (c.publicClient !== true) err(`${c.clientId}: must be public`);
      if (c.secret) err(`${c.clientId}: public client must not have a secret`);
      if (c.attributes?.["pkce.code.challenge.method"] !== "S256") err(`${c.clientId}: PKCE S256 required`);
      if (c.implicitFlowEnabled !== false || c.directAccessGrantsEnabled !== false) err(`${c.clientId}: implicit and password grants must be off`);
    }
    if (entry.type === "open-finance-tpp") {
      if (c.publicClient !== false) err(`${c.clientId}: TPP clients are confidential`);
      if (c.attributes?.["require.pushed.authorization.requests"] !== "true") err(`${c.clientId}: PAR required`);
      if (c.attributes?.["dpop.bound.access.tokens"] !== "true" && c.attributes?.["tls.client.certificate.bound.access.tokens"] !== "true") {
        err(`${c.clientId}: tokens must be DPoP- or mTLS-bound`);
      }
    }
  }

  // Staff SSO clients (Grafana): confidential, code + PKCE, roles in userinfo.
  for (const entry of registry.ssoClients || []) {
    const c = clients.get(entry.clientId);
    if (!c) { err(`staff SSO client ${entry.clientId} missing from realm`); continue; }
    if (c.publicClient !== false) err(`${c.clientId}: must be confidential`);
    if (c.standardFlowEnabled !== true) err(`${c.clientId}: authorization code flow must be enabled`);
    for (const f of ["implicitFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled"]) {
      if (c[f] !== false) err(`${c.clientId}: ${f} must be false`);
    }
    if (c.attributes?.["pkce.code.challenge.method"] !== "S256") err(`${c.clientId}: PKCE S256 required`);
    if (c.attributes?.["fbx.client-type"] !== "staff-sso") err(`${c.clientId}: attribute fbx.client-type must be staff-sso`);
    if (c.secret !== `$(env:${secretEnvName(c.clientId)})`) err(`${c.clientId}: secret must be $(env:${secretEnvName(c.clientId)})`);
    const rm = (c.protocolMappers || []).find((m) => m.protocolMapper === "oidc-usermodel-realm-role-mapper");
    if (!rm || rm.config?.["claim.name"] !== "realm_access.roles" || rm.config?.["userinfo.token.claim"] !== "true") {
      err(`${c.clientId}: realm_access.roles mapper with userinfo claim required`);
    }
    const sm = (realm.scopeMappings || []).find((s) => s.client === c.clientId);
    const scoped = [...(sm?.roles || [])].sort();
    if (JSON.stringify(scoped) !== JSON.stringify([...(entry.roles || [])].sort())) err(`${c.clientId}: scope mapping ${scoped.join(",")} != registry roles`);
    if (!(c.redirectUris || []).every((u) => /^\$\(env:[A-Z0-9_]+\)\/login\/generic_oauth$/.test(u))) err(`${c.clientId}: redirect URIs must be <root placeholder>/login/generic_oauth`);
  }

  // Every audience must name a client in the realm; every client must be registered.
  const registered = new Set([
    ...registry.clients.map((c) => c.clientId),
    ...(registry.channelClients || []).map((c) => c.clientId),
    ...(registry.ssoClients || []).map((c) => c.clientId)
  ]);
  for (const c of clients.values()) {
    if (!registered.has(c.clientId)) err(`client ${c.clientId} is not in realm/service-clients.json`);
    for (const a of audiences(c)) if (!knownIds.has(a)) err(`${c.clientId}: audience ${a} is not a client of the realm`);
  }

  // FAPI 2.0 policies for open-finance TPPs.
  const policies = realm.clientPolicies?.policies || [];
  const profilesUsed = new Set(policies.filter((p) => p.enabled !== false).flatMap((p) => p.profiles || []));
  for (const p of ["fapi-2-dpop-security-profile", "fapi-2-security-profile"]) {
    if (!profilesUsed.has(p)) err(`client policy using ${p} missing`);
  }

  // LDAP federation: read-only, credentials as placeholders, group mapper read-only.
  const ldap = (realm.components?.["org.keycloak.storage.UserStorageProvider"] || []).find((c) => c.providerId === "ldap");
  if (!ldap) {
    err("LDAP user federation component missing");
  } else {
    const cfg = ldap.config || {};
    if (cfg.editMode?.[0] !== "READ_ONLY") err("LDAP editMode must be READ_ONLY");
    for (const k of ["connectionUrl", "bindDn", "bindCredential"]) {
      if (!PLACEHOLDER.test(cfg[k]?.[0] || "")) err(`LDAP ${k} must be a $(env:NAME) placeholder`);
    }
    const mappers = ldap.subComponents?.["org.keycloak.storage.ldap.mappers.LDAPStorageMapper"] || [];
    const gm = mappers.find((m) => m.providerId === "group-ldap-mapper");
    if (!gm) err("LDAP group mapper missing");
    else if (gm.config?.mode?.[0] !== "READ_ONLY") err("LDAP group mapper mode must be READ_ONLY");
    const staff = (realm.groups || []).find((g) => g.name === "staff");
    for (const [group, role] of Object.entries(STAFF_ROLE_GROUPS)) {
      const g = (staff?.subGroups || []).find((s) => s.name === group);
      if (!g || !(g.realmRoles || []).includes(role)) err(`group /staff/${group} must grant realm role ${role}`);
    }
  }

  // Every placeholder must be supplied by the import Job.
  if (importEnv && importSecretKeys) {
    const supplied = new Set([...Object.keys(importEnv), ...importSecretKeys]);
    const used = new Set();
    walk(realm, (_k, v) => {
      for (const s of Array.isArray(v) ? v : [v]) {
        if (typeof s !== "string") continue;
        for (const m of s.matchAll(/\$\(env:([A-Z0-9_]+)\)/g)) used.add(m[1]);
      }
    });
    for (const name of used) if (!supplied.has(name)) err(`placeholder ${name} is not supplied by the realm import Job`);
    for (const entry of [...registry.clients, ...(registry.ssoClients || [])]) {
      const env = secretEnvName(entry.clientId);
      if (!importSecretKeys.includes(env)) err(`ExternalSecret keycloak-realm-import lacks ${env}`);
      const want = `ENVIRONMENT/${entry.serviceSlug}/oidc-client`;
      if (importSecretRefs && importSecretKeys.includes(env) && importSecretRefs[env] !== want) {
        err(`ExternalSecret keycloak-realm-import ${env} must read ${want} (found ${importSecretRefs[env]})`);
      }
    }
  }

  return errors;
}

export function loadFromRepo(root) {
  const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
  const realm = JSON.parse(read("realm/fintechbankx-realm.json"));
  const registry = JSON.parse(read("realm/service-clients.json"));
  const importEnv = YAML.parse(read("deploy/kustomize/base/realm-import/env.yaml")).data;
  const es = YAML.parse(read("deploy/kustomize/base/realm-import/externalsecret.yaml"));
  const importSecretKeys = es.spec.data.map((d) => d.secretKey);
  const importSecretRefs = Object.fromEntries(es.spec.data.map((d) => [d.secretKey, d.remoteRef?.key]));
  return { realm, registry, importEnv, importSecretKeys, importSecretRefs };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const i = process.argv.indexOf("--root");
  const root = i > 0 ? process.argv[i + 1] : path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const input = loadFromRepo(root);
  const errors = checkRealm(input);
  const n = input.realm.clients.length;
  if (errors.length > 0) {
    for (const e of errors) console.error(`realm-check: ${e}`);
    console.error(`realm-check: FAILED (${errors.length} problem(s), ${n} clients)`);
    process.exit(1);
  }
  console.log(`realm-check: OK (${n} clients, ${input.registry.clients.length} service clients, ${(input.registry.ssoClients || []).length} staff SSO clients, roles ${CONTRACT_ROLES.length})`);
}
