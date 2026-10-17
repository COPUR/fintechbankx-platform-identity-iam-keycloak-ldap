#!/usr/bin/env node
// Sanity gate for realm-as-code (realm/fintechbankx-realm.json).
// Checks the realm against the platform contract and the client registry
// (realm/service-clients.json), that it carries no credential values, and
// that every $(env:NAME) placeholder is supplied by the realm import Job.
//
// usage: node scripts/ci/check-realm.mjs [--root <repo-root>]
//        node scripts/ci/check-realm.mjs (--live | --live-export <file>) [--realm <name>] [--root <repo-root>]
//        (live drift check, see checkLive below)
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { PAYMENTS_SCOPE, TPP_CLIENT_TYPE, CLIENT_TYPE_CLAIM, TPP_CLIENT_TYPE_SCOPE, DCR_SOURCES, DCR_POLICY_TYPE, tppClientErrors, clientTypeMappers, parseList } from "../realm/tpp-rules.mjs";
import { fetchAdminToken } from "../realm/apply-admin-permissions.mjs";
import { AUDIENCE_SCOPE, audiences, serviceClientErrors } from "../realm/service-client-rules.mjs";
import { liveExportView, fetchLiveView, liveRealmErrors } from "../realm/live-view.mjs";

export const CONTRACT_ROLES = ["customer", "banker", "loan_officer", "admin", "service", "auditor", "compliance_officer"];
export const STAFF_ROLE_GROUPS = {
  "fbx-banker": "banker",
  "fbx-loan-officer": "loan_officer",
  "fbx-admin": "admin",
  "fbx-auditor": "auditor",
  "fbx-compliance-officer": "compliance_officer"
};
const CUSTOMER_ID_SCOPE = "customer-id";
export { PAYMENTS_SCOPE, TPP_CLIENT_TYPE, CLIENT_TYPE_CLAIM, TPP_CLIENT_TYPE_SCOPE, tppClientErrors, liveTppErrors } from "../realm/tpp-rules.mjs";
const PLACEHOLDER = /^\$\(env:[A-Z0-9_]+\)$/;
const SECRET_KEY = /(secret|credential|password|passwd|private.?key)/i;

export const secretEnvName = (clientId) => "FBX_OIDC_SECRET_" + clientId.toUpperCase().replace(/-/g, "_");

// Audience scopes (registry audienceByScope), audience mappers and
// fullScopeAllowed: scripts/realm/service-client-rules.mjs, shared with the
// live drift check below.
export { audienceScopeName, serviceClientErrors } from "../realm/service-client-rules.mjs";

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

export const STAFF_ROLES = Object.values(STAFF_ROLE_GROUPS);
// Audiences only staff may reach (risk decisions, compliance evidence).
export const STAFF_ONLY_AUDIENCES = ["svc-rsk-decisioning", "svc-cmp-evidence"];
const MAX_OFFLINE_IDLE = 1209600; // 14 days
const MAX_OFFLINE_LIFESPAN = 2592000; // 30 days
const MAX_STAFF_IDLE = 900;
const MAX_STAFF_LIFESPAN = 28800;
const inRange = (v, max) => Number(v) > 0 && Number(v) <= max;

export const ADMIN_PERMISSION_SCOPES = ["view-members", "manage-members"];

export function checkRealm({ realm, registry, adminPermissions = null, importEnv = null, importSecretKeys = null, importSecretRefs = null }) {
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
  if (realm.offlineSessionMaxLifespanEnabled !== true) err("offlineSessionMaxLifespanEnabled must be true");
  if (!inRange(realm.offlineSessionIdleTimeout, MAX_OFFLINE_IDLE)) err(`offlineSessionIdleTimeout must be 1..${MAX_OFFLINE_IDLE}`);
  if (!inRange(realm.offlineSessionMaxLifespan, MAX_OFFLINE_LIFESPAN)) err(`offlineSessionMaxLifespan must be 1..${MAX_OFFLINE_LIFESPAN}`);
  // Fine-grained admin permissions v2; a default group would also be joined
  // by every new service account, so none.
  if (realm.adminPermissionsEnabled !== true) err("adminPermissionsEnabled must be true (fine-grained admin permissions v2)");
  if (!realm.clientScopeMappings || typeof realm.clientScopeMappings !== "object") err("clientScopeMappings must be present (empty object), or keycloak-config-cli never removes client scope mappings");
  if ((realm.defaultGroups || []).length) err("defaultGroups must be empty (service accounts would join them)");

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

  // Service clients: one per registry entry (a missing one is reported by
  // serviceClientErrors), client credentials only.
  for (const entry of registry.clients) {
    const c = clients.get(entry.clientId);
    if (!c) continue;
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
    const sm = (realm.scopeMappings || []).find((s) => s.client === c.clientId);
    if (!sm || !(sm.roles || []).includes("service")) err(`${c.clientId}: scope mapping for role service missing`);
    // No realm-management role on any service client (ADMIN_ROLES_ALLOWED is
    // empty): user administration is granted per group through fine-grained
    // admin permissions v2 (realm/admin-permissions.json), never realm-wide.
    const ADMIN_ROLES_ALLOWED = [];
    if ((entry.adminRoles || []).some((r) => !ADMIN_ROLES_ALLOWED.includes(r))) err(`${c.clientId}: registry adminRoles are not allowed (use realm/admin-permissions.json)`);
    if ((sa?.clientRoles?.["realm-management"] || []).length) err(`${c.clientId}: service account must not hold realm-management roles`);
    else if (sa && !Array.isArray(sa.clientRoles?.["realm-management"])) err(`${c.clientId}: service account must list clientRoles realm-management: [] (so keycloak-config-cli removes earlier grants)`);
    if ((realm.clientScopeMappings?.["realm-management"] || []).some((m) => m.client === c.clientId)) err(`${c.clientId}: realm-management scope mapping is not allowed`);
  }
  // Audience mappers and optional audience scopes of service and channel
  // clients against the registry, the by-scope callees reached only through
  // their aud- scope (no client mapper, other scope, realm default or
  // client-role scope mapping), and fullScopeAllowed false on every client.
  for (const m of serviceClientErrors(realm, registry)) err(m);

  // Channel clients: web, mobile, TPP template. A missing one, audience
  // mappers and optional audience scopes: serviceClientErrors.
  for (const entry of registry.channelClients || []) {
    const c = clients.get(entry.clientId);
    if (!c) continue;
    if (!(entry.audiences || []).length) err(`${entry.clientId}: registry must list at least one audience`);
    if (entry.type === "first-party-public") {
      if (c.publicClient !== true) err(`${c.clientId}: must be public`);
      if (c.secret) err(`${c.clientId}: public client must not have a secret`);
      if (c.attributes?.["pkce.code.challenge.method"] !== "S256") err(`${c.clientId}: PKCE S256 required`);
      if (c.implicitFlowEnabled !== false || c.directAccessGrantsEnabled !== false) err(`${c.clientId}: implicit and password grants must be off`);
      // One user type per client: customer clients map only customer, the
      // staff client only the staff roles (never both on one client).
      const e = (m) => err(`${c.clientId}: ${m}`);
      if (!["customer", "staff"].includes(entry.userType)) e("registry userType must be customer or staff");
      const staff = entry.userType === "staff";
      const wantRoles = (staff ? [...STAFF_ROLES] : ["customer"]).sort();
      const sm = [...((realm.scopeMappings || []).find((x) => x.client === c.clientId)?.roles || [])].sort();
      if (JSON.stringify(sm) !== JSON.stringify(wantRoles)) e(`scope mapping ${sm.join(",")} != ${wantRoles.join(",")}`);
      if (!staff) for (const a of new Set([...audiences(c), ...(entry.audiences || [])])) if (STAFF_ONLY_AUDIENCES.includes(a)) e(`staff-only audience ${a} on a customer client`);
      const scopes = [...(c.defaultClientScopes || []), ...(c.optionalClientScopes || [])];
      if (scopes.includes("offline_access")) {
        if (entry.offlineAccess !== true || staff) e("offline_access is not allowed (registry offlineAccess, customer clients only)");
        if (!inRange(c.attributes?.["client.offline.session.idle.timeout"], MAX_OFFLINE_IDLE)) e(`client.offline.session.idle.timeout must be 1..${MAX_OFFLINE_IDLE}`);
        if (!inRange(c.attributes?.["client.offline.session.max.lifespan"], MAX_OFFLINE_LIFESPAN)) e(`client.offline.session.max.lifespan must be 1..${MAX_OFFLINE_LIFESPAN}`);
      }
      if (staff) {
        if ((c.optionalClientScopes || []).some((s) => !AUDIENCE_SCOPE.test(s))) e("staff clients may have no optional scopes but their registry audience scopes");
        if (scopes.includes(CUSTOMER_ID_SCOPE)) e("staff clients must not carry the customer-id scope");
        if (!inRange(c.attributes?.["client.session.idle.timeout"], MAX_STAFF_IDLE)) e(`client.session.idle.timeout must be 1..${MAX_STAFF_IDLE}`);
        if (!inRange(c.attributes?.["client.session.max.lifespan"], MAX_STAFF_LIFESPAN)) e(`client.session.max.lifespan must be 1..${MAX_STAFF_LIFESPAN}`);
      } else if (!scopes.includes(CUSTOMER_ID_SCOPE)) {
        e("customer clients must carry the customer-id scope");
      }
    }
    if (entry.type !== "first-party-public" && (c.optionalClientScopes || []).includes("offline_access")) err(`${c.clientId}: offline_access is not allowed`);
    if (entry.type === "open-finance-tpp") {
      if (c.publicClient !== false) err(`${c.clientId}: TPP clients are confidential`);
      if (c.attributes?.["require.pushed.authorization.requests"] !== "true") err(`${c.clientId}: PAR required`);
      if (c.attributes?.["dpop.bound.access.tokens"] !== "true") err(`${c.clientId}: tokens must be DPoP-bound`);
      if (c.attributes?.["fbx.tpp.token-binding"] !== "dpop") err(`${c.clientId}: fbx.tpp.token-binding must be dpop (mTLS-bound tokens are not supported)`);
    }
  }

  // Staff SSO clients (Grafana): confidential, code + PKCE, roles in userinfo.
  // A missing one, audience mappers and optional audience scopes:
  // serviceClientErrors.
  for (const entry of registry.ssoClients || []) {
    const c = clients.get(entry.clientId);
    if (!c) continue;
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
  // Every registry audience says where it comes from (confirmed by the owning
  // service thread, or derived); a provenance without its audience is stale.
  for (const entry of [...registry.clients, ...(registry.channelClients || []), ...(registry.ssoClients || [])]) {
    const prov = entry.audienceProvenance || {};
    for (const a of entry.audiences || []) {
      if (!/^(confirmed by|derived)/.test(prov[a] ?? "")) err(`${entry.clientId}: audience ${a} needs an audienceProvenance starting with "confirmed by" or "derived"`);
    }
    for (const k of Object.keys(prov)) if (!(entry.audiences || []).includes(k)) err(`${entry.clientId}: audienceProvenance ${k} names no registry audience of this client`);
  }

  // Fine-grained admin permissions (applied by scripts/realm/apply-admin-permissions.mjs).
  const groupPaths = new Set();
  const collect = (gs, parent = "") => {
    for (const g of gs || []) { const p = g.path || `${parent}/${g.name}`; groupPaths.add(p); collect(g.subGroups, p); }
  };
  collect(realm.groups);
  const serviceIds = new Set(registry.clients.map((c) => c.clientId));
  if (adminPermissions) {
    if (adminPermissions.realm !== realm.realm) err(`admin-permissions.json realm ${adminPermissions.realm} != ${realm.realm}`);
    for (const p of adminPermissions.permissions || []) {
      const e = (m) => err(`${p.name}: ${m}`);
      if (!/^fbx-[a-z0-9-]+$/.test(p.name || "")) err(`admin permission name ${p.name} must match fbx-<kebab>`);
      if (p.resourceType !== "Groups") e("resourceType must be Groups (no realm-wide Users, Clients or Roles permission)");
      if (!(p.groupPaths || []).length) e("groupPaths must list at least one group");
      for (const gp of p.groupPaths || []) {
        if (gp === "/staff" || gp.startsWith("/staff/")) e(`group ${gp} must not be a staff group`);
        else if (!groupPaths.has(gp)) e(`group ${gp} is not in the realm`);
      }
      for (const sc of p.scopes || []) if (!ADMIN_PERMISSION_SCOPES.includes(sc)) e(`scope ${sc} is not allowed (only ${ADMIN_PERMISSION_SCOPES.join(", ")})`);
      if (!(p.scopes || []).length) e("scopes must not be empty");
      if (p.decisionStrategy !== "UNANIMOUS") e("decisionStrategy must be UNANIMOUS");
      if (!p.reason) e("reason required");
      if (p.policy?.type !== "client" || p.policy?.logic !== "POSITIVE") e("policy must be a POSITIVE client policy");
      if (!(p.policy?.clients || []).length) e("policy must name at least one client");
      for (const id of p.policy?.clients || []) if (!serviceIds.has(id)) e(`policy client ${id} is not a service client`);
    }
  }

  // Scopes that only open-finance TPP clients may carry (request-to-pay
  // PR #14): payments (optional, requested by the TPP) and the client-type
  // scope, whose hardcoded fbx_client_type must equal the client's
  // fbx.client-type attribute. Neither may be a realm default: a client
  // created without explicit scopes would get it.
  const scopesByName = new Map((realm.clientScopes || []).map((s) => [s.name, s]));
  const realmDefaults = [...(realm.defaultDefaultClientScopes || []), ...(realm.defaultOptionalClientScopes || [])];
  const payments = scopesByName.get(PAYMENTS_SCOPE);
  if (!payments) err(`client scope ${PAYMENTS_SCOPE} missing`);
  else if (payments.attributes?.["include.in.token.scope"] !== "true") err(`client scope ${PAYMENTS_SCOPE} must set include.in.token.scope=true (services read it from the scope claim)`);
  const typeScopes = [...scopesByName.values()].flatMap((s) =>
    (s.protocolMappers || [])
      .filter((m) => m.config?.["claim.name"] === CLIENT_TYPE_CLAIM)
      .map((m) => ({ scope: s.name, value: m.config?.["claim.value"], mapper: m })));
  for (const t of typeScopes) {
    if (t.mapper.protocolMapper !== "oidc-hardcoded-claim-mapper") err(`client scope ${t.scope}: ${CLIENT_TYPE_CLAIM} must come from a hardcoded-claim mapper`);
    if (t.mapper.config?.["access.token.claim"] !== "true") err(`client scope ${t.scope}: ${CLIENT_TYPE_CLAIM} must be in the access token`);
  }
  for (const name of [PAYMENTS_SCOPE, ...typeScopes.map((t) => t.scope)]) {
    if (realmDefaults.includes(name)) err(`client scope ${name} must not be a realm default scope`);
  }
  for (const c of clients.values()) {
    const scopes = [...(c.defaultClientScopes || []), ...(c.optionalClientScopes || [])];
    const type = c.attributes?.["fbx.client-type"];
    if (scopes.includes(PAYMENTS_SCOPE) && type !== TPP_CLIENT_TYPE) err(`${c.clientId}: scope ${PAYMENTS_SCOPE} is for open-finance TPP clients only`);
    for (const t of typeScopes) {
      if (scopes.includes(t.scope) && t.value !== type) err(`${c.clientId}: scope ${t.scope} emits ${CLIENT_TYPE_CLAIM}=${t.value} but the client is fbx.client-type=${type}`);
    }
    if (type === TPP_CLIENT_TYPE) {
      if (!(c.optionalClientScopes || []).includes(PAYMENTS_SCOPE)) err(`${c.clientId}: TPP clients must carry the ${PAYMENTS_SCOPE} scope (optional)`);
      if (!typeScopes.some((t) => t.value === type && (c.defaultClientScopes || []).includes(t.scope))) err(`${c.clientId}: TPP clients must carry a default scope emitting ${CLIENT_TYPE_CLAIM}=${type}`);
      for (const m of tppClientErrors(c)) err(`${c.clientId}: ${m}`);
    } else {
      for (const m of clientTypeMappers(c)) err(`${c.clientId}: ${CLIENT_TYPE_CLAIM} may only come from a client scope (found client mapper ${m.name})`);
    }
  }
  if (!typeScopes.some((t) => t.scope === TPP_CLIENT_TYPE_SCOPE && t.value === TPP_CLIENT_TYPE)) err(`client scope ${TPP_CLIENT_TYPE_SCOPE} must emit ${CLIENT_TYPE_CLAIM}=${TPP_CLIENT_TYPE}`);
  for (const entry of registry.channelClients || []) {
    const c = clients.get(entry.clientId);
    if (c && entry.type === TPP_CLIENT_TYPE && c.attributes?.["fbx.client-type"] !== TPP_CLIENT_TYPE) err(`${c.clientId}: registry type ${TPP_CLIENT_TYPE} requires attribute fbx.client-type=${TPP_CLIENT_TYPE}`);
  }

  // FAPI 2.0 policies for open-finance TPPs.
  const policies = realm.clientPolicies?.policies || [];
  const profilesUsed = new Set(policies.filter((p) => p.enabled !== false).flatMap((p) => p.profiles || []));
  if (!profilesUsed.has("fapi-2-dpop-security-profile")) err("client policy using fapi-2-dpop-security-profile missing");

  // DPoP is the only token binding. TLS ends at the Istio gateway (SIMPLE)
  // and Keycloak runs behind plain HTTP, so it never sees a client
  // certificate: no certificate-bound tokens, no client-x509 authentication.
  for (const c of clients.values()) {
    if (c.attributes?.["tls.client.certificate.bound.access.tokens"] === "true") err(`${c.clientId}: certificate-bound tokens are not supported (DPoP only)`);
    if (c.attributes?.["fbx.tpp.token-binding"] && c.attributes["fbx.tpp.token-binding"] !== "dpop") err(`${c.clientId}: fbx.tpp.token-binding must be dpop`);
    if (c.clientAuthenticatorType === "client-x509") err(`${c.clientId}: clientAuthenticatorType client-x509 is not allowed`);
  }
  for (const p of policies) {
    const conds = JSON.stringify(p.conditions || []);
    if ((p.profiles || []).includes("fapi-2-security-profile") || /token-binding\\?"[^}]*mtls/.test(conds)) {
      err(`client policy ${p.name}: mTLS-bound tokens are not supported (DPoP only)`);
    }
  }
  for (const prof of realm.clientProfiles?.profiles || []) {
    for (const e of prof.executors || []) {
      if ((e.configuration?.["allowed-client-authenticators"] || []).includes("client-x509")) err(`client profile ${prof.name}: client-x509 is not allowed`);
      if (e.configuration?.["tls-client-certificate-bound-access-tokens"] === "true" || e.executor === "holder-of-key-enforcer") err(`client profile ${prof.name}: certificate-bound tokens are not supported`);
    }
  }

  // Dynamic Client Registration closed: an enabled client policy whose only
  // condition is the DCR updater context (all three sources) applies a
  // profile with the reject-request executor.
  const rejectProfiles = new Set((realm.clientProfiles?.profiles || [])
    .filter((p) => (p.executors || []).some((x) => x.executor === "reject-request"))
    .map((p) => p.name));
  const closesDcr = policies.some((p) => {
    if (p.enabled === false || (p.conditions || []).length !== 1) return false;
    const [cond] = p.conditions;
    const sources = parseList(cond.configuration?.["update-client-source"]);
    return cond.condition === "client-updater-context"
      && cond.configuration?.is_negative_logic !== true
      && DCR_SOURCES.every((s) => sources.includes(s))
      && (p.profiles || []).some((n) => rejectProfiles.has(n));
  });
  if (!closesDcr) err(`client policy rejecting Dynamic Client Registration (client-updater-context ${DCR_SOURCES.join(", ")} -> reject-request) missing`);

  // Registration policies declared in the realm file (defence in depth if the
  // client policy above is ever switched off): anonymous registration closed,
  // neither TPP scope registrable, no mapper type that could emit the claim.
  const dcr = realm.components?.[DCR_POLICY_TYPE] || [];
  for (const subType of ["anonymous", "authenticated"]) {
    for (const [providerId, name] of [["allowed-client-templates", "Allowed Client Scopes"], ["allowed-protocol-mappers", "Allowed Protocol Mapper Types"]]) {
      if (!dcr.some((c) => c.subType === subType && c.providerId === providerId)) err(`DCR policy ${name} (${subType}) missing`);
    }
  }
  const th = dcr.find((c) => c.subType === "anonymous" && c.providerId === "trusted-hosts");
  if (!th || parseList(th.config?.["trusted-hosts"]).length > 0
    || parseList(th.config?.["host-sending-registration-request-must-match"])[0] !== "true"
    || parseList(th.config?.["client-uris-must-match"])[0] !== "true") {
    err("DCR policy Trusted Hosts (anonymous): anonymous registration must stay closed (no trusted hosts, both checks on)");
  }
  for (const c of dcr) {
    const label = `DCR policy ${c.name} (${c.subType})`;
    if (c.providerId === "allowed-client-templates") {
      for (const s of parseList(c.config?.["allowed-client-scopes"])) {
        if (s === PAYMENTS_SCOPE || typeScopes.some((t) => t.scope === s)) err(`${label}: must not allow ${s}`);
      }
    }
    if (c.providerId === "allowed-protocol-mappers" && parseList(c.config?.["allowed-protocol-mapper-types"]).includes("oidc-hardcoded-claim-mapper")) {
      err(`${label}: oidc-hardcoded-claim-mapper is not allowed (it could emit ${CLIENT_TYPE_CLAIM})`);
    }
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
  // yaml is loaded here only, so --live runs without node_modules.
  const YAML = createRequire(import.meta.url)("yaml");
  const read = (p) => fs.readFileSync(path.join(root, p), "utf8");
  const realm = JSON.parse(read("realm/fintechbankx-realm.json"));
  const registry = JSON.parse(read("realm/service-clients.json"));
  const adminPermissions = JSON.parse(read("realm/admin-permissions.json"));
  const importEnv = YAML.parse(read("deploy/kustomize/base/realm-import/env.yaml")).data;
  const es = YAML.parse(read("deploy/kustomize/base/realm-import/externalsecret.yaml"));
  const importSecretKeys = es.spec.data.map((d) => d.secretKey);
  const importSecretRefs = Object.fromEntries(es.spec.data.map((d) => [d.secretKey, d.remoteRef?.key]));
  return { realm, registry, adminPermissions, importEnv, importSecretKeys, importSecretRefs };
}

// Live drift check: the clients and client scopes of a running realm against
// the TPP rules (scripts/realm/tpp-rules.mjs; runtime TPP clients are not in
// the realm file) and the service-client rules
// (scripts/realm/service-client-rules.mjs) with the registry
// realm/service-clients.json, on the view of scripts/realm/live-view.mjs
// (shared with the realm import Job's onboard-tpp.mjs --verify-live).
//   --live-export <file>  partial export of the realm (liveExportView)
//   --live                reads the same through the admin API from
//                         KEYCLOAK_URL with the KEYCLOAK_* credential
//                         variables of apply-admin-permissions.mjs
//   --realm <name>        realm for --live (default fintechbankx)
//   --root <repo-root>    where realm/service-clients.json is read
export { liveExportView, fetchLiveView, liveRealmErrors } from "../realm/live-view.mjs";

export async function checkLive({ argv = process.argv, env = process.env, fetch = globalThis.fetch } = {}) {
  const arg = (n) => { const i = argv.indexOf(n); return i > 0 ? argv[i + 1] : undefined; };
  const root = arg("--root") || path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
  const registry = JSON.parse(fs.readFileSync(path.join(root, "realm/service-clients.json"), "utf8"));
  let view;
  if (arg("--live-export")) {
    view = liveExportView(JSON.parse(fs.readFileSync(arg("--live-export"), "utf8")));
  } else {
    const token = await fetchAdminToken({ fetch, env });
    view = await fetchLiveView({ fetch, baseUrl: env.KEYCLOAK_URL, token, realm: arg("--realm") || "fintechbankx", registry });
  }
  return { clients: view.clients, registry, errors: liveRealmErrors(view, registry) };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain && (process.argv.includes("--live") || process.argv.includes("--live-export"))) {
  try {
    const { clients, registry, errors } = await checkLive();
    const tpps = clients.filter((c) => c.attributes?.["fbx.client-type"] === TPP_CLIENT_TYPE).length;
    const counts = `${clients.length} clients, ${tpps} open-finance-tpp, ${registry.clients.length} service clients`;
    for (const e of errors) console.error(`realm-check --live: ${e}`);
    if (errors.length) {
      console.error(`realm-check --live: FAILED (${errors.length} problem(s), ${counts})`);
      process.exit(1);
    }
    console.log(`realm-check --live: OK (${counts})`);
  } catch (e) {
    console.error(`realm-check --live: FAILED: ${e.message}`);
    process.exit(1);
  }
} else if (isMain) {
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
