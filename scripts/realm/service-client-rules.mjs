// Service-client audience and scope rules, without dependencies. One set of
// rules for the realm file (scripts/ci/check-realm.mjs) and for a running
// realm (check-realm.mjs --live and --live-export), so a live Keycloak is held
// to the realm-as-code.
//
// Input: a realm representation, or the same shape assembled from the admin
// API: clients, clientScopes, defaultDefaultClientScopes,
// defaultOptionalClientScopes (scope names), roles, scopeMappings (realm-role
// scope mappings) and clientScopeMappings (client-role scope mappings by
// role-owning client, as in a realm export).
//
// A registry callee with audienceByScope: true is reached only through the
// optional client scope aud-<callee>. These routes to its audience are
// refused (Keycloak 26.7.5):
// - an oidc-audience-mapper naming it (client or custom audience) on any
//   client, or in any client scope but aud-<callee> (realm default scopes
//   included);
// - on any client or client scope, any mapper whose claim.name, read as a
//   Keycloak claim path (claimPath below), starts with aud (this realm sets
//   audiences only through oidc-audience-mapper);
// - on any client but the callee and on any client scope, an
//   oidc-hardcoded-role-mapper whose role starts with "<callee>.", and an
//   oidc-role-name-mapper whose new.role.name starts with "<callee>.";
// - a client role of the callee in the role scope of another client or of a
//   client scope (calleeRoleScopes below).
// The last two kinds rely on Keycloak's audience resolve mapper (built-in scope
// roles), which adds the owning client of every client role in the token to
// aud, also for a role name that no client defines.
export const AUDIENCE_MAPPER = "oidc-audience-mapper";
export const HARDCODED_ROLE_MAPPER = "oidc-hardcoded-role-mapper";
export const ROLE_NAME_MAPPER = "oidc-role-name-mapper";
export const AUDIENCE_SCOPE = /^aud-/;
export const audienceScopeName = (aud) => `aud-${aud}`;
export const scopedCalleesOf = (registry) => new Set((registry.clients || []).filter((c) => c.audienceByScope === true).map((c) => c.clientId));

// The audience of each audience mapper of a client: included.client.audience
// (the registry form), else custom:<included.custom.audience>, which never
// matches a registry audience.
export const audiences = (client) => (client.protocolMappers || [])
  .filter((m) => m.protocolMapper === AUDIENCE_MAPPER)
  .map((m) => m.config?.["included.client.audience"] || `custom:${m.config?.["included.custom.audience"] ?? ""}`)
  .sort();
export const audienceScopes = (client) => (client.optionalClientScopes || []).filter((s) => AUDIENCE_SCOPE.test(s)).sort();

// Every audience one mapper adds: the client audience and the custom audience.
const mapperAudiences = (m) => (m.protocolMapper === AUDIENCE_MAPPER
  ? [m.config?.["included.client.audience"], m.config?.["included.custom.audience"]].filter(Boolean)
  : []);
const scopedAudiences = (holder, scopedCallees) => [...new Set((holder.protocolMappers || []).flatMap(mapperAudiences))]
  .filter((a) => scopedCallees.has(a))
  .sort();

const onlyVia = (a) => `is reached only through the optional scope ${audienceScopeName(a)} (registry audienceByScope)`;

// claim.name as Keycloak reads it (JsonUtils.splitClaimPath, 26.7.5): split
// on dots that no backslash escapes, then a backslash before any character
// stands for that character. The token's aud is set when the first component
// is aud, so "aud.", "\aud" and "a\ud" set it too.
export function claimPath(name) {
  const out = [];
  let rest = String(name);
  const unescape = (s) => s.replace(/\\(.)/g, "$1");
  for (let m = /^((?:\\.|[^\\.])+?)\./.exec(rest); m; m = /^((?:\\.|[^\\.])+?)\./.exec(rest)) {
    out.push(unescape(m[1]));
    rest = rest.slice(m[0].length);
  }
  if (rest.length) out.push(unescape(rest));
  return out;
}

// Mappers that put a by-scope callee into aud other than oidc-audience-mapper.
// holderClientId: the client that holds the mapper (undefined for a client
// scope). The audience resolve mapper never puts the token's own client into
// aud, so a callee role on the callee's own client is no route.
const otherAudienceRoutes = (m, scopedCallees, holderClientId) => {
  const c = m.config || {};
  const out = [];
  const name = c["claim.name"];
  const claim = typeof name === "string" ? claimPath(name) : [];
  if (m.protocolMapper !== AUDIENCE_MAPPER && claim[0] === "aud") {
    const how = name === "aud" ? "writes claim aud"
      : `writes ${claim.length === 1 ? "claim" : "under claim"} aud (claim.name ${JSON.stringify(name)}, Keycloak claim path ${JSON.stringify(claim)})`;
    out.push(`mapper ${m.name} (${m.protocolMapper}) ${how}; this realm sets audiences only through ${AUDIENCE_MAPPER}`);
  }
  for (const callee of scopedCallees) {
    if (callee === holderClientId) continue;
    const yields = (role) => typeof role === "string" && role.startsWith(`${callee}.`);
    const tail = `a client role of ${callee}, so tokens would carry aud=${callee} (audience resolve); ${callee} ${onlyVia(callee)}`;
    if (m.protocolMapper === HARDCODED_ROLE_MAPPER && yields(c.role)) out.push(`mapper ${m.name} (${m.protocolMapper}) adds role ${c.role}, ${tail}`);
    if (m.protocolMapper === ROLE_NAME_MAPPER && yields(c["new.role.name"])) out.push(`mapper ${m.name} (${m.protocolMapper}) renames a role to ${c["new.role.name"]}, ${tail}`);
  }
  return out;
};

// Keycloak's built-in admin clients: created with fullScopeAllowed=true and
// lightweight access tokens, which carry no aud. Exempt from the role-scope
// rule only while that attribute is "true" and no audience resolve mapper
// with lightweight.claim "true" sits on the client or in one of its default or
// optional client scopes: such a mapper puts aud back into lightweight tokens
// (Keycloak 26.7.5). Token introspection still returns the full token, aud
// included, so the exemption holds only for resource servers that validate
// the JWT locally.
export const BUILT_IN_ADMIN_CLIENTS = ["admin-cli", "security-admin-console"];
export const LIGHTWEIGHT_TOKENS = "client.use.lightweight.access.token.enabled";
export const AUDIENCE_RESOLVE_MAPPER = "oidc-audience-resolve-mapper";
const lightweightAudienceResolve = (holder) => (holder?.protocolMappers || [])
  .some((m) => m.protocolMapper === AUDIENCE_RESOLVE_MAPPER && m.config?.["lightweight.claim"] === "true");
const exemptBuiltIn = (c, scopesByName) => BUILT_IN_ADMIN_CLIENTS.includes(c.clientId) && c.attributes?.[LIGHTWEIGHT_TOKENS] === "true"
  && ![c, ...[...(c.defaultClientScopes || []), ...(c.optionalClientScopes || [])].map((n) => scopesByName.get(n))].some(lightweightAudienceResolve);

// The client roles of callee in each client's and client scope's role scope,
// as Keycloak's hasScope decides it (ClientAdapter, ClientScopeAdapter):
// a client other than the callee holds every callee role when its
// fullScopeAllowed is not false; otherwise, like a client scope, a callee role
// when an explicit realm-role or client-role scope mapping, or (for a client)
// one of its own client roles, is that role or a composite containing it at any
// depth (roles.realm, roles.client). The exempt built-ins (exemptBuiltIn) are
// left out.
// Given the effective mappings Keycloak returns (--live), the result is those
// mappings again.
export function calleeRoleScopes(realm, callee) {
  const calleeRoles = (realm.roles?.client?.[callee] || []).map((r) => r.name);
  if (!calleeRoles.length) return [];
  const key = (owner, name) => JSON.stringify([owner, name]);
  const defs = new Map([
    ...(realm.roles?.realm || []).map((r) => [key(null, r.name), r]),
    ...Object.entries(realm.roles?.client || {}).flatMap(([id, rs]) => (rs || []).map((r) => [key(id, r.name), r]))
  ]);
  const inScope = (seeds) => {
    const seen = new Set();
    const todo = [...seeds];
    while (todo.length) {
      const [owner, name] = todo.pop();
      const k = key(owner, name);
      if (seen.has(k)) continue;
      seen.add(k);
      const r = defs.get(k);
      for (const n of r?.composites?.realm || []) todo.push([null, n]);
      for (const [id, ns] of Object.entries(r?.composites?.client || {})) for (const n of ns || []) todo.push([id, n]);
    }
    return calleeRoles.filter((n) => seen.has(key(callee, n))).sort();
  };
  const explicit = (match) => [
    ...(realm.scopeMappings || []).filter(match).flatMap((m) => (m.roles || []).map((n) => [null, n])),
    ...Object.entries(realm.clientScopeMappings || {}).flatMap(([owner, ms]) => (ms || []).filter(match).flatMap((m) => (m.roles || []).map((n) => [owner, n])))
  ];
  // A client or client scope named only in a mapping (a Keycloak built-in, in
  // the realm file) is judged by its explicit mappings.
  const named = (field, known) => [...new Set([...(realm.scopeMappings || []), ...Object.values(realm.clientScopeMappings || {}).flat()]
    .map((m) => m?.[field]).filter((n) => n && !known.has(n)))];
  const clients = realm.clients || [];
  const scopes = realm.clientScopes || [];
  const scopesByName = new Map(scopes.map((s) => [s.name, s]));
  const out = [];
  for (const c of [...clients, ...named("client", new Set(clients.map((x) => x.clientId))).map((clientId) => ({ clientId, fullScopeAllowed: false }))]) {
    if (c.clientId === callee || exemptBuiltIn(c, scopesByName)) continue;
    const roles = c.fullScopeAllowed !== false ? [...calleeRoles].sort()
      : inScope([...explicit((m) => m.client === c.clientId), ...(realm.roles?.client?.[c.clientId] || []).map((r) => [c.clientId, r.name])]);
    if (roles.length) out.push({ client: c.clientId, roles });
  }
  for (const name of [...scopes.map((s) => s.name), ...named("clientScope", new Set(scopes.map((s) => s.name)))]) {
    const roles = inScope(explicit((m) => m.clientScope === name));
    if (roles.length) out.push({ clientScope: name, roles });
  }
  return out;
}

// Keycloak treats a missing fullScopeAllowed as true: every realm role and
// client role of the user (or service account) would reach the token.
export const fullScopeErrors = (c) => (c.fullScopeAllowed === false ? [] : [`${c.clientId}: fullScopeAllowed must be false (Keycloak treats a missing value as true)`]);

export function serviceClientErrors(realm, registry) {
  const errors = [];
  const err = (m) => errors.push(m);
  const clients = new Map((realm.clients || []).map((c) => [c.clientId, c]));
  const scopedCallees = scopedCalleesOf(registry);
  const serviceIds = new Set(registry.clients.map((c) => c.clientId));
  const registered = new Set([...serviceIds, ...(registry.channelClients || []).map((c) => c.clientId), ...(registry.ssoClients || []).map((c) => c.clientId)]);

  // Each service client: its audience mappers and optional audience scopes
  // are the registry's.
  for (const entry of registry.clients) {
    const c = clients.get(entry.clientId);
    if (!c) { err(`service client ${entry.clientId} missing from realm`); continue; }
    const want = (entry.audiences || []).filter((a) => !scopedCallees.has(a)).sort();
    if (JSON.stringify(audiences(c)) !== JSON.stringify(want)) {
      err(`${c.clientId}: audience mappers ${audiences(c).join(",") || "<none>"} != registry ${want.join(",") || "<none>"}`);
    }
    const wantScopes = (entry.audiences || []).filter((a) => scopedCallees.has(a)).map(audienceScopeName).sort();
    if (JSON.stringify(audienceScopes(c)) !== JSON.stringify(wantScopes)) {
      err(`${c.clientId}: optional audience scopes ${audienceScopes(c).join(",") || "<none>"} != registry ${wantScopes.join(",") || "<none>"}`);
    }
  }

  // Every client: no mapper for a by-scope callee, audience scopes optional
  // and on service clients only. fullScopeAllowed false on every registry
  // client and every client tagged fbx.client-type (runtime TPP clients);
  // Keycloak's built-in clients of a running realm are neither.
  for (const c of clients.values()) {
    for (const a of scopedAudiences(c, scopedCallees)) err(`${c.clientId}: audience ${a} ${onlyVia(a)}, never through a mapper`);
    if (!serviceIds.has(c.clientId) && audienceScopes(c).length) err(`${c.clientId}: optional audience scopes are for service clients only`);
    for (const name of c.defaultClientScopes || []) if (AUDIENCE_SCOPE.test(name)) err(`${c.clientId}: audience scope ${name} must be optional, not default`);
    if (registered.has(c.clientId) || c.attributes?.["fbx.client-type"]) for (const m of fullScopeErrors(c)) err(m);
  }

  // One audience scope per by-scope callee, holding exactly one access-token
  // audience mapper for it and nothing else; no aud- scope without a callee.
  const scopes = new Map((realm.clientScopes || []).map((s) => [s.name, s]));
  for (const aud of scopedCallees) {
    const name = audienceScopeName(aud);
    const s = scopes.get(name);
    if (!s) { err(`client scope ${name} missing (registry ${aud} has audienceByScope)`); continue; }
    const ms = s.protocolMappers || [];
    const ok = s.protocol === "openid-connect" && ms.length === 1 && ms[0].protocolMapper === AUDIENCE_MAPPER
      && ms[0].config?.["included.client.audience"] === aud && !ms[0].config?.["included.custom.audience"]
      && ms[0].config?.["access.token.claim"] === "true";
    if (!ok) err(`client scope ${name}: must carry exactly one access-token audience mapper for ${aud}`);
  }
  for (const name of scopes.keys()) {
    if (AUDIENCE_SCOPE.test(name) && !scopedCallees.has(name.slice("aud-".length))) err(`client scope ${name}: no registry client with audienceByScope is named ${name.slice("aud-".length)}`);
  }

  // No other client scope carries a by-scope audience (customer-id, payments,
  // the client-type scope, a new scope, another aud- scope).
  for (const s of scopes.values()) {
    for (const a of scopedAudiences(s, scopedCallees)) {
      if (s.name !== audienceScopeName(a)) err(`client scope ${s.name}: audience ${a} ${onlyVia(a)}, never through another client scope`);
    }
  }

  // Realm default scopes: a client created without explicit scopes gets them.
  for (const name of [...(realm.defaultDefaultClientScopes || []), ...(realm.defaultOptionalClientScopes || [])]) {
    if (AUDIENCE_SCOPE.test(name)) { err(`realm: audience scope ${name} must not be a realm default scope`); continue; }
    for (const a of scopedAudiences(scopes.get(name) || {}, scopedCallees)) {
      err(`realm: default scope ${name} carries audience ${a} (registry audienceByScope); a client created without explicit scopes would get it`);
    }
  }

  // Other audience routes on every client and client scope (realm default
  // scopes included): a mapper writing claim aud, a hardcoded or renamed
  // client role of a by-scope callee (except on the callee's own client).
  for (const [label, holder, holderClientId] of [...[...clients.values()].map((c) => [c.clientId, c, c.clientId]), ...[...scopes.values()].map((s) => [`client scope ${s.name}`, s, undefined])]) {
    for (const m of holder.protocolMappers || []) {
      for (const r of otherAudienceRoutes(m, scopedCallees, holderClientId)) err(`${label}: ${r}`);
    }
  }

  // Audience resolve: a client role of a by-scope callee in another client's
  // or a client scope's role scope (calleeRoleScopes). The callee may have
  // roles of its own; a role in no such role scope is not refused.
  for (const callee of scopedCallees) {
    const tail = `, so tokens issued with it would carry aud=${callee} (audience resolve); ${callee} ${onlyVia(callee)}`;
    for (const h of calleeRoleScopes(realm, callee)) {
      const target = h.client ? `client ${h.client}` : `client scope ${h.clientScope}`;
      err(`${callee}: client roles ${h.roles.join(",")} are in the role scope of ${target}${tail}`);
    }
  }
  return errors;
}
