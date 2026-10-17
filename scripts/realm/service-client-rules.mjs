// Service-client audience and scope rules, without dependencies. One set of
// rules for the realm file (scripts/ci/check-realm.mjs) and for a running
// realm (check-realm.mjs --live and --live-export), so a live Keycloak is held
// to the realm-as-code.
//
// Input: a realm representation, or the same shape assembled from the admin
// API: clients, clientScopes, defaultDefaultClientScopes,
// defaultOptionalClientScopes (scope names), roles and clientScopeMappings
// (client-role scope mappings by role-owning client, as in a realm export).
//
// A registry callee with audienceByScope: true is reached only through the
// optional client scope aud-<callee>. Its audience is refused anywhere else:
// in a client mapper, in another client scope, in a realm default scope, and
// as a client role of the callee in another client's or client scope's role
// scope (Keycloak's audience resolve mapper, in the built-in scope roles,
// adds the owning client of every client role in the token to aud).
export const AUDIENCE_MAPPER = "oidc-audience-mapper";
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
  const onlyVia = (a) => `is reached only through the optional scope ${audienceScopeName(a)} (registry audienceByScope)`;

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

  // Audience resolve: a client role of a by-scope callee in another client's
  // or client scope's role scope, directly or through a composite role. The
  // callee may have roles of its own; only these mappings are refused.
  for (const callee of scopedCallees) {
    const tail = `, so tokens issued with it would carry aud=${callee} (audience resolve); ${callee} ${onlyVia(callee)}`;
    for (const m of realm.clientScopeMappings?.[callee] || []) {
      if (m.client === callee || !(m.roles || []).length) continue;
      const target = m.client ? `client ${m.client}` : `client scope ${m.clientScope}`;
      err(`${callee}: client roles ${[...m.roles].sort().join(",")} are in the role scope of ${target}${tail}`);
    }
    const roles = [
      ...(realm.roles?.realm || []).map((r) => [r.name, r]),
      ...Object.entries(realm.roles?.client || {}).filter(([id]) => id !== callee).flatMap(([id, rs]) => (rs || []).map((r) => [`${id}/${r.name}`, r]))
    ];
    for (const [label, r] of roles) {
      const inner = r.composites?.client?.[callee] || [];
      if (inner.length) err(`role ${label}: composite of ${callee} client roles ${[...inner].sort().join(",")}${tail}`);
    }
  }
  return errors;
}
