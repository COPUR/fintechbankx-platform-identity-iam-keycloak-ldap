// The view of a running realm that the service-client rules
// (service-client-rules.mjs) and the TPP rules (tpp-rules.mjs) check, without
// dependencies, so the realm import Job's node:alpine container loads it as
// well as check-realm.mjs --live and --live-export. One model for all three
// callers: check-realm.mjs (--live-export reads a partial export, --live the
// admin API) and onboard-tpp.mjs --verify-live (admin API, the import Job's
// last step).
import { liveTppErrors, fetchClients } from "./tpp-rules.mjs";
import { scopedCalleesOf, serviceClientErrors } from "./service-client-rules.mjs";

// The flows and authenticator configs of the view, one model for both modes:
// the top-level flows GET /authentication/flows lists, which in Keycloak
// 26.7.5 is every one but SAML_ECP_FLOW (AuthenticationManagementResource
// getFlows), and the subflows and configs that the executions of every
// top-level flow name, SAML_ECP_FLOW included (its executions are read by
// alias). A top-level flow aliased . or .. is reported by name and its
// executions are not read: a URL path collapses that segment, so the admin
// API cannot be asked for them. Orphan flows and configs, which a partial
// export lists and the admin API never shows, are left out.
export const SAML_ECP_FLOW = "saml ecp";
const DOT_SEGMENTS = [".", ".."];
const dotSegmentError = (alias) => `flow alias ${JSON.stringify(alias)} cannot be read through the admin API (URL paths collapse . and .. segments); rename it`;

// From a partial export, which names a subflow (flowAlias) and a config
// (authenticatorConfig) by alias: an orphan that shares its alias with a flow
// or config the executions use cannot be told apart and stays in (a config
// alias used twice then fails --live-export only).
function exportFlows(flows, configs) {
  const kept = new Set();
  const configAliases = new Set();
  const readErrors = [];
  const follow = (flow) => {
    for (const e of flow.authenticationExecutions || []) {
      if (e.authenticatorConfig !== undefined) configAliases.add(e.authenticatorConfig);
      if (e.authenticatorFlow !== true) continue;
      for (const sub of flows.filter((f) => f.alias === e.flowAlias && !kept.has(f))) {
        kept.add(sub);
        follow(sub);
      }
    }
  };
  for (const top of flows.filter((f) => f.topLevel === true)) {
    if (top.alias !== SAML_ECP_FLOW) kept.add(top);
    if (DOT_SEGMENTS.includes(top.alias)) readErrors.push(dotSegmentError(top.alias));
    else follow(top);
  }
  return { authenticationFlows: flows.filter((f) => kept.has(f)), authenticatorConfig: configs.filter((c) => configAliases.has(c.alias)), readErrors };
}

// A partial export of the realm (POST
// .../partial-export?exportClients=true&exportGroupsAndRoles=true): an object
// with clients, clientScopes, defaultDefaultClientScopes and
// defaultOptionalClientScopes (scope names), authenticationFlows (every flow,
// subflows included, with ids; a client's flow override names a flow id) and
// roles (with their composites; defaultRole names the default role);
// scopeMappings, clientScopeMappings and authenticatorConfig count as empty
// when absent (Keycloak's export leaves them out then). Flows and configs are
// cut to what the admin API shows (exportFlows).
const EXPORT_KEYS = ["clients", "clientScopes", "defaultDefaultClientScopes", "defaultOptionalClientScopes", "authenticationFlows"];
export function liveExportView(json) {
  if (Array.isArray(json)) throw new Error("--live-export: a GET /clients array covers the TPP rules only; export the realm with partial-export?exportClients=true&exportGroupsAndRoles=true");
  for (const k of EXPORT_KEYS) if (!Array.isArray(json?.[k])) throw new Error(`--live-export: the export lacks ${k} (partial-export?exportClients=true&exportGroupsAndRoles=true)`);
  if (!json.roles || typeof json.roles !== "object") throw new Error("--live-export: the export lacks roles (partial-export with exportGroupsAndRoles=true)");
  return { ...Object.fromEntries(EXPORT_KEYS.map((k) => [k, json[k]])), roles: json.roles, scopeMappings: json.scopeMappings || [], clientScopeMappings: json.clientScopeMappings || {},
    resetCredentialsFlow: json.resetCredentialsFlow, registrationAllowed: json.registrationAllowed, editUsernameAllowed: json.editUsernameAllowed, identityProviders: json.identityProviders || [],
    defaultRole: json.defaultRole, ...exportFlows(json.authenticationFlows, json.authenticatorConfig || []) };
}

// The same view from the admin API (view-clients, view-realm and
// view-identity-providers). Client-role scope mappings are read only for a
// by-scope callee that has client roles: the roles of that callee in each
// client's and client scope's effective role scope, as Keycloak's hasScope
// gives them (fullScopeAllowed, composites and a client's own roles applied).
// calleeRoleScopes returns these unchanged, so both modes apply one model. The
// staff sign-in rule reads the realm's resetCredentialsFlow,
// registrationAllowed and defaultRole, its identity providers, the realm roles
// with the composites of each composite role and of each composite client
// role they reach (GET /roles-by-id/{id}/composites), and the flows and
// configs of the model above: the top-level flows GET /authentication/flows
// lists, and from the flattened executions of each top-level flow
// (GET /authentication/flows/{alias}/executions; SAML_ECP_FLOW too, by alias)
// its subflows by id (GET /authentication/flows/{id}) and authenticator
// configs by id (GET /authentication/config/{id}), each read once, so the view
// has the shape of an export (a config alias used twice by executions is seen
// in both modes).
export async function fetchLiveView({ fetch = globalThis.fetch, baseUrl, token, realm, registry }) {
  const base = `${String(baseUrl).replace(/\/+$/, "")}/admin/realms/${encodeURIComponent(realm)}`;
  const get = async (p, missingOk = false) => {
    const url = base + p;
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}`, Accept: "application/json" } });
    if (missingOk && res.status === 404) return undefined;
    if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
    return res.json();
  };
  const names = (list) => list.map((s) => s.name);
  const clients = await fetchClients({ fetch, baseUrl, token, realm });
  const clientScopes = await get("/client-scopes");
  const view = {
    clients,
    clientScopes,
    defaultDefaultClientScopes: names(await get("/default-default-client-scopes")),
    defaultOptionalClientScopes: names(await get("/default-optional-client-scopes")),
    roles: { realm: await get("/roles"), client: {} },
    scopeMappings: [],
    clientScopeMappings: {},
    authenticationFlows: await get("/authentication/flows"),
    authenticatorConfig: [],
    identityProviders: await get("/identity-provider/instances")
  };
  const realmRep = await get("");
  view.resetCredentialsFlow = realmRep.resetCredentialsFlow;
  view.registrationAllowed = realmRep.registrationAllowed;
  view.editUsernameAllowed = realmRep.editUsernameAllowed;
  view.defaultRole = realmRep.defaultRole;
  view.readErrors = [];
  const flowIds = new Set(view.authenticationFlows.map((f) => f.id));
  const configIds = new Set();
  const tops = view.authenticationFlows.filter((f) => f.topLevel !== false).map((f) => f.alias);
  if (!tops.includes(SAML_ECP_FLOW)) tops.push(SAML_ECP_FLOW);
  for (const alias of tops) {
    if (DOT_SEGMENTS.includes(alias)) { view.readErrors.push(dotSegmentError(alias)); continue; }
    // SAML_ECP_FLOW is not listed; a realm without it answers 404.
    for (const row of (await get(`/authentication/flows/${encodeURIComponent(alias)}/executions`, alias === SAML_ECP_FLOW)) || []) {
      if (row.authenticationFlow === true && !flowIds.has(row.flowId)) {
        flowIds.add(row.flowId);
        view.authenticationFlows.push(await get(`/authentication/flows/${encodeURIComponent(row.flowId)}`));
      }
      if (row.authenticationConfig && !configIds.has(row.authenticationConfig)) {
        configIds.add(row.authenticationConfig);
        view.authenticatorConfig.push(await get(`/authentication/config/${encodeURIComponent(row.authenticationConfig)}`));
      }
    }
  }
  for (const callee of scopedCalleesOf(registry)) {
    const c = clients.find((x) => x.clientId === callee);
    if (!c) continue; // reported as missing by serviceClientErrors
    const id = encodeURIComponent(c.id);
    const own = await get(`/clients/${id}/roles`);
    view.roles.client[callee] = own;
    if (!own.length) continue;
    const mappings = [];
    for (const h of clients) {
      if (h.clientId === callee) continue;
      const r = await get(`/clients/${encodeURIComponent(h.id)}/scope-mappings/clients/${id}/composite`);
      if (r.length) mappings.push({ client: h.clientId, roles: names(r) });
    }
    for (const sc of clientScopes) {
      const r = await get(`/client-scopes/${encodeURIComponent(sc.id)}/scope-mappings/clients/${id}/composite`);
      if (r.length) mappings.push({ clientScope: sc.name, roles: names(r) });
    }
    view.clientScopeMappings[callee] = mappings;
  }
  // Composites in the export's shape ({realm: [names], client: {clientId:
  // [names]}}) on each composite realm role, and on each composite client
  // role reached from one, added to roles.client.
  const clientIdOf = new Map(clients.map((c) => [c.id, c.clientId]));
  const todo = view.roles.realm.filter((r) => r.composite === true).map((r) => [r.id, r]);
  const read = new Set();
  while (todo.length) {
    const [id, role] = todo.pop();
    if (read.has(id)) continue;
    read.add(id);
    role.composites = { realm: [], client: {} };
    for (const c of await get(`/roles-by-id/${encodeURIComponent(id)}/composites`)) {
      let def;
      if (c.clientRole === true) {
        const owner = clientIdOf.get(c.containerId) ?? c.containerId;
        (role.composites.client[owner] ||= []).push(c.name);
        const own = (view.roles.client[owner] ||= []);
        def = own.find((x) => x.name === c.name) || (own.push(c), c);
      } else {
        role.composites.realm.push(c.name);
        def = view.roles.realm.find((x) => x.name === c.name);
      }
      if (c.composite === true && def) todo.push([c.id, def]);
    }
  }
  return view;
}

// Every live problem: what the view could not read (a flow aliased . or ..),
// the TPP rules on the clients, the service-client rules on the whole view
// with the registry realm/service-clients.json.
export const liveRealmErrors = (view, registry) => [...(view.readErrors || []), ...liveTppErrors(view.clients), ...serviceClientErrors(view, registry)];
