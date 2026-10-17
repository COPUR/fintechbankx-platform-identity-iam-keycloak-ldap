// The view of a running realm that the service-client rules
// (service-client-rules.mjs) and the TPP rules (tpp-rules.mjs) check, without
// dependencies, so the realm import Job's node:alpine container loads it as
// well as check-realm.mjs --live and --live-export. One model for all three
// callers: check-realm.mjs (--live-export reads a partial export, --live the
// admin API) and onboard-tpp.mjs --verify-live (admin API, the import Job's
// last step).
import { liveTppErrors, fetchClients } from "./tpp-rules.mjs";
import { scopedCalleesOf, serviceClientErrors } from "./service-client-rules.mjs";

// A partial export of the realm (POST
// .../partial-export?exportClients=true&exportGroupsAndRoles=true): an object
// with clients, clientScopes, defaultDefaultClientScopes and
// defaultOptionalClientScopes (scope names) and roles; scopeMappings and
// clientScopeMappings count as empty when absent (Keycloak's export leaves
// them out then).
const EXPORT_KEYS = ["clients", "clientScopes", "defaultDefaultClientScopes", "defaultOptionalClientScopes"];
export function liveExportView(json) {
  if (Array.isArray(json)) throw new Error("--live-export: a GET /clients array covers the TPP rules only; export the realm with partial-export?exportClients=true&exportGroupsAndRoles=true");
  for (const k of EXPORT_KEYS) if (!Array.isArray(json?.[k])) throw new Error(`--live-export: the export lacks ${k} (partial-export?exportClients=true&exportGroupsAndRoles=true)`);
  if (!json.roles || typeof json.roles !== "object") throw new Error("--live-export: the export lacks roles (partial-export with exportGroupsAndRoles=true)");
  return { ...Object.fromEntries(EXPORT_KEYS.map((k) => [k, json[k]])), roles: json.roles, scopeMappings: json.scopeMappings || [], clientScopeMappings: json.clientScopeMappings || {} };
}

// The same view from the admin API (view-clients and view-realm). Client-role
// scope mappings are read only for a by-scope callee that has client roles:
// the roles of that callee in each client's and client scope's effective role
// scope, as Keycloak's hasScope gives them (fullScopeAllowed, composites and a
// client's own roles applied). calleeRoleScopes returns these unchanged, so
// both modes apply one model.
export async function fetchLiveView({ fetch = globalThis.fetch, baseUrl, token, realm, registry }) {
  const base = `${String(baseUrl).replace(/\/+$/, "")}/admin/realms/${encodeURIComponent(realm)}`;
  const get = async (p) => {
    const url = base + p;
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}`, Accept: "application/json" } });
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
    roles: { client: {} },
    scopeMappings: [],
    clientScopeMappings: {}
  };
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
  return view;
}

// Every live problem: the TPP rules on the clients, the service-client rules
// on the whole view with the registry realm/service-clients.json.
export const liveRealmErrors = (view, registry) => [...liveTppErrors(view.clients), ...serviceClientErrors(view, registry)];
