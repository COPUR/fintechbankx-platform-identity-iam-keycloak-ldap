// The TPP client-type guarantee, without dependencies (runs in the realm
// import Job's node:alpine container as well as in CI).
//
// The request-to-pay service and the gateway fail closed unless the access
// token carries fbx_client_type=open-finance-tpp. Only the default client
// scope fbx-client-type-open-finance-tpp emits it, so every client tagged
// fbx.client-type=open-finance-tpp must carry that scope as a default scope.
// Used by scripts/ci/check-realm.mjs (clients in the realm file and, with
// --live, clients in a running Keycloak) and scripts/realm/onboard-tpp.mjs
// (TPP clients created at runtime).
export const PAYMENTS_SCOPE = "payments";
export const TPP_CLIENT_TYPE = "open-finance-tpp";
export const CLIENT_TYPE_CLAIM = "fbx_client_type";
export const TPP_CLIENT_TYPE_SCOPE = `fbx-client-type-${TPP_CLIENT_TYPE}`;

// Dynamic Client Registration (Keycloak 26.7.5, checked locally): anonymous
// registration is refused by the Trusted Hosts policy, but an initial access
// token can register a client tagged fbx.client-type=open-finance-tpp without
// the client-type scope (Allowed Client Scopes can forbid a scope, never
// require one). DCR is therefore closed by a client policy and TPPs are
// onboarded only through scripts/realm/onboard-tpp.mjs.
export const DCR_POLICY_TYPE = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy";
export const DCR_SOURCES = ["ByAnonymous", "ByInitialAccessToken", "ByRegistrationAccessToken"];

export const parseList = (v) => (Array.isArray(v) ? v : typeof v === "string" ? [v] : []);
export const clientTypeMappers = (c) => (c.protocolMappers || []).filter((m) => m.config?.["claim.name"] === CLIENT_TYPE_CLAIM);

// Rules for one TPP client representation. paymentsAuthorised true/false
// also checks that payments is (not) an optional scope; undefined leaves it.
export function tppClientErrors(c, { paymentsAuthorised } = {}) {
  const errors = [];
  const e = (m) => errors.push(m);
  const defaults = c.defaultClientScopes || [];
  const optional = c.optionalClientScopes || [];
  if (c.attributes?.["fbx.client-type"] !== TPP_CLIENT_TYPE) e(`attribute fbx.client-type must be ${TPP_CLIENT_TYPE}`);
  if (c.attributes?.["fbx.tpp.token-binding"] !== "dpop") e("open-finance-tpp clients must set fbx.tpp.token-binding=dpop");
  if (c.attributes?.["dpop.bound.access.tokens"] !== "true") e("open-finance-tpp clients must set dpop.bound.access.tokens=true");
  if (c.attributes?.["require.pushed.authorization.requests"] !== "true") e("open-finance-tpp clients must require PAR");
  if (c.publicClient !== false) e("open-finance-tpp clients are confidential");
  if (c.clientAuthenticatorType !== "client-jwt") e("open-finance-tpp clients authenticate with private_key_jwt (client-jwt) only");
  if (!defaults.includes(TPP_CLIENT_TYPE_SCOPE)) e(`open-finance-tpp clients must carry client scope ${TPP_CLIENT_TYPE_SCOPE} as a default scope`);
  if (optional.includes(TPP_CLIENT_TYPE_SCOPE)) e(`client scope ${TPP_CLIENT_TYPE_SCOPE} must not be optional (it would only appear when requested)`);
  if (defaults.includes(PAYMENTS_SCOPE)) e(`${PAYMENTS_SCOPE} must be an optional scope of open-finance-tpp clients, never a default scope`);
  if (paymentsAuthorised === true && !optional.includes(PAYMENTS_SCOPE)) e(`${PAYMENTS_SCOPE} must be an optional scope when payment services are authorised`);
  if (paymentsAuthorised === false && optional.includes(PAYMENTS_SCOPE)) e(`${PAYMENTS_SCOPE} is only for TPPs authorised for payment services`);
  for (const m of clientTypeMappers(c)) e(`${CLIENT_TYPE_CLAIM} may only come from a client scope (found client mapper ${m.name})`);
  return errors;
}

// Drift check over the clients of a running realm (admin API GET /clients or
// a partial export): every client tagged open-finance-tpp follows the rules
// above; no other client carries a TPP scope or emits the claim itself.
export function liveTppErrors(clients) {
  const errors = [];
  for (const c of clients || []) {
    const id = c.clientId;
    if (c.attributes?.["fbx.client-type"] === TPP_CLIENT_TYPE) {
      for (const m of tppClientErrors(c)) errors.push(`${id}: ${m}`);
      continue;
    }
    const scopes = [...(c.defaultClientScopes || []), ...(c.optionalClientScopes || [])];
    for (const s of [TPP_CLIENT_TYPE_SCOPE, PAYMENTS_SCOPE]) {
      if (scopes.includes(s)) errors.push(`${id}: scope ${s} on a client that is not fbx.client-type=${TPP_CLIENT_TYPE}`);
    }
    for (const m of clientTypeMappers(c)) errors.push(`${id}: ${CLIENT_TYPE_CLAIM} may only come from a client scope (found client mapper ${m.name})`);
  }
  return errors;
}

// Reads the clients of a partial export ({clients: [...]}) or of GET /clients ([...]).
export const clientsOf = (json) => (Array.isArray(json) ? json : json?.clients || []);

// Every client of a realm through the admin API (needs view-clients), paged.
export async function fetchClients({ fetch = globalThis.fetch, baseUrl, token, realm, pageSize = 100 }) {
  const out = [];
  for (let first = 0; ; first += pageSize) {
    const url = `${String(baseUrl).replace(/\/+$/, "")}/admin/realms/${encodeURIComponent(realm)}/clients?first=${first}&max=${pageSize}`;
    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}`, Accept: "application/json" } });
    if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
    const page = await res.json();
    out.push(...page);
    if (page.length < pageSize) return out;
  }
}
