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
// optional client scope aud-<callee>, held by exactly the registry clients
// (service, channel or staff SSO) whose registry audiences list it. These routes to its
// audience are refused (Keycloak 26.7.5):
// - an oidc-audience-mapper naming it (client or custom audience) on any
//   client, or in any client scope but aud-<callee> (realm default scopes
//   included);
// - on any client or client scope, a protocol mapper that is not a stock
//   Keycloak mapper (STOCK_PROTOCOL_MAPPERS below: script and custom SPI
//   mappers can write any claim);
// - on any client, standard token exchange (STANDARD_TOKEN_EXCHANGE below);
// - on any client but Keycloak's admin-permissions, Authorization Services
//   (UMA: authorizationServicesErrors below);
// - on any client or client scope, any mapper whose claim.name, read as a
//   Keycloak claim path (claimPath below), starts with aud (this realm sets
//   audiences only through oidc-audience-mapper);
// - on any client or client scope, a mapper with ${client_id} in claim.name
//   other than the built-in resource_access.${client_id}.roles (the client
//   role mapper puts a client id there first, so a client named aud would
//   write claim aud);
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
// Keycloak's client role mapper replaces ${client_id} in claim.name with the
// role's client id before reading the claim path (26.7.5), so only its
// built-in claim name may carry the placeholder.
export const CLIENT_ID_PLACEHOLDER = "${client_id}";
export const CLIENT_ROLES_CLAIM = "resource_access.${client_id}.roles";

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
  if (m.protocolMapper !== AUDIENCE_MAPPER && typeof name === "string" && name.includes(CLIENT_ID_PLACEHOLDER) && name !== CLIENT_ROLES_CLAIM) {
    out.push(`mapper ${m.name} (${m.protocolMapper}) has ${CLIENT_ID_PLACEHOLDER} in claim.name ${JSON.stringify(name)}; the client role mapper replaces it with a client id, so a client named aud would write claim aud; only ${CLIENT_ROLES_CLAIM} is allowed`);
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

// The protocol mapper provider ids of a stock Keycloak 26.7.5 (GET
// /admin/serverinfo, protocolMapperTypes for openid-connect and saml, read
// from a local 26.7.5 server with default features). A script mapper
// (script-<file>.js, from a deployed script provider) or a custom SPI mapper
// can write any claim, aud included, so any other provider id is refused on
// every client and client scope (built-in ones included).
export const STOCK_PROTOCOL_MAPPERS = {
  "openid-connect": ["oidc-acr-mapper", "oidc-address-mapper", "oidc-allowed-origins-mapper", "oidc-amr-mapper", "oidc-audience-mapper",
    "oidc-audience-resolve-mapper", "oidc-claims-param-token-mapper", "oidc-claims-param-value-idtoken-mapper", "oidc-full-name-mapper",
    "oidc-group-membership-mapper", "oidc-hardcoded-claim-mapper", "oidc-hardcoded-role-mapper", "oidc-nonce-backwards-compatible-mapper",
    "oidc-organization-group-membership-mapper", "oidc-organization-membership-mapper", "oidc-role-name-mapper", "oidc-session-state-mapper",
    "oidc-sha256-pairwise-sub-mapper", "oidc-sub-mapper", "oidc-usermodel-attribute-mapper", "oidc-usermodel-client-role-mapper",
    "oidc-usermodel-property-mapper", "oidc-usermodel-realm-role-mapper", "oidc-usersessionmodel-note-mapper"],
  saml: ["saml-audience-mapper", "saml-audience-resolve-mapper", "saml-authn-context-class-ref-mapper", "saml-group-membership-mapper",
    "saml-hardcode-attribute-mapper", "saml-hardcode-role-mapper", "saml-organization-group-membership-mapper",
    "saml-organization-membership-mapper", "saml-role-list-mapper", "saml-role-name-mapper", "saml-user-attribute-mapper",
    "saml-user-attribute-nameid-mapper", "saml-user-property-mapper", "saml-user-session-note-mapper"]
};
const STOCK_MAPPER_IDS = new Set(Object.values(STOCK_PROTOCOL_MAPPERS).flat());
const notStockMapper = (m) => (STOCK_MAPPER_IDS.has(m.protocolMapper) ? []
  : [`mapper ${m.name} (${m.protocolMapper}) is not a stock Keycloak 26.7.5 protocol mapper; script and custom SPI mappers can write any claim, aud included`]);

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

// Every role that seeds ([owner client id or null for a realm role, name])
// reach through composites at any depth (roles.realm, roles.client, and the
// realm's defaultRole when roles.realm lacks it), keyed by roleKey.
const roleKey = (owner, name) => JSON.stringify([owner, name]);
const compositesOf = (r) => [...(r?.composites?.realm || []).map((n) => [null, n]),
  ...Object.entries(r?.composites?.client || {}).flatMap(([id, ns]) => (ns || []).map((n) => [id, n]))];
function roleReach(realm) {
  const defs = new Map([
    ...(realm.defaultRole?.name ? [[roleKey(null, realm.defaultRole.name), realm.defaultRole]] : []),
    ...(realm.roles?.realm || []).map((r) => [roleKey(null, r.name), r]),
    ...Object.entries(realm.roles?.client || {}).flatMap(([id, rs]) => (rs || []).map((r) => [roleKey(id, r.name), r]))
  ]);
  return (seeds) => {
    const seen = new Set();
    const todo = [...seeds];
    while (todo.length) {
      const [owner, name] = todo.pop();
      const k = roleKey(owner, name);
      if (seen.has(k)) continue;
      seen.add(k);
      todo.push(...compositesOf(defs.get(k)));
    }
    return seen;
  };
}

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
  const reach = roleReach(realm);
  const inScope = (seeds) => {
    const seen = reach(seeds);
    return calleeRoles.filter((n) => seen.has(roleKey(callee, n))).sort();
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

// Standard token exchange (Keycloak 26.7.5, feature token-exchange-standard,
// on by default) is enabled per client by this attribute, read with
// Boolean.parseBoolean. With it, a client in the aud of a token it received
// can exchange that token for a new one for the same user, with its own
// optional scopes: svc-ln-loan-lifecycle turned a customer's
// fintechbankx-web token into one with aud svc-acc-accounts-ledger (scope
// aud-svc-acc-accounts-ledger). No client of this realm uses it.
export const STANDARD_TOKEN_EXCHANGE = "standard.token.exchange.enabled";
const tokenExchangeErrors = (c) => {
  const v = c.attributes?.[STANDARD_TOKEN_EXCHANGE];
  // Keycloak reads the attribute with Boolean.parseBoolean; a JSON boolean
  // true in the realm file is stored as "true".
  return v !== undefined && v !== null && String(v).toLowerCase() === "true"
    ? [`${c.clientId}: attribute ${STANDARD_TOKEN_EXCHANGE} is ${JSON.stringify(v)}; standard token exchange is not used in this realm (a client could trade a token it received for a new one with other audiences)`]
    : [];
};

// Authorization Services (UMA, Keycloak 26.7.5 feature authorization, on by
// default): on a client with authorizationServicesEnabled and a granting
// policy, any client's token buys an RPT with that client in aud (grant type
// urn:ietf:params:oauth:grant-type:uma-ticket, audience=<client>), with the
// realm roles of its role scope: svc-cus-profile-kyc got an RPT with aud
// svc-acc-accounts-ledger and realm role service. No client of this realm
// uses it. Keycloak's FGAP v2 client admin-permissions (adminPermissionsEnabled)
// is the resource server of the admin permissions and keeps it. Keycloak and
// keycloak-config-cli read the JSON strings "true", "True", "TRUE" and
// space-padded forms as true (mixed case such as "tRuE" fails the import), so
// any authorizationServicesEnabled but absent, false or "false" (any case) is
// refused.
export const FGAP_V2_CLIENT = "admin-permissions";
const authorizationServicesOff = (v) => v === undefined || v === false || (typeof v === "string" && v.toLowerCase() === "false");
const authorizationServicesErrors = (c) => (c.clientId !== FGAP_V2_CLIENT && (!authorizationServicesOff(c.authorizationServicesEnabled) || c.authorizationSettings !== undefined)
  ? [`${c.clientId}: Authorization Services are enabled (authorizationServicesEnabled or authorizationSettings); they are not used in this realm (any client could trade its token for an RPT with aud=${c.clientId} through grant type uma-ticket)`]
  : []);

// Keycloak treats a missing fullScopeAllowed as true: every realm role and
// client role of the user (or service account) would reach the token.
export const fullScopeErrors = (c) => (c.fullScopeAllowed === false ? [] : [`${c.clientId}: fullScopeAllowed must be false (Keycloak treats a missing value as true)`]);

// Staff sign-in (DevSecOps 2026-10-17, formerly REALM_AS_CODE gap 5). Every
// registry channel client with userType staff (staff web) binds its browser
// flow (authenticationFlowBindingOverrides.browser: the flow alias in the
// realm file, which keycloak-config-cli resolves; the flow id in an export
// and the admin API) to STAFF_BROWSER_FLOW. That flow signs the user in as
// Keycloak's built-in browser flow does (SSO cookie, else username and
// password, then OTP when the user has one configured; no Kerberos, no
// identity provider) and then runs a conditional subflow whose conditions all
// hold only for a user with none of the staff roles: one negated
// conditional-user-role per role (conditions of one subflow are ANDed), then
// deny-access-authenticator. The check runs after sign-in, so an SSO session
// started at the customer web client is refused at staff web too. Keycloak's
// role condition (ConditionalRoleAuthenticator, 26.7.5) returns false for a
// role name it cannot resolve whatever negate says, so one unknown role turns
// the deny off for every user: the gate requires the exact flow tree (order,
// requirements, authenticators, configs, compared as structures: every config
// an exact key set with exact string values), negate "true" and every staff
// role to exist as a realm role. Staff roles reach users only through the
// LDAP groups /staff/fbx-*. Keycloak's hasRole also counts composites and the
// default role default-roles-<realm>, which every user holds, so the gate
// refuses a staff role in the composites (at any depth, through client roles
// too) of any other realm role or of the default role, and, in the realm file,
// on any group outside /staff/fbx-* and on any user but a service account, and
// the legacy key defaultRoles. The LDAP provider and its mappers (no role or
// group mapper but the one group mapper into /staff/fbx-*) are checked in
// scripts/ci/check-realm.mjs, statically only.
//
// "Forgot password" ends in a sign-in to the client it started from, through
// the realm's reset credentials flow, which no client override reaches (a
// customer reset from staff web's login page got a staff web token with the
// ledger audience: local Keycloak 26.7.5 with an SMTP sink). The realm binds
// STAFF_RESET_FLOW instead: the built-in reset credentials flow plus the same
// staff check after the e-mail step, before the new password is set, run only
// for a client that has the marker client scope STAFF_CHANNEL_SCOPE as a
// default scope (conditional-client-scope reads the client's default and
// requested scopes; every staff channel client carries the marker). The page
// before the e-mail is the same for every username, and staff and customers
// alike get the e-mail, so the staff check adds nothing observable before the
// link (Keycloak's built-in e-mail step still answers more slowly when it
// sends a mail). The check runs at sign-in only: a refresh does not check
// roles again, so a session started with a staff role keeps refreshing until
// it ends (8 h at most). A staff group removed in the directory alone never
// calls Keycloak: the LDAP provider (cachePolicy DEFAULT) keeps the cached
// membership until the next changed-users sync or another eviction, and new
// sign-ins pass the staff check until then. Offboarding must log the user out
// or disable them in Keycloak (REALM_AS_CODE.md, gap 5). Self-registration
// and identity providers would sign users in through flows without the
// check, and direct grant through the realm's direct grant flow, so the realm
// allows neither and staff channel clients keep direct grant off.
export const STAFF_ROLES = ["banker", "loan_officer", "admin", "auditor", "compliance_officer"];
export const STAFF_BROWSER_FLOW = "fbx-staff-browser";
export const STAFF_RESET_FLOW = "fbx-reset-credentials";
export const STAFF_CHANNEL_SCOPE = "fbx-staff-channel";
export const staffChannelScope = () => ({
  name: STAFF_CHANNEL_SCOPE,
  description: "Marks the staff channel clients: the reset credentials flow runs its staff check only for clients with this default scope. No mappers; not in the token's scope claim.",
  protocol: "openid-connect",
  attributes: { "include.in.token.scope": "false", "display.on.consent.screen": "false" },
  protocolMappers: []
});
export function staffSignInFlows(roles = STAFF_ROLES) {
  const A = STAFF_BROWSER_FLOW;
  const R = STAFF_RESET_FLOW;
  const step = (authenticator, requirement, priority, authenticatorConfig) => ({ authenticator, authenticatorFlow: false, requirement, priority, userSetupAllowed: false, ...(authenticatorConfig ? { authenticatorConfig } : {}) });
  const sub = (flowAlias, requirement, priority) => ({ authenticatorFlow: true, flowAlias, requirement, priority, userSetupAllowed: false });
  const flow = (alias, topLevel, description, authenticationExecutions) => ({ alias, description, providerId: "basic-flow", topLevel, builtIn: false, authenticationExecutions });
  const notRole = (r) => `${A} not ${r}`;
  const resetNotRole = (r) => `${R} not ${r}`;
  return {
    authenticationFlows: [
      flow(A, true, "Staff web browser flow: sign in, then deny any user without a staff role", [sub(`${A} sign-in`, "REQUIRED", 10), sub(`${A} staff only`, "CONDITIONAL", 20)]),
      flow(`${A} sign-in`, false, "SSO cookie, else username and password", [step("auth-cookie", "ALTERNATIVE", 10), sub(`${A} forms`, "ALTERNATIVE", 20)]),
      flow(`${A} forms`, false, "Username and password, then OTP when the user has one", [step("auth-username-password-form", "REQUIRED", 10), sub(`${A} OTP`, "CONDITIONAL", 20)]),
      flow(`${A} OTP`, false, "OTP when the user has one configured", [step("conditional-user-configured", "REQUIRED", 10), step("auth-otp-form", "REQUIRED", 20)]),
      flow(`${A} staff only`, false, `Deny access to a user without any of ${roles.join(", ")}`,
        [...roles.map((r, i) => step("conditional-user-role", "REQUIRED", 10 * (i + 1), notRole(r))), step("deny-access-authenticator", "REQUIRED", 10 * (roles.length + 1))]),
      flow(R, true, "Reset credentials (the built-in flow), with the staff check for staff channel clients after the e-mail step",
        [step("reset-credentials-choose-user", "REQUIRED", 10), step("reset-credential-email", "REQUIRED", 20), sub(`${R} staff only`, "CONDITIONAL", 30),
          step("reset-password", "REQUIRED", 40), sub(`${R} OTP`, "CONDITIONAL", 50)]),
      flow(`${R} staff only`, false, `At a client with ${STAFF_CHANNEL_SCOPE}, deny access to a user without any of ${roles.join(", ")}`,
        [step("conditional-client-scope", "REQUIRED", 10, `${R} staff channel`), ...roles.map((r, i) => step("conditional-user-role", "REQUIRED", 10 * (i + 2), resetNotRole(r))),
          step("deny-access-authenticator", "REQUIRED", 10 * (roles.length + 2))]),
      flow(`${R} OTP`, false, "Reset OTP when the user has one configured", [step("conditional-user-configured", "REQUIRED", 10), step("reset-otp", "REQUIRED", 20)])
    ],
    authenticatorConfig: [
      ...roles.map((r) => ({ alias: notRole(r), config: { condUserRole: r, negate: "true" } })),
      { alias: `${R} staff channel`, config: { client_scope: STAFF_CHANNEL_SCOPE, negate: "false" } },
      ...roles.map((r) => ({ alias: resetNotRole(r), config: { condUserRole: r, negate: "true" } }))
    ]
  };
}

// The flow tree as Keycloak runs it: executions in priority order (Keycloak
// sorts by priority; keycloak-config-cli creates subflow executions in list
// order with a priority of its own, so list and priority order must agree),
// each a subflow (by alias) or an authenticator with its config (by alias).
// Ids, descriptions, subflow aliases and the priority values themselves do
// not count (treeShape); alias is kept for the error messages only.
function flowTree(view, alias, errs, seen = [], root = alias) {
  const found = (view.authenticationFlows || []).filter((f) => f.alias === alias);
  if (found.length !== 1 || seen.includes(alias)) return { missing: alias };
  const f = found[0];
  const execs = f.authenticationExecutions || [];
  const sorted = [...execs].sort((a, b) => Number(a.priority) - Number(b.priority));
  if (new Set(execs.map((e) => Number(e.priority))).size !== execs.length) errs.add(`flow ${alias}: two executions share priority; Keycloak's order between them is undefined`);
  else if (sorted.some((e, i) => e !== execs[i])) errs.add(`flow ${alias}: executions are not listed in priority order (keycloak-config-cli creates subflows in list order, Keycloak runs by priority)`);
  const config = (a) => {
    const cs = (view.authenticatorConfig || []).filter((c) => c.alias === a);
    if (cs.length > 1) errs.add(`flow ${root}: authenticator config alias ${a} is not unique`);
    return cs.length === 1 ? Object.fromEntries(Object.entries(cs[0].config || {}).map(([k, v]) => [k, String(v)]).sort()) : { missing: a };
  };
  return {
    alias,
    providerId: f.providerId,
    steps: sorted.map((e) => (e.authenticatorFlow === true
      ? { requirement: e.requirement, flow: flowTree(view, e.flowAlias, errs, [...seen, alias], root) }
      : { requirement: e.requirement, authenticator: e.authenticator, ...(e.authenticatorConfig !== undefined ? { config: config(e.authenticatorConfig) } : {}) }))
  };
}
// What the comparison reads of a tree, compared as JSON (never as a string
// joined by hand: a config value holding "," or "=" must not read as two keys).
const treeShape = (t) => (t.missing !== undefined ? { missing: t.missing } : { providerId: t.providerId, steps: t.steps.map(stepShape) });
const stepShape = (s) => (s.flow ? { requirement: s.requirement, flow: treeShape(s.flow) } : { requirement: s.requirement, authenticator: s.authenticator, config: s.config ?? null });
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const describeStep = (s) => (!s ? "nothing" : `${s.requirement} ${s.flow ? (s.flow.missing !== undefined ? `<missing ${s.flow.missing}>` : `flow ${s.flow.alias}`)
  : `${s.authenticator}${s.config ? ` ${JSON.stringify(s.config)}` : ""}`}`);
// Each difference, as "<expected flow alias> step <n>: got ..., want ...".
function treeDiffs(got, want, out = []) {
  if (same(treeShape(got), treeShape(want))) return out;
  if (got.missing !== undefined) return [...out, `${want.alias}: got <missing ${got.missing}>`];
  if (got.providerId !== want.providerId) out.push(`${want.alias}: got provider ${got.providerId}, want ${want.providerId}`);
  for (let i = 0; i < Math.max(got.steps.length, want.steps.length); i++) {
    const [g, w] = [got.steps[i], want.steps[i]];
    if (g && w && same(stepShape(g), stepShape(w))) continue;
    if (g?.flow && w?.flow && g.requirement === w.requirement && g.flow.missing === undefined) treeDiffs(g.flow, w.flow, out);
    else out.push(`${want.alias} step ${i + 1}: got ${describeStep(g)}, want ${describeStep(w)}`);
  }
  return out;
}

export function staffSignInErrors(realm, registry) {
  const errs = new Set();
  const flows = realm.authenticationFlows || [];
  const want = staffSignInFlows();
  const checkFlow = (alias, what) => {
    if (!flows.some((f) => f.alias === alias)) { errs.add(`flow ${alias} missing (${what})`); return; }
    const diffs = treeDiffs(flowTree(realm, alias, errs), flowTree(want, alias, new Set()));
    if (diffs.length) errs.add(`flow ${alias}: differs from the realm-as-code (${what}): ${diffs.join("; ")}`);
  };
  const roleList = STAFF_ROLES.join(", ");
  checkFlow(STAFF_BROWSER_FLOW, `sign in, then deny any user without one of ${roleList}`);
  checkFlow(STAFF_RESET_FLOW, `the built-in reset credentials flow plus, at a client with ${STAFF_CHANNEL_SCOPE}, the deny of any user without one of ${roleList} after the e-mail step`);
  if (flows.some((f) => f.alias === STAFF_BROWSER_FLOW || f.alias === STAFF_RESET_FLOW)) {
    const realmRoles = new Set((realm.roles?.realm || []).map((r) => r.name));
    for (const r of STAFF_ROLES) {
      if (!realmRoles.has(r)) errs.add(`flow ${STAFF_BROWSER_FLOW}: realm role ${r} does not exist; Keycloak's role condition is then false for every user and the flow lets everyone through`);
    }
  }
  const reach = roleReach(realm);
  const staffReached = (seeds) => { const seen = reach(seeds); return STAFF_ROLES.filter((r) => seen.has(roleKey(null, r))); };
  const defaultRole = realm.defaultRole?.name ?? (realm.realm !== undefined ? `default-roles-${String(realm.realm).toLowerCase()}` : undefined);
  const roleDefs = [...(realm.roles?.realm || []), ...(realm.defaultRole?.name && !(realm.roles?.realm || []).some((r) => r.name === realm.defaultRole.name) ? [realm.defaultRole] : [])];
  for (const r of roleDefs) {
    for (const s of staffReached(compositesOf(r)).filter((x) => x !== r.name)) {
      errs.add(r.name === defaultRole
        ? `realm: default role ${r.name} reaches staff role ${s} through its composites; every user holds it, so the staff check lets every user through`
        : `realm role ${r.name} reaches staff role ${s} through its composites; staff roles come only from the /staff/fbx-* groups, and every user who holds ${r.name} passes the staff check`);
    }
  }
  // The legacy RealmRepresentation and ClientRepresentation key defaultRoles:
  // when the realm file has no defaultRole, Keycloak 26.7.5 adds those roles
  // (a client's: its client roles, created if missing) to the default role,
  // which every user holds (convertDeprecatedDefaultRoles), so the reach of
  // the default role above would miss them. Only a realm file carries the key
  // (Keycloak's export and admin API give defaultRole); it is refused.
  const legacy = "legacy key defaultRoles is not allowed: Keycloak adds these roles to the default role, which every user holds, so with a staff role among them every user passes the staff check; use defaultRole";
  if (Object.hasOwn(realm, "defaultRoles")) errs.add(`realm: ${legacy}`);
  for (const c of realm.clients || []) if (Object.hasOwn(c, "defaultRoles")) errs.add(`${c.clientId}: ${legacy}`);
  // Groups and users: the realm file only (the live views carry neither).
  const roleSeeds = (x) => [...(x.realmRoles || []).map((n) => [null, n]), ...Object.entries(x.clientRoles || {}).flatMap(([id, ns]) => (ns || []).map((n) => [id, n]))];
  const groupSeeds = new Map(); // path -> role seeds of the group and its parents
  const groupErrors = (gs, parent = "", inherited = []) => {
    for (const g of gs || []) {
      const p = g.path || `${parent}/${g.name}`;
      if (!/^\/staff\/fbx-[^/]+$/.test(p)) {
        for (const s of staffReached(roleSeeds(g))) errs.add(`group ${p} grants staff role ${s}, directly or through composites; staff roles come only from the /staff/fbx-* groups`);
      }
      groupSeeds.set(p, [...inherited, ...roleSeeds(g)]);
      groupErrors(g.subGroups, p, groupSeeds.get(p));
    }
  };
  groupErrors(realm.groups);
  // A user of the realm file is a local user, not one of the directory, so it
  // holds no staff role: not directly, not through composites, not through any
  // group or its parents (/staff/fbx-* included). Service accounts (users with
  // serviceAccountClientId) are left out: Keycloak's authentication refuses
  // them as browser users.
  for (const u of realm.users || []) {
    if (u.serviceAccountClientId) continue;
    const seeds = [...roleSeeds(u), ...(u.groups || []).flatMap((p) => groupSeeds.get(p) || [])];
    for (const s of staffReached(seeds)) errs.add(`user ${u.username} holds staff role ${s}, directly, through composites or through a group; staff roles come only from the directory's /staff/fbx-* groups, never from a realm-file user`);
  }
  if (realm.resetCredentialsFlow !== STAFF_RESET_FLOW) {
    errs.add(`realm: resetCredentialsFlow must be the flow ${STAFF_RESET_FLOW} (got ${JSON.stringify(realm.resetCredentialsFlow ?? "none")}); with another flow "forgot password" signs any user in to a staff channel client`);
  }
  // Jackson (Keycloak 26.7.5 and keycloak-config-cli 6.5.1) reads a JSON
  // string as a Boolean only after Java's trim (characters up to U+0020) and
  // only as true, True or TRUE, false, False or FALSE; any other spelling
  // ("tRue", "fAlse") fails the import. Only false, absent or a string Jackson
  // reads as false pass.
  const v = realm.registrationAllowed;
  if (!(v === false || v === undefined || (typeof v === "string" && ["false", "False", "FALSE"].includes(v.replace(/^[\x00-\x20]+|[\x00-\x20]+$/g, ""))))) {
    errs.add("realm: registrationAllowed must be false (self-registration signs the new user in to the client it started from, staff web included, without the staff check)");
  }
  for (const idp of realm.identityProviders || []) {
    errs.add(`realm: identity provider ${idp.alias} signs users in to any client without the staff check; this realm has none`);
  }
  const scope = (realm.clientScopes || []).find((x) => x.name === STAFF_CHANNEL_SCOPE);
  if (!scope) errs.add(`client scope ${STAFF_CHANNEL_SCOPE} missing (the reset flow runs its staff check for the clients that have it)`);
  else if ((scope.protocolMappers || []).length) errs.add(`client scope ${STAFF_CHANNEL_SCOPE}: must have no protocol mappers (it only marks the staff channel clients)`);
  const clients = new Map((realm.clients || []).map((c) => [c.clientId, c]));
  for (const entry of (registry.channelClients || []).filter((c) => c.userType === "staff")) {
    const c = clients.get(entry.clientId);
    if (!c) continue; // reported as missing by serviceClientErrors
    const v = c.authenticationFlowBindingOverrides?.browser;
    const target = v === undefined ? undefined : flows.find((f) => f.id !== undefined && f.id === v) || flows.find((f) => f.alias === v);
    if (target?.alias !== STAFF_BROWSER_FLOW || target.topLevel === false) {
      errs.add(`${c.clientId}: authenticationFlowBindingOverrides.browser must be the flow ${STAFF_BROWSER_FLOW} (got ${v === undefined ? "none" : JSON.stringify(v)}); without it any realm user, customers included, signs in to it`);
    }
    if (!(c.defaultClientScopes || []).includes(STAFF_CHANNEL_SCOPE)) {
      errs.add(`${c.clientId}: client scope ${STAFF_CHANNEL_SCOPE} must be a default scope (the reset flow's staff check runs only for clients that have it)`);
    }
    if (c.directAccessGrantsEnabled !== false) errs.add(`${c.clientId}: directAccessGrantsEnabled must be false (the direct grant flow has no staff check)`);
  }
  return [...errs];
}

export function serviceClientErrors(realm, registry) {
  const errors = [];
  const err = (m) => errors.push(m);
  const clients = new Map((realm.clients || []).map((c) => [c.clientId, c]));
  const scopedCallees = scopedCalleesOf(registry);
  const serviceIds = new Set(registry.clients.map((c) => c.clientId));
  const registered = new Set([...serviceIds, ...(registry.channelClients || []).map((c) => c.clientId), ...(registry.ssoClients || []).map((c) => c.clientId)]);

  // Each service, channel and staff SSO client: its audience mappers and
  // optional audience scopes are the registry's. A by-scope callee in its
  // registry audiences becomes the optional scope aud-<callee>, never a mapper.
  const channelIds = new Set((registry.channelClients || []).map((c) => c.clientId));
  const ssoIds = new Set((registry.ssoClients || []).map((c) => c.clientId));
  const kind = (id) => (ssoIds.has(id) ? "staff SSO" : channelIds.has(id) ? "channel" : "service");
  for (const entry of [...registry.clients, ...(registry.channelClients || []), ...(registry.ssoClients || [])]) {
    const c = clients.get(entry.clientId);
    if (!c) { err(`${kind(entry.clientId)} client ${entry.clientId} missing from realm`); continue; }
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
  // and only on the registry clients (service, channel or staff SSO) whose
  // registry audiences list the callee (compared above). fullScopeAllowed false on
  // every registry client and every client tagged fbx.client-type (runtime
  // TPP clients); Keycloak's built-in clients of a running realm are neither.
  // No client, built-ins included, enables standard token exchange or
  // Authorization Services (but Keycloak's admin-permissions).
  for (const c of clients.values()) {
    for (const a of scopedAudiences(c, scopedCallees)) err(`${c.clientId}: audience ${a} ${onlyVia(a)}, never through a mapper`);
    if (!registered.has(c.clientId) && audienceScopes(c).length) {
      err(`${c.clientId}: optional audience scopes ${audienceScopes(c).join(",")} are only for the registry clients (service, channel or staff SSO) whose registry audiences list the callee`);
    }
    for (const name of c.defaultClientScopes || []) if (AUDIENCE_SCOPE.test(name)) err(`${c.clientId}: audience scope ${name} must be optional, not default`);
    if (registered.has(c.clientId) || c.attributes?.["fbx.client-type"]) for (const m of fullScopeErrors(c)) err(m);
    for (const m of tokenExchangeErrors(c)) err(m);
    for (const m of authorizationServicesErrors(c)) err(m);
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
  // scopes included): a mapper that is not a stock Keycloak mapper, a mapper
  // writing claim aud, a hardcoded or renamed client role of a by-scope
  // callee (except on the callee's own client).
  for (const [label, holder, holderClientId] of [...[...clients.values()].map((c) => [c.clientId, c, c.clientId]), ...[...scopes.values()].map((s) => [`client scope ${s.name}`, s, undefined])]) {
    for (const m of holder.protocolMappers || []) {
      for (const r of [...notStockMapper(m), ...otherAudienceRoutes(m, scopedCallees, holderClientId)]) err(`${label}: ${r}`);
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

  // Who can obtain staff web's audiences (the ledger's among them): users who
  // hold a staff role at sign-in.
  for (const m of staffSignInErrors(realm, registry)) err(m);
  return errors;
}
