#!/usr/bin/env node
// Onboards open-finance TPP clients into realm fintechbankx through the
// Keycloak admin API. Identity owns TPP onboarding (REALM_AS_CODE.md); this is
// the only runtime path: Dynamic Client Registration is closed (client policy
// fbx-dynamic-client-registration-closed).
//
// Each TPP client is built from the realm template of-tpp-conformance-template
// (realm/fintechbankx-realm.json), so it always carries
//   - attribute fbx.client-type=open-finance-tpp and fbx.tpp.token-binding=dpop,
//   - client scope fbx-client-type-open-finance-tpp as a default scope (the
//     access-token claim fbx_client_type=open-finance-tpp),
//   - client scope payments as an optional scope only when the TPP is
//     authorised for payment services (with the authorisation reference).
// The spec names the TPP only (client id, name, redirect URIs, JWKS, payment
// authorisation, status); it cannot set scopes or attributes.
//
// status (active | suspended, default active) decides the enabled flag, never
// the template:
//   - suspended: the client is disabled, its notBefore is set to now on the
//     transition from enabled, or on the first sync of a client an operator
//     already disabled in the console while its notBefore is still 0 or
//     missing (refresh and offline tokens issued before are rejected), and
//     every user holding a session or offline token of the client has it
//     revoked (DELETE /users/{id}/consents/{clientId}: consent, offline token
//     and that client's sessions only; the user's other sessions are kept).
//   - active: an existing client keeps the enabled flag Keycloak holds. A
//     client an operator disabled stays disabled and is reported ("listed
//     active but disabled in Keycloak"); only the create path enables, after
//     verification.
// POST /clients/{id}/push-revocation is not used: it only pushes the client's
// notBefore to the client's admin URL, which TPP clients do not have.
//
// Safe to re-run: a client is looked up by clientId and updated in place; its
// default and optional scopes are reconciled to the exact lists; nothing else
// is deleted. Refuses before any write when the client would break the rules
// of scripts/realm/tpp-rules.mjs, and refuses to retype an existing client of
// another type. A new client is created disabled, updated once (so Keycloak's
// client policies for open-finance-tpp, which only match an existing client,
// check it), given its scopes, verified, and only then enabled; if any step
// fails it is deleted again (a spec listed suspended is created and left
// disabled).
//
// usage: node onboard-tpp.mjs (--tpp <spec.json> | --tpps <list.json>) [--realm <realm.json>] [--dry-run] [--verify-live [--registry <service-clients.json>]]
//   list.json: {"tpps": [spec, ...]}
//   --verify-live: afterwards, fail when the running realm breaks the TPP
//                  rules or the service-client rules with the registry
//                  (--registry, default realm/service-clients.json next to
//                  this script's repository; the same check as
//                  check-realm.mjs --live, through live-view.mjs); with
//                  --tpps (the complete list) also fail when an enabled
//                  open-finance-tpp client is not listed or a listed-suspended
//                  client is enabled, and warn when a listed-active client is
//                  disabled
// env: KEYCLOAK_URL and the KEYCLOAK_* credential variables of
//      apply-admin-permissions.mjs (the realm import Job's bootstrap admin client).
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { fetchAdminToken } from "./apply-admin-permissions.mjs";
import { PAYMENTS_SCOPE, TPP_CLIENT_TYPE, TPP_CLIENT_TYPE_SCOPE, tppClientErrors } from "./tpp-rules.mjs";
import { fetchLiveView, liveRealmErrors } from "./live-view.mjs";

export const TEMPLATE_CLIENT_ID = "of-tpp-conformance-template";
const SPEC_FIELDS = ["clientId", "name", "redirectUris", "jwksUri", "jwks", "paymentServices", "status"];
export const TPP_STATUSES = ["active", "suspended"];
const CLIENT_ID = /^of-tpp-[a-z0-9]+(-[a-z0-9]+)*$/;
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"];
const httpsUrl = (u) => {
  if (typeof u !== "string" || u.includes("*") || u.includes("#")) return false;
  try { return new URL(u).protocol === "https:"; } catch { return false; }
};

export function validateTppSpec(spec) {
  const errors = [];
  const e = (m) => errors.push(m);
  for (const [k, v] of Object.entries(spec || {})) {
    if (v !== undefined && !SPEC_FIELDS.includes(k)) e(`unknown field ${k} (scopes and attributes are set by identity, not by the spec)`);
  }
  const id = spec?.clientId;
  if (typeof id !== "string" || !CLIENT_ID.test(id) || id.length > 64) e("clientId must match of-tpp-<kebab> (max 64 characters)");
  else if (id === TEMPLATE_CLIENT_ID) e(`clientId ${id} is the realm template`);
  if (typeof spec?.name !== "string" || !spec.name.trim()) e("name is required");
  if (!Array.isArray(spec?.redirectUris) || spec.redirectUris.length === 0) e("redirectUris must list at least one URI");
  for (const u of spec?.redirectUris || []) if (!httpsUrl(u)) e(`redirect URI ${u} must be an absolute https URL without wildcard or fragment`);
  const hasUri = spec?.jwksUri !== undefined;
  const hasSet = spec?.jwks !== undefined;
  if (hasUri === hasSet) e("give exactly one of jwksUri or jwks");
  if (hasUri && !httpsUrl(spec.jwksUri)) e("jwksUri must be an absolute https URL");
  if (hasSet) {
    const keys = spec.jwks?.keys;
    if (!Array.isArray(keys) || keys.length === 0) e("jwks must be a JWK set with at least one key");
    (keys || []).forEach((k, i) => {
      for (const m of PRIVATE_JWK_MEMBERS) if (k && m in k) e(`jwks key ${i} carries private key member ${m}`);
    });
  }
  const pay = spec?.paymentServices;
  if (pay !== undefined) {
    if (typeof pay !== "object" || typeof pay.authorised !== "boolean") e("paymentServices.authorised must be true or false");
    else if (pay.authorised && !(typeof pay.reference === "string" && pay.reference.trim())) e("paymentServices.reference is required when payment services are authorised");
  }
  if (spec?.status !== undefined && !TPP_STATUSES.includes(spec.status)) e("status must be active or suspended (default active)");
  return errors;
}

export const paymentsAuthorisedOf = (spec) => spec?.paymentServices?.authorised === true;
export const statusOf = (spec) => spec?.status ?? "active";
const disabledWarning = (id) => `${id}: listed active but disabled in Keycloak; leaving disabled — set status in Git`;

// Client representation for one TPP, from the realm template.
export function buildTppClient({ template, spec }) {
  const errors = validateTppSpec(spec);
  if (errors.length) throw new Error(`refusing to build TPP client ${spec?.clientId}: ${errors.join("; ")}`);
  const payments = paymentsAuthorisedOf(spec);
  const c = structuredClone(template);
  delete c.id;
  c.clientId = spec.clientId;
  c.name = spec.name;
  c.description = `Open-finance TPP client, onboarded by the identity platform (scripts/realm/onboard-tpp.mjs) from ${TEMPLATE_CLIENT_ID}. Payment services: ${payments ? `authorised (${spec.paymentServices.reference})` : "not authorised"}.`;
  c.enabled = statusOf(spec) === "active";
  c.redirectUris = [...spec.redirectUris];
  const a = { ...c.attributes };
  delete a["jwks.url"];
  delete a["jwks.string"];
  delete a["fbx.tpp.payment-services-reference"];
  if (spec.jwksUri !== undefined) {
    Object.assign(a, { "use.jwks.url": "true", "jwks.url": spec.jwksUri });
    delete a["use.jwks.string"];
  } else {
    Object.assign(a, { "use.jwks.url": "false", "use.jwks.string": "true", "jwks.string": JSON.stringify(spec.jwks) });
  }
  if (payments) a["fbx.tpp.payment-services-reference"] = spec.paymentServices.reference;
  c.attributes = a;
  c.protocolMappers = (template.protocolMappers || []).map(({ id, ...m }) => structuredClone(m));
  c.defaultClientScopes = [...(template.defaultClientScopes || [])];
  c.optionalClientScopes = payments ? [PAYMENTS_SCOPE] : [];
  return c;
}

function adminApi({ fetch, baseUrl, token, realm }) {
  const R = `${String(baseUrl).replace(/\/+$/, "")}/admin/realms/${encodeURIComponent(realm)}`;
  const call = async (method, url, body) => {
    const headers = { Authorization: `Bearer ${token}`, Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text();
    if (!res.ok) throw new Error(`${method} ${url} -> ${res.status}${text ? ` ${text.slice(0, 200)}` : ""}`);
    return { json: text ? JSON.parse(text) : undefined, location: res.headers.get("location") };
  };
  return { R, call };
}

// Every user holding a session (online or offline) of the client, paged.
async function sessionUsers(call, R, uuid, pageSize = 100) {
  const users = new Set();
  for (const kind of ["user-sessions", "offline-sessions"]) {
    for (let first = 0; ; first += pageSize) {
      const page = (await call("GET", `${R}/clients/${uuid}/${kind}?first=${first}&max=${pageSize}`)).json || [];
      for (const s of page) if (s.userId) users.add(s.userId);
      if (page.length < pageSize) break;
    }
  }
  return [...users].sort();
}

export async function onboardTpp({ fetch = globalThis.fetch, baseUrl, token, realm, client, paymentsAuthorised, status = "active", log = () => {}, warn = log }) {
  const id = client.clientId;
  if (!TPP_STATUSES.includes(status)) throw new Error(`refusing to onboard ${id}: status must be active or suspended`);
  const refused = tppClientErrors(client, { paymentsAuthorised });
  if (refused.length) throw new Error(`refusing to onboard ${id}: ${refused.join("; ")}`);
  const { R, call } = adminApi({ fetch, baseUrl, token, realm });

  // Resolve before the first write, so a realm without the scopes changes nothing.
  const scopeIds = new Map(((await call("GET", `${R}/client-scopes`)).json || []).map((s) => [s.name, s.id]));
  for (const s of [...client.defaultClientScopes, ...client.optionalClientScopes]) {
    if (!scopeIds.has(s)) throw new Error(`client scope ${s} not found in realm ${realm}; import the realm first`);
  }
  const existing = ((await call("GET", `${R}/clients?clientId=${encodeURIComponent(id)}`)).json || []).find((c) => c.clientId === id);
  if (existing && existing.attributes?.["fbx.client-type"] !== TPP_CLIENT_TYPE) {
    throw new Error(`${id} exists with fbx.client-type=${existing.attributes?.["fbx.client-type"]}; refusing to change its type`);
  }

  let uuid = existing?.id;
  const action = existing ? "updated" : "created";
  const suspended = status === "suspended";
  // Enabled flag of an existing client: suspended disables it; active keeps
  // what Keycloak holds (an operator's disable is honoured, and flagged).
  const enabled = existing ? !suspended && existing.enabled !== false : !suspended;
  const revokedUsers = [];
  try {
    if (existing) {
      const update = { ...client, id: uuid, enabled };
      // Tokens issued before the suspension are rejected from now on. Set on the
      // transition from enabled, and on a client an operator already disabled in
      // the console whose notBefore is still unset (0 or missing), so the
      // break-glass path gets it too; a re-run does not move it.
      if (suspended && (existing.enabled !== false || !(existing.notBefore > 0))) update.notBefore = Math.floor(Date.now() / 1000);
      await call("PUT", `${R}/clients/${uuid}`, update);
      if (!suspended && existing.enabled === false) warn(disabledWarning(id));
      if (suspended) {
        for (const userId of await sessionUsers(call, R, uuid)) {
          try {
            await call("DELETE", `${R}/users/${encodeURIComponent(userId)}/consents/${encodeURIComponent(id)}`);
            revokedUsers.push(userId);
          } catch (e) {
            // 404: the user holds neither a consent nor an offline token of the
            // client; the disabled client and notBefore already stop its tokens.
            if (!/ -> 404\b/.test(e.message)) throw e;
          }
        }
      }
    } else {
      const created = await call("POST", `${R}/clients`, { ...client, enabled: false });
      uuid = created.location?.split("/").pop()
        || ((await call("GET", `${R}/clients?clientId=${encodeURIComponent(id)}`)).json || []).find((c) => c.clientId === id)?.id;
      // Keycloak's client policies for open-finance-tpp match existing clients only.
      await call("PUT", `${R}/clients/${uuid}`, { ...client, id: uuid, enabled: false });
    }

    // Exact default and optional scope lists; removals first, so payments is
    // never default and optional at once.
    const scopeChanges = [];
    const lists = { default: client.defaultClientScopes, optional: client.optionalClientScopes };
    const current = {};
    for (const kind of Object.keys(lists)) current[kind] = ((await call("GET", `${R}/clients/${uuid}/${kind}-client-scopes`)).json || []).map((s) => s.name);
    for (const kind of Object.keys(lists)) {
      for (const name of current[kind].filter((n) => !lists[kind].includes(n))) {
        await call("DELETE", `${R}/clients/${uuid}/${kind}-client-scopes/${scopeIds.get(name) ?? encodeURIComponent(name)}`);
        scopeChanges.push(`${kind} -${name}`);
      }
    }
    for (const kind of Object.keys(lists)) {
      for (const name of lists[kind].filter((n) => !current[kind].includes(n))) {
        await call("PUT", `${R}/clients/${uuid}/${kind}-client-scopes/${scopeIds.get(name)}`);
        scopeChanges.push(`${kind} +${name}`);
      }
    }

    // Verify what Keycloak now holds, then enable a new client.
    const stored = (await call("GET", `${R}/clients/${uuid}`)).json;
    const names = async (kind) => ((await call("GET", `${R}/clients/${uuid}/${kind}-client-scopes`)).json || []).map((s) => s.name);
    const verified = { ...stored, defaultClientScopes: await names("default"), optionalClientScopes: await names("optional") };
    const drift = tppClientErrors(verified, { paymentsAuthorised });
    if (drift.length) throw new Error(`verification failed: ${drift.join("; ")}`);
    if (!existing && enabled) await call("PUT", `${R}/clients/${uuid}`, { ...client, id: uuid, enabled: true });
    const notes = [...scopeChanges, ...(suspended ? [`suspended: disabled${revokedUsers.length ? `, sessions of ${revokedUsers.length} user(s) revoked` : ""}`] : [])];
    log(`${id}: ${action}${notes.length ? ` (${notes.join(", ")})` : ""}`);
    return { clientId: id, id: uuid, action, status, enabled, scopeChanges, revokedUsers };
  } catch (e) {
    if (!existing && uuid) {
      await call("DELETE", `${R}/clients/${uuid}`).catch(() => {});
      throw new Error(`${id}: ${e.message}; the new client was deleted again (rolled back)`);
    }
    throw new Error(`${id}: ${e.message}`);
  }
}

// Listing check for --verify-live against the complete list (realm/tpp-clients.json).
// errors: an enabled open-finance-tpp client that is not listed (created
// outside Git, or removed from the list without being suspended first), a
// listed-suspended client that is enabled. warnings: a listed-active client
// that is disabled (an operator's disable is honoured, but Git should say so).
export function tppListingFindings(clients, specs) {
  const listed = new Map((specs || []).map((s) => [s.clientId, statusOf(s)]));
  const errors = [];
  const warnings = [];
  for (const c of clients || []) {
    if (c.attributes?.["fbx.client-type"] !== TPP_CLIENT_TYPE) continue;
    const status = listed.get(c.clientId);
    const enabled = c.enabled !== false;
    if (!status && enabled) errors.push(`${c.clientId}: enabled open-finance-tpp client not listed in realm/tpp-clients.json (add it, or disable and off-board it)`);
    else if (status === "suspended" && enabled) errors.push(`${c.clientId}: listed suspended in realm/tpp-clients.json but enabled in Keycloak`);
    else if (status === "active" && !enabled) warnings.push(disabledWarning(c.clientId));
  }
  return { errors, warnings };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const arg = (n) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : undefined; };
  const out = (m) => console.log(`onboard-tpp: ${m}`);
  try {
    const realmPath = arg("--realm") || path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../realm/fintechbankx-realm.json");
    const realm = JSON.parse(fs.readFileSync(realmPath, "utf8"));
    const template = (realm.clients || []).find((c) => c.clientId === TEMPLATE_CLIENT_ID);
    if (!template) throw new Error(`${TEMPLATE_CLIENT_ID} not found in ${path.basename(realmPath)}`);
    // Read before any write, so a missing registry changes nothing.
    const verifyLive = process.argv.includes("--verify-live");
    const registry = verifyLive ? JSON.parse(fs.readFileSync(arg("--registry") || path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../realm/service-clients.json"), "utf8")) : undefined;
    let specs;
    if (arg("--tpp")) specs = [JSON.parse(fs.readFileSync(arg("--tpp"), "utf8"))];
    else if (arg("--tpps")) specs = JSON.parse(fs.readFileSync(arg("--tpps"), "utf8")).tpps || [];
    else throw new Error("usage: onboard-tpp.mjs (--tpp <spec.json> | --tpps <list.json>) [--realm <realm.json>] [--dry-run] [--verify-live [--registry <service-clients.json>]]");
    const ids = specs.map((s) => s?.clientId);
    const dup = ids.find((x, i) => ids.indexOf(x) !== i);
    if (dup) throw new Error(`refusing: clientId ${dup} listed twice`);
    // Every spec is checked before the first write.
    const built = specs.map((spec) => ({ spec, client: buildTppClient({ template, spec }) }));
    if (process.argv.includes("--dry-run")) {
      console.log(JSON.stringify(arg("--tpp") ? built[0].client : built.map((b) => b.client), null, 2));
      process.exit(0);
    }
    const token = await fetchAdminToken();
    const failures = [];
    for (const { spec, client } of built) {
      try {
        await onboardTpp({ baseUrl: process.env.KEYCLOAK_URL, token, realm: realm.realm, client, paymentsAuthorised: paymentsAuthorisedOf(spec), status: statusOf(spec), log: out, warn: (m) => console.warn(`onboard-tpp: WARNING ${m}`) });
      } catch (e) {
        failures.push(e.message);
        console.error(`onboard-tpp: ${e.message}`);
      }
    }
    if (verifyLive) {
      const view = await fetchLiveView({ baseUrl: process.env.KEYCLOAK_URL, token, realm: realm.realm, registry });
      const { clients } = view;
      const errors = liveRealmErrors(view, registry);
      // The listing check needs the complete list, so only with --tpps.
      if (arg("--tpps")) {
        const listing = tppListingFindings(clients, specs);
        errors.push(...listing.errors);
        for (const w of listing.warnings) console.warn(`onboard-tpp: live: WARNING ${w}`);
      }
      for (const e of errors) console.error(`onboard-tpp: live: ${e}`);
      if (errors.length) failures.push(`${errors.length} live problem(s)`);
      else out(`live check OK (${clients.length} clients, ${clients.filter((c) => c.attributes?.["fbx.client-type"] === TPP_CLIENT_TYPE).length} open-finance-tpp, ${registry.clients.length} service clients)`);
    }
    if (failures.length) {
      console.error(`onboard-tpp: FAILED (${failures.length})`);
      process.exit(1);
    }
    out(`OK (${built.length} TPP client(s) in realm ${realm.realm})`);
  } catch (e) {
    console.error(`onboard-tpp: ${e.message}`);
    process.exit(1);
  }
}
