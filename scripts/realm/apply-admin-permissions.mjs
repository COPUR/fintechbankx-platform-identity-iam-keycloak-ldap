#!/usr/bin/env node
// Applies the fine-grained admin permissions (Keycloak 26 FGAP v2) listed in
// realm/admin-permissions.json to a running Keycloak. keycloak-config-cli
// 6.5.1 skips the system-managed admin-permissions client, so this runs as
// the second step of the realm import Job, after config-cli has created the
// realm (adminPermissionsEnabled: true), the clients and the groups.
//
// Idempotent: clients are looked up by clientId, groups by path, policies and
// permissions by exact name; an existing policy or permission is updated in
// place (PUT), a missing one is created (POST). Nothing is ever deleted.
// No dependencies beyond Node 22 (global fetch).
//
// usage: node apply-admin-permissions.mjs --spec <admin-permissions.json>
// env:   KEYCLOAK_URL, KEYCLOAK_LOGINREALM (default master),
//        KEYCLOAK_GRANTTYPE client_credentials (default) with
//        KEYCLOAK_CLIENTID + KEYCLOAK_CLIENTSECRET, or password with
//        KEYCLOAK_USER + KEYCLOAK_PASSWORD (+ KEYCLOAK_CLIENTID, default admin-cli)
//        - the same variables keycloak-config-cli reads.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const trimSlash = (u) => String(u || "").replace(/\/+$/, "");
const enc = encodeURIComponent;

export async function fetchAdminToken({ fetch = globalThis.fetch, env = process.env } = {}) {
  const base = trimSlash(env.KEYCLOAK_URL);
  if (!base) throw new Error("KEYCLOAK_URL is required");
  const grant = env.KEYCLOAK_GRANTTYPE || "client_credentials";
  const form = new URLSearchParams({ grant_type: grant });
  if (grant === "client_credentials") {
    if (!env.KEYCLOAK_CLIENTID || !env.KEYCLOAK_CLIENTSECRET) throw new Error("KEYCLOAK_CLIENTID and KEYCLOAK_CLIENTSECRET are required for client_credentials");
    form.set("client_id", env.KEYCLOAK_CLIENTID);
    form.set("client_secret", env.KEYCLOAK_CLIENTSECRET);
  } else if (grant === "password") {
    if (!env.KEYCLOAK_USER || !env.KEYCLOAK_PASSWORD) throw new Error("KEYCLOAK_USER and KEYCLOAK_PASSWORD are required for the password grant");
    form.set("client_id", env.KEYCLOAK_CLIENTID || "admin-cli");
    if (env.KEYCLOAK_CLIENTSECRET) form.set("client_secret", env.KEYCLOAK_CLIENTSECRET);
    form.set("username", env.KEYCLOAK_USER);
    form.set("password", env.KEYCLOAK_PASSWORD);
  } else {
    throw new Error(`KEYCLOAK_GRANTTYPE ${grant} is not supported`);
  }
  const realm = env.KEYCLOAK_LOGINREALM || "master";
  const url = `${base}/realms/${enc(realm)}/protocol/openid-connect/token`;
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: form.toString() });
  if (!res.ok) throw new Error(`POST ${url} -> ${res.status}`);
  const body = await res.json();
  if (!body.access_token) throw new Error(`POST ${url}: no access_token in the response`);
  return body.access_token;
}

export async function applyAdminPermissions({ fetch = globalThis.fetch, baseUrl, token, spec, log = () => {} }) {
  const R = `${trimSlash(baseUrl)}/admin/realms/${enc(spec.realm)}`;
  const call = async (method, url, body) => {
    const headers = { Authorization: `Bearer ${token}`, Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const res = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text();
    return { status: res.status, ok: res.ok, json: text ? JSON.parse(text) : undefined };
  };
  const get = async (url, notFound) => {
    const r = await call("GET", url);
    if (r.status === 404 && notFound) throw new Error(notFound);
    if (!r.ok) throw new Error(`GET ${url} -> ${r.status}`);
    return r.json;
  };
  const write = async (method, url, body) => {
    const r = await call(method, url, body);
    if (!r.ok) throw new Error(`${method} ${url} -> ${r.status}`);
    return r.json;
  };
  const clientUuid = async (clientId, hint) => {
    const found = (await get(`${R}/clients?clientId=${enc(clientId)}`)) || [];
    const c = found.find((x) => x.clientId === clientId);
    if (!c) throw new Error(hint || `client ${clientId} not found in realm ${spec.realm}`);
    return c.id;
  };

  // Resolve everything before the first write, so a bad spec changes nothing.
  const ap = await clientUuid("admin-permissions", `realm ${spec.realm} has no admin-permissions client; set adminPermissionsEnabled: true (Keycloak 26.2+ FGAP v2) and import the realm first`);
  const RS = `${R}/clients/${ap}/authz/resource-server`;
  const plan = [];
  for (const p of spec.permissions) {
    const clients = [];
    for (const id of p.policy.clients) clients.push(await clientUuid(id));
    const resources = [];
    for (const gp of p.groupPaths) {
      const g = await get(`${R}/group-by-path/${gp.replace(/^\//, "").split("/").map(enc).join("/")}`, `group ${gp} not found in realm ${spec.realm}`);
      resources.push(g.id);
    }
    plan.push({ p, clients, resources });
  }

  const findByName = async (name, type) => {
    const list = (await get(`${RS}/policy?name=${enc(name)}&first=0&max=100`)) || [];
    const hit = list.find((x) => x.name === name);
    if (hit && hit.type !== type) throw new Error(`${name} exists with type ${hit.type}, expected ${type}; fix it by hand`);
    return hit;
  };
  const upsert = async (kind, typePath, type, rep) => {
    const existing = await findByName(rep.name, type);
    if (existing) {
      await write("PUT", `${RS}/${typePath}/${existing.id}`, { id: existing.id, ...rep });
      log(`${kind} ${rep.name}: updated`);
      return { kind, name: rep.name, action: "updated", id: existing.id };
    }
    const created = await write("POST", `${RS}/${typePath}`, rep);
    log(`${kind} ${rep.name}: created`);
    return { kind, name: rep.name, action: "created", id: created?.id };
  };

  const results = [];
  const policyIds = new Map();
  for (const { p, clients, resources } of plan) {
    if (!policyIds.has(p.policy.name)) {
      const r = await upsert("policy", "policy/client", "client", {
        name: p.policy.name,
        description: `Client policy: service account of ${p.policy.clients.join(", ")} (fine-grained admin permissions v2).`,
        type: "client",
        logic: p.policy.logic || "POSITIVE",
        decisionStrategy: "UNANIMOUS",
        clients
      });
      results.push(r);
      policyIds.set(p.policy.name, r.id);
    }
    results.push(await upsert("permission", "permission/scope", "scope", {
      name: p.name,
      description: p.description,
      type: "scope",
      logic: "POSITIVE",
      decisionStrategy: p.decisionStrategy,
      resourceType: p.resourceType,
      resources,
      scopes: p.scopes,
      policies: [policyIds.get(p.policy.name)]
    }));
  }
  return results;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const i = process.argv.indexOf("--spec");
  if (i < 0 || !process.argv[i + 1]) {
    console.error("usage: apply-admin-permissions.mjs --spec <admin-permissions.json>");
    process.exit(2);
  }
  try {
    const spec = JSON.parse(fs.readFileSync(process.argv[i + 1], "utf8"));
    const token = await fetchAdminToken();
    const results = await applyAdminPermissions({ baseUrl: process.env.KEYCLOAK_URL, token, spec, log: (m) => console.log(`admin-permissions: ${m}`) });
    console.log(`admin-permissions: OK (${results.length} object(s) in realm ${spec.realm})`);
  } catch (e) {
    console.error(`admin-permissions: FAILED: ${e.message}`);
    process.exit(1);
  }
}
