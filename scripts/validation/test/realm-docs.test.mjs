// Decisions recorded in the identity docs. The residual risk of
// svc-cus-profile-kyc's manage-members on /customers was answered by the
// project owner on 2026-10-10 (decision card "Decide how to handle the
// customer service's power to change customer e-mails in Keycloak", option
// "Accept for now"). The acceptance is narrow: e-mail and name changes only.
// The alert's allow-list also lets username, emailVerified and attributes
// through; the doc must name those as not covered by the decision.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const realmDoc = fs.readFileSync(path.join(root, "docs/identity/REALM_AS_CODE.md"), "utf8");

function markdownFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...markdownFiles(p));
    else if (entry.name.endsWith(".md")) out.push(p);
  }
  return out;
}

// One paragraph of REALM_AS_CODE.md, found by its bold lead-in.
const paragraph = (lead) => {
  const start = realmDoc.indexOf(`**${lead}`);
  assert.ok(start >= 0, `REALM_AS_CODE.md has no **${lead}** paragraph`);
  const end = realmDoc.indexOf("\n\n", start);
  return realmDoc.slice(start, end < 0 ? undefined : end);
};

// The **Residual risk:** paragraph and the decision paragraphs that follow it.
const residualRisk = () =>
  [paragraph("Residual risk:"), paragraph("Owner decision"), paragraph("Not covered by the owner decision")].join("\n\n");

const sentences = (text) => text.split(/(?<=\.)\s+/);

// Changes the owner did NOT accept; the acceptance sentence must name none of them.
const NOT_ACCEPTED = /password|credential reset|disable|delete|log ?out|required action|role|group|username|emailVerified|attribute|outside/i;

test("no document still calls the customer-service residual risk a pending user decision", () => {
  for (const file of markdownFiles(root)) {
    const text = fs.readFileSync(file, "utf8");
    assert.doesNotMatch(text, /user decision, not done/i, `${path.relative(root, file)} still says the decision is pending`);
  }
});

test("the residual risk records the owner's acceptance with its date and source", () => {
  assert.match(residualRisk(), /accepted for now by the project owner \(decision card, 2026-10-10\)/);
});

test("the acceptance sentence names e-mail and the name fields only", () => {
  const scope = sentences(paragraph("Owner decision")).filter((x) => x.startsWith("Scope:"));
  assert.equal(scope.length, 1, "the owner decision has exactly one Scope: sentence");
  assert.match(scope[0], /e-mail/);
  assert.match(scope[0], /`firstName`/);
  assert.match(scope[0], /`lastName`/);
  assert.doesNotMatch(scope[0], NOT_ACCEPTED, "the Scope: sentence names a change the owner did not accept");
});

test("no sentence of the owner decision accepts anything beyond e-mail and names", () => {
  for (const s of sentences(paragraph("Owner decision"))) {
    if (!/\baccept/i.test(s) || /\bnot\b/.test(s)) continue;
    assert.doesNotMatch(s, NOT_ACCEPTED, `sentence accepts more than e-mail and names: ${s}`);
  }
});

test("the owner decision says every other change still alerts and is not accepted", () => {
  const negation = sentences(paragraph("Owner decision")).filter((s) => /does (\*\*)?not(\*\*)? accept/.test(s));
  assert.equal(negation.length, 1, "the owner decision has exactly one 'does not accept' sentence");
  const [text] = negation;
  for (const still of ["credential reset", "disable", "delete", "logout", "required action", "role", "group", "outside `/customers`"]) {
    assert.ok(text.includes(still), `the 'does not accept' sentence does not name ${still}`);
  }
  assert.match(text, /: those still alert\.$/);
});

test("the keys the alert also lets through are named and left open, not presented as accepted", () => {
  const risk = paragraph("Residual risk:");
  for (const key of ["`username`", "`email`", "`firstName`", "`lastName`", "`emailVerified`", "`attributes`"]) {
    assert.ok(risk.includes(key), `the residual risk does not say the alert lets ${key} through`);
  }
  assert.doesNotMatch(risk, /except the identity-link update and the e-mail and name changes/);
  const open = paragraph("Not covered by the owner decision");
  for (const key of ["`username`", "`emailVerified`", "`attributes`", "`verifyEmail: true`"]) {
    assert.ok(open.includes(key), `the not-covered paragraph does not name ${key}`);
  }
  assert.match(open, /new e-mail together with `emailVerified: true`/);
  assert.match(open, /without an alert/);
  assert.match(open, /2026-10-08[^.]*stays open/);
});

test("the remaining manage-members sign-off card stays open and no security-team sign-off is claimed", () => {
  const text = residualRisk();
  assert.match(text, /2026-10-08[^.]*Keycloak permission[^.]*stays open|Keycloak permission[^.]*2026-10-08[^.]*stays open/);
  assert.doesNotMatch(text, /security[- ]team (has )?(signed|approved|accepted)/i);
  assert.doesNotMatch(text, /signed off by/i);
});

// Counts and lists in REALM_AS_CODE.md follow the client registry
// (realm/service-clients.json) and the realm import ExternalSecret.
const registry = JSON.parse(fs.readFileSync(path.join(root, "realm/service-clients.json"), "utf8"));

test("REALM_AS_CODE.md counts and names every service client of the registry", () => {
  const m = realmDoc.match(/\*\*(\d+) confidential service clients\*\* \(([^)]*)\)/);
  assert.ok(m, "REALM_AS_CODE.md has no **N confidential service clients** (list) item");
  assert.equal(Number(m[1]), registry.clients.length, "service client count");
  const named = [...m[2].matchAll(/`([^`]+)`/g)].map((x) => x[1]);
  for (const { clientId } of registry.clients) {
    const covered = named.some((n) => (n.endsWith("*") ? clientId.startsWith(n.slice(0, -1)) : n === clientId));
    assert.ok(covered, `${clientId} is not named in the service client list`);
  }
});

test("REALM_AS_CODE.md counts the client credentials of the realm import ExternalSecret", () => {
  const es = fs.readFileSync(path.join(root, "deploy/kustomize/base/realm-import/externalsecret.yaml"), "utf8");
  const credentials = (es.match(/secretKey: FBX_OIDC_SECRET_/g) || []).length;
  assert.equal(credentials, registry.clients.length + (registry.ssoClients || []).length, "one ExternalSecret entry per service and staff SSO client");
  const m = realmDoc.match(/ExternalSecret `keycloak-realm-import` \(admin client, LDAP bind, (\d+) client credentials/);
  assert.ok(m, "REALM_AS_CODE.md does not count the import Job's client credentials");
  assert.equal(Number(m[1]), credentials);
});

// The audience table of REALM_AS_CODE.md has one row per calling service
// client naming exactly its registry audiences (service ids in backticks).
test("the REALM_AS_CODE.md audience table names exactly the registry audiences of each calling service client", () => {
  const rows = new Map(realmDoc.split("\n")
    .map((l) => l.match(/^\s*\| `(svc-[a-z0-9-]+)` \| (.*) \|\s*$/))
    .filter(Boolean)
    .map((m) => [m[1], m[2]]));
  for (const c of registry.clients.filter((x) => x.audiences.length > 0)) {
    assert.ok(rows.has(c.clientId), `the audience table has no row for ${c.clientId}`);
    const named = [...rows.get(c.clientId).matchAll(/`(svc-[a-z0-9-]+)`/g)].map((x) => x[1]).sort();
    assert.deepEqual(named, [...c.audiences].sort(), `${c.clientId} row`);
  }
});
