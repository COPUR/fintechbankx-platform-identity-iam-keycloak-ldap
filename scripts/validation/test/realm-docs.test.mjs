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

test("the manage-members residual risk is accepted until go-live only, with the identity-link service as a go-live item", () => {
  const text = paragraph("Owner decision (accepted until go-live");
  assert.match(text, /accepted until go-live by the project owner/);
  assert.match(text, /2026-10-19/);
  assert.match(text, /"Accept until go-live"/);
  assert.match(text, /does not extend to production/);
  assert.match(text, /identity-link service[^.]*must replace[^.]*`manage-members`/);
  assert.match(text, /Go-live item/);
  assert.match(text, /not a security-team sign-off/);
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

// The README overview counts the service clients of the registry.
test("README.md counts every service client of the registry", () => {
  const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
  const counts = [...readme.matchAll(/(\d+) service clients/g)].map((m) => Number(m[1]));
  assert.ok(counts.length > 0, "README.md has no \"N service clients\"");
  for (const n of counts) assert.equal(n, registry.clients.length, "README.md service client count");
});

// Who can obtain staff web's ledger audience: only users who hold a staff
// role at sign-in (DevSecOps 2026-10-17): staff web's browser flow
// fbx-staff-browser denies every other user after sign-in, an SSO session
// from the customer web client included; the gate checks the flow in all
// three modes and in the import Job.
test("REALM_AS_CODE.md says staff web signs in only users who hold a staff role at sign-in, and lists gap 5 as checked", () => {
  const ledger = realmDoc.split("\n").find((l) => l.trim().startsWith("The accounts ledger audience reaches"));
  assert.ok(ledger, "no ledger audience paragraph");
  assert.doesNotMatch(ledger, /any realm user, customers included, can sign in/);
  assert.match(ledger, /only users who hold a staff role at sign-in[^.]*`fintechbankx-staff-web`|`fintechbankx-staff-web`[^.]*only users who hold a staff role at sign-in/);
  assert.match(ledger, /`fbx-staff-browser`/);
  assert.match(ledger, /role scope[^.]*`@PreAuthorize`/);
  const line = realmDoc.split("\n").find((l) => l.includes("Known gap, not checked"));
  const checked = line.slice(line.indexOf("Checked since 2026-10-17"), line.indexOf("Known gap, not checked"));
  const open = line.slice(line.indexOf("Known gap, not checked"));
  assert.match(checked, /\(5\)[^.]*`fintechbankx-staff-web`[^.]*`fbx-staff-browser`/);
  assert.doesNotMatch(open, /\(5\)/);
  // Forgot password reaches staff web through the realm's reset flow.
  assert.match(checked, /"Forgot password"[^.]*reset credentials flow[^.]*no client override reaches/);
  assert.match(checked, /`fbx-reset-credentials`[^.]*`fbx-staff-channel`/);
});

// onboard-tpp.mjs --verify-live always runs the service-client rules; --registry only picks the file.
test("REALM_AS_CODE.md: --verify-live always runs the service-client rules, with the default registry", () => {
  const row = realmDoc.split("\n").find((l) => l.startsWith("| `scripts/realm/onboard-tpp.mjs` |"));
  assert.ok(row, "no onboard-tpp.mjs row");
  assert.doesNotMatch(row, /and, with `--registry`, the service-client rules/);
  assert.match(row, /the TPP rules and the service-client rules \(registry from `--registry`, default `realm\/service-clients\.json`/);
  assert.match(paragraph("Live drift check."), /checked statically only/);
});

// Review findings on gap (5), 2026-10-17. The staff check runs in the sign-in
// and reset flows only: Keycloak 26.7.5's refresh grant runs no flow and
// checks no role, so a banker removed from /staff/fbx-banker kept refreshing
// staff web tokens with the ledger audience until the client session ended.
// prompt=none answers with a redirect carrying error=login_required, not a
// 401. The page before the reset e-mail is the same for every username; the
// response time is not (the built-in step sends the mail before it answers).
const gap5 = () => {
  const line = realmDoc.split("\n").find((l) => l.includes("Known gap, not checked"));
  return line.slice(line.indexOf("(5) Who signs in to staff web"), line.indexOf("Known gap, not checked"));
};

test("REALM_AS_CODE.md gap (5): staff role at sign-in only, refresh does not check roles again, and a removal from a staff group logs the user out", () => {
  const text = gap5();
  assert.match(text, /users who hold a staff role at sign-in/);
  assert.doesNotMatch(text, /Only users with a staff role/);
  assert.match(text, /refresh[^.]*does not check roles again/);
  // The window follows staff web's client session limits in the realm file.
  const realm = JSON.parse(fs.readFileSync(path.join(root, "realm/fintechbankx-realm.json"), "utf8"));
  const attrs = realm.clients.find((c) => c.clientId === "fintechbankx-staff-web").attributes;
  assert.equal(attrs["client.session.max.lifespan"], "28800");
  assert.equal(attrs["client.session.idle.timeout"], "900");
  assert.match(text, /8 hours at most[^.]*15 minutes idle/);
  assert.match(text, /`POST \/admin\/realms\/<realm>\/users\/\{id\}\/logout`/);
  assert.match(text, /or disable the user/);
});

// Review finding (major, docs): gap (5) said a user removed from a staff group
// keeps only an existing staff web session until it ends. For a removal in
// the directory that is wrong: the LDAP provider (cachePolicy DEFAULT) keeps
// the cached group membership until the next changed-users sync or another
// eviction, new sign-ins pass the staff check meanwhile, and each session
// refreshes for up to 8 hours. An LDAP-only change never calls Keycloak.
const ldapConfig = () => JSON.parse(fs.readFileSync(path.join(root, "realm/fintechbankx-realm.json"), "utf8"))
  .components["org.keycloak.storage.UserStorageProvider"].find((c) => c.providerId === "ldap").config;
const comments = (file) => fs.readFileSync(path.join(root, file), "utf8").replace(/\n\s*\/\/ ?/g, " ");

test("REALM_AS_CODE.md gap (5): a staff group removed in the directory reaches Keycloak only after the cached membership is evicted; offboarding logs out or disables the user in Keycloak", () => {
  const cfg = ldapConfig();
  assert.deepEqual([cfg.cachePolicy, cfg.changedSyncPeriod, cfg.fullSyncPeriod], [["DEFAULT"], ["900"], ["86400"]]);
  const text = gap5();
  assert.doesNotMatch(text, /removed from a staff group keeps getting new staff web tokens[^.]*until that client session ends/);
  assert.match(text, /`cachePolicy` `DEFAULT`, `changedSyncPeriod` 900 s\) keeps the user's cached group membership until the next changed-users sync or another eviction/);
  assert.match(text, /new sign-ins still pass the staff check and get staff web tokens[^.]*refreshable for up to 8 hours/);
  assert.match(text, /exposure is up to about 8 hours plus that window/);
  assert.match(text, /`fullSyncPeriod` 86400 s/);
  assert.match(text, /An LDAP-only change never calls Keycloak, so the offboarding step[^.]*must log out the user's sessions in Keycloak \(`POST \/admin\/realms\/<realm>\/users\/\{id\}\/logout`\) or disable the user/);
  const rules = comments("scripts/realm/service-client-rules.mjs");
  assert.doesNotMatch(rules, /a user removed from a staff group keeps refreshing an existing staff web session until it ends/);
  assert.match(rules, /keeps the cached membership until the next changed-users sync or another eviction/);
  assert.match(rules, /must log the user out or disable them in Keycloak/);
});

// Review finding (major): the LDAP mapper allow-list is a static guarantee;
// --live and --live-export do not read user storage providers.
test("REALM_AS_CODE.md says the LDAP provider and its mappers are checked statically only, and names the refused role and group mappers", () => {
  const text = gap5();
  for (const m of ["`hardcoded-ldap-role-mapper`", "`role-ldap-mapper`", "`hardcoded-ldap-group-mapper`", "`groups.path` `/staff`", "`groups.ldap.filter` `(cn=fbx-*)`"]) {
    assert.ok(text.includes(m), `gap (5) does not name ${m}`);
  }
  assert.match(text, /LDAP mapper integrity is a static guarantee only: `--live` and `--live-export` do not read the LDAP provider/);
  assert.match(text, /legacy key `defaultRoles`/);
  assert.match(text, /realm-file user/);
  assert.match(paragraph("Live drift check."), /the LDAP provider and its mappers \(neither form reads user storage providers\)[^.]*checked statically only/);
});

// Review findings (minor): GET .../authentication/flows leaves out saml ecp
// and a partial export lists orphan flows and configs; a flow aliased . or ..
// cannot be read through the admin API.
test("REALM_AS_CODE.md: the Live drift check names saml ecp, orphans, the . and .. aliases and the export's alias limit", () => {
  const text = paragraph("Live drift check.");
  assert.doesNotMatch(text, /executions` of every top-level flow with each subflow/);
  assert.match(text, /`saml ecp` included \(`\.\.\.\/authentication\/flows` leaves it out\)/);
  assert.match(text, /aliased `\.` or `\.\.`[^.]*error/);
  assert.match(text, /orphan/);
  assert.match(text, /shares its alias[^.]*fails `--live-export` only/);
  assert.doesNotMatch(gap5(), /a config alias used twice anywhere in the realm/);
});

test("REALM_AS_CODE.md: prompt=none answers error=login_required, and only the page before the reset e-mail is the same for every username", () => {
  const text = gap5();
  assert.match(text, /`prompt=none`[^.]*`error=login_required`/);
  assert.match(text, /plain cookie visit[^.]*401/);
  assert.match(text, /page before the e-mail is the same for every username/);
  assert.match(text, /answers more slowly when it sends a mail/);
  const rules = fs.readFileSync(path.join(root, "scripts/realm/service-client-rules.mjs"), "utf8");
  for (const [name, body] of [...markdownFiles(path.join(root, "docs")).map((f) => [path.relative(root, f), fs.readFileSync(f, "utf8")]), ["service-client-rules.mjs", rules]]) {
    assert.doesNotMatch(body.replace(/\n\/\/ ?/g, " "), /(answer|response) before the e-mail is the same for every username/, name);
    for (const sentence of sentences(body.replace(/\n\/\/ ?/g, " "))) {
      if (/prompt=none/.test(sentence) && /\b401\b/.test(sentence)) assert.match(sentence, /login_required/, `${name}: ${sentence}`);
    }
  }
});

test("REALM_AS_CODE.md: the Live drift check paragraph names what --live and --live-export read now, and the credential a CronJob would need", () => {
  const text = paragraph("Live drift check.");
  for (const k of ["`authenticationFlows`", "`resetCredentialsFlow`", "`registrationAllowed`", "`identityProviders`", "`defaultRole`", "composites",
    ".../roles`", ".../roles-by-id/<id>/composites`", ".../authentication/flows`", ".../authentication/flows/<alias>/executions`", ".../authentication/flows/<id>`",
    ".../authentication/config/<id>`", ".../identity-provider/instances`", "staff sign-in rule", "`view-clients`", "`view-realm`", "`view-identity-providers`"]) {
    assert.ok(text.includes(k), `the Live drift check paragraph does not name ${k}`);
  }
  assert.doesNotMatch(text, /probably `view-realm`/);
});
