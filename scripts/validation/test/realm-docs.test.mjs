// Decisions recorded in the identity docs. The residual risk of
// svc-cus-profile-kyc's manage-members on /customers was answered by the
// project owner on 2026-10-10 (decision card "Decide how to handle the
// customer service's power to change customer e-mails in Keycloak", option
// "Accept for now"). The acceptance is narrow: e-mail and name changes only.
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

// The **Residual risk:** paragraph and, when present, the **Owner decision**
// paragraph that follows it.
const residualRisk = () => {
  const start = realmDoc.indexOf("**Residual risk:**");
  assert.ok(start >= 0, "REALM_AS_CODE.md has no **Residual risk:** paragraph");
  let end = realmDoc.indexOf("\n\n", start);
  if (end >= 0 && realmDoc.startsWith("**Owner decision", end + 2)) end = realmDoc.indexOf("\n\n", end + 2);
  return realmDoc.slice(start, end < 0 ? undefined : end);
};

test("no document still calls the customer-service residual risk a pending user decision", () => {
  for (const file of markdownFiles(root)) {
    const text = fs.readFileSync(file, "utf8");
    assert.doesNotMatch(text, /user decision, not done/i, `${path.relative(root, file)} still says the decision is pending`);
  }
});

test("the residual risk records the owner's acceptance with its date and source", () => {
  assert.match(residualRisk(), /accepted for now by the project owner \(decision card, 2026-10-10\)/);
});

test("the acceptance covers e-mail and name changes only; everything else still alerts", () => {
  const text = residualRisk();
  assert.match(text, /e-mail/i);
  assert.match(text, /name/i);
  for (const still of ["credential", "required action", "disable", "delete", "log", "role", "group", "outside `/customers`"]) {
    assert.ok(text.toLowerCase().includes(still.toLowerCase()), `residual risk does not say that ${still} still alerts`);
  }
  assert.match(text, /still alert/i);
});

test("the remaining manage-members sign-off card stays open and no security-team sign-off is claimed", () => {
  const text = residualRisk();
  assert.match(text, /2026-10-08[^.]*Keycloak permission[^.]*stays open|Keycloak permission[^.]*2026-10-08[^.]*stays open/);
  assert.doesNotMatch(text, /security[- ]team (has )?(signed|approved|accepted)/i);
  assert.doesNotMatch(text, /signed off by/i);
});
