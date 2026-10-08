// Keycloak CR (deploy/kustomize/base/keycloak.yaml) options other repos rely on.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const crPath = path.join(root, "deploy/kustomize/base/keycloak.yaml");
const cr = YAML.parse(fs.readFileSync(crPath, "utf8"));
const option = (name) => (cr.spec.additionalOptions || []).find((o) => o.name === name);

// Observability alert KeycloakServiceAccountAdminEventOutOfScope (observability
// repo, Loki rule identity-admin-events) tells a user disable or a credential
// change from other user updates only through the event representation.
test("admin event lines carry the representation (observability admin-event alert)", () => {
  const o = option("spi-events-listener--jboss-logging--include-representation");
  assert.ok(o, "option spi-events-listener--jboss-logging--include-representation missing");
  assert.equal(o.value, "true");
});

test("the CR documents that representations can carry personal data", () => {
  const text = fs.readFileSync(crPath, "utf8");
  assert.match(text, /personal data[\s\S]{0,600}include-representation/i);
});

test("the jboss-logging success and error levels stay set", () => {
  assert.equal(option("spi-events-listener--jboss-logging--success-level")?.value, "info");
  assert.equal(option("spi-events-listener--jboss-logging--error-level")?.value, "warn");
});

// Aurora TLS (request-to-pay PR #14 review applies to Keycloak too):
// sslmode=require trusts any certificate. The mesh repo publishes ConfigMap
// rds-ca-bundle (key global-bundle.pem) in the identity namespace.
test("the Keycloak database connection verifies the server certificate", () => {
  assert.equal(option("db-url-properties")?.value, "?sslmode=verify-full&sslrootcert=/etc/fintechbankx/rds-ca/global-bundle.pem");
  const spec = cr.spec.unsupported.podTemplate.spec;
  assert.deepEqual(spec.volumes.find((v) => v.name === "database-ca"), {
    name: "database-ca",
    configMap: { name: "rds-ca-bundle", items: [{ key: "global-bundle.pem", path: "global-bundle.pem" }] }
  });
  assert.deepEqual(spec.containers[0].volumeMounts, [{ name: "database-ca", mountPath: "/etc/fintechbankx/rds-ca", readOnly: true }]);
});
