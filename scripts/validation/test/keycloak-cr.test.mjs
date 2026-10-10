// Keycloak CR (deploy/kustomize/base/keycloak.yaml) options other repos rely on.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
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

// Database TLS guardrail: the Keycloak CR carries exactly one sslmode, it is
// verify-full, and sslrootcert is the RDS CA bundle (ConfigMap rds-ca-bundle,
// key global-bundle.pem, from the mesh repo's trust-manager Bundle) at the
// path where the CR mounts it. The JDBC URL is the one the operator builds
// from spec.db (host, port, database) plus that db-url-properties option.
// Keycloak 26.7.5 also reads its options from the sources below. Each of them
// can set db-url, which replaces that URL and drops db-url-properties (pgjdbc
// then connects without TLS when the server declines it), so the check allows
// none of them for the Keycloak container:
// - spec.db.url, and every additionalOptions name the operator turns into a
//   KC_DB* env var (KC_ + upper case, non-alphanumerics to _: db_url, DB-URL)
//   except the one db-url-properties;
// - KC_DB* env vars in spec.env (the operator adds it to the container) or in
//   the pod template, any spelling; a KCKEY_* env var naming a db option (it
//   maps another KC_* variable to that option); KC_CONFIG_FILE or option
//   config-file; kc. system properties in env values (JAVA_OPTS_APPEND);
// - pod template args or command (CLI options such as --db-url), envFrom
//   (its variables are not visible here) and mounts over /opt/keycloak/conf
//   (keycloak.conf);
// - a jdbc: URL anywhere in the CR.
const RDS_CA_CONFIGMAP = "rds-ca-bundle";
const RDS_CA_KEY = "global-bundle.pem";
const KEYCLOAK_CONF_DIR = "/opt/keycloak/conf";
const PROTECTED_CR_PATHS = ["/spec/additionalOptions", "/spec/unsupported", "/spec/db/url", "/spec/env"];
const JVM_OPTIONS_ENV = /^(JAVA_OPTS.*|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)$/;

// Env var form of a Keycloak option or variable name: upper case, every
// non-alphanumeric character an underscore. The operator names the variable
// for an additionalOptions entry KC_ + this (getKeycloakOptionEnvVarName).
const envForm = (name) => String(name ?? "").replace(/[^A-Za-z0-9]/g, "_").toUpperCase();
const isDatabaseOption = (env) => /^KC_DB(_|$)/.test(env);
const pathsOverlap = (a, b) => {
  const [x, y] = [a, b].map((p) => String(p).replace(/\/+$/, ""));
  return x === y || x.startsWith(`${y}/`) || y.startsWith(`${x}/`);
};

// Path of the RDS CA bundle inside the Keycloak container, or null when the
// CR does not mount it. The operator merges the first podTemplate container
// with the Keycloak container.
function rdsCaPath(kc) {
  const pod = kc?.spec?.unsupported?.podTemplate?.spec;
  const volume = (pod?.volumes || []).find((v) => v.configMap?.name === RDS_CA_CONFIGMAP);
  if (!volume) return null;
  const items = volume.configMap.items;
  const file = items ? items.find((i) => i.key === RDS_CA_KEY)?.path : RDS_CA_KEY;
  const mount = (pod?.containers?.[0]?.volumeMounts || []).find((m) => m.name === volume.name);
  if (!file || !mount) return null;
  if (mount.subPath !== undefined) return mount.subPath === file ? mount.mountPath : null;
  return path.posix.join(mount.mountPath, file);
}

function databaseTlsProblems(kc) {
  const problems = [];
  // Parsed YAML: comments do not count, every value (patches, env, options) does.
  const text = JSON.stringify(kc);
  const sslmodeCount = (text.match(/sslmode/gi) || []).length;
  if (sslmodeCount !== 1) problems.push(`expected exactly one sslmode in the Keycloak CR, found ${sslmodeCount}`);
  if (/sslfactory|sslhostnameverifier/i.test(text)) problems.push("a custom sslfactory or sslhostnameverifier can skip certificate verification");
  if (/jdbc:/i.test(text)) problems.push("the Keycloak CR carries a JDBC URL; the operator builds it from spec.db host, port and database");
  if (kc?.spec?.db?.url !== undefined) problems.push("spec.db.url replaces the default JDBC URL and drops db-url-properties");
  const options = kc?.spec?.additionalOptions || [];
  for (const o of options) {
    const env = `KC_${envForm(o.name)}`;
    if (o.name === "db-url-properties") continue;
    if (isDatabaseOption(env)) problems.push(`additional option ${o.name} (${env}) must not be set: the operator sets the database options from spec.db, db-url-properties is the only other one`);
    if (env === "KC_CONFIG_FILE") problems.push(`additional option ${o.name} (${env}) points Keycloak at another configuration file`);
  }
  const pod = kc?.spec?.unsupported?.podTemplate?.spec;
  const envSources = [["spec.env", kc?.spec?.env], ...(pod?.containers || []).map((c, i) => [`podTemplate containers[${i}].env`, c.env])];
  for (const [where, envs] of envSources) {
    for (const e of envs || []) {
      const env = envForm(e.name);
      // Only a literal value can be checked; secret and valueFrom cannot.
      const literal = e.value === undefined || e.value === null ? undefined : String(e.value);
      if (isDatabaseOption(env)) problems.push(`${where} ${e.name} sets a database option outside spec.db`);
      if (env === "KC_CONFIG_FILE") problems.push(`${where} ${e.name} points Keycloak at another configuration file`);
      if (env.startsWith("KCKEY_")) {
        const target = `KC_${envForm(literal)}`;
        if (literal === undefined) problems.push(`${where} ${e.name} must be a literal value (it names the option KC_${env.slice(6)} sets)`);
        else if (isDatabaseOption(target)) problems.push(`${where} ${e.name} maps KC_${env.slice(6)} to the database option ${literal}`);
        else if (target === "KC_CONFIG_FILE") problems.push(`${where} ${e.name} maps KC_${env.slice(6)} to ${literal}, another configuration file`);
      }
      if (JVM_OPTIONS_ENV.test(env) && literal === undefined) problems.push(`${where} ${e.name} must be a literal value (JVM options can set kc. system properties)`);
      if (literal !== undefined && /-D(kc|quarkus)\./i.test(literal)) problems.push(`${where} ${e.name} sets a kc. or quarkus. system property`);
    }
  }
  const keycloakContainer = pod?.containers?.[0] || {};
  if ((keycloakContainer.args || []).length) problems.push("podTemplate args replace the operator's start command, and CLI options such as --db-url take precedence over the CR's options");
  if ((keycloakContainer.command || []).length) problems.push("podTemplate command replaces the operator's start command");
  if (keycloakContainer.envFrom !== undefined) problems.push("podTemplate envFrom on the Keycloak container can set KC_DB_URL, and its variables are not visible to this check");
  for (const m of keycloakContainer.volumeMounts || []) {
    if (pathsOverlap(m.mountPath, KEYCLOAK_CONF_DIR)) problems.push(`podTemplate mount at ${m.mountPath} replaces Keycloak's configuration files (${KEYCLOAK_CONF_DIR}/keycloak.conf can set db-url)`);
  }
  const props = options.filter((o) => `KC_${envForm(o.name)}` === "KC_DB_URL_PROPERTIES");
  if (props.length !== 1) {
    problems.push(`expected exactly one db-url-properties option, found ${props.length}`);
    return problems;
  }
  const value = props[0].value;
  if (typeof value !== "string" || !value.startsWith("?")) {
    problems.push("db-url-properties must be a literal query string starting with ?");
    return problems;
  }
  const query = new URLSearchParams(value.slice(1));
  const modes = query.getAll("sslmode");
  if (modes.length !== 1 || modes[0] !== "verify-full") problems.push(`sslmode must be exactly verify-full, found ${JSON.stringify(modes)}`);
  const ca = rdsCaPath(kc);
  if (!ca) problems.push(`ConfigMap ${RDS_CA_CONFIGMAP} key ${RDS_CA_KEY} is not mounted into the Keycloak container`);
  const roots = query.getAll("sslrootcert");
  if (roots.length !== 1 || roots[0] !== ca) problems.push(`sslrootcert must be exactly the mounted RDS CA bundle ${ca}, found ${JSON.stringify(roots)}`);
  return problems;
}

test("the Keycloak CR has exactly one sslmode, verify-full, with the mounted RDS CA bundle as sslrootcert", () => {
  assert.deepEqual(databaseTlsProblems(cr), []);
  assert.equal(rdsCaPath(cr), "/etc/fintechbankx/rds-ca/global-bundle.pem");
});

test("the database TLS check rejects anything but one sslmode=verify-full with the mounted bundle", () => {
  const props = (kc) => kc.spec.additionalOptions.find((o) => o.name === "db-url-properties");
  const pod = (kc) => kc.spec.unsupported.podTemplate.spec;
  const cases = {
    "sslmode=require": [(kc) => { props(kc).value = props(kc).value.replace("verify-full", "require"); }, /sslmode must be exactly verify-full/],
    "sslmode=verify-ca": [(kc) => { props(kc).value = props(kc).value.replace("verify-full", "verify-ca"); }, /sslmode must be exactly verify-full/],
    "no sslmode": [(kc) => { props(kc).value = "?sslrootcert=/etc/fintechbankx/rds-ca/global-bundle.pem"; }, /exactly one sslmode/],
    "a second sslmode": [(kc) => { props(kc).value += "&sslmode=require"; }, /exactly one sslmode/],
    "a second sslmode in another casing": [(kc) => { props(kc).value += "&sslMode=disable"; }, /exactly one sslmode/],
    "no sslrootcert": [(kc) => { props(kc).value = "?sslmode=verify-full"; }, /sslrootcert must be exactly/],
    "an sslrootcert outside the mount": [(kc) => { props(kc).value = "?sslmode=verify-full&sslrootcert=/opt/keycloak/rds.pem"; }, /sslrootcert must be exactly/],
    "a non-validating sslfactory": [(kc) => { props(kc).value += "&sslfactory=org.postgresql.ssl.NonValidatingFactory"; }, /sslfactory/],
    "the bundle volume removed": [(kc) => { pod(kc).volumes = []; }, /is not mounted/],
    "the bundle mount removed": [(kc) => { pod(kc).containers[0].volumeMounts = []; }, /is not mounted/],
    "another ConfigMap as the bundle": [(kc) => { pod(kc).volumes[0].configMap.name = "corporate-directory-ca"; }, /is not mounted/],
    "a second db-url-properties option": [(kc) => { kc.spec.additionalOptions.push({ name: "db-url-properties", value: "?ssl=true" }); }, /exactly one db-url-properties/],
    "db-url-properties from a Secret": [(kc) => { delete props(kc).value; props(kc).secret = { name: "x", key: "y" }; }, /literal query string/],
    "a full db-url option": [(kc) => { kc.spec.additionalOptions.push({ name: "db-url", value: "jdbc:postgresql://h:5432/d" }); }, /option db-url \(KC_DB_URL\) must not be set/],
    "spec.db.url": [(kc) => { kc.spec.db.url = "jdbc:postgresql://h:5432/d"; }, /spec\.db\.url/],
    "a KC_DB_URL_PROPERTIES env": [(kc) => { pod(kc).containers[0].env = [{ name: "KC_DB_URL_PROPERTIES", value: "?ssl=true" }]; }, /KC_DB_URL_PROPERTIES/],
    // The operator adds spec.env to the Keycloak container (addEnvVars).
    "KC_DB_URL in the CR's spec.env": [(kc) => { kc.spec.env = [{ name: "KC_DB_URL", value: "jdbc:postgresql://h:5432/d" }]; }, /spec\.env KC_DB_URL sets a database option/],
    "KC_DB_URL_PROPERTIES in spec.env from a Secret": [(kc) => { kc.spec.env = [{ name: "KC_DB_URL_PROPERTIES", secret: { name: "x", key: "y" } }]; }, /spec\.env KC_DB_URL_PROPERTIES sets a database option/],
    "a lower-case kc_db_url env": [(kc) => { pod(kc).containers[0].env = [{ name: "kc_db_url", valueFrom: { secretKeyRef: { name: "x", key: "y" } } }]; }, /kc_db_url sets a database option/],
    // The operator maps an option name to KC_ + upper case, non-alphanumerics
    // to _ (getKeycloakOptionEnvVarName): db_url and DB-URL become KC_DB_URL.
    "option db_url": [(kc) => { kc.spec.additionalOptions.push({ name: "db_url", value: "jdbc:postgresql://h:5432/d" }); }, /option db_url \(KC_DB_URL\) must not be set/],
    "option DB-URL from a Secret": [(kc) => { kc.spec.additionalOptions.push({ name: "DB-URL", secret: { name: "x", key: "y" } }); }, /option DB-URL \(KC_DB_URL\) must not be set/],
    "a second properties option spelled db_url_properties": [(kc) => { kc.spec.additionalOptions.unshift({ name: "db_url_properties", value: "?" }); }, /option db_url_properties \(KC_DB_URL_PROPERTIES\) must not be set/],
    // A KCKEY_FOO env (from envFrom, say) would map KC_FOO to db-url.
    "a JDBC URL in any field": [(kc) => { kc.spec.env = [{ name: "KC_FOO", value: "jdbc:postgresql://h:5432/d" }]; }, /carries a JDBC URL/],
    // podTemplate args replace the operator's "--verbose start"; CLI options
    // take precedence over every option the CR sets.
    "podTemplate args with --db-url": [(kc) => { pod(kc).containers[0].args = ["--verbose", "start", "--db-url=jdbc:postgresql://h:5432/d"]; }, /podTemplate args/],
    "any podTemplate args": [(kc) => { pod(kc).containers[0].args = ["--verbose", "start"]; }, /podTemplate args/],
    "a podTemplate command": [(kc) => { pod(kc).containers[0].command = ["/opt/keycloak/bin/kc.sh"]; }, /podTemplate command/],
    "a podTemplate envFrom": [(kc) => { pod(kc).containers[0].envFrom = [{ secretRef: { name: "x" } }]; }, /envFrom/],
    "a kc. system property in JAVA_OPTS_APPEND": [(kc) => { kc.spec.env = [{ name: "JAVA_OPTS_APPEND", value: "-Dkc.db-url-properties=?ssl=false" }]; }, /JAVA_OPTS_APPEND sets a kc\. or quarkus\. system property/],
    "JAVA_OPTS_APPEND from a Secret": [(kc) => { pod(kc).containers[0].env = [{ name: "JAVA_OPTS_APPEND", valueFrom: { secretKeyRef: { name: "x", key: "y" } } }]; }, /JAVA_OPTS_APPEND must be a literal value/],
    "a KCKEY_ env naming a database option": [(kc) => { kc.spec.env = [{ name: "KC_FOO", value: "x" }, { name: "KCKEY_FOO", value: "db-url" }]; }, /KCKEY_FOO maps KC_FOO to the database option db-url/],
    "a KCKEY_ env naming config-file": [(kc) => { pod(kc).containers[0].env = [{ name: "KCKEY_FOO", value: "config-file" }]; }, /KCKEY_FOO maps KC_FOO to config-file, another configuration file/],
    "a KCKEY_ env from a Secret": [(kc) => { kc.spec.env = [{ name: "KCKEY_FOO", secret: { name: "x", key: "y" } }]; }, /KCKEY_FOO must be a literal value/],
    "KC_CONFIG_FILE in spec.env": [(kc) => { kc.spec.env = [{ name: "KC_CONFIG_FILE", value: "/opt/keycloak/conf/other.conf" }]; }, /spec\.env KC_CONFIG_FILE points Keycloak at another configuration file/],
    "a config-file option": [(kc) => { kc.spec.additionalOptions.push({ name: "config-file", value: "/opt/keycloak/conf/other.conf" }); }, /option config-file \(KC_CONFIG_FILE\) points Keycloak at another configuration file/],
    "a mount over the Keycloak conf directory": [(kc) => { pod(kc).containers[0].volumeMounts.push({ name: "conf", mountPath: "/opt/keycloak/conf/" }); }, /mount at \/opt\/keycloak\/conf\/ replaces Keycloak's configuration files/],
    "a mount of keycloak.conf": [(kc) => { pod(kc).containers[0].volumeMounts.push({ name: "conf", mountPath: "/opt/keycloak/conf/keycloak.conf", subPath: "keycloak.conf" }); }, /mount at \/opt\/keycloak\/conf\/keycloak\.conf replaces Keycloak's configuration files/]
  };
  const missed = [];
  for (const [name, [mutate, expected]] of Object.entries(cases)) {
    const kc = structuredClone(cr);
    mutate(kc);
    const problems = databaseTlsProblems(kc);
    if (!problems.some((p) => expected.test(p))) missed.push(`${name}: expected a problem matching ${expected}, got ${JSON.stringify(problems)}`);
  }
  assert.deepEqual(missed, []);
});

// Local kustomization directories an overlay is built from (resources and
// components that are directories, recursively).
function kustomizationFiles(dir, seen = new Set()) {
  if (seen.has(dir)) return [];
  seen.add(dir);
  const file = path.join(dir, "kustomization.yaml");
  const k = YAML.parse(fs.readFileSync(file, "utf8"));
  const out = [{ dir, file, k }];
  for (const entry of [...(k.resources || []), ...(k.components || [])]) {
    if (/^[a-z]+:\/\//.test(entry)) continue;
    const p = path.resolve(dir, entry);
    if (fs.statSync(p).isDirectory()) out.push(...kustomizationFiles(p, seen));
  }
  return out;
}

const overlays = fs.readdirSync(path.join(root, "deploy/kustomize/overlays"));

test("no overlay or component patch rewrites the database options, the pod template or spec.db.url", () => {
  const touchesProtected = (p) =>
    p === "" || p === "/" || PROTECTED_CR_PATHS.some((x) => p === x || p.startsWith(`${x}/`) || x.startsWith(`${p.replace(/\/$/, "")}/`));
  for (const overlay of overlays) {
    for (const { dir, file, k } of kustomizationFiles(path.join(root, "deploy/kustomize/overlays", overlay))) {
      const where = `${overlay}: ${path.relative(root, file)}`;
      assert.equal(k.patchesJson6902, undefined, `${where} uses patchesJson6902; use patches`);
      assert.equal(k.patchesStrategicMerge, undefined, `${where} uses patchesStrategicMerge; use patches`);
      for (const patch of k.patches || []) {
        const body = YAML.parse(patch.patch ?? fs.readFileSync(path.join(dir, patch.path), "utf8"));
        const kind = patch.target?.kind ?? (Array.isArray(body) ? undefined : body?.kind);
        if (kind !== undefined && kind !== "Keycloak") continue;
        if (Array.isArray(body)) {
          for (const op of body) {
            for (const p of [op.path, op.from].filter((x) => x !== undefined)) {
              assert.ok(!touchesProtected(p), `${where}: patch ${op.op} ${p} on the Keycloak CR touches the database TLS settings`);
            }
          }
        } else {
          assert.equal(body?.spec?.additionalOptions, undefined, `${where}: patch sets spec.additionalOptions`);
          assert.equal(body?.spec?.unsupported, undefined, `${where}: patch sets spec.unsupported`);
          assert.equal(body?.spec?.db?.url, undefined, `${where}: patch sets spec.db.url`);
        }
      }
      for (const r of k.replacements || []) {
        for (const t of r.targets || []) {
          if (t.select?.kind !== undefined && t.select.kind !== "Keycloak") continue;
          for (const fp of t.fieldPaths || []) {
            const p = `/${fp.replace(/\./g, "/")}`;
            assert.ok(!touchesProtected(p), `${where}: replacement into ${fp} touches the database TLS settings`);
          }
        }
      }
    }
  }
});

test("the Keycloak package mentions sslmode and sslrootcert exactly once (the CR option)", () => {
  const counts = { sslmode: 0, sslrootcert: 0 };
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (/\.ya?ml$/.test(entry.name)) {
        for (const doc of YAML.parseAllDocuments(fs.readFileSync(p, "utf8"))) {
          const text = JSON.stringify(doc.toJS()) || "";
          counts.sslmode += (text.match(/sslmode/gi) || []).length;
          counts.sslrootcert += (text.match(/sslrootcert/gi) || []).length;
        }
      }
    }
  };
  walk(path.join(root, "deploy/kustomize"));
  assert.deepEqual(counts, { sslmode: 1, sslrootcert: 1 });
});

// Rendered overlays: runs where kustomize is on PATH. The manifests job sets
// FBX_REQUIRE_KUSTOMIZE=1 so a missing kustomize fails there instead of
// skipping; elsewhere the static checks above cover the overlays.
test("every overlay renders exactly one sslmode=verify-full with the mounted RDS CA bundle", (t) => {
  const probe = spawnSync("kustomize", ["version"], { encoding: "utf8" });
  if (probe.error) {
    assert.notEqual(process.env.FBX_REQUIRE_KUSTOMIZE, "1", "FBX_REQUIRE_KUSTOMIZE=1 but kustomize is not on PATH");
    t.skip("kustomize not on PATH");
    return;
  }
  for (const overlay of overlays) {
    const out = spawnSync("kustomize", ["build", path.join(root, "deploy/kustomize/overlays", overlay)], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    assert.equal(out.status, 0, `kustomize build ${overlay}: ${out.stderr}`);
    const keycloaks = YAML.parseAllDocuments(out.stdout).map((d) => d.toJS()).filter((d) => d?.kind === "Keycloak");
    assert.equal(keycloaks.length, 1, `${overlay} renders one Keycloak CR`);
    assert.deepEqual(databaseTlsProblems(keycloaks[0]), [], overlay);
    assert.equal(rdsCaPath(keycloaks[0]), "/etc/fintechbankx/rds-ca/global-bundle.pem", overlay);
  }
});

// docs/identity/KEYCLOAK_ON_EKS.md describes the same connection.
test("KEYCLOAK_ON_EKS.md states the database TLS the CR configures", () => {
  const doc = fs.readFileSync(path.join(root, "docs/identity/KEYCLOAK_ON_EKS.md"), "utf8");
  const ca = rdsCaPath(cr);
  assert.deepEqual(doc.match(/sslmode=[A-Za-z-]+/gi), ["sslmode=verify-full"], "the doc names exactly one sslmode, verify-full");
  const row = doc.split("\n").find((l) => l.startsWith("| Database |"));
  assert.ok(row, "Runtime shape table has a Database row");
  assert.match(row, /`sslmode=verify-full`/);
  assert.ok(row.includes(`sslrootcert=${ca}`), `the Database row names sslrootcert=${ca}`);
  assert.ok(row.includes(`\`${RDS_CA_CONFIGMAP}\``) && row.includes(`\`${RDS_CA_KEY}\``), "the Database row names the RDS CA ConfigMap and key");
  const prerequisites = doc.split("\n").find((l) => l.startsWith("1. Platform prerequisites"));
  assert.ok(prerequisites?.includes(`\`${RDS_CA_CONFIGMAP}\``), "install order step 1 lists the RDS CA bundle ConfigMap the Keycloak pods mount");
});
