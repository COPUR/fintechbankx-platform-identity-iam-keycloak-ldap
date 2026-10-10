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

// spec.db: the operator passes vendor, host, port and database through
// unescaped as the options db, db-url-host, db-url-port and db-url-database
// (KeycloakDistConfigurator.configureDatabase), and Keycloak builds
// jdbc:postgresql://<host>:<port>/<database><db-url-properties>. pgjdbc
// starts the query string at the first '?', so a '?' in host or database
// moves sslmode=verify-full into another parameter and the connection falls
// back to the default sslmode (prefer). The check requires vendor postgres,
// an integer port, a host made only of letters, digits, '.', '-' and '_',
// and a database name made only of letters, digits and '_' (so no '?', '&',
// '=', ';', '/', ':', '%', '$', whitespace or quotes). The overlays set host
// and database through ConfigMap identity-environment (data.databaseHost,
// data.databaseName), whose values get the same check.
const DB_HOST_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const DB_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const IDENTITY_ENVIRONMENT = "identity-environment";
const plainHostProblems = (value, field) =>
  typeof value === "string" && DB_HOST_PATTERN.test(value) ? [] : [`${field} must be a plain host name (letters, digits, '.', '-', '_'), found ${JSON.stringify(value)}`];
const plainDatabaseProblems = (value, field) =>
  typeof value === "string" && DB_NAME_PATTERN.test(value) ? [] : [`${field} must be a plain database name (letters, digits, '_'), found ${JSON.stringify(value)}`];
const environmentDatabaseProblems = (cm) => [
  ...plainHostProblems(cm?.data?.databaseHost, "data.databaseHost (spec.db.host)"),
  ...plainDatabaseProblems(cm?.data?.databaseName, "data.databaseName (spec.db.database)")
];

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
  const db = kc?.spec?.db || {};
  if (db.vendor !== "postgres") problems.push(`spec.db.vendor must be postgres, found ${JSON.stringify(db.vendor)}`);
  if (!Number.isInteger(db.port)) problems.push(`spec.db.port must be an integer, found ${JSON.stringify(db.port)}`);
  problems.push(...plainHostProblems(db.host, "spec.db.host"), ...plainDatabaseProblems(db.database, "spec.db.database"));
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
    "a mount of keycloak.conf": [(kc) => { pod(kc).containers[0].volumeMounts.push({ name: "conf", mountPath: "/opt/keycloak/conf/keycloak.conf", subPath: "keycloak.conf" }); }, /mount at \/opt\/keycloak\/conf\/keycloak\.conf replaces Keycloak's configuration files/],
    // pgjdbc starts the query string at the first '?' of the URL the
    // operator builds from spec.db, so db-url-properties no longer sets sslmode.
    "a '?' in spec.db.database": [(kc) => { kc.spec.db.database = "db_idn_keycloak_ldap_dev?"; }, /spec\.db\.database must be a plain database name/],
    "query parameters in spec.db.database": [(kc) => { kc.spec.db.database = "db_idn_keycloak_ldap_dev?connectTimeout=10&"; }, /spec\.db\.database must be a plain database name/],
    "a path in spec.db.database": [(kc) => { kc.spec.db.database = "db/x"; }, /spec\.db\.database must be a plain database name/],
    "whitespace in spec.db.database": [(kc) => { kc.spec.db.database = "db x"; }, /spec\.db\.database must be a plain database name/],
    "a quote in spec.db.database": [(kc) => { kc.spec.db.database = "db\""; }, /spec\.db\.database must be a plain database name/],
    "an expression in spec.db.database": [(kc) => { kc.spec.db.database = "${DB_NAME}"; }, /spec\.db\.database must be a plain database name/],
    "no spec.db.database": [(kc) => { delete kc.spec.db.database; }, /spec\.db\.database must be a plain database name/],
    "a '?' in spec.db.host": [(kc) => { kc.spec.db.host = "writer.example?sslmode=disable&"; }, /spec\.db\.host must be a plain host name/],
    "a port and path in spec.db.host": [(kc) => { kc.spec.db.host = "writer.example:5432/db"; }, /spec\.db\.host must be a plain host name/],
    "a ';' in spec.db.host": [(kc) => { kc.spec.db.host = "writer.example;x=y"; }, /spec\.db\.host must be a plain host name/],
    "no spec.db.host": [(kc) => { delete kc.spec.db.host; }, /spec\.db\.host must be a plain host name/],
    "spec.db.port as a string": [(kc) => { kc.spec.db.port = "5432/db?"; }, /spec\.db\.port must be an integer/],
    "spec.db.vendor other than postgres": [(kc) => { kc.spec.db.vendor = "mysql"; }, /spec\.db\.vendor must be postgres/]
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
    if (isRemote(entry)) continue; // reported by kustomizationPatchProblems
    const p = path.resolve(dir, entry);
    if (fs.statSync(p).isDirectory()) out.push(...kustomizationFiles(p, seen));
  }
  return out;
}

const overlays = fs.readdirSync(path.join(root, "deploy/kustomize/overlays"));

const touchesProtected = (p) =>
  p === "" || p === "/" || PROTECTED_CR_PATHS.some((x) => p === x || p.startsWith(`${x}/`) || x.startsWith(`${p.replace(/\/$/, "")}/`));

// kustomize selects the resources a patch applies to by the target's group,
// version, kind, name and namespace, each an anchored regular expression
// (api/types/selector.go), and by label and annotation selectors. A target
// may select the Keycloak CR unless one of these patterns cannot match it;
// namespace and the selectors are not evaluated, so they never exclude it.
// Replacement targets match exactly (kyaml resid IsSelectedBy).
const KEYCLOAK_ID = { group: "k8s.keycloak.org", version: "v2beta1", kind: "Keycloak", name: "keycloak" };
function targetMaySelectKeycloak(target) {
  return Object.entries(KEYCLOAK_ID).every(([field, value]) => {
    const pattern = target?.[field];
    if (pattern === undefined || pattern === null || pattern === "") return true;
    try {
      return new RegExp(`^(?:${pattern})$`).test(value);
    } catch {
      return true; // a Go (RE2) pattern JavaScript cannot compile: assume it matches
    }
  });
}
const replacementMaySelectKeycloak = (select) =>
  Object.entries(KEYCLOAK_ID).every(([field, value]) => !select?.[field] || select[field] === value);

// Paths a strategic-merge patch writes, replaces or deletes. $patch
// (replace, delete) and $retainKeys act on the map that holds them;
// $setElementOrder/<field> and $deleteFromPrimitiveList/<field> on <field>.
function smpTouchedPaths(node, at) {
  if (node === null || typeof node !== "object" || Array.isArray(node)) return [at];
  const out = [];
  for (const [key, value] of Object.entries(node)) {
    if (key === "$patch") {
      if (value !== "merge") out.push(at);
    } else if (key === "$retainKeys") out.push(at);
    else if (key.startsWith("$")) out.push(`${at}/${key.split("/").slice(1).join("/")}`.replace(/\/$/, ""));
    else out.push(...smpTouchedPaths(value, `${at}/${key}`));
  }
  return out;
}

const isRemote = (entry) => /^[a-z][a-z0-9+.-]*:\/\/|^git::|^git@|^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}\//i.test(entry);

// Patches, replacements and transformers in one kustomization that can reach
// the database TLS settings of the Keycloak CR, read without building it.
// load(relativePath) returns a file's text. This is a fast check for the
// realm job's npm test; the rendered check below, which the manifests job
// runs with FBX_REQUIRE_KUSTOMIZE=1, judges the built result.
function kustomizationPatchProblems(k, load) {
  const problems = [];
  if (k.patchesJson6902 !== undefined) problems.push("uses patchesJson6902; use patches");
  if (k.patchesStrategicMerge !== undefined) problems.push("uses patchesStrategicMerge; use patches");
  if (k.transformers !== undefined) problems.push("uses transformers, which this check does not read; use patches or replacements");
  for (const entry of [...(k.resources || []), ...(k.components || [])]) {
    if (isRemote(entry)) problems.push(`remote ${entry} cannot be checked without building it`);
  }
  for (const patch of k.patches || []) {
    const docs = YAML.parseAllDocuments(patch.patch ?? load(patch.path)).map((d) => d.toJS());
    if (docs.length === 1 && Array.isArray(docs[0])) {
      if (!targetMaySelectKeycloak(patch.target)) continue;
      for (const op of docs[0]) {
        for (const p of [op.path, op.from].filter((x) => x !== undefined)) {
          if (touchesProtected(p)) problems.push(`patch ${op.op} ${p} on the Keycloak CR touches the database TLS settings`);
        }
      }
      continue;
    }
    // Strategic merge: with a target, kustomize applies the patch to what the
    // target selects; without one, to the resource with the patch's own id.
    for (const body of docs) {
      if (patch.target ? !targetMaySelectKeycloak(patch.target) : body?.kind !== "Keycloak") continue;
      const { apiVersion, kind, metadata, ...rest } = body || {};
      for (const p of smpTouchedPaths(rest, "")) {
        if (touchesProtected(p)) problems.push(`strategic-merge patch on the Keycloak CR touches ${p || "the whole resource"}`);
      }
    }
  }
  for (const r of k.replacements || []) {
    const loaded = r.path === undefined ? [r] : [YAML.parse(load(r.path))].flat();
    for (const t of loaded.flatMap((x) => x?.targets || [])) {
      if (!replacementMaySelectKeycloak(t.select)) continue;
      for (const fp of t.fieldPaths || []) {
        const p = `/${fp.replace(/\./g, "/")}`;
        if (touchesProtected(p)) problems.push(`replacement into ${fp} touches the database TLS settings`);
      }
    }
  }
  return problems;
}

test("no overlay or component patch rewrites the database options, the pod template, spec.env or spec.db.url", () => {
  for (const overlay of overlays) {
    for (const { dir, file, k } of kustomizationFiles(path.join(root, "deploy/kustomize/overlays", overlay))) {
      const problems = kustomizationPatchProblems(k, (rel) => fs.readFileSync(path.join(dir, rel), "utf8"));
      assert.deepEqual(problems, [], `${overlay}: ${path.relative(root, file)}`);
    }
  }
});

test("the patch check finds every patch, replacement and transformer that can reach the Keycloak CR", () => {
  const remove0 = "- op: remove\n  path: /spec/additionalOptions/0\n";
  const smp = (spec, extra = "") => `apiVersion: k8s.keycloak.org/v2beta1\nkind: Keycloak\nmetadata:\n  name: keycloak\n${extra}spec:\n${spec}`;
  const replacementInto = (fieldPath) => ({
    source: { kind: "ConfigMap", name: "identity-environment", fieldPath: "data.databaseName" },
    targets: [{ select: { kind: "Keycloak", name: "keycloak" }, fieldPaths: [fieldPath] }]
  });
  const files = {
    "replacement-list.yaml": YAML.stringify([replacementInto("spec.additionalOptions.0.value")]),
    "replacement-one.yaml": YAML.stringify(replacementInto("spec.db.url")),
    "patch-file.yaml": remove0
  };
  const load = (rel) => {
    if (!(rel in files)) throw new Error(`no fixture ${rel}`);
    return files[rel];
  };
  // kustomize compiles target group, version, kind, name and namespace as
  // anchored regular expressions (api/types/selector.go).
  const flagged = {
    "JSON patch with target kind Keycloa.": { patches: [{ target: { kind: "Keycloa.", name: "keycloak" }, patch: remove0 }] },
    "JSON patch with target kind .*": { patches: [{ target: { kind: ".*" }, patch: remove0 }] },
    "JSON patch with target kind Keycloak|Secret": { patches: [{ target: { kind: "Keycloak|Secret", name: "keycloak" }, patch: remove0 }] },
    "JSON patch with target name key.* and no kind": { patches: [{ target: { name: "key.*" }, patch: remove0 }] },
    "JSON patch with only a label selector": { patches: [{ target: { labelSelector: "app.kubernetes.io/name=keycloak" }, patch: remove0 }] },
    "JSON patch from a file": { patches: [{ target: { kind: "Keycloak" }, path: "patch-file.yaml" }] },
    "JSON patch adding spec.env": { patches: [{ target: { kind: "Keycloak", name: "keycloak" }, patch: "- op: add\n  path: /spec/env\n  value: []\n" }] },
    "JSON patch replacing spec": { patches: [{ target: { kind: "Keycloak" }, patch: "- op: replace\n  path: /spec\n  value: {}\n" }] },
    "JSON patch moving into spec.unsupported": { patches: [{ target: { kind: "Keycloak" }, patch: "- op: move\n  from: /spec/tracing\n  path: /spec/unsupported\n" }] },
    "SMP with spec $patch: replace": { patches: [{ patch: smp("  $patch: replace\n  instances: 2\n") }] },
    "SMP with $patch: replace under target kind Keycloa.": { patches: [{ target: { kind: "Keycloa." }, patch: smp("  $patch: replace\n  instances: 2\n") }] },
    "SMP with $patch: delete on the CR": { patches: [{ patch: smp("  instances: 2\n", "$patch: delete\n") }] },
    "SMP with $retainKeys on spec": { patches: [{ patch: smp("  $retainKeys: [instances, db]\n  instances: 2\n") }] },
    "SMP with $setElementOrder on additionalOptions": { patches: [{ patch: smp("  $setElementOrder/additionalOptions:\n    - name: health-enabled\n") }] },
    "SMP deleting spec.db": { patches: [{ patch: smp("  db: null\n") }] },
    "SMP setting spec.db.url": { patches: [{ patch: smp("  db:\n    url: jdbc:postgresql://h:5432/d\n") }] },
    "SMP setting spec.env": { patches: [{ patch: smp("  env:\n    - name: KC_DB_URL\n      value: jdbc:postgresql://h:5432/d\n") }] },
    "SMP replacing the pod template": { patches: [{ patch: smp("  unsupported:\n    podTemplate:\n      $patch: replace\n") }] },
    "SMP as the second document of a patch": { patches: [{ patch: `apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\ndata: {}\n---\n${smp("  additionalOptions: []\n")}` }] },
    "replacement from a file holding a list": { replacements: [{ path: "replacement-list.yaml" }] },
    "replacement from a file holding one replacement": { replacements: [{ path: "replacement-one.yaml" }] },
    "inline replacement into spec.env": { replacements: [replacementInto("spec.env.0.value")] },
    "a transformers entry": { transformers: ["patch-transformer.yaml"] },
    "a remote component": { components: ["https://github.com/example/repo//component?ref=v1"] },
    "a remote resource": { resources: ["github.com/example/repo//base?ref=v1"] }
  };
  const clean = {
    "JSON patch on a PodDisruptionBudget": { patches: [{ target: { kind: "PodDisruptionBudget", name: "keycloak" }, patch: remove0 }] },
    "JSON patch with target kind Keycloak.+": { patches: [{ target: { kind: "Keycloak.+" }, patch: remove0 }] },
    "JSON patch with target name other": { patches: [{ target: { kind: "Keycloak", name: "other" }, patch: remove0 }] },
    "JSON patch on spec.instances": { patches: [{ target: { kind: "Keycloak", name: "keycloak" }, patch: "- op: replace\n  path: /spec/instances\n  value: 2\n" }] },
    "SMP $patch: replace on spec.hostname": { patches: [{ patch: smp("  hostname:\n    $patch: replace\n    hostname: https://IDENTITY_HOST\n") }] },
    "SMP on spec.db.poolMaxSize": { patches: [{ patch: smp("  db:\n    poolMaxSize: 40\n") }] },
    "replacement into a Secret": { replacements: [{ source: { kind: "ConfigMap", name: "x", fieldPath: "data.y" }, targets: [{ select: { kind: "Secret" }, fieldPaths: ["data.additionalOptions"] }] }] },
    "local resources and components": { resources: ["../../base", "extra.yaml"], components: ["../../components/environment"] }
  };
  const missed = [];
  for (const [name, k] of Object.entries(flagged)) {
    let problems;
    try { problems = kustomizationPatchProblems(k, load); } catch (e) { problems = [`threw ${e.message}`]; }
    if (problems.length === 0 || problems.some((p) => p.startsWith("threw "))) missed.push(`${name}: expected a problem, got ${JSON.stringify(problems)}`);
  }
  for (const [name, k] of Object.entries(clean)) {
    let problems;
    try { problems = kustomizationPatchProblems(k, load); } catch (e) { problems = [`threw ${e.message}`]; }
    if (problems.length !== 0) missed.push(`${name}: expected no problem, got ${JSON.stringify(problems)}`);
  }
  assert.deepEqual(missed, []);
});

// The overlays set spec.db.host and spec.db.database through
// identity-environment (data.databaseHost, data.databaseName), which
// components/environment copies into the CR.
function identityEnvironments(overlay) {
  const found = [];
  for (const { dir, k } of kustomizationFiles(path.join(root, "deploy/kustomize/overlays", overlay))) {
    for (const entry of k.resources || []) {
      if (isRemote(entry)) continue;
      const p = path.resolve(dir, entry);
      if (fs.statSync(p).isDirectory()) continue;
      for (const doc of YAML.parseAllDocuments(fs.readFileSync(p, "utf8")).map((d) => d.toJS())) {
        if (doc?.kind === "ConfigMap" && doc?.metadata?.name === IDENTITY_ENVIRONMENT) found.push(doc);
      }
    }
  }
  return found;
}

test("every overlay feeds spec.db a plain host and database name through identity-environment", () => {
  for (const overlay of overlays) {
    const found = identityEnvironments(overlay);
    assert.equal(found.length, 1, `${overlay} has exactly one ConfigMap ${IDENTITY_ENVIRONMENT}`);
    assert.deepEqual(environmentDatabaseProblems(found[0]), [], overlay);
  }
});

test("the identity-environment check rejects anything but a plain host and database name", () => {
  const env = (data) => ({ apiVersion: "v1", kind: "ConfigMap", metadata: { name: IDENTITY_ENVIRONMENT }, data });
  const host = "fbx-dev-identity-keycloak.cluster-x.me-central-1.rds.amazonaws.com";
  assert.deepEqual(environmentDatabaseProblems(env({ databaseHost: host, databaseName: "db_idn_keycloak_ldap_dev" })), []);
  const cases = {
    "a '?' in databaseName": [env({ databaseHost: host, databaseName: "db_idn_keycloak_ldap_dev?" }), /databaseName \(spec\.db\.database\) must be a plain database name/],
    "query parameters in databaseName": [env({ databaseHost: host, databaseName: "db_idn_keycloak_ldap_dev?connectTimeout=10&" }), /databaseName/],
    "no databaseName": [env({ databaseHost: host }), /databaseName/],
    "a '?' in databaseHost": [env({ databaseHost: `${host}?sslmode=disable&`, databaseName: "db" }), /databaseHost \(spec\.db\.host\) must be a plain host name/],
    "a '/' in databaseHost": [env({ databaseHost: `${host}/db`, databaseName: "db" }), /databaseHost/],
    "a quote in databaseHost": [env({ databaseHost: `'${host}'`, databaseName: "db" }), /databaseHost/],
    "no data": [env(undefined), /databaseHost/]
  };
  const missed = [];
  for (const [name, [cm, expected]] of Object.entries(cases)) {
    const problems = environmentDatabaseProblems(cm);
    if (!problems.some((p) => expected.test(p))) missed.push(`${name}: expected a problem matching ${expected}, got ${JSON.stringify(problems)}`);
  }
  assert.deepEqual(missed, []);
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
// skipping. This is the check that decides: the static patch check above
// reads patches, replacements and the CR source without applying them, and
// in the realm job's npm test (no kustomize) it is the only overlay check.
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
