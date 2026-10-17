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
// - env values it cannot read as written (see JAVA_ARGS_ENV): "$(" anywhere
//   in the CR, and quotes or backslashes in the variables kc.sh or the JVM
//   turns into java arguments and in KCKEY_*;
// - pod template args or command (CLI options such as --db-url), envFrom
//   (its variables are not visible here) and mounts over /opt/keycloak/conf
//   (keycloak.conf);
// - a jdbc: URL anywhere in the CR.
const RDS_CA_CONFIGMAP = "rds-ca-bundle";
const RDS_CA_KEY = "global-bundle.pem";
const KEYCLOAK_CONF_DIR = "/opt/keycloak/conf";
const PROTECTED_CR_PATHS = ["/spec/additionalOptions", "/spec/unsupported", "/spec/db", "/spec/env"];

// Env values. The operator passes spec.env, additionalOptions and the CR's
// first-class options to the Keycloak container as env values, and
// Kubernetes expands $(VAR) in an env value from the variables defined before
// it, which can come from a Secret. So no value in the CR may contain "$("
// (this also refuses the escaped "$$("). kc.sh (26.7.5) builds the java
// command line from JAVA_OPTS, JAVA_OPTS_KC_HEAP, JAVA_ADD_OPENS, JAVA_LOCALE,
// JAVA_OPTS_APPEND and, in debug mode (KC_DEBUG or DEBUG), the debug port and
// suspend values (KC_DEBUG_PORT or DEBUG_PORT, KC_DEBUG_SUSPEND or
// DEBUG_SUSPEND); it splits them with xargs, which removes quotes and
// backslashes, and runs JAVA (default JAVA_HOME/bin/java) through eval. The
// JVM splits JAVA_TOOL_OPTIONS, JDK_JAVA_OPTIONS and _JAVA_OPTIONS and
// removes quotes. These variables and KCKEY_* must be literal values without
// a quote (' or ") or backslash, so the -Dkc. / -Dquarkus. and jdbc: checks
// read the text Java gets. Not checked: options a JVM argument loads from a
// file (@argfiles, -XX:VMOptionsFile, -XX:Flags).
const JAVA_ARGS_ENV = /^(JAVA|JAVA_HOME|JAVA_OPTS.*|JAVA_ADD_OPENS|JAVA_LOCALE|(KC_)?DEBUG(_PORT|_SUSPEND)?|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)$/;

// Env names the Keycloak container may set, matched case-sensitively as Linux
// does: Keycloak options (KC_*, checked above as database options and config
// files), KCKEY_* (value checked) and the JAVA_ARGS_ENV names (value checked).
// kc.sh also reads variables it never initialises (result, CONFIG_ARGS among
// them in 26.7.5) and puts them on the java command line through eval, so
// every other name is refused instead of being modelled one at a time; add a
// name here only with a check for what kc.sh or the JVM does with it.
const KEYCLOAK_ENV_NAME = /^(KC_[A-Z0-9_]+|KCKEY_[A-Z0-9_]+)$/;
const allowedKeycloakEnvName = (name) => KEYCLOAK_ENV_NAME.test(name) || JAVA_ARGS_ENV.test(name);

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
  if (text.includes("$(")) problems.push('the Keycloak CR contains "$(": Kubernetes expands $(VAR) in the container\'s env values from variables defined before it, which can come from a Secret');
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
      if (where !== "spec.env" && where !== "podTemplate containers[0].env") {
        // Other containers do not run kc.sh; the checks below still apply.
      } else if (!allowedKeycloakEnvName(String(e.name ?? ""))) {
        problems.push(`${where} ${e.name} is not an env name the Keycloak container may set (allowed: KC_*, KCKEY_* and the java argument variables, all value checked)`);
      }
      // Only a literal value can be checked; secret and valueFrom cannot.
      const literal = e.value === undefined || e.value === null ? undefined : String(e.value);
      if (isDatabaseOption(env)) problems.push(`${where} ${e.name} sets a database option outside spec.db`);
      if (env === "KC_CONFIG_FILE") problems.push(`${where} ${e.name} points Keycloak at another configuration file`);
      const why = env.startsWith("KCKEY_") ? `it names the option KC_${env.slice(6)} sets` : JAVA_ARGS_ENV.test(env) ? "kc.sh or the JVM turns it into java arguments" : undefined;
      if (why && (literal === undefined || /['"\\]/.test(literal))) problems.push(`${where} ${e.name} must be a literal value without quotes or backslashes (${why})`);
      if (env.startsWith("KCKEY_") && literal !== undefined) {
        const target = `KC_${envForm(literal)}`;
        if (isDatabaseOption(target)) problems.push(`${where} ${e.name} maps KC_${env.slice(6)} to the database option ${literal}`);
        else if (target === "KC_CONFIG_FILE") problems.push(`${where} ${e.name} maps KC_${env.slice(6)} to ${literal}, another configuration file`);
      }
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
    "spec.db.vendor other than postgres": [(kc) => { kc.spec.db.vendor = "mysql"; }, /spec\.db\.vendor must be postgres/],
    // Kubernetes expands $(VAR) in env values from the variables defined
    // before it, which can come from a Secret.
    "a KCKEY_ env naming its option through $(VAR)": [(kc) => { kc.spec.env = [{ name: "OPTION_NAME", value: "db-url" }, { name: "KC_FOO", secret: { name: "keycloak-db", key: "url" } }, { name: "KCKEY_FOO", value: "$(OPTION_NAME)" }]; }, /contains "\$\("/],
    "JAVA_OPTS_APPEND set through $(VAR) from a Secret": [(kc) => { kc.spec.env = [{ name: "EXTRA_JVM", secret: { name: "keycloak-db", key: "jvm" } }, { name: "JAVA_OPTS_APPEND", value: "$(EXTRA_JVM)" }]; }, /contains "\$\("/],
    "$(VAR) in a pod template env value": [(kc) => { pod(kc).containers[0].env = [{ name: "KC_LOG_LEVEL", value: "$(LEVEL)" }]; }, /contains "\$\("/],
    "$(VAR) in an additionalOptions value": [(kc) => { kc.spec.additionalOptions.push({ name: "log-level", value: "$(LEVEL)" }); }, /contains "\$\("/],
    // kc.sh passes JAVA_OPTS through xargs, which removes quotes and
    // backslashes; the JVM removes quotes from JAVA_TOOL_OPTIONS and
    // JDK_JAVA_OPTIONS.
    "a quoted kc. property in JAVA_OPTS_APPEND": [(kc) => { kc.spec.env = [{ name: "JAVA_OPTS_APPEND", value: "-D'kc'.db-url=jd'bc':postgresql://h:5432/d" }]; }, /JAVA_OPTS_APPEND must be a literal value without quotes or backslashes/],
    "a backslash in JAVA_TOOL_OPTIONS": [(kc) => { pod(kc).containers[0].env = [{ name: "JAVA_TOOL_OPTIONS", value: "-D\\kc.db-url=x" }]; }, /JAVA_TOOL_OPTIONS must be a literal value without quotes or backslashes/],
    "double quotes in JDK_JAVA_OPTIONS": [(kc) => { kc.spec.env = [{ name: "JDK_JAVA_OPTIONS", value: '-D"kc".db-url=x' }]; }, /JDK_JAVA_OPTIONS must be a literal value without quotes or backslashes/],
    "a quote in JAVA_LOCALE (kc.sh appends it to JAVA_OPTS)": [(kc) => { kc.spec.env = [{ name: "JAVA_LOCALE", value: "-D'kc'.db-url=x" }]; }, /JAVA_LOCALE must be a literal value without quotes or backslashes/],
    "a quote in KC_DEBUG_SUSPEND (kc.sh puts it in the jdwp option)": [(kc) => { kc.spec.env = [{ name: "KC_DEBUG_SUSPEND", value: "n -D'kc'.db-url=x" }]; }, /KC_DEBUG_SUSPEND must be a literal value without quotes or backslashes/],
    "JAVA_ADD_OPENS from a Secret": [(kc) => { kc.spec.env = [{ name: "JAVA_ADD_OPENS", secret: { name: "x", key: "y" } }]; }, /JAVA_ADD_OPENS must be a literal value/],
    "DEBUG_PORT from a Secret": [(kc) => { kc.spec.env = [{ name: "DEBUG_PORT", secret: { name: "x", key: "y" } }]; }, /DEBUG_PORT must be a literal value/],
    "JAVA from a Secret (kc.sh runs it through eval)": [(kc) => { pod(kc).containers[0].env = [{ name: "JAVA", valueFrom: { secretKeyRef: { name: "x", key: "y" } } }]; }, /JAVA must be a literal value/],
    "a quote in a KCKEY_ value": [(kc) => { kc.spec.env = [{ name: "KCKEY_FOO", value: "'db-url'" }]; }, /KCKEY_FOO must be a literal value without quotes or backslashes/],
    // kc.sh never initialises result or CONFIG_ARGS, so their environment
    // values reach the java command line through eval; any name outside the
    // allow-list is refused rather than modelled one by one.
    "kc.sh's uninitialised result in spec.env": [(kc) => { kc.spec.env = [{ name: "result", value: "-D'kc'.db-url=jd'bc':postgresql://h:5432/d" }]; }, /spec\.env result is not an env name the Keycloak container may set/],
    "kc.sh's uninitialised CONFIG_ARGS in spec.env": [(kc) => { kc.spec.env = [{ name: "CONFIG_ARGS", value: " --db-url=jd'bc':postgresql://h:5432/d" }]; }, /spec\.env CONFIG_ARGS is not an env name the Keycloak container may set/],
    "SERVER_OPTS in the pod template": [(kc) => { pod(kc).containers[0].env = [{ name: "SERVER_OPTS", value: "x" }]; }, /podTemplate containers\[0\]\.env SERVER_OPTS is not an env name the Keycloak container may set/],
    "a lower-case kc_ name (Linux env names are case-sensitive)": [(kc) => { kc.spec.env = [{ name: "kc_log_level", value: "info" }]; }, /spec\.env kc_log_level is not an env name the Keycloak container may set/]
  };
  // Plain JVM options and a KCKEY_ mapping to another option stay allowed.
  const plain = structuredClone(cr);
  plain.spec.env = [{ name: "JAVA_OPTS_APPEND", value: "-XX:+UseZGC -Dfile.encoding=UTF-8" }, { name: "KC_FOO", value: "info" }, { name: "KCKEY_FOO", value: "log-level" }];
  assert.deepEqual(databaseTlsProblems(plain), []);
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

// Known gap (1) of REALM_AS_CODE.md: a script mapper or a custom SPI mapper can
// write any claim, aud included. check-realm.mjs refuses every mapper that is
// not on its list of stock Keycloak 26.7.5 mappers; this keeps the deployment
// from loading other mappers at all. The CR runs the stock image
// quay.io/keycloak/keycloak:26.7.5 (no provider jars), enables no feature but
// the allow-listed ones (ENABLED_FEATURES: not scripts, preview, legacy
// token-exchange, token-exchange-delegation, jwt-authorization-grant or any
// other feature that adds mappers, grants or token exchange), and nothing is
// mounted at /opt/keycloak/providers. Features are read from spec.features
// only, so features set as an additional option, a KC_FEATURES* env var, a
// KCKEY_* env var naming the features option or a -Dkc.features system
// property are refused; the Keycloak container (the first pod template
// container) takes no args, command or envFrom, because the operator keeps
// non-empty args (it sets "--verbose start" only when they are empty) and
// both can set features or fetch a provider jar. The pod template may not
// replace the image.
const STOCK_IMAGE = "quay.io/keycloak/keycloak:26.7.5";
const PROVIDERS_DIR = "/opt/keycloak/providers";
const ENABLED_FEATURES = /^token-exchange-standard(:v\d+)?$/;
function providerProblems(kc) {
  const problems = [];
  if (kc?.spec?.image !== STOCK_IMAGE) problems.push(`spec.image must be ${STOCK_IMAGE}, found ${JSON.stringify(kc?.spec?.image)}`);
  for (const f of kc?.spec?.features?.enabled || []) {
    if (!ENABLED_FEATURES.test(String(f).trim().toLowerCase())) problems.push(`spec.features.enabled must not enable ${f} (only token-exchange-standard may be listed; other features can load script mappers or add grants and token exchange)`);
  }
  for (const o of kc?.spec?.additionalOptions || []) {
    if (`KC_${envForm(o.name)}`.startsWith("KC_FEATURES")) problems.push(`additional option ${o.name} sets features outside spec.features`);
  }
  const pod = kc?.spec?.unsupported?.podTemplate?.spec;
  const keycloakContainer = pod?.containers?.[0] || {};
  for (const f of ["args", "command"]) if ((keycloakContainer[f] || []).length) problems.push(`podTemplate containers[0] ${f} can set features or fetch a provider jar into ${PROVIDERS_DIR}`);
  if (keycloakContainer.envFrom !== undefined) problems.push("podTemplate containers[0] envFrom can set KC_FEATURES, and its variables are not visible to this check");
  for (const [where, c] of [["spec", { env: kc?.spec?.env }], ...(pod?.containers || []).map((c, i) => [`podTemplate containers[${i}]`, c]), ...(pod?.initContainers || []).map((c, i) => [`podTemplate initContainers[${i}]`, c])]) {
    for (const e of c.env || []) {
      if (envForm(e.name).startsWith("KC_FEATURES")) problems.push(`${where} env ${e.name} sets features outside spec.features`);
      if (envForm(e.name).startsWith("KCKEY_") && `KC_${envForm(e.value)}`.startsWith("KC_FEATURES")) problems.push(`${where} env ${e.name} maps KC_${envForm(e.name).slice(6)} to ${e.value}, which sets features outside spec.features`);
      if (/-Dkc\.features/i.test(String(e.value ?? ""))) problems.push(`${where} env ${e.name} sets features outside spec.features (-Dkc.features)`);
    }
    if (c.image !== undefined) problems.push(`${where} image ${c.image} would replace or add to the stock image`);
    for (const m of c.volumeMounts || []) {
      if (pathsOverlap(m.mountPath, PROVIDERS_DIR)) problems.push(`${where} mount at ${m.mountPath} reaches ${PROVIDERS_DIR}, where Keycloak loads provider jars`);
    }
  }
  return problems;
}

test("the Keycloak CR cannot load script or custom SPI mappers: stock image 26.7.5, no scripts or legacy token-exchange feature, nothing at /opt/keycloak/providers", () => {
  assert.deepEqual(providerProblems(cr), []);
  assert.deepEqual(cr.spec.features, { disabled: ["impersonation"] });
});

test("the provider check rejects another image, a refused feature and a mount at the providers directory", () => {
  const withSpec = (mutate) => { const kc = structuredClone(cr); mutate(kc.spec); return kc; };
  const podContainer = (spec) => spec.unsupported.podTemplate.spec.containers[0];
  const cases = {
    "a custom image": [withSpec((s) => { s.image = "123456789012.dkr.ecr.me-central-1.amazonaws.com/keycloak:26.7.5"; }), /spec\.image must be/],
    "an image digest": [withSpec((s) => { s.image = `${STOCK_IMAGE}@sha256:${"0".repeat(64)}`; }), /spec\.image must be/],
    "another version": [withSpec((s) => { s.image = "quay.io/keycloak/keycloak:26.7.4"; }), /spec\.image must be/],
    "scripts": [withSpec((s) => { s.features.enabled = ["scripts"]; }), /must not enable scripts/],
    "Scripts:v1": [withSpec((s) => { s.features.enabled = ["Scripts:v1"]; }), /must not enable Scripts:v1/],
    "preview": [withSpec((s) => { s.features.enabled = ["preview"]; }), /must not enable preview/],
    "token-exchange": [withSpec((s) => { s.features.enabled = ["token-exchange"]; }), /must not enable token-exchange/],
    "token-exchange:v1": [withSpec((s) => { s.features.enabled = ["token-exchange:v1"]; }), /must not enable token-exchange:v1/],
    "option features": [withSpec((s) => { s.additionalOptions.push({ name: "features", value: "scripts" }); }), /additional option features sets features/],
    "env KC_FEATURES": [withSpec((s) => { s.env = [{ name: "KC_FEATURES", value: "scripts" }]; }), /spec env KC_FEATURES sets features/],
    "pod env KC_FEATURES": [withSpec((s) => { podContainer(s).env = [{ name: "KC_FEATURES", value: "scripts" }]; }), /podTemplate containers\[0\] env KC_FEATURES/],
    "pod container image": [withSpec((s) => { podContainer(s).image = "example/keycloak-with-scripts:1"; }), /podTemplate containers\[0\] image/],
    "mount at providers": [withSpec((s) => { podContainer(s).volumeMounts.push({ name: "jars", mountPath: "/opt/keycloak/providers" }); }), /mount at \/opt\/keycloak\/providers reaches/],
    "mount of one jar": [withSpec((s) => { podContainer(s).volumeMounts.push({ name: "jars", mountPath: "/opt/keycloak/providers/aud.jar", subPath: "aud.jar" }); }), /mount at \/opt\/keycloak\/providers\/aud\.jar reaches/],
    "mount over /opt/keycloak": [withSpec((s) => { podContainer(s).volumeMounts.push({ name: "jars", mountPath: "/opt/keycloak/" }); }), /mount at \/opt\/keycloak\/ reaches/],
    "init container filling providers": [withSpec((s) => { s.unsupported.podTemplate.spec.initContainers = [{ name: "fetch", image: "busybox", volumeMounts: [{ name: "jars", mountPath: "/opt/keycloak/providers" }] }]; }), /initContainers\[0\] mount at \/opt\/keycloak\/providers/],
    // Features outside the allow-list (Keycloak 26.7.5 Profile$Feature).
    "jwt-authorization-grant": [withSpec((s) => { s.features.enabled = ["jwt-authorization-grant"]; }), /must not enable jwt-authorization-grant/],
    "token-exchange-delegation": [withSpec((s) => { s.features.enabled = ["token-exchange-delegation:v1"]; }), /must not enable token-exchange-delegation:v1/],
    "identity-assertion-jwt": [withSpec((s) => { s.features.enabled = ["identity-assertion-jwt"]; }), /must not enable identity-assertion-jwt/],
    // The operator keeps non-empty pod template args (it sets "--verbose
    // start" only when they are empty), so they can enable features.
    "pod args enabling scripts": [withSpec((s) => { podContainer(s).args = ["start", "--features=scripts"]; }), /podTemplate containers\[0\] args/],
    "pod command fetching a jar": [withSpec((s) => { podContainer(s).command = ["/bin/sh", "-c", "wget -O /opt/keycloak/providers/aud.jar https://example.invalid/aud.jar && exec /opt/keycloak/bin/kc.sh start"]; }), /podTemplate containers\[0\] command/],
    "pod envFrom": [withSpec((s) => { podContainer(s).envFrom = [{ configMapRef: { name: "kc-features" } }]; }), /podTemplate containers\[0\] envFrom/],
    "-Dkc.features in JAVA_OPTS_APPEND": [withSpec((s) => { s.env = [{ name: "JAVA_OPTS_APPEND", value: "-Dkc.features=scripts" }]; }), /spec env JAVA_OPTS_APPEND sets features/],
    "-Dkc.features in pod JAVA_OPTS": [withSpec((s) => { podContainer(s).env = [{ name: "JAVA_OPTS", value: "-Xmx1g -DKC.FEATURES=scripts" }]; }), /podTemplate containers\[0\] env JAVA_OPTS sets features/],
    "KCKEY_ env naming features": [withSpec((s) => { s.env = [{ name: "KC_FOO", value: "scripts" }, { name: "KCKEY_FOO", value: "features" }]; }), /spec env KCKEY_FOO maps KC_FOO to features/]
  };
  const missed = [];
  for (const [name, [kc, expected]] of Object.entries(cases)) {
    const problems = providerProblems(kc);
    if (!problems.some((p) => expected.test(p))) missed.push(`${name}: expected a problem matching ${expected}, got ${JSON.stringify(problems)}`);
  }
  assert.deepEqual(missed, []);
  // Not refused: the allow-listed feature, and a KCKEY_ mapping to another option.
  assert.deepEqual(providerProblems(withSpec((s) => { s.features.enabled = ["token-exchange-standard:v2"]; })), []);
  assert.deepEqual(providerProblems(withSpec((s) => { s.env = [{ name: "KC_FOO", value: "info" }, { name: "KCKEY_FOO", value: "log-level" }]; })), []);
});


// kustomize selects the resources a patch applies to by the target's group,
// version, kind, name and namespace, each an anchored regular expression
// (api/types/selector.go), and by label and annotation selectors. A target
// may select a protected resource unless one of these patterns cannot match
// it; namespace and the selectors are not evaluated, so they never exclude it.
// Replacement targets match exactly (kyaml resid IsSelectedBy).
const KEYCLOAK_ID = { group: "k8s.keycloak.org", version: "v2beta1", kind: "Keycloak", name: "keycloak" };
const IDENTITY_ENVIRONMENT_ID = { group: "", version: "v1", kind: "ConfigMap", name: IDENTITY_ENVIRONMENT };

// What overlay and component patches and replacements may not touch, per
// resource: the Keycloak CR's database options, pod template, env and spec.db
// (except the pool sizes), and the identity-environment values that
// components/environment copies into spec.db.host and spec.db.database.
// Those two replacements, with no options, are the only way into spec.db;
// "every overlay feeds spec.db a plain host and database name" checks the
// values they copy.
// Also the CR's image and features, which decide the mappers Keycloak can
// load (providerProblems).
const DATABASE_TLS = "the database TLS settings";
const PROTECTED = [
  { id: KEYCLOAK_ID, label: "the Keycloak CR", paths: PROTECTED_CR_PATHS, allowed: ["/spec/db/poolInitialSize", "/spec/db/poolMinSize", "/spec/db/poolMaxSize"], concern: DATABASE_TLS },
  { id: KEYCLOAK_ID, label: "the Keycloak CR", paths: ["/spec/image", "/spec/features"], allowed: [], concern: "the image or features (stock mappers only)" },
  { id: IDENTITY_ENVIRONMENT_ID, label: `ConfigMap ${IDENTITY_ENVIRONMENT}`, paths: ["/data/databaseHost", "/data/databaseName"], allowed: [], concern: DATABASE_TLS }
];
const touches = (p, { paths, allowed }) =>
  !allowed.includes(p) && (p === "" || p === "/" || paths.some((x) => p === x || p.startsWith(`${x}/`) || x.startsWith(`${p.replace(/\/$/, "")}/`)));
const ENVIRONMENT_DATABASE_FIELDS = new Map([["spec.db.host", "data.databaseHost"], ["spec.db.database", "data.databaseName"]]);
const isEnvironmentDatabaseReplacement = (r, t, fieldPath) =>
  ENVIRONMENT_DATABASE_FIELDS.has(fieldPath) &&
  r?.source?.kind === "ConfigMap" && r.source.name === IDENTITY_ENVIRONMENT &&
  r.source.fieldPath === ENVIRONMENT_DATABASE_FIELDS.get(fieldPath) &&
  r.source.options === undefined && t.options === undefined;

function targetMaySelect(target, id) {
  return Object.entries(id).every(([field, value]) => {
    const pattern = target?.[field];
    if (pattern === undefined || pattern === null || pattern === "") return true;
    try {
      return new RegExp(`^(?:${pattern})$`).test(value);
    } catch {
      return true; // a Go (RE2) pattern JavaScript cannot compile: assume it matches
    }
  });
}
const replacementMaySelect = (select, id) =>
  Object.entries(id).every(([field, value]) => !select?.[field] || select[field] === value);

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

// Patches, replacements, transformers and generators in one kustomization
// that can reach the database TLS settings of the Keycloak CR (PROTECTED),
// read without building it.
// load(relativePath) returns a file's text. This is a fast check for the
// realm job's npm test; the rendered check below, which the manifests job
// runs with FBX_REQUIRE_KUSTOMIZE=1, judges the built result.
function kustomizationPatchProblems(k, load) {
  const problems = [];
  if (k.patchesJson6902 !== undefined) problems.push("uses patchesJson6902; use patches");
  if (k.patchesStrategicMerge !== undefined) problems.push("uses patchesStrategicMerge; use patches");
  if (k.transformers !== undefined) problems.push("uses transformers, which this check does not read; use patches or replacements");
  if (k.generators !== undefined) problems.push("uses generators, which this check does not read");
  for (const g of k.configMapGenerator || []) {
    if (g?.name === IDENTITY_ENVIRONMENT) problems.push(`configMapGenerator ${g.name} can replace the values copied into spec.db; edit the overlay's ${IDENTITY_ENVIRONMENT}.yaml`);
  }
  for (const entry of [...(k.resources || []), ...(k.components || [])]) {
    if (isRemote(entry)) problems.push(`remote ${entry} cannot be checked without building it`);
  }
  for (const patch of k.patches || []) {
    const docs = YAML.parseAllDocuments(patch.patch ?? load(patch.path)).map((d) => d.toJS());
    if (docs.length === 1 && Array.isArray(docs[0])) {
      for (const rule of PROTECTED) {
        if (!targetMaySelect(patch.target, rule.id)) continue;
        for (const op of docs[0]) {
          for (const p of [op.path, op.from].filter((x) => x !== undefined)) {
            if (touches(p, rule)) problems.push(`patch ${op.op} ${p} on ${rule.label} touches ${rule.concern}`);
          }
        }
      }
      continue;
    }
    // Strategic merge: with a target, kustomize applies the patch to what the
    // target selects; without one, to the resource with the patch's own id
    // (here: any resource of that kind).
    for (const body of docs) {
      const { apiVersion, kind, metadata, ...rest } = body || {};
      for (const rule of PROTECTED) {
        if (patch.target ? !targetMaySelect(patch.target, rule.id) : kind !== rule.id.kind) continue;
        for (const p of smpTouchedPaths(rest, "")) {
          if (touches(p, rule)) problems.push(`strategic-merge patch on ${rule.label} touches ${p || "the whole resource"}`);
        }
      }
    }
  }
  for (const r of k.replacements || []) {
    const loaded = r.path === undefined ? [r] : [YAML.parse(load(r.path))].flat();
    for (const x of loaded) {
      for (const t of x?.targets || []) {
        for (const rule of PROTECTED) {
          if (!replacementMaySelect(t.select, rule.id)) continue;
          for (const fp of t.fieldPaths || []) {
            const p = `/${fp.replace(/\./g, "/")}`;
            if (touches(p, rule) && !isEnvironmentDatabaseReplacement(x, t, fp)) problems.push(`replacement into ${fp} of ${rule.label} touches ${rule.concern}`);
          }
        }
      }
    }
  }
  return problems;
}

test("no overlay or component patch rewrites the database options, the pod template, spec.env, spec.db or the identity-environment database values", () => {
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
    "a remote resource": { resources: ["github.com/example/repo//base?ref=v1"] },
    // spec.db: host and database go into the JDBC URL; only the pool sizes
    // may be patched, and only identity-environment feeds host and database.
    "JSON patch on spec.db.database": { patches: [{ target: { kind: "Keycloak", name: "keycloak" }, patch: "- op: replace\n  path: /spec/db/database\n  value: db?\n" }] },
    "JSON patch replacing spec.db": { patches: [{ target: { kind: "Keycloak" }, patch: "- op: replace\n  path: /spec/db\n  value: {}\n" }] },
    "SMP setting spec.db.host": { patches: [{ patch: smp("  db:\n    host: writer.example\n") }] },
    "SMP replacing spec.db": { patches: [{ patch: smp("  db:\n    $patch: replace\n    poolMaxSize: 40\n") }] },
    "replacement into spec.db.database from another ConfigMap": { replacements: [{ source: { kind: "ConfigMap", name: "other", fieldPath: "data.databaseName" }, targets: [{ select: { kind: "Keycloak", name: "keycloak" }, fieldPaths: ["spec.db.database"] }] }] },
    "replacement of databaseHost into spec.db.database": { replacements: [{ source: { kind: "ConfigMap", name: "identity-environment", fieldPath: "data.databaseHost" }, targets: [{ select: { kind: "Keycloak", name: "keycloak" }, fieldPaths: ["spec.db.database"] }] }] },
    "replacement of databaseName with target options": { replacements: [{ source: { kind: "ConfigMap", name: "identity-environment", fieldPath: "data.databaseName" }, targets: [{ select: { kind: "Keycloak", name: "keycloak" }, fieldPaths: ["spec.db.database"], options: { delimiter: "?", index: 1 } }] }] },
    "replacement of databaseName with source options": { replacements: [{ source: { kind: "ConfigMap", name: "identity-environment", fieldPath: "data.databaseName", options: { delimiter: "_", index: 0 } }, targets: [{ select: { kind: "Keycloak", name: "keycloak" }, fieldPaths: ["spec.db.database"] }] }] },
    // identity-environment data.databaseHost and data.databaseName: the
    // static check reads them from the overlay's resource file.
    "JSON patch on identity-environment databaseName": { patches: [{ target: { kind: "ConfigMap", name: "identity-environment" }, patch: "- op: replace\n  path: /data/databaseName\n  value: db?\n" }] },
    "JSON patch replacing the data of any ConfigMap": { patches: [{ target: { kind: "ConfigMap" }, patch: "- op: replace\n  path: /data\n  value: {}\n" }] },
    "SMP on identity-environment databaseHost": { patches: [{ patch: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: identity-environment\ndata:\n  databaseHost: writer.example?\n" }] },
    "replacement into identity-environment databaseName": { replacements: [{ source: { kind: "ConfigMap", name: "other", fieldPath: "data.x" }, targets: [{ select: { kind: "ConfigMap", name: "identity-environment" }, fieldPaths: ["data.databaseName"] }] }] },
    "configMapGenerator merging into identity-environment": { configMapGenerator: [{ name: "identity-environment", behavior: "merge", literals: ["databaseName=db?"] }] },
    "a generators entry": { generators: ["generator.yaml"] },
    // The image and the features decide which mappers Keycloak can load.
    "JSON patch on spec.image": { patches: [{ target: { kind: "Keycloak", name: "keycloak" }, patch: "- op: replace\n  path: /spec/image\n  value: example/keycloak:1\n" }] },
    "JSON patch adding an enabled feature": { patches: [{ target: { kind: "Keycloak" }, patch: "- op: add\n  path: /spec/features/enabled\n  value: [scripts]\n" }] },
    "SMP enabling a feature": { patches: [{ patch: smp("  features:\n    enabled: [scripts]\n") }] },
    "replacement into spec.image": { replacements: [{ source: { kind: "ConfigMap", name: "x", fieldPath: "data.y" }, targets: [{ select: { kind: "Keycloak", name: "keycloak" }, fieldPaths: ["spec.image"] }] }] }
  };
  const environmentComponent = YAML.parse(fs.readFileSync(path.join(root, "deploy/kustomize/components/environment/kustomization.yaml"), "utf8"));
  const clean = {
    "JSON patch on a PodDisruptionBudget": { patches: [{ target: { kind: "PodDisruptionBudget", name: "keycloak" }, patch: remove0 }] },
    "JSON patch with target kind Keycloak.+": { patches: [{ target: { kind: "Keycloak.+" }, patch: remove0 }] },
    "JSON patch with target name other": { patches: [{ target: { kind: "Keycloak", name: "other" }, patch: remove0 }] },
    "JSON patch on spec.instances": { patches: [{ target: { kind: "Keycloak", name: "keycloak" }, patch: "- op: replace\n  path: /spec/instances\n  value: 2\n" }] },
    "SMP $patch: replace on spec.hostname": { patches: [{ patch: smp("  hostname:\n    $patch: replace\n    hostname: https://IDENTITY_HOST\n") }] },
    "SMP on spec.db.poolMaxSize": { patches: [{ patch: smp("  db:\n    poolMaxSize: 40\n") }] },
    "replacement into a Secret": { replacements: [{ source: { kind: "ConfigMap", name: "x", fieldPath: "data.y" }, targets: [{ select: { kind: "Secret" }, fieldPaths: ["data.additionalOptions"] }] }] },
    "local resources and components": { resources: ["../../base", "extra.yaml"], components: ["../../components/environment"] },
    "JSON patch on spec.db.poolMaxSize": { patches: [{ target: { kind: "Keycloak", name: "keycloak" }, patch: "- op: replace\n  path: /spec/db/poolMaxSize\n  value: 40\n" }] },
    "the environment component's replacements": { replacements: environmentComponent.replacements },
    "JSON patch on another ConfigMap's data": { patches: [{ target: { kind: "ConfigMap", name: "keycloak-realm-import-env" }, patch: "- op: replace\n  path: /data/FBX_WEB_ORIGIN\n  value: https://app.example\n" }] },
    "configMapGenerator for another ConfigMap": { configMapGenerator: [{ name: "openldap-seed", files: ["seed/50-fintechbankx-structure.ldif"] }] }
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
test("every overlay renders exactly one sslmode=verify-full with the mounted RDS CA bundle, and the stock image without providers", (t) => {
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
    assert.deepEqual(providerProblems(keycloaks[0]), [], overlay);
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

// Every service client of the realm registry reaches keycloak:8080 for its
// token and for the JWKS it validates callers with, so the operator
// NetworkPolicy must admit its namespace (namespace-wide rules only; the
// istio-ingress rule admits the gateway pods alone). Accounts ledger
// (2026-10-17): namespace corebanking.
test("the Keycloak NetworkPolicy admits the namespace of every registry service client on 8080", () => {
  const registry = JSON.parse(fs.readFileSync(path.join(root, "realm/service-clients.json"), "utf8"));
  assert.equal(cr.spec.networkPolicy.enabled, true);
  const admitted = new Set((cr.spec.networkPolicy.http || [])
    .filter((rule) => rule.namespaceSelector && !rule.podSelector)
    .flatMap((rule) => [
      ...[rule.namespaceSelector.matchLabels?.["kubernetes.io/metadata.name"]].filter(Boolean),
      ...(rule.namespaceSelector.matchExpressions || [])
        .filter((e) => e.key === "kubernetes.io/metadata.name" && e.operator === "In")
        .flatMap((e) => e.values)
    ]));
  assert.ok(admitted.has("corebanking"), "namespace corebanking (accounts ledger) cannot reach keycloak:8080");
  for (const c of registry.clients) assert.ok(admitted.has(c.namespace), `${c.clientId}: namespace ${c.namespace} cannot reach keycloak:8080`);
});
