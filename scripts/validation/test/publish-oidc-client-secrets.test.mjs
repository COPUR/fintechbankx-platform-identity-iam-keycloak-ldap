// scripts/identity/publish-oidc-client-secrets.sh against a stub aws CLI
// (DevSecOps review of identity round 16: B-1, S-1, S-2).
//  - B-1: the generated secret never reaches a command line (ps) or a file:
//    it goes from openssl through jq to aws on pipes, and aws reads it with
//    --secret-string file:///dev/stdin. A jq wrapper logs every argv.
//  - S-1: whether a container already has a value comes from describe-secret
//    (an AWSCURRENT version), never from reading the value, and any error
//    other than "not found" stops the run instead of counting as empty.
//  - S-2: --only with a client id that is not in the registry fails before
//    any AWS call.
import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { spawnSync, execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const SCRIPT = path.join(root, "scripts/identity/publish-oidc-client-secrets.sh");
const ISSUER = "https://identity.dev.fintechbankx.example/realms/fintechbankx";
const registry = JSON.parse(readFileSync(path.join(root, "realm/service-clients.json"), "utf8"));
const ALL = [...registry.clients, ...(registry.ssoClients || [])];
const REAL_JQ = execFileSync("bash", ["-c", "command -v jq"], { encoding: "utf8" }).trim();

// aws stub. AWS_STUB_STATE: current (AWSCURRENT exists), pending (only AWSPENDING),
// empty (container, no version), notfound, denied (describe refused),
// unreadable (describe works and shows AWSCURRENT, get-secret-value is refused).
const AWS_STUB = `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$STUB_DIR/argv.log"
sub="$2"
case "$sub" in
  describe-secret)
    case "$AWS_STUB_STATE" in
      notfound) echo "An error occurred (ResourceNotFoundException) when calling the DescribeSecret operation: Secrets Manager can't find the specified secret." >&2; exit 254 ;;
      denied) echo "An error occurred (AccessDeniedException) when calling the DescribeSecret operation: not authorized" >&2; exit 254 ;;
    esac
    if [[ " $* " == *" --query VersionIdsToStages "* ]]; then
      case "$AWS_STUB_STATE" in
        current|unreadable) echo '{"v-1": ["AWSCURRENT", "AWSPREVIOUS"]}' ;;
        pending) echo '{"v-2": ["AWSPENDING"]}' ;;
        *) echo 'null' ;;
      esac
    else
      echo '{"Name": "stub"}'
    fi ;;
  get-secret-value)
    case "$AWS_STUB_STATE" in
      current) echo "v-1" ;;
      unreadable) echo "An error occurred (AccessDeniedException) when calling the GetSecretValue operation: kms:Decrypt denied" >&2; exit 254 ;;
      *) echo "An error occurred (ResourceNotFoundException) when calling the GetSecretValue operation: no AWSCURRENT" >&2; exit 254 ;;
    esac ;;
  put-secret-value)
    src=""
    while [ $# -gt 0 ]; do [ "$1" = "--secret-string" ] && src="$2"; shift; done
    echo "SOURCE $src" >> "$STUB_DIR/put.log"
    case "$src" in
      file:///dev/stdin) cat >> "$STUB_DIR/put.log" ;;
      file://*) cat "\${src#file://}" >> "$STUB_DIR/put.log" ;;
      *) printf '%s' "$src" >> "$STUB_DIR/put.log" ;;
    esac
    echo >> "$STUB_DIR/put.log"
    echo '{"VersionId": "v-new"}' ;;
  *) echo "stub: unexpected $sub" >&2; exit 99 ;;
esac
`;
const JQ_WRAPPER = `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$STUB_DIR/jq-argv.log"
exec "${REAL_JQ}" "$@"
`;

function run(args, state = "empty") {
  const dir = mkdtempSync(path.join(tmpdir(), "publish-oidc-"));
  writeFileSync(path.join(dir, "aws"), AWS_STUB);
  writeFileSync(path.join(dir, "jq"), JQ_WRAPPER);
  chmodSync(path.join(dir, "aws"), 0o755);
  chmodSync(path.join(dir, "jq"), 0o755);
  const r = spawnSync("bash", [SCRIPT, "--env", "dev", "--issuer", ISSUER, ...args], {
    encoding: "utf8",
    env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, STUB_DIR: dir, AWS_STUB_STATE: state },
  });
  const read = (f) => (existsSync(path.join(dir, f)) ? readFileSync(path.join(dir, f), "utf8") : "");
  const out = { status: r.status, stdout: r.stdout, stderr: r.stderr, argv: read("argv.log"), jqArgv: read("jq-argv.log"), put: read("put.log") };
  rmSync(dir, { recursive: true, force: true });
  return out;
}
const puts = (r) => r.put.split("\n").filter((l) => l.startsWith("{")).map((l) => JSON.parse(l));

test("B-1: --apply sends the secret through stdin only; no argv and no file carries it", () => {
  const r = run(["--apply", "--only", "svc-cmp-evidence"], "empty");
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.put, /^SOURCE file:\/\/\/dev\/stdin$/m);
  const [payload] = puts(r);
  assert.deepEqual(Object.keys(payload).sort(), ["client_id", "client_secret", "issuer_uri", "token_uri"]);
  assert.equal(payload.client_id, "svc-cmp-evidence");
  assert.match(payload.client_secret, /^[A-Za-z0-9_-]{64}$/);
  assert.equal(payload.token_uri, `${ISSUER}/protocol/openid-connect/token`);
  assert.ok(!r.argv.includes(payload.client_secret), "the secret is on an aws command line");
  assert.ok(!r.jqArgv.includes(payload.client_secret), "the secret is on a jq command line");
  assert.ok(!r.stdout.includes(payload.client_secret) && !r.stderr.includes(payload.client_secret), "the secret is printed");
  assert.match(r.stdout, /^SET +dev\/compliance-evidence-service\/oidc-client \(svc-cmp-evidence\)$/m);
});

test("B-1: the script holds the secret in no shell variable, jq argument or payload file", () => {
  const src = readFileSync(SCRIPT, "utf8").split("\n").filter((l) => !/^\s*#/.test(l)).join("\n");
  assert.doesNotMatch(src, /payload/);
  assert.doesNotMatch(src, /=\s*"?\$\(\s*openssl/, "openssl output is captured in a variable");
  assert.match(src, /--secret-string file:\/\/\/dev\/stdin/);
  // S-4: every value jq takes from outside comes through --arg with one of these names; no
  // --argjson, --rawfile, --slurpfile, --args or --jsonargs, which could carry the secret instead.
  const injected = [...src.matchAll(/--(arg|argjson|rawfile|slurpfile|args|jsonargs)\b(?:\s+(\S+))?/g)].map((m) => `--${m[1]} ${m[2] ?? ""}`.trim());
  assert.ok(injected.length > 0, "the guard found no jq arguments; it reads the wrong file");
  for (const opt of injected) {
    assert.match(opt, /^--arg (id|iss|tok)$/, `jq takes a value through ${opt}`);
  }
});

test("S-3: --only with an empty or missing value fails before any AWS call", () => {
  for (const args of [["--apply", "--only", ""], ["--apply", "--only"]]) {
    const r = run(args, "empty");
    assert.equal(r.status, 2, `${JSON.stringify(args)}: ${r.stderr}`);
    assert.equal(r.argv, "", "aws was called");
    assert.match(r.stderr, /--only needs a client id/);
  }
});

test("S-1: a value is detected from describe-secret, so an unreadable live secret is kept, not overwritten", () => {
  const r = run(["--apply", "--only", "svc-rsk-decisioning"], "unreadable");
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.put, "", "a live secret was overwritten");
  assert.match(r.stdout, /^KEEP +dev\/risk-decisioning-service\/oidc-client \(svc-rsk-decisioning\) already has a value$/m);
  assert.doesNotMatch(r.argv, /get-secret-value/, "the script reads the secret value");
});

test("S-1: describe errors other than not found stop the run; not found names the missing container", () => {
  const denied = run(["--apply", "--only", "svc-rsk-decisioning"], "denied");
  assert.notEqual(denied.status, 0);
  assert.equal(denied.put, "");
  assert.match(denied.stderr, /AccessDeniedException/);
  assert.doesNotMatch(denied.stderr, /container not found/);
  const missing = run(["--apply", "--only", "svc-rsk-decisioning"], "notfound");
  assert.equal(missing.status, 1);
  assert.equal(missing.put, "");
  assert.match(missing.stderr, /^MISSING +dev\/risk-decisioning-service\/oidc-client: container not found/m);
});

test("an existing value is kept without --rotate and replaced with it; AWSPENDING alone is no value", () => {
  const keep = run(["--apply", "--only", "svc-cmp-evidence"], "current");
  assert.equal(keep.status, 0, keep.stderr);
  assert.equal(keep.put, "");
  const rotate = run(["--apply", "--rotate", "--only", "svc-cmp-evidence"], "current");
  assert.equal(rotate.status, 0, rotate.stderr);
  assert.equal(puts(rotate).length, 1);
  assert.match(rotate.stdout, /^ROTATE +dev\/compliance-evidence-service\/oidc-client/m);
  const pending = run(["--apply", "--only", "svc-cmp-evidence"], "pending");
  assert.equal(pending.status, 0, pending.stderr);
  assert.equal(puts(pending).length, 1);
});

test("S-2: --only with an unknown client id fails before any AWS call", () => {
  const r = run(["--apply", "--only", "svc-cmp-evidense"], "empty");
  assert.equal(r.status, 2);
  assert.equal(r.argv, "", "aws was called");
  assert.match(r.stderr, /svc-cmp-evidense/);
});

test("a dry run covers every registry client and writes nothing", () => {
  const r = run([], "empty");
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.put, "");
  assert.equal((r.stdout.match(/^DRY-RUN +SET /gm) || []).length, ALL.length);
  assert.doesNotMatch(r.argv, /put-secret-value/);
});
