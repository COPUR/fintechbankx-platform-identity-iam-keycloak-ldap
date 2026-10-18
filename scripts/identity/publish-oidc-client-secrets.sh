#!/usr/bin/env bash
# Writes each service's OIDC client credential to AWS Secrets Manager as
#   <env>/<service-slug>/oidc-client
#   {"client_id", "client_secret", "issuer_uri", "token_uri"}
# Secrets Manager is the source of truth: the realm import Job reads the same
# entries (ExternalSecret keycloak-realm-import) and configures Keycloak with
# them; each service syncs its own entry with its ExternalSecret.
#
# Default is a dry run that only reports what would change. Nothing is
# printed or logged that contains a credential value. A generated value only
# travels on pipes (openssl to jq to aws --secret-string file:///dev/stdin):
# it is never on a command line, in a shell variable or in a file. Whether a
# container already has a value comes from describe-secret (an AWSCURRENT
# version), so the script never reads a secret; it calls only DescribeSecret
# and PutSecretValue.
#
# usage:
#   scripts/identity/publish-oidc-client-secrets.sh --env dev --issuer https://identity.dev.fintechbankx.example/realms/fintechbankx [--apply] [--rotate] [--only <client-id>]
#
#   --apply    write to Secrets Manager (otherwise dry run)
#   --rotate   replace existing values (default: only fill empty/missing ones)
#   --only     limit to one client id from realm/service-clients.json (clients or
#              ssoClients); an id that is not there fails before any AWS call
#
# Needs: aws CLI v2 (credentials for the target account), jq, openssl.
# The secret containers come from deploy/terraform; this script never creates
# containers, so KMS key, tags and resource policies stay under Terraform.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REGISTRY="${SCRIPT_DIR}/../../realm/service-clients.json"

ENVIRONMENT=""
ISSUER=""
APPLY=false
ROTATE=false
ONLY=""

while [ $# -gt 0 ]; do
  case "$1" in
    --env) ENVIRONMENT="$2"; shift 2 ;;
    --issuer) ISSUER="$2"; shift 2 ;;
    --apply) APPLY=true; shift ;;
    --rotate) ROTATE=true; shift ;;
    --only)
      # An empty value would turn the filter off and process every client (S-3).
      if [ $# -lt 2 ] || [ -z "$2" ]; then echo "--only needs a client id" >&2; exit 2; fi
      ONLY="$2"; shift 2 ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$ENVIRONMENT" in
  dev|staging|prod) ;;
  *) echo "--env must be dev, staging or prod" >&2; exit 2 ;;
esac
if ! [[ "$ISSUER" =~ ^https://[a-z0-9.-]+/realms/fintechbankx$ ]]; then
  echo "--issuer must be https://<identity-host>/realms/fintechbankx" >&2
  exit 2
fi
for bin in aws jq openssl; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing dependency: $bin" >&2; exit 2; }
done

umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

TOKEN_URI="${ISSUER}/protocol/openid-connect/token"
mapfile -t ROWS < <(jq -r '(.clients + (.ssoClients // []))[] | [.clientId, .serviceSlug] | @tsv' "$REGISTRY")
if [ -n "$ONLY" ] && ! jq -e --arg id "$ONLY" 'any((.clients + (.ssoClients // []))[]; .clientId == $id)' "$REGISTRY" >/dev/null; then
  echo "--only ${ONLY}: no such client id in realm/service-clients.json" >&2
  exit 2
fi

changed=0
skipped=0
for row in "${ROWS[@]}"; do
  client_id="${row%%$'\t'*}"
  slug="${row#*$'\t'}"
  if [ -n "$ONLY" ] && [ "$ONLY" != "$client_id" ]; then
    continue
  fi
  name="${ENVIRONMENT}/${slug}/oidc-client"

  # Only "not found" means the container is missing; any other error (access,
  # throttling, KMS) stops the run, so a live value is never taken for empty.
  if ! stages="$(aws secretsmanager describe-secret --secret-id "$name" \
      --query 'VersionIdsToStages' --output json 2>"$WORK/describe.err")"; then
    if grep -q 'ResourceNotFoundException' "$WORK/describe.err"; then
      echo "MISSING  ${name}: container not found (run deploy/terraform first)" >&2
    else
      echo "ERROR    ${name}: describe-secret failed: $(tr '\n' ' ' < "$WORK/describe.err")" >&2
    fi
    exit 1
  fi

  # A value exists when a version carries AWSCURRENT (AWSPENDING alone is not one).
  has_value=false
  if printf '%s' "$stages" | jq -e '(. // {}) | any(.[]; index("AWSCURRENT") != null)' >/dev/null; then
    has_value=true
  fi

  if [ "$has_value" = true ] && [ "$ROTATE" = false ]; then
    echo "KEEP     ${name} (${client_id}) already has a value"
    skipped=$((skipped + 1))
    continue
  fi

  action="SET"
  [ "$has_value" = true ] && action="ROTATE"
  if [ "$APPLY" = false ]; then
    echo "DRY-RUN  ${action} ${name} (${client_id})"
    continue
  fi

  # 48 random bytes, URL-safe. jq reads them as raw input and aws reads the
  # JSON from stdin, so the value stays on pipes.
  openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n' \
    | jq -cRn --arg id "$client_id" --arg iss "$ISSUER" --arg tok "$TOKEN_URI" \
        '{client_id: $id, client_secret: input, issuer_uri: $iss, token_uri: $tok}' \
    | aws secretsmanager put-secret-value --secret-id "$name" --secret-string file:///dev/stdin >/dev/null
  echo "${action}      ${name} (${client_id})"
  changed=$((changed + 1))
done

echo "done: changed=${changed} kept=${skipped} apply=${APPLY}"
if [ "$changed" -gt 0 ]; then
  cat <<'NEXT'
Next: re-run the realm import so Keycloak uses the new values, then refresh
the services' ExternalSecrets (docs/identity/CLIENT_SECRET_DELIVERY.md).
NEXT
fi
