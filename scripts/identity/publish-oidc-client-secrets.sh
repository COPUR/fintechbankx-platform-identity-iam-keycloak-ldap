#!/usr/bin/env bash
# Writes each service's OIDC client credential to AWS Secrets Manager as
#   <env>/<service-slug>/oidc-client
#   {"client_id", "client_secret", "issuer_uri", "token_uri"}
# Secrets Manager is the source of truth: the realm import Job reads the same
# entries (ExternalSecret keycloak-realm-import) and configures Keycloak with
# them; each service syncs its own entry with its ExternalSecret.
#
# Default is a dry run that only reports what would change. Nothing is
# printed or logged that contains a credential value.
#
# usage:
#   scripts/identity/publish-oidc-client-secrets.sh --env dev --issuer https://identity.dev.fintechbankx.example/realms/fintechbankx [--apply] [--rotate] [--only <client-id>]
#
#   --apply    write to Secrets Manager (otherwise dry run)
#   --rotate   replace existing values (default: only fill empty/missing ones)
#   --only     limit to one client id from realm/service-clients.json
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
    --only) ONLY="$2"; shift 2 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
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
mapfile -t ROWS < <(jq -r '.clients[] | [.clientId, .serviceSlug] | @tsv' "$REGISTRY")

changed=0
skipped=0
for row in "${ROWS[@]}"; do
  client_id="${row%%$'\t'*}"
  slug="${row#*$'\t'}"
  if [ -n "$ONLY" ] && [ "$ONLY" != "$client_id" ]; then
    continue
  fi
  name="${ENVIRONMENT}/${slug}/oidc-client"

  if ! aws secretsmanager describe-secret --secret-id "$name" >/dev/null 2>&1; then
    echo "MISSING  ${name}: container not found (run deploy/terraform first)" >&2
    exit 1
  fi

  has_value=false
  if aws secretsmanager get-secret-value --secret-id "$name" --query 'VersionId' --output text >/dev/null 2>&1; then
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

  # 48 random bytes, URL-safe, never echoed.
  value="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')"
  jq -n --arg id "$client_id" --arg v "$value" --arg iss "$ISSUER" --arg tok "$TOKEN_URI" \
    '{client_id: $id, client_secret: $v, issuer_uri: $iss, token_uri: $tok}' > "$WORK/payload.json"
  unset value
  aws secretsmanager put-secret-value --secret-id "$name" \
    --secret-string "file://$WORK/payload.json" >/dev/null
  rm -f "$WORK/payload.json"
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
