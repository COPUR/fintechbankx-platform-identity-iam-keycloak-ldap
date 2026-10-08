# Service client credential delivery (Proposed)

Every service authenticates to Keycloak with client credentials. The credential has one home: AWS Secrets Manager.

```
<env>/<service-slug>/oidc-client
{"client_id": "<service id>", "client_secret": "...", "issuer_uri": "https://<identity-host>/realms/fintechbankx", "token_uri": "<issuer_uri>/protocol/openid-connect/token"}
```

1. `deploy/terraform` creates one empty secret container per entry of `realm/service-clients.json`, encrypted with the identity KMS key (tagged `fintechbankx.io/secrets=true` so External Secrets Operator may decrypt it).
2. `scripts/identity/publish-oidc-client-secrets.sh` fills the containers (dry run by default):

   ```bash
   scripts/identity/publish-oidc-client-secrets.sh --env dev \
     --issuer https://identity.dev.fintechbankx.example/realms/fintechbankx          # report only
   scripts/identity/publish-oidc-client-secrets.sh --env dev --issuer ... --apply  # fill empty ones
   ```

   It generates 48 random bytes per client with `openssl`, writes them through a private temporary file, and never prints a value. Existing values are kept unless `--rotate` is given.
3. The realm import Job reads the same entries (ExternalSecret `keycloak-realm-import`) and sets them as the client credentials in Keycloak.
4. Each service syncs its own entry with an ExternalSecret (ClusterSecretStore `aws-secrets-manager`, `remoteRef.key: <env>/<service-slug>/oidc-client`, properties `client_id`, `client_secret`) and uses `token_uri` for the client-credentials grant.

## Rotation

1. `publish-oidc-client-secrets.sh --env <env> --issuer ... --apply --rotate --only <service id>`.
2. Force-sync ExternalSecret `keycloak-realm-import` (annotate `force-sync=<timestamp>`) and re-run the realm import Job.
3. Force-sync the service's ExternalSecret and roll the deployment.

Between steps 2 and 3 the service holds the old value and its token requests fail; tokens it already holds stay valid for at most 5 minutes. Run the steps back to back, one service at a time. Follow-up (Proposed): Keycloak's client secret rotation policy keeps the previous secret valid for a grace period and removes that window.

## Who may read what

| Reader | Access |
|---|---|
| External Secrets Operator (IRSA, `external-secrets/external-secrets`) | `<env>/*` and decrypt with keys tagged `fintechbankx.io/secrets=true` (platform contract addendum) |
| Identity squad operators | write the containers (publish script), no read needed |
| Services | no direct AWS access to these secrets; only the Kubernetes Secret ESO writes in their namespace |
