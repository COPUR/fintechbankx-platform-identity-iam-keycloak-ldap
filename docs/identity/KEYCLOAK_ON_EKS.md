# Keycloak on EKS (Proposed)

Nothing here is deployed. The manifests render and validate (`kustomize build` + `kubeconform -strict` per overlay); see the workflow `identity-platform-validate`.

## Layout

```
deploy/
  kustomize/
    operator/              Keycloak Operator 26.7.5 (upstream CRDs + Deployment, namespace identity)
    base/                  Keycloak CR, ExternalSecrets, PDB, HPA, realm import Job
    components/openldap/   OpenLDAP StatefulSet for dev/staging (+ Keycloak truststore patch)
    components/environment copies identity-environment into the resources (include last)
    overlays/{dev,staging,prod}
  terraform/               Aurora PostgreSQL + Secrets Manager containers + KMS key
realm/                     realm-as-code and client registry (kustomize component)
```

## Install order (per environment, by the platform pipeline)

1. Platform prerequisites (other repositories): EKS, the `identity` namespace with `istio-injection=enabled` and the mesh policies (mesh repo), External Secrets Operator with ClusterSecretStore `aws-secrets-manager`, cert-manager with ClusterIssuer `fintechbankx-internal-ca` and trust-manager publishing ConfigMap `fintechbankx-internal-ca` (dev/staging), Prometheus Operator CRDs (for the operator-created ServiceMonitor).
2. `deploy/terraform`: `terraform init -backend-config=environments/<env>.backend.hcl`, plan and apply with `environments/<env>.tfvars` (copy from the `.example`). Put output `keycloak_db_writer_endpoint` into `overlays/<env>/identity-environment.yaml` (`databaseHost`).
3. DBA bootstrap: with the RDS-managed admin credential (output `keycloak_db_master_secret_arn`) create role `keycloak_app` owning database `db_idn_keycloak_ldap_<env>` and schema `keycloak`; write `{"username","password"}` to `<env>/identity-keycloak/db-app`.
4. Write `<env>/identity-keycloak/bootstrap-admin-client` (`client_id`, `client_secret` of a fresh random value), `<env>/identity-keycloak/ldap-bind` (`bind_credential`) and in dev/staging `<env>/identity-openldap/admin` (`admin_credential`, `config_credential`).
5. `scripts/identity/publish-oidc-client-secrets.sh --env <env> --issuer https://<identity-host>/realms/fintechbankx --apply` (`CLIENT_SECRET_DELIVERY.md`).
6. `kubectl apply -k deploy/kustomize/operator` (once per cluster and Keycloak upgrade).
7. `kubectl apply -k deploy/kustomize/overlays/<env>` (or Argo CD). The realm import Job runs as an Argo CD PostSync hook; with plain kubectl delete and re-create it after each realm change.
8. After the first successful import, create a permanent admin path (identity squad, break-glass procedure) and rotate the bootstrap admin client.

## Runtime shape

| Concern | Setting |
|---|---|
| Version | Keycloak and operator 26.7.5 (`quay.io/keycloak/keycloak:26.7.5`); keycloak-config-cli 6.5.1 by digest. Mirror both into ECR and pin by digest before prod. |
| Replicas | 3 (prod/staging), 2 (dev); HPA on the CR scale subresource, CPU 70 %, prod max 12. |
| Spread | topologySpreadConstraints across `topology.kubernetes.io/zone` (hard) and hosts (soft). |
| Disruption | PDB `minAvailable: 2` (dev 1). |
| Database | Aurora PostgreSQL Serverless v2 via terraform-modules `aurora-postgresql`, Multi-AZ readers, KMS, `rds.force_ssl`, `sslmode=require`; pool 5-30 per pod (prod 40). |
| Cache | Keycloak 26 embedded Infinispan, JDBC_PING discovery through the database, JGroups data 7800 and failure detection 57800 between Keycloak pods with Keycloak's own mTLS. 7800 is declared by the operator Service `keycloak-discovery` (port name `tcp`), 57800 by `keycloak-jgroups-fd` (`tcp-jgroups-fd`) so Istio REGISTRY_ONLY routes both; the mesh must allow `identity/keycloak -> identity/keycloak` on 7800 and 57800. No `excludeInboundPorts` (contract addendum). |
| HTTP | 8080 plain HTTP inside the mesh (STRICT mTLS); TLS terminates at the Istio ingress gateway; `proxy.headers=xforwarded`; Service `keycloak` (`keycloak.identity.svc.cluster.local:8080`). |
| Hostname | `https://identity.<env>.fintechbankx.example` (prod `identity.fintechbankx.example`), strict; `backchannelDynamic` so services call Keycloak in-cluster while `iss` stays public. The public route only exposes `/realms/fintechbankx/` and `/resources/` (mesh VirtualService `fintechbankx-identity`); the admin console and master realm are not routed. |
| Health, metrics | management port 9000: `/health/live`, `/health/ready`, `/metrics` (Keycloak's default port; the 8081 contract port applies to Spring services). Operator-created ServiceMonitor; user event metrics and HTTP histograms on. |
| Tracing | OTLP gRPC to `otel-collector.observability.svc.cluster.local:4317`, 10 % parent-based sampling. |
| Logs | JSON console logs; login and admin events through `jboss-logging`. |
| NetworkPolicy | operator-managed policy on the Keycloak pods: 8080 from the ingress gateway, the service namespaces and the realm import Job; 9000 from `observability`. OpenLDAP: 389 from Keycloak only. Additive to the mesh repo's default-deny policies. |
| Identity | service accounts `keycloak`, `openldap`, `keycloak-realm-import`; no IRSA (no AWS API calls); tokens not auto-mounted. |

## Service integration

| Setting in a service | Value |
|---|---|
| `OIDC_ISSUER_URI` | `https://identity.<env>.fintechbankx.example/realms/fintechbankx` |
| `OIDC_JWK_SET_URI` | `http://keycloak.identity.svc.cluster.local:8080/realms/fintechbankx/protocol/openid-connect/certs` |
| audience | validate that `aud` contains the service's own id |
| client credentials | ExternalSecret from `<env>/<service-slug>/oidc-client` |
| roles | `realm_access.roles`, upper-cased to `ROLE_*` |

## Dependencies and resilience (cell plan)

| Dependency | Type | Behaviour when it fails |
|---|---|---|
| Aurora PostgreSQL | sync | Keycloak readiness fails; existing access tokens stay valid until expiry (5 min) because services verify signatures against cached JWKS. Aurora failover to the reader in another AZ takes about 30 s. |
| Directory (OpenLDAP / Managed AD) | sync, staff logins only | new staff logins fail; customers and client credentials unaffected. |
| Secrets Manager via ESO | async | existing Kubernetes Secrets keep working; only rotation stalls. |
| OTel collector | async | spans dropped. |

Services should cache the JWKS (Spring does) and fetch client-credential tokens with a 2 s connect / 5 s read timeout, retry twice with jitter, then fail closed. Drill evidence still needed (Proposed): kill one Keycloak pod under load (no failed token requests expected with 3 replicas), Aurora failover, directory outage, realm import re-run during traffic.

## Upgrades

Bump `KEYCLOAK_VERSION`, the image in `base/keycloak.yaml` and the three URLs in `operator/kustomization.yaml` together; re-run the local import test in `REALM_AS_CODE.md` against the new version before merging; `update.strategy: Auto` lets the operator choose a rolling or recreate update.
