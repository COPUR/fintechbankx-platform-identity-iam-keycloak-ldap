# Migration Granularity Notes

- Repository: `fintechbankx-platform-identity-keycloak-ldap`
- Source monorepo: `enterprise-loan-management-system`
- Sync date: `2026-03-15`
- Sync branch: `chore/granular-source-sync-20260313`

## Applied Rules

- dir: `security/vault` -> `security/vault`
- dir: `security/secrets` -> `security/secrets`
- file: `security/service-architecture/service-mesh-config.yaml` -> `security/service-architecture/service-mesh-config.yaml`
- dir: `k8s/envoy` -> `k8s/envoy`
- file: `docs/enterprisearchitecture/compliance-security/ENTERPRISE_ANONYMITY_SECURITY_STANDARD.md` -> `docs/ENTERPRISE_ANONYMITY_SECURITY_STANDARD.md`

## Notes

- This is an extraction seed for bounded-context split migration.
- Follow-up refactoring may be needed to remove residual cross-context coupling.
- Build artifacts and local machine files are excluded by policy.

