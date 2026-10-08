# Documentation

Service-level architecture, contracts, and test references for `fintechbankx-platform-identity-iam-keycloak-ldap`.

- [Realm as code](identity/REALM_AS_CODE.md): realm `fintechbankx`, client registry, audiences, FAPI 2.0 policies, local import evidence
- [Keycloak on EKS](identity/KEYCLOAK_ON_EKS.md): operator, overlays, Aurora, install order, service integration, resilience
- [Directory federation](identity/DIRECTORY_FEDERATION.md): OpenLDAP (dev/staging), AWS Managed Microsoft AD (prod), group-to-role mapping
- [Client credential delivery](identity/CLIENT_SECRET_DELIVERY.md): `<env>/<service-slug>/oidc-client`, publish script, rotation
- [Cell-based architecture plan](architecture/CELL_BASED_ARCHITECTURE_IMPLEMENTATION_PLAN.md)
- [Publication Guardrails](publication/PUBLICATION_GUARDRAILS.md)
