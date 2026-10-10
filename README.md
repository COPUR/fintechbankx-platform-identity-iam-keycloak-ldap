# fintechbankx-platform-identity-iam-keycloak-ldap

## What this repository provides (Proposed)

The deployable identity platform of FinTechBankX: Keycloak realm `fintechbankx` on EKS, federated to a directory, with per-service OIDC clients. Nothing here is deployed yet; everything is **Proposed** until the Identity Platform Squad merges and releases it.

| Area | Path | Doc |
|---|---|---|
| Realm as code (roles, groups, 15 service clients with audience mappers, customer web and mobile, staff web PKCE clients (one user type each), FAPI 2.0 TPP policies, LDAP federation, token lifetimes, brute force, events) | `realm/` | [REALM_AS_CODE](docs/identity/REALM_AS_CODE.md) |
| Open-finance TPP onboarding (identity-owned; Dynamic Client Registration closed): TPP list, onboarding script run by the realm import Job, live drift check, token drill | `realm/tpp-clients.json`, `scripts/realm/onboard-tpp.mjs` | [REALM_AS_CODE](docs/identity/REALM_AS_CODE.md) |
| Keycloak 26.7.5 on EKS via the Keycloak Operator, kustomize base + dev/staging/prod overlays, realm import Job | `deploy/kustomize/` | [KEYCLOAK_ON_EKS](docs/identity/KEYCLOAK_ON_EKS.md) |
| Aurora PostgreSQL (terraform-modules `aurora-postgresql`), Secrets Manager containers, KMS | `deploy/terraform/` | [KEYCLOAK_ON_EKS](docs/identity/KEYCLOAK_ON_EKS.md) |
| OpenLDAP for dev/staging, corporate directory (AWS Managed Microsoft AD) for prod | `deploy/kustomize/components/openldap/` | [DIRECTORY_FEDERATION](docs/identity/DIRECTORY_FEDERATION.md) |
| Per-service client credential delivery to `<env>/<service-slug>/oidc-client` | `scripts/identity/` | [CLIENT_SECRET_DELIVERY](docs/identity/CLIENT_SECRET_DELIVERY.md) |
| CI: realm contract check, render drift, kustomize + kubeconform per overlay, terraform fmt/validate, shellcheck | `.github/workflows/identity-platform-validate.yml`, `scripts/ci/` | |

### How a service consumes it

- Issuer `https://<identity-host>/realms/fintechbankx`; JWKS in-cluster at `http://keycloak.identity.svc.cluster.local:8080/realms/fintechbankx/protocol/openid-connect/certs`.
- Validate `aud` contains your service id; map `realm_access.roles` (`customer`, `banker`, `loan_officer`, `admin`, `service`, `auditor`, `compliance_officer`) to `ROLE_*`.
- Your client id is your service id; read the credential with an ExternalSecret from `<env>/<service-slug>/oidc-client` (ClusterSecretStore `aws-secrets-manager`).
- To add a client or an audience, change `realm/service-clients.json` and run `node scripts/realm/render-realm.mjs` (PR to this repository).
- To onboard an open-finance TPP, add its spec to `realm/tpp-clients.json` (PR to this repository); the realm import Job creates the client with the `fbx_client_type` and, if authorised, `payments` scopes.

### Local checks

```bash
npm ci && npm test                       # validator unit tests
node scripts/realm/render-realm.mjs --check
node scripts/ci/check-realm.mjs
kustomize build deploy/kustomize/overlays/dev | kubeconform -strict -summary -
```

The legacy monolith seed under `k8s/envoy/`, `security/vault/` and `security/service-architecture/` is kept for reference only; it targets the monolith namespaces (`banking-production`) and is not part of the deployable path.

Bu repository, FinTechBankX DDD/EDA dönüşümünde **svc-idn-keycloak-ldap** servis yetkinliğinin kaynak kodunu, kontratlarını ve operasyonel guardrail'lerini içerir.

## Sorumluluk ve Sahiplik
| Alan | Değer |
|---|---|
| Organizasyon Modeli | Spotify Model (Tribe/Squad) |
| Tribe | Platform & Enablement Tribe |
| Squad | Identity Platform Squad |
| Repo Kümesi (Capability) | platform |
| Service ID | svc-idn-keycloak-ldap |
| Bounded Context | identity_access_management |
| Wave | 0 |
| Mimari Yaklaşım | DDD + Hexagonal + Event-Driven |

## Sorumluluk Sınırları
- Bu repo kendi bounded context domain modelinin tek yetkili sahibidir.
- Domain kuralları altyapıdan bağımsız tutulur; entegrasyonlar port/adapter katmanında yönetilir.
- API/Event kontratları geriye dönük uyumluluk kontrolleri ile korunur.
- Güvenlik guardrail'leri (mTLS, token doğrulama, idempotency, log hijyeni) CI/CD ile zorlanır.

## Kapsam
### In Scope
- identity_access_management bağlamına ait uygulama kodu, testler ve otomasyon.
- Bu servise ait OpenAPI/AsyncAPI veya şema artefaktları.
- Bu servisin çalışma zamanı operasyonları (gözlemlenebilirlik, release, rollback).

### Out of Scope
- Diğer bounded context'lerin iş kuralları ve veri sahipliği.
- Paylaşımlı DB anti-pattern'i; cross-context doğrudan tablo erişimi.
- Platform dışı gizli bilgi/anahtar yönetimi (merkezi policy dışında local hardcode).

## Mühendislik Standartları
- **TDD öncelikli** geliştirme, birim test + entegrasyon testi.
- **Clean Architecture**: Domain katmanı framework bağımsız.
- **12-Factor** ve environment-driven configuration.
- **FAPI odaklı güvenlik** (OIDC/OAuth2, mTLS, DPoP gereksinimleri ilgili servislerde).
- **PII güvenliği**: loglarda maskeleme, secret'ların source/env içine yazılmaması.

## Branching ve Release Akışı
- Uzun ömürlü branch'ler: `main`, `dev`, `staging`, `local`.
- Feature branch kuralı: `codex/<kisa-aciklama>`.
- Release yaklaşımı: PR + required status checks + tag tabanlı sürümleme.

## Dokümantasyon ve Referanslar
- [Enterprise Architecture Hub](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture)
- [Secure Microservices Architecture](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/architecture/overview/SECURE_MICROSERVICES_ARCHITECTURE.md)
- [Service Data Ownership Matrix](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/enterprisearchitecture/implementation-development/SERVICE_DATA_OWNERSHIP_MATRIX.md)
- [Service API Contracts Index](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/enterprisearchitecture/implementation-development/SERVICE_API_CONTRACTS_INDEX.md)
- [Transformation Plan](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/enterprisearchitecture/implementation-development/MICROSERVICES_TRANSFORMATION_PLAN.md)
- [Capability Map (PUML)](https://github.com/COPUR/fintechbankx-governance-architecture-enablement-enterprise-architecture/blob/main/docs/puml/service-mesh/enterprise-capability-map.puml)
- [Bu Repo Dokümantasyonu](./docs)

## Güvenlik ve Uyumluluk Notları
- Gerçek secret değerleri repo veya `.env` içinde tutulmaz.
- Secret üretim/rotasyon olayları merkezi log/SIEM'e taşınır.
- CI pipeline, anonimlik ve local-path sızıntısı kontrollerini bloklayıcı olarak çalıştırır.

## Katkı
- Katkı süreci için `CONTRIBUTING.md` ve squad runbook'ları izlenmelidir.
- PR'larda mimari kararlar ADR veya backlog referansı ile ilişkilendirilmelidir.

<!-- cell-architecture-start -->
## Cell-Based Architecture

This repository participates in the FinTechBankX cell-based resilience program.

- Plan: docs/architecture/CELL_BASED_ARCHITECTURE_IMPLEMENTATION_PLAN.md
- Backlog: docs/project-management/CELL_ARCHITECTURE_BACKLOG_BOARD.md
<!-- cell-architecture-end -->
