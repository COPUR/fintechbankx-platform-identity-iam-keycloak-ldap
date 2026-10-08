# Realm as code: `fintechbankx` (Proposed)

Status: **Proposed**. Owner: Identity Platform Squad (svc-idn-keycloak-ldap).

## Files

| File | Role |
|---|---|
| `realm/service-clients.json` | Client registry: every service client (client id = service id), its service slug, namespace, service account and the audiences it may request; plus the channel clients (web, mobile, TPP template). Edit this first. |
| `scripts/realm/render-realm.mjs` | Renders the realm from the registry and the realm settings in the script. |
| `realm/fintechbankx-realm.json` | Rendered realm representation (Keycloak JSON), applied by keycloak-config-cli. Never edit by hand; CI fails on drift. |
| `scripts/ci/check-realm.mjs` | Contract gate: roles, clients, audiences, FAPI policies, LDAP federation, no credential values, every placeholder supplied by the import Job. |

Change flow: edit the registry or the render script, run `node scripts/realm/render-realm.mjs`, run `node scripts/ci/check-realm.mjs` and `npm test`, open a PR. The realm import Job applies the merged file.

## What the realm contains

- **Realm roles** (lower-case, services upper-case them to `ROLE_*`): `customer`, `banker`, `loan_officer`, `admin`, `service`, `auditor`, `compliance_officer`.
- **Groups**: `/staff/fbx-banker`, `/staff/fbx-loan-officer`, `/staff/fbx-admin`, `/staff/fbx-auditor`, `/staff/fbx-compliance-officer` (filled by the LDAP group mapper, each grants the matching role) and `/customers` (role `customer`).
- **15 confidential service clients** (`svc-ln-loan-lifecycle`, `svc-pay-*`, `svc-cus-profile-kyc`, `svc-rsk-decisioning`, `svc-cmp-evidence`, `svc-of-*`): client credentials only (no browser, implicit, password or device grant), no refresh token, 5-minute access token, `fullScopeAllowed=false` with a scope mapping for `service` only, service account holding realm role `service`. Credential is the placeholder `$(env:FBX_OIDC_SECRET_<CLIENT_ID>)`, resolved at import from Secrets Manager `<env>/<service-slug>/oidc-client`.
- **Audience mappers** (platform contract addendum 2026-10-08): every calling client carries one `oidc-audience-mapper` per service id it may call, so `aud` contains the callee's service id. The registry records whether each audience is confirmed by the owning service thread or derived. Current edges:

  | Client | aud |
  |---|---|
  | `svc-ln-loan-lifecycle` | `svc-cus-profile-kyc` (confirmed) |
  | `svc-pay-initiation-settlement` | `svc-rsk-decisioning`, `svc-cmp-evidence`, `svc-of-consent-authorization`, `svc-of-payee-verification` (confirmed) |
  | `fintechbankx-web` | `svc-cus-profile-kyc` (confirmed); loan, the four payment services, `svc-rsk-decisioning`, `svc-cmp-evidence` (derived) |
  | `fintechbankx-mobile` | `svc-cus-profile-kyc` (confirmed); loan and the four payment services (derived) |
  | TPP clients (`of-tpp-conformance-template`) | the six open-finance resource services (confirmed), `svc-of-consent-authorization` (derived) |
  | other service clients | none yet (no synchronous call found) |

- **First-party public clients** `fintechbankx-web` and `fintechbankx-mobile`: authorization code + PKCE S256, no client credential, redirect URIs from the overlay, end-user roles only. DPoP is not required for first-party clients yet (contract addendum; Proposed for mobile later).
- **Open-finance TPPs (FAPI 2.0)**: client policies apply Keycloak's built-in `fapi-2-dpop-security-profile` (DPoP-bound tokens) or `fapi-2-security-profile` (mTLS certificate-bound tokens) to clients tagged `fbx.client-type=open-finance-tpp` with `fbx.tpp.token-binding=dpop|mtls`; both enforce PAR, PKCE, confidential `private_key_jwt`/mTLS client authentication and PS256. A separate policy applies the DPoP profile to every Dynamic Client Registration request, because attribute conditions only match once a client exists. `of-tpp-conformance-template` is a **disabled** reference client; real TPP clients are onboarded through consent-authorization, never committed. PAR request URIs live 60 s.
- **Service client baseline policy** (`fbx-service-client-baseline`): client-secret, client-jwt or mTLS authentication; implicit and password grants rejected; full scope disabled.
- **Tokens and sessions**: access token 300 s; SSO idle 30 min, max 10 h; refresh tokens revoked on use (`revokeRefreshToken`, reuse 0); authorization code 60 s; offline sessions 30 days idle, 60 days max. Realm signs with RS256 (the Spring resource servers accept RS256 by default); FAPI clients are moved to PS256 by the FAPI profile.
- **Brute-force protection**: after 5 failures the account is locked temporarily, waits growing by 60 s up to 15 min. No permanent lockout, so an attacker cannot disable staff accounts; lockouts appear in the login events.
- **Password policy** (local accounts only; staff authenticate against the directory): length 14-128, upper, lower, digit, special, not username/email, history 12, expiry 90 days.
- **Events**: login events (90 days) and admin events with representation details (90 days), plus the `jboss-logging` listener so both reach the log pipeline.
- **User federation**: LDAP provider `fbx-directory`, `READ_ONLY`, import on, StartTLS or LDAPS through the Keycloak truststore, daily full and 15-minute changed-user sync; connection URL, bind DN, bind credential and the directory schema are placeholders (see `DIRECTORY_FEDERATION.md`).

Deviation from `keycloak-aaa-blueprint.md` (enterprise-architecture repo): the blueprint proposes three realms (`open-finance-prod`, `-internal`, `-sandbox`); the platform contract fixes one realm `fintechbankx` per environment. Sandbox isolation therefore comes from the environment (dev/staging), not from a realm.

## Applying the realm

`deploy/kustomize/base/realm-import/job.yaml` runs keycloak-config-cli 6.5.1 (image pinned by digest) with `IMPORT_VARSUBSTITUTION_ENABLED=true`. Non-secret inputs come from ConfigMap `keycloak-realm-import-env` (overlay-specific), secret inputs from ExternalSecret `keycloak-realm-import` (admin client, LDAP bind, 15 client credentials). keycloak-config-cli keeps remote state, so a client removed from Git is removed from Keycloak, while clients created outside Git (for example TPPs registered dynamically) are left alone.

KeycloakRealmImport (operator CR) is not used: it only creates a missing realm and never updates an existing one.

## Local evidence (2026-10-08)

Run against a local Keycloak 26.7.5 (same version as the CR) and OpenLDAP loaded with `deploy/kustomize/components/openldap/seed/50-fintechbankx-structure.ldif` plus one synthetic test user, using the keycloak-config-cli 6.5.1 jar extracted from the pinned image:

- Fresh import and repeated update import: exit 0 (about 7 s).
- Client credentials for all 15 service clients: token issued, `realm_access.roles=[service]`, `aud` equal to the registry.
- Wrong client credential: HTTP 401. Password grant on `fintechbankx-web`: rejected (`unauthorized_client`).
- Authorization request without PKCE on `fintechbankx-web`: rejected (`Missing parameter: code_challenge_method`); with S256: login page.
- LDAP full sync imported the test user into `/staff/fbx-loan-officer`; browser login with PKCE returned a token with role `loan_officer` and `aud` equal to the web client's registry audiences (no `account` audience).
- Six wrong logins: user temporarily locked. Login and admin events recorded.
- TPP rules: changing the template to client-secret authentication rejected (`invalid_client_metadata`); a non-conforming Dynamic Client Registration rejected, a conforming one (`private_key_jwt`, DPoP-bound) accepted; front-channel authorization without PAR rejected (400).
- Gap found: a TPP client created through the admin API with non-conforming settings is accepted at creation (the attribute condition cannot match a client that does not exist yet); it is blocked on its first update and at the authorization endpoint. Onboard TPPs only through Dynamic Client Registration.

None of this is a deployment; it proves the realm file and the import path work with the pinned versions.
