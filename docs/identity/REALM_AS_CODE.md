# Realm as code: `fintechbankx` (Proposed)

Status: **Proposed**. Owner: Identity Platform Squad (svc-idn-keycloak-ldap).

## Files

| File | Role |
|---|---|
| `realm/service-clients.json` | Client registry: every service client (client id = service id), its service slug, namespace, service account and the audiences it may request; plus the channel clients (web, mobile, TPP template). Edit this first. |
| `scripts/realm/render-realm.mjs` | Renders the realm from the registry and the realm settings in the script. |
| `realm/fintechbankx-realm.json` | Rendered realm representation (Keycloak JSON), applied by keycloak-config-cli. Never edit by hand; CI fails on drift. |
| `realm/admin-permissions.json` | Fine-grained admin permissions (Keycloak 26 FGAP v2): which service client may administer the members of which group, with which scopes and why. |
| `scripts/realm/apply-admin-permissions.mjs` | Applies `realm/admin-permissions.json` through the admin REST API (second step of the import Job; keycloak-config-cli cannot import FGAP v2 permissions). Idempotent: looks up by name and path, creates or updates, never deletes. |
| `scripts/ci/check-realm.mjs` | Contract gate: roles, clients, audiences, FAPI policies, LDAP federation, no credential values, every placeholder supplied by the import Job, no realm-management role on a service client, admin permissions limited to non-staff groups. |

Change flow: edit the registry or the render script, run `node scripts/realm/render-realm.mjs`, run `node scripts/ci/check-realm.mjs` and `npm test`, open a PR. The realm import Job applies the merged file.

## What the realm contains

- **Realm roles** (lower-case, services upper-case them to `ROLE_*`): `customer`, `banker`, `loan_officer`, `admin`, `service`, `auditor`, `compliance_officer`.
- **Groups**: `/staff/fbx-banker`, `/staff/fbx-loan-officer`, `/staff/fbx-admin`, `/staff/fbx-auditor`, `/staff/fbx-compliance-officer` (filled by the LDAP group mapper, each grants the matching role) and `/customers` (role `customer`).
- **15 confidential service clients** (`svc-ln-loan-lifecycle`, `svc-pay-*`, `svc-cus-profile-kyc`, `svc-rsk-decisioning`, `svc-cmp-evidence`, `svc-of-*`): client credentials only (no browser, implicit, password or device grant), no refresh token, 5-minute access token, `fullScopeAllowed=false` with a scope mapping for `service` only, service account holding realm role `service`. Credential is the placeholder `$(env:FBX_OIDC_SECRET_<CLIENT_ID>)`, resolved at import from Secrets Manager `<env>/<service-slug>/oidc-client`.
- **Audience mappers** (platform contract addendum 2026-10-08): every calling client carries one `oidc-audience-mapper` per service id it may call, so `aud` contains the callee's service id. The registry records whether each audience is confirmed by the owning service thread or derived. Current edges:

  | Client | aud |
  |---|---|
  | `svc-ln-loan-lifecycle` | `svc-cus-profile-kyc` (confirmed) |
  | `svc-pay-initiation-settlement` | `svc-rsk-decisioning`, `svc-cmp-evidence`, `svc-of-consent-authorization`, `svc-of-payee-verification`, `svc-cus-profile-kyc` (kyc-status) (confirmed) |
  | `fintechbankx-web` (customers) | `svc-cus-profile-kyc` (confirmed); loan and the four payment services (derived) |
  | `fintechbankx-staff-web` (staff) | `svc-cus-profile-kyc` (confirmed); loan, the four payment services, `svc-rsk-decisioning`, `svc-cmp-evidence` (derived; risk and compliance moved here from `fintechbankx-web`) |
  | `fintechbankx-mobile` | `svc-cus-profile-kyc` (confirmed); loan and the four payment services (derived) |
  | TPP clients (`of-tpp-conformance-template`) | the six open-finance resource services (confirmed), `svc-of-consent-authorization` (derived) |
  | other service clients | none yet (no synchronous call found) |

- **First-party public clients**: authorization code + PKCE S256, no client credential, redirect URIs from the overlay, `fullScopeAllowed=false`. Each client serves one user type (registry `userType`), so a token from a customer channel can never carry a staff role and the other way round (security review 2026-10-08). DPoP is not required for first-party clients yet (contract addendum; Proposed for mobile later).

  | Client | Roles in the token | Scopes | Sessions |
  |---|---|---|---|
  | `fintechbankx-web` | `customer` only | `customer-id` default; **no** `offline_access` | realm SSO (30 min idle, 10 h max) |
  | `fintechbankx-mobile` | `customer` only | `customer-id` default; `offline_access` optional | offline token 14 days idle, 30 days max (client and realm) |
  | `fintechbankx-staff-web` | `banker`, `loan_officer`, `admin`, `auditor`, `compliance_officer` | no `customer-id`, no optional scopes (no offline tokens) | client session 15 min idle, 8 h max |

  Redirect, origin and post-logout URIs of the staff portal come from `FBX_STAFF_WEB_REDIRECT_URI`, `FBX_STAFF_WEB_ORIGIN` and `FBX_STAFF_WEB_POST_LOGOUT_REDIRECT_URI` (realm import ConfigMap, set per overlay; base value host `STAFF_APP_HOST`). A staff user who signs in to `fintechbankx-web` gets a token without roles, and a customer in `fintechbankx-staff-web` likewise. `check-realm.mjs` enforces the role split, the staff-only audiences (`svc-rsk-decisioning`, `svc-cmp-evidence`) and the session and offline limits.
- **Staff SSO client `svc-obs-grafana`** (registry section `ssoClients`): confidential, authorization code + PKCE S256, no implicit, password or client-credentials grant, policy `fbx-staff-sso-clients`. Redirect `<Grafana root>/login/generic_oauth` from the overlay (`FBX_GRAFANA_ROOT_URL`, e.g. `https://grafana.dev.fintechbankx.example`). A realm-role mapper puts `realm_access.roles` into the access token, ID token and userinfo; `fullScopeAllowed=false` with a scope mapping of `admin` and `auditor` only, so Grafana sees nothing else. Credential at `<env>/observability-grafana/oidc-client`. Grafana side (observability repo, Proposed):

  ```ini
  [auth.generic_oauth]
  enabled = true
  name = FinTechBankX
  client_id = svc-obs-grafana
  ; client credential from env GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET (ExternalSecret, property client_secret)
  auth_url = https://<identity-host>/realms/fintechbankx/protocol/openid-connect/auth
  token_url = http://keycloak.identity.svc.cluster.local:8080/realms/fintechbankx/protocol/openid-connect/token
  api_url = http://keycloak.identity.svc.cluster.local:8080/realms/fintechbankx/protocol/openid-connect/userinfo
  scopes = openid profile email
  use_pkce = true
  role_attribute_path = contains(realm_access.roles[*], 'admin') && 'Admin' || contains(realm_access.roles[*], 'auditor') && 'Viewer'
  role_attribute_strict = true
  ```

  | Realm role | Grafana role |
  |---|---|
  | `admin` | `Admin` (organisation admin; add `allow_assign_grafana_admin = true` and `'GrafanaAdmin'` in the path only if server admin is wanted) |
  | `auditor` | `Viewer` |
  | anything else | login refused (`role_attribute_strict`) |
- **Open-finance TPPs (FAPI 2.0)**: TPP access tokens are **DPoP-bound only** (RFC 9449). Client policy `fbx-open-finance-tpp-fapi2-dpop` applies Keycloak's built-in `fapi-2-dpop-security-profile` plus `fbx-open-finance-tpp-client-auth` (client authentication `private_key_jwt` only) to clients tagged `fbx.client-type=open-finance-tpp` with `fbx.tpp.token-binding=dpop`; together they enforce PAR, PKCE, DPoP, `private_key_jwt` and PS256. A separate policy applies the same two profiles to every Dynamic Client Registration request, because attribute conditions only match once a client exists. mTLS certificate-bound tokens (RFC 8705) and `tls_client_auth` are **not** supported: TLS ends at the Istio ingress gateway (mode SIMPLE, no client certificate requested) and Keycloak runs behind plain HTTP, so Keycloak never sees a TPP certificate (security review 2026-10-08 removed the former `fbx-open-finance-tpp-fapi2-mtls` policy). `check-realm.mjs` rejects `fbx.tpp.token-binding=mtls`, `tls.client.certificate.bound.access.tokens`, the `fapi-2-security-profile` and `client-x509` anywhere in the realm. `of-tpp-conformance-template` is a **disabled** reference client; real TPP clients are onboarded through consent-authorization, never committed. PAR request URIs live 60 s.
- **TPP scopes (request-to-pay PR #14, Proposed)**: client scope `payments` (`include.in.token.scope=true`, no claims) is an **optional** scope of TPP clients: the TPP requests `scope=payments` at PAR or token time and the payment services (request to pay, VRP, file payments) require it next to `aud`. Client scope `fbx-client-type-open-finance-tpp` is a **default** scope of TPP clients and adds the access-token claim `fbx_client_type=open-finance-tpp`; Keycloak 26 has no mapper that reads a client attribute, so the value is a hardcoded claim and `check-realm.mjs` fails when it differs from the carrying client's `fbx.client-type`, when any non-TPP client carries either scope, or when either becomes a realm default (a client created without explicit scopes would inherit it). Onboarding must assign both to every TPP authorised for payment services: realm defaults do not cover them.
- **Service client baseline policy** (`fbx-service-client-baseline`): client-secret or client-jwt authentication (no `client-x509`; service-to-service mTLS is the mesh's job, not Keycloak's); implicit and password grants rejected; full scope disabled.
- **Tokens and sessions**: access token 300 s; SSO idle 30 min, max 10 h; refresh tokens revoked on use (`revokeRefreshToken`, reuse 0); authorization code 60 s; offline sessions (mobile only) 14 days idle, 30 days max. Realm signs with RS256 (the Spring resource servers accept RS256 by default); FAPI clients are moved to PS256 by the FAPI profile.
- **Brute-force protection**: after 5 failures the account is locked temporarily, waits growing by 60 s up to 15 min. No permanent lockout, so an attacker cannot disable staff accounts; lockouts appear in the login events.
- **Password policy** (local accounts only; staff authenticate against the directory): length 14-128, upper, lower, digit, special, not username/email, history 12, expiry 90 days.
- **Events**: login events (90 days) and admin events with representation details (90 days), plus the `jboss-logging` listener so both reach the log pipeline.
- **User federation**: LDAP provider `fbx-directory`, `READ_ONLY`, import on, StartTLS or LDAPS through the Keycloak truststore, daily full and 15-minute changed-user sync; connection URL, bind DN, bind credential and the directory schema are placeholders (see `DIRECTORY_FEDERATION.md`).

Deviation from `keycloak-aaa-blueprint.md` (enterprise-architecture repo): the blueprint proposes three realms (`open-finance-prod`, `-internal`, `-sandbox`); the platform contract fixes one realm `fintechbankx` per environment. Sandbox isolation therefore comes from the environment (dev/staging), not from a realm.

## Customer user administration (fine-grained admin permissions)

The customer service (`svc-cus-profile-kyc`) links an identity user to a customer profile: `PUT /api/v1/customers/{id}/identity-link` (staff step) reads the user and sets the attribute `customer_id` with `GET` and `PUT /admin/realms/fintechbankx/users/{id}`. It does **not** hold `realm-management` `manage-users` (that would let it edit every user, staff included, and grant itself realm roles). Instead (security review 2026-10-08, option A):

- The realm sets `adminPermissionsEnabled: true` (FGAP v2) and has no `defaultGroups` (a default group would also be joined by every new service account).
- `realm/admin-permissions.json` defines client policy `fbx-customer-service-client` (the client `svc-cus-profile-kyc`, positive) and scope permission `fbx-customers-customer-service` (resource type Groups, resource `/customers`, scopes `view-members` and `manage-members`, decision strategy UNANIMOUS).
- `check-realm.mjs` rejects any `realm-management` role on a service client (service account, scope mapping or registry `adminRoles`) and any admin permission that is not group-scoped, targets `/staff`, uses another scope, or names a client that is not a registered service client.

**Customer users must be created in group `/customers`** (customer onboarding or whoever creates the Keycloak user). A user outside `/customers` is invisible to the customer service: `GET` and `PUT` answer 403.

Verified locally against Keycloak 26.7.5 (realm imported with the pinned keycloak-config-cli 6.5.1 jar, then the script; token of `svc-cus-profile-kyc` by client credentials):

| Call by the customer service | Customer user (in `/customers`) | Staff user |
|---|---|---|
| `GET /users/{id}`, `PUT /users/{id}` (set `customer_id`) | 200, 204 | 403, 403 |
| add realm role, move into `/staff`, remove from `/customers` | 403 | - |
| search, count, create users; list clients, roles, groups; impersonate | 403 | - |
| reset password, read credentials, log out, change email, disable, delete | **allowed** | 403 |

**Residual risk:** `manage-members` is all or nothing for a member, so the customer service can still reset passwords, send required actions, log out, change the email of, disable and delete *customer* users. It cannot touch staff, roles, groups or clients. Admin events (enabled, with representation) record every such call. Recommended follow-up (user decision, not done): move this permission to an identity-owned identity-link service that only sets `customer_id`, and let the customer service call that service instead of the admin API.

The script and config-cli are independent: a re-run of the import keeps the permissions (checked locally), and a permission removed from `admin-permissions.json` is **not** deleted from Keycloak (the script never deletes; remove it in the admin console under Permissions).

## Applying the realm

`deploy/kustomize/base/realm-import/job.yaml` runs keycloak-config-cli 6.5.1 (image pinned by digest) as an initContainer with `IMPORT_VARSUBSTITUTION_ENABLED=true`, then `apply-admin-permissions.mjs` in `node:22.22.0-alpine3.22` (pinned by digest), which receives only the bootstrap admin client credential. Non-secret inputs come from ConfigMap `keycloak-realm-import-env` (overlay-specific), secret inputs from ExternalSecret `keycloak-realm-import` (admin client, LDAP bind, 15 client credentials). keycloak-config-cli keeps remote state, so a client removed from Git is removed from Keycloak, while clients created outside Git (for example TPPs registered dynamically) are left alone.

**Removals on an existing realm.** keycloak-config-cli 6.5.1 with its defaults does not remove everything Git removes (checked locally by importing the previous realm and then this one):

- realm roles dropped from a client's scope mapping stay (`import.managed.scope-mapping=no-delete`; role removal is tied to `import.managed.client-scope=full`, which would also delete Keycloak's built-in client scopes such as `service_account` and strip `offline_access`, so it is not used). The Job's second step therefore removes every realm role the realm file no longer lists for a client (`reconcileScopeMappings` in `apply-admin-permissions.mjs`).
- a user's client roles are only reconciled for clients named in that user's `clientRoles`, and client scope mappings only when `clientScopeMappings` is present. The render therefore writes `clientRoles: {"realm-management": []}` on every service account and `clientScopeMappings: {}`; `check-realm.mjs` requires both.

With both in place, an upgrade from the previous realm removed `manage-users` from `svc-cus-profile-kyc` (service account and scope mapping) and the staff roles from `fintechbankx-web` and `fintechbankx-mobile`, and left the built-in client scopes intact.

KeycloakRealmImport (operator CR) is not used: it only creates a missing realm and never updates an existing one.

## Local evidence (2026-10-08)

Run against a local Keycloak 26.7.5 (same version as the CR) and OpenLDAP loaded with `deploy/kustomize/components/openldap/seed/50-fintechbankx-structure.ldif` plus one synthetic test user, using the keycloak-config-cli 6.5.1 jar extracted from the pinned image:

- Fresh import and repeated update import: exit 0 (about 7 s).
- Client credentials for all 15 service clients: token issued, `realm_access.roles=[service]`, `aud` equal to the registry.
- Wrong client credential: HTTP 401. Password grant on `fintechbankx-web`: rejected (`unauthorized_client`).
- Authorization request without PKCE on `fintechbankx-web`: rejected (`Missing parameter: code_challenge_method`); with S256: login page.
- LDAP full sync imported the test user into `/staff/fbx-loan-officer`; browser login with PKCE returned a token with role `loan_officer` and `aud` equal to the web client's registry audiences (no `account` audience).
- Six wrong logins: user temporarily locked. Login and admin events recorded.
- `svc-obs-grafana`: authorization request without PKCE rejected; code + PKCE login of an LDAP user in `fbx-admin` and `fbx-loan-officer` returned `realm_access.roles=["admin"]` in userinfo and ID token (scope mapping filters `loan_officer`); wrong client credential 401; client-credentials grant refused (`unauthorized_client`).
- TPP rules: changing the template to client-secret authentication rejected (`invalid_client_metadata`); a non-conforming Dynamic Client Registration rejected, a conforming one (`private_key_jwt`, DPoP-bound) accepted; front-channel authorization without PAR rejected (400).
- Gap found: a TPP client created through the admin API with non-conforming settings is accepted at creation (the attribute condition cannot match a client that does not exist yet); it is blocked on its first update and at the authorization endpoint. Onboard TPPs only through Dynamic Client Registration.

None of this is a deployment; it proves the realm file and the import path work with the pinned versions.
