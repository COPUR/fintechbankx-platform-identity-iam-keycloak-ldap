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
| `scripts/ci/check-realm.mjs` | Contract gate: roles, clients, audiences, FAPI policies, LDAP federation, no credential values, every placeholder supplied by the import Job, no realm-management role on a service client, admin permissions limited to non-staff groups, the TPP client-type rules, Dynamic Client Registration closed. With `--live` (admin API) or `--live-export <file>` (partial export) it checks the clients of a running realm instead (TPP drift check). |
| `scripts/realm/tpp-rules.mjs` | The TPP client-type rules shared by `check-realm.mjs` and the onboarding script (no dependencies, so the import Job can run them). |
| `realm/tpp-clients.json` | Open-finance TPP clients to onboard (one spec per TPP: client id, name, redirect URIs, JWKS, payment authorisation). Empty until the first TPP is approved. |
| `scripts/realm/onboard-tpp.mjs` | Creates or repairs TPP clients through the admin API from the realm template (last step of the import Job; also an operator CLI). Idempotent. |
| `scripts/realm/tpp-token-drill.mjs` | Drill: obtains a real DPoP-bound TPP access token (PAR, PSU login, consent, code) and checks `fbx_client_type`, `azp`, `scope`, `cnf.jkt`. |

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
- **Open-finance TPPs (FAPI 2.0)**: TPP access tokens are **DPoP-bound only** (RFC 9449). Client policy `fbx-open-finance-tpp-fapi2-dpop` applies Keycloak's built-in `fapi-2-dpop-security-profile` plus `fbx-open-finance-tpp-client-auth` (client authentication `private_key_jwt` only) to every client tagged `fbx.client-type=open-finance-tpp`; its only condition is that attribute. Together they enforce PAR, PKCE, DPoP, `private_key_jwt` and PS256. The attribute `fbx.tpp.token-binding=dpop` is informational for Keycloak (no policy reads it); `check-realm.mjs` requires it on every TPP client and rejects `mtls` on any client. Dynamic Client Registration is closed (see below); policy `fbx-open-finance-tpp-dynamic-registration` still applies the same two profiles to any registration request, as defence in depth, because attribute conditions only match once a client exists. mTLS certificate-bound tokens (RFC 8705) and `tls_client_auth` are **not** supported: TLS ends at the Istio ingress gateway (mode SIMPLE, no client certificate requested) and Keycloak runs behind plain HTTP, so Keycloak never sees a TPP certificate (security review 2026-10-08 removed the former `fbx-open-finance-tpp-fapi2-mtls` policy). `check-realm.mjs` rejects `fbx.tpp.token-binding=mtls`, `tls.client.certificate.bound.access.tokens`, the `fapi-2-security-profile` and `client-x509` anywhere in the realm. `of-tpp-conformance-template` is a **disabled** reference client and the template every TPP client is built from; real TPP clients are onboarded by the identity platform (below) and never appear in the realm file. PAR request URIs live 60 s.
- **TPP scopes (request-to-pay PR #14, Proposed)**: client scope `payments` (`include.in.token.scope=true`, no claims) is an **optional** scope of TPP clients: the TPP requests `scope=payments` at PAR or token time and the payment services (request to pay, VRP, file payments) require it next to `aud`. Client scope `fbx-client-type-open-finance-tpp` is a **default** scope of TPP clients and adds the access-token claim `fbx_client_type=open-finance-tpp`; Keycloak 26 has no mapper that reads a client attribute, so the value is a hardcoded claim and `check-realm.mjs` fails when it differs from the carrying client's `fbx.client-type`, when any non-TPP client carries either scope, or when either becomes a realm default (a client created without explicit scopes would inherit it). The client-type claim is mandatory on every TPP client (services fail closed when it is absent): `check-realm.mjs` fails for any client tagged `fbx.client-type=open-finance-tpp` without `fbx-client-type-open-finance-tpp` (by name) as a **default** scope, with `payments` as a default scope, or without `fbx.tpp.token-binding=dpop`, and for any client that emits `fbx_client_type` through its own protocol mapper. In the realm file that covers only the template; runtime TPPs are covered below.
- **Runtime TPP onboarding (Proposed, owned by the identity platform)**: identity owns the creation of every open-finance TPP client; consent-authorization (or the TPP onboarding desk) is the caller and asks for a TPP by pull request adding one spec to `realm/tpp-clients.json`. No open-finance repository creates TPP clients itself (no Dynamic Client Registration or admin API calls). The last step of the realm import Job (`tpp-onboarding`, bootstrap admin client, same credential as the earlier steps) runs `scripts/realm/onboard-tpp.mjs --tpps realm/tpp-clients.json --verify-live` on every sync. For each TPP the script builds the client from `of-tpp-conformance-template`, so it carries:
  1. attributes `fbx.client-type=open-finance-tpp` (the FAPI 2.0 DPoP policy above applies on this attribute alone) and `fbx.tpp.token-binding=dpop`;
  2. client scope `fbx-client-type-open-finance-tpp` as a **default** client scope;
  3. client scope `payments` as an **optional** client scope only when the spec says `paymentServices.authorised: true` with an authorisation reference (stored as `fbx.tpp.payment-services-reference`); otherwise no `payments`.

  A spec names the TPP only (`clientId` `of-tpp-<kebab>`, `name`, https `redirectUris`, `jwksUri` or a public `jwks`, `paymentServices`); any other field, a private JWK member, an http or wildcard redirect URI is refused. The script refuses before any write a client that would break the rules (`scripts/realm/tpp-rules.mjs`), refuses to retype an existing client of another `fbx.client-type`, and is idempotent (update in place, exact default and optional scope lists, nothing else deleted). A new client is created disabled, updated once so Keycloak's open-finance-tpp client policies check it, given its scopes, verified, and only then enabled; on any failure it is deleted again. `--verify-live` then fails the Job when any client of the running realm tagged `open-finance-tpp` breaks the rules, or when a non-TPP client carries a TPP scope or emits `fbx_client_type`.

  **Credential.** The script needs `manage-clients`. It runs with the import Job's bootstrap admin client, which already holds it, instead of a new standing client: no service client gets a `realm-management` role (`check-realm.mjs` keeps `ADMIN_ROLES_ALLOWED` empty, no exception added), and TPPs are only created from reviewed Git changes. An operator may run the same CLI with that credential for break-glass (`--tpp <spec.json>`, `--dry-run` prints the client without calling Keycloak). A dedicated onboarding client with an FGAP v2 Clients permission was not chosen: a permission can only name existing clients, so creating new ones needs a Clients `manage` permission over all clients (which would also cover the service clients) or a `realm-management` role such as `create-client` (whether FGAP v2 needs both was not verified).

  **What enforces the guarantee, per creation path** (checked locally against Keycloak 26.7.5, see "Local evidence (2026-10-10)"):

  | Path | Enforcement |
  |---|---|
  | Realm file (`realm/fintechbankx-realm.json`) | `check-realm.mjs` in CI: every client tagged `open-finance-tpp` has the default client-type scope, `payments` optional only, DPoP binding; no client-level `fbx_client_type` mapper. |
  | Onboarding script (`realm/tpp-clients.json`, import Job) | Clients built from the template; same rules checked before the first write and after the last (`tpp-rules.mjs`); a new client stays disabled until verified, else is deleted. Re-run on every sync, so a scope removed by hand comes back. |
  | Dynamic Client Registration | **Closed.** Client policy `fbx-dynamic-client-registration-closed` (condition `client-updater-context` `ByAnonymous`, `ByInitialAccessToken`, `ByRegistrationAccessToken`; profile `fbx-reject-request`, executor `reject-request`) rejects every registration and every update by registration access token (403 `invalid_request`). Reason: with an initial access token Keycloak registered a client tagged `open-finance-tpp` without the client-type scope; registration policies can forbid a scope (Allowed Client Scopes) but never require one, and Keycloak has no stock executor that adds a default scope. The registration policies are also declared in the realm file (Keycloak's default set): anonymous Trusted Hosts with no trusted host, Allowed Client Scopes with realm defaults only (never `payments` or the client-type scope), Allowed Protocol Mapper Types without `oidc-hardcoded-claim-mapper` (so a registered client cannot emit `fbx_client_type`). `check-realm.mjs` fails when any of this is weakened. No post-registration reconciler exists; reopening DCR needs one first. |
  | Admin console or any other admin API caller | Not prevented at creation (Keycloak checks the open-finance-tpp client policies only once the client exists, and no stock client policy can require a scope at token time: the `client-scopes` condition only votes on requests that carry a scope, so a `reject-request` policy would also reject compliant TPPs at PAR and on updates). Detected by the `--verify-live` step on every sync and by `check-realm.mjs --live`; repaired by adding the TPP to `realm/tpp-clients.json`. Such a client gets tokens without the claim (drill case E), which request to pay and the gateway refuse (fail closed per their contract; not verified in this repository). |

  **Live drift check.** `node scripts/ci/check-realm.mjs --live` (env `KEYCLOAK_URL` and the `KEYCLOAK_*` credential variables of `apply-admin-permissions.mjs`, realm `fintechbankx` or `--realm`) or `--live-export <file>` (output of `POST /admin/realms/fintechbankx/partial-export?exportClients=true`, or of `GET .../clients`) exits 1 when a client tagged `open-finance-tpp` lacks the default client-type scope or breaks another TPP rule. It runs in every realm import (`--verify-live`). A scheduled check between syncs is Proposed: a CronJob running the same command needs a read-only credential (`view-clients`), which would be the first `realm-management` role on a client and therefore needs an allow-listed exception in `check-realm.mjs` and the owner's decision; until then, run it from the operator workstation or re-sync.

  **TPP token drill** (`scripts/realm/tpp-token-drill.mjs`, Proposed for every environment before cohort entry): against a non-production Keycloak with this realm and the TPP onboarded, with a test customer in `/customers`, it runs PAR with `private_key_jwt`, the PSU login and consent, the code exchange with PKCE and a DPoP proof, decodes the access token and requires `token_type=DPoP`, `fbx_client_type=open-finance-tpp`, `azp` equal to the TPP client id, `cnf.jkt` equal to the DPoP key thumbprint, and `payments` in `scope` exactly when an authorised TPP requested it (`DRILL_EXPECT_PAYMENTS`). The repository has no Keycloak test harness in CI and no container runtime was available, so this drill is the integration evidence; its assertion is unit-tested (`scripts/validation/test/tpp-token-drill.test.mjs`).

  **Request-to-pay cohort entry depends on this.** The mesh cut-over (mesh repo `gateway.cutovers` `rtp-cutover`, runbook RUNBOOK-EXTRACT-pay-request-to-pay) routes on the validated token's `azp`, and request to pay rejects tokens without the client-type claim. A TPP client id may enter `rtp-cutover-cohort` (runbook step 3, the first step that moves TPP traffic) only after identity has onboarded it through `realm/tpp-clients.json`, the import Job's `--verify-live` step has passed in that environment, and the TPP token drill has passed for that client (cases A and C or D below). Status: implemented here and drilled locally only; not deployed.
- **Service client baseline policy** (`fbx-service-client-baseline`): client-secret or client-jwt authentication (no `client-x509`; service-to-service mTLS is the mesh's job, not Keycloak's); implicit and password grants rejected; full scope disabled.
- **Tokens and sessions**: access token 300 s; SSO idle 30 min, max 10 h; refresh tokens revoked on use (`revokeRefreshToken`, reuse 0); authorization code 60 s; offline sessions (mobile only) 14 days idle, 30 days max. Realm signs with RS256 (the Spring resource servers accept RS256 by default); FAPI clients are moved to PS256 by the FAPI profile.
- **Brute-force protection**: after 5 failures the account is locked temporarily, waits growing by 60 s up to 15 min. No permanent lockout, so an attacker cannot disable staff accounts; lockouts appear in the login events.
- **Password policy** (local accounts only; staff authenticate against the directory): length 14-128, upper, lower, digit, special, not username/email, history 12, expiry 90 days.
- **Events**: login events (90 days) and admin events with representation details (90 days), plus the `jboss-logging` listener so both reach the log pipeline. The Keycloak CR sets `spi-events-listener--jboss-logging--include-representation=true`, so admin event log lines also carry the representation (the observability alert `KeycloakServiceAccountAdminEventOutOfScope` needs it to see a user disable or a credential change). Those representations can carry personal data (username, email, names, `customer_id`); they are subject to the collector privacy processors and the Loki retention and access rules.
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

`deploy/kustomize/base/realm-import/job.yaml` runs keycloak-config-cli 6.5.1 (image pinned by digest) as an initContainer with `IMPORT_VARSUBSTITUTION_ENABLED=true`, then `apply-admin-permissions.mjs` (initContainer) and `onboard-tpp.mjs --verify-live` (container), both in `node:22.22.0-alpine3.22` (pinned by digest) and receiving only the bootstrap admin client credential. Non-secret inputs come from ConfigMap `keycloak-realm-import-env` (overlay-specific), secret inputs from ExternalSecret `keycloak-realm-import` (admin client, LDAP bind, 15 client credentials). keycloak-config-cli keeps remote state, so a client removed from Git is removed from Keycloak, while clients created outside the realm file (the onboarded TPPs) are left alone. The script never deletes a TPP client: a TPP removed from `realm/tpp-clients.json` must be disabled or deleted by hand (offboarding is not automated).

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
- Gap found: a TPP client created through the admin API with non-conforming settings is accepted at creation (the attribute condition cannot match a client that does not exist yet); it is blocked on its first update and at the authorization endpoint. (Superseded 2026-10-10: DCR is closed; `onboard-tpp.mjs` creates the client disabled and updates it once so the policies check it before it is enabled.)

None of this is a deployment; it proves the realm file and the import path work with the pinned versions.

## Local evidence (2026-10-10): TPP client-type guarantee

Keycloak 26.7.5 started locally from the release archive (JVM, dev mode; no container runtime was available), realm imported with the keycloak-config-cli 6.5.1 jar, LDAP provider disabled for the drill (no directory running; the test customer is a local user in `/customers`). Synthetic TPPs only (`*.drill.example`).

- Before the change: anonymous DCR 403 (Trusted Hosts); DCR with an initial access token asking for `fbx-client-type-open-finance-tpp` or `payments` 403 (Allowed Client Scopes) and for a hardcoded `fbx_client_type` mapper 403 (Allowed Protocol Mapper Types), **but** a client tagged `fbx.client-type=open-finance-tpp` without the scope was registered (201).
- After the change: every registration (anonymous, initial access token, OIDC and Keycloak endpoints) and an update by registration access token answer 403 `invalid_request`; admin API creation still works. Fresh import and re-import give exactly the ten declared registration policies (no duplicates); after a trusted host was added to Trusted Hosts, `payments` allowed in an extra Allowed Client Scopes policy and the DCR client policy switched off in the console, the next import cleared the trusted host and the allowed scope and switched the policy back on (the extra policy component itself stayed: keycloak-config-cli does not delete components it did not create).
- `onboard-tpp.mjs`: two TPPs created (one authorised for payments), second run `updated` without scope changes; after removing the client-type scope and moving `payments` to default by hand, the next run repaired both; a spec setting scopes and a client id held by a service-type client were refused (exit 1). `--verify-live` and `check-realm.mjs --live` failed on the earlier DCR-registered client (`of-tpp-dcr2: open-finance-tpp clients must carry client scope fbx-client-type-open-finance-tpp as a default scope`) and passed once it was deleted; `--live-export` on a partial export agreed.
- TPP token drill (PAR, login, consent, DPoP-bound code exchange):

  | Case | Result |
  |---|---|
  | A authorised TPP, `scope=openid payments` | `token_type=DPoP`, `azp=of-tpp-drill-pay`, `fbx_client_type=open-finance-tpp`, `scope=openid payments`, `cnf.jkt` matches |
  | B authorised TPP, `scope=openid` | same, `scope=openid` |
  | C TPP not authorised, `scope=openid payments` | PAR refused: `invalid_request` "Invalid scopes" |
  | D TPP not authorised, `scope=openid` | `fbx_client_type=open-finance-tpp`, `scope=openid` |
  | E negative control: client-type scope removed by hand | token issued **without** `fbx_client_type`; drill exit 1 |
  | F after `onboard-tpp.mjs` re-run | scope restored, drill passes |

