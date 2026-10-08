#!/usr/bin/env node
// Renders realm/fintechbankx-realm.json from the realm settings below and the
// client registry realm/service-clients.json (service clients, channel
// clients, audiences). Edit the registry or this file, never the JSON by
// hand; CI fails when the committed JSON differs from the render.
//
// usage: node scripts/realm/render-realm.mjs [--check]
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const checkOnly = process.argv.includes("--check");
const manifest = JSON.parse(fs.readFileSync(`${repo}/realm/service-clients.json`, "utf8"));
const env = (n) => `$(env:${n})`;
const secretEnv = (id) => "FBX_OIDC_SECRET_" + id.toUpperCase().replace(/-/g, "_");

const roles = [
  ["customer", "Retail or corporate customer (PSU) using first-party channels."],
  ["banker", "Branch or relationship banker (staff, LDAP group fbx-banker)."],
  ["loan_officer", "Credit and loan officer (staff, LDAP group fbx-loan-officer)."],
  ["admin", "Platform or business administrator (staff, LDAP group fbx-admin)."],
  ["service", "Machine identity of a FinTechBankX service (client-credentials service accounts only)."],
  ["auditor", "Internal or external auditor, read-only evidence access (staff, LDAP group fbx-auditor)."],
  ["compliance_officer", "Compliance and AML officer (staff, LDAP group fbx-compliance-officer)."]
];

const staffGroups = [
  ["fbx-banker", ["banker"]],
  ["fbx-loan-officer", ["loan_officer"]],
  ["fbx-admin", ["admin"]],
  ["fbx-auditor", ["auditor"]],
  ["fbx-compliance-officer", ["compliance_officer"]]
];

const audienceMappers = (audiences) => audiences.map((aud) => ({
  name: `aud-${aud}`,
  protocol: "openid-connect",
  protocolMapper: "oidc-audience-mapper",
  consentRequired: false,
  config: {
    "included.client.audience": aud,
    "access.token.claim": "true",
    "id.token.claim": "false",
    "introspection.token.claim": "true",
    "lightweight.claim": "false"
  }
}));
// End-user id claim for resource servers: user attribute customer_id (set by
// customer onboarding, admin-edit only) -> access-token claim customer_id.
// Default scope for the channel clients, the TPP template and, via
// defaultDefaultClientScopes, every TPP client created by registration.
const CUSTOMER_ID_SCOPE = "customer-id";
const customerIdScope = {
  name: CUSTOMER_ID_SCOPE,
  description: "Adds the end user's customer_id (customer profile id) to access tokens; absent for staff and service accounts.",
  protocol: "openid-connect",
  attributes: { "include.in.token.scope": "false", "display.on.consent.screen": "false" },
  protocolMappers: [{
    name: "customer_id",
    protocol: "openid-connect",
    protocolMapper: "oidc-usermodel-attribute-mapper",
    consentRequired: false,
    config: {
      "user.attribute": "customer_id",
      "claim.name": "customer_id",
      "jsonType.label": "String",
      "multivalued": "false",
      "aggregate.attrs": "false",
      "access.token.claim": "true",
      "id.token.claim": "false",
      "userinfo.token.claim": "true",
      "introspection.token.claim": "true",
      "lightweight.claim": "false"
    }
  }]
};
const ALL_USERS = { view: ["admin", "user"], edit: ["admin", "user"] };
// Full user-profile configuration (Keycloak 26 defaults plus customer_id);
// keycloak-config-cli replaces the realm's profile with it.
const userProfile = {
  attributes: [
    { name: "username", displayName: "${username}", validations: { length: { min: 3, max: 255 }, "username-prohibited-characters": {}, "up-username-not-idn-homograph": {} }, permissions: ALL_USERS, multivalued: false },
    { name: "email", displayName: "${email}", validations: { email: {}, length: { max: 255 } }, required: { roles: ["user"] }, permissions: ALL_USERS, multivalued: false },
    { name: "firstName", displayName: "${firstName}", validations: { length: { max: 255 }, "person-name-prohibited-characters": {} }, required: { roles: ["user"] }, permissions: ALL_USERS, multivalued: false },
    { name: "lastName", displayName: "${lastName}", validations: { length: { max: 255 }, "person-name-prohibited-characters": {} }, required: { roles: ["user"] }, permissions: ALL_USERS, multivalued: false },
    { name: "customer_id", displayName: "Customer id", validations: { length: { min: 1, max: 64 }, pattern: { pattern: "^[A-Za-z0-9-]+$", "error-message": "customer_id: letters, digits and hyphens only" } }, permissions: { view: ["admin", "user"], edit: ["admin"] }, multivalued: false, group: "user-metadata" }
  ],
  groups: [{ name: "user-metadata", displayHeader: "User metadata", displayDescription: "Attributes, which refer to user metadata" }]
};
const channel = Object.fromEntries(manifest.channelClients.map((c) => [c.clientId, c]));

// Staff SSO clients (e.g. Grafana): confidential, authorization code + PKCE,
// realm roles exposed in ID token and userinfo for the tool's role mapping.
const ssoClients = (manifest.ssoClients || []).map((c) => ({
  clientId: c.clientId,
  name: c.displayName,
  description: `Confidential staff SSO client (authorization code + PKCE S256). Credential delivered via Secrets Manager <env>/${c.serviceSlug}/oidc-client.`,
  enabled: true,
  protocol: "openid-connect",
  publicClient: false,
  clientAuthenticatorType: "client-secret",
  secret: env(secretEnv(c.clientId)),
  standardFlowEnabled: true,
  implicitFlowEnabled: false,
  directAccessGrantsEnabled: false,
  serviceAccountsEnabled: false,
  frontchannelLogout: true,
  consentRequired: false,
  fullScopeAllowed: false,
  rootUrl: env(c.redirectPathEnv),
  baseUrl: env(c.redirectPathEnv),
  redirectUris: [`${env(c.redirectPathEnv)}/login/generic_oauth`],
  webOrigins: [env(c.redirectPathEnv)],
  attributes: {
    "fbx.client-type": "staff-sso",
    "fbx.service-slug": c.serviceSlug,
    "fbx.namespace": c.namespace,
    "pkce.code.challenge.method": "S256",
    "post.logout.redirect.uris": `${env(c.redirectPathEnv)}/login`,
    "use.refresh.tokens": "true",
    "oauth2.device.authorization.grant.enabled": "false",
    "oidc.ciba.grant.enabled": "false"
  },
  protocolMappers: [
    {
      name: "realm-roles-userinfo",
      protocol: "openid-connect",
      protocolMapper: "oidc-usermodel-realm-role-mapper",
      consentRequired: false,
      config: {
        "claim.name": "realm_access.roles",
        "jsonType.label": "String",
        multivalued: "true",
        "access.token.claim": "true",
        "id.token.claim": "true",
        "userinfo.token.claim": "true",
        "introspection.token.claim": "true"
      }
    }
  ],
  defaultClientScopes: ["basic", "web-origins", "acr", "profile", "email"],
  optionalClientScopes: []
}));

const serviceClients = manifest.clients.map((c) => ({
  clientId: c.clientId,
  name: c.displayName,
  description: `Confidential client-credentials client for ${c.clientId} (namespace ${c.namespace}, service account ${c.serviceAccount}). Credential delivered via Secrets Manager <env>/${c.serviceSlug}/oidc-client.`,
  enabled: true,
  protocol: "openid-connect",
  publicClient: false,
  bearerOnly: false,
  clientAuthenticatorType: "client-secret",
  secret: env(secretEnv(c.clientId)),
  standardFlowEnabled: false,
  implicitFlowEnabled: false,
  directAccessGrantsEnabled: false,
  serviceAccountsEnabled: true,
  frontchannelLogout: false,
  consentRequired: false,
  fullScopeAllowed: false,
  redirectUris: [],
  webOrigins: [],
  attributes: {
    "fbx.client-type": "service",
    "fbx.service-slug": c.serviceSlug,
    "fbx.namespace": c.namespace,
    "access.token.lifespan": "300",
    "client_credentials.use_refresh_token": "false",
    "use.refresh.tokens": "false",
    "oauth2.device.authorization.grant.enabled": "false",
    "oidc.ciba.grant.enabled": "false"
  },
  protocolMappers: audienceMappers(c.audiences),
  defaultClientScopes: ["basic", "roles"],
  optionalClientScopes: []
}));

// First-party public clients. Each serves one user type (registry userType):
// customer clients map only the customer role and add the customer-id scope;
// the staff client maps only the staff roles, has short sessions and no
// optional scopes. Offline tokens only where the registry says offlineAccess
// (mobile), with client offline-session limits.
const STAFF_ROLES = ["banker", "loan_officer", "admin", "auditor", "compliance_officer"];
const rolesOfUserType = (t) => (t === "staff" ? STAFF_ROLES : ["customer"]);
const publicClient = (clientId, name, redirectEnv, originEnv, logoutEnv) => {
  const entry = channel[clientId];
  const staff = entry.userType === "staff";
  return {
    clientId,
    name,
    description: `First-party public client (authorization code + PKCE S256, no client credential). ${name}; ${staff ? "staff" : "customer"} roles only.`,
    enabled: true,
    protocol: "openid-connect",
    publicClient: true,
    standardFlowEnabled: true,
    implicitFlowEnabled: false,
    directAccessGrantsEnabled: false,
    serviceAccountsEnabled: false,
    frontchannelLogout: true,
    // Only this client's user-type roles reach the token (scopeMappings
    // below); no account-console or realm-management roles, so aud stays the
    // service list.
    fullScopeAllowed: false,
    redirectUris: [env(redirectEnv)],
    webOrigins: originEnv ? [env(originEnv)] : [],
    attributes: Object.assign({
      "fbx.client-type": "first-party-public",
      "fbx.user-type": entry.userType,
      "pkce.code.challenge.method": "S256",
      "require.pushed.authorization.requests": "false",
      "use.refresh.tokens": "true",
      "oauth2.device.authorization.grant.enabled": "false",
      "oidc.ciba.grant.enabled": "false"
    },
    logoutEnv ? { "post.logout.redirect.uris": env(logoutEnv) } : {},
    staff ? { "client.session.idle.timeout": "900", "client.session.max.lifespan": "28800" } : {},
    entry.offlineAccess ? { "client.offline.session.idle.timeout": "1209600", "client.offline.session.max.lifespan": "2592000" } : {}),
    protocolMappers: audienceMappers(entry.audiences),
    defaultClientScopes: ["basic", "web-origins", "acr", "profile", "roles", "email", ...(staff ? [] : [CUSTOMER_ID_SCOPE])],
    optionalClientScopes: entry.offlineAccess ? ["offline_access"] : []
  };
};

const tppTemplate = {
  clientId: "of-tpp-conformance-template",
  name: "Open Finance TPP conformance template (disabled)",
  description: "Disabled reference client showing the settings every onboarded TPP client must carry. Real TPP clients are registered through the consent-authorization onboarding flow, never committed here.",
  enabled: false,
  protocol: "openid-connect",
  publicClient: false,
  clientAuthenticatorType: "client-jwt",
  standardFlowEnabled: true,
  implicitFlowEnabled: false,
  directAccessGrantsEnabled: false,
  serviceAccountsEnabled: false,
  consentRequired: true,
  fullScopeAllowed: false,
  frontchannelLogout: false,
  redirectUris: ["https://tpp.example/callback"],
  webOrigins: [],
  attributes: {
    "fbx.client-type": "open-finance-tpp",
    "fbx.tpp.token-binding": "dpop",
    "require.pushed.authorization.requests": "true",
    "dpop.bound.access.tokens": "true",
    "pkce.code.challenge.method": "S256",
    "use.jwks.url": "true",
    "jwks.url": "https://tpp.example/.well-known/jwks.json",
    "token.endpoint.auth.signing.alg": "PS256",
    "id.token.signed.response.alg": "PS256",
    "access.token.signed.response.alg": "PS256",
    "authorization.signed.response.alg": "PS256",
    "request.object.signature.alg": "PS256",
    "access.token.lifespan": "300",
    "use.refresh.tokens": "true",
    "oauth2.device.authorization.grant.enabled": "false",
    "oidc.ciba.grant.enabled": "false"
  },
  protocolMappers: audienceMappers(channel["of-tpp-conformance-template"].audiences),
  defaultClientScopes: ["basic", "acr", "roles", CUSTOMER_ID_SCOPE],
  optionalClientScopes: []
};

const attrMapper = (name, ldapAttr, modelAttr, mandatory) => ({
  name,
  providerId: "user-attribute-ldap-mapper",
  subComponents: {},
  config: {
    "ldap.attribute": [ldapAttr],
    "user.model.attribute": [modelAttr],
    "read.only": ["true"],
    "always.read.value.from.ldap": ["true"],
    "is.mandatory.in.ldap": [mandatory ? "true" : "false"],
    "is.binary.attribute": ["false"],
    "attribute.force.default": ["false"]
  }
});

const realm = {
  realm: "fintechbankx",
  displayName: "FinTechBankX",
  enabled: true,
  sslRequired: "external",
  registrationAllowed: false,
  registrationEmailAsUsername: false,
  rememberMe: false,
  verifyEmail: true,
  loginWithEmailAllowed: true,
  duplicateEmailsAllowed: false,
  resetPasswordAllowed: true,
  editUsernameAllowed: false,
  userManagedAccessAllowed: false,
  organizationsEnabled: false,
  // Fine-grained admin permissions v2 (Keycloak 26.2+): Keycloak creates the
  // system client admin-permissions; scripts/realm/apply-admin-permissions.mjs
  // adds the permissions of realm/admin-permissions.json. No defaultGroups:
  // a default group would also be joined by every new service account.
  adminPermissionsEnabled: true,

  defaultSignatureAlgorithm: "RS256",
  revokeRefreshToken: true,
  refreshTokenMaxReuse: 0,
  accessTokenLifespan: 300,
  accessTokenLifespanForImplicitFlow: 300,
  ssoSessionIdleTimeout: 1800,
  ssoSessionMaxLifespan: 36000,
  ssoSessionIdleTimeoutRememberMe: 0,
  ssoSessionMaxLifespanRememberMe: 0,
  clientSessionIdleTimeout: 0,
  clientSessionMaxLifespan: 0,
  // Offline tokens (mobile only): 14 days idle, 30 days max.
  offlineSessionIdleTimeout: 1209600,
  offlineSessionMaxLifespanEnabled: true,
  offlineSessionMaxLifespan: 2592000,
  accessCodeLifespan: 60,
  accessCodeLifespanUserAction: 300,
  accessCodeLifespanLogin: 1800,
  actionTokenGeneratedByAdminLifespan: 43200,
  actionTokenGeneratedByUserLifespan: 300,
  oauth2DeviceCodeLifespan: 600,
  oauth2DevicePollingInterval: 5,

  bruteForceProtected: true,
  permanentLockout: false,
  maxTemporaryLockouts: 0,
  bruteForceStrategy: "MULTIPLE",
  maxFailureWaitSeconds: 900,
  minimumQuickLoginWaitSeconds: 60,
  waitIncrementSeconds: 60,
  quickLoginCheckMilliSeconds: 1000,
  maxDeltaTimeSeconds: 43200,
  failureFactor: 5,

  passwordPolicy: "length(14) and maxLength(128) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1) and notUsername and notEmail and passwordHistory(12) and forceExpiredPasswordChange(90)",

  otpPolicyType: "totp",
  otpPolicyAlgorithm: "HmacSHA1",
  otpPolicyDigits: 6,
  otpPolicyPeriod: 30,
  otpPolicyLookAheadWindow: 1,

  eventsEnabled: true,
  eventsExpiration: 7776000,
  eventsListeners: ["jboss-logging"],
  adminEventsEnabled: true,
  adminEventsDetailsEnabled: true,

  clientScopes: [customerIdScope],
  defaultDefaultClientScopes: ["basic", "web-origins", "acr", "profile", "roles", "email", CUSTOMER_ID_SCOPE],
  userProfile,

  attributes: {
    userProfileEnabled: "true",
    parRequestUriLifetime: "60",
    adminEventsExpiration: "7776000",
    frontendUrl: "",
    "shortVerificationUri": ""
  },

  roles: {
    realm: roles.map(([name, description]) => ({ name, description, composite: false, clientRole: false }))
  },

  groups: [
    {
      name: "staff",
      path: "/staff",
      attributes: { "fbx.managed-by": ["ldap-group-mapper"] },
      realmRoles: [],
      subGroups: staffGroups.map(([name, realmRoles]) => ({ name, path: `/staff/${name}`, realmRoles, attributes: {}, subGroups: [] }))
    },
    { name: "customers", path: "/customers", realmRoles: ["customer"], attributes: {}, subGroups: [] }
  ],

  clients: [
    ...serviceClients,
    publicClient("fintechbankx-web", "FinTechBankX web portal (customers)", "FBX_WEB_REDIRECT_URI", "FBX_WEB_ORIGIN", "FBX_WEB_POST_LOGOUT_REDIRECT_URI"),
    publicClient("fintechbankx-staff-web", "FinTechBankX staff web portal", "FBX_STAFF_WEB_REDIRECT_URI", "FBX_STAFF_WEB_ORIGIN", "FBX_STAFF_WEB_POST_LOGOUT_REDIRECT_URI"),
    publicClient("fintechbankx-mobile", "FinTechBankX mobile app", "FBX_MOBILE_REDIRECT_URI", null, null),
    tppTemplate,
    ...ssoClients
  ],

  scopeMappings: [
    ...(manifest.ssoClients || []).map((c) => ({ client: c.clientId, roles: c.roles })),
    ...serviceClients.map((c) => ({ client: c.clientId, roles: ["service"] })),
    ...["fintechbankx-web", "fintechbankx-staff-web", "fintechbankx-mobile"].map((client) => ({
      client,
      roles: rolesOfUserType(channel[client].userType)
    }))
  ],

  users: serviceClients.map((c) => ({
    username: `service-account-${c.clientId}`,
    enabled: true,
    serviceAccountClientId: c.clientId,
    realmRoles: ["service"],
    // No realm-management roles on any service account (check-realm). User
    // administration is granted per group through fine-grained admin
    // permissions v2 (realm/admin-permissions.json). The explicit empty list
    // makes keycloak-config-cli remove roles granted earlier (it only
    // reconciles the clients listed here).
    clientRoles: { "realm-management": [] },
    groups: []
  })),

  // Present and empty: keycloak-config-cli skips client-scope-mapping cleanup
  // when the key is absent, so an earlier realm-management mapping would stay.
  clientScopeMappings: {},

  components: {
    "org.keycloak.storage.UserStorageProvider": [
      {
        name: "fbx-directory",
        providerId: "ldap",
        subComponents: {
          "org.keycloak.storage.ldap.mappers.LDAPStorageMapper": [
            attrMapper("username", env("LDAP_USERNAME_ATTRIBUTE"), "username", true),
            attrMapper("first name", "givenName", "firstName", false),
            attrMapper("last name", "sn", "lastName", true),
            attrMapper("email", "mail", "email", false),
            {
              name: "staff-groups",
              providerId: "group-ldap-mapper",
              subComponents: {},
              config: {
                "groups.dn": [env("LDAP_GROUPS_DN")],
                "group.name.ldap.attribute": ["cn"],
                "group.object.classes": [env("LDAP_GROUP_OBJECT_CLASSES")],
                "groups.ldap.filter": ["(cn=fbx-*)"],
                "preserve.group.inheritance": ["false"],
                "ignore.missing.groups": ["true"],
                "membership.ldap.attribute": ["member"],
                "membership.attribute.type": ["DN"],
                "membership.user.ldap.attribute": [env("LDAP_USERNAME_ATTRIBUTE")],
                "memberof.ldap.attribute": ["memberOf"],
                "user.roles.retrieve.strategy": ["LOAD_GROUPS_BY_MEMBER_ATTRIBUTE"],
                "mode": ["READ_ONLY"],
                "groups.path": ["/staff"],
                "drop.non.existing.groups.during.sync": ["false"]
              }
            }
          ]
        },
        config: {
          enabled: ["true"],
          priority: ["0"],
          vendor: [env("LDAP_VENDOR")],
          editMode: ["READ_ONLY"],
          importEnabled: ["true"],
          syncRegistrations: ["false"],
          connectionUrl: [env("LDAP_CONNECTION_URL")],
          startTls: [env("LDAP_START_TLS")],
          useTruststoreSpi: ["always"],
          connectionPooling: ["true"],
          connectionTimeout: ["5000"],
          readTimeout: ["10000"],
          authType: ["simple"],
          bindDn: [env("LDAP_BIND_DN")],
          bindCredential: [env("LDAP_BIND_CREDENTIAL")],
          usersDn: [env("LDAP_USERS_DN")],
          usernameLDAPAttribute: [env("LDAP_USERNAME_ATTRIBUTE")],
          rdnLDAPAttribute: [env("LDAP_RDN_ATTRIBUTE")],
          uuidLDAPAttribute: [env("LDAP_UUID_ATTRIBUTE")],
          userObjectClasses: [env("LDAP_USER_OBJECT_CLASSES")],
          customUserSearchFilter: [env("LDAP_USER_SEARCH_FILTER")],
          searchScope: ["2"],
          pagination: ["true"],
          batchSizeForSync: ["500"],
          fullSyncPeriod: ["86400"],
          changedSyncPeriod: ["900"],
          cachePolicy: ["DEFAULT"],
          trustEmail: ["true"],
          validatePasswordPolicy: ["false"],
          allowKerberosAuthentication: ["false"],
          useKerberosForPasswordAuthentication: ["false"],
          krbPrincipalAttribute: [""]
        }
      }
    ]
  },

  clientProfiles: {
    profiles: [
      {
        name: "fbx-service-client-baseline",
        description: "Machine-to-machine clients: client credentials only, no browser or password grants, no full scope. No client-x509: TLS ends at the mesh, Keycloak never sees a client certificate.",
        executors: [
          { executor: "secure-client-authenticator", configuration: { "allowed-client-authenticators": ["client-secret", "client-jwt"], "default-client-authenticator": "client-secret" } },
          { executor: "reject-implicit-grant", configuration: { "auto-configure": "true" } },
          { executor: "reject-ropc-grant", configuration: { "auto-configure": "true" } },
          { executor: "full-scope-disabled", configuration: { "auto-configure": "true" } }
        ]
      },
      {
        name: "fbx-staff-sso",
        description: "Confidential staff SSO clients (Grafana): authorization code with PKCE S256, no implicit or password grant.",
        executors: [
          { executor: "secure-client-authenticator", configuration: { "allowed-client-authenticators": ["client-secret", "client-jwt"], "default-client-authenticator": "client-secret" } },
          { executor: "pkce-enforcer", configuration: { "auto-configure": "true" } },
          { executor: "reject-implicit-grant", configuration: { "auto-configure": "true" } },
          { executor: "reject-ropc-grant", configuration: { "auto-configure": "true" } }
        ]
      },
      {
        name: "fbx-open-finance-tpp-client-auth",
        description: "Open-finance TPPs authenticate with private_key_jwt only (added to the built-in FAPI 2.0 DPoP profile, which would also allow tls_client_auth; TLS ends at the gateway, so Keycloak never sees a client certificate).",
        executors: [
          { executor: "secure-client-authenticator", configuration: { "allowed-client-authenticators": ["client-jwt"], "default-client-authenticator": "client-jwt" } }
        ]
      },
      {
        name: "fbx-first-party-public",
        description: "OAuth 2.1 public clients (web, mobile): PKCE S256, no implicit or password grant, strict redirect URIs. DPoP is not required for first-party clients yet (platform contract addendum 2026-10-08).",
        executors: [
          { executor: "secure-redirect-uris-enforcer", configuration: { "allow-ipv4-loopback-address": "false", "allow-ipv6-loopback-address": "false", "allow-private-use-uri-scheme": "true", "oauth-2-1-compliant": "true" } },
          { executor: "pkce-enforcer", configuration: { "auto-configure": "true" } },
          { executor: "reject-implicit-grant", configuration: { "auto-configure": "true" } },
          { executor: "reject-ropc-grant", configuration: { "auto-configure": "true" } }
        ]
      }
    ]
  },

  clientPolicies: {
    policies: [
      {
        name: "fbx-service-clients",
        description: "Applies the service client baseline to every client tagged fbx.client-type=service.",
        enabled: true,
        conditions: [{ condition: "client-attributes", configuration: { "is_negative_logic": false, attributes: JSON.stringify([{ key: "fbx.client-type", value: "service" }]) } }],
        profiles: ["fbx-service-client-baseline"]
      },
      {
        name: "fbx-staff-sso-clients",
        description: "Applies the staff SSO profile to clients tagged fbx.client-type=staff-sso.",
        enabled: true,
        conditions: [{ condition: "client-attributes", configuration: { "is_negative_logic": false, attributes: JSON.stringify([{ key: "fbx.client-type", value: "staff-sso" }]) } }],
        profiles: ["fbx-staff-sso"]
      },
      {
        name: "fbx-first-party-public-clients",
        description: "Applies OAuth 2.1 public-client rules to web and mobile clients.",
        enabled: true,
        conditions: [{ condition: "client-attributes", configuration: { "is_negative_logic": false, attributes: JSON.stringify([{ key: "fbx.client-type", value: "first-party-public" }]) } }],
        profiles: ["fbx-first-party-public"]
      },
      {
        name: "fbx-open-finance-tpp-fapi2-dpop",
        description: "FAPI 2.0 Security Profile with DPoP sender-constrained tokens (PAR, PKCE, private_key_jwt client auth, PS256) for open-finance TPP clients. DPoP is the only token binding: TLS ends at the gateway (SIMPLE) and Keycloak runs behind plain HTTP, so mTLS-bound tokens cannot work.",
        enabled: true,
        conditions: [{ condition: "client-attributes", configuration: { "is_negative_logic": false, attributes: JSON.stringify([{ key: "fbx.client-type", value: "open-finance-tpp" }, { key: "fbx.tpp.token-binding", value: "dpop" }]) } }],
        profiles: ["fapi-2-dpop-security-profile", "fbx-open-finance-tpp-client-auth"]
      },
      {
        name: "fbx-open-finance-tpp-dynamic-registration",
        description: "TPP onboarding through Dynamic Client Registration (initial or registration access token) must already satisfy FAPI 2.0 + DPoP at registration time; the client-attributes conditions only match once the client exists.",
        enabled: true,
        conditions: [{ condition: "client-updater-context", configuration: { "is_negative_logic": false, "update-client-source": ["ByInitialAccessToken", "ByRegistrationAccessToken"] } }],
        profiles: ["fapi-2-dpop-security-profile", "fbx-open-finance-tpp-client-auth"]
      }
    ]
  }
};

const target = `${repo}/realm/fintechbankx-realm.json`;
const rendered = JSON.stringify(realm, null, 2) + "\n";
if (checkOnly) {
  if (fs.readFileSync(target, "utf8") !== rendered) {
    console.error("render-realm: realm/fintechbankx-realm.json is out of date; run node scripts/realm/render-realm.mjs");
    process.exit(1);
  }
  console.log(`render-realm: up to date (${realm.clients.length} clients)`);
} else {
  fs.writeFileSync(target, rendered);
  console.log(`render-realm: wrote ${realm.clients.length} clients`);
}
