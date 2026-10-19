# Directory federation (Proposed)

Staff authenticate against a directory; Keycloak federates it read-only and maps directory groups to realm roles. Customers are local Keycloak users (group `/customers`).

## Mapping (all environments)

| Directory group (cn) | Keycloak group | Realm role |
|---|---|---|
| `fbx-banker` | `/staff/fbx-banker` | `banker` |
| `fbx-loan-officer` | `/staff/fbx-loan-officer` | `loan_officer` |
| `fbx-admin` | `/staff/fbx-admin` | `admin` |
| `fbx-auditor` | `/staff/fbx-auditor` | `auditor` |
| `fbx-compliance-officer` | `/staff/fbx-compliance-officer` | `compliance_officer` |

Mappers in `realm/fintechbankx-realm.json` (provider `fbx-directory`): username, first name, last name, email (all read-only) and `staff-groups` (`group-ldap-mapper`, `READ_ONLY`, filter `(cn=fbx-*)` so only these groups are imported, membership attribute `member` by DN). Only the connection and schema values differ per environment; they are `$(env:LDAP_*)` placeholders filled from ConfigMap `keycloak-realm-import-env`. `check-realm.mjs` refuses a second user storage provider, any other mapper (a role or hardcoded role or group mapper above all), a second group mapper, and a group mapper whose path, filter, name attribute or nesting differs; it checks the realm file only, not a running Keycloak (see `REALM_AS_CODE.md`, gap 5).

## dev and staging: in-cluster OpenLDAP

`deploy/kustomize/components/openldap` (included by the dev and staging overlays):

- StatefulSet `openldap` (service account `openldap`, one replica, 5 Gi encrypted gp3 volume), image `osixia/openldap:1.5.0` pinned by digest, the image the monolith `docker-compose.yml` used.
- TLS: cert-manager Certificate `openldap-tls` from ClusterIssuer `fintechbankx-internal-ca`; slapd enforces StartTLS (`LDAP_TLS_ENFORCE=true`, TLS 1.2+). Keycloak connects to `ldap://openldap.identity.svc.cluster.local:389` with StartTLS and trusts the CA through ConfigMap `fintechbankx-internal-ca` (trust-manager). Port 636 is not exposed.
- Credentials: admin and config credentials from `<env>/identity-openldap/admin`, the read-only bind account `cn=readonly,dc=fintechbankx,dc=internal` from `<env>/identity-keycloak/ldap-bind` (the same value Keycloak binds with).
- Seed: `seed/50-fintechbankx-structure.ldif` creates `ou=people`, `ou=groups`, `ou=system` and the five groups. It contains no people and no credentials. groupOfNames needs one member, so each group lists the non-person entry `cn=membership-placeholder,ou=system`, which Keycloak ignores.
- NetworkPolicy `openldap-from-keycloak`: only Keycloak pods reach port 389.

Synthetic test staff are created per environment by the identity squad with `ldapadd` over StartTLS using the admin credential from Secrets Manager; never commit them.

### Base DN: `dc=fintechbankx,dc=internal`

The monolith used `dc=banking,dc=local`. This repository uses `dc=fintechbankx,dc=internal` because `.local` is reserved for multicast DNS (RFC 6762) and clashes with mDNS resolvers, `.internal` is reserved for private use, the name matches the FinTechBankX brand used everywhere else, and the monolith never committed its LDIF (`config/ldap/bootstrap` is not in Git), so there is no directory data to migrate.

## prod: corporate directory (AWS Managed Microsoft AD)

No OpenLDAP in prod. The prod overlay points the same provider and mappers at the corporate directory over LDAPS:

| Placeholder | prod value (overlay) |
|---|---|
| `LDAP_VENDOR` | `ad` |
| `LDAP_CONNECTION_URL` | `ldaps://corp.fintechbankx.example:636` |
| `LDAP_START_TLS` | `false` (LDAPS) |
| `LDAP_BIND_DN` | read-only service account in `OU=Service Accounts` |
| `LDAP_USERS_DN` / `LDAP_GROUPS_DN` | FinTechBankX user OU / `OU=Keycloak Roles` |
| `LDAP_USERNAME_ATTRIBUTE` / `LDAP_RDN_ATTRIBUTE` / `LDAP_UUID_ATTRIBUTE` | `sAMAccountName` / `cn` / `objectGUID` |
| `LDAP_USER_OBJECT_CLASSES` / `LDAP_GROUP_OBJECT_CLASSES` | `person, organizationalPerson, user` / `group` |
| `LDAP_USER_SEARCH_FILTER` | persons that are not disabled |

The directory owner creates the five `fbx-*` groups in the role OU and a read-only bind account; its credential goes to `prod/identity-keycloak/ldap-bind`. AWS Managed Microsoft AD needs LDAPS enabled (client-side LDAPS with a certificate from the corporate CA) and a security group rule from the EKS node or pod security group to the directory on 636. The CA bundle is published as ConfigMap `corporate-directory-ca` and mounted as a Keycloak truststore. The host names and DNs in the overlay are placeholders until the directory owner confirms them.

## Failure behaviour

If the directory is unreachable, staff with a cached Keycloak session keep working; new staff logins fail (Keycloak cannot verify the credential). Customer logins and service client-credentials are unaffected because they do not touch the directory.
