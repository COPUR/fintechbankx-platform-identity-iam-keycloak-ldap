# Enterprise Anonymity & Security Standard (Product-Grade Baseline)

## Purpose
Define an enforceable, enterprise-grade baseline for anonymity protection, secret management, and secure software delivery across this repository.

## Authoritative Standards
- OWASP Secrets Management Cheat Sheet (secret lifecycle, rotation, least privilege): https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- OWASP ASVS (application security verification baseline): https://owasp.org/www-project-application-security-verification-standard/
- NIST SP 800-63B (authentication and credential handling): https://csrc.nist.gov/pubs/sp/800/63/b/upd2/final
- OpenID FAPI 2.0 Security Profile Final (financial API security controls): https://openid.net/specs/fapi-security-profile-2_0-final.html
- PCI DSS v4.0.1 (protection of stored authentication/account data): https://www.pcisecuritystandards.org/document_library/
- Kubernetes Secrets Good Practices (runtime secret injection and access control): https://kubernetes.io/docs/concepts/security/secrets-good-practices/
- Twelve-Factor App Config (externalized config/secrets): https://12factor.net/config

## Mandatory Controls
1. No plaintext production secrets in source control, docs, tests, or examples.
2. Runtime secret sourcing must use one of:
   - mounted secret file (`*_FILE`), or
   - runtime injection (`*_SECRET` env var from orchestrator/Vault integration).
3. Secret metadata/reference catalog is mandatory and versioned:
   - `security/secrets/secret-references.yaml`
4. Personal workstation paths and personal identity markers must not appear in committed artifacts.
5. PII in sample data must be synthetic only and not traceable to real individuals.
6. CI must fail on anonymity/security baseline violations.

## Repository Implementation
- Secret resolver library:
  - `scripts/lib/secrets.sh`
- Runtime secret reference catalog:
  - `security/secrets/secret-references.yaml`
- Enforced script-level secret usage (no hardcoded client secret):
  - `scripts/performance/load-test.sh`
  - `testing/security/security-test-suite.sh`
- CI gate for anonymity and hardcoded secret hygiene:
  - `tools/validation/validate-anonymity-security.sh`
  - `.github/workflows/ci.yml` (`anonymity-security-baseline` job)

## Verification Checklist
- [ ] No `/Users/...`, `C:\Users\...`, or `/home/<user>/...` in tracked files.
- [ ] No personal identifiers (individual names/usernames) in docs and source.
- [ ] No private key/token signature patterns committed.
- [ ] Secret-bearing scripts read from `*_FILE` or environment injection only.
- [ ] Secret reference catalog exists and contains no secret values.
- [ ] CI gate is green on every PR.

## Operational Notes
- Use mounted files for secrets in Kubernetes:
  - Example: `/var/run/secrets/openfinance/oauth_client_secret`
- Rotate secrets on schedule and incident response triggers.
- Keep audit logs for all secret mutations and accesses.
