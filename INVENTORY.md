# Fixture inventory

| Owner | Location | Scenario |
|---|---|---|
| Payments Engineering | apps/payments/ | Application wraps a data encryption key |
| Identity Engineering | apps/identity/ | Service assertion signing policy |
| Ledger Engineering | apps/ledger/ | Batch signature implementation |
| Partner Integrations | apps/partner-gateway/ | Partner signature verification |
| Ingress Platform | platform/edge/ | TLS certificate and key exchange policy |
| PKI Platform | platform/pki/ | Three synthetic public keys and their asset inventory |
| Records Engineering | security/archive/ | Retired formats and replacement policy |
| Ledger Operations | data/exports/ | Retention policy and an encrypted statement |
| Security Engineering | security/controls/ | Health check with no cryptographic calls |

## Expected report

With CipherSetu 0.2.0-alpha and a confidentiality lifetime of 10 years, expect
1 Critical, 21 High, 1 Medium, and 4 Low findings. The findings are line matches,
so several may come from a single file. The health check should have no findings.
