# Security policy

VDB is pre-1.0 security-sensitive database software. It is not yet a complete
production-ready distributed database. Security reports are welcome for the
current `main` branch and latest published release. Older snapshots may be
investigated when a supported deployment is affected, but no maintenance
window is promised before the project publishes a version-support policy.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability or include secrets,
private keys, protected plaintext, production databases, or exploit data in a
public report.

Use the repository host's private security-advisory facility when available.
If it is unavailable, contact the maintainers privately through the channel
from which the VDB build was obtained and request a secure reporting channel
before sending sensitive details. Include the affected revision and platform,
reachable entry point, required attacker capabilities, minimal reproduction,
expected security property, observed result, and any operational mitigation.

Maintainers will acknowledge receipt when possible, validate the report,
coordinate a fix and release, and credit reporters who request credit. No fixed
response or remediation SLA is currently offered.

## Security boundaries

The authoritative implemented threat model is [docs/threat-model.md](docs/threat-model.md).
In particular:

- storage servers do not receive document content keys, but see documented
  metadata and cannot authenticate an AEAD tag without the content key;
- TLS, static signed-request authorization, and process-local replay/rate
  controls protect the current REST service;
- replication is an embedded API without a production transport or durable
  membership/revocation service;
- local verification cannot detect a self-consistent rollback without an
  externally retained checkpoint; and
- raw keys in command-line arguments and CLI plaintext output remain exposed
  to operating-system and terminal capture.

Confidentiality, integrity, authentication, authorization, canonical parsing,
cryptographic misuse, crash consistency, corruption, rollback, unsafe resource
consumption, and cross-boundary metadata disclosure are in scope. Mining,
tokens, global blockchain consensus, arbitrary encrypted querying, compromised
client endpoints, and availability against an operator able to delete all data
are not implemented guarantees.

## Handling sensitive test material

Use synthetic keys and databases. Never submit live credentials or customer
data. Diagnostics and tests must not log protected plaintext, content keys,
signing seeds, authentication headers, complete ciphertexts, or passwords.
