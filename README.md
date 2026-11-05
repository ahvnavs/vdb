# vdb (working name)

An early prototype of a lightweight, cryptographically verifiable, local-first encrypted document database.

VDB is not yet a supported 1.0 distributed database. Its built-in service is TLS-only and requires signed, authorized requests, but network replication transport, durable key custody, migrations, certificate automation, durable replay state, dynamic revocation, and release provenance remain. Start with the [installation guide](docs/installation.md), [quickstart](docs/quickstart.md), [CLI reference](docs/cli.md), and [compatibility policy](docs/compatibility.md). See also the [current architecture](docs/architecture.md), [network protocol](docs/protocol.md), [threat model](docs/threat-model.md), [invariants](docs/invariants.md), and [roadmap](docs/roadmap.md).

## v0.1 invariants

1. Document bodies are encrypted with XChaCha20-Poly1305 before persistence.
2. The server/API stores opaque encrypted envelopes; it does not require the document key.
3. Envelope database, identity, version, and exact key reference are authenticated as AEAD associated data.
4. Every stored envelope is hashed with BLAKE3.
5. Every mutation has a database-bound BLAKE3 ID, Ed25519 signature, and hash-chain link.
6. Document versions must increase monotonically.
7. Local storage is ACID via redb.
8. The database can run as a local CLI or expose a versioned, authenticated HTTPS API.

This is **not** yet production-ready cryptographic software. The current release establishes the architecture and invariants.

## Build

```bash
cargo build --release
```

## Generate a database key

```bash
./target/release/vdb keygen --output app.key
```

Keep this key on the client. The networked database process does not need it.

## Store a local JSON document

```bash
cat > alice.json <<'JSON'
{"name":"Alice","role":"engineer"}
JSON

./target/release/vdb put --db demo.vdb --key-file app.key users alice alice.json
```

## Read and decrypt

```bash
./target/release/vdb get --db demo.vdb --key-file app.key users alice
```

## Verify mutation history

```bash
./target/release/vdb verify --db demo.vdb
```

## Backup and operations

```bash
./target/release/vdb backup --db demo.vdb --output demo.vdbbak
./target/release/vdb backup-verify --backup demo.vdbbak
./target/release/vdb restore --backup demo.vdbbak --db restored.vdb
./target/release/vdb restore-verify --db restored.vdb
./target/release/vdb inspect --db demo.vdb
./target/release/vdb status --db demo.vdb
# Stop all processes using the database before compaction.
./target/release/vdb compact --db demo.vdb
```

See [backup and recovery](docs/backup-recovery.md), the [operations runbook](docs/operations.md),
and the [reproducible benchmark methodology](docs/benchmarks.md).

## Start the built-in API

Generate an Ed25519 service/device identity with `vdb writer-keygen --output device.json`, retain its
secret seed on the client, and place only the public identity in an authorization
file:

```json
{
  "format_version": 1,
  "principals": [
    {
      "principal_id": "<writer_id>",
      "key_version": 1,
      "public_key": "<public_key>",
      "permissions": ["read", "write", "query", "verify", "admin"]
    }
  ]
}
```

```bash
./target/release/vdb serve \
  --db demo.vdb \
  --bind 127.0.0.1:8787 \
  --tls-cert server-cert.pem \
  --tls-key server-key.pem \
  --auth-config authorization.json
```

Endpoints:

```text
GET     /healthz
GET     /readyz
GET     /v1/documents/{collection}/{id}
PUT     /v1/documents/{collection}/{id}
DELETE  /v1/documents/{collection}/{id}
POST    /v1/query
POST    /v1/explain
GET     /v1/verify
GET     /v1/metrics
GET     /v1/indexes/{collection}
POST    /v1/indexes/{collection}
DELETE  /v1/indexes/{collection}/{name}
PUT     /v1/indexes/{collection}/{name}
```

Except for health and readiness, requests require the protocol-version and
Ed25519 authentication headers defined in [the protocol document](docs/protocol.md).
PUT expects an already encrypted `EncryptedDocument` envelope. The service
validates and stores ciphertext without receiving the plaintext encryption key.

## Architecture

```text
Client / CLI
    |
    | plaintext exists here
    v
XChaCha20-Poly1305 encryption
    |
    | encrypted envelope
    v
+-----------------------------+
| vdb process                 |
|                             |
| HTTPS / local API           |
|       |                     |
| validation                  |
|       |                     |
| BLAKE3 document hash        |
|       |                     |
| append-only hash chain      |
|       |                     |
| redb ACID storage           |
+-----------------------------+
    |
    v
Disk
```

## Current local storage capabilities

- explicit checksummed database format header and database identity
- storage-engine abstraction with redb isolated behind it
- separate document metadata and encrypted payload records
- atomic conditional put and tombstone delete
- exact-version compare-and-swap and atomic multi-document batches
- stable MVCC read snapshots
- canonical binary records and current-state/history verification
- cryptographic writer identities, signed mutations, replay detection, Merkle checkpoints, and inclusion proofs
- typed visible-metadata queries, collection scans, cursor pagination, explain plans, and durable secondary/compound indexes
- TLS-only versioned REST, typed internal protocol requests, signed device/service authentication, scoped authorization, replay/rate controls, bounded requests, and graceful shutdown
- signed dotted-version-vector replication, incremental missing-event exchange, explicit deterministic conflicts, tombstone synchronization, and event-set checkpoints
- consistent verified backup/restore, operational snapshots, offline verified compaction, database inspection/status, JSON tracing, and authenticated metrics

## Next milestones

- atomic database migrations and compatibility fixtures
- stable API and compatibility fixtures
- trusted-client JSON filtering and planner statistics for protected-field candidate queries
- dynamic principal revocation/configuration and durable or distributed replay/rate state
- certificate issuance, rotation, and deployment automation
- replication network transport, durable replica membership/revocation, retirement, and safe tombstone garbage collection
- streaming change feed
- streaming, incremental, compressed, and optionally encrypted backups
- sustained fuzz campaigns, compatibility fixtures, and broader fault injection
