# vdb (working name)

An early prototype of a lightweight, cryptographically verifiable, local-first encrypted document database.

VDB is not production-ready. The current server has no TLS, authentication, or authorization and must not be exposed to an untrusted network. See [the current architecture](docs/architecture.md), [threat model](docs/threat-model.md), [invariants](docs/invariants.md), and [roadmap](docs/roadmap.md).

## v0.1 invariants

1. Document bodies are encrypted with XChaCha20-Poly1305 before persistence.
2. The server/API stores opaque encrypted envelopes; it does not require the document key.
3. Envelope database, identity, version, and exact key reference are authenticated as AEAD associated data.
4. Every stored envelope is hashed with BLAKE3.
5. Every mutation has a database-bound BLAKE3 ID, Ed25519 signature, and hash-chain link.
6. Document versions must increase monotonically.
7. Local storage is ACID via redb.
8. The database can run as a local CLI or expose a built-in HTTP API.

This is **not** yet production-ready cryptographic software. The current release establishes the architecture and invariants.

## Build

```bash
cargo build --release
```

## Generate a database key

```bash
KEY=$(./target/release/vdb keygen)
```

Keep this key on the client. The networked database process does not need it.

## Store a local JSON document

```bash
cat > alice.json <<'JSON'
{"name":"Alice","role":"engineer"}
JSON

./target/release/vdb put --db demo.vdb --key "$KEY" users alice alice.json
```

## Read and decrypt

```bash
./target/release/vdb get --db demo.vdb --key "$KEY" users alice
```

## Verify mutation history

```bash
./target/release/vdb verify --db demo.vdb
```

## Start the built-in API

```bash
./target/release/vdb serve --db demo.vdb --bind 127.0.0.1:8787
```

Endpoints:

```text
GET  /health
PUT  /v1/{collection}/{id}
GET  /v1/{collection}/{id}
GET  /v1/verify
```

The PUT endpoint expects an already encrypted `EncryptedDocument` envelope. This is deliberate: remote storage should not need the plaintext encryption key.

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
| HTTP / local API            |
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

## Next milestones

- offline backup/restore and atomic database migrations
- stable API and compatibility fixtures
- query planning with client-side filtering for protected fields
- peer replication protocol
- conflict resolution for offline/local-first replicas
- streaming change feed
- TLS and capability-based authorization
- snapshot / backup format
- benchmarks and fuzz/property tests
