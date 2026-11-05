# ADR 0009: TLS-only signed-request network protocol

Status: accepted, protocol version 1

## Decision

Place a typed `DatabaseService` between transports and `Store`. Expose a versioned REST adapter over rustls TLS only. Authenticate every protected request with a canonical Ed25519 signature bound to method, target, body hash, request ID, timestamp, nonce, key version, and protocol version. Authorize configured device/service principals with explicit scopes.

Apply bounded body collection, deadlines, global concurrency backpressure, per-principal rate windows, replay detection, structured errors, health/readiness, and graceful shutdown. Continue accepting opaque encrypted envelopes without content keys.

## Consequences

Network attackers cannot read or modify protected traffic without TLS failure, and stolen bearer tokens do not exist. Clients must manage signing keys, clock synchronization, fresh nonces, and TLS trust roots. Replay and rate state are process-local. Request identity proves authorization at admission but is not yet durable mutation provenance. A timed-out atomic write may still commit, so conditional/idempotent retries remain required.
