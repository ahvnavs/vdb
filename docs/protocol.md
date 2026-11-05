# Network protocol

Status: implemented REST adapter and native service abstraction, protocol version 1.

## Layering

`DatabaseService` accepts typed `ProtocolRequest` values and returns typed `ProtocolResponse` values. It is independent of HTTP and redb. The REST router translates `/v1` requests into that service boundary; no table names, redb transactions, page concepts, or storage-engine errors cross the API.

The server is TLS-only. `vdb serve` requires a PEM certificate, PEM private key, and authorization JSON. Rustls provides TLS through `axum-server`. Plain HTTP is not offered and there is no insecure fallback.

## Versioning

Every protected request uses a `/v1/...` route and must send `X-VDB-Protocol-Version: 1`. Unsupported versions receive `426 Upgrade Required` with structured code `unsupported_protocol_version`. Responses include the supported version header. Protocol-incompatible changes require a new route/header version; database format and protocol version are independent.

## Request authentication

Protected requests require:

- `X-VDB-Principal`: 128-bit lowercase hexadecimal device/service ID;
- `X-VDB-Key-Version`: non-zero identity key version;
- `X-VDB-Timestamp`: Unix milliseconds;
- `X-VDB-Nonce`: fresh random 128-bit hexadecimal nonce;
- `X-VDB-Request-ID`: random 128-bit hexadecimal request ID;
- `X-VDB-Signature`: Ed25519 signature;
- `X-VDB-Protocol-Version: 1`.

The signature covers the canonical domain, protocol version, HTTP method, exact path and query, request ID, timestamp, nonce, and BLAKE3 request-body hash. Variable fields are unsigned 64-bit length-prefixed and integers are big-endian. The server checks the configured `(principal ID, key version, public key)` binding, clock skew, signature, permission, nonce replay, and per-principal rate window.

Health and readiness are public because load balancers must call them. They expose no database contents. All other routes require authentication.

## Authorization

Permissions are deny-by-default:

- `read`: document reads;
- `write`: document put/delete;
- `query`: query and explain;
- `verify`: database verification;
- `admin`: index listing/creation/drop/rebuild.

Authentication proves possession of a configured device/service key. It does not automatically grant mutation-writer authority, and request identities are not yet embedded into signed database mutations. The current store identity signs accepted local mutations; correlating network principals into durable provenance is a future format decision.

## REST resources

```text
GET    /healthz
GET    /readyz
GET    /v1/documents/{collection}/{id}
PUT    /v1/documents/{collection}/{id}
DELETE /v1/documents/{collection}/{id}
POST   /v1/query
POST   /v1/explain
GET    /v1/verify
GET    /v1/metrics
GET    /v1/indexes/{collection}
POST   /v1/indexes/{collection}
DELETE /v1/indexes/{collection}/{name}
PUT    /v1/indexes/{collection}/{name}
```

PUT accepts a `PutDocumentRequest` containing an already encrypted envelope and precondition. The server validates envelope structure and database/path bindings but never receives a content key. DELETE accepts logical version and precondition. Query/index bodies use the typed structures documented in `query-language.md`.

`/v1/metrics` requires `admin` permission and returns Prometheus text containing bounded operational counters plus storage, verification, and replication-health gauges. It never emits protected payloads, ciphertext, keys, signatures, nonces, or request bodies.

## Limits, cancellation, and shutdown

Defaults are a 4 MiB body limit, 30-second request deadline, 128 concurrent requests, 600 requests per principal per 60 seconds, five-minute authentication skew, and 30-second graceful-shutdown deadline. Limits are configurable through the library configuration. Body collection is bounded before JSON parsing. The global concurrency semaphore applies backpressure instead of allowing unbounded database work.

Deadline expiry or client cancellation drops the request future and response. Work already executing in a redb blocking transaction cannot be interrupted safely; an atomic write may commit even if its client disconnects or times out. Clients must use version preconditions and retry idempotently. Graceful shutdown stops acceptance, lets in-flight connections finish up to the configured deadline, then closes them.

## Errors and observability

Errors are JSON:

```json
{"error":{"code":"unauthorized","message":"request authentication failed","request_id":"..."}}
```

Request IDs are echoed in `X-VDB-Request-ID`. Authentication failures intentionally avoid distinguishing unknown principals, wrong keys, stale timestamps, and invalid signatures. Internal storage/corruption details return a generic `internal_error`. Plaintext, keys, signatures, authorization headers, and bodies are not logged by the server implementation.

## Known limitations

There is no certificate automation, mTLS, durable/distributed replay cache, distributed rate limiter, dynamic authorization reload, revocation list, per-document authorization, audit log, streaming protocol, or native binary wire encoding. Replay/rate state is per process and resets on restart. TLS protects transport but visible metadata described in the threat model remains visible to the authenticated server.
