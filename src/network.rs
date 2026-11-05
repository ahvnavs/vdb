use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use serde::{Deserialize, Serialize};
use tower::limit::GlobalConcurrencyLimitLayer;

use crate::{
    api,
    identity::verify_detached,
    protocol::{DatabaseService, PROTOCOL_VERSION},
};

pub const HEADER_PROTOCOL: &str = "x-vdb-protocol-version";
pub const HEADER_PRINCIPAL: &str = "x-vdb-principal";
pub const HEADER_KEY_VERSION: &str = "x-vdb-key-version";
pub const HEADER_TIMESTAMP: &str = "x-vdb-timestamp";
pub const HEADER_NONCE: &str = "x-vdb-nonce";
pub const HEADER_SIGNATURE: &str = "x-vdb-signature";
pub const HEADER_REQUEST_ID: &str = "x-vdb-request-id";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Read,
    Write,
    Query,
    Verify,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedPrincipal {
    pub principal_id: String,
    pub key_version: u32,
    pub public_key: String,
    pub permissions: HashSet<Permission>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationConfig {
    pub principals: Vec<AuthorizedPrincipal>,
}

#[derive(Debug, Clone)]
pub struct NetworkLimits {
    pub max_body_bytes: usize,
    pub request_timeout: Duration,
    pub max_concurrent_requests: usize,
    pub requests_per_window: u32,
    pub rate_window: Duration,
    pub authentication_clock_skew: Duration,
    pub graceful_shutdown_timeout: Duration,
}

impl Default for NetworkLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 4 * 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            max_concurrent_requests: 128,
            requests_per_window: 600,
            rate_window: Duration::from_secs(60),
            authentication_clock_skew: Duration::from_secs(300),
            graceful_shutdown_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsServerConfig {
    pub bind: SocketAddr,
    pub certificate_pem: PathBuf,
    pub private_key_pem: PathBuf,
    pub authorization: AuthorizationConfig,
    pub limits: NetworkLimits,
}

#[derive(Debug, Clone)]
pub struct RequestContext {
    pub request_id: String,
    pub principal_id: Option<String>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub service: DatabaseService,
    pub metrics: Arc<NetworkMetrics>,
    security: Arc<SecurityState>,
    limits: NetworkLimits,
}

#[derive(Default)]
pub(crate) struct NetworkMetrics {
    requests: AtomicU64,
    errors: AtomicU64,
    authentication_failures: AtomicU64,
    rate_limited: AtomicU64,
    timeouts: AtomicU64,
    inflight: AtomicU64,
}

impl NetworkMetrics {
    pub(crate) fn prometheus(&self) -> String {
        format!(
            "# TYPE vdb_http_requests_total counter\nvdb_http_requests_total {}\n# TYPE vdb_http_errors_total counter\nvdb_http_errors_total {}\n# TYPE vdb_authentication_failures_total counter\nvdb_authentication_failures_total {}\n# TYPE vdb_rate_limited_total counter\nvdb_rate_limited_total {}\n# TYPE vdb_request_timeouts_total counter\nvdb_request_timeouts_total {}\n# TYPE vdb_http_requests_inflight gauge\nvdb_http_requests_inflight {}\n",
            self.requests.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
            self.authentication_failures.load(Ordering::Relaxed),
            self.rate_limited.load(Ordering::Relaxed),
            self.timeouts.load(Ordering::Relaxed),
            self.inflight.load(Ordering::Relaxed)
        )
    }
}

struct SecurityState {
    principals: HashMap<(String, u32), AuthorizedPrincipal>,
    replay: Mutex<HashMap<(String, String), u64>>,
    rates: Mutex<HashMap<String, RateWindow>>,
}

struct RateWindow {
    started_ms: u64,
    count: u32,
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
    request_id: String,
}

pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    request_id: String,
}

impl ApiError {
    pub fn new(
        status: StatusCode,
        code: &'static str,
        message: impl Into<String>,
        request_id: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            request_id: request_id.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let request_id = self.request_id.clone();
        let mut response = (
            self.status,
            axum::Json(ErrorEnvelope {
                error: ErrorBody {
                    code: self.code,
                    message: self.message,
                    request_id: self.request_id,
                },
            }),
        )
            .into_response();
        if let Ok(value) = HeaderValue::from_str(&request_id) {
            response.headers_mut().insert(HEADER_REQUEST_ID, value);
        }
        response
            .headers_mut()
            .insert(HEADER_PROTOCOL, HeaderValue::from_static("1"));
        response
    }
}

pub fn router(
    service: DatabaseService,
    authorization: AuthorizationConfig,
    limits: NetworkLimits,
) -> Router {
    let service = service.with_max_concurrent_operations(limits.max_concurrent_requests);
    let principals = authorization
        .principals
        .into_iter()
        .map(|principal| {
            (
                (principal.principal_id.clone(), principal.key_version),
                principal,
            )
        })
        .collect();
    let state = AppState {
        service,
        metrics: Arc::new(NetworkMetrics::default()),
        security: Arc::new(SecurityState {
            principals,
            replay: Mutex::new(HashMap::new()),
            rates: Mutex::new(HashMap::new()),
        }),
        limits: limits.clone(),
    };
    api::router(state.clone())
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .layer(middleware::from_fn_with_state(state, request_timeout))
        .layer(GlobalConcurrencyLimitLayer::new(
            limits.max_concurrent_requests,
        ))
}

pub async fn serve_tls<F>(
    config: TlsServerConfig,
    service: DatabaseService,
    shutdown: F,
) -> anyhow::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    validate_server_config(&config)?;
    let tls = RustlsConfig::from_pem_file(&config.certificate_pem, &config.private_key_pem).await?;
    let handle = Handle::new();
    let shutdown_handle = handle.clone();
    let grace = config.limits.graceful_shutdown_timeout;
    tokio::spawn(async move {
        shutdown.await;
        shutdown_handle.graceful_shutdown(Some(grace));
    });
    axum_server::bind_rustls(config.bind, tls)
        .handle(handle)
        .serve(router(service, config.authorization, config.limits).into_make_service())
        .await?;
    Ok(())
}

fn validate_server_config(config: &TlsServerConfig) -> anyhow::Result<()> {
    if config.authorization.principals.is_empty() {
        anyhow::bail!("at least one authorized principal is required");
    }
    if config.limits.max_body_bytes == 0
        || config.limits.max_concurrent_requests == 0
        || config.limits.requests_per_window == 0
    {
        anyhow::bail!("network limits must be non-zero");
    }
    let mut identities = HashSet::new();
    for principal in &config.authorization.principals {
        if principal.principal_id.len() != 32
            || hex::decode(&principal.principal_id).map_or(true, |value| value.len() != 16)
            || principal.key_version == 0
            || hex::decode(&principal.public_key).map_or(true, |value| value.len() != 32)
            || principal.permissions.is_empty()
            || !identities.insert((principal.principal_id.clone(), principal.key_version))
        {
            anyhow::bail!("invalid or duplicate authorized principal");
        }
    }
    Ok(())
}

async fn request_timeout(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let request_id = match resolved_request_id(request.headers()) {
        Ok(request_id) => request_id,
        Err(error) => return error.into_response(),
    };
    match tokio::time::timeout(state.limits.request_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => {
            state.metrics.timeouts.fetch_add(1, Ordering::Relaxed);
            state.metrics.errors.fetch_add(1, Ordering::Relaxed);
            ApiError::new(
                StatusCode::REQUEST_TIMEOUT,
                "request_timeout",
                "request exceeded the configured deadline",
                request_id,
            )
            .into_response()
        }
    }
}

async fn authenticate(State(state): State<AppState>, request: Request, next: Next) -> Response {
    state.metrics.requests.fetch_add(1, Ordering::Relaxed);
    state.metrics.inflight.fetch_add(1, Ordering::Relaxed);
    let _inflight = InflightGuard(Arc::clone(&state.metrics));
    let started = std::time::Instant::now();
    let (parts, body) = request.into_parts();
    let request_id = match resolved_request_id(&parts.headers) {
        Ok(request_id) => request_id,
        Err(error) => return error.into_response(),
    };
    let public = matches!(parts.uri.path(), "/healthz" | "/readyz");
    let body = match to_bytes(body, state.limits.max_body_bytes).await {
        Ok(body) => body,
        Err(_) => {
            return ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                "request body exceeds the configured limit",
                request_id,
            )
            .into_response();
        }
    };
    let principal_id = if public {
        None
    } else {
        match authenticate_headers(
            &state,
            &parts.headers,
            &parts.method,
            &parts.uri,
            &body,
            &request_id,
        ) {
            Ok(principal) => Some(principal),
            Err(error) => {
                if error.status == StatusCode::UNAUTHORIZED {
                    state
                        .metrics
                        .authentication_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
                return error.into_response();
            }
        }
    };
    let method = parts.method.clone();
    let path = parts.uri.path().to_owned();
    let mut request = Request::from_parts(parts, Body::from(body));
    request.extensions_mut().insert(RequestContext {
        request_id: request_id.clone(),
        principal_id,
    });
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(HEADER_REQUEST_ID, value);
    }
    response
        .headers_mut()
        .insert(HEADER_PROTOCOL, HeaderValue::from_static("1"));
    if response.status().is_client_error() || response.status().is_server_error() {
        state.metrics.errors.fetch_add(1, Ordering::Relaxed);
    }
    tracing::info!(request_id = %request_id, method = %method, path = %path, status = response.status().as_u16(), elapsed_ms = started.elapsed().as_millis() as u64, "request completed");
    response
}

struct InflightGuard(Arc<NetworkMetrics>);
impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

fn authenticate_headers(
    state: &AppState,
    headers: &HeaderMap,
    method: &axum::http::Method,
    uri: &axum::http::Uri,
    body: &[u8],
    request_id: &str,
) -> Result<String, ApiError> {
    let protocol = header(headers, HEADER_PROTOCOL, request_id)?;
    if protocol != PROTOCOL_VERSION.to_string() {
        return Err(ApiError::new(
            StatusCode::UPGRADE_REQUIRED,
            "unsupported_protocol_version",
            format!("supported protocol version is {PROTOCOL_VERSION}"),
            request_id,
        ));
    }
    let principal_id = header(headers, HEADER_PRINCIPAL, request_id)?;
    let key_version = header(headers, HEADER_KEY_VERSION, request_id)?
        .parse::<u32>()
        .map_err(|_| unauthorized(request_id))?;
    let timestamp = header(headers, HEADER_TIMESTAMP, request_id)?
        .parse::<u64>()
        .map_err(|_| unauthorized(request_id))?;
    let nonce = header(headers, HEADER_NONCE, request_id)?;
    let signature = header(headers, HEADER_SIGNATURE, request_id)?;
    if !valid_hex(&nonce, 16) || !valid_hex(request_id, 16) {
        return Err(unauthorized(request_id));
    }
    let principal = state
        .security
        .principals
        .get(&(principal_id.clone(), key_version))
        .ok_or_else(|| unauthorized(request_id))?;
    let now = now_ms().map_err(|_| unauthorized(request_id))?;
    let skew = state.limits.authentication_clock_skew.as_millis() as u64;
    if now.abs_diff(timestamp) > skew {
        return Err(unauthorized(request_id));
    }
    let target = uri
        .path_and_query()
        .map_or(uri.path(), |value| value.as_str());
    let message = canonical_request(
        PROTOCOL_VERSION,
        method.as_str(),
        target,
        request_id,
        timestamp,
        &nonce,
        body,
    );
    if !verify_detached(&principal.public_key, &signature, &message) {
        return Err(unauthorized(request_id));
    }
    let required = required_permission(method.as_str(), uri.path());
    if !principal.permissions.contains(&required) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden",
            "principal lacks the required permission",
            request_id,
        ));
    }
    enforce_replay_and_rate(state, &principal_id, &nonce, timestamp, now, request_id)?;
    Ok(principal_id)
}

fn enforce_replay_and_rate(
    state: &AppState,
    principal: &str,
    nonce: &str,
    timestamp: u64,
    now: u64,
    request_id: &str,
) -> Result<(), ApiError> {
    // Charge the bounded rate window before retaining a nonce. Otherwise a
    // valid but rate-limited principal could grow the replay cache without
    // bound using fresh signed nonces.
    let mut rates = state.security.rates.lock().map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error",
            request_id,
        )
    })?;
    let window_ms = state.limits.rate_window.as_millis() as u64;
    let window = rates.entry(principal.into()).or_insert(RateWindow {
        started_ms: now,
        count: 0,
    });
    if now.saturating_sub(window.started_ms) >= window_ms {
        window.started_ms = now;
        window.count = 0;
    }
    if window.count >= state.limits.requests_per_window {
        state.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "principal exceeded the request rate limit",
            request_id,
        ));
    }
    window.count += 1;
    drop(rates);

    let cutoff = now.saturating_sub(state.limits.authentication_clock_skew.as_millis() as u64);
    let mut replay = state.security.replay.lock().map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "internal error",
            request_id,
        )
    })?;
    replay.retain(|_, seen| *seen >= cutoff);
    if replay
        .insert((principal.into(), nonce.into()), timestamp)
        .is_some()
    {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "replayed_request",
            "request nonce was already used",
            request_id,
        ));
    }
    Ok(())
}

fn required_permission(method: &str, path: &str) -> Permission {
    if path.contains("/indexes") || path.ends_with("/metrics") {
        Permission::Admin
    } else if path.ends_with("/verify") {
        Permission::Verify
    } else if path.ends_with("/query") || path.ends_with("/explain") {
        Permission::Query
    } else if method == "GET" {
        Permission::Read
    } else {
        Permission::Write
    }
}

fn header(headers: &HeaderMap, name: &str, request_id: &str) -> Result<String, ApiError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .ok_or_else(|| unauthorized(request_id))
}

fn unauthorized(request_id: &str) -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        "request authentication failed",
        request_id,
    )
}

fn request_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get(HEADER_REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_hex(value, 16))
        .map(ToOwned::to_owned)
}

fn resolved_request_id(headers: &HeaderMap) -> Result<String, ApiError> {
    if let Some(request_id) = request_id(headers) {
        return Ok(request_id);
    }
    random_request_id().map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "request_id_unavailable",
            "secure request ID generation failed",
            "unavailable",
        )
    })
}

fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2 && hex::decode(value).is_ok()
}

fn random_request_id() -> Result<String, getrandom::Error> {
    let mut value = [0_u8; 16];
    getrandom::fill(&mut value)?;
    Ok(hex::encode(value))
}

fn now_ms() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

pub fn canonical_request(
    protocol: u16,
    method: &str,
    target: &str,
    request_id: &str,
    timestamp_ms: u64,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut encoded = b"vdb.network.request.v1\0".to_vec();
    encoded.extend_from_slice(&protocol.to_be_bytes());
    for value in [method.as_bytes(), target.as_bytes(), request_id.as_bytes()] {
        encoded.extend_from_slice(&(value.len() as u64).to_be_bytes());
        encoded.extend_from_slice(value);
    }
    encoded.extend_from_slice(&timestamp_ms.to_be_bytes());
    encoded.extend_from_slice(&(nonce.len() as u64).to_be_bytes());
    encoded.extend_from_slice(nonce.as_bytes());
    encoded.extend_from_slice(blake3::hash(body).as_bytes());
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, sync::Arc};

    use bytes::Bytes;
    use futures_util::{TryStreamExt as _, stream};
    use http_body::Frame;
    use http_body_util::StreamBody;
    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use reqwest::{Client, Method, StatusCode as ClientStatus};
    use tempfile::tempdir;
    use tokio::sync::oneshot;

    use crate::{
        crypto::{DatabaseKey, encrypt_document},
        identity::WriterIdentity,
        protocol::{DatabaseService, Precondition, PutDocumentRequest},
        store::Store,
    };

    #[test]
    fn rate_limited_request_does_not_grow_replay_cache() -> anyhow::Result<()> {
        let directory = tempdir()?;
        let store = Arc::new(Store::open(directory.path().join("rate.vdb"))?);
        let state = AppState {
            service: DatabaseService::new(store),
            metrics: Arc::new(NetworkMetrics::default()),
            security: Arc::new(SecurityState {
                principals: HashMap::new(),
                replay: Mutex::new(HashMap::new()),
                rates: Mutex::new(HashMap::new()),
            }),
            limits: NetworkLimits {
                requests_per_window: 1,
                ..NetworkLimits::default()
            },
        };
        assert!(
            enforce_replay_and_rate(&state, "principal", "nonce-1", 1_000, 1_000, "request")
                .is_ok()
        );
        let limited =
            enforce_replay_and_rate(&state, "principal", "nonce-2", 1_001, 1_001, "request");
        assert!(limited.is_err());
        let replay = state
            .security
            .replay
            .lock()
            .map_err(|_| anyhow::anyhow!("replay lock poisoned"))?;
        assert_eq!(replay.len(), 1);
        assert!(!replay.contains_key(&("principal".into(), "nonce-2".into())));
        Ok(())
    }

    struct TestServer {
        client: Client,
        base: String,
        identity: WriterIdentity,
        read_only_identity: WriterIdentity,
        shutdown: Option<oneshot::Sender<()>>,
        task: tokio::task::JoinHandle<anyhow::Result<()>>,
        _directory: tempfile::TempDir,
        database_id: String,
    }

    impl TestServer {
        async fn start(timeout: Duration, max_body: usize) -> anyhow::Result<Self> {
            let directory = tempdir()?;
            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed(vec!["localhost".into()])?;
            let certificate_pem = cert.pem();
            let certificate_path = directory.path().join("certificate.pem");
            let key_path = directory.path().join("private-key.pem");
            fs::write(&certificate_path, certificate_pem.as_bytes())?;
            fs::write(&key_path, signing_key.serialize_pem().as_bytes())?;

            let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
            let port = listener.local_addr()?.port();
            drop(listener);
            let bind = SocketAddr::from(([127, 0, 0, 1], port));
            let store = Arc::new(Store::open(directory.path().join("network.vdb"))?);
            let database_id = store.metadata()?.database_id;
            let identity = WriterIdentity::generate()?;
            let read_only_identity = WriterIdentity::generate()?;
            let permissions = [
                Permission::Read,
                Permission::Write,
                Permission::Query,
                Permission::Verify,
                Permission::Admin,
            ]
            .into_iter()
            .collect();
            let authorization = AuthorizationConfig {
                principals: vec![
                    AuthorizedPrincipal {
                        principal_id: identity.writer_id(),
                        key_version: identity.key_version(),
                        public_key: identity.public_key(),
                        permissions,
                    },
                    AuthorizedPrincipal {
                        principal_id: read_only_identity.writer_id(),
                        key_version: read_only_identity.key_version(),
                        public_key: read_only_identity.public_key(),
                        permissions: [Permission::Read].into_iter().collect(),
                    },
                ],
            };
            let limits = NetworkLimits {
                max_body_bytes: max_body,
                request_timeout: timeout,
                max_concurrent_requests: 8,
                requests_per_window: 10_000,
                rate_window: Duration::from_secs(60),
                authentication_clock_skew: Duration::from_secs(30),
                graceful_shutdown_timeout: Duration::from_secs(2),
            };
            let (shutdown, receiver) = oneshot::channel();
            let task = tokio::spawn(serve_tls(
                TlsServerConfig {
                    bind,
                    certificate_pem: certificate_path,
                    private_key_pem: key_path,
                    authorization,
                    limits,
                },
                DatabaseService::new(store),
                async move {
                    let _ = receiver.await;
                },
            ));
            let certificate = reqwest::tls::Certificate::from_pem(certificate_pem.as_bytes())?;
            let client = Client::builder()
                .tls_certs_only([certificate])
                .connect_timeout(Duration::from_secs(2))
                .build()?;
            let base = format!("https://localhost:{port}");
            for _ in 0..100 {
                if client.get(format!("{base}/healthz")).send().await.is_ok() {
                    return Ok(Self {
                        client,
                        base,
                        identity,
                        read_only_identity,
                        shutdown: Some(shutdown),
                        task,
                        _directory: directory,
                        database_id,
                    });
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            anyhow::bail!("test server did not become ready")
        }

        fn signed(&self, method: Method, path: &str, body: &[u8]) -> reqwest::RequestBuilder {
            self.signed_with(&self.identity, method, path, body)
        }

        fn signed_with(
            &self,
            identity: &WriterIdentity,
            method: Method,
            path: &str,
            body: &[u8],
        ) -> reqwest::RequestBuilder {
            let request_id = random_request_id().expect("secure test request ID");
            let nonce = random_request_id().expect("secure test nonce");
            let timestamp = now_ms().expect("system clock");
            let canonical = canonical_request(
                PROTOCOL_VERSION,
                method.as_str(),
                path,
                &request_id,
                timestamp,
                &nonce,
                body,
            );
            self.client
                .request(method, format!("{}{path}", self.base))
                .header(HEADER_PROTOCOL, PROTOCOL_VERSION)
                .header(HEADER_PRINCIPAL, identity.writer_id())
                .header(HEADER_KEY_VERSION, identity.key_version())
                .header(HEADER_TIMESTAMP, timestamp)
                .header(HEADER_NONCE, nonce)
                .header(HEADER_REQUEST_ID, request_id)
                .header(HEADER_SIGNATURE, identity.sign_bytes(&canonical))
        }

        async fn stop(mut self) -> anyhow::Result<()> {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            self.task.await??;
            Ok(())
        }
    }

    #[tokio::test]
    async fn real_tls_socket_security_limits_and_graceful_shutdown() -> anyhow::Result<()> {
        let server = TestServer::start(Duration::from_millis(150), 1024).await?;

        let health = server
            .client
            .get(format!("{}/healthz", server.base))
            .send()
            .await?;
        assert_eq!(health.status(), ClientStatus::OK);
        assert_eq!(health.headers()[HEADER_PROTOCOL], "1");

        let readiness = server
            .client
            .get(format!("{}/readyz", server.base))
            .send()
            .await?;
        assert_eq!(readiness.status(), ClientStatus::OK);

        let unauthorized = server
            .client
            .get(format!("{}/v1/verify", server.base))
            .send()
            .await?;
        assert_eq!(unauthorized.status(), ClientStatus::UNAUTHORIZED);
        assert!(unauthorized.headers().contains_key(HEADER_REQUEST_ID));

        let forbidden = server
            .signed_with(&server.read_only_identity, Method::GET, "/v1/verify", b"")
            .send()
            .await?;
        assert_eq!(forbidden.status(), ClientStatus::FORBIDDEN);

        let malformed_body = b"{";
        let malformed = server
            .signed(Method::POST, "/v1/query", malformed_body)
            .body(malformed_body.to_vec())
            .send()
            .await?;
        assert_eq!(malformed.status(), ClientStatus::BAD_REQUEST);

        let oversized_body = vec![b'x'; 2048];
        let oversized = server
            .signed(Method::POST, "/v1/query", &oversized_body)
            .body(oversized_body)
            .send()
            .await?;
        assert_eq!(oversized.status(), ClientStatus::PAYLOAD_TOO_LARGE);

        let mut invalid_request = server.signed(Method::GET, "/v1/verify", b"").build()?;
        invalid_request
            .headers_mut()
            .insert(HEADER_SIGNATURE, HeaderValue::from_str(&"00".repeat(64))?);
        let invalid_signature = server.client.execute(invalid_request).await?;
        assert_eq!(invalid_signature.status(), ClientStatus::UNAUTHORIZED);

        let mut unsupported_protocol = server.signed(Method::GET, "/v1/verify", b"").build()?;
        unsupported_protocol
            .headers_mut()
            .insert(HEADER_PROTOCOL, HeaderValue::from_static("2"));
        let unsupported_protocol = server.client.execute(unsupported_protocol).await?;
        assert_eq!(
            unsupported_protocol.status(),
            ClientStatus::UPGRADE_REQUIRED
        );

        let first_request = server.signed(Method::GET, "/v1/verify", b"").build()?;
        let replayed_request = first_request
            .try_clone()
            .ok_or_else(|| anyhow::anyhow!("empty request must be cloneable"))?;
        let first_response = server.client.execute(first_request).await?;
        assert_eq!(first_response.status(), ClientStatus::OK);
        let replayed_response = server.client.execute(replayed_request).await?;
        assert_eq!(replayed_response.status(), ClientStatus::UNAUTHORIZED);

        let key = DatabaseKey::from_database_secret(&server.database_id, [7_u8; 32])?;
        let mut document =
            encrypt_document(&key, &server.database_id, "users", "alice", 1, b"secret")?;
        document.ciphertext_b64 = "AA==".into();
        let body = serde_json::to_vec(&PutDocumentRequest {
            document,
            precondition: Precondition::MustNotExist,
        })?;
        let invalid_ciphertext = server
            .signed(Method::PUT, "/v1/documents/users/alice", &body)
            .body(body)
            .send()
            .await?;
        assert_eq!(invalid_ciphertext.status(), ClientStatus::BAD_REQUEST);

        let slow_body = serde_json::to_vec(&serde_json::json!({"collection":"users"}))?;
        let delayed = slow_body.clone();
        let slow_stream = stream::once(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            Ok::<Bytes, std::io::Error>(Bytes::from(delayed))
        });
        let slow = server
            .signed(Method::POST, "/v1/query", &slow_body)
            .body(reqwest::Body::wrap(StreamBody::new(
                slow_stream.map_ok(Frame::data),
            )))
            .send()
            .await?;
        assert_eq!(slow.status(), ClientStatus::REQUEST_TIMEOUT);

        let mut clients = Vec::new();
        for _ in 0..24 {
            clients.push(server.signed(Method::GET, "/v1/verify", b"").send());
        }
        let responses = futures_util::future::join_all(clients).await;
        assert!(responses.into_iter().all(|response| {
            response
                .map(|response| response.status() == ClientStatus::OK)
                .unwrap_or(false)
        }));

        let metrics = server
            .signed(Method::GET, "/v1/metrics", b"")
            .send()
            .await?;
        assert_eq!(metrics.status(), ClientStatus::OK);
        let metrics = metrics.text().await?;
        assert!(metrics.contains("vdb_http_requests_total"));
        assert!(metrics.contains("vdb_verification_valid 1"));

        let base = server.base.clone();
        let client = server.client.clone();
        server.stop().await?;
        assert!(client.get(format!("{base}/healthz")).send().await.is_err());
        Ok(())
    }
}
