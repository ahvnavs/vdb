use std::{
    collections::HashSet,
    fs,
    net::{SocketAddr, TcpListener},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use rcgen::{CertifiedKey, generate_simple_self_signed};
use reqwest::{Client, Method, StatusCode};
use tempfile::tempdir;
use tokio::sync::oneshot;
use vdb::{
    crypto::{DatabaseKey, decrypt_document, encrypt_document},
    identity::WriterIdentity,
    network::{
        AUTHORIZATION_CONFIG_VERSION, AuthorizationConfig, AuthorizedPrincipal, HEADER_KEY_VERSION,
        HEADER_NONCE, HEADER_PRINCIPAL, HEADER_PROTOCOL, HEADER_REQUEST_ID, HEADER_SIGNATURE,
        HEADER_TIMESTAMP, NetworkLimits, Permission, TlsServerConfig, canonical_request, serve_tls,
    },
    operations::{restore, verify_backup, verify_restored},
    protocol::{DatabaseService, PROTOCOL_VERSION},
    replication::{AuthorizedPeer, Replica, ReplicatedDocument},
    store::Store,
};

fn challenge(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn signed_request(
    client: &Client,
    base: &str,
    identity: &WriterIdentity,
    method: Method,
    path: &str,
) -> anyhow::Result<reqwest::RequestBuilder> {
    let request_id = hex::encode([11_u8; 16]);
    let nonce = hex::encode([12_u8; 16]);
    let timestamp: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let message = canonical_request(
        PROTOCOL_VERSION,
        method.as_str(),
        path,
        &request_id,
        timestamp,
        &nonce,
        b"",
    );
    Ok(client
        .request(method, format!("{base}{path}"))
        .header(HEADER_PROTOCOL, PROTOCOL_VERSION)
        .header(HEADER_PRINCIPAL, identity.writer_id())
        .header(HEADER_KEY_VERSION, identity.key_version())
        .header(HEADER_TIMESTAMP, timestamp)
        .header(HEADER_NONCE, nonce)
        .header(HEADER_REQUEST_ID, request_id)
        .header(HEADER_SIGNATURE, identity.sign_bytes(&message)))
}

#[tokio::test]
async fn release_acceptance_path() -> anyhow::Result<()> {
    let directory = tempdir()?;
    let first_path = directory.path().join("first.vdb");
    let second_path = directory.path().join("second.vdb");
    let bootstrap = directory.path().join("bootstrap.vdbbak");
    let identity_a = WriterIdentity::generate()?;
    let identity_b = WriterIdentity::generate()?;
    let store_a = Store::open_with_identity(&first_path, identity_a)?;

    // A restored empty backup gives the second replica the same database identity.
    store_a.backup(&bootstrap)?;
    restore(&bootstrap, &second_path)?;
    let store_b = Store::open_with_identity(&second_path, identity_b)?;
    let database_id = store_a.metadata()?.database_id;
    assert_eq!(store_b.metadata()?.database_id, database_id);

    let content_key = DatabaseKey::from_database_secret(&database_id, [42_u8; 32])?;
    let initial = encrypt_document(
        &content_key,
        &database_id,
        "users",
        "alice",
        1,
        br#"{"name":"Alice"}"#,
    )?;
    store_a.put(&initial)?;
    let local = store_a.get("users", "alice")?.expect("local document");
    assert_eq!(
        decrypt_document(&content_key, &local)?,
        br#"{"name":"Alice"}"#
    );

    let replica_a = Replica::new(store_a.clone());
    let replica_b = Replica::new(store_b.clone());
    replica_a.put(initial)?;
    let peer_a = AuthorizedPeer {
        replica_id: replica_a.replica_id(),
        key_version: 1,
        public_key: match replica_a.document("users", "alice")? {
            ReplicatedDocument::Live { event } => event.replica_public_key,
            state => anyhow::bail!("unexpected initial state: {state:?}"),
        },
    };
    replica_b.sync_from(&replica_a, &[peer_a], &challenge(1))?;

    // Disconnected concurrent writes remain an explicit conflict after exchange.
    let a_update = encrypt_document(
        &content_key,
        &database_id,
        "users",
        "alice",
        2,
        br#"{"name":"Alice A"}"#,
    )?;
    let b_update = encrypt_document(
        &content_key,
        &database_id,
        "users",
        "alice",
        2,
        br#"{"name":"Alice B"}"#,
    )?;
    replica_a.put(a_update)?;
    replica_b.put(b_update)?;
    // Authentication is bound to the actual peer identity advertised by each replica.
    let hello_a = replica_a.hello(&challenge(2))?;
    let hello_b = replica_b.hello(&challenge(3))?;
    let peer_a = AuthorizedPeer {
        replica_id: hello_a.replica_id,
        key_version: hello_a.key_version,
        public_key: hello_a.public_key,
    };
    let peer_b = AuthorizedPeer {
        replica_id: hello_b.replica_id,
        key_version: hello_b.key_version,
        public_key: hello_b.public_key,
    };
    replica_a.sync_from(&replica_b, &[peer_b], &challenge(4))?;
    replica_b.sync_from(&replica_a, std::slice::from_ref(&peer_a), &challenge(5))?;
    let conflicts = match replica_a.document("users", "alice")? {
        ReplicatedDocument::Conflict { events } => events,
        state => anyhow::bail!("expected explicit conflict, found {state:?}"),
    };
    assert_eq!(
        replica_b.document("users", "alice")?,
        ReplicatedDocument::Conflict {
            events: conflicts.clone()
        }
    );
    let chosen = conflicts[0].event_id.clone();
    replica_a.resolve("users", "alice", &chosen)?;
    replica_b.sync_from(&replica_a, std::slice::from_ref(&peer_a), &challenge(6))?;
    assert_eq!(
        replica_a.document("users", "alice")?,
        replica_b.document("users", "alice")?
    );
    assert!(store_a.verify()?.valid);
    assert!(store_b.verify()?.valid);

    // Start the real TLS service and prove protected operations require authorization.
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_path = directory.path().join("server.pem");
    let key_path = directory.path().join("server-key.pem");
    fs::write(&cert_path, cert.pem())?;
    fs::write(&key_path, signing_key.serialize_pem())?;
    let network_identity = WriterIdentity::generate()?;
    let authorization = AuthorizationConfig {
        format_version: AUTHORIZATION_CONFIG_VERSION,
        principals: vec![AuthorizedPrincipal {
            principal_id: network_identity.writer_id(),
            key_version: network_identity.key_version(),
            public_key: network_identity.public_key(),
            permissions: HashSet::from([Permission::Read, Permission::Verify]),
        }],
    };
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let bind = SocketAddr::from(([127, 0, 0, 1], port));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = tokio::spawn(serve_tls(
        TlsServerConfig {
            bind,
            certificate_pem: cert_path,
            private_key_pem: key_path,
            authorization,
            limits: NetworkLimits::default(),
        },
        DatabaseService::new(Arc::new(store_a.clone())),
        async move {
            let _ = shutdown_rx.await;
        },
    ));
    let certificate = reqwest::tls::Certificate::from_pem(cert.pem().as_bytes())?;
    let client = Client::builder().tls_certs_only([certificate]).build()?;
    let base = format!("https://localhost:{port}");
    for _ in 0..100 {
        if client.get(format!("{base}/healthz")).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let unauthorized = client.get(format!("{base}/v1/verify")).send().await?;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let authorized = signed_request(
        &client,
        &base,
        &network_identity,
        Method::GET,
        "/v1/documents/users/alice",
    )?
    .send()
    .await?;
    assert_eq!(authorized.status(), StatusCode::OK);
    let _ = shutdown_tx.send(());
    server.await??;

    let backup = directory.path().join("release.vdbbak");
    store_a.backup(&backup)?;
    assert_eq!(verify_backup(&backup)?.database_id, database_id);
    drop(replica_a);
    drop(store_a);
    fs::remove_file(&first_path)?;
    assert!(!first_path.exists());
    restore(&backup, &first_path)?;
    let restored = verify_restored(&first_path)?;
    assert!(restored.verified);
    assert_eq!(restored.database_id, database_id);
    Ok(())
}
