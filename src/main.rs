use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use vdb::{
    crypto::{DatabaseKey, decrypt_document, encrypt_document, generate_key, key_from_hex},
    identity::WriterIdentity,
    network::{AuthorizationConfig, NetworkLimits, TlsServerConfig, serve_tls},
    operations::{compact, restore, verify_backup, verify_restored},
    protocol::DatabaseService,
    store::Store,
};

#[derive(Parser)]
#[command(
    name = "vdb",
    version,
    about = "Encrypted, verifiable local-first document database"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keygen,
    WriterKeygen,
    Put {
        #[arg(long)]
        db: String,
        #[arg(long)]
        key: String,
        collection: String,
        id: String,
        file: String,
        #[arg(long, default_value_t = 1)]
        version: u64,
    },
    Get {
        #[arg(long)]
        db: String,
        #[arg(long)]
        key: String,
        collection: String,
        id: String,
    },
    Verify {
        #[arg(long)]
        db: String,
    },
    Backup {
        #[arg(long)]
        db: String,
        #[arg(long)]
        output: PathBuf,
    },
    BackupVerify {
        #[arg(long)]
        backup: PathBuf,
    },
    Restore {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        db: PathBuf,
    },
    RestoreVerify {
        #[arg(long)]
        db: PathBuf,
    },
    Snapshot {
        #[arg(long)]
        db: String,
        #[arg(long)]
        output: PathBuf,
    },
    Inspect {
        #[arg(long)]
        db: String,
    },
    Status {
        #[arg(long)]
        db: String,
    },
    Compact {
        #[arg(long)]
        db: PathBuf,
    },
    Serve {
        #[arg(long)]
        db: String,
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: SocketAddr,
        #[arg(long)]
        tls_cert: PathBuf,
        #[arg(long)]
        tls_key: PathBuf,
        #[arg(long)]
        auth_config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen => {
            let key = zeroize::Zeroizing::new(generate_key()?);
            let encoded = zeroize::Zeroizing::new(hex::encode(*key));
            println!("{}", encoded.as_str());
        }
        Command::WriterKeygen => {
            let identity = WriterIdentity::generate()?;
            let secret = identity.secret_seed_hex();
            println!(
                "writer_id={}\nkey_version={}\nalgorithm=Ed25519\npublic_key={}\nsecret_seed={}",
                identity.writer_id(),
                identity.key_version(),
                identity.public_key(),
                secret.as_str()
            );
        }
        Command::Put {
            db,
            key,
            collection,
            id,
            file,
            version,
        } => {
            let raw_key = zeroize::Zeroizing::new(key_from_hex(&key)?);
            let plaintext = zeroize::Zeroizing::new(fs::read(file)?);
            serde_json::from_slice::<serde_json::Value>(plaintext.as_ref())
                .map_err(|e| anyhow!("input must be valid JSON: {e}"))?;
            let store = Store::open(&db)?;
            let database_id = store.metadata()?.database_id;
            let key = DatabaseKey::from_database_secret(&database_id, *raw_key)?;
            let doc = encrypt_document(
                &key,
                &database_id,
                &collection,
                &id,
                version,
                plaintext.as_ref(),
            )?;
            let mutation = store.put(&doc)?;
            println!("{}", serde_json::to_string_pretty(&mutation)?);
        }
        Command::Get {
            db,
            key,
            collection,
            id,
        } => {
            let store = Store::open(&db)?;
            let database_id = store.metadata()?.database_id;
            let key = DatabaseKey::from_database_secret(&database_id, key_from_hex(&key)?)?;
            let doc = store
                .get(&collection, &id)?
                .ok_or_else(|| anyhow!("not found"))?;
            let plaintext = zeroize::Zeroizing::new(decrypt_document(&key, &doc)?);
            println!("{}", std::str::from_utf8(plaintext.as_ref())?);
        }
        Command::Verify { db } => {
            let store = Store::open(&db)?;
            println!("{}", serde_json::to_string_pretty(&store.verify()?)?);
        }
        Command::Backup { db, output } => {
            let report = Store::open(db)?.backup(output)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::BackupVerify { backup } => {
            println!("{}", serde_json::to_string_pretty(&verify_backup(backup)?)?);
        }
        Command::Restore { backup, db } => {
            println!("{}", serde_json::to_string_pretty(&restore(backup, db)?)?);
        }
        Command::RestoreVerify { db } => {
            println!("{}", serde_json::to_string_pretty(&verify_restored(db)?)?);
        }
        Command::Snapshot { db, output } => {
            let report = Store::open(db)?.snapshot_to(output)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Inspect { db } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&Store::open(db)?.inspect()?)?
            );
        }
        Command::Status { db } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&Store::open(db)?.status()?)?
            );
        }
        Command::Compact { db } => {
            println!("{}", serde_json::to_string_pretty(&compact(db)?)?);
        }
        Command::Serve {
            db,
            bind,
            tls_cert,
            tls_key,
            auth_config,
        } => {
            let store = Arc::new(Store::open(&db)?);
            let authorization: AuthorizationConfig =
                serde_json::from_slice(&fs::read(auth_config)?)?;
            println!("vdb listening on https://{bind}");
            serve_tls(
                TlsServerConfig {
                    bind,
                    certificate_pem: tls_cert,
                    private_key_pem: tls_key,
                    authorization,
                    limits: NetworkLimits::default(),
                },
                DatabaseService::new(store),
                shutdown_signal(),
            )
            .await?;
        }
    }
    Ok(())
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_writer(std::io::stderr)
        .init();
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
