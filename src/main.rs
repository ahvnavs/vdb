use std::{fs, sync::Arc};

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use vdb::{
    api,
    crypto::{decrypt_json, encrypt_json, generate_key, key_from_hex},
    identity::WriterIdentity,
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
    Serve {
        #[arg(long)]
        db: String,
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
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
            let key = zeroize::Zeroizing::new(key_from_hex(&key)?);
            let plaintext = fs::read(file)?;
            serde_json::from_slice::<serde_json::Value>(&plaintext)
                .map_err(|e| anyhow!("input must be valid JSON: {e}"))?;
            let doc = encrypt_json(&key, &collection, &id, version, &plaintext)?;
            let store = Store::open(&db)?;
            let mutation = store.put(&doc)?;
            println!("{}", serde_json::to_string_pretty(&mutation)?);
        }
        Command::Get {
            db,
            key,
            collection,
            id,
        } => {
            let key = zeroize::Zeroizing::new(key_from_hex(&key)?);
            let store = Store::open(&db)?;
            let doc = store
                .get(&collection, &id)?
                .ok_or_else(|| anyhow!("not found"))?;
            let plaintext = decrypt_json(&key, &doc)?;
            println!("{}", String::from_utf8(plaintext)?);
        }
        Command::Verify { db } => {
            let store = Store::open(&db)?;
            println!("{}", serde_json::to_string_pretty(&store.verify()?)?);
        }
        Command::Serve { db, bind } => {
            let store = Arc::new(Store::open(&db)?);
            let listener = tokio::net::TcpListener::bind(&bind).await?;
            println!("vdb listening on http://{bind}");
            axum::serve(listener, api::router(store)).await?;
        }
    }
    Ok(())
}
