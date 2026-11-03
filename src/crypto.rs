use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::model::EncryptedDocument;

pub fn key_from_hex(input: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(input)?;
    if raw.len() != 32 {
        return Err(anyhow!("key must be exactly 32 bytes / 64 hex characters"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw);
    Ok(key)
}

pub fn generate_key() -> Result<[u8; 32]> {
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key).map_err(|error| anyhow!("operating system RNG failed: {error}"))?;
    Ok(key)
}

fn associated_data(collection: &str, id: &str, version: u64, plaintext_hash: &str) -> Vec<u8> {
    let mut aad = b"vdb.envelope.v1\0".to_vec();
    for value in [collection.as_bytes(), id.as_bytes()] {
        aad.extend_from_slice(&(value.len() as u64).to_be_bytes());
        aad.extend_from_slice(value);
    }
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(&(plaintext_hash.len() as u64).to_be_bytes());
    aad.extend_from_slice(plaintext_hash.as_bytes());
    aad
}

pub fn encrypt_json(
    key: &[u8; 32],
    collection: &str,
    id: &str,
    version: u64,
    plaintext: &[u8],
) -> Result<EncryptedDocument> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)?;
    let plaintext_hash = blake3::hash(plaintext).to_hex().to_string();
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|error| anyhow!("operating system RNG failed: {error}"))?;
    let nonce = XNonce::try_from(nonce.as_slice()).map_err(|_| anyhow!("invalid nonce"))?;
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &associated_data(collection, id, version, &plaintext_hash),
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;

    Ok(EncryptedDocument {
        format_version: 1,
        collection: collection.to_owned(),
        id: id.to_owned(),
        version,
        nonce_b64: B64.encode(nonce),
        ciphertext_b64: B64.encode(ciphertext),
        plaintext_hash,
    })
}

pub fn decrypt_json(key: &[u8; 32], doc: &EncryptedDocument) -> Result<Vec<u8>> {
    if doc.format_version != 1 {
        return Err(anyhow!(
            "unsupported encrypted document format {}",
            doc.format_version
        ));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key)?;
    let nonce = B64.decode(&doc.nonce_b64)?;
    if nonce.len() != 24 {
        return Err(anyhow!("invalid XChaCha20 nonce length"));
    }
    let ciphertext = B64.decode(&doc.ciphertext_b64)?;
    let nonce = XNonce::try_from(nonce.as_slice()).map_err(|_| anyhow!("invalid nonce"))?;
    let aad = associated_data(&doc.collection, &doc.id, doc.version, &doc.plaintext_hash);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("decryption/authentication failed"))?;

    let actual = blake3::hash(&plaintext).to_hex().to_string();
    if actual != doc.plaintext_hash {
        return Err(anyhow!("plaintext hash mismatch"));
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_metadata_authentication() -> Result<()> {
        let key = generate_key()?;
        let document = encrypt_json(&key, "users", "alice", 1, br#"{"name":"Alice"}"#)?;
        assert_eq!(decrypt_json(&key, &document)?, br#"{"name":"Alice"}"#);

        let mut moved = document.clone();
        moved.id = "mallory".to_owned();
        assert!(decrypt_json(&key, &moved).is_err());

        let mut altered_hash = document;
        altered_hash.plaintext_hash = "00".repeat(32);
        assert!(decrypt_json(&key, &altered_hash).is_err());
        Ok(())
    }

    #[test]
    fn rejects_wrong_key_and_malformed_key() -> Result<()> {
        let key = generate_key()?;
        let other = generate_key()?;
        let document = encrypt_json(&key, "users", "alice", 1, b"{}")?;
        assert!(decrypt_json(&other, &document).is_err());
        assert!(key_from_hex("00").is_err());
        Ok(())
    }
}
