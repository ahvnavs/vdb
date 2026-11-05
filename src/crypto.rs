use std::collections::HashMap;

use anyhow::{Result, anyhow};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::model::{ENVELOPE_FORMAT_VERSION, EncryptedDocument};

pub const ENCRYPTION_ALGORITHM: &str = "XChaCha20-Poly1305";
const KEY_WRAP_FORMAT: u8 = 1;
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const MAX_CIPHERTEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_CIPHERTEXT_B64: usize = MAX_CIPHERTEXT_BYTES.div_ceil(3) * 4;

pub struct DatabaseKey {
    key_id: [u8; 16],
    version: u32,
    secret: Zeroizing<[u8; 32]>,
}

impl DatabaseKey {
    pub fn generate() -> Result<Self> {
        let mut key_id = [0_u8; 16];
        let mut secret = Zeroizing::new([0_u8; 32]);
        getrandom::fill(&mut key_id).map_err(|e| anyhow!("operating system RNG failed: {e}"))?;
        getrandom::fill(secret.as_mut())
            .map_err(|e| anyhow!("operating system RNG failed: {e}"))?;
        Ok(Self {
            key_id,
            version: 1,
            secret,
        })
    }

    pub fn from_parts(key_id: [u8; 16], version: u32, mut secret: [u8; 32]) -> Result<Self> {
        if version == 0 {
            secret.zeroize();
            return Err(anyhow!("key version must be non-zero"));
        }
        let key = Self {
            key_id,
            version,
            secret: Zeroizing::new(secret),
        };
        secret.zeroize();
        Ok(key)
    }

    /// Transitional CLI import for a raw version-1 secret. The database-scoped key ID
    /// prevents correlation when the same secret is reused across databases.
    pub fn from_database_secret(database_id: &str, mut secret: [u8; 32]) -> Result<Self> {
        let valid_database_id = database_id.len() == 32
            && hex::decode(database_id)
                .map(|decoded| decoded.len() == 16)
                .unwrap_or(false);
        if !valid_database_id {
            secret.zeroize();
            return Err(anyhow!("invalid database ID"));
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"vdb.database.key.id.v1\0");
        hasher.update(database_id.as_bytes());
        hasher.update(&secret);
        let mut key_id = [0_u8; 16];
        key_id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Self::from_parts(key_id, 1, secret)
    }

    pub fn key_id(&self) -> String {
        hex::encode(self.key_id)
    }
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Creates a new random secret under the same logical key ID and next version.
    pub fn rotate(&self) -> Result<Self> {
        let version = self
            .version
            .checked_add(1)
            .ok_or_else(|| anyhow!("key version overflow"))?;
        let mut secret = Zeroizing::new([0_u8; 32]);
        getrandom::fill(secret.as_mut())
            .map_err(|e| anyhow!("operating system RNG failed: {e}"))?;
        Ok(Self {
            key_id: self.key_id,
            version,
            secret,
        })
    }

    pub fn wrap_with_password(&self, password: &[u8]) -> Result<WrappedDatabaseKey> {
        if password.is_empty() {
            return Err(anyhow!("password must not be empty"));
        }
        let mut salt = [0_u8; 16];
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut salt).map_err(|e| anyhow!("operating system RNG failed: {e}"))?;
        getrandom::fill(&mut nonce).map_err(|e| anyhow!("operating system RNG failed: {e}"))?;
        let mut wrapping_key = Zeroizing::new([0_u8; 32]);
        derive_wrapping_key(password, &salt, &mut wrapping_key)?;
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())?;
        let plaintext = Zeroizing::new(encode_key_material(self));
        let aad = wrapping_aad(&salt);
        let nonce_value =
            XNonce::try_from(nonce.as_slice()).map_err(|_| anyhow!("invalid wrap nonce"))?;
        let ciphertext = cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("key wrapping failed"))?;
        Ok(WrappedDatabaseKey {
            format_version: KEY_WRAP_FORMAT,
            kdf: "Argon2id".into(),
            memory_kib: ARGON2_MEMORY_KIB,
            iterations: ARGON2_ITERATIONS,
            parallelism: ARGON2_PARALLELISM,
            salt_b64: B64.encode(salt),
            nonce_b64: B64.encode(nonce),
            ciphertext_b64: B64.encode(ciphertext),
        })
    }

    pub fn unwrap_with_password(wrapped: &WrappedDatabaseKey, password: &[u8]) -> Result<Self> {
        wrapped.validate_policy()?;
        if password.is_empty() {
            return Err(anyhow!("password must not be empty"));
        }
        let salt = decode_exact::<16>(&wrapped.salt_b64, "key-wrap salt")?;
        let nonce = decode_exact::<24>(&wrapped.nonce_b64, "key-wrap nonce")?;
        if wrapped.ciphertext_b64.len() > 128 {
            return Err(anyhow!("invalid wrapped-key ciphertext length"));
        }
        let ciphertext = B64
            .decode(&wrapped.ciphertext_b64)
            .map_err(|_| anyhow!("invalid wrapped-key ciphertext"))?;
        if ciphertext.len() != 16 + 4 + 32 + 16 {
            return Err(anyhow!("invalid wrapped-key ciphertext length"));
        }
        let mut wrapping_key = Zeroizing::new([0_u8; 32]);
        derive_wrapping_key(password, &salt, &mut wrapping_key)?;
        let cipher = XChaCha20Poly1305::new_from_slice(wrapping_key.as_ref())?;
        let aad = wrapping_aad(&salt);
        let nonce_value =
            XNonce::try_from(nonce.as_slice()).map_err(|_| anyhow!("invalid wrap nonce"))?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce_value,
                    Payload {
                        msg: &ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow!("key unwrapping/authentication failed"))?,
        );
        decode_key_material(&plaintext)
    }
}

pub fn generate_key() -> Result<[u8; 32]> {
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key).map_err(|e| anyhow!("operating system RNG failed: {e}"))?;
    Ok(key)
}

pub fn key_from_hex(input: &str) -> Result<[u8; 32]> {
    if input.len() != 64 {
        return Err(anyhow!("key must be exactly 32 bytes / 64 hex characters"));
    }
    Zeroizing::new(hex::decode(input)?)
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("key must be exactly 32 bytes / 64 hex characters"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedDatabaseKey {
    pub format_version: u8,
    pub kdf: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

impl WrappedDatabaseKey {
    pub fn to_json(&self) -> Result<String> {
        self.validate_policy()?;
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    pub fn from_json(encoded: &str) -> Result<Self> {
        if encoded.len() > 16 * 1024 {
            return Err(anyhow!("wrapped-key document is too large"));
        }
        let wrapped: Self = serde_json::from_str(encoded)
            .map_err(|error| anyhow!("invalid wrapped-key document: {error}"))?;
        wrapped.validate_policy()?;
        Ok(wrapped)
    }

    fn validate_policy(&self) -> Result<()> {
        if self.format_version != KEY_WRAP_FORMAT
            || self.kdf != "Argon2id"
            || self.memory_kib != ARGON2_MEMORY_KIB
            || self.iterations != ARGON2_ITERATIONS
            || self.parallelism != ARGON2_PARALLELISM
        {
            return Err(anyhow!("unsupported or unsafe wrapped-key parameters"));
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct Keyring {
    keys: HashMap<(String, u32), DatabaseKey>,
}

impl Keyring {
    pub fn insert(&mut self, key: DatabaseKey) -> Result<()> {
        let id = key.key_id();
        let version = key.version();
        if self.keys.insert((id, version), key).is_some() {
            return Err(anyhow!("duplicate key ID and version"));
        }
        Ok(())
    }
    pub fn decrypt(&self, document: &EncryptedDocument) -> Result<Vec<u8>> {
        let key = self
            .keys
            .get(&(document.key_id.clone(), document.key_version))
            .ok_or_else(|| anyhow!("required content key is unavailable"))?;
        decrypt_document(key, document)
    }
}

pub fn encrypt_document(
    key: &DatabaseKey,
    database_id: &str,
    collection: &str,
    id: &str,
    version: u64,
    plaintext: &[u8],
) -> Result<EncryptedDocument> {
    validate_context(database_id, collection, id, version)?;
    let document_key = derive_document_key(key, database_id, collection, id)?;
    let cipher = XChaCha20Poly1305::new_from_slice(document_key.as_ref())?;
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|e| anyhow!("operating system RNG failed: {e}"))?;
    let mut document = EncryptedDocument {
        format_version: ENVELOPE_FORMAT_VERSION,
        algorithm: ENCRYPTION_ALGORITHM.into(),
        database_id: database_id.into(),
        key_id: key.key_id(),
        key_version: key.version(),
        collection: collection.into(),
        id: id.into(),
        version,
        nonce_b64: B64.encode(nonce),
        ciphertext_b64: String::new(),
    };
    let aad = envelope_aad(&document);
    let nonce_value = XNonce::try_from(nonce.as_slice()).map_err(|_| anyhow!("invalid nonce"))?;
    document.ciphertext_b64 = B64.encode(
        cipher
            .encrypt(
                &nonce_value,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("encryption failed"))?,
    );
    nonce.zeroize();
    Ok(document)
}

pub fn decrypt_document(key: &DatabaseKey, document: &EncryptedDocument) -> Result<Vec<u8>> {
    validate_envelope(document)?;
    if document.key_id != key.key_id() || document.key_version != key.version() {
        return Err(anyhow!("content key ID or version mismatch"));
    }
    let document_key = derive_document_key(
        key,
        &document.database_id,
        &document.collection,
        &document.id,
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(document_key.as_ref())?;
    let nonce = decode_exact::<24>(&document.nonce_b64, "XChaCha20 nonce")?;
    let ciphertext = B64
        .decode(&document.ciphertext_b64)
        .map_err(|_| anyhow!("invalid ciphertext encoding"))?;
    if ciphertext.len() < 16 {
        return Err(anyhow!("ciphertext is too short"));
    }
    let nonce_value = XNonce::try_from(nonce.as_slice()).map_err(|_| anyhow!("invalid nonce"))?;
    cipher
        .decrypt(
            &nonce_value,
            Payload {
                msg: &ciphertext,
                aad: &envelope_aad(document),
            },
        )
        .map_err(|_| anyhow!("decryption/authentication failed"))
}

pub fn validate_envelope(document: &EncryptedDocument) -> Result<()> {
    validate_context(
        &document.database_id,
        &document.collection,
        &document.id,
        document.version,
    )?;
    if document.format_version != ENVELOPE_FORMAT_VERSION
        || document.algorithm != ENCRYPTION_ALGORITHM
        || document.key_version == 0
    {
        return Err(anyhow!("unsupported encrypted envelope"));
    }
    if document.key_id.len() != 32
        || hex::decode(&document.database_id)?.len() != 16
        || hex::decode(&document.key_id)?.len() != 16
    {
        return Err(anyhow!("invalid database or key ID"));
    }
    decode_exact::<24>(&document.nonce_b64, "XChaCha20 nonce")?;
    if document.ciphertext_b64.len() > MAX_CIPHERTEXT_B64 {
        return Err(anyhow!("invalid ciphertext length"));
    }
    let ciphertext = B64
        .decode(&document.ciphertext_b64)
        .map_err(|_| anyhow!("invalid ciphertext encoding"))?;
    if ciphertext.len() < 16 || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(anyhow!("invalid ciphertext length"));
    }
    Ok(())
}

fn derive_document_key(
    key: &DatabaseKey,
    database_id: &str,
    collection: &str,
    id: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let salt = hex::decode(database_id)?;
    let root = Hkdf::<Sha256>::new(Some(&salt), key.secret.as_ref());
    let mut collection_key = Zeroizing::new([0_u8; 32]);
    let mut collection_info = b"vdb.collection.key.v1\0".to_vec();
    append_field(&mut collection_info, key.key_id().as_bytes());
    collection_info.extend_from_slice(&key.version.to_be_bytes());
    append_field(&mut collection_info, collection.as_bytes());
    root.expand(&collection_info, collection_key.as_mut())
        .map_err(|_| anyhow!("collection key derivation failed"))?;
    let document_hkdf = Hkdf::<Sha256>::new(None, collection_key.as_ref());
    let mut document_key = Zeroizing::new([0_u8; 32]);
    let mut document_info = b"vdb.document.key.v1\0".to_vec();
    append_field(&mut document_info, id.as_bytes());
    document_hkdf
        .expand(&document_info, document_key.as_mut())
        .map_err(|_| anyhow!("document key derivation failed"))?;
    Ok(document_key)
}

fn envelope_aad(document: &EncryptedDocument) -> Vec<u8> {
    let mut aad = b"vdb.envelope.aad.v2\0".to_vec();
    aad.push(document.format_version);
    for value in [&document.algorithm, &document.database_id, &document.key_id] {
        append_field(&mut aad, value.as_bytes());
    }
    aad.extend_from_slice(&document.key_version.to_be_bytes());
    append_field(&mut aad, document.collection.as_bytes());
    append_field(&mut aad, document.id.as_bytes());
    aad.extend_from_slice(&document.version.to_be_bytes());
    aad
}

fn validate_context(database_id: &str, collection: &str, id: &str, version: u64) -> Result<()> {
    if version == 0
        || database_id.len() != 32
        || collection.is_empty()
        || id.is_empty()
        || collection.len() > 1024
        || id.len() > 1024
        || collection.contains('\0')
        || id.contains('\0')
    {
        return Err(anyhow!("invalid encryption context"));
    }
    Ok(())
}

fn derive_wrapping_key(password: &[u8], salt: &[u8; 16], output: &mut [u8; 32]) -> Result<()> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|_| anyhow!("invalid Argon2id parameters"))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, output)
        .map_err(|_| anyhow!("Argon2id key derivation failed"))
}

fn wrapping_aad(salt: &[u8; 16]) -> Vec<u8> {
    let mut aad = b"vdb.key.wrap.v1\0".to_vec();
    aad.extend_from_slice(&ARGON2_MEMORY_KIB.to_be_bytes());
    aad.extend_from_slice(&ARGON2_ITERATIONS.to_be_bytes());
    aad.extend_from_slice(&ARGON2_PARALLELISM.to_be_bytes());
    aad.extend_from_slice(salt);
    aad
}

fn encode_key_material(key: &DatabaseKey) -> Vec<u8> {
    let mut value = Vec::with_capacity(52);
    value.extend_from_slice(&key.key_id);
    value.extend_from_slice(&key.version.to_be_bytes());
    value.extend_from_slice(key.secret.as_ref());
    value
}

fn decode_key_material(bytes: &[u8]) -> Result<DatabaseKey> {
    if bytes.len() != 52 {
        return Err(anyhow!("invalid key material length"));
    }
    let key_id = bytes[..16]
        .try_into()
        .map_err(|_| anyhow!("invalid key ID"))?;
    let version = u32::from_be_bytes(
        bytes[16..20]
            .try_into()
            .map_err(|_| anyhow!("invalid key version"))?,
    );
    let secret = bytes[20..]
        .try_into()
        .map_err(|_| anyhow!("invalid key secret"))?;
    DatabaseKey::from_parts(key_id, version, secret)
}

fn append_field(output: &mut Vec<u8>, field: &[u8]) {
    output.extend_from_slice(&(field.len() as u64).to_be_bytes());
    output.extend_from_slice(field);
}

fn decode_exact<const N: usize>(encoded: &str, name: &str) -> Result<[u8; N]> {
    let expected_encoded_len = N.div_ceil(3) * 4;
    if encoded.len() != expected_encoded_len {
        return Err(anyhow!("invalid {name} length"));
    }
    B64.decode(encoded)
        .map_err(|_| anyhow!("invalid {name} encoding"))?
        .try_into()
        .map_err(|_| anyhow!("invalid {name} length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DB: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn round_trip_tamper_wrong_key_and_metadata_substitution() -> Result<()> {
        let key = DatabaseKey::generate()?;
        let wrong = DatabaseKey::generate()?;
        let document = encrypt_document(&key, DB, "users", "alice", 1, br#"{"name":"Alice"}"#)?;
        assert_eq!(decrypt_document(&key, &document)?, br#"{"name":"Alice"}"#);
        assert!(decrypt_document(&wrong, &document).is_err());
        let mut tampered = document.clone();
        let mut ciphertext = B64.decode(&tampered.ciphertext_b64)?;
        ciphertext[0] ^= 1;
        tampered.ciphertext_b64 = B64.encode(ciphertext);
        assert!(decrypt_document(&key, &tampered).is_err());
        for substituted in [
            EncryptedDocument {
                database_id: "ffeeddccbbaa99887766554433221100".into(),
                ..document.clone()
            },
            EncryptedDocument {
                collection: "admins".into(),
                ..document.clone()
            },
            EncryptedDocument {
                id: "mallory".into(),
                ..document.clone()
            },
            EncryptedDocument {
                version: 2,
                ..document.clone()
            },
        ] {
            assert!(decrypt_document(&key, &substituted).is_err());
        }
        Ok(())
    }

    #[test]
    fn random_nonces_are_unique_across_many_encryptions() -> Result<()> {
        let key = DatabaseKey::generate()?;
        let mut nonces = std::collections::HashSet::new();
        for version in 1..=1024 {
            let document = encrypt_document(&key, DB, "users", "alice", version, b"{}")?;
            assert!(nonces.insert(document.nonce_b64));
        }
        Ok(())
    }

    #[test]
    fn rotation_requires_exact_old_or_new_key_version() -> Result<()> {
        let old = DatabaseKey::generate()?;
        let new = old.rotate()?;
        let old_doc = encrypt_document(&old, DB, "users", "alice", 1, b"old")?;
        let new_doc = encrypt_document(&new, DB, "users", "alice", 2, b"new")?;
        assert!(decrypt_document(&new, &old_doc).is_err());
        assert!(decrypt_document(&old, &new_doc).is_err());
        let mut ring = Keyring::default();
        ring.insert(old)?;
        ring.insert(new)?;
        assert_eq!(ring.decrypt(&old_doc)?, b"old");
        assert_eq!(ring.decrypt(&new_doc)?, b"new");
        Ok(())
    }

    #[test]
    fn password_wrap_round_trip_and_wrong_password_fails() -> Result<()> {
        let key = DatabaseKey::generate()?;
        let wrapped = key.wrap_with_password(b"correct horse battery staple")?;
        let wrapped = WrappedDatabaseKey::from_json(&wrapped.to_json()?)?;
        let imported =
            DatabaseKey::unwrap_with_password(&wrapped, b"correct horse battery staple")?;
        assert_eq!(imported.key_id(), key.key_id());
        assert_eq!(imported.version(), key.version());
        assert!(DatabaseKey::unwrap_with_password(&wrapped, b"wrong password").is_err());

        let mut tampered = wrapped.clone();
        let mut ciphertext = B64.decode(&tampered.ciphertext_b64)?;
        ciphertext[0] ^= 1;
        tampered.ciphertext_b64 = B64.encode(ciphertext);
        assert!(
            DatabaseKey::unwrap_with_password(&tampered, b"correct horse battery staple").is_err()
        );

        let mut downgraded = wrapped;
        downgraded.memory_kib -= 1;
        assert!(
            DatabaseKey::unwrap_with_password(&downgraded, b"correct horse battery staple")
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn malformed_ciphertext_is_rejected_without_panicking() -> Result<()> {
        let key = DatabaseKey::generate()?;
        let mut document = encrypt_document(&key, DB, "users", "alice", 1, b"{}")?;
        document.ciphertext_b64 = "not base64".into();
        assert!(decrypt_document(&key, &document).is_err());

        let mut document = encrypt_document(&key, DB, "users", "alice", 1, b"{}")?;
        document.nonce_b64 = "AA==".into();
        assert!(decrypt_document(&key, &document).is_err());

        let mut document = encrypt_document(&key, DB, "users", "alice", 1, b"{}")?;
        document.ciphertext_b64 = "A".repeat(MAX_CIPHERTEXT_B64 + 1);
        assert!(validate_envelope(&document).is_err());
        Ok(())
    }
}
