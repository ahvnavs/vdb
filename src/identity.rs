use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Result, StoreError, corruption};

pub const SIGNATURE_ALGORITHM: &str = "Ed25519";

/// An in-memory writer/device signing identity. `SigningKey` zeroizes its secret on drop.
pub struct WriterIdentity {
    writer_id: [u8; 16],
    key_version: u32,
    signing_key: SigningKey,
}

impl WriterIdentity {
    pub fn generate() -> Result<Self> {
        let mut writer_id = [0_u8; 16];
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut writer_id).map_err(|e| StoreError::Storage(e.to_string()))?;
        getrandom::fill(&mut seed).map_err(|e| StoreError::Storage(e.to_string()))?;
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(Self {
            writer_id,
            key_version: 1,
            signing_key,
        })
    }

    pub fn from_seed(writer_id: [u8; 16], key_version: u32, mut seed: [u8; 32]) -> Result<Self> {
        if key_version == 0 {
            seed.zeroize();
            return Err(StoreError::InvalidInput(
                "writer key version must be non-zero".into(),
            ));
        }
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(Self {
            writer_id,
            key_version,
            signing_key,
        })
    }

    pub fn writer_id(&self) -> String {
        hex::encode(self.writer_id)
    }
    pub fn key_version(&self) -> u32 {
        self.key_version
    }
    pub fn public_key(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }
    pub fn secret_seed_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.signing_key.to_bytes()))
    }
    pub(crate) fn sign(&self, message: &[u8]) -> String {
        hex::encode(self.signing_key.sign(message).to_bytes())
    }
}

pub(crate) fn verify_signature(
    public_key_hex: &str,
    signature_hex: &str,
    message: &[u8],
) -> Result<()> {
    let public: [u8; 32] = hex::decode(public_key_hex)
        .map_err(corruption)?
        .try_into()
        .map_err(|_| corruption("invalid Ed25519 public key length"))?;
    let signature: [u8; 64] = hex::decode(signature_hex)
        .map_err(corruption)?
        .try_into()
        .map_err(|_| corruption("invalid Ed25519 signature length"))?;
    let key = VerifyingKey::from_bytes(&public).map_err(corruption)?;
    key.verify(message, &Signature::from_bytes(&signature))
        .map_err(|_| corruption("invalid mutation signature"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_signs_and_wrong_identity_fails() -> Result<()> {
        let identity = WriterIdentity::generate()?;
        let wrong = WriterIdentity::generate()?;
        let message = b"vdb identity test";
        let signature = identity.sign(message);
        verify_signature(&identity.public_key(), &signature, message)?;
        assert!(verify_signature(&wrong.public_key(), &signature, message).is_err());
        Ok(())
    }
}
