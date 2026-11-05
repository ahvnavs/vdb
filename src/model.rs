use serde::{Deserialize, Serialize};

pub const DATABASE_FORMAT_VERSION: u32 = 5;
pub const ENVELOPE_FORMAT_VERSION: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedDocument {
    pub format_version: u8,
    pub algorithm: String,
    pub database_id: String,
    pub key_id: String,
    pub key_version: u32,
    pub collection: String,
    pub id: String,
    pub version: u64,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseMetadata {
    pub format_version: u32,
    pub database_id: String,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentMetadata {
    pub collection: String,
    pub id: String,
    pub version: u64,
    pub created_sequence: u64,
    pub modified_sequence: u64,
    pub deleted: bool,
    pub payload_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentRecord {
    pub metadata: DocumentMetadata,
    pub payload: Option<EncryptedDocument>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    Put,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationRecord {
    pub sequence: u64,
    pub kind: MutationKind,
    pub collection: String,
    pub id: String,
    pub version: u64,
    pub metadata_hash: String,
    pub payload_hash: Option<String>,
    pub previous_mutation_hash: String,
    pub database_id: String,
    pub writer_id: String,
    pub writer_key_version: u32,
    pub writer_public_key: String,
    pub signature_algorithm: String,
    pub mutation_id: String,
    pub signature: String,
    pub mutation_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateCheckpoint {
    pub format_version: u32,
    pub database_id: String,
    pub sequence: u64,
    pub history_head: String,
    pub state_root: String,
    pub leaf_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub checkpoint: StateCheckpoint,
    pub metadata: DocumentMetadata,
    pub leaf_hash: String,
    pub leaf_index: u64,
    pub siblings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionPrecondition {
    Any,
    MustNotExist,
    MustExist,
    IfVersion(u64),
}

#[derive(Debug, Clone)]
pub enum WriteOperation {
    Put {
        document: EncryptedDocument,
        precondition: VersionPrecondition,
    },
    Delete {
        collection: String,
        id: String,
        version: u64,
        precondition: VersionPrecondition,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub valid: bool,
    pub mutations: u64,
    pub head: String,
    pub error: Option<String>,
}
