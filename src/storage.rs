use crate::{
    error::Result,
    identity::WriterIdentity,
    model::{
        DatabaseMetadata, DocumentRecord, InclusionProof, MutationRecord, StateCheckpoint,
        VerifyReport, WriteOperation,
    },
    query::{IndexDefinition, QueryValue},
    replication::ReplicationEvent,
};

#[derive(Debug, Clone)]
pub(crate) struct BackupTable {
    pub id: u8,
    pub rows: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub(crate) struct BackupImage {
    pub tables: Vec<BackupTable>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StorageStatistics {
    pub allocated_pages: u64,
    pub leaf_pages: u64,
    pub branch_pages: u64,
    pub stored_bytes: u64,
    pub metadata_bytes: u64,
    pub fragmented_bytes: u64,
    pub page_size: usize,
    pub documents: u64,
    pub live_documents: u64,
    pub tombstones: u64,
    pub mutations: u64,
    pub writers: u64,
    pub indexes: u64,
    pub index_entries: u64,
    pub replication_events: u64,
}

pub(crate) trait StorageSnapshot: Send + Sync {
    fn get(&self, collection: &str, id: &str) -> Result<Option<DocumentRecord>>;
    fn scan_collection(&self, collection: &str) -> Result<Vec<DocumentRecord>>;
    fn lookup_index(
        &self,
        index: &IndexDefinition,
        equality_prefix: &[QueryValue],
    ) -> Result<Vec<DocumentRecord>>;
    fn list_indexes(&self, collection: &str) -> Result<Vec<IndexDefinition>>;
}

pub(crate) trait StorageEngine: Send + Sync {
    fn metadata(&self) -> Result<DatabaseMetadata>;
    fn snapshot(&self) -> Result<Box<dyn StorageSnapshot>>;
    fn write(
        &self,
        operations: &[WriteOperation],
        identity: &WriterIdentity,
    ) -> Result<Vec<MutationRecord>>;
    fn mutation(&self, sequence: u64) -> Result<Option<MutationRecord>>;
    fn checkpoint(&self) -> Result<StateCheckpoint>;
    fn inclusion_proof(&self, collection: &str, id: &str) -> Result<Option<InclusionProof>>;
    fn list_indexes(&self, collection: &str) -> Result<Vec<IndexDefinition>>;
    fn create_index(&self, index: &IndexDefinition) -> Result<()>;
    fn drop_index(&self, collection: &str, name: &str) -> Result<()>;
    fn rebuild_index(&self, collection: &str, name: &str) -> Result<()>;
    fn verify(&self) -> Result<VerifyReport>;
    fn replication_events(&self) -> Result<Vec<ReplicationEvent>>;
    fn store_replication_events(&self, events: &[ReplicationEvent]) -> Result<usize>;
    fn backup_image(&self) -> Result<BackupImage>;
    fn statistics(&self) -> Result<StorageStatistics>;
}

pub(crate) mod redb;
