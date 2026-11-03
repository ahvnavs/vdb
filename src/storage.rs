use crate::{
    error::Result,
    identity::WriterIdentity,
    model::{
        DatabaseMetadata, DocumentRecord, InclusionProof, MutationRecord, StateCheckpoint,
        VerifyReport, WriteOperation,
    },
};

pub(crate) trait StorageSnapshot: Send + Sync {
    fn get(&self, collection: &str, id: &str) -> Result<Option<DocumentRecord>>;
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
    fn verify(&self) -> Result<VerifyReport>;
}

pub(crate) mod redb;
