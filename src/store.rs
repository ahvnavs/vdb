use std::{path::Path, sync::Arc};

use crate::{
    error::Result,
    identity::WriterIdentity,
    model::{
        DatabaseMetadata, DocumentRecord, EncryptedDocument, InclusionProof, MutationRecord,
        StateCheckpoint, VerifyReport, VersionPrecondition, WriteOperation,
    },
    storage::{StorageEngine, StorageSnapshot, redb::RedbEngine},
};

/// Database facade. Storage-engine details never cross this boundary.
#[derive(Clone)]
pub struct Store {
    engine: Arc<dyn StorageEngine>,
    identity: Arc<WriterIdentity>,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_identity(path, WriterIdentity::generate()?)
    }

    pub fn open_with_identity(path: impl AsRef<Path>, identity: WriterIdentity) -> Result<Self> {
        Ok(Self {
            engine: Arc::new(RedbEngine::open(path)?),
            identity: Arc::new(identity),
        })
    }

    pub fn writer_id(&self) -> String {
        self.identity.writer_id()
    }

    pub fn mutation(&self, sequence: u64) -> Result<Option<MutationRecord>> {
        let record = self.engine.mutation(sequence)?;
        if let Some(record) = &record {
            crate::storage::redb::verify_mutation_record(record)?;
        }
        Ok(record)
    }

    pub fn checkpoint(&self) -> Result<StateCheckpoint> {
        self.engine.checkpoint()
    }

    pub fn inclusion_proof(&self, collection: &str, id: &str) -> Result<Option<InclusionProof>> {
        self.engine.inclusion_proof(collection, id)
    }

    /// Detects rollback/truncation relative to a checkpoint retained outside the database.
    pub fn verify_against(&self, expected: &StateCheckpoint) -> Result<bool> {
        Ok(self.checkpoint()? == *expected)
    }

    pub fn metadata(&self) -> Result<DatabaseMetadata> {
        self.engine.metadata()
    }

    /// Starts a stable read snapshot. Later commits are not visible through it.
    pub fn read_snapshot(&self) -> Result<ReadSnapshot> {
        Ok(ReadSnapshot {
            inner: self.engine.snapshot()?,
        })
    }

    pub fn get_record(&self, collection: &str, id: &str) -> Result<Option<DocumentRecord>> {
        self.read_snapshot()?.get_record(collection, id)
    }

    /// Returns only live payloads. Use `get_record` to observe tombstones.
    pub fn get(&self, collection: &str, id: &str) -> Result<Option<EncryptedDocument>> {
        self.read_snapshot()?.get(collection, id)
    }

    pub fn put(&self, document: &EncryptedDocument) -> Result<MutationRecord> {
        self.put_if(document, VersionPrecondition::Any)
    }

    pub fn put_if(
        &self,
        document: &EncryptedDocument,
        precondition: VersionPrecondition,
    ) -> Result<MutationRecord> {
        let mut result = self.write_transaction(vec![WriteOperation::Put {
            document: document.clone(),
            precondition,
        }])?;
        Ok(result.remove(0))
    }

    pub fn delete(
        &self,
        collection: &str,
        id: &str,
        version: u64,
        precondition: VersionPrecondition,
    ) -> Result<MutationRecord> {
        let mut result = self.write_transaction(vec![WriteOperation::Delete {
            collection: collection.into(),
            id: id.into(),
            version,
            precondition,
        }])?;
        Ok(result.remove(0))
    }

    /// Applies all operations atomically. On any validation or conflict error, none commit.
    pub fn write_transaction(
        &self,
        operations: Vec<WriteOperation>,
    ) -> Result<Vec<MutationRecord>> {
        self.engine.write(&operations, &self.identity)
    }

    pub fn verify(&self) -> Result<VerifyReport> {
        self.engine.verify()
    }
}

pub struct ReadSnapshot {
    inner: Box<dyn StorageSnapshot>,
}

impl ReadSnapshot {
    pub fn get_record(&self, collection: &str, id: &str) -> Result<Option<DocumentRecord>> {
        self.inner.get(collection, id)
    }

    pub fn get(&self, collection: &str, id: &str) -> Result<Option<EncryptedDocument>> {
        Ok(self.get_record(collection, id)?.and_then(|record| {
            if record.metadata.deleted {
                None
            } else {
                record.payload
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{DatabaseKey, encrypt_document, generate_key},
        error::StoreError,
    };
    use std::{
        env, fs,
        process::Command,
        sync::{Arc, Barrier},
        thread,
    };
    use tempfile::tempdir;

    fn database() -> Result<(tempfile::TempDir, Store, [u8; 32])> {
        let directory = tempdir().map_err(|e| StoreError::Storage(e.to_string()))?;
        let store = Store::open(directory.path().join("test.vdb"))?;
        let key = generate_key().map_err(|e| StoreError::Storage(e.to_string()))?;
        Ok((directory, store, key))
    }

    fn test_document(
        store: &Store,
        secret: &[u8; 32],
        collection: &str,
        id: &str,
        version: u64,
        plaintext: &[u8],
    ) -> std::result::Result<EncryptedDocument, anyhow::Error> {
        let database_id = store.metadata().map_err(anyhow::Error::from)?.database_id;
        let key = DatabaseKey::from_database_secret(&database_id, *secret)?;
        encrypt_document(&key, &database_id, collection, id, version, plaintext)
    }

    #[test]
    fn metadata_survives_reopen_and_database_id_is_stable() -> Result<()> {
        let directory = tempdir().map_err(|e| StoreError::Storage(e.to_string()))?;
        let path = directory.path().join("test.vdb");
        let first = Store::open(&path)?.metadata()?;
        drop(Store::open(&path)?);
        let reopened = Store::open(&path)?.metadata()?;
        assert_eq!(first, reopened);
        assert_eq!(first.format_version, crate::model::DATABASE_FORMAT_VERSION);
        Ok(())
    }

    #[test]
    fn put_delete_tombstone_and_reopen() -> Result<()> {
        let (directory, store, key) = database()?;
        let path = directory.path().join("test.vdb");
        let document = test_document(&store, &key, "users", "alice", 1, b"{}")
            .map_err(|e| StoreError::Storage(e.to_string()))?;
        store.put_if(&document, VersionPrecondition::MustNotExist)?;
        store.delete("users", "alice", 2, VersionPrecondition::IfVersion(1))?;
        assert!(store.get("users", "alice")?.is_none());
        let tombstone = store.get_record("users", "alice")?.expect("tombstone");
        assert!(tombstone.metadata.deleted);
        assert!(tombstone.payload.is_none());
        drop(store);
        let reopened = Store::open(path)?;
        assert!(
            reopened
                .get_record("users", "alice")?
                .expect("tombstone after reopen")
                .metadata
                .deleted
        );
        assert!(reopened.verify()?.valid);
        Ok(())
    }

    #[test]
    fn storage_round_trip_does_not_require_the_content_key() -> Result<()> {
        let directory = tempdir().map_err(|e| StoreError::Storage(e.to_string()))?;
        let path = directory.path().join("test.vdb");
        let store = Store::open(&path)?;
        let database_id = store.metadata()?.database_id;
        let key = DatabaseKey::generate().map_err(|e| StoreError::Storage(e.to_string()))?;
        let document = encrypt_document(&key, &database_id, "users", "alice", 1, b"secret")
            .map_err(|e| StoreError::Storage(e.to_string()))?;
        drop(key);

        store.put(&document)?;
        drop(store);
        let reopened = Store::open(path)?;
        assert_eq!(reopened.get("users", "alice")?, Some(document));
        assert!(reopened.verify()?.valid);
        Ok(())
    }

    #[test]
    fn transaction_is_all_or_nothing_on_conflict() -> Result<()> {
        let (_directory, store, key) = database()?;
        let alice = test_document(&store, &key, "users", "alice", 1, b"{}")
            .map_err(|e| StoreError::Storage(e.to_string()))?;
        let bob = test_document(&store, &key, "users", "bob", 1, b"{}")
            .map_err(|e| StoreError::Storage(e.to_string()))?;
        store.put(&alice)?;
        let result = store.write_transaction(vec![
            WriteOperation::Put {
                document: bob,
                precondition: VersionPrecondition::MustNotExist,
            },
            WriteOperation::Delete {
                collection: "users".into(),
                id: "alice".into(),
                version: 2,
                precondition: VersionPrecondition::IfVersion(99),
            },
        ]);
        assert!(matches!(result, Err(StoreError::Conflict { .. })));
        assert!(store.get("users", "bob")?.is_none());
        assert_eq!(store.verify()?.mutations, 1);
        Ok(())
    }

    #[test]
    fn multi_document_transaction_commits_one_atomic_sequence() -> Result<()> {
        let (_directory, store, key) = database()?;
        let alice = test_document(&store, &key, "users", "alice", 1, b"{}")
            .map_err(|e| StoreError::Storage(e.to_string()))?;
        let bob = test_document(&store, &key, "users", "bob", 1, b"{}")
            .map_err(|e| StoreError::Storage(e.to_string()))?;
        let mutations = store.write_transaction(vec![
            WriteOperation::Put {
                document: alice,
                precondition: VersionPrecondition::MustNotExist,
            },
            WriteOperation::Put {
                document: bob,
                precondition: VersionPrecondition::MustNotExist,
            },
        ])?;
        assert_eq!(
            mutations.iter().map(|m| m.sequence).collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(store.get("users", "alice")?.is_some());
        assert!(store.get("users", "bob")?.is_some());
        assert!(store.verify()?.valid);
        Ok(())
    }

    #[test]
    fn deterministic_checkpoint_and_inclusion_proof_cover_tombstones() -> Result<()> {
        let (_directory, store, key) = database()?;
        for id in ["alice", "bob", "carol"] {
            let document = test_document(&store, &key, "users", id, 1, b"{}")
                .map_err(|e| StoreError::Storage(e.to_string()))?;
            store.put(&document)?;
        }
        store.delete("users", "bob", 2, VersionPrecondition::IfVersion(1))?;
        let first = store.checkpoint()?;
        let second = store.checkpoint()?;
        assert_eq!(first, second);
        assert_eq!(first.leaf_count, 3);

        let proof = store.inclusion_proof("users", "bob")?.expect("proof");
        assert!(proof.metadata.deleted);
        crate::merkle::verify_inclusion_proof(&proof)?;

        let mut invalid = proof.clone();
        invalid.checkpoint.state_root = "00".repeat(32);
        assert!(crate::merkle::verify_inclusion_proof(&invalid).is_err());
        let mut invalid_sibling = proof;
        invalid_sibling.siblings[0] = "ff".repeat(32);
        assert!(crate::merkle::verify_inclusion_proof(&invalid_sibling).is_err());
        Ok(())
    }

    #[test]
    fn writer_key_version_can_rotate_without_changing_writer_id() -> Result<()> {
        let directory = tempdir().map_err(|e| StoreError::Storage(e.to_string()))?;
        let path = directory.path().join("rotation.vdb");
        let writer_id = [8_u8; 16];
        let first_identity = crate::identity::WriterIdentity::from_seed(writer_id, 1, [1_u8; 32])?;
        let first = Store::open_with_identity(&path, first_identity)?;
        let document = test_document(&first, &[7_u8; 32], "users", "alice", 1, b"{}")
            .map_err(|e| StoreError::Storage(e.to_string()))?;
        first.put(&document)?;
        drop(first);

        let second_identity = crate::identity::WriterIdentity::from_seed(writer_id, 2, [2_u8; 32])?;
        let second = Store::open_with_identity(&path, second_identity)?;
        let document = test_document(&second, &[7_u8; 32], "users", "alice", 2, b"{\"v\":2}")
            .map_err(|e| StoreError::Storage(e.to_string()))?;
        second.put(&document)?;
        assert_eq!(
            second
                .mutation(1)?
                .expect("first mutation")
                .writer_key_version,
            1
        );
        assert_eq!(
            second
                .mutation(2)?
                .expect("second mutation")
                .writer_key_version,
            2
        );
        assert!(second.verify()?.valid);
        Ok(())
    }

    #[test]
    fn held_snapshot_does_not_observe_later_commit() -> Result<()> {
        let (_directory, store, key) = database()?;
        let first = test_document(&store, &key, "users", "alice", 1, b"{}")
            .map_err(|e| StoreError::Storage(e.to_string()))?;
        store.put(&first)?;
        let snapshot = store.read_snapshot()?;
        let second = test_document(&store, &key, "users", "alice", 2, b"{\"v\":2}")
            .map_err(|e| StoreError::Storage(e.to_string()))?;
        store.put(&second)?;
        assert_eq!(
            snapshot
                .get("users", "alice")?
                .expect("snapshot value")
                .version,
            1
        );
        assert_eq!(
            store.get("users", "alice")?.expect("current value").version,
            2
        );
        Ok(())
    }

    #[test]
    fn concurrent_readers_and_single_cas_winner() -> Result<()> {
        let (_directory, store, key) = database()?;
        let initial = test_document(&store, &key, "users", "alice", 1, b"{}")
            .map_err(|e| StoreError::Storage(e.to_string()))?;
        store.put(&initial)?;
        let store = Arc::new(store);
        let barrier = Arc::new(Barrier::new(3));
        let mut writers = Vec::new();
        for marker in [2_u8, 3_u8] {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            writers.push(thread::spawn(move || {
                let document =
                    test_document(&store, &key, "users", "alice", 2, &[marker]).expect("encrypt");
                barrier.wait();
                store.put_if(&document, VersionPrecondition::IfVersion(1))
            }));
        }
        barrier.wait();
        let results: Vec<_> = writers
            .into_iter()
            .map(|h| h.join().expect("writer thread"))
            .collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(StoreError::Conflict { .. })))
                .count(),
            1
        );
        let mut readers = Vec::new();
        for _ in 0..8 {
            let store = Arc::clone(&store);
            readers.push(thread::spawn(move || store.get("users", "alice")));
        }
        for reader in readers {
            assert_eq!(
                reader
                    .join()
                    .expect("reader thread")?
                    .expect("value")
                    .version,
                2
            );
        }
        Ok(())
    }

    #[test]
    fn malformed_file_is_not_reported_as_recoverable() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("malformed.vdb");
        fs::write(&path, b"not a redb database").expect("write malformed database");
        let error = match Store::open(path) {
            Ok(_) => panic!("malformed database opened"),
            Err(error) => error,
        };
        assert!(!error.is_recoverable());
    }

    #[test]
    fn committed_write_survives_process_abort() -> Result<()> {
        const CHILD_FLAG: &str = "VDB_CRASH_TEST_CHILD";
        const PATH_FLAG: &str = "VDB_CRASH_TEST_PATH";
        if env::var_os(CHILD_FLAG).is_some() {
            let path = env::var_os(PATH_FLAG).expect("child database path");
            let store = Store::open(path)?;
            let document = test_document(&store, &[9_u8; 32], "users", "alice", 1, b"{}")
                .map_err(|e| StoreError::Storage(e.to_string()))?;
            store.put(&document)?;
            std::process::abort();
        }

        let directory = tempdir().map_err(|e| StoreError::Storage(e.to_string()))?;
        let path = directory.path().join("crash.vdb");
        let status =
            Command::new(env::current_exe().map_err(|e| StoreError::Storage(e.to_string()))?)
                .args([
                    "--exact",
                    "store::tests::committed_write_survives_process_abort",
                    "--nocapture",
                ])
                .env(CHILD_FLAG, "1")
                .env(PATH_FLAG, &path)
                .status()
                .map_err(|e| StoreError::Storage(e.to_string()))?;
        assert!(!status.success(), "child must terminate abnormally");

        let reopened = Store::open(path)?;
        assert_eq!(
            reopened
                .get("users", "alice")?
                .expect("durable value")
                .version,
            1
        );
        assert!(reopened.verify()?.valid);
        Ok(())
    }
}
