use std::collections::BTreeMap;
use std::{path::Path, sync::Arc};

use crate::{
    error::Result,
    identity::WriterIdentity,
    model::{
        DatabaseMetadata, DocumentRecord, EncryptedDocument, InclusionProof, MutationRecord,
        StateCheckpoint, VerifyReport, VersionPrecondition, WriteOperation,
    },
    query::{
        AccessPath, Direction, ExecutionMode, ExplainPlan, IndexDefinition, MetadataField,
        OrderingClause, Query, QueryResult, QueryRow, QueryValue, compare_records, cursor_for,
        decode_cursor, equality_constraints, field_value, is_after_cursor, matches_server,
        requires_client_filter, validate_query,
    },
    replication::ReplicationEvent,
    storage::{BackupImage, StorageEngine, StorageSnapshot, StorageStatistics, redb::RedbEngine},
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

    pub(crate) fn writer_key_version(&self) -> u32 {
        self.identity.key_version()
    }

    pub(crate) fn writer_public_key(&self) -> String {
        self.identity.public_key()
    }

    pub(crate) fn sign_bytes(&self, message: &[u8]) -> String {
        self.identity.sign_bytes(message)
    }

    pub(crate) fn replication_events(&self) -> Result<Vec<ReplicationEvent>> {
        self.engine.replication_events()
    }

    pub(crate) fn store_replication_events(&self, events: &[ReplicationEvent]) -> Result<usize> {
        self.engine.store_replication_events(events)
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

    pub fn storage_statistics(&self) -> Result<StorageStatistics> {
        self.engine.statistics()
    }

    pub(crate) fn backup_image(&self) -> Result<BackupImage> {
        self.engine.backup_image()
    }

    pub fn list_indexes(&self, collection: &str) -> Result<Vec<IndexDefinition>> {
        self.engine.list_indexes(collection)
    }

    pub fn create_index(&self, index: &IndexDefinition) -> Result<()> {
        self.engine.create_index(index)
    }

    pub fn drop_index(&self, collection: &str, name: &str) -> Result<()> {
        self.engine.drop_index(collection, name)
    }

    pub fn rebuild_index(&self, collection: &str, name: &str) -> Result<()> {
        self.engine.rebuild_index(collection, name)
    }

    pub fn explain(&self, query: &Query) -> Result<ExplainPlan> {
        let snapshot = self.read_snapshot()?;
        snapshot.explain(query)
    }

    pub fn query(&self, query: &Query) -> Result<QueryResult> {
        let snapshot = self.read_snapshot()?;
        snapshot.query(query)
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

    pub fn scan_collection(&self, collection: &str) -> Result<Vec<DocumentRecord>> {
        self.inner.scan_collection(collection)
    }

    pub fn explain(&self, query: &Query) -> Result<ExplainPlan> {
        validate_query(query)?;
        let indexes = self.inner.list_indexes(&query.collection)?;
        Ok(plan_query(query, &indexes))
    }

    pub fn query(&self, query: &Query) -> Result<QueryResult> {
        validate_query(query)?;
        let indexes = self.inner.list_indexes(&query.collection)?;
        let plan = plan_query(query, &indexes);
        let mut records = match &plan.access_path {
            AccessPath::DocumentId { id } => {
                self.inner.get(&query.collection, id)?.into_iter().collect()
            }
            AccessPath::SecondaryIndex {
                name,
                equality_prefix,
            } => {
                let index = indexes
                    .iter()
                    .find(|index| index.name == *name)
                    .ok_or_else(|| {
                        crate::error::StoreError::Corruption("planned index is missing".into())
                    })?;
                self.inner.lookup_index(index, equality_prefix)?
            }
            AccessPath::CollectionScan => self.inner.scan_collection(&query.collection)?,
        };
        if !query.include_deleted {
            records.retain(|record| !record.metadata.deleted);
        }
        if let Some(predicate) = &query.predicate {
            records.retain(|record| matches_server(record, predicate));
        }
        let order_by = effective_order(&query.order_by);
        records.sort_by(|left, right| compare_records(left, right, &order_by));
        if let Some(cursor) = &query.cursor {
            let (values, id) = decode_cursor(cursor)?;
            if values.len() != order_by.len() {
                return Err(crate::error::StoreError::InvalidInput(
                    "query cursor does not match ordering".into(),
                ));
            }
            records.retain(|record| is_after_cursor(record, &order_by, &values, &id));
        }
        let has_more = records.len() > query.limit;
        records.truncate(query.limit);
        let next_cursor = if has_more {
            records
                .last()
                .map(|record| cursor_for(record, &order_by))
                .transpose()?
        } else {
            None
        };
        let rows = records
            .into_iter()
            .map(|record| project_record(record, query.projection.as_deref()))
            .collect();
        Ok(QueryResult {
            rows,
            next_cursor,
            plan,
        })
    }
}

fn plan_query(query: &Query, indexes: &[IndexDefinition]) -> ExplainPlan {
    let requires_client = query.predicate.as_ref().is_some_and(requires_client_filter);
    let mode = if requires_client {
        ExecutionMode::ClientSideFiltering
    } else {
        ExecutionMode::ServerVisibleMetadata
    };
    let mut constraints = BTreeMap::new();
    if let Some(predicate) = &query.predicate {
        equality_constraints(predicate, &mut constraints);
    }
    let access_path =
        if let Some(QueryValue::String(id)) = constraints.get(&MetadataField::DocumentId) {
            AccessPath::DocumentId { id: id.clone() }
        } else {
            let selected = indexes
                .iter()
                .filter_map(|index| {
                    let prefix: Vec<_> = index
                        .fields
                        .iter()
                        .map_while(|field| constraints.get(field).cloned())
                        .collect();
                    (!prefix.is_empty()).then_some((index, prefix))
                })
                .max_by_key(|(_, prefix)| prefix.len());
            selected.map_or(AccessPath::CollectionScan, |(index, equality_prefix)| {
                AccessPath::SecondaryIndex {
                    name: index.name.clone(),
                    equality_prefix,
                }
            })
        };
    let order_in_memory = !matches!(access_path, AccessPath::DocumentId { .. });
    ExplainPlan {
        mode,
        residual_filter: query.predicate.is_some(),
        requires_client_filter: requires_client,
        order_in_memory,
        access_path,
    }
}

fn effective_order(order: &[OrderingClause]) -> Vec<OrderingClause> {
    if order.is_empty() {
        vec![OrderingClause {
            field: MetadataField::DocumentId,
            direction: Direction::Ascending,
        }]
    } else {
        order.to_vec()
    }
}

fn project_record(record: DocumentRecord, projection: Option<&[MetadataField]>) -> QueryRow {
    let fields = projection
        .map(|projection| {
            projection
                .iter()
                .filter_map(|field| {
                    field_value(&record, *field).map(|value| (field_name(*field).into(), value))
                })
                .collect()
        })
        .unwrap_or_default();
    QueryRow {
        collection: record.metadata.collection.clone(),
        id: record.metadata.id.clone(),
        fields,
        record: projection.is_none().then_some(record),
    }
}

fn field_name(field: MetadataField) -> &'static str {
    match field {
        MetadataField::DocumentId => "document_id",
        MetadataField::Version => "version",
        MetadataField::CreatedSequence => "created_sequence",
        MetadataField::ModifiedSequence => "modified_sequence",
        MetadataField::Deleted => "deleted",
        MetadataField::KeyId => "key_id",
        MetadataField::KeyVersion => "key_version",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{DatabaseKey, encrypt_document, generate_key},
        error::StoreError,
        query::{
            AccessPath, Direction, ExecutionMode, IndexDefinition, MetadataField, OrderingClause,
            Predicate, Query, QueryValue,
        },
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
    fn query_ast_projection_ordering_and_cursor_pagination() -> Result<()> {
        let (_directory, store, key) = database()?;
        for (id, version) in [("alice", 3), ("bob", 1), ("carol", 2), ("dave", 4)] {
            let document = test_document(&store, &key, "users", id, version, b"{}")
                .map_err(|error| StoreError::Storage(error.to_string()))?;
            store.put(&document)?;
        }
        let mut query = Query::collection("users");
        query.predicate = Some(Predicate::And {
            predicates: vec![
                Predicate::Ge {
                    field: MetadataField::Version,
                    value: QueryValue::Number(2),
                },
                Predicate::Or {
                    predicates: vec![
                        Predicate::Lt {
                            field: MetadataField::DocumentId,
                            value: QueryValue::String("dave".into()),
                        },
                        Predicate::Eq {
                            field: MetadataField::DocumentId,
                            value: QueryValue::String("dave".into()),
                        },
                    ],
                },
                Predicate::Exists {
                    field: MetadataField::KeyId,
                    exists: true,
                },
            ],
        });
        query.projection = Some(vec![MetadataField::Version]);
        query.order_by = vec![OrderingClause {
            field: MetadataField::Version,
            direction: Direction::Descending,
        }];
        query.limit = 2;

        let first = store.query(&query)?;
        assert_eq!(
            first
                .rows
                .iter()
                .map(|row| row.id.as_str())
                .collect::<Vec<_>>(),
            ["dave", "alice"]
        );
        assert!(first.rows.iter().all(|row| row.record.is_none()));
        assert_eq!(
            first.rows[0].fields.get("version"),
            Some(&QueryValue::Number(4))
        );
        query.cursor = first.next_cursor;
        let second = store.query(&query)?;
        assert_eq!(
            second
                .rows
                .iter()
                .map(|row| row.id.as_str())
                .collect::<Vec<_>>(),
            ["carol"]
        );
        assert!(second.next_cursor.is_none());
        Ok(())
    }

    #[test]
    fn indexed_and_scan_execution_are_logically_identical() -> Result<()> {
        let (directory, store, key) = database()?;
        for (id, version) in [("alice", 1), ("bob", 2), ("carol", 3), ("dave", 4)] {
            let document = test_document(&store, &key, "users", id, version, b"{}")
                .map_err(|error| StoreError::Storage(error.to_string()))?;
            store.put(&document)?;
        }
        let mut query = Query::collection("users");
        query.predicate = Some(Predicate::And {
            predicates: vec![
                Predicate::Eq {
                    field: MetadataField::Deleted,
                    value: QueryValue::Bool(false),
                },
                Predicate::Eq {
                    field: MetadataField::KeyVersion,
                    value: QueryValue::Number(1),
                },
                Predicate::Ne {
                    field: MetadataField::DocumentId,
                    value: QueryValue::String("bob".into()),
                },
            ],
        });
        let scan = store.query(&query)?;
        assert!(matches!(scan.plan.access_path, AccessPath::CollectionScan));

        let index = IndexDefinition {
            name: "live_key_version".into(),
            collection: "users".into(),
            fields: vec![MetadataField::Deleted, MetadataField::KeyVersion],
        };
        store.create_index(&index)?;
        let indexed = store.query(&query)?;
        assert!(matches!(
            indexed.plan.access_path,
            AccessPath::SecondaryIndex { ref name, .. } if name == "live_key_version"
        ));
        assert_eq!(
            scan.rows.iter().map(|row| &row.id).collect::<Vec<_>>(),
            indexed.rows.iter().map(|row| &row.id).collect::<Vec<_>>()
        );

        drop(store);
        let store = Store::open(directory.path().join("test.vdb"))?;
        assert_eq!(store.list_indexes("users")?, vec![index.clone()]);
        assert!(matches!(
            store.explain(&query)?.access_path,
            AccessPath::SecondaryIndex { .. }
        ));

        let updated = test_document(&store, &key, "users", "alice", 5, b"updated")
            .map_err(|error| StoreError::Storage(error.to_string()))?;
        store.put(&updated)?;
        store.delete("users", "carol", 6, VersionPrecondition::IfVersion(3))?;
        let report = store.verify()?;
        assert!(report.valid, "{report:?}");
        store.rebuild_index("users", "live_key_version")?;
        let report = store.verify()?;
        assert!(report.valid, "{report:?}");
        assert_eq!(store.list_indexes("users")?, vec![index]);
        store.drop_index("users", "live_key_version")?;
        assert!(store.list_indexes("users")?.is_empty());
        assert!(matches!(
            store.explain(&query)?.access_path,
            AccessPath::CollectionScan
        ));
        Ok(())
    }

    #[test]
    fn document_id_plan_and_zero_trust_modes_are_explicit() -> Result<()> {
        let (_directory, store, key) = database()?;
        let document = test_document(&store, &key, "users", "alice", 1, b"secret")
            .map_err(|error| StoreError::Storage(error.to_string()))?;
        store.put(&document)?;

        let mut point = Query::collection("users");
        point.predicate = Some(Predicate::Eq {
            field: MetadataField::DocumentId,
            value: QueryValue::String("alice".into()),
        });
        assert!(matches!(
            store.explain(&point)?.access_path,
            AccessPath::DocumentId { .. }
        ));

        let mut protected = Query::collection("users");
        protected.predicate = Some(Predicate::ClientProtected {
            marker: "client-filter-1".into(),
        });
        let result = store.query(&protected)?;
        assert_eq!(result.plan.mode, ExecutionMode::ClientSideFiltering);
        assert!(result.plan.requires_client_filter);
        assert_eq!(result.rows.len(), 1);
        assert!(
            result.rows[0]
                .record
                .as_ref()
                .and_then(|record| record.payload.as_ref())
                .is_some()
        );

        let mut blind = Query::collection("users");
        blind.predicate = Some(Predicate::BlindToken {
            index: "email".into(),
            token: "opaque".into(),
        });
        assert!(matches!(
            store.query(&blind),
            Err(StoreError::InvalidInput(_))
        ));
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
