use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use redb::{
    Database, ReadTransaction, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition,
};

use crate::{
    codec::{Decoder, Encoder},
    crypto::validate_envelope,
    error::{Result, StoreError, corruption, storage},
    identity::{SIGNATURE_ALGORITHM, WriterIdentity, verify_signature},
    merkle::{build_proof, build_root, state_leaf},
    model::{
        DATABASE_FORMAT_VERSION, DatabaseMetadata, DocumentMetadata, DocumentRecord,
        EncryptedDocument, InclusionProof, MutationKind, MutationRecord, StateCheckpoint,
        VerifyReport, VersionPrecondition, WriteOperation,
    },
    query::{
        IndexDefinition, MAX_QUERY_SCAN_BYTES, MAX_QUERY_SCAN_ROWS, MetadataField, QueryValue,
        field_value,
    },
    replication::{ReplicationEvent, decode_event, encode_event, verify_event},
    storage::{BackupImage, BackupTable, StorageEngine, StorageSnapshot, StorageStatistics},
};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("vdb1.metadata");
const DOCUMENT_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vdb1.document_metadata");
const PAYLOADS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vdb1.payloads");
const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("vdb1.mutation_log");
const WRITERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vdb1.writer_keys");
const MUTATION_IDS: TableDefinition<&[u8], u64> = TableDefinition::new("vdb1.mutation_ids");
const INDEX_DEFINITIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("vdb1.index_definitions");
const INDEX_ENTRIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vdb1.index_entries");
const REPLICATION_EVENTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("vdb1.replication_events");
const REPLICATION_DOTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("vdb1.replication_dots");
const HEADER_KEY: &str = "database_header";
const SEQUENCE_KEY: &str = "mutation_sequence";
const HEAD_KEY: &str = "mutation_head";
const GENESIS: &str = "GENESIS";
const MAX_NAME: usize = 1024;
const MAX_PAYLOAD: usize = 4 * 1024 * 1024;

pub(crate) struct RedbEngine {
    db: Arc<Database>,
}

impl RedbEngine {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path).map_err(map_database_error)?;
        let tx = db.begin_write().map_err(storage)?;
        let existing_tables = tx.list_tables().map_err(storage)?.count();
        {
            let mut meta = tx.open_table(META).map_err(storage)?;
            let header = meta
                .get(HEADER_KEY)
                .map_err(storage)?
                .map(|value| value.value().to_vec());
            match header {
                Some(header) => validate_database_metadata(&header)?,
                None if existing_tables == 0 => {
                    let metadata = new_database_metadata()?;
                    let encoded = encode_database_metadata(&metadata);
                    meta.insert(HEADER_KEY, encoded.as_slice())
                        .map_err(storage)?;
                }
                None => {
                    return Err(StoreError::UnsupportedFormat {
                        found: 0,
                        supported: DATABASE_FORMAT_VERSION,
                    });
                }
            }
            tx.open_table(DOCUMENT_META).map_err(storage)?;
            tx.open_table(PAYLOADS).map_err(storage)?;
            tx.open_table(LOG).map_err(storage)?;
            tx.open_table(WRITERS).map_err(storage)?;
            tx.open_table(MUTATION_IDS).map_err(storage)?;
            tx.open_table(INDEX_DEFINITIONS).map_err(storage)?;
            tx.open_table(INDEX_ENTRIES).map_err(storage)?;
            tx.open_table(REPLICATION_EVENTS).map_err(storage)?;
            tx.open_table(REPLICATION_DOTS).map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        Ok(Self { db: Arc::new(db) })
    }

    pub(crate) fn restore_image(path: impl AsRef<Path>, image: &BackupImage) -> Result<()> {
        let db = Database::create(path).map_err(map_database_error)?;
        let tx = db.begin_write().map_err(storage)?;
        for table in &image.tables {
            match table.id {
                1 => {
                    let mut target = tx.open_table(META).map_err(storage)?;
                    for (key, value) in &table.rows {
                        let key = std::str::from_utf8(key).map_err(corruption)?;
                        target.insert(key, value.as_slice()).map_err(storage)?;
                    }
                }
                2 => restore_bytes_table(&tx, DOCUMENT_META, &table.rows)?,
                3 => restore_bytes_table(&tx, PAYLOADS, &table.rows)?,
                4 => {
                    let mut target = tx.open_table(LOG).map_err(storage)?;
                    for (key, value) in &table.rows {
                        let key =
                            u64::from_be_bytes(key.as_slice().try_into().map_err(corruption)?);
                        target.insert(key, value.as_slice()).map_err(storage)?;
                    }
                }
                5 => restore_bytes_table(&tx, WRITERS, &table.rows)?,
                6 => {
                    let mut target = tx.open_table(MUTATION_IDS).map_err(storage)?;
                    for (key, value) in &table.rows {
                        let value =
                            u64::from_be_bytes(value.as_slice().try_into().map_err(corruption)?);
                        target.insert(key.as_slice(), value).map_err(storage)?;
                    }
                }
                7 => restore_bytes_table(&tx, INDEX_DEFINITIONS, &table.rows)?,
                8 => restore_bytes_table(&tx, INDEX_ENTRIES, &table.rows)?,
                9 => restore_bytes_table(&tx, REPLICATION_EVENTS, &table.rows)?,
                10 => restore_bytes_table(&tx, REPLICATION_DOTS, &table.rows)?,
                _ => return Err(corruption("unknown backup table identifier")),
            }
        }
        tx.commit().map_err(storage)
    }
}

impl StorageEngine for RedbEngine {
    fn metadata(&self) -> Result<DatabaseMetadata> {
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(META).map_err(storage)?;
        let value = table
            .get(HEADER_KEY)
            .map_err(storage)?
            .ok_or_else(|| corruption("missing database header"))?;
        decode_database_metadata(value.value())
    }

    fn snapshot(&self) -> Result<Box<dyn StorageSnapshot>> {
        Ok(Box::new(RedbSnapshot {
            tx: self.db.begin_read().map_err(storage)?,
        }))
    }

    fn write(
        &self,
        operations: &[WriteOperation],
        identity: &WriterIdentity,
    ) -> Result<Vec<MutationRecord>> {
        if operations.is_empty() {
            return Err(StoreError::InvalidInput(
                "transaction must contain at least one operation".into(),
            ));
        }
        let mut targets = HashSet::new();
        for operation in operations {
            let (collection, id) = operation_identity(operation);
            validate_identity(collection, id)?;
            if !targets.insert((collection, id)) {
                return Err(StoreError::InvalidInput(
                    "transaction contains duplicate document target".into(),
                ));
            }
        }

        let tx = self.db.begin_write().map_err(storage)?;
        let mut records = Vec::with_capacity(operations.len());
        let index_definitions = {
            let table = tx.open_table(INDEX_DEFINITIONS).map_err(storage)?;
            let mut definitions = Vec::new();
            for item in table.iter().map_err(storage)? {
                let (_, value) = item.map_err(storage)?;
                definitions.push(decode_index_definition(value.value())?);
            }
            definitions
        };
        {
            let mut metadata_table = tx.open_table(DOCUMENT_META).map_err(storage)?;
            let mut payload_table = tx.open_table(PAYLOADS).map_err(storage)?;
            let mut log = tx.open_table(LOG).map_err(storage)?;
            let mut meta = tx.open_table(META).map_err(storage)?;
            let mut writers = tx.open_table(WRITERS).map_err(storage)?;
            let mut mutation_ids = tx.open_table(MUTATION_IDS).map_err(storage)?;
            let mut index_entries = tx.open_table(INDEX_ENTRIES).map_err(storage)?;
            let mut sequence = read_sequence(&meta)?;
            let mut head = read_head(&meta)?;
            let database_id = {
                let header = meta
                    .get(HEADER_KEY)
                    .map_err(storage)?
                    .ok_or_else(|| corruption("missing database header"))?;
                decode_database_metadata(header.value())?.database_id
            };
            let writer_key = writer_key(identity.writer_id().as_str(), identity.key_version());
            let public_key = identity.public_key();
            if let Some(existing) = writers.get(writer_key.as_slice()).map_err(storage)? {
                if existing.value() != public_key.as_bytes() {
                    return Err(corruption(
                        "writer key version maps to a different public key",
                    ));
                }
            } else {
                writers
                    .insert(writer_key.as_slice(), public_key.as_bytes())
                    .map_err(storage)?;
            }

            for operation in operations {
                let (collection, id) = operation_identity(operation);
                let key = document_key(collection, id);
                let existing = metadata_table
                    .get(key.as_slice())
                    .map_err(storage)?
                    .map(|value| decode_document_metadata(value.value()))
                    .transpose()?;
                let existing_record = existing
                    .as_ref()
                    .map(|metadata| {
                        let payload = if metadata.deleted {
                            None
                        } else {
                            let value = payload_table
                                .get(key.as_slice())
                                .map_err(storage)?
                                .ok_or_else(|| corruption("live document payload missing"))?;
                            Some(decode_document(value.value())?)
                        };
                        Ok(DocumentRecord {
                            metadata: metadata.clone(),
                            payload,
                        })
                    })
                    .transpose()?;
                check_precondition(
                    collection,
                    id,
                    existing.as_ref(),
                    operation_precondition(operation),
                )?;
                sequence = sequence
                    .checked_add(1)
                    .ok_or_else(|| corruption("mutation sequence overflow"))?;

                let (metadata, payload, payload_document, kind) = match operation {
                    WriteOperation::Put { document, .. } => {
                        validate_document(document, &database_id)?;
                        ensure_newer(collection, id, existing.as_ref(), document.version)?;
                        let bytes = encode_document(document);
                        let payload_hash = blake3::hash(&bytes).to_hex().to_string();
                        let created = existing
                            .as_ref()
                            .map_or(sequence, |value| value.created_sequence);
                        (
                            DocumentMetadata {
                                collection: collection.into(),
                                id: id.into(),
                                version: document.version,
                                created_sequence: created,
                                modified_sequence: sequence,
                                deleted: false,
                                payload_hash: Some(payload_hash),
                            },
                            Some(bytes),
                            Some(document.clone()),
                            MutationKind::Put,
                        )
                    }
                    WriteOperation::Delete { version, .. } => {
                        ensure_newer(collection, id, existing.as_ref(), *version)?;
                        let created = existing
                            .as_ref()
                            .map_or(sequence, |value| value.created_sequence);
                        (
                            DocumentMetadata {
                                collection: collection.into(),
                                id: id.into(),
                                version: *version,
                                created_sequence: created,
                                modified_sequence: sequence,
                                deleted: true,
                                payload_hash: None,
                            },
                            None,
                            None,
                            MutationKind::Delete,
                        )
                    }
                };
                let metadata_bytes = encode_document_metadata(&metadata);
                let metadata_hash = blake3::hash(&metadata_bytes).to_hex().to_string();
                let mut record = MutationRecord {
                    sequence,
                    kind,
                    collection: collection.into(),
                    id: id.into(),
                    version: metadata.version,
                    metadata_hash,
                    payload_hash: metadata.payload_hash.clone(),
                    previous_mutation_hash: head,
                    database_id: database_id.clone(),
                    writer_id: identity.writer_id(),
                    writer_key_version: identity.key_version(),
                    writer_public_key: public_key.clone(),
                    signature_algorithm: SIGNATURE_ALGORITHM.into(),
                    mutation_id: String::new(),
                    signature: String::new(),
                    mutation_hash: String::new(),
                };
                let signing_material = mutation_signing_material(&record);
                record.mutation_id = blake3::hash(&signing_material).to_hex().to_string();
                record.signature = identity.sign(&signing_material);
                record.mutation_hash = mutation_hash(&record);
                let record_bytes = encode_mutation(&record);
                if mutation_ids
                    .get(record.mutation_id.as_bytes())
                    .map_err(storage)?
                    .is_some()
                {
                    return Err(StoreError::Conflict {
                        collection: collection.into(),
                        id: id.into(),
                        expected: "unique mutation id".into(),
                        actual: record.mutation_id.clone(),
                    });
                }

                for definition in index_definitions
                    .iter()
                    .filter(|definition| definition.collection == collection)
                {
                    if let Some(record) = &existing_record
                        && let Some(entry) = index_entry_key(definition, record)
                    {
                        index_entries.remove(entry.as_slice()).map_err(storage)?;
                    }
                    let new_record = DocumentRecord {
                        metadata: metadata.clone(),
                        payload: payload_document.clone(),
                    };
                    if let Some(entry) = index_entry_key(definition, &new_record) {
                        index_entries
                            .insert(entry.as_slice(), key.as_slice())
                            .map_err(storage)?;
                    }
                }

                metadata_table
                    .insert(key.as_slice(), metadata_bytes.as_slice())
                    .map_err(storage)?;
                if let Some(payload) = payload {
                    payload_table
                        .insert(key.as_slice(), payload.as_slice())
                        .map_err(storage)?;
                } else {
                    payload_table.remove(key.as_slice()).map_err(storage)?;
                }
                log.insert(sequence, record_bytes.as_slice())
                    .map_err(storage)?;
                mutation_ids
                    .insert(record.mutation_id.as_bytes(), sequence)
                    .map_err(storage)?;
                head = record.mutation_hash.clone();
                records.push(record);
            }
            meta.insert(SEQUENCE_KEY, sequence.to_be_bytes().as_slice())
                .map_err(storage)?;
            meta.insert(HEAD_KEY, head.as_bytes()).map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        Ok(records)
    }

    fn mutation(&self, sequence: u64) -> Result<Option<MutationRecord>> {
        let tx = self.db.begin_read().map_err(storage)?;
        let log = tx.open_table(LOG).map_err(storage)?;
        log.get(sequence)
            .map_err(storage)?
            .map(|value| decode_mutation(value.value()))
            .transpose()
    }

    fn checkpoint(&self) -> Result<StateCheckpoint> {
        let tx = self.db.begin_read().map_err(storage)?;
        checkpoint_for(&tx)
    }

    fn inclusion_proof(&self, collection: &str, id: &str) -> Result<Option<InclusionProof>> {
        validate_identity(collection, id)?;
        let tx = self.db.begin_read().map_err(storage)?;
        let checkpoint = checkpoint_for(&tx)?;
        let entries = state_entries(&tx)?;
        let target = document_key(collection, id);
        let Some(index) = entries.iter().position(|(key, _, _)| *key == target) else {
            return Ok(None);
        };
        let leaves: Vec<_> = entries.iter().map(|(_, _, leaf)| *leaf).collect();
        Ok(Some(InclusionProof {
            checkpoint,
            metadata: entries[index].1.clone(),
            leaf_hash: hex::encode(entries[index].2),
            leaf_index: index as u64,
            siblings: build_proof(&leaves, index)
                .into_iter()
                .map(hex::encode)
                .collect(),
        }))
    }

    fn list_indexes(&self, collection: &str) -> Result<Vec<IndexDefinition>> {
        validate_identity(collection, "index-placeholder")?;
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(INDEX_DEFINITIONS).map_err(storage)?;
        let mut definitions = Vec::new();
        for item in table.iter().map_err(storage)? {
            let (_, value) = item.map_err(storage)?;
            let definition = decode_index_definition(value.value())?;
            if definition.collection == collection {
                definitions.push(definition);
            }
        }
        definitions.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(definitions)
    }

    fn create_index(&self, index: &IndexDefinition) -> Result<()> {
        validate_index_definition(index)?;
        let tx = self.db.begin_write().map_err(storage)?;
        {
            let key = index_definition_key(&index.collection, &index.name);
            let mut definitions = tx.open_table(INDEX_DEFINITIONS).map_err(storage)?;
            if definitions.get(key.as_slice()).map_err(storage)?.is_some() {
                return Err(StoreError::Conflict {
                    collection: index.collection.clone(),
                    id: index.name.clone(),
                    expected: "index name to be absent".into(),
                    actual: "index already exists".into(),
                });
            }
            let encoded = encode_index_definition(index);
            definitions
                .insert(key.as_slice(), encoded.as_slice())
                .map_err(storage)?;

            let metadata = tx.open_table(DOCUMENT_META).map_err(storage)?;
            let payloads = tx.open_table(PAYLOADS).map_err(storage)?;
            let mut entries = tx.open_table(INDEX_ENTRIES).map_err(storage)?;
            for item in metadata.iter().map_err(storage)? {
                let (document_key, value) = item.map_err(storage)?;
                let record = record_from_tables(&payloads, document_key.value(), value.value())?;
                if record.metadata.collection == index.collection
                    && let Some(entry) = index_entry_key(index, &record)
                {
                    entries
                        .insert(entry.as_slice(), document_key.value())
                        .map_err(storage)?;
                }
            }
        }
        tx.commit().map_err(storage)
    }

    fn drop_index(&self, collection: &str, name: &str) -> Result<()> {
        validate_index_name(collection, name)?;
        let tx = self.db.begin_write().map_err(storage)?;
        {
            let key = index_definition_key(collection, name);
            let mut definitions = tx.open_table(INDEX_DEFINITIONS).map_err(storage)?;
            if definitions
                .remove(key.as_slice())
                .map_err(storage)?
                .is_none()
            {
                return Err(StoreError::InvalidInput("index does not exist".into()));
            }
            let prefix = index_namespace_prefix(collection, name);
            let mut entries = tx.open_table(INDEX_ENTRIES).map_err(storage)?;
            let keys = keys_with_prefix(&entries, &prefix)?;
            for key in keys {
                entries.remove(key.as_slice()).map_err(storage)?;
            }
        }
        tx.commit().map_err(storage)
    }

    fn rebuild_index(&self, collection: &str, name: &str) -> Result<()> {
        validate_index_name(collection, name)?;
        let tx = self.db.begin_write().map_err(storage)?;
        {
            let definition_key = index_definition_key(collection, name);
            let definitions = tx.open_table(INDEX_DEFINITIONS).map_err(storage)?;
            let definition = definitions
                .get(definition_key.as_slice())
                .map_err(storage)?
                .ok_or_else(|| StoreError::InvalidInput("index does not exist".into()))
                .and_then(|value| decode_index_definition(value.value()))?;
            let metadata = tx.open_table(DOCUMENT_META).map_err(storage)?;
            let payloads = tx.open_table(PAYLOADS).map_err(storage)?;
            let mut entries = tx.open_table(INDEX_ENTRIES).map_err(storage)?;
            let prefix = index_namespace_prefix(collection, name);
            for key in keys_with_prefix(&entries, &prefix)? {
                entries.remove(key.as_slice()).map_err(storage)?;
            }
            for item in metadata.iter().map_err(storage)? {
                let (document_key, value) = item.map_err(storage)?;
                let record = record_from_tables(&payloads, document_key.value(), value.value())?;
                if record.metadata.collection == collection
                    && let Some(entry) = index_entry_key(&definition, &record)
                {
                    entries
                        .insert(entry.as_slice(), document_key.value())
                        .map_err(storage)?;
                }
            }
        }
        tx.commit().map_err(storage)
    }

    fn verify(&self) -> Result<VerifyReport> {
        let tx = self.db.begin_read().map_err(storage)?;
        let log = tx.open_table(LOG).map_err(storage)?;
        let writers = tx.open_table(WRITERS).map_err(storage)?;
        let mutation_index = tx.open_table(MUTATION_IDS).map_err(storage)?;
        let meta = tx.open_table(META).map_err(storage)?;
        let database_id = meta
            .get(HEADER_KEY)
            .map_err(storage)?
            .ok_or_else(|| corruption("missing database header"))
            .and_then(|v| decode_database_metadata(v.value()))?
            .database_id;
        let mut previous = GENESIS.to_owned();
        let mut count = 0_u64;
        let mut latest = HashMap::<Vec<u8>, (String, Option<String>)>::new();
        let mut mutation_ids = HashSet::new();
        for (expected, item) in (1_u64..).zip(log.iter().map_err(storage)?) {
            let (key, value) = item.map_err(storage)?;
            let record = decode_mutation(value.value())?;
            count += 1;
            if key.value() != expected || record.sequence != expected {
                return Ok(invalid_report(
                    count,
                    &previous,
                    "non-contiguous mutation sequence",
                ));
            }
            if record.database_id != database_id
                || record.previous_mutation_hash != previous
                || verify_mutation_record(&record).is_err()
            {
                return Ok(invalid_report(
                    count,
                    &previous,
                    "invalid mutation hash chain",
                ));
            }
            if !mutation_ids.insert(record.mutation_id.clone()) {
                return Ok(invalid_report(count, &previous, "duplicate mutation id"));
            }
            if mutation_index
                .get(record.mutation_id.as_bytes())
                .map_err(storage)?
                .map(|v| v.value())
                != Some(record.sequence)
            {
                return Ok(invalid_report(
                    count,
                    &previous,
                    "mutation id index mismatch",
                ));
            }
            let key = writer_key(&record.writer_id, record.writer_key_version);
            let trusted = writers.get(key.as_slice()).map_err(storage)?;
            if trusted.as_ref().map(|v| v.value()) != Some(record.writer_public_key.as_bytes()) {
                return Ok(invalid_report(
                    count,
                    &previous,
                    "writer identity registry mismatch",
                ));
            }
            latest.insert(
                document_key(&record.collection, &record.id),
                (record.metadata_hash.clone(), record.payload_hash.clone()),
            );
            previous = record.mutation_hash;
        }
        if read_sequence_read(&meta)? != count || read_head_read(&meta)? != previous {
            return Ok(invalid_report(
                count,
                &previous,
                "mutation metadata mismatch",
            ));
        }
        if mutation_index.len().map_err(storage)? != count {
            return Ok(invalid_report(
                count,
                &previous,
                "mutation id index cardinality mismatch",
            ));
        }

        let docs = tx.open_table(DOCUMENT_META).map_err(storage)?;
        let payloads = tx.open_table(PAYLOADS).map_err(storage)?;
        let mut seen = 0_usize;
        for item in docs.iter().map_err(storage)? {
            let (key, value) = item.map_err(storage)?;
            let metadata = decode_document_metadata(value.value())?;
            let expected = latest
                .get(key.value())
                .ok_or_else(|| corruption("document has no mutation"))?;
            if blake3::hash(value.value()).to_hex().as_str() != expected.0 {
                return Ok(invalid_report(
                    count,
                    &previous,
                    "current metadata hash mismatch",
                ));
            }
            let payload = payloads.get(key.value()).map_err(storage)?;
            match (metadata.deleted, payload, expected.1.as_deref()) {
                (true, None, None) => {}
                (false, Some(bytes), Some(hash))
                    if blake3::hash(bytes.value()).to_hex().as_str() == hash =>
                {
                    decode_document(bytes.value())?;
                }
                _ => return Ok(invalid_report(count, &previous, "current payload mismatch")),
            }
            seen += 1;
        }
        if seen != latest.len() {
            return Ok(invalid_report(
                count,
                &previous,
                "mutation references missing current document",
            ));
        }
        let definitions_table = tx.open_table(INDEX_DEFINITIONS).map_err(storage)?;
        let mut definitions = Vec::new();
        for item in definitions_table.iter().map_err(storage)? {
            let (_, value) = item.map_err(storage)?;
            definitions.push(decode_index_definition(value.value())?);
        }
        let mut expected_entries = HashMap::<Vec<u8>, Vec<u8>>::new();
        for item in docs.iter().map_err(storage)? {
            let (key, value) = item.map_err(storage)?;
            let record = record_from_tables(&payloads, key.value(), value.value())?;
            for definition in definitions
                .iter()
                .filter(|definition| definition.collection == record.metadata.collection)
            {
                if let Some(entry) = index_entry_key(definition, &record) {
                    expected_entries.insert(entry, key.value().to_vec());
                }
            }
        }
        let entries = tx.open_table(INDEX_ENTRIES).map_err(storage)?;
        let mut actual_entries = HashMap::new();
        for item in entries.iter().map_err(storage)? {
            let (key, value) = item.map_err(storage)?;
            actual_entries.insert(key.value().to_vec(), value.value().to_vec());
        }
        if actual_entries != expected_entries {
            return Ok(invalid_report(
                count,
                &previous,
                "secondary index state mismatch",
            ));
        }
        let replication_events = tx.open_table(REPLICATION_EVENTS).map_err(storage)?;
        let replication_dots = tx.open_table(REPLICATION_DOTS).map_err(storage)?;
        let mut replication_count = 0_u64;
        for item in replication_events.iter().map_err(storage)? {
            let (key, value) = item.map_err(storage)?;
            let event = decode_event(value.value())?;
            if key.value() != event.event_id.as_bytes()
                || verify_event(&event, &database_id).is_err()
            {
                return Ok(invalid_report(
                    count,
                    &previous,
                    "invalid replication event",
                ));
            }
            let dot = replication_dot_key(&event.replica_id, event.counter);
            if replication_dots
                .get(dot.as_slice())
                .map_err(storage)?
                .map(|value| value.value().to_vec())
                != Some(event.event_id.as_bytes().to_vec())
            {
                return Ok(invalid_report(
                    count,
                    &previous,
                    "replication dot index mismatch",
                ));
            }
            replication_count += 1;
        }
        if replication_dots.len().map_err(storage)? != replication_count {
            return Ok(invalid_report(
                count,
                &previous,
                "replication dot index cardinality mismatch",
            ));
        }
        Ok(VerifyReport {
            valid: true,
            mutations: count,
            head: previous,
            error: None,
        })
    }

    fn replication_events(&self) -> Result<Vec<ReplicationEvent>> {
        let tx = self.db.begin_read().map_err(storage)?;
        let table = tx.open_table(REPLICATION_EVENTS).map_err(storage)?;
        let mut events = Vec::new();
        for item in table.iter().map_err(storage)? {
            let (key, value) = item.map_err(storage)?;
            let event = decode_event(value.value())?;
            if key.value() != event.event_id.as_bytes() {
                return Err(corruption("replication event key mismatch"));
            }
            events.push(event);
        }
        Ok(events)
    }

    fn store_replication_events(&self, events: &[ReplicationEvent]) -> Result<usize> {
        let tx = self.db.begin_write().map_err(storage)?;
        let mut accepted = 0;
        {
            let mut stored = tx.open_table(REPLICATION_EVENTS).map_err(storage)?;
            let mut dots = tx.open_table(REPLICATION_DOTS).map_err(storage)?;
            for event in events {
                let dot = replication_dot_key(&event.replica_id, event.counter);
                if let Some(existing) = dots.get(dot.as_slice()).map_err(storage)? {
                    if existing.value() != event.event_id.as_bytes() {
                        return Err(StoreError::Conflict {
                            collection: event.collection.clone(),
                            id: event.id.clone(),
                            expected: "one event per replica counter".into(),
                            actual: "replica equivocation".into(),
                        });
                    }
                    continue;
                }
                if stored
                    .get(event.event_id.as_bytes())
                    .map_err(storage)?
                    .is_some()
                {
                    return Err(corruption("replication event exists without its dot index"));
                }
                let encoded = encode_event(event);
                stored
                    .insert(event.event_id.as_bytes(), encoded.as_slice())
                    .map_err(storage)?;
                dots.insert(dot.as_slice(), event.event_id.as_bytes())
                    .map_err(storage)?;
                accepted += 1;
            }
        }
        tx.commit().map_err(storage)?;
        Ok(accepted)
    }

    fn backup_image(&self) -> Result<BackupImage> {
        let tx = self.db.begin_read().map_err(storage)?;
        let mut tables = Vec::with_capacity(10);
        let meta = tx.open_table(META).map_err(storage)?;
        let mut rows = Vec::new();
        for item in meta.iter().map_err(storage)? {
            let (key, value) = item.map_err(storage)?;
            rows.push((key.value().as_bytes().to_vec(), value.value().to_vec()));
        }
        tables.push(BackupTable { id: 1, rows });
        tables.push(BackupTable {
            id: 2,
            rows: collect_bytes_table(&tx.open_table(DOCUMENT_META).map_err(storage)?)?,
        });
        tables.push(BackupTable {
            id: 3,
            rows: collect_bytes_table(&tx.open_table(PAYLOADS).map_err(storage)?)?,
        });
        let log = tx.open_table(LOG).map_err(storage)?;
        let mut rows = Vec::new();
        for item in log.iter().map_err(storage)? {
            let (key, value) = item.map_err(storage)?;
            rows.push((key.value().to_be_bytes().to_vec(), value.value().to_vec()));
        }
        tables.push(BackupTable { id: 4, rows });
        tables.push(BackupTable {
            id: 5,
            rows: collect_bytes_table(&tx.open_table(WRITERS).map_err(storage)?)?,
        });
        let mutation_ids = tx.open_table(MUTATION_IDS).map_err(storage)?;
        let mut rows = Vec::new();
        for item in mutation_ids.iter().map_err(storage)? {
            let (key, value) = item.map_err(storage)?;
            rows.push((key.value().to_vec(), value.value().to_be_bytes().to_vec()));
        }
        tables.push(BackupTable { id: 6, rows });
        tables.push(BackupTable {
            id: 7,
            rows: collect_bytes_table(&tx.open_table(INDEX_DEFINITIONS).map_err(storage)?)?,
        });
        tables.push(BackupTable {
            id: 8,
            rows: collect_bytes_table(&tx.open_table(INDEX_ENTRIES).map_err(storage)?)?,
        });
        tables.push(BackupTable {
            id: 9,
            rows: collect_bytes_table(&tx.open_table(REPLICATION_EVENTS).map_err(storage)?)?,
        });
        tables.push(BackupTable {
            id: 10,
            rows: collect_bytes_table(&tx.open_table(REPLICATION_DOTS).map_err(storage)?)?,
        });
        Ok(BackupImage { tables })
    }

    fn statistics(&self) -> Result<StorageStatistics> {
        let tx = self.db.begin_write().map_err(storage)?;
        let stats = tx.stats().map_err(storage)?;
        let documents = tx.open_table(DOCUMENT_META).map_err(storage)?;
        let mut live_documents = 0_u64;
        let mut tombstones = 0_u64;
        for item in documents.iter().map_err(storage)? {
            let (_, value) = item.map_err(storage)?;
            if decode_document_metadata(value.value())?.deleted {
                tombstones += 1;
            } else {
                live_documents += 1;
            }
        }
        let result = StorageStatistics {
            allocated_pages: stats.allocated_pages(),
            leaf_pages: stats.leaf_pages(),
            branch_pages: stats.branch_pages(),
            stored_bytes: stats.stored_bytes(),
            metadata_bytes: stats.metadata_bytes(),
            fragmented_bytes: stats.fragmented_bytes(),
            page_size: stats.page_size(),
            documents: documents.len().map_err(storage)?,
            live_documents,
            tombstones,
            mutations: tx
                .open_table(LOG)
                .map_err(storage)?
                .len()
                .map_err(storage)?,
            writers: tx
                .open_table(WRITERS)
                .map_err(storage)?
                .len()
                .map_err(storage)?,
            indexes: tx
                .open_table(INDEX_DEFINITIONS)
                .map_err(storage)?
                .len()
                .map_err(storage)?,
            index_entries: tx
                .open_table(INDEX_ENTRIES)
                .map_err(storage)?
                .len()
                .map_err(storage)?,
            replication_events: tx
                .open_table(REPLICATION_EVENTS)
                .map_err(storage)?
                .len()
                .map_err(storage)?,
        };
        drop(documents);
        tx.abort().map_err(storage)?;
        Ok(result)
    }
}

fn collect_bytes_table<T>(table: &T) -> Result<Vec<(Vec<u8>, Vec<u8>)>>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let mut rows = Vec::new();
    for item in table.iter().map_err(storage)? {
        let (key, value) = item.map_err(storage)?;
        rows.push((key.value().to_vec(), value.value().to_vec()));
    }
    Ok(rows)
}

fn restore_bytes_table(
    tx: &redb::WriteTransaction,
    definition: TableDefinition<&[u8], &[u8]>,
    rows: &[(Vec<u8>, Vec<u8>)],
) -> Result<()> {
    let mut table = tx.open_table(definition).map_err(storage)?;
    for (key, value) in rows {
        table
            .insert(key.as_slice(), value.as_slice())
            .map_err(storage)?;
    }
    Ok(())
}

fn replication_dot_key(replica_id: &str, counter: u64) -> Vec<u8> {
    let mut encoder = Encoder::new(b"vdb.replication.dot.v1\0");
    encoder.string(replica_id);
    encoder.u64(counter);
    encoder.finish()
}

struct RedbSnapshot {
    tx: ReadTransaction,
}
impl StorageSnapshot for RedbSnapshot {
    fn get(&self, collection: &str, id: &str) -> Result<Option<DocumentRecord>> {
        validate_identity(collection, id)?;
        let key = document_key(collection, id);
        let metadata_table = self.tx.open_table(DOCUMENT_META).map_err(storage)?;
        let Some(value) = metadata_table.get(key.as_slice()).map_err(storage)? else {
            return Ok(None);
        };
        let metadata = decode_document_metadata(value.value())?;
        let payload = if metadata.deleted {
            None
        } else {
            let table = self.tx.open_table(PAYLOADS).map_err(storage)?;
            let bytes = table
                .get(key.as_slice())
                .map_err(storage)?
                .ok_or_else(|| corruption("live document payload missing"))?;
            let expected = metadata
                .payload_hash
                .as_deref()
                .ok_or_else(|| corruption("live document payload hash missing"))?;
            if blake3::hash(bytes.value()).to_hex().as_str() != expected {
                return Err(corruption("document payload checksum mismatch"));
            }
            Some(decode_document(bytes.value())?)
        };
        Ok(Some(DocumentRecord { metadata, payload }))
    }

    fn scan_collection(&self, collection: &str) -> Result<Vec<DocumentRecord>> {
        validate_identity(collection, "scan-placeholder")?;
        let metadata = self.tx.open_table(DOCUMENT_META).map_err(storage)?;
        let payloads = self.tx.open_table(PAYLOADS).map_err(storage)?;
        let mut records = Vec::new();
        let mut scanned = 0_usize;
        let mut selected_bytes = 0_usize;
        for item in metadata.iter().map_err(storage)? {
            scanned = scanned
                .checked_add(1)
                .ok_or_else(|| StoreError::InvalidInput("query scan budget exceeded".into()))?;
            if scanned > MAX_QUERY_SCAN_ROWS {
                return Err(StoreError::InvalidInput(
                    "query scan row budget exceeded".into(),
                ));
            }
            let (key, value) = item.map_err(storage)?;
            let record = record_from_tables(&payloads, key.value(), value.value())?;
            if record.metadata.collection == collection {
                selected_bytes = selected_bytes
                    .checked_add(value.value().len())
                    .and_then(|bytes| {
                        record.payload.as_ref().map_or(Some(bytes), |payload| {
                            bytes.checked_add(payload.ciphertext_b64.len())
                        })
                    })
                    .ok_or_else(|| {
                        StoreError::InvalidInput("query scan byte budget exceeded".into())
                    })?;
                if selected_bytes > MAX_QUERY_SCAN_BYTES {
                    return Err(StoreError::InvalidInput(
                        "query scan byte budget exceeded".into(),
                    ));
                }
                records.push(record);
            }
        }
        Ok(records)
    }

    fn lookup_index(
        &self,
        index: &IndexDefinition,
        equality_prefix: &[QueryValue],
    ) -> Result<Vec<DocumentRecord>> {
        if equality_prefix.is_empty() || equality_prefix.len() > index.fields.len() {
            return Err(StoreError::InvalidInput(
                "invalid index equality prefix".into(),
            ));
        }
        let prefix = index_value_prefix(index, equality_prefix);
        let end =
            prefix_successor(&prefix).ok_or_else(|| corruption("index prefix has no successor"))?;
        let entries = self.tx.open_table(INDEX_ENTRIES).map_err(storage)?;
        let metadata = self.tx.open_table(DOCUMENT_META).map_err(storage)?;
        let payloads = self.tx.open_table(PAYLOADS).map_err(storage)?;
        let mut records = Vec::new();
        let mut selected_bytes = 0_usize;
        for item in entries
            .range(prefix.as_slice()..end.as_slice())
            .map_err(storage)?
        {
            let (_, value) = item.map_err(storage)?;
            let document_key = value.value();
            let metadata_bytes = metadata
                .get(document_key)
                .map_err(storage)?
                .ok_or_else(|| corruption("index references missing document"))?;
            selected_bytes = selected_bytes
                .checked_add(metadata_bytes.value().len())
                .ok_or_else(|| {
                    StoreError::InvalidInput("query scan byte budget exceeded".into())
                })?;
            if records.len() >= MAX_QUERY_SCAN_ROWS || selected_bytes > MAX_QUERY_SCAN_BYTES {
                return Err(StoreError::InvalidInput(
                    "query scan budget exceeded".into(),
                ));
            }
            let record = record_from_tables(&payloads, document_key, metadata_bytes.value())?;
            if let Some(payload) = &record.payload {
                selected_bytes = selected_bytes
                    .checked_add(payload.ciphertext_b64.len())
                    .ok_or_else(|| {
                        StoreError::InvalidInput("query scan byte budget exceeded".into())
                    })?;
            }
            if selected_bytes > MAX_QUERY_SCAN_BYTES {
                return Err(StoreError::InvalidInput(
                    "query scan byte budget exceeded".into(),
                ));
            }
            records.push(record);
        }
        Ok(records)
    }

    fn list_indexes(&self, collection: &str) -> Result<Vec<IndexDefinition>> {
        validate_identity(collection, "index-placeholder")?;
        let table = self.tx.open_table(INDEX_DEFINITIONS).map_err(storage)?;
        let mut definitions = Vec::new();
        for item in table.iter().map_err(storage)? {
            let (_, value) = item.map_err(storage)?;
            let definition = decode_index_definition(value.value())?;
            if definition.collection == collection {
                definitions.push(definition);
            }
        }
        definitions.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(definitions)
    }
}

fn checkpoint_for(tx: &ReadTransaction) -> Result<StateCheckpoint> {
    let meta = tx.open_table(META).map_err(storage)?;
    let database_id = meta
        .get(HEADER_KEY)
        .map_err(storage)?
        .ok_or_else(|| corruption("missing database header"))
        .and_then(|value| decode_database_metadata(value.value()))?
        .database_id;
    let sequence = read_sequence_read(&meta)?;
    let history_head = read_head_read(&meta)?;
    let entries = state_entries(tx)?;
    let root = build_root(entries.iter().map(|(_, _, leaf)| *leaf).collect());
    Ok(StateCheckpoint {
        format_version: DATABASE_FORMAT_VERSION,
        database_id,
        sequence,
        history_head,
        state_root: hex::encode(root),
        leaf_count: entries.len() as u64,
    })
}

type StateEntry = (Vec<u8>, DocumentMetadata, [u8; 32]);

fn state_entries(tx: &ReadTransaction) -> Result<Vec<StateEntry>> {
    let table = tx.open_table(DOCUMENT_META).map_err(storage)?;
    let mut entries = Vec::new();
    for item in table.iter().map_err(storage)? {
        let (key, value) = item.map_err(storage)?;
        let metadata = decode_document_metadata(value.value())?;
        entries.push((
            key.value().to_vec(),
            metadata.clone(),
            state_leaf(&metadata),
        ));
    }
    Ok(entries)
}

fn map_database_error(error: redb::DatabaseError) -> StoreError {
    match error {
        redb::DatabaseError::Storage(redb::StorageError::Corrupted(message)) => corruption(message),
        other => storage(other),
    }
}

fn new_database_metadata() -> Result<DatabaseMetadata> {
    let mut id = [0_u8; 16];
    getrandom::fill(&mut id).map_err(storage)?;
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(storage)?
        .as_millis();
    Ok(DatabaseMetadata {
        format_version: DATABASE_FORMAT_VERSION,
        database_id: hex::encode(id),
        created_at_unix_ms: u64::try_from(millis).map_err(storage)?,
    })
}

fn validate_database_metadata(bytes: &[u8]) -> Result<()> {
    let metadata = decode_database_metadata(bytes)?;
    if metadata.format_version != DATABASE_FORMAT_VERSION {
        return Err(StoreError::UnsupportedFormat {
            found: metadata.format_version,
            supported: DATABASE_FORMAT_VERSION,
        });
    }
    Ok(())
}

fn encode_database_metadata(value: &DatabaseMetadata) -> Vec<u8> {
    let mut e = Encoder::new(b"vdb.database.v1\0");
    e.u32(value.format_version);
    e.string(&value.database_id);
    e.u64(value.created_at_unix_ms);
    with_checksum(e.finish())
}
fn decode_database_metadata(bytes: &[u8]) -> Result<DatabaseMetadata> {
    let body = checked_body(bytes)?;
    let mut d = Decoder::new(body, b"vdb.database.v1\0")?;
    let value = DatabaseMetadata {
        format_version: d.u32()?,
        database_id: d.string(64)?,
        created_at_unix_ms: d.u64()?,
    };
    d.finish()?;
    if hex::decode(&value.database_id).map_err(corruption)?.len() != 16 {
        return Err(corruption("invalid database id"));
    }
    Ok(value)
}
fn with_checksum(mut bytes: Vec<u8>) -> Vec<u8> {
    let hash = blake3::hash(&bytes);
    bytes.extend_from_slice(hash.as_bytes());
    bytes
}
fn checked_body(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.len() < 32 {
        return Err(corruption("checksummed record is truncated"));
    }
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    if blake3::hash(body).as_bytes() != checksum {
        return Err(corruption("record checksum mismatch"));
    }
    Ok(body)
}

fn document_key(collection: &str, id: &str) -> Vec<u8> {
    let mut e = Encoder::new(b"vdb.key.v1\0");
    e.string(collection);
    e.string(id);
    e.finish()
}

fn index_definition_key(collection: &str, name: &str) -> Vec<u8> {
    let mut encoder = Encoder::new(b"vdb.index.definition.key.v1\0");
    encoder.string(collection);
    encoder.string(name);
    encoder.finish()
}

fn index_namespace_prefix(collection: &str, name: &str) -> Vec<u8> {
    let mut encoder = Encoder::new(b"vdb.index.entry.v1\0");
    encoder.string(collection);
    encoder.string(name);
    encoder.finish()
}

fn index_value_prefix(index: &IndexDefinition, values: &[QueryValue]) -> Vec<u8> {
    let mut encoded = index_namespace_prefix(&index.collection, &index.name);
    for value in values {
        encode_query_value(&mut encoded, value);
    }
    encoded
}

fn index_entry_key(index: &IndexDefinition, record: &DocumentRecord) -> Option<Vec<u8>> {
    let values: Option<Vec<_>> = index
        .fields
        .iter()
        .map(|field| field_value(record, *field))
        .collect();
    let mut encoded = index_value_prefix(index, &values?);
    let key = document_key(&record.metadata.collection, &record.metadata.id);
    encoded.extend_from_slice(&(key.len() as u64).to_be_bytes());
    encoded.extend_from_slice(&key);
    Some(encoded)
}

fn encode_query_value(encoded: &mut Vec<u8>, value: &QueryValue) {
    match value {
        QueryValue::String(value) => {
            encoded.push(1);
            encoded.extend_from_slice(&(value.len() as u64).to_be_bytes());
            encoded.extend_from_slice(value.as_bytes());
        }
        QueryValue::Number(value) => {
            encoded.push(2);
            encoded.extend_from_slice(&value.to_be_bytes());
        }
        QueryValue::Bool(value) => {
            encoded.push(3);
            encoded.push(u8::from(*value));
        }
    }
}

fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut result = prefix.to_vec();
    for index in (0..result.len()).rev() {
        if result[index] != u8::MAX {
            result[index] += 1;
            result.truncate(index + 1);
            return Some(result);
        }
    }
    None
}

fn validate_index_name(collection: &str, name: &str) -> Result<()> {
    validate_identity(collection, name)?;
    if name.len() > 128 {
        return Err(StoreError::InvalidInput("index name is too long".into()));
    }
    Ok(())
}

fn validate_index_definition(index: &IndexDefinition) -> Result<()> {
    validate_index_name(&index.collection, &index.name)?;
    if index.fields.is_empty() || index.fields.len() > 4 {
        return Err(StoreError::InvalidInput(
            "an index must contain between one and four fields".into(),
        ));
    }
    let unique: HashSet<_> = index.fields.iter().collect();
    if unique.len() != index.fields.len() {
        return Err(StoreError::InvalidInput(
            "an index cannot repeat a field".into(),
        ));
    }
    Ok(())
}

fn encode_index_definition(index: &IndexDefinition) -> Vec<u8> {
    let mut encoder = Encoder::new(b"vdb.index.definition.v1\0");
    encoder.string(&index.name);
    encoder.string(&index.collection);
    encoder.u64(index.fields.len() as u64);
    for field in &index.fields {
        encoder.u8(index_field_tag(*field));
    }
    with_checksum(encoder.finish())
}

fn decode_index_definition(bytes: &[u8]) -> Result<IndexDefinition> {
    let mut decoder = Decoder::new(checked_body(bytes)?, b"vdb.index.definition.v1\0")?;
    let name = decoder.string(128)?;
    let collection = decoder.string(MAX_NAME)?;
    let count = usize::try_from(decoder.u64()?).map_err(corruption)?;
    if count == 0 || count > 4 {
        return Err(corruption("invalid index field count"));
    }
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        fields.push(index_field_from_tag(decoder.u8()?)?);
    }
    decoder.finish()?;
    let definition = IndexDefinition {
        name,
        collection,
        fields,
    };
    validate_index_definition(&definition).map_err(|error| corruption(error.to_string()))?;
    Ok(definition)
}

fn index_field_tag(field: MetadataField) -> u8 {
    match field {
        MetadataField::DocumentId => 1,
        MetadataField::Version => 2,
        MetadataField::CreatedSequence => 3,
        MetadataField::ModifiedSequence => 4,
        MetadataField::Deleted => 5,
        MetadataField::KeyId => 6,
        MetadataField::KeyVersion => 7,
    }
}

fn index_field_from_tag(tag: u8) -> Result<MetadataField> {
    match tag {
        1 => Ok(MetadataField::DocumentId),
        2 => Ok(MetadataField::Version),
        3 => Ok(MetadataField::CreatedSequence),
        4 => Ok(MetadataField::ModifiedSequence),
        5 => Ok(MetadataField::Deleted),
        6 => Ok(MetadataField::KeyId),
        7 => Ok(MetadataField::KeyVersion),
        _ => Err(corruption("invalid index field")),
    }
}

fn record_from_tables<T>(
    payloads: &T,
    document_key: &[u8],
    metadata_bytes: &[u8],
) -> Result<DocumentRecord>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let metadata = decode_document_metadata(metadata_bytes)?;
    let payload = if metadata.deleted {
        None
    } else {
        let value = payloads
            .get(document_key)
            .map_err(storage)?
            .ok_or_else(|| corruption("live document payload missing"))?;
        Some(decode_document(value.value())?)
    };
    Ok(DocumentRecord { metadata, payload })
}

fn keys_with_prefix<T>(table: &T, prefix: &[u8]) -> Result<Vec<Vec<u8>>>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let end =
        prefix_successor(prefix).ok_or_else(|| corruption("index prefix has no successor"))?;
    let mut keys = Vec::new();
    for item in table.range(prefix..end.as_slice()).map_err(storage)? {
        let (key, _) = item.map_err(storage)?;
        keys.push(key.value().to_vec());
    }
    Ok(keys)
}
fn operation_identity(operation: &WriteOperation) -> (&str, &str) {
    match operation {
        WriteOperation::Put { document, .. } => (&document.collection, &document.id),
        WriteOperation::Delete { collection, id, .. } => (collection, id),
    }
}
fn operation_precondition(operation: &WriteOperation) -> &VersionPrecondition {
    match operation {
        WriteOperation::Put { precondition, .. } | WriteOperation::Delete { precondition, .. } => {
            precondition
        }
    }
}
fn validate_identity(collection: &str, id: &str) -> Result<()> {
    for (name, value) in [("collection", collection), ("id", id)] {
        if value.is_empty() || value.len() > MAX_NAME || value.contains('\0') {
            return Err(StoreError::InvalidInput(format!("invalid {name}")));
        }
    }
    Ok(())
}
fn validate_document(document: &EncryptedDocument, expected_database_id: &str) -> Result<()> {
    validate_identity(&document.collection, &document.id)?;
    validate_envelope(document)
        .map_err(|_| StoreError::InvalidInput("invalid encrypted envelope".into()))?;
    if document.database_id != expected_database_id {
        return Err(StoreError::InvalidInput(
            "encrypted envelope belongs to another database".into(),
        ));
    }
    Ok(())
}
fn ensure_newer(
    collection: &str,
    id: &str,
    existing: Option<&DocumentMetadata>,
    version: u64,
) -> Result<()> {
    if version == 0 || existing.is_some_and(|v| version <= v.version) {
        return Err(conflict(
            collection,
            id,
            format!("version greater than {}", existing.map_or(0, |v| v.version)),
            existing.map_or("absent".into(), |v| v.version.to_string()),
        ));
    }
    Ok(())
}
fn check_precondition(
    collection: &str,
    id: &str,
    existing: Option<&DocumentMetadata>,
    condition: &VersionPrecondition,
) -> Result<()> {
    let ok = match condition {
        VersionPrecondition::Any => true,
        VersionPrecondition::MustNotExist => existing.is_none(),
        VersionPrecondition::MustExist => existing.is_some(),
        VersionPrecondition::IfVersion(v) => existing.is_some_and(|m| m.version == *v),
    };
    if ok {
        Ok(())
    } else {
        Err(conflict(
            collection,
            id,
            format!("{condition:?}"),
            existing.map_or("absent".into(), |v| v.version.to_string()),
        ))
    }
}
fn conflict(collection: &str, id: &str, expected: String, actual: String) -> StoreError {
    StoreError::Conflict {
        collection: collection.into(),
        id: id.into(),
        expected,
        actual,
    }
}

fn encode_document(value: &EncryptedDocument) -> Vec<u8> {
    let mut e = Encoder::new(b"vdb.envelope.storage.v2\0");
    e.u8(value.format_version);
    e.string(&value.algorithm);
    e.string(&value.database_id);
    e.string(&value.key_id);
    e.u32(value.key_version);
    e.string(&value.collection);
    e.string(&value.id);
    e.u64(value.version);
    e.string(&value.nonce_b64);
    e.string(&value.ciphertext_b64);
    with_checksum(e.finish())
}
fn decode_document(bytes: &[u8]) -> Result<EncryptedDocument> {
    let mut d = Decoder::new(checked_body(bytes)?, b"vdb.envelope.storage.v2\0")?;
    let value = EncryptedDocument {
        format_version: d.u8()?,
        algorithm: d.string(32)?,
        database_id: d.string(32)?,
        key_id: d.string(32)?,
        key_version: d.u32()?,
        collection: d.string(MAX_NAME)?,
        id: d.string(MAX_NAME)?,
        version: d.u64()?,
        nonce_b64: d.string(64)?,
        ciphertext_b64: d.string(MAX_PAYLOAD * 2)?,
    };
    d.finish()?;
    validate_envelope(&value).map_err(|e| corruption(e.to_string()))?;
    Ok(value)
}
fn encode_document_metadata(value: &DocumentMetadata) -> Vec<u8> {
    let mut e = Encoder::new(b"vdb.document.metadata.v1\0");
    e.string(&value.collection);
    e.string(&value.id);
    e.u64(value.version);
    e.u64(value.created_sequence);
    e.u64(value.modified_sequence);
    e.u8(u8::from(value.deleted));
    match &value.payload_hash {
        Some(v) => {
            e.u8(1);
            e.string(v);
        }
        None => e.u8(0),
    };
    with_checksum(e.finish())
}
fn decode_document_metadata(bytes: &[u8]) -> Result<DocumentMetadata> {
    let mut d = Decoder::new(checked_body(bytes)?, b"vdb.document.metadata.v1\0")?;
    let collection = d.string(MAX_NAME)?;
    let id = d.string(MAX_NAME)?;
    let version = d.u64()?;
    let created_sequence = d.u64()?;
    let modified_sequence = d.u64()?;
    let deleted = match d.u8()? {
        0 => false,
        1 => true,
        _ => return Err(corruption("invalid tombstone flag")),
    };
    let payload_hash = match d.u8()? {
        0 => None,
        1 => Some(decode_hash(&mut d, "payload hash")?),
        _ => return Err(corruption("invalid payload hash flag")),
    };
    d.finish()?;
    let value = DocumentMetadata {
        collection,
        id,
        version,
        created_sequence,
        modified_sequence,
        deleted,
        payload_hash,
    };
    if value.version == 0
        || value.created_sequence == 0
        || value.modified_sequence < value.created_sequence
        || value.deleted == value.payload_hash.is_some()
    {
        return Err(corruption("invalid document metadata invariants"));
    }
    Ok(value)
}

fn mutation_signing_material(value: &MutationRecord) -> Vec<u8> {
    let mut e = Encoder::new(b"vdb.mutation.signing.v2\0");
    e.string(&value.database_id);
    e.u64(value.sequence);
    e.u8(match value.kind {
        MutationKind::Put => 1,
        MutationKind::Delete => 2,
    });
    e.string(&value.collection);
    e.string(&value.id);
    e.u64(value.version);
    e.string(&value.metadata_hash);
    match &value.payload_hash {
        Some(v) => {
            e.u8(1);
            e.string(v);
        }
        None => e.u8(0),
    };
    e.string(&value.previous_mutation_hash);
    e.string(&value.writer_id);
    e.u32(value.writer_key_version);
    e.string(&value.writer_public_key);
    e.string(&value.signature_algorithm);
    e.finish()
}
fn mutation_record_material(value: &MutationRecord) -> Vec<u8> {
    let mut e = Encoder::new(b"vdb.mutation.record.v2\0");
    e.bytes(&mutation_signing_material(value));
    e.string(&value.mutation_id);
    e.string(&value.signature);
    e.finish()
}
fn mutation_hash(value: &MutationRecord) -> String {
    blake3::hash(&mutation_record_material(value))
        .to_hex()
        .to_string()
}
fn encode_mutation(value: &MutationRecord) -> Vec<u8> {
    let mut e = Encoder::new(b"vdb.mutation.storage.v2\0");
    e.bytes(&mutation_record_material(value));
    e.string(&value.mutation_hash);
    with_checksum(e.finish())
}
fn decode_mutation(bytes: &[u8]) -> Result<MutationRecord> {
    let body = checked_body(bytes)?;
    let mut outer = Decoder::new(body, b"vdb.mutation.storage.v2\0")?;
    let record_bytes = outer.bytes(MAX_PAYLOAD)?;
    let mutation_hash = decode_hash(&mut outer, "mutation hash")?;
    outer.finish()?;
    let mut record_decoder = Decoder::new(record_bytes, b"vdb.mutation.record.v2\0")?;
    let signing_bytes = record_decoder.bytes(MAX_PAYLOAD)?;
    let mutation_id = decode_hash(&mut record_decoder, "mutation id")?;
    let signature = record_decoder.string(128)?;
    record_decoder.finish()?;
    let mut d = Decoder::new(signing_bytes, b"vdb.mutation.signing.v2\0")?;
    let database_id = d.string(64)?;
    let sequence = d.u64()?;
    let kind = match d.u8()? {
        1 => MutationKind::Put,
        2 => MutationKind::Delete,
        _ => return Err(corruption("invalid mutation kind")),
    };
    let collection = d.string(MAX_NAME)?;
    let id = d.string(MAX_NAME)?;
    let version = d.u64()?;
    let metadata_hash = decode_hash(&mut d, "metadata hash")?;
    let payload_hash = match d.u8()? {
        0 => None,
        1 => Some(decode_hash(&mut d, "payload hash")?),
        _ => return Err(corruption("invalid mutation payload flag")),
    };
    let previous_mutation_hash = d.string(64)?;
    if previous_mutation_hash != GENESIS
        && (previous_mutation_hash.len() != 64
            || hex::decode(&previous_mutation_hash)
                .map_err(corruption)?
                .len()
                != 32)
    {
        return Err(corruption("invalid previous mutation hash"));
    }
    let writer_id = d.string(32)?;
    let writer_key_version = d.u32()?;
    let writer_public_key = d.string(64)?;
    let signature_algorithm = d.string(32)?;
    d.finish()?;
    let record = MutationRecord {
        sequence,
        kind,
        collection,
        id,
        version,
        metadata_hash,
        payload_hash,
        previous_mutation_hash,
        database_id,
        writer_id,
        writer_key_version,
        writer_public_key,
        signature_algorithm,
        mutation_id,
        signature,
        mutation_hash,
    };
    validate_mutation_fields(&record)?;
    Ok(record)
}

fn validate_mutation_fields(record: &MutationRecord) -> Result<()> {
    if record.signature_algorithm != SIGNATURE_ALGORITHM || record.writer_key_version == 0 {
        return Err(corruption("unsupported mutation signature metadata"));
    }
    if hex::decode(&record.database_id).map_err(corruption)?.len() != 16
        || hex::decode(&record.writer_id).map_err(corruption)?.len() != 16
        || hex::decode(&record.writer_public_key)
            .map_err(corruption)?
            .len()
            != 32
        || hex::decode(&record.signature).map_err(corruption)?.len() != 64
    {
        return Err(corruption(
            "invalid mutation identity or signature encoding",
        ));
    }
    Ok(())
}

pub(crate) fn verify_mutation_record(record: &MutationRecord) -> Result<()> {
    validate_mutation_fields(record)?;
    let signing_material = mutation_signing_material(record);
    let expected_id = blake3::hash(&signing_material).to_hex().to_string();
    if expected_id != record.mutation_id {
        return Err(corruption("mutation id mismatch"));
    }
    verify_signature(
        &record.writer_public_key,
        &record.signature,
        &signing_material,
    )?;
    if mutation_hash(record) != record.mutation_hash {
        return Err(corruption("mutation record hash mismatch"));
    }
    Ok(())
}

fn writer_key(writer_id: &str, key_version: u32) -> Vec<u8> {
    let mut e = Encoder::new(b"vdb.writer.key.v1\0");
    e.string(writer_id);
    e.u32(key_version);
    e.finish()
}

fn decode_hash(decoder: &mut Decoder<'_>, name: &str) -> Result<String> {
    let value = decoder.string(64)?;
    if value.len() != 64 || hex::decode(&value).map_err(corruption)?.len() != 32 {
        return Err(corruption(format!("invalid {name}")));
    }
    Ok(value)
}

fn read_sequence(table: &redb::Table<&str, &[u8]>) -> Result<u64> {
    table
        .get(SEQUENCE_KEY)
        .map_err(storage)?
        .map(|v| decode_u64(v.value()))
        .transpose()
        .map(|v| v.unwrap_or(0))
}
fn read_head(table: &redb::Table<&str, &[u8]>) -> Result<String> {
    table
        .get(HEAD_KEY)
        .map_err(storage)?
        .map(|v| decode_head(v.value()))
        .transpose()
        .map(|v| v.unwrap_or_else(|| GENESIS.into()))
}
fn read_sequence_read(table: &redb::ReadOnlyTable<&str, &[u8]>) -> Result<u64> {
    table
        .get(SEQUENCE_KEY)
        .map_err(storage)?
        .map(|v| decode_u64(v.value()))
        .transpose()
        .map(|v| v.unwrap_or(0))
}
fn read_head_read(table: &redb::ReadOnlyTable<&str, &[u8]>) -> Result<String> {
    table
        .get(HEAD_KEY)
        .map_err(storage)?
        .map(|v| decode_head(v.value()))
        .transpose()
        .map(|v| v.unwrap_or_else(|| GENESIS.into()))
}
fn decode_u64(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| corruption("invalid sequence metadata"))?,
    ))
}
fn decode_head(bytes: &[u8]) -> Result<String> {
    let value = String::from_utf8(bytes.to_vec()).map_err(corruption)?;
    if value != GENESIS && hex::decode(&value).map_err(corruption)?.len() != 32 {
        return Err(corruption("invalid mutation head"));
    }
    Ok(value)
}
fn invalid_report(mutations: u64, head: &str, error: &str) -> VerifyReport {
    VerifyReport {
        valid: false,
        mutations,
        head: head.into(),
        error: Some(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{DatabaseKey, ENCRYPTION_ALGORITHM, encrypt_document};
    use base64::Engine as _;
    use proptest::prelude::*;
    use tempfile::tempdir;

    proptest! {
        #[test]
        fn document_metadata_canonical_round_trip(collection in "[a-z]{1,20}", id in "[a-z0-9]{1,20}", version in 1_u64..u64::MAX, created in 1_u64..1000, delta in 0_u64..1000) {
            let value = DocumentMetadata { collection, id, version, created_sequence: created, modified_sequence: created + delta, deleted: false, payload_hash: Some("ab".repeat(32)) };
            prop_assert_eq!(decode_document_metadata(&encode_document_metadata(&value)).expect("round trip"), value);
        }

        #[test]
        fn envelope_canonical_round_trip(collection in "[a-z]{1,20}", id in "[a-z0-9]{1,20}", version in 1_u64..u64::MAX, ciphertext in proptest::collection::vec(any::<u8>(), 16..100)) {
            let value = EncryptedDocument { format_version: 2, algorithm: ENCRYPTION_ALGORITHM.into(), database_id: "11".repeat(16), key_id: "22".repeat(16), key_version: 1, collection, id, version, nonce_b64: base64::engine::general_purpose::STANDARD.encode([7_u8; 24]), ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(ciphertext) };
            prop_assert_eq!(decode_document(&encode_document(&value)).expect("round trip"), value);
        }

        #[test]
        fn mutation_canonical_round_trip(collection in "[a-z]{1,20}", id in "[a-z0-9]{1,20}", sequence in 1_u64..u64::MAX, version in 1_u64..u64::MAX) {
            let mut value = MutationRecord { sequence, kind: MutationKind::Put, collection, id, version, metadata_hash: "11".repeat(32), payload_hash: Some("22".repeat(32)), previous_mutation_hash: "33".repeat(32), database_id: "44".repeat(16), writer_id: "55".repeat(16), writer_key_version: 1, writer_public_key: "66".repeat(32), signature_algorithm: SIGNATURE_ALGORITHM.into(), mutation_id: String::new(), signature: "77".repeat(64), mutation_hash: String::new() };
            value.mutation_id = blake3::hash(&mutation_signing_material(&value)).to_hex().to_string();
            value.mutation_hash = mutation_hash(&value);
            prop_assert_eq!(decode_mutation(&encode_mutation(&value)).expect("round trip"), value);
        }

        #[test]
        fn index_definition_canonical_round_trip(name in "[a-z]{1,20}", collection in "[a-z]{1,20}", tags in proptest::collection::vec(1_u8..=7, 1..=4)) {
            let mut fields: Vec<_> = tags.into_iter().map(|tag| index_field_from_tag(tag).expect("valid generated field")).collect();
            fields.sort();
            fields.dedup();
            prop_assume!(!fields.is_empty());
            let value = IndexDefinition { name, collection, fields };
            prop_assert_eq!(decode_index_definition(&encode_index_definition(&value)).expect("round trip"), value);
        }
    }

    #[test]
    fn checksummed_record_corruption_is_classified() {
        let value = DocumentMetadata {
            collection: "users".into(),
            id: "alice".into(),
            version: 1,
            created_sequence: 1,
            modified_sequence: 1,
            deleted: true,
            payload_hash: None,
        };
        let mut encoded = encode_document_metadata(&value);
        encoded[10] ^= 0x80;
        let error = decode_document_metadata(&encoded).expect_err("corruption must fail");
        assert!(error.is_corruption());
    }

    #[test]
    fn rejects_unversioned_legacy_layout() {
        const LEGACY: TableDefinition<&str, &[u8]> = TableDefinition::new("documents");
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("legacy.vdb");
        let db = Database::create(&path).expect("create legacy database");
        let tx = db.begin_write().expect("legacy transaction");
        tx.open_table(LEGACY).expect("legacy table");
        tx.commit().expect("legacy commit");
        drop(db);
        let error = match RedbEngine::open(path) {
            Ok(_) => panic!("legacy database opened"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            StoreError::UnsupportedFormat { found: 0, .. }
        ));
    }

    #[test]
    fn verification_detects_altered_persisted_payload() {
        let directory = tempdir().expect("temporary directory");
        let engine = RedbEngine::open(directory.path().join("tampered.vdb")).expect("open");
        let identity = WriterIdentity::from_seed([1_u8; 16], 1, [2_u8; 32]).expect("identity");
        let database_id = engine.metadata().expect("metadata").database_id;
        let key = DatabaseKey::from_database_secret(&database_id, [3_u8; 32]).expect("key");
        let document =
            encrypt_document(&key, &database_id, "users", "alice", 1, b"{}").expect("encrypt");
        engine
            .write(
                &[WriteOperation::Put {
                    document,
                    precondition: VersionPrecondition::MustNotExist,
                }],
                &identity,
            )
            .expect("write");
        let tx = engine.db.begin_write().expect("tamper transaction");
        {
            let mut payloads = tx.open_table(PAYLOADS).expect("payload table");
            let key = document_key("users", "alice");
            payloads
                .insert(key.as_slice(), b"altered".as_slice())
                .expect("alter payload");
        }
        tx.commit().expect("commit tamper");
        let report = engine.verify().expect("verification report");
        assert!(!report.valid);
        assert_eq!(report.error.as_deref(), Some("current payload mismatch"));
    }

    #[test]
    fn verification_detects_altered_secondary_index() {
        let directory = tempdir().expect("temporary directory");
        let engine = RedbEngine::open(directory.path().join("tampered-index.vdb")).expect("open");
        let identity = WriterIdentity::from_seed([1_u8; 16], 1, [2_u8; 32]).expect("identity");
        let database_id = engine.metadata().expect("metadata").database_id;
        let key = DatabaseKey::from_database_secret(&database_id, [3_u8; 32]).expect("key");
        let document =
            encrypt_document(&key, &database_id, "users", "alice", 1, b"{}").expect("encrypt");
        engine
            .write(
                &[WriteOperation::Put {
                    document,
                    precondition: VersionPrecondition::MustNotExist,
                }],
                &identity,
            )
            .expect("write");
        engine
            .create_index(&IndexDefinition {
                name: "versions".into(),
                collection: "users".into(),
                fields: vec![MetadataField::Version],
            })
            .expect("create index");

        let tx = engine.db.begin_write().expect("tamper transaction");
        {
            let mut entries = tx.open_table(INDEX_ENTRIES).expect("index entries");
            let key = entries
                .first()
                .expect("read first entry")
                .expect("entry")
                .0
                .value()
                .to_vec();
            entries
                .insert(key.as_slice(), b"wrong-document".as_slice())
                .expect("tamper entry");
        }
        tx.commit().expect("commit tamper");
        let report = engine.verify().expect("verification report");
        assert!(!report.valid);
        assert_eq!(
            report.error.as_deref(),
            Some("secondary index state mismatch")
        );
    }
}
