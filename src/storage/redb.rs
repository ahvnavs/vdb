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
    storage::{StorageEngine, StorageSnapshot},
};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("vdb1.metadata");
const DOCUMENT_META: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vdb1.document_metadata");
const PAYLOADS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vdb1.payloads");
const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("vdb1.mutation_log");
const WRITERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("vdb1.writer_keys");
const MUTATION_IDS: TableDefinition<&[u8], u64> = TableDefinition::new("vdb1.mutation_ids");
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
        }
        tx.commit().map_err(storage)?;
        Ok(Self { db: Arc::new(db) })
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
        {
            let mut metadata_table = tx.open_table(DOCUMENT_META).map_err(storage)?;
            let mut payload_table = tx.open_table(PAYLOADS).map_err(storage)?;
            let mut log = tx.open_table(LOG).map_err(storage)?;
            let mut meta = tx.open_table(META).map_err(storage)?;
            let mut writers = tx.open_table(WRITERS).map_err(storage)?;
            let mut mutation_ids = tx.open_table(MUTATION_IDS).map_err(storage)?;
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
                check_precondition(
                    collection,
                    id,
                    existing.as_ref(),
                    operation_precondition(operation),
                )?;
                sequence = sequence
                    .checked_add(1)
                    .ok_or_else(|| corruption("mutation sequence overflow"))?;

                let (metadata, payload, kind) = match operation {
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
        Ok(VerifyReport {
            valid: true,
            mutations: count,
            head: previous,
            error: None,
        })
    }
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
}
