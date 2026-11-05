use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    codec::{Decoder, Encoder},
    crypto::validate_envelope,
    error::{Result, StoreError, corruption},
    identity::{SIGNATURE_ALGORITHM, verify_detached},
    merkle::build_root,
    model::{EncryptedDocument, MutationKind},
    store::Store,
};

const EVENT_DOMAIN: &[u8] = b"vdb.replication.event.v1\0";
const SIGNING_DOMAIN: &[u8] = b"vdb.replication.signing.v1\0";
const BATCH_DOMAIN: &[u8] = b"vdb.replication.batch.v1\0";
const HELLO_DOMAIN: &[u8] = b"vdb.replication.hello.v1\0";
const MAX_NAME: usize = 1024;
const MAX_EVENTS: usize = 100_000;
const MAX_EVENT_BYTES: usize = 8 * 1024 * 1024;

pub type VersionVector = BTreeMap<String, u64>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationEvent {
    pub format_version: u16,
    pub database_id: String,
    pub replica_id: String,
    pub replica_key_version: u32,
    pub replica_public_key: String,
    pub counter: u64,
    pub context: VersionVector,
    pub kind: MutationKind,
    pub collection: String,
    pub id: String,
    pub version: u64,
    pub payload: Option<EncryptedDocument>,
    pub event_id: String,
    pub signature_algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaProgress {
    pub contiguous: u64,
    pub sparse: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationCheckpoint {
    pub database_id: String,
    pub event_count: u64,
    pub event_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationState {
    pub database_id: String,
    pub replicas: BTreeMap<String, ReplicaProgress>,
    pub checkpoint: ReplicationCheckpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ReplicatedDocument {
    Absent,
    Live { event: ReplicationEvent },
    Deleted { event: ReplicationEvent },
    Conflict { events: Vec<ReplicationEvent> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedPeer {
    pub replica_id: String,
    pub key_version: u32,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerHello {
    pub database_id: String,
    pub replica_id: String,
    pub key_version: u32,
    pub public_key: String,
    pub challenge: String,
    pub state_root: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReport {
    pub offered: usize,
    pub accepted: usize,
    pub duplicates: usize,
    pub checkpoint: ReplicationCheckpoint,
}

#[derive(Clone)]
pub struct Replica {
    store: Store,
}

impl Replica {
    pub fn new(store: Store) -> Self {
        Self { store }
    }

    pub fn replica_id(&self) -> String {
        self.store.writer_id()
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn state(&self) -> Result<ReplicationState> {
        state_from_events(
            &self.store.metadata()?.database_id,
            &self.store.replication_events()?,
        )
    }

    pub fn checkpoint(&self) -> Result<ReplicationCheckpoint> {
        Ok(self.state()?.checkpoint)
    }

    pub fn verify_checkpoint(&self, expected: &ReplicationCheckpoint) -> Result<bool> {
        Ok(self.checkpoint()? == *expected)
    }

    pub fn put(&self, document: EncryptedDocument) -> Result<ReplicationEvent> {
        self.create_event(
            MutationKind::Put,
            document.collection.clone(),
            document.id.clone(),
            document.version,
            Some(document),
        )
    }

    pub fn delete(&self, collection: &str, id: &str, version: u64) -> Result<ReplicationEvent> {
        self.create_event(
            MutationKind::Delete,
            collection.into(),
            id.into(),
            version,
            None,
        )
    }

    pub fn resolve(
        &self,
        collection: &str,
        id: &str,
        chosen_event_id: &str,
    ) -> Result<ReplicationEvent> {
        let events = self.store.replication_events()?;
        let heads = document_heads(&events, collection, id);
        if heads.len() < 2 {
            return Err(StoreError::InvalidInput(
                "document does not have a conflict".into(),
            ));
        }
        let chosen = heads
            .iter()
            .find(|event| event.event_id == chosen_event_id)
            .ok_or_else(|| {
                StoreError::InvalidInput("chosen event is not a current conflict head".into())
            })?;
        self.create_event(
            chosen.kind,
            collection.into(),
            id.into(),
            chosen.version,
            chosen.payload.clone(),
        )
    }

    pub fn document(&self, collection: &str, id: &str) -> Result<ReplicatedDocument> {
        let heads = document_heads(&self.store.replication_events()?, collection, id);
        Ok(match heads.as_slice() {
            [] => ReplicatedDocument::Absent,
            [event] if event.kind == MutationKind::Delete => ReplicatedDocument::Deleted {
                event: event.clone(),
            },
            [event] => ReplicatedDocument::Live {
                event: event.clone(),
            },
            _ => ReplicatedDocument::Conflict { events: heads },
        })
    }

    pub fn hello(&self, challenge: &str) -> Result<PeerHello> {
        if !valid_hex(challenge, 32) {
            return Err(StoreError::InvalidInput(
                "peer challenge must be 32 random bytes in hexadecimal".into(),
            ));
        }
        let state = self.state()?;
        let mut hello = PeerHello {
            database_id: state.database_id,
            replica_id: self.store.writer_id(),
            key_version: self.store.writer_key_version(),
            public_key: self.store.writer_public_key(),
            challenge: challenge.into(),
            state_root: state.checkpoint.event_root,
            signature: String::new(),
        };
        hello.signature = self.store.sign_bytes(&hello_material(&hello));
        Ok(hello)
    }

    pub fn missing_for(&self, remote: &ReplicationState) -> Result<Vec<ReplicationEvent>> {
        if remote.database_id != self.store.metadata()?.database_id {
            return Err(StoreError::InvalidInput(
                "replication database identity mismatch".into(),
            ));
        }
        let mut events: Vec<_> = self
            .store
            .replication_events()?
            .into_iter()
            .filter(|event| {
                !progress_contains(remote.replicas.get(&event.replica_id), event.counter)
            })
            .collect();
        events.sort_by(event_order);
        Ok(events)
    }

    pub fn apply(&self, events: &[ReplicationEvent]) -> Result<SyncReport> {
        let database_id = self.store.metadata()?.database_id;
        for event in events {
            verify_event(event, &database_id)?;
        }
        let accepted = self.store.store_replication_events(events)?;
        Ok(SyncReport {
            offered: events.len(),
            accepted,
            duplicates: events.len() - accepted,
            checkpoint: self.checkpoint()?,
        })
    }

    pub fn sync_from(
        &self,
        peer: &Replica,
        authorized: &[AuthorizedPeer],
        challenge: &str,
    ) -> Result<SyncReport> {
        let hello = peer.hello(challenge)?;
        verify_peer(
            &hello,
            authorized,
            challenge,
            &self.store.metadata()?.database_id,
        )?;
        let state = self.state()?;
        self.apply(&peer.missing_for(&state)?)
    }

    fn create_event(
        &self,
        kind: MutationKind,
        collection: String,
        id: String,
        version: u64,
        payload: Option<EncryptedDocument>,
    ) -> Result<ReplicationEvent> {
        validate_name(&collection, "collection")?;
        validate_name(&id, "document id")?;
        if version == 0 {
            return Err(StoreError::InvalidInput(
                "document version must be non-zero".into(),
            ));
        }
        let database_id = self.store.metadata()?.database_id;
        match (&kind, &payload) {
            (MutationKind::Put, Some(document)) => {
                validate_envelope(document)
                    .map_err(|_| StoreError::InvalidInput("invalid encrypted envelope".into()))?;
                if document.database_id != database_id
                    || document.collection != collection
                    || document.id != id
                    || document.version != version
                {
                    return Err(StoreError::InvalidInput(
                        "replication envelope identity mismatch".into(),
                    ));
                }
            }
            (MutationKind::Delete, None) => {}
            _ => {
                return Err(StoreError::InvalidInput(
                    "replication event kind/payload mismatch".into(),
                ));
            }
        }
        let existing = self.store.replication_events()?;
        let context = version_vector(&existing);
        let counter = context
            .get(&self.store.writer_id())
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| StoreError::Corruption("replica counter overflow".into()))?;
        let mut event = ReplicationEvent {
            format_version: 1,
            database_id,
            replica_id: self.store.writer_id(),
            replica_key_version: self.store.writer_key_version(),
            replica_public_key: self.store.writer_public_key(),
            counter,
            context,
            kind,
            collection,
            id,
            version,
            payload,
            event_id: String::new(),
            signature_algorithm: SIGNATURE_ALGORITHM.into(),
            signature: String::new(),
        };
        let material = signing_material(&event);
        event.event_id = blake3::hash(&material).to_hex().to_string();
        event.signature = self.store.sign_bytes(&material);
        let report = self.apply(std::slice::from_ref(&event))?;
        if report.accepted != 1 {
            return Err(StoreError::Conflict {
                collection: event.collection.clone(),
                id: event.id.clone(),
                expected: "new replica dot".into(),
                actual: "duplicate replica dot".into(),
            });
        }
        Ok(event)
    }
}

pub fn verify_peer(
    hello: &PeerHello,
    authorized: &[AuthorizedPeer],
    challenge: &str,
    database_id: &str,
) -> Result<()> {
    if hello.challenge != challenge || hello.database_id != database_id || !valid_hex(challenge, 32)
    {
        return Err(StoreError::InvalidInput(
            "peer authentication failed".into(),
        ));
    }
    let allowed = authorized.iter().any(|peer| {
        peer.replica_id == hello.replica_id
            && peer.key_version == hello.key_version
            && peer.public_key == hello.public_key
    });
    if !allowed || !verify_detached(&hello.public_key, &hello.signature, &hello_material(hello)) {
        return Err(StoreError::InvalidInput(
            "peer authentication failed".into(),
        ));
    }
    Ok(())
}

pub fn verify_event(event: &ReplicationEvent, database_id: &str) -> Result<()> {
    if event.format_version != 1
        || event.database_id != database_id
        || event.counter == 0
        || event.replica_key_version == 0
        || event.signature_algorithm != SIGNATURE_ALGORITHM
        || !valid_hex(&event.replica_id, 16)
        || !valid_hex(&event.replica_public_key, 32)
        || !valid_hex(&event.event_id, 32)
        || !valid_hex(&event.signature, 64)
    {
        return Err(StoreError::InvalidInput(
            "invalid replication event metadata".into(),
        ));
    }
    validate_name(&event.collection, "collection")?;
    validate_name(&event.id, "document id")?;
    let expected_counter = event
        .context
        .get(&event.replica_id)
        .copied()
        .unwrap_or(0)
        .checked_add(1);
    if event.version == 0 || event.context.len() > 10_000 || expected_counter != Some(event.counter)
    {
        return Err(StoreError::InvalidInput(
            "invalid replication causal dot".into(),
        ));
    }
    for (replica, counter) in &event.context {
        if !valid_hex(replica, 16) || *counter == 0 {
            return Err(StoreError::InvalidInput(
                "invalid replication version vector".into(),
            ));
        }
    }
    match (event.kind, &event.payload) {
        (MutationKind::Put, Some(document)) => {
            validate_envelope(document)
                .map_err(|_| StoreError::InvalidInput("invalid replicated envelope".into()))?;
            if document.database_id != event.database_id
                || document.collection != event.collection
                || document.id != event.id
                || document.version != event.version
            {
                return Err(StoreError::InvalidInput(
                    "replicated envelope identity mismatch".into(),
                ));
            }
        }
        (MutationKind::Delete, None) => {}
        _ => {
            return Err(StoreError::InvalidInput(
                "replication event kind/payload mismatch".into(),
            ));
        }
    }
    let material = signing_material(event);
    if blake3::hash(&material).to_hex().as_str() != event.event_id
        || !verify_detached(&event.replica_public_key, &event.signature, &material)
    {
        return Err(StoreError::InvalidInput(
            "invalid replication event signature".into(),
        ));
    }
    Ok(())
}

pub fn encode_batch(events: &[ReplicationEvent]) -> Result<Vec<u8>> {
    if events.len() > MAX_EVENTS {
        return Err(StoreError::InvalidInput(
            "replication batch is too large".into(),
        ));
    }
    let mut encoder = Encoder::new(BATCH_DOMAIN);
    encoder.u64(events.len() as u64);
    for event in events {
        encoder.bytes(&encode_event(event));
    }
    let mut bytes = encoder.finish();
    bytes.extend_from_slice(blake3::hash(&bytes).as_bytes());
    Ok(bytes)
}

pub fn decode_batch(bytes: &[u8]) -> Result<Vec<ReplicationEvent>> {
    if bytes.len() < 32 || bytes.len() > MAX_EVENTS.saturating_mul(MAX_EVENT_BYTES) {
        return Err(corruption("invalid replication batch size"));
    }
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    if blake3::hash(body).as_bytes() != checksum {
        return Err(corruption("replication batch checksum mismatch"));
    }
    let mut decoder = Decoder::new(body, BATCH_DOMAIN)?;
    let count = usize::try_from(decoder.u64()?).map_err(corruption)?;
    if count > MAX_EVENTS {
        return Err(corruption("replication batch event limit exceeded"));
    }
    let mut events = Vec::with_capacity(count);
    for _ in 0..count {
        events.push(decode_event(decoder.bytes(MAX_EVENT_BYTES)?)?);
    }
    decoder.finish()?;
    Ok(events)
}

pub(crate) fn encode_event(event: &ReplicationEvent) -> Vec<u8> {
    let mut encoder = Encoder::new(EVENT_DOMAIN);
    encoder.bytes(&signing_material(event));
    encoder.string(&event.event_id);
    encoder.string(&event.signature);
    let mut bytes = encoder.finish();
    bytes.extend_from_slice(blake3::hash(&bytes).as_bytes());
    bytes
}

pub(crate) fn decode_event(bytes: &[u8]) -> Result<ReplicationEvent> {
    if bytes.len() < 32 {
        return Err(corruption("truncated replication event"));
    }
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    if blake3::hash(body).as_bytes() != checksum {
        return Err(corruption("replication event checksum mismatch"));
    }
    let mut outer = Decoder::new(body, EVENT_DOMAIN)?;
    let signing = outer.bytes(MAX_EVENT_BYTES)?;
    let event_id = outer.string(64)?;
    let signature = outer.string(128)?;
    outer.finish()?;
    decode_signing_material(signing, event_id, signature)
}

fn signing_material(event: &ReplicationEvent) -> Vec<u8> {
    let mut e = Encoder::new(SIGNING_DOMAIN);
    e.u32(event.format_version.into());
    e.string(&event.database_id);
    e.string(&event.replica_id);
    e.u32(event.replica_key_version);
    e.string(&event.replica_public_key);
    e.u64(event.counter);
    e.u64(event.context.len() as u64);
    for (replica, counter) in &event.context {
        e.string(replica);
        e.u64(*counter);
    }
    e.u8(if event.kind == MutationKind::Put {
        1
    } else {
        2
    });
    e.string(&event.collection);
    e.string(&event.id);
    e.u64(event.version);
    match &event.payload {
        Some(payload) => {
            e.u8(1);
            encode_document(&mut e, payload);
        }
        None => e.u8(0),
    }
    e.string(&event.signature_algorithm);
    e.finish()
}

fn decode_signing_material(
    bytes: &[u8],
    event_id: String,
    signature: String,
) -> Result<ReplicationEvent> {
    let mut d = Decoder::new(bytes, SIGNING_DOMAIN)?;
    let format_version = u16::try_from(d.u32()?).map_err(corruption)?;
    let database_id = d.string(64)?;
    let replica_id = d.string(32)?;
    let replica_key_version = d.u32()?;
    let replica_public_key = d.string(64)?;
    let counter = d.u64()?;
    let count = usize::try_from(d.u64()?).map_err(corruption)?;
    if count > 10_000 {
        return Err(corruption("replication vector is too large"));
    }
    let mut context = BTreeMap::new();
    for _ in 0..count {
        let id = d.string(32)?;
        let counter = d.u64()?;
        if context.insert(id, counter).is_some() {
            return Err(corruption("duplicate replication vector entry"));
        }
    }
    let kind = match d.u8()? {
        1 => MutationKind::Put,
        2 => MutationKind::Delete,
        _ => return Err(corruption("invalid replication mutation kind")),
    };
    let collection = d.string(MAX_NAME)?;
    let id = d.string(MAX_NAME)?;
    let version = d.u64()?;
    let payload = match d.u8()? {
        0 => None,
        1 => Some(decode_document(&mut d)?),
        _ => return Err(corruption("invalid replication payload flag")),
    };
    let signature_algorithm = d.string(32)?;
    d.finish()?;
    Ok(ReplicationEvent {
        format_version,
        database_id,
        replica_id,
        replica_key_version,
        replica_public_key,
        counter,
        context,
        kind,
        collection,
        id,
        version,
        payload,
        event_id,
        signature_algorithm,
        signature,
    })
}

fn encode_document(e: &mut Encoder, value: &EncryptedDocument) {
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
}
fn decode_document(d: &mut Decoder<'_>) -> Result<EncryptedDocument> {
    Ok(EncryptedDocument {
        format_version: d.u8()?,
        algorithm: d.string(32)?,
        database_id: d.string(64)?,
        key_id: d.string(64)?,
        key_version: d.u32()?,
        collection: d.string(MAX_NAME)?,
        id: d.string(MAX_NAME)?,
        version: d.u64()?,
        nonce_b64: d.string(128)?,
        ciphertext_b64: d.string(8 * 1024 * 1024)?,
    })
}

fn version_vector(events: &[ReplicationEvent]) -> VersionVector {
    let mut vector: VersionVector = BTreeMap::new();
    for event in events {
        vector
            .entry(event.replica_id.clone())
            .and_modify(|v| *v = (*v).max(event.counter))
            .or_insert(event.counter);
    }
    vector
}

fn state_from_events(database_id: &str, events: &[ReplicationEvent]) -> Result<ReplicationState> {
    let mut counters: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
    let mut ids = Vec::with_capacity(events.len());
    for event in events {
        verify_event(event, database_id)?;
        counters
            .entry(event.replica_id.clone())
            .or_default()
            .insert(event.counter);
        ids.push(event.event_id.clone());
    }
    let replicas = counters
        .into_iter()
        .map(|(replica, values)| {
            let mut contiguous = 0;
            while values.contains(&(contiguous + 1)) {
                contiguous += 1;
            }
            let sparse = values
                .into_iter()
                .filter(|counter| *counter > contiguous)
                .collect();
            (replica, ReplicaProgress { contiguous, sparse })
        })
        .collect();
    ids.sort();
    let leaves: Result<Vec<[u8; 32]>> = ids
        .iter()
        .map(|id| {
            hex::decode(id)
                .map_err(corruption)?
                .try_into()
                .map_err(|_| corruption("invalid replication event id"))
        })
        .collect();
    let root = build_root(leaves?);
    Ok(ReplicationState {
        database_id: database_id.into(),
        replicas,
        checkpoint: ReplicationCheckpoint {
            database_id: database_id.into(),
            event_count: events.len() as u64,
            event_root: hex::encode(root),
        },
    })
}

fn document_heads(
    events: &[ReplicationEvent],
    collection: &str,
    id: &str,
) -> Vec<ReplicationEvent> {
    let mut counters: BTreeMap<&str, BTreeSet<u64>> = BTreeMap::new();
    for event in events {
        counters
            .entry(event.replica_id.as_str())
            .or_default()
            .insert(event.counter);
    }
    let contiguous: BTreeMap<_, _> = counters
        .into_iter()
        .map(|(replica, values)| {
            let mut frontier = 0;
            while values.contains(&(frontier + 1)) {
                frontier += 1;
            }
            (replica, frontier)
        })
        .collect();
    let candidates: Vec<_> = events
        .iter()
        .filter(|event| {
            event.context.iter().all(|(replica, counter)| {
                contiguous.get(replica.as_str()).copied().unwrap_or(0) >= *counter
            })
        })
        .filter(|event| event.collection == collection && event.id == id)
        .collect();
    let mut heads: Vec<_> = candidates
        .iter()
        .filter(|candidate| {
            !candidates
                .iter()
                .any(|other| other.event_id != candidate.event_id && observes(other, candidate))
        })
        .map(|event| (*event).clone())
        .collect();
    heads.sort_by(|a, b| a.event_id.cmp(&b.event_id));
    heads
}
fn observes(later: &ReplicationEvent, earlier: &ReplicationEvent) -> bool {
    later.context.get(&earlier.replica_id).copied().unwrap_or(0) >= earlier.counter
}
fn progress_contains(progress: Option<&ReplicaProgress>, counter: u64) -> bool {
    progress.is_some_and(|p| counter <= p.contiguous || p.sparse.binary_search(&counter).is_ok())
}
fn event_order(a: &ReplicationEvent, b: &ReplicationEvent) -> std::cmp::Ordering {
    a.replica_id
        .cmp(&b.replica_id)
        .then(a.counter.cmp(&b.counter))
        .then(a.event_id.cmp(&b.event_id))
}

fn hello_material(hello: &PeerHello) -> Vec<u8> {
    let mut e = Encoder::new(HELLO_DOMAIN);
    e.string(&hello.database_id);
    e.string(&hello.replica_id);
    e.u32(hello.key_version);
    e.string(&hello.public_key);
    e.string(&hello.challenge);
    e.string(&hello.state_root);
    e.finish()
}
fn valid_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2 && hex::decode(value).is_ok()
}
fn validate_name(value: &str, name: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_NAME || value.contains('\0') {
        Err(StoreError::InvalidInput(format!("invalid {name}")))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::{fs, path::PathBuf};

    use tempfile::tempdir;

    use crate::{
        crypto::{DatabaseKey, encrypt_document},
        identity::WriterIdentity,
    };

    proptest! {
        #[test]
        fn arbitrary_replication_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..65_536)) {
            let _ = decode_batch(&bytes);
        }
    }

    struct Harness {
        _directory: tempfile::TempDir,
        path_b: PathBuf,
        a: Replica,
        b: Replica,
        secret: [u8; 32],
    }

    impl Harness {
        fn new() -> Result<Self> {
            let directory = tempdir().map_err(|error| StoreError::Storage(error.to_string()))?;
            let path_a = directory.path().join("a.vdb");
            let path_b = directory.path().join("b.vdb");
            let initial = Store::open_with_identity(&path_a, identity(1, 11)?)?;
            drop(initial);
            fs::copy(&path_a, &path_b).map_err(|error| StoreError::Storage(error.to_string()))?;
            let a = Replica::new(Store::open_with_identity(&path_a, identity(1, 11)?)?);
            let b = Replica::new(Store::open_with_identity(&path_b, identity(2, 22)?)?);
            Ok(Self {
                _directory: directory,
                path_b,
                a,
                b,
                secret: [9; 32],
            })
        }

        fn document(
            &self,
            replica: &Replica,
            id: &str,
            version: u64,
            body: &[u8],
        ) -> Result<EncryptedDocument> {
            let database_id = replica.store().metadata()?.database_id;
            let key = DatabaseKey::from_database_secret(&database_id, self.secret)
                .map_err(|error| StoreError::Storage(error.to_string()))?;
            encrypt_document(&key, &database_id, "items", id, version, body)
                .map_err(|error| StoreError::Storage(error.to_string()))
        }

        fn authorize(replica: &Replica) -> AuthorizedPeer {
            AuthorizedPeer {
                replica_id: replica.store.writer_id(),
                key_version: replica.store.writer_key_version(),
                public_key: replica.store.writer_public_key(),
            }
        }
    }

    fn identity(id: u8, seed: u8) -> Result<WriterIdentity> {
        WriterIdentity::from_seed([id; 16], 1, [seed; 32])
    }

    fn challenge() -> String {
        hex::encode([42_u8; 32])
    }

    fn sync_both(harness: &Harness) -> Result<()> {
        harness
            .a
            .sync_from(&harness.b, &[Harness::authorize(&harness.b)], &challenge())?;
        harness
            .b
            .sync_from(&harness.a, &[Harness::authorize(&harness.a)], &challenge())?;
        Ok(())
    }

    #[test]
    fn partition_concurrent_writes_rejoin_and_explicitly_resolve() -> Result<()> {
        let harness = Harness::new()?;
        harness
            .a
            .put(harness.document(&harness.a, "one", 1, b"from-a")?)?;
        harness
            .b
            .put(harness.document(&harness.b, "one", 1, b"from-b")?)?;

        sync_both(&harness)?;
        let ReplicatedDocument::Conflict { events: left } = harness.a.document("items", "one")?
        else {
            panic!("A must preserve conflict")
        };
        let ReplicatedDocument::Conflict { events: right } = harness.b.document("items", "one")?
        else {
            panic!("B must preserve conflict")
        };
        assert_eq!(left, right);
        let chosen = left[0].event_id.clone();
        harness.a.resolve("items", "one", &chosen)?;
        sync_both(&harness)?;
        assert_eq!(
            harness.a.document("items", "one")?,
            harness.b.document("items", "one")?
        );
        assert_eq!(harness.a.checkpoint()?, harness.b.checkpoint()?);
        assert!(harness.b.verify_checkpoint(&harness.a.checkpoint()?)?);
        assert!(matches!(
            harness.a.document("items", "one")?,
            ReplicatedDocument::Live { .. }
        ));
        assert!(harness.a.store().verify()?.valid);
        assert!(harness.b.store().verify()?.valid);
        Ok(())
    }

    #[test]
    fn duplicate_reordered_and_lossy_incremental_delivery_converges() -> Result<()> {
        let harness = Harness::new()?;
        for version in 1..=12 {
            harness.a.put(harness.document(
                &harness.a,
                &format!("doc-{version}"),
                version,
                &[version as u8],
            )?)?;
        }
        let mut missing = harness.a.missing_for(&harness.b.state()?)?;
        missing.reverse();
        let first = missing.split_off(6);
        harness.b.apply(&first)?;
        assert_ne!(harness.a.checkpoint()?, harness.b.checkpoint()?);
        let duplicate = harness.b.apply(&first)?;
        assert_eq!(duplicate.accepted, 0);
        let remainder = harness.a.missing_for(&harness.b.state()?)?;
        assert_eq!(remainder.len(), 6);
        harness.b.apply(&remainder)?;
        assert_eq!(harness.a.checkpoint()?, harness.b.checkpoint()?);
        Ok(())
    }

    #[test]
    fn restart_mid_sync_and_long_offline_period_converge() -> Result<()> {
        let mut harness = Harness::new()?;
        for version in 1..=64 {
            harness.a.put(harness.document(
                &harness.a,
                &format!("offline-{version}"),
                version,
                &[version as u8],
            )?)?;
        }
        let offered = harness.a.missing_for(&harness.b.state()?)?;
        harness.b.apply(&offered[..17])?;
        let old = std::mem::replace(
            &mut harness.b,
            Replica::new(Store::open_with_identity(
                harness._directory.path().join("temporary.vdb"),
                identity(3, 33)?,
            )?),
        );
        drop(old);
        harness.b = Replica::new(Store::open_with_identity(
            &harness.path_b,
            identity(2, 22)?,
        )?);
        let remaining = harness.a.missing_for(&harness.b.state()?)?;
        assert_eq!(remaining.len(), 47);
        harness.b.apply(&remaining)?;
        assert_eq!(harness.a.checkpoint()?, harness.b.checkpoint()?);
        Ok(())
    }

    #[test]
    fn deletion_and_modification_remain_a_conflict() -> Result<()> {
        let harness = Harness::new()?;
        harness
            .a
            .put(harness.document(&harness.a, "one", 1, b"base")?)?;
        sync_both(&harness)?;
        harness.a.delete("items", "one", 2)?;
        harness
            .b
            .put(harness.document(&harness.b, "one", 2, b"modified")?)?;
        sync_both(&harness)?;
        let ReplicatedDocument::Conflict { events } = harness.a.document("items", "one")? else {
            panic!("delete/modify must conflict")
        };
        assert!(
            events
                .iter()
                .any(|event| event.kind == MutationKind::Delete)
        );
        assert!(events.iter().any(|event| event.kind == MutationKind::Put));
        Ok(())
    }

    #[test]
    fn invalid_peer_forgery_and_corrupted_stream_are_rejected() -> Result<()> {
        let harness = Harness::new()?;
        let event = harness
            .a
            .put(harness.document(&harness.a, "one", 1, b"valid")?)?;
        let unauthorized = harness.b.sync_from(&harness.a, &[], &challenge());
        assert!(matches!(unauthorized, Err(StoreError::InvalidInput(_))));

        let mut forged = event.clone();
        forged.version += 1;
        assert!(matches!(
            harness.b.apply(&[forged]),
            Err(StoreError::InvalidInput(_))
        ));

        let encoded = encode_batch(std::slice::from_ref(&event))?;
        let mut corrupted = encoded.clone();
        corrupted[20] ^= 1;
        assert!(matches!(
            decode_batch(&corrupted),
            Err(StoreError::Corruption(_))
        ));
        assert_eq!(decode_batch(&encoded)?, vec![event]);
        Ok(())
    }

    #[test]
    fn later_event_delivered_before_dependency_is_not_visible() -> Result<()> {
        let harness = Harness::new()?;
        harness
            .a
            .put(harness.document(&harness.a, "one", 1, b"first")?)?;
        harness
            .a
            .put(harness.document(&harness.a, "one", 2, b"second")?)?;
        let events = harness.a.missing_for(&harness.b.state()?)?;
        harness.b.apply(&events[1..])?;
        assert_eq!(
            harness.b.document("items", "one")?,
            ReplicatedDocument::Absent
        );
        harness.b.apply(&events[..1])?;
        assert!(
            matches!(harness.b.document("items", "one")?, ReplicatedDocument::Live { event } if event.version == 2)
        );
        Ok(())
    }
}
