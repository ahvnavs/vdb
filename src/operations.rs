use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use redb::Database;
use serde::Serialize;

use crate::{
    codec::{Decoder, Encoder},
    error::{Result, StoreError, corruption},
    model::{DATABASE_FORMAT_VERSION, DatabaseMetadata, StateCheckpoint, VerifyReport},
    replication::{Replica, ReplicationCheckpoint, ReplicationEvent},
    storage::{BackupImage, BackupTable, redb::RedbEngine},
    store::Store,
};

pub use crate::storage::StorageStatistics;

const BACKUP_DOMAIN: &[u8] = b"vdb.backup.v1\0";
const MAX_TABLES: usize = 32;
const MAX_ROWS: usize = 10_000_000;
const MAX_FIELD: usize = 16 * 1024 * 1024;
const MAX_BACKUP_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct ReplicationHealth {
    pub replicas: usize,
    pub events: u64,
    pub pending_events: u64,
    pub sparse_gaps: u64,
    pub conflicted_documents: u64,
    pub checkpoint: ReplicationCheckpoint,
}

#[derive(Debug, Clone, Serialize)]
pub struct CryptographicStatistics {
    pub valid: bool,
    pub signed_mutations_verified: u64,
    pub replication_events_verified: u64,
    pub state_leaves_verified: u64,
    pub history_head: String,
    pub state_root: String,
    pub replication_root: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DatabaseStatus {
    pub metadata: DatabaseMetadata,
    pub storage: StorageStatistics,
    pub verification: CryptographicStatistics,
    pub replication: ReplicationHealth,
}

#[derive(Debug, Clone, Serialize)]
pub struct DatabaseInspection {
    pub metadata: DatabaseMetadata,
    pub checkpoint: StateCheckpoint,
    pub storage: StorageStatistics,
    pub replication: ReplicationHealth,
    pub visible_metadata_only: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupReport {
    pub path: PathBuf,
    pub bytes: u64,
    pub database_id: String,
    pub format_version: u32,
    pub mutations: u64,
    pub replication_events: u64,
    pub state_root: String,
    pub replication_root: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestoreReport {
    pub path: PathBuf,
    pub database_id: String,
    pub verified: bool,
    pub mutations: u64,
    pub replication_events: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompactionReport {
    pub path: PathBuf,
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub passes: u32,
    pub verified_before: bool,
    pub verified_after: bool,
}

impl Store {
    pub fn inspect(&self) -> Result<DatabaseInspection> {
        Ok(DatabaseInspection {
            metadata: self.metadata()?,
            checkpoint: self.checkpoint()?,
            storage: self.storage_statistics()?,
            replication: replication_health(self)?,
            visible_metadata_only: true,
        })
    }

    pub fn status(&self) -> Result<DatabaseStatus> {
        let metadata = self.metadata()?;
        let storage = self.storage_statistics()?;
        let checkpoint = self.checkpoint()?;
        let report = self.verify()?;
        let replication = replication_health(self)?;
        Ok(DatabaseStatus {
            metadata,
            verification: crypto_statistics(&report, &checkpoint, &replication, &storage),
            storage,
            replication,
        })
    }

    pub fn backup(&self, destination: impl AsRef<Path>) -> Result<BackupReport> {
        let destination = destination.as_ref();
        ensure_absent(destination, "backup destination")?;
        let bytes = encode_backup(&self.backup_image()?);
        write_new_atomic(destination, &bytes)?;
        let report = verify_backup(destination)?;
        tracing::info!(operation = "backup", database_id = %report.database_id, bytes = report.bytes, "backup created and verified");
        Ok(report)
    }

    pub fn snapshot_to(&self, destination: impl AsRef<Path>) -> Result<BackupReport> {
        self.backup(destination)
    }
}

pub fn verify_backup(path: impl AsRef<Path>) -> Result<BackupReport> {
    let path = path.as_ref();
    let bytes = read_backup(path)?;
    let image = decode_backup(&bytes)?;
    let temporary = reserve_temporary_file(&std::env::temp_dir(), "vdb-backup-verify")?;
    let guard = TemporaryPath::new(temporary.clone());
    RedbEngine::restore_image(&temporary, &image)?;
    let store = Store::open(&temporary)?;
    let status = store.status()?;
    if !status.verification.valid {
        return Err(corruption(
            status
                .verification
                .error
                .unwrap_or_else(|| "backup verification failed".into()),
        ));
    }
    drop(store);
    drop(guard);
    Ok(BackupReport {
        path: path.to_path_buf(),
        bytes: bytes.len() as u64,
        database_id: status.metadata.database_id,
        format_version: status.metadata.format_version,
        mutations: status.verification.signed_mutations_verified,
        replication_events: status.verification.replication_events_verified,
        state_root: status.verification.state_root,
        replication_root: status.verification.replication_root,
    })
}

pub fn restore(backup: impl AsRef<Path>, destination: impl AsRef<Path>) -> Result<RestoreReport> {
    let backup = backup.as_ref();
    let destination = destination.as_ref();
    ensure_absent(destination, "restore destination")?;
    let image = decode_backup(&read_backup(backup)?)?;
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let temporary = reserve_temporary_file(parent, "vdb-restore")?;
    let mut guard = TemporaryPath::new(temporary.clone());
    RedbEngine::restore_image(&temporary, &image)?;
    let store = Store::open(&temporary)?;
    let status = store.status()?;
    if !status.verification.valid {
        return Err(corruption(
            status
                .verification
                .error
                .unwrap_or_else(|| "restored database verification failed".into()),
        ));
    }
    let report = RestoreReport {
        path: destination.to_path_buf(),
        database_id: status.metadata.database_id.clone(),
        verified: true,
        mutations: status.verification.signed_mutations_verified,
        replication_events: status.verification.replication_events_verified,
    };
    drop(store);
    install_noreplace(&temporary, destination)?;
    guard.disarm();
    sync_parent(destination)?;
    tracing::info!(operation = "restore", database_id = %report.database_id, "backup restored and verified");
    Ok(report)
}

pub fn verify_restored(path: impl AsRef<Path>) -> Result<RestoreReport> {
    let path = path.as_ref();
    let store = Store::open(path)?;
    let status = store.status()?;
    Ok(RestoreReport {
        path: path.to_path_buf(),
        database_id: status.metadata.database_id,
        verified: status.verification.valid,
        mutations: status.verification.signed_mutations_verified,
        replication_events: status.verification.replication_events_verified,
    })
}

pub fn compact(path: impl AsRef<Path>) -> Result<CompactionReport> {
    let path = path.as_ref();
    let before = fs::metadata(path).map_err(storage_error)?.len();
    let verified_before = Store::open(path)?.verify()?.valid;
    if !verified_before {
        return Err(corruption(
            "refusing to compact a database that fails verification",
        ));
    }
    let mut database = Database::open(path).map_err(storage_error)?;
    let mut passes = 0_u32;
    while database.compact().map_err(storage_error)? {
        passes = passes.saturating_add(1);
    }
    drop(database);
    let verified_after = Store::open(path)?.verify()?.valid;
    if !verified_after {
        return Err(corruption("database failed verification after compaction"));
    }
    let after = fs::metadata(path).map_err(storage_error)?.len();
    tracing::info!(
        operation = "compact",
        bytes_before = before,
        bytes_after = after,
        passes,
        "database compacted and verified"
    );
    Ok(CompactionReport {
        path: path.to_path_buf(),
        bytes_before: before,
        bytes_after: after,
        passes,
        verified_before,
        verified_after,
    })
}

fn crypto_statistics(
    report: &VerifyReport,
    checkpoint: &StateCheckpoint,
    replication: &ReplicationHealth,
    storage: &StorageStatistics,
) -> CryptographicStatistics {
    CryptographicStatistics {
        valid: report.valid,
        signed_mutations_verified: report.mutations,
        replication_events_verified: storage.replication_events,
        state_leaves_verified: checkpoint.leaf_count,
        history_head: report.head.clone(),
        state_root: checkpoint.state_root.clone(),
        replication_root: replication.checkpoint.event_root.clone(),
        error: report.error.clone(),
    }
}

fn replication_health(store: &Store) -> Result<ReplicationHealth> {
    let events = store.replication_events()?;
    let state = Replica::new(store.clone()).state()?;
    let sparse_gaps = state
        .replicas
        .values()
        .map(|progress| progress.sparse.len() as u64)
        .sum();
    let pending_events = events
        .iter()
        .filter(|event| {
            event.context.iter().any(|(replica, counter)| {
                state.replicas.get(replica).map_or(0, |p| p.contiguous) < *counter
            })
        })
        .count() as u64;
    let mut documents: BTreeMap<(&str, &str), Vec<&ReplicationEvent>> = BTreeMap::new();
    for event in &events {
        let ready = event.context.iter().all(|(replica, counter)| {
            state
                .replicas
                .get(replica)
                .map_or(0, |progress| progress.contiguous)
                >= *counter
        });
        if ready {
            documents
                .entry((&event.collection, &event.id))
                .or_default()
                .push(event);
        }
    }
    let conflicted_documents = documents
        .values()
        .filter(|events| {
            let heads = events
                .iter()
                .filter(|candidate| {
                    !events.iter().any(|other| {
                        other.event_id != candidate.event_id
                            && other
                                .context
                                .get(&candidate.replica_id)
                                .copied()
                                .unwrap_or(0)
                                >= candidate.counter
                    })
                })
                .count();
            heads > 1
        })
        .count() as u64;
    Ok(ReplicationHealth {
        replicas: state.replicas.len(),
        events: events.len() as u64,
        pending_events,
        sparse_gaps,
        conflicted_documents,
        checkpoint: state.checkpoint,
    })
}

fn encode_backup(image: &BackupImage) -> Vec<u8> {
    let mut encoder = Encoder::new(BACKUP_DOMAIN);
    encoder.u32(DATABASE_FORMAT_VERSION);
    encoder.u64(image.tables.len() as u64);
    for table in &image.tables {
        encoder.u8(table.id);
        encoder.u64(table.rows.len() as u64);
        for (key, value) in &table.rows {
            encoder.bytes(key);
            encoder.bytes(value);
        }
    }
    let mut bytes = encoder.finish();
    bytes.extend_from_slice(blake3::hash(&bytes).as_bytes());
    bytes
}

fn decode_backup(bytes: &[u8]) -> Result<BackupImage> {
    if bytes.len() < 32 {
        return Err(corruption("backup is truncated"));
    }
    let (body, checksum) = bytes.split_at(bytes.len() - 32);
    if blake3::hash(body).as_bytes() != checksum {
        return Err(corruption("backup checksum mismatch"));
    }
    let mut decoder = Decoder::new(body, BACKUP_DOMAIN)?;
    let version = decoder.u32()?;
    if version != DATABASE_FORMAT_VERSION {
        return Err(StoreError::UnsupportedFormat {
            found: version,
            supported: DATABASE_FORMAT_VERSION,
        });
    }
    let count = usize::try_from(decoder.u64()?).map_err(corruption)?;
    if count == 0 || count > MAX_TABLES {
        return Err(corruption("invalid backup table count"));
    }
    let mut ids = BTreeSet::new();
    let mut tables = Vec::with_capacity(count);
    let mut total_rows = 0_usize;
    for _ in 0..count {
        let id = decoder.u8()?;
        if !ids.insert(id) {
            return Err(corruption("duplicate backup table"));
        }
        let rows_count = usize::try_from(decoder.u64()?).map_err(corruption)?;
        total_rows = total_rows
            .checked_add(rows_count)
            .ok_or_else(|| corruption("backup row count overflow"))?;
        if total_rows > MAX_ROWS {
            return Err(corruption("backup row limit exceeded"));
        }
        // Every row needs at least two encoded u64 lengths. Bind capacity to
        // bytes actually remaining rather than trusting an attacker header.
        if rows_count > decoder.remaining() / 16 {
            return Err(corruption("backup row count exceeds remaining data"));
        }
        let mut rows = Vec::with_capacity(rows_count);
        for _ in 0..rows_count {
            rows.push((
                decoder.bytes(MAX_FIELD)?.to_vec(),
                decoder.bytes(MAX_FIELD)?.to_vec(),
            ));
        }
        tables.push(BackupTable { id, rows });
    }
    decoder.finish()?;
    if ids != (1_u8..=10).collect() {
        return Err(corruption("backup is missing required tables"));
    }
    Ok(BackupImage { tables })
}

fn write_new_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temporary = temporary_path(parent, "vdb-backup")?;
    let mut guard = TemporaryPath::new(temporary.clone());
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(storage_error)?;
    file.write_all(bytes).map_err(storage_error)?;
    file.sync_all().map_err(storage_error)?;
    drop(file);
    install_noreplace(&temporary, path)?;
    guard.disarm();
    sync_parent(path)
}

fn temporary_path(parent: &Path, prefix: &str) -> Result<PathBuf> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(storage_error)?;
    Ok(parent.join(format!(".{prefix}-{}.tmp", hex::encode(random))))
}
fn reserve_temporary_file(parent: &Path, prefix: &str) -> Result<PathBuf> {
    for _ in 0..16 {
        let path = temporary_path(parent, prefix)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                file.sync_all().map_err(storage_error)?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(storage_error(error)),
        }
    }
    Err(StoreError::Storage(
        "could not reserve a unique temporary database path".into(),
    ))
}
fn ensure_absent(path: &Path, what: &str) -> Result<()> {
    if path.exists() {
        Err(StoreError::InvalidInput(format!("{what} already exists")))
    } else {
        Ok(())
    }
}
fn read_backup(path: &Path) -> Result<Vec<u8>> {
    let size = fs::metadata(path).map_err(storage_error)?.len();
    if size > MAX_BACKUP_BYTES {
        return Err(StoreError::InvalidInput(format!(
            "backup exceeds the {MAX_BACKUP_BYTES}-byte in-memory archive limit"
        )));
    }
    fs::read(path).map_err(storage_error)
}

/// Atomically creates the destination name without ever replacing an entry
/// created after the caller's advisory absence check. The temporary file and
/// destination are in the same directory, so a hard link is an atomic
/// no-clobber promotion; removing the temporary name leaves the verified inode.
fn install_noreplace(temporary: &Path, destination: &Path) -> Result<()> {
    fs::hard_link(temporary, destination).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            StoreError::InvalidInput("destination was created concurrently".into())
        } else {
            storage_error(error)
        }
    })?;
    fs::remove_file(temporary).map_err(storage_error)
}
fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(storage_error)?;
    }
    Ok(())
}
fn storage_error(error: impl std::fmt::Display) -> StoreError {
    StoreError::Storage(error.to_string())
}

struct TemporaryPath {
    path: PathBuf,
    armed: bool,
}
impl TemporaryPath {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for TemporaryPath {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, thread};

    use tempfile::tempdir;

    use crate::crypto::{DatabaseKey, encrypt_document};

    fn put(store: &Store, id: &str, version: u64) -> Result<()> {
        let database_id = store.metadata()?.database_id;
        let key =
            DatabaseKey::from_database_secret(&database_id, [7_u8; 32]).map_err(storage_error)?;
        let document = encrypt_document(
            &key,
            &database_id,
            "operations",
            id,
            version,
            br#"{"protected":true}"#,
        )
        .map_err(storage_error)?;
        store.put(&document)?;
        Ok(())
    }

    #[test]
    fn backup_restore_and_status_preserve_verified_state() -> Result<()> {
        let directory = tempdir().map_err(storage_error)?;
        let database = directory.path().join("source.vdb");
        let backup = directory.path().join("source.vdbbak");
        let restored = directory.path().join("restored.vdb");
        let store = Store::open(&database)?;
        put(&store, "one", 1)?;
        put(&store, "two", 1)?;
        store.delete(
            "operations",
            "two",
            2,
            crate::model::VersionPrecondition::IfVersion(1),
        )?;
        let expected_checkpoint = store.checkpoint()?;
        let expected_metadata = store.metadata()?;
        let report = store.backup(&backup)?;
        assert_eq!(report.database_id, expected_metadata.database_id);
        assert_eq!(
            verify_backup(&backup)?.state_root,
            expected_checkpoint.state_root
        );
        drop(store);

        let restored_report = restore(&backup, &restored)?;
        assert!(restored_report.verified);
        let reopened = Store::open(&restored)?;
        assert_eq!(reopened.metadata()?, expected_metadata);
        assert_eq!(reopened.checkpoint()?, expected_checkpoint);
        assert!(reopened.status()?.verification.valid);
        assert_eq!(reopened.storage_statistics()?.tombstones, 1);
        Ok(())
    }

    #[test]
    fn corrupt_or_interrupted_backup_never_promotes_restore() -> Result<()> {
        let directory = tempdir().map_err(storage_error)?;
        let database = directory.path().join("source.vdb");
        let backup = directory.path().join("source.vdbbak");
        let corrupted = directory.path().join("corrupted.vdbbak");
        let target = directory.path().join("target.vdb");
        let store = Store::open(&database)?;
        put(&store, "one", 1)?;
        store.backup(&backup)?;
        let mut bytes = fs::read(&backup).map_err(storage_error)?;
        bytes.truncate(bytes.len() / 2);
        fs::write(&corrupted, bytes).map_err(storage_error)?;
        assert!(matches!(
            verify_backup(&corrupted),
            Err(StoreError::Corruption(_))
        ));
        assert!(matches!(
            restore(&corrupted, &target),
            Err(StoreError::Corruption(_))
        ));
        assert!(!target.exists());
        Ok(())
    }

    #[test]
    fn live_backup_is_consistent_and_offline_compaction_preserves_integrity() -> Result<()> {
        let directory = tempdir().map_err(storage_error)?;
        let database = directory.path().join("source.vdb");
        let backup = directory.path().join("concurrent.vdbbak");
        let restored = directory.path().join("restored.vdb");
        let store = Arc::new(Store::open(&database)?);
        for version in 1..=12 {
            put(&store, &format!("initial-{version}"), 1)?;
        }
        let writer = {
            let store = Arc::clone(&store);
            thread::spawn(move || -> Result<()> {
                for version in 1..=24 {
                    put(&store, &format!("concurrent-{version}"), 1)?;
                }
                Ok(())
            })
        };
        store.backup(&backup)?;
        writer
            .join()
            .map_err(|_| StoreError::Storage("writer thread panicked".into()))??;
        restore(&backup, &restored)?;
        assert!(Store::open(&restored)?.verify()?.valid);
        drop(store);
        let report = compact(&database)?;
        assert!(report.verified_before && report.verified_after);
        assert!(Store::open(&database)?.verify()?.valid);
        Ok(())
    }

    #[test]
    fn malicious_row_count_is_rejected_without_large_reservation() -> Result<()> {
        let mut encoder = Encoder::new(BACKUP_DOMAIN);
        encoder.u32(DATABASE_FORMAT_VERSION);
        encoder.u64(10);
        encoder.u8(1);
        encoder.u64(MAX_ROWS as u64);
        let mut bytes = encoder.finish();
        bytes.extend_from_slice(blake3::hash(&bytes).as_bytes());
        assert!(decode_backup(&bytes).is_err());
        Ok(())
    }

    #[test]
    fn no_clobber_promotion_rejects_concurrently_created_destination() -> Result<()> {
        let directory = tempdir().map_err(storage_error)?;
        let temporary = directory.path().join("temporary");
        let destination = directory.path().join("destination");
        fs::write(&temporary, b"verified").map_err(storage_error)?;
        fs::write(&destination, b"attacker").map_err(storage_error)?;
        assert!(matches!(
            install_noreplace(&temporary, &destination),
            Err(StoreError::InvalidInput(_))
        ));
        assert_eq!(fs::read(&destination).map_err(storage_error)?, b"attacker");
        assert_eq!(fs::read(&temporary).map_err(storage_error)?, b"verified");
        Ok(())
    }
}
