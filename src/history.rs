use std::collections::HashSet;

use crate::{
    error::{Result, corruption},
    model::{MutationRecord, StateCheckpoint},
};

pub fn verify_mutation(record: &MutationRecord) -> Result<()> {
    crate::storage::redb::verify_mutation_record(record)
}

/// Verifies an ordered history. An externally retained checkpoint makes truncation detectable.
pub fn verify_history(
    records: &[MutationRecord],
    database_id: &str,
    expected_checkpoint: Option<&StateCheckpoint>,
) -> Result<()> {
    let mut previous = "GENESIS".to_owned();
    let mut ids = HashSet::new();
    for (offset, record) in records.iter().enumerate() {
        let expected_sequence = offset as u64 + 1;
        if record.sequence != expected_sequence || record.database_id != database_id {
            return Err(corruption("history sequence or database identity mismatch"));
        }
        if record.previous_mutation_hash != previous {
            return Err(corruption("history predecessor mismatch"));
        }
        verify_mutation(record)?;
        if !ids.insert(&record.mutation_id) {
            return Err(corruption("duplicate or replayed mutation id"));
        }
        previous.clone_from(&record.mutation_hash);
    }
    if let Some(checkpoint) = expected_checkpoint
        && (checkpoint.database_id != database_id
            || checkpoint.sequence != records.len() as u64
            || checkpoint.history_head != previous)
    {
        return Err(corruption("history does not match retained checkpoint"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::{
        crypto::{DatabaseKey, encrypt_document},
        model::MutationKind,
        store::Store,
    };

    fn history_fixture() -> (
        tempfile::TempDir,
        Store,
        Vec<MutationRecord>,
        StateCheckpoint,
    ) {
        let directory = tempdir().expect("temporary directory");
        let store = Store::open(directory.path().join("history.vdb")).expect("open store");
        let database_id = store.metadata().expect("metadata").database_id;
        let key = DatabaseKey::from_database_secret(&database_id, [7_u8; 32]).expect("key");
        for (id, version) in [("alice", 1), ("bob", 1)] {
            let document = encrypt_document(&key, &database_id, "users", id, version, b"{}")
                .expect("encrypt document");
            store.put(&document).expect("write document");
        }
        let records = vec![
            store
                .mutation(1)
                .expect("read mutation")
                .expect("mutation one"),
            store
                .mutation(2)
                .expect("read mutation")
                .expect("mutation two"),
        ];
        let checkpoint = store.checkpoint().expect("checkpoint");
        (directory, store, records, checkpoint)
    }

    #[test]
    fn rejects_altered_payload_mutation_predecessor_signature_and_identity() {
        let (_directory, _store, records, _) = history_fixture();
        let mut altered_payload = records[0].clone();
        altered_payload.payload_hash = Some("00".repeat(32));
        assert!(verify_mutation(&altered_payload).is_err());

        let mut altered_mutation = records[0].clone();
        altered_mutation.kind = MutationKind::Delete;
        assert!(verify_mutation(&altered_mutation).is_err());

        let mut altered_predecessor = records[1].clone();
        altered_predecessor.previous_mutation_hash = "00".repeat(32);
        assert!(verify_mutation(&altered_predecessor).is_err());

        let mut invalid_signature = records[0].clone();
        invalid_signature.signature = "00".repeat(64);
        assert!(verify_mutation(&invalid_signature).is_err());

        let mut wrong_identity = records[0].clone();
        wrong_identity.writer_public_key = records[1].writer_public_key.clone();
        if wrong_identity.writer_public_key == records[0].writer_public_key {
            wrong_identity.writer_public_key = "00".repeat(32);
        }
        assert!(verify_mutation(&wrong_identity).is_err());
    }

    #[test]
    fn rejects_truncated_reordered_and_replayed_history() {
        let (_directory, _store, records, checkpoint) = history_fixture();
        let database_id = checkpoint.database_id.as_str();
        verify_history(&records, database_id, Some(&checkpoint)).expect("valid history");
        assert!(verify_history(&records[..1], database_id, Some(&checkpoint)).is_err());
        assert!(
            verify_history(&[records[1].clone(), records[0].clone()], database_id, None).is_err()
        );
        assert!(
            verify_history(&[records[0].clone(), records[0].clone()], database_id, None).is_err()
        );
    }
}
