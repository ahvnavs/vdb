# Backup and recovery

Status: implemented logical backup format 1 for database format 5.

## Consistency model

`Store::backup` opens one redb read transaction and exports every private VDB table from that single MVCC snapshot. Concurrent commits are either wholly before or wholly after the captured state; a backup cannot contain half of a transaction. Backup files never contain encryption keys or plaintext protected document contents, but they do contain ciphertext and all server-visible metadata described in the threat model.

The backup container is canonical binary data beginning with `vdb.backup.v1\0`. It stores database format version, ten required logical table sections, and length-prefixed raw keys and values. A raw 32-byte BLAKE3 checksum covers the complete body. Decoders reject wrong formats, missing/duplicate/unknown tables, excessive row/field counts, truncation, checksum failure, and trailing bytes.

Backup creation writes a randomly named mode-0600 temporary file in the destination directory, calls `fsync`, atomically links it to the requested unused destination without replacement, removes the temporary name, syncs the parent directory, then performs a full restore-and-verify cycle. Existing or concurrently created destinations are never overwritten.

## Commands

```text
vdb backup --db app.vdb --output app.vdbbak
vdb backup-verify --backup app.vdbbak
vdb snapshot --db app.vdb --output snapshot.vdbbak
vdb restore --backup app.vdbbak --db restored.vdb
vdb restore-verify --db restored.vdb
vdb verify --db restored.vdb
```

`snapshot` is an operational alias for a consistent verified backup. It is not a persistent redb savepoint and does not block later writes.

## Restore and promotion

Restore requires an absent destination. VDB decodes the archive into a random temporary database in the destination directory, imports all logical rows in one transaction, opens it through the normal format checks, verifies signed mutation history, current state, indexes, replication events/dot indexes, and checkpoints, then atomically links it into place without replacement and syncs the parent directory. A decode, write, crash, verification failure, or concurrently created destination cannot promote or overwrite the temporary database. Leftover `.vdb-restore-*.tmp` files are incomplete and may be removed only after confirming no restore process is active.

After restore, compare the reported database ID, mutation count, state root, replication event count, and replication root with the verified backup report or an externally retained checkpoint. VDB cannot detect restoration of a self-consistent old backup without that external reference.

## Corruption and recovery procedure

1. Stop writers and preserve the original database and relevant logs. Do not compact or modify the only copy.
2. Run `vdb verify --db damaged.vdb` and `vdb status --db damaged.vdb`. Record the exact typed error or invalid verification report.
3. Run `vdb backup-verify` against candidate backups. Never restore an unverified archive over an existing database.
4. Restore to a new path, run `restore-verify`, then compare external checkpoints.
5. Switch the application to the restored path only after verification and application-level checks.

redb automatically chooses a valid durable commit after ordinary process interruption. VDB then validates its format header and records on open/read and performs full semantic verification when requested. VDB does not repair cryptographic or canonical-record corruption in place; recovery uses a verified backup or trusted replica.

## Limitations

The current logical archive is materialized in memory during creation and verification; archives larger than 512 MiB are rejected before reading. It has no compression or encryption layer and cannot be streamed. Protect backup files with filesystem access controls or an external reviewed encryption system. There is no incremental backup, retention scheduler, remote object-store integration, key escrow, migration, point-in-time recovery, or automatic replica restore.
