# Quickstart

This quickstart covers the implemented local encrypted database. Key files are
created without overwriting an existing file and with mode 0600 on Unix. They
are still raw secrets: keep them outside backups and source control and prefer
an external secret manager when one becomes supported.

```text
cargo build --release
target/release/vdb keygen --output app.key
printf '%s\n' '{"name":"Alice"}' > alice.json
target/release/vdb put --db app.vdb --key-file app.key users alice alice.json
target/release/vdb get --db app.vdb --key-file app.key users alice
target/release/vdb verify --db app.vdb
target/release/vdb status --db app.vdb
target/release/vdb backup --db app.vdb --output app.vdbbak
target/release/vdb backup-verify --backup app.vdbbak
target/release/vdb restore --backup app.vdbbak --db restored.vdb
target/release/vdb restore-verify --db restored.vdb
```

For the TLS service, generate a device identity with
`vdb writer-keygen --output device.json`, create the authorization JSON
described in `docs/protocol.md`, obtain a certificate valid for the bind name,
and run `vdb serve`. The server accepts already-encrypted envelopes and never
needs the content key. There is not yet a supported network client or network
replication command; use of the REST API requires canonical request signing.

