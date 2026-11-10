# wok

Wok is a Nostr relay core in Rust, moved out of the Bothy node. It is a
library: it never opens a port, runs a daemon, authenticates clients or
decides grants. Those belong to the application around it.

## Build & Test

| Command | Purpose |
|---------|---------|
| `cargo build` | Compile the workspace |
| `cargo test --locked` | Run the test suite |
| `cargo fmt --all -- --check` | Check formatting |
| `cargo clippy --all-targets -- -D warnings` | Lint, warnings deny |
| `scripts/check` | The full local gate (what CI runs) |

The pinned toolchain is 1.94.1 (`rust-toolchain.toml`). The event relay tests
open many sockets and files at once; raise the open-file limit
(`ulimit -n 10240`) where the default is low.

## Structure

```
crates/
  wok-store/
    src/lib.rs     - crate docs and re-exports
    src/store.rs   - EventStore, SqliteEventStore, schema and migration
    src/writer.rs  - EventWriter: one writer thread, group commit
    src/live.rs    - LiveFanout: byte-bounded live delivery
```

## Conventions

- British English in prose and comments.
- The store never infers a partition from an event's tags; the caller
  supplies it.
- `single_d_value`, `event_frame`, `LiveFanout` and `PreparedPut::verified`
  are public only because Bothy's relay engine still uses them from outside
  this crate. They become crate-private again when the engine moves here.
  `PreparedPut::verified` skips the signature check: never call it with an
  event whose signature has not just been verified.

## Common Pitfalls

- The on-disk format is shared with existing Bothy stores. Any schema change
  needs a forward migration, a test that opens the previous version, and a
  `SCHEMA_VERSION` bump. Never lower `SCHEMA_VERSION` to open a newer store.
- An older build must keep refusing a newer schema (`NewerSchema`); do not
  relax that to make a rollback easier.
