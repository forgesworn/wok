# wok

Wok is a Nostr relay core in Rust, moved out of the Bothy node. Its library
crates (`wok-store`, `wok-ws`) never open a port or run a daemon, and they
hold no policy: the application around them says who may connect, who its
keepers and guests are, and which events carry authority, and it binds the
listeners. `wokd` is the one program: a members-only relay its operator runs
for one group. Keep it members-only, with no open mode.

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
    src/relay.rs   - EventRelay, RelaySession: the NIP-01/42/45/77 session
                     engine and the policy traits it asks
  wok-ws/
    src/lib.rs     - Door: the WebSocket doors, their budgets, Admission
  wok-bench/       - store-level baselines and remote-relay comparison (not published)
  wokd/
    src/lib.rs     - Config, Members, PerAddress, run/serve, reload, remove
    src/main.rs    - the wokd command line and its SIGHUP reload
    README.md      - what an operator runs and owes
```

## Conventions

- British English in prose and comments.
- The store never infers a partition from an event's tags; the caller
  supplies it.
- `PreparedPut::verified` skips the signature check, so it is crate-private:
  only the relay engine's own prepared frames, verified moments earlier, may
  use it. Keep it that way. `LiveFanout` is public because `wok-bench` drives
  it directly.
- `wok-ws` builds its sheltered router only with an `Admission`. Do not add a
  permissive default: a request the admission cannot place is refused.
- `wok-ws` carries no dependency only a daemon would need (configuration
  parsing, a command line), because applications link it into their own
  builds, mobile ones included.

## Common Pitfalls

- The on-disk format is shared with existing Bothy stores. Any schema change
  needs a forward migration, a test that opens the previous version, and a
  `SCHEMA_VERSION` bump. Never lower `SCHEMA_VERSION` to open a newer store.
- An older build must keep refusing a newer schema (`NewerSchema`); do not
  relax that to make a rollback easier.
