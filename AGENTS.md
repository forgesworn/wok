# wok

Wok is a Nostr relay core in Rust, moved out of the Bothy node. Its library
crates (`wok-store`, `wok-ws`) never open a port or run a daemon, and they
hold no policy: the application around them says who may connect, who its
keepers and guests are, and which events carry authority, and it binds the
listeners. `wokd` is the main program: a members-only relay its operator runs
for one group, with listed keepers and their explicitly signed, room-scoped
guests. `wok-roomd` is a second, for a supervised node: a database for each
room, an allowlist pushed over a local socket, and an ask door for keys not
yet admitted. Keep every read and write authenticated and scoped, with no
open mode.

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
  wok-roomd/       - Unix only; uses wok-store, not wok-ws
    src/relay.rs   - RoomRelay: rooms, device grants, the room and ask doors, purge
    src/host.rs    - the loopback listener, the control socket, the command line
    README.md      - the control protocol and what an unadmitted key can do
  wokd/
    src/lib.rs     - Config, Members, PerAddress, run/serve, reload, remove
    src/authority.rs - persistent signed room grants and guest scopes
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
- The workspace's `[profile.release]` reaches the workspace's own programs
  only (`wokd`, `wok-roomd`, `wok-bench`). An application that links the
  libraries builds them under its own profile.
- `wokd`'s manifest turns on secp256k1's `lowmemory` (small tables, slower
  signature checks). Cargo unifies features across one build, so a build
  that includes `wokd` (`--workspace`, `-p wokd -p wok-bench`) gives the
  small tables to every package in it. Build `wok-bench` on its own when its
  signature or ingest figures are to be compared.

## Common Pitfalls

- The on-disk format is shared with existing Bothy stores. Any schema change
  needs a forward migration, a test that opens the previous version, and a
  `SCHEMA_VERSION` bump. Never lower `SCHEMA_VERSION` to open a newer store.
- An older build must keep refusing a newer schema (`NewerSchema`); do not
  relax that to make a rollback easier.
- A batch keeps its savepoint journals in memory only when every event in it
  passes `PreparedPut::journal_fits_memory` and `replaces_little`. A write
  that can change any number of pages (a deletion, an expiry sweep, a
  removal, a purge, the replacement of a version with many tags) must keep
  SQLite's default journal, which moves to a temporary file as it grows.
- The store's connections plan from the statement alone (`stable_plans`), so
  SQLite never sees a bound value when it chooses a plan: not a `LIMIT ?`,
  not a partition key. Steer a plan with the statement's shape or
  `INDEXED BY`. `stable_plans_are_the_plans_bound_values_chose` compares the
  plans of the query shapes and of every statement the connections keep
  prepared; run a new query shape through it.
- One query's shape is chosen from stored data: for a filter that names
  `authors` and a tag, `SqliteEventStore::drive` counts the driving tag's
  rows and picks the table that drives. That choice is part of the SQL
  cache's key (`query_shape`). Anything else that changes the SQL for one
  filter shape must go into the key too, or the first query of a shape
  fixes the SQL for every later one; and every route must select what
  `Drive::Events` selects, which the oracle tests compare.
- The production image is distroless: no shell, so nothing can be `RUN` in
  its final stage or `docker exec`ed in a container. What that stage needs
  is made under `/runtime` in the build stage and laid over the base in one
  `COPY`, which keeps each entry's owner and mode; a `COPY --chown` of
  `/data` alone loses its 0700. Wide writes still need a temporary
  directory the `wok` user can write to (`/var/tmp`, which the base has).
