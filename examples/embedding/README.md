# Embedding Wok

Use `wok-store` to store and query signed Nostr events in-process. Add
`wok-ws` when the application needs to serve them over WebSockets. These
examples use checkout paths so CI exercises proposed changes and resolves
them in a separate Cargo workspace. In another project, pin both
dependencies to the same Wok tag, as Bothy does.

```toml
[dependencies]
wok-store = { git = "https://github.com/forgesworn/wok", tag = "v0.8.0" }
wok-ws = { git = "https://github.com/forgesworn/wok", tag = "v0.8.0" }
```

## Storage only

```sh
cargo run --manifest-path examples/embedding/Cargo.toml --example store
```

The [storage example](examples/store.rs) stores a signed event in a temporary
database, reopens it and reads the event from the caller-selected partition.
For a persistent store, pick an application-owned path and a storage ceiling.
On a phone, pass `StoreOptions::phone()` to
`SqliteEventStore::open_with_options`. The profile budgets 1.75 MiB for page
caches per store. It groups quiet-period WAL cleanup across writes made
within 30 seconds and checkpoints when it reaches the size threshold or
the store closes.

Call the synchronous store API on a thread that may block. Async hosts can
use `spawn_blocking` and bound how many calls reach the blocking pool.

## Sheltered WebSocket relay

```sh
cargo run --manifest-path examples/embedding/Cargo.toml \
  --features websocket --example sheltered
```

The [Axum example](examples/sheltered.rs) merges `/events` into the host's
router, binds an ephemeral loopback port, authenticates with a throwaway
keeper key and publishes an event. The host supplies `Admission` from trusted
connection information and `KeeperAccess` from its own membership state.
Use `Door::with_history_limits` to bound simultaneous catch-up replies.
The example allows two sheltered history replies at a time.
Every admitted socket still authenticates with NIP-42. The canonical URL
must be the `/events` URL clients name in AUTH, including when a TLS proxy
terminates their connection.

Drive expiry on a host-owned task. Signal `Door::shutdown` while the host
runtime is still running so upgraded sockets can close. In a long-running
host, wait for connection tasks to release their admission guards before
flushing pending writes off the async worker threads and dropping the relay.
