# Changelog

## Unreleased

- `wok-bench` gains a `socket` scenario: acknowledged writes through
  `wok-ws`'s two doors over real WebSocket connections, beside the same
  events driven straight at the session engine in the same run. Each cell
  starts its own store, relay, door and server runtime; clients authenticate
  with NIP-42 and every event is signed and verified. Server worker and
  blocking threads, the doors' work permits and `TCP_NODELAY` can be varied
  per run, and each door's refusals are checked before anything is measured.
- The libraries are unchanged and still open no port. The unpublished bench
  binary binds `127.0.0.1` on an ephemeral port for this scenario, refuses
  any other address, and a default `all` run now does so. Its sheltered door
  uses an admit-everything `Admission` that lives in `wok-bench` only and is
  not for applications.

## 0.4.0 - 2026-11-11

- Add `wok-ws`, the relay's WebSocket doors, moved from Bothy's node
  repository. A `Door` holds one relay's connection and work budgets and
  hands out unbound axum routers: a public one, which also serves the NIP-11
  relay information document, and a sheltered one. It opens no port.
- The sheltered router is built only with an `Admission`, which decides from
  the request's extensions whether a connection may open and holds what it
  returns (a per-peer permit, say) for the connection's life. There is no
  default, and a request it cannot place is refused. NIP-42 is still required
  on every connection it admits.
- The deadlines (`Timings`), the budgets (32 connections, 24 of them public;
  `WORK_PERMITS` of 2, 1 of them public, adjustable with
  `with_connection_limits` and `with_work_limits`), the buffer sizes, the
  close codes and reasons, the HTTP statuses and the NIP-11 document are as
  Bothy had them, including a close reason that still says "circle authority
  expired".
- New dependencies, in `wok-ws` only: `axum` 0.8 with `ws`, and
  `futures-util` 0.3. `wok-store` gains none.
- `wok-bench` gains an `engine` scenario: the relay session engine driven
  frame by frame with no network, beside the bare writer and the raw store in
  the same run. It gives acknowledged writes by session count and in-flight
  window, REQ and COUNT through a session against the same filters on the
  store, and what a subscribed session holds in Rust allocations. Every event
  is signed and the engine checks each signature. A default run now includes
  it, and the whole process runs under a counting allocator, which each
  result's header records.
- `wok-store` is unchanged since 0.3.0, and so is schema 4.

## 0.3.0 - 2026-11-11

- Add the relay session engine as `wok_store::relay`, moved from Bothy's node
  repository: NIP-01 sessions with NIP-42 authentication, NIP-45 counts and
  NIP-77 reconciliation over the store, on a public door and a sheltered one.
  Replies are word for word what Bothy sent, including two refusals that still
  say "circle grant".
- The engine holds no policy. `KeeperAccess` says who the keepers are,
  `GuestAuthority` gives guests room- and kind-scoped access to the sheltered
  partition, `AuthorityEvents` names the events a door installs instead of
  storing, and `AnnounceHook` sees each event announced live.
- Breaking: `single_d_value`, `event_frame` and the hidden
  `PreparedPut::verified`, public in 0.1.0 and 0.2.0 only for Bothy's copy of
  the engine, are crate-private again, so a caller outside the crate can no
  longer skip the signature check. Bothy no longer uses them. `LiveFanout`
  stays public, since `wok-bench` drives it directly.
- New dependencies: `negentropy` 0.5, `url` 2.5, `hex` 0.4, and `nostr`'s
  `os-rng` feature, from which each NIP-42 challenge is drawn.
- A filter that names several ids is answered from the id index, one seek for
  each id. SQLite used to walk the partition in time order for it, so the
  query took longer as the partition grew; a filter with one id was not
  affected. Answers and their order are unchanged.
- New unpublished workspace crate `wok-bench`: a store-level baseline
  benchmark of ingest, queries and live fan-out. Its figures hold later
  changes to "no slower" on one machine; they are not a comparison with any
  other relay.
- No schema change.

## 0.2.0 - 2026-11-10

- Move to `rusqlite` 0.41.1 and its bundled SQLite 3.54 for RUSTSEC-2026-0459
  (#1). The advisory is no longer ignored in `cargo audit`.
- `EventStoreError::Sqlite` carries `rusqlite::Error`, so this release is
  breaking: a consumer that also links `rusqlite` must move to 0.41 in the
  same change, since a build links only one bundled SQLite.
- The minimum supported Rust version is now 1.89, as `rusqlite` 0.41 requires.
- `rusqlite` 0.41 replaces a progress handler only through `&mut Connection`,
  which an open transaction does not give. Each connection now carries one
  handler from when it opens, and the store arms and disarms its query and
  expiry deadlines through it. A reader's deadline is disarmed when its query
  returns, where it used to stay set until the next query.
- Update locked tokio to 1.54.1 and faster-hex to 0.10.1 for
  RUSTSEC-2026-0386 and RUSTSEC-2026-0306.
- No schema change: schema 4 remains, and existing stores open as before.

## 0.1.0 - 2026-11-10

- First release: the event store, its group-commit writer and live fan-out,
  moved from Bothy's node repository at `9d75c2c` as the `wok-store` crate.
  Behaviour and the on-disk format (schema 4) are unchanged.
- Thread names are now `wok-event-writer`, `wok-wal-checkpoint` and
  `wok-warm`.
- `single_d_value`, `event_frame`, `LiveFanout` (with its methods) and the
  hidden `PreparedPut::verified` are public, for Bothy's relay engine until it
  moves into Wok.
- The writer counts a batch in `stats()` before it answers the batch's
  callers. In Bothy a caller could hold its answer while `stats()` still
  lacked its batch, which made one writer test fail on slow machines (#2).
- The truncate-race test's competing connection pauses between TRUNCATE
  checkpoints. Back to back, they could hold the write lock for the writer's
  whole busy timeout on a slow CI runner (#2).
- Known: the bundled SQLite 3.53.2 is affected by RUSTSEC-2026-0459 (#1),
  ignored in `cargo audit` until the joint move to `rusqlite` 0.41.
