# Changelog

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
