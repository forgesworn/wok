# Changelog

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
