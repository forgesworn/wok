# Wok

Wok is a Nostr relay core in Rust. It is being moved out of the Bothy node,
where it was built as Bothy's event shelter, so that other applications can
run the same relay.

The `wok-store` crate holds the storage half and, since 0.3.0, the session
engine that serves clients from it.

- **Event store.** Nostr events in SQLite, split into a public and a sheltered
  partition. The caller chooses the partition; the store never infers it from
  an event's tags. Queries take ordinary NIP-01 filters, deletion follows
  NIP-09, and expired events are removed in bounded passes. Counts serve
  NIP-45.
- **Writer.** One writer thread with group commit. Connections prepare and
  verify events on their own threads; the writer stores whatever is queued in
  one transaction and only then answers each caller.
- **Live fan-out.** Committed events are delivered to attached connections,
  each with its own queue bounded by bytes. A reader that falls behind is
  dropped as lagged instead of holding memory for everyone.
- **Session engine** (`wok_store::relay`). One session per connection turns
  client frames into replies: NIP-01 `EVENT`, `REQ` and `CLOSE`, NIP-42
  `AUTH`, NIP-45 `COUNT` and NIP-77 reconciliation, each bounded per frame,
  filter, reply and minute. A public door serves anyone and takes only
  keeper-authored events of a short list of public kinds; a sheltered door
  serves authenticated keepers and guests.

The `wok-ws` crate, since 0.4.0, carries those frames over WebSockets.

- **Doors.** A `Door` holds one relay's connection and work budgets and hands
  out unbound axum routers: a public one, which also serves the NIP-11 relay
  information document, and a sheltered one, which serves that document only
  if asked to and then says every read and write needs NIP-42. Each
  connection's writes are
  pipelined to the writer and answered in order, live events follow their
  own `OK`, and a closing connection answers every frame it has read.
- **Admission.** The sheltered router is built only with an `Admission`,
  which decides from the request's extensions (an authenticated peer, a
  connecting address) whether a connection may open, and holds what it
  returns for the connection's life. A request it cannot place is refused.
  NIP-42 is still required on every connection it admits.

`wok-store` and `wok-ws` are libraries. They open no port and hold no
policy of their own: the application says who its keepers are
(`KeeperAccess`), which guests may read and write which kinds in which rooms
(`GuestAuthority`), which events carry authority to install rather than
content to store (`AuthorityEvents`) and who may connect to the sheltered
door (`Admission`), and it binds the listeners itself. Every operation asks
again, so a withdrawn key or scope stops working at once.

The `wokd` crate, since 0.5.0, is a program built on them: a members-only
relay that its operator runs for one group, with full-access keepers and their
signed, room-scoped guests, plus a removal command for that operator. Whoever
runs an instance operates it; see
[`crates/wokd/README.md`](crates/wokd/README.md).

The `wok-roomd` crate is a second program, built on the store alone: a room
relay for a node that hosts several rooms under a supervisor. Each room has a
database of its own. A supervisor on the same machine says, over a private
Unix socket, which devices are admitted and when a room is purged. An ask
door takes sealed requests for a room's inviter from keys that have not been
admitted. It runs on Unix-like systems only; see
[`crates/wok-roomd/README.md`](crates/wok-roomd/README.md).

## Embed Wok in a Rust application

The [embedding examples](examples/embedding/README.md) show how to use the
SQLite store on its own and how to add a sheltered relay to an existing Axum
application. CI builds and runs both from a separate Cargo workspace.

## Storage compatibility

The store is at schema version 5: version 4, the format Bothy's event store
writes today, with one more index. A version 4 store, an existing Bothy event
database included, opens and is upgraded at its first open with this build,
which builds the index; the store is marked version 5 only once the index is
there. After that, builds that know only version 4, current Bothy builds
among them, refuse it. An older build refuses a newer schema rather than
downgrading it in place; going back is an export with the newer build and an
import with the older one.

## Performance

The unpublished `wok-bench` tool times storage, in-process sessions and
WebSocket relays. Use `--profile phone` in its local scenarios to exercise
the mobile store settings.

For a relay comparison, seed both stores with the signed corpus from
`wok-bench relay export`. Run `wok-bench relay query --input corpus.jsonl
--url <relay-url> --set overlap` on each relay. The overlapping filters
return the same page as `--set authors_kinds`. Compare both the event
counts and `id_set_digest` before comparing times. For write load alongside
history, use `relay write --rate` with `--readers`, `--read-rate`,
`--read-set overlap` and the same corpus. Record the build, authentication
settings and transport for each run.

## Build and test

Rust 1.94.1 (pinned in `rust-toolchain.toml`).

```
cargo test --locked
```

`scripts/check` runs formatting, Clippy, the tests and the docs, as CI does.

## Support development

Wok is part of [ForgeSworn](https://github.com/forgesworn), maintained by
TheCryptoDonkey. Donations support development, testing and documentation.

- [GitHub Sponsors](https://github.com/sponsors/TheCryptoDonkey)
- [Ko-fi](https://ko-fi.com/brays)
- [ForgeSworn on Geyser](https://geyser.fund/project/forgesworn)
- Lightning: `profusemeat89@walletofsatoshi.com`

See [support and donation details](SUPPORT.md), including Nostr zaps.
Donations are optional and do not buy relay access or a service guarantee.

## Licence

MIT, copyright 2026 TheCryptoDonkey. See `LICENSE`.
