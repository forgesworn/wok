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
relay that its operator runs for one group, with a removal command for that
operator. Whoever runs an instance operates it; see
[`crates/wokd/README.md`](crates/wokd/README.md).

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

The store has been benchmarked, including against another relay
implementation, but only inside Bothy and with Bothy's relay on top. Those results have not yet been reproduced from
this repository, and no performance claim is made for Wok itself until they
are.

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
