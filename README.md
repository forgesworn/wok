# Wok

Wok is a Nostr relay core in Rust. It is being moved out of the Bothy node,
where it was built as Bothy's event shelter, so that other applications can
run the same relay.

The `wok-store` crate holds the storage half and, unreleased on `main`, the
session engine that serves clients from it.

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

Wok is a library. It opens no port and holds no policy of its own: the
application says who its keepers are (`KeeperAccess`), which guests may read
and write which kinds in which rooms (`GuestAuthority`), and which events carry
authority to install rather than content to store (`AuthorityEvents`), and it
carries the frames over its own transport. Every operation asks again, so a
withdrawn key or scope stops working at once. The WebSocket server is still
inside Bothy and moves here in a later release.

## Storage compatibility

The store is at schema version 4, the format Bothy's event store writes
today, so an existing Bothy event database opens unchanged. An older build refuses a newer
schema rather than downgrading it in place; going back is an export with the
newer build and an import with the older one.

## Performance

The store has been benchmarked against strfry 1.1.2, but only inside Bothy
and with Bothy's relay on top. Those results have not yet been reproduced from
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
