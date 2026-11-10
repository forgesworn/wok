# Wok

Wok is a Nostr relay core in Rust. It is being moved out of the Bothy node,
where it was built as Bothy's event shelter, so that other applications can
run the same relay.

Version 0.1.0 is the first step: the storage half, as the `wok-store` crate.

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

Wok is a library. It opens no port, authenticates nobody and holds no grant
model. The NIP-01/NIP-42 session engine and the WebSocket server are still
inside Bothy and move here in later releases.

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
