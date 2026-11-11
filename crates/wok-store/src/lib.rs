//! Wok's durable Nostr event store and relay session engine.
//!
//! The store is a SQLite event store split into [`Visibility`] partitions,
//! one writer thread with group commit ([`writer`]), and live fan-out to
//! attached connections with queues bounded by bytes ([`live`]). The store
//! never infers a partition from an event's tags: the caller names it.
//!
//! [`relay`] is the NIP-01, NIP-42, NIP-45 and NIP-77 session engine over
//! that store: one [`relay::RelaySession`] per connection, which turns client
//! frames into replies. It opens no port and holds no policy of its own. The
//! application supplies who the keepers are, who may be a guest and which
//! events carry authority rather than content, through the traits in
//! [`relay`], and a transport that carries the frames.
//!
//! The store's interface is synchronous. Async transports call it through
//! `spawn_blocking`.

mod store;

pub mod live;
pub mod relay;
pub mod writer;

pub use store::*;
