//! Wok's durable Nostr event store.
//!
//! This crate is the storage half of the Wok relay: a SQLite event store
//! split into [`Visibility`] partitions, one writer thread with group commit
//! ([`writer`]), and live fan-out to attached connections with queues bounded
//! by bytes ([`live`]). It has no network listener, no authentication and no
//! grant model. The relay above it decides which partition a caller may read
//! or write; this crate never infers that from an event's tags.
//!
//! The store's interface is synchronous. Async transports call it through
//! `spawn_blocking`.

mod store;

pub mod live;
pub mod writer;

pub use store::*;
