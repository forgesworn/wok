//! `wok-roomd`: a keeper-controlled room relay on Wok.
//!
//! One process serves several rooms, each in a database of its own. It holds
//! no list of members in a file: a supervisor on the same machine sends the
//! whole list of rooms and admitted devices over a private Unix socket, and
//! renews it every few seconds. Without a current list every door refuses.
//!
//! - [`relay`] is the core: rooms, device grants, the two doors, intake,
//!   queries and purge. It opens no socket.
//! - [`host`] is the process around it: the loopback WebSocket listener, the
//!   control socket, the command line.
//!
//! The control channel is a Unix socket, so this crate is empty on other
//! systems and its binary only says so.
#![cfg(unix)]

pub mod host;
pub mod relay;
