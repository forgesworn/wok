# wok-roomd

`wok-roomd` is a room relay built on Wok's event store. One instance serves
several rooms, each in a database of its own. It keeps no member list in a
file: a supervisor on the same machine tells it which rooms exist and which
devices are admitted, over a private Unix socket, and says so again every few
seconds. ForgeSworn publishes the software and runs no instance of it.
Whoever runs one operates it, and is responsible for it.

It is a different program from [`wokd`](../wokd/README.md). `wokd` reads its
members from a file and installs signed grants itself. This one is told its
whole allowlist by another process, purges a room when told to, and has a
door for people who have not been admitted yet. It uses Wok's store and not
its WebSocket doors or session engine.

It runs on Unix-like systems only, because the control channel is a Unix
socket. On anything else the binary says so and exits.

## What it does

- Every connection is sent a NIP-42 challenge and has ten seconds to answer.
  The AUTH event is an ordinary kind 22242 with two more signed tags: `room`,
  a room id, and `mode`, which is `room` or `ask`. That choice holds for the
  life of the connection. A refused `room` login is refused; it never
  becomes an `ask` login.
- **The room door** is for admitted devices. The key that signs AUTH must
  hold a current grant for that room, with `read` to sign in and query and
  `write` to publish. What it publishes may be signed by any key, because
  rooms use rotating and one-time authors: the connection's room decides
  where an event is stored, and nothing in the event can choose another
  room.
- **The ask door** is for a key that has not been admitted. See the next
  section for exactly what it allows.
- Every event written must carry one NIP-40 `expiration`, still in the
  future: no later than the room's end if it has one, and otherwise at most
  30 days after the event was created. Ephemeral kinds are delivered to
  whoever is attached and never stored.
- History and live delivery check the allowlist again for every event sent.
  A device whose grant is withdrawn or has expired, a room that is closed,
  or a supervisor that has stopped renewing: each ends the connection within
  about a quarter of a second.
- A room's database is named by a salted hash of its id, so the directory
  does not list room ids.
- It writes no log while it runs, and sends nothing anywhere: no telemetry,
  no update check, no contact with ForgeSworn.

It answers `EVENT`, `REQ` and `CLOSE`. There is no `COUNT`, no negentropy
and no NIP-11 document.

## What somebody who has not been admitted can do

Anyone who knows a room's id and this relay's address can authenticate at
the ask door, with any key, while the room is in the supervisor's list. That
connection can then do two things and no more:

- store kind 1059 events that carry exactly one `p` tag naming the room's
  inviter and an `expiration` no more than ten minutes ahead;
- read kind 1059 events whose `p` tag names its own key.

The inviter, signing in at the same door, reads what is addressed to it and
may answer only a key whose ask has not yet expired. Nobody at the ask door
can read or write the room itself. Asks are kept apart from room events,
expire within ten minutes and go when the room is purged.

So the relay stores sealed messages from strangers, briefly, for one named
recipient in each room. The bounds on that are 24 ask connections at once,
1,024 askers waiting for an answer, and the storage ceiling everything else
shares.

## Running it

```
wok-roomd --data ./private/rooms --control ./private/relay.sock \
  --url wss://node.example/events --listen 127.0.0.1:3745 \
  --max-bytes 1073741824 --min-free-bytes 1073741824 --max-rooms 32
```

| Flag | Meaning |
|------|---------|
| `--data` | Directory for the room stores. Made if missing, and set to mode 0700. |
| `--control` | Path of the control socket, made with mode 0600. Its parent directory must be private, with no access for group or others: make it before the first start. |
| `--url` | The exact public address clients use. It must be `wss://`, with the path `/events` and no credentials, query or fragment. Their AUTH must name it. |
| `--listen` | Where the WebSocket listener binds. Loopback only. Default `127.0.0.1:3745`. |
| `--max-bytes` | The most all rooms together may store. No default. |
| `--min-free-bytes` | Free space intake leaves on the volume. No default. |
| `--max-rooms` | The most rooms at once, 1 to 64. Default 32. |
| `--local-test` | Allow a `ws://` URL, for a test on one machine. The listener stays on loopback. |

The process serves plain `ws://` on loopback. A TLS proxy in front owns the
public listener, its certificates and its logs. Connections are counted by
source address in memory, for the upgrade limit below; behind a proxy on
loopback that address is the last `X-Forwarded-For` entry, so the proxy must
append the real one.

Only one process can hold a data directory. A second one started on it
exits. A control socket left behind by a process that was killed is replaced
at the next start; a path that is anything other than a socket is left alone
and the start refused.

It stops on SIGTERM or Ctrl-C and removes its socket. The exit code is 0
after a signal, 2 for a mistake on the command line and 1 for anything else
that kept it from running.

The list of rooms and devices is held in memory only. After a restart every
door refuses with `node reconnecting` until the supervisor sends the list
again. The room databases are found again at start, so they still count
towards `--max-bytes` and `--max-rooms` and are still swept for expired
events, whether or not the new list names them. A store goes only when its
room is purged.

## Local control

The supervisor connects to the control socket, writes one JSON document of
at most 1 MiB, and closes its writing side. It has five seconds. The reply
is `{"v":1,"ok":true,"result":{...}}`, or `{"v":1,"ok":false,"error":"..."}`
with a fixed text. Whoever owns the socket is trusted completely: it is that
process's job to verify a keeper's signed grants before it passes them on.

- `{"v":1,"op":"sync","rooms":[...],"grants":[...]}` replaces the whole
  allowlist and renews its 15-second lease. The reply is `leaseSeconds`.
  - A room is `room` and `inviter` (64 lower-case hex characters each) and
    `ends` (Unix seconds, at most 30 days ahead, or `null`). `existing: true`
    marks a room moved here with its history, whose older events may have no
    expiry.
  - A grant is `room`, `device`, `expires` (at most 90 days ahead), `read`
    and `write`.
  - A list that fails any check changes nothing, and neither does one that
    names a room purged in the last 30 days.
- `{"v":1,"op":"publish","room":"...","events":[...]}` stores one or two
  closing events (kinds 1461 and 1462) that the room's inviter has already
  signed. The signature and expiry checks are the room door's. The reply
  lists the ids `accepted`. A repeat is accepted without a second live
  delivery.
- `{"v":1,"op":"purge","room":"..."}` records a tombstone for the room,
  removes its access, deletes its events with their replacement and deletion
  records, truncates the write-ahead log and removes the database file. The
  reply is `eventsDeleted`. A repeat returns zero. Other rooms are not
  touched. For 30 days afterwards the room's id is refused with `room
  closed`, so a device that was offline learns that the room ended.
- `{"v":1,"op":"status"}` returns `rooms`, `devices`, `usedBytes` and
  `leaseActive`. It names no room, device or address.

Each control request and each stored event is one unit of work on one lock,
so a `sync` is seen whole or not at all.

## Limits

| | |
|---|---|
| Connections | 32 in all, of which at most 24 at the ask door |
| New connections | 60 a minute from one source address |
| Frames | 120 a minute on a connection, 257 KiB each |
| Subscriptions | 16 on a connection, up to 8 filters each |
| One history reply | 128 events or 2 MiB |
| Device grants in a list | 1,024 |
| Control requests in progress | 8 |

## What it keeps, and what purge does not reach

Events are stored as clients send them. The process sees device keys, room
ids, connecting addresses and whatever the events carry; it logs none of
them, and the addresses are held only in the in-memory table that counts new
connections. The tombstone for a purged room is a salted hash and a time.

A purge deletes rows and truncates the log with SQLite's secure deletion on.
That is not a promise about snapshots a hosting provider takes, backups, or
what the storage device keeps underneath.

## Your responsibilities

Running a relay for other people can bring legal duties, and they fall on
whoever runs it. [`wokd`'s README](../wokd/README.md#your-responsibilities)
lists things to check if you or your users are in the UK. Those notes were
written for a relay only listed members can use. This one also stores
messages from people you have not admitted, at the ask door, so read them
with that in mind. None of this is legal advice.

## Tests

The unit tests cover the two doors, rotating authors, room separation,
purge, restart, withdrawal and expiry, and the name a room's store is given.
`tests/roomd.rs` runs the built binary: its command line, the control
socket, AUTH over a real WebSocket, a second process on the same directory,
and a restart after being killed.

```
cargo test --locked -p wok-roomd
```

These run on one machine. They say nothing about a relay on the internet
behind a proxy, a mobile network or a particular phone.
