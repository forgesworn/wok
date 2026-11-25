# wokd

`wokd` is a members-only Nostr relay built on Wok. One instance serves one
group: you list its keeper public keys, which have full access, and those
keepers can sign room-scoped grants for guests. ForgeSworn publishes the
software and runs no instance of it. Whoever runs one operates it, and is
responsible for it.

## What it does

- Every read, write, count and reconciliation needs NIP-42 authentication as
  a listed keeper or a guest with a current grant. A key with neither is
  refused when it authenticates, and gets nothing. It is not challenged again,
  so a client does not keep signing: everything else it sends on that
  connection is refused as `restricted:`, and a key with access can still
  authenticate there.
- A keeper's signed kind-24242 `t=event-grant` event names this relay's exact
  `ws://` or `wss://` `/events` URL, one room, a guest persona and device, the
  allowed kinds and an expiry. The relay installs it as authority, never as
  room history. Ordinary rooms currently read kinds 1460, 1462 and 20461 and
  write kinds 1460 and 20461; calls, new invitations, rekeys and protected MLS
  are outside this guest profile. Exact retries are safe. A newer grant,
  terminal revocation, expiry or removal of its keeper takes away the access.
- It listens on loopback (`127.0.0.1:7447`) unless you say otherwise. Anyone
  who can reach the address can open a connection and receive the AUTH
  challenge; only members can authenticate.
- There is no open mode and no public door.
- It answers a NIP-11 request for its relay information document with the
  same static document for everyone: the NIPs it supports, its limits, and
  that every read and write needs NIP-42. The document names no member, no
  operator and no address. It tells a client no more than the AUTH challenge
  any connection is sent, and it lets a browser page read that without
  opening a socket. `relay_information = false` turns it off.
- It sends nothing anywhere: no telemetry, no update check, no contact with
  ForgeSworn.

## Running it

```
wokd --config wokd.toml
```

Copy [`wokd.example.toml`](wokd.example.toml) and fill it in. Every field is
read and checked at start; an unknown field, an empty member list or a
malformed key stops it, and no error repeats a key. Members are listed as `npub` public
keys only. If you paste an `nsec` by mistake, `wokd` refuses it: treat that
secret key as exposed.

`wokd` serves plain `ws://`. For clients on other machines, put a TLS proxy
in front and set `url` to the `wss://` address clients use; their AUTH must
name it, and its path must be `/events`. The proxy, its certificates and its
logs are yours. A client that names another address (the one behind the
proxy, or the host without its port) is refused and not challenged again,
so its client does not keep signing, and `wokd` logs a warning
that AUTH named a relay URL other than `url`, with a count and nothing the
client sent. Anyone who can connect can cause that warning, so it points at
`url` only when your members' clients are the ones failing.

Several groups means one instance each.

The repository root also has a production Docker image definition. It builds
only `wokd`, runs it as uid 10001 and keeps state in `/data`; it is not the
benchmark image. CI publishes it for amd64 and arm64 as
`ghcr.io/forgesworn/wok`: each release tag as its version (`0.7.0` for
`v0.7.0`), and `main` as `latest`. Pin a version. The image's SQLite is built
without the extensions `wokd` never uses (full-text search, R-tree, JSON and
the like); the `Dockerfile` lists them. Its base is distroless: `wokd` is the
only program in it, so there is no shell to `docker exec` into, and anything
you run in it is a `wokd` command. Or build it yourself:

```sh
docker build -t localhost/wokd:dev .
docker run --rm -p 127.0.0.1:7447:7447 \
  -v "$PWD/wokd.toml:/etc/wokd/wokd.toml:ro" \
  -v wok-data:/data localhost/wokd:dev
```

In that configuration, use `data_dir = "/data"` and `listen =
"0.0.0.0:7447"`. Inside a container, loopback is the container's own, so a
relay left on the default `127.0.0.1:7447` cannot be reached through the
published port. The `-p 127.0.0.1:7447:7447` above still keeps it on the
host's loopback. The [Compose deployment bundle](../../deploy/README.md)
adds TLS and keeps this listener private; do not expose plain `ws://` beyond
loopback or a deliberately isolated network.

## Changing the members

Edit `members` and send `wokd` SIGHUP (`kill -HUP <pid>`; under systemd,
`ExecReload=kill -HUP $MAINPID`). It reads the file again and applies the
new list without a restart:

- A removed key's open subscriptions are closed with `CLOSED`
  (`restricted: sheltered authority changed`), then its connection. Nothing
  more is read or stored for it, and it is refused if it comes back. Grants it
  issued stop counting too, so its guests lose their scoped access. What the
  key stored stays in the store, and what it was sent stays with its clients;
  `wokd remove` is for the first.
- An added key can authenticate, on a new connection or on one that had not
  yet authenticated. A client that key used before the reload was refused
  and, as stock clients do, will not try again on that connection: it needs
  to reconnect.
- Members on both lists are not disturbed.
- A file that cannot be read or does not pass the checks changes nothing.
  The error is logged, without repeating a key.

SIGHUP gives no answer of its own, so check the log after a reload,
especially after removing someone: `membership changed`, with the counts
added and removed, means the new list is in force; `reload refused` means
the old one still is.
- Every other setting takes a restart. A reload that changes one says so in
  the log and goes on as before.

SIGHUP does not stop `wokd`, so closing the terminal it runs in leaves it
running; stop it with SIGTERM or Ctrl-C. On Windows there is no SIGHUP, and
a change of members takes a restart.

## What members, guests and the operator can see

- Every keeper reads everything the group stores. A guest reads only the
  rooms and kinds its current grants name, and writes only with the granted
  device key. The relay never fans a grant out as content.
- Events are stored as clients send them. Unless a client encrypts an event
  (a NIP-59 gift wrap, say, which still shows its outer event), its content
  can be read by you, by anyone with the data directory or its backups, and
  by every member.
- A keeper can store an event signed by any key, including keys outside the
  group. NIP-09 deletion is its author's alone, so nobody can delete such an
  event over the protocol; you can, with `wokd remove`.
- On Unix-like systems, a data directory `wokd` creates is readable by its
  owner only; an existing one is used as it is, with a warning if others can
  read it. `events.sqlite` holds room events and `room-authority.sqlite`
  holds signed grants, their exact receipts and replay watermarks. Back up
  both together. `wokd remove` removes content, not authority; revoke a grant
  with its signed terminal or remove its keeper.

## Removing content

Stop the relay, remove, start it again:

```
wokd remove --config wokd.toml --id <event id> [--id <event id> ...]
wokd remove --config wokd.toml --author <npub>
```

With the container image, run the removal as its own container on the
stopped relay's configuration and volume:

```sh
docker run --rm -v "$PWD/wokd.toml:/etc/wokd/wokd.toml:ro" -v wok-data:/data \
  localhost/wokd:dev remove --config /etc/wokd/wokd.toml --id <event id>
```

- A removal is refused while the relay is running on that data directory.
- Each removed event is barred from being stored again: a client that
  re-publishes it is refused. The bar is per event, so a re-signed copy is a
  new event. The store does not record which member sent an event, so
  finding who stores such copies is up to you.
- `--author` removes what that key has signed so far, not what it signs
  later; to stop a member, take the key out of `members` and reload or
  restart.
- An id that is not stored is reported, and the command exits 3. Nothing can
  be barred for it.
- It clears this store only. Backups, your proxy's logs and members' own
  clients keep whatever copies they have. If it reports that the
  write-ahead log could not be truncated, the removed bytes stay there until
  the relay next truncates it.

## Limits

These are the limits Wok's doors keep, and they bound how large a group one
instance suits: 32 connections in all, 120 frames a minute for each, at most
128 events for each query. A connection has 15 seconds to authenticate
(`auth_deadline_secs`). Each remote address may hold 8 sockets at once
(`sockets_per_address`); loopback is not capped, so behind a local proxy no
client is, and the connection budget and the AUTH deadline are what hold
strangers back.

The relay runs on 2 worker threads (`workers`) rather than one per core,
with its store's work on threads of its own. Signature checks and each
connection's store steps share a pool of at most 8 more, however many frames
are in flight. On Linux with glibc it caps
the allocator at 2 arenas at start-up, unless `MALLOC_ARENA_MAX` is already
set in its environment, in which case that value stands. There it also hands
the allocator's free memory back to the kernel every 30 seconds, so what a
burst of writes used does not stay resident.

## Testing a container image

From the repository root on macOS or Linux, run the CI smoke tests against a
local image. The first starts two containers in turn with the same volume.
It checks keeper and guest access, then verifies that the event and grant
revocation survive replacing the first container. The second stores an event
with 500 tags and a deletion of 40 events, the writes that need a temporary
file, then runs `wokd remove` in the image on the stopped relay's volume.

```sh
WOK_TEST_IMAGE=localhost/wokd:dev cargo test --locked -p wokd --test wokd -- \
  --ignored --exact container::packaged_relay_preserves_member_events \
  container::packaged_relay_takes_wide_writes_and_an_operators_removal
```

To check an upgrade, set `WOK_TEST_PREVIOUS_IMAGE` as well: the first test
then writes with that image and reads the same volume with `WOK_TEST_IMAGE`.

## Your responsibilities

Running a relay can bring legal duties. They depend on who your members are
and where you and they are, more than on the software. This is not legal
advice, and ForgeSworn does not decide it for you. Things to check, if you
or your members are in the UK:

- **Online safety.**
  - A relay used only by the people who work on your business or project,
    volunteers and contractors included, as a tool for that work, and run by
    whoever carries on that work, may fall under the internal business
    exemption (Online Safety Act 2023, Schedule 1 paragraph 7). It holds only
    while every listed key belongs to those people. Whether an unpaid
    open-source project counts as a business here is not settled.
  - No exemption names a relay for family and friends. Whether one for a
    handful of people is regulated turns on its links with the UK, and no
    decision on such a service has been found. A relay only you use is
    probably outside the Act, since nobody else can encounter its content;
    that too is a reading.
  - If yours is regulated, the duties include:
    - carrying out an illegal content risk assessment and keeping a written
      record of it;
    - assessing whether children can use it;
    - a way to report illegal content and to complain;
    - removing illegal content swiftly once you know of it, and saying how
      you do so;
    - reporting child sexual abuse content you become aware of to the
      National Crime Agency (register with it first). Keep that content and
      what you reported for a year: do not rely on `wokd remove` alone.
  - If children could be members, a regulated service owes them more, and
    further rules on under-16s are expected.
- **Data protection.** You hold members' public keys, the public keys of
  anyone whose signed events members store, a record of the id and author of
  each event you remove, connecting addresses in any logs you or your proxy
  keep, and whatever members store. Running it purely for your own private
  and household life is probably outside UK data protection law; running it
  for a project or a business probably is not, and then you may owe a
  privacy notice and the data protection fee. Neither reading is settled.
- **Lawful requests.** Running a store of messages for people in the UK very
  probably makes you a telecommunications operator under the Investigatory
  Powers Act 2016; that is a reading, not a ruling. An operator can be served
  a notice that it may not reveal. If one arrives, the next step is a
  solicitor.

Other countries' rules differ.
