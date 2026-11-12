# wokd

`wokd` is a members-only Nostr relay built on Wok. One instance serves one
group: you list the group's public keys, and only those keys can read or
write anything. ForgeSworn publishes the software and runs no instance of it.
Whoever runs one operates it, and is responsible for it.

## What it does

- Every read, write, count and reconciliation needs NIP-42 authentication as
  a listed key. A key that is not listed is refused when it authenticates,
  and gets nothing. It is not challenged again, so a client does not keep
  signing: everything else it sends on that connection is refused as
  `restricted:`, and a listed key can still authenticate there.
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
logs are yours.

Several groups means one instance each.

## Changing the members

Edit `members` and send `wokd` SIGHUP (`kill -HUP <pid>`; under systemd,
`ExecReload=kill -HUP $MAINPID`). It reads the file again and applies the
new list without a restart:

- A removed key's open subscriptions are closed with `CLOSED`
  (`restricted: sheltered authority changed`), then its connection. Nothing
  more is read or stored for it, and it is refused if it comes back. What it
  stored stays in the store, and what it was sent stays with its clients;
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

## What members and the operator can see

- Every member reads everything the group stores.
- Events are stored as clients send them. Unless a client encrypts an event
  (a NIP-59 gift wrap, say, which still shows its outer event), its content
  can be read by you, by anyone with the data directory or its backups, and
  by every member.
- A member can store an event signed by any key, including keys outside the
  group. NIP-09 deletion is its author's alone, so nobody can delete such an
  event over the protocol; you can, with `wokd remove`.
- On Unix-like systems, a data directory `wokd` creates is readable by its
  owner only; an existing one is used as it is, with a warning if others can
  read it.

## Removing content

Stop the relay, remove, start it again:

```
wokd remove --config wokd.toml --id <event id> [--id <event id> ...]
wokd remove --config wokd.toml --author <npub>
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
