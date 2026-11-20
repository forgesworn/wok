# Run Wok behind TLS with Compose

This example runs one `wokd` for one group. Nginx terminates TLS and exposes
`/events`. The relay stays on an internal Docker network and stores both
databases in the `wok-data` volume. A WebSocket connection still needs
NIP-42 authentication as a keeper or a guest with a current grant.

1. Copy `wokd.example.toml` to `wokd.toml` in this directory. Fill in at least
   one keeper `npub`. Set `url` to the exact `wss://` address members use,
   including `/events` and any non-default port.
2. Place the host's TLS certificate chain at `tls/fullchain.pem` and its
   private key at `tls/privkey.pem`. The certificate must cover the hostname
   in `url`. Your certificate issuer and renewal process are operator-owned.
3. Set `WOK_IMAGE` in `.env` to the Wok image version or digest you intend
   to run. The proxy binds to `127.0.0.1:443` by default. For remote members,
   set `WOK_HTTPS_BIND` to the interface that should serve them. Set
   `WOK_HTTPS_PORT` here if the public port differs from 443. Give multiple
   groups on one host distinct `COMPOSE_PROJECT_NAME` values and listeners
   so each group has its own volume.
4. Run `docker compose config --quiet` and `docker compose up -d` from this
   directory. Check `docker compose logs` if a service fails to start.

With relay information enabled, use the exact public HTTPS address and
verify that it serves a NIP-11 document with `auth_required` set to `true`.
Then connect with a keeper in your Nostr client to confirm NIP-42 and event
readback.

```sh
curl --fail --silent --show-error -H 'Accept: application/nostr+json' \
  https://relay.example.com/events
```

Nginx limits concurrent `/events` requests and upgraded sockets to four per
source address. Members behind the same NAT share that limit. This example
expects clients to connect directly to the TLS proxy. A forwarding proxy or
load balancer in front would make its connections share one address. Access
logging is disabled. Treat error logs as private operational data.

Reload Nginx after placing renewed certificate files in `tls/` using
`docker compose exec proxy nginx -s reload`. To stop the stack and retain
the databases, use `docker compose down`. Back up both databases and the
membership configuration together before upgrading. See the [wokd operator
guide](../crates/wokd/README.md) for membership reload and storage details.

## Exercise the bundle locally

From the repository root on macOS or Linux, build the relay image and run
the Compose smoke test. It creates test certificates with OpenSSL and uses a
loopback port and a disposable data volume.

```sh
docker build -t localhost/wokd:dev .
WOK_TEST_IMAGE=localhost/wokd:dev cargo test --locked -p wokd --test wokd \
  tls_deploy::packaged_relay_behind_tls -- --ignored --exact
```
