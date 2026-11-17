# syntax=docker/dockerfile:1
FROM rust:1.94.1-slim-trixie AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p wokd

FROM debian:trixie-slim
RUN groupadd --gid 10001 wok \
    && useradd --uid 10001 --gid 10001 --home-dir /data --no-create-home wok \
    && install -d -o wok -g wok -m 0700 /data
COPY --from=build /src/target/release/wokd /usr/local/bin/wokd
COPY LICENSE /usr/share/doc/wok/LICENSE
LABEL org.opencontainers.image.licenses=MIT \
      org.opencontainers.image.source=https://github.com/forgesworn/wok \
      org.opencontainers.image.description="Members-only Nostr relay with scoped guest grants"
USER wok
WORKDIR /data
VOLUME ["/data"]
EXPOSE 7447/tcp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/wokd"]
CMD ["--config", "/etc/wokd/wokd.toml"]
