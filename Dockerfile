# syntax=docker/dockerfile:1
FROM rust:1.94.1-slim-trixie AS build
WORKDIR /src
# The bundled SQLite without what the stores never use: full-text search,
# R-tree, JSON, the dbstat table, soundex, loadable extensions, deprecated
# interfaces and shared cache. It also keeps no memory statistics, which
# otherwise cost a lock on every allocation. The whole test suite passes
# built this way.
ENV LIBSQLITE3_FLAGS="-USQLITE_ENABLE_FTS3 -USQLITE_ENABLE_FTS3_PARENTHESIS -USQLITE_ENABLE_FTS5 -USQLITE_ENABLE_RTREE -USQLITE_ENABLE_DBSTAT_VTAB -USQLITE_SOUNDEX -USQLITE_ENABLE_LOAD_EXTENSION -DSQLITE_OMIT_LOAD_EXTENSION -DSQLITE_OMIT_JSON -DSQLITE_OMIT_DEPRECATED -DSQLITE_OMIT_SHARED_CACHE -DSQLITE_DEFAULT_MEMSTATUS=0"
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
