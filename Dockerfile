# syntax=docker/dockerfile:1
# What the relay runs on: glibc, libgcc and the base's own files, with no
# shell and no package manager. `wokd` is the only program in the image.
FROM gcr.io/distroless/cc-debian13 AS runtime

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
# Made here, because the runtime image has nothing to make them with: the
# `wok` user and group beside the base's own, and the data directory, whose
# owner and mode a new volume takes.
COPY --from=runtime /etc/passwd /etc/group /runtime/etc/
RUN echo 'wok:x:10001:10001::/data:/sbin/nologin' >> /runtime/etc/passwd \
    && echo 'wok:x:10001:' >> /runtime/etc/group \
    && install -d -o 10001 -g 10001 -m 0700 /runtime/data

FROM runtime
# Laid over the base as they are: a copy between stages keeps each entry's
# owner and mode, so `/data` arrives owned by `wok` and closed to others.
COPY --from=build /runtime/ /
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
