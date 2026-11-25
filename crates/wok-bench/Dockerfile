FROM rust:1.94.1-bookworm AS build
WORKDIR /src
COPY . .
# Two builds, not one: `wokd` asks for secp256k1's small tables, and one
# build would give them to `wok-bench` as well and slow the signing and
# checking its own figures time.
RUN cargo build --locked --release -p wokd \
    && cargo build --locked --release -p wok-bench

FROM debian:bookworm-slim
COPY --from=build /src/target/release/wokd /usr/local/bin/wokd
COPY --from=build /src/target/release/wok-bench /usr/local/bin/wok-bench
ENTRYPOINT ["/usr/local/bin/wokd"]
