FROM rust:1.94.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p wokd -p wok-bench

FROM debian:bookworm-slim
COPY --from=build /src/target/release/wokd /usr/local/bin/wokd
COPY --from=build /src/target/release/wok-bench /usr/local/bin/wok-bench
ENTRYPOINT ["/usr/local/bin/wokd"]
