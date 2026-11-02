# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.99.1

FROM rust:${RUST_VERSION}-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY tests ./tests
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p aza-node && cp target/release/aza-node /aza-node

FROM debian:trixie-slim AS runtime

LABEL org.opencontainers.image.title="aza-node" \
    org.opencontainers.image.description="An aza node: change logs, sync data, records and inboxes over the node API" \
    org.opencontainers.image.source="https://git.aza.network/aza/protocol"

RUN groupadd --system --gid 10001 aza \
    && useradd --system --uid 10001 --gid aza --home-dir /tmp --shell /usr/sbin/nologin aza

COPY --from=build /aza-node /usr/local/bin/aza-node
ARG SOURCE_REV=unknown
RUN printf '%s\n' "$SOURCE_REV" > /.source-rev

EXPOSE 8080
USER aza
ENTRYPOINT ["/usr/local/bin/aza-node"]
