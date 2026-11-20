# Privileged-container end-to-end harness for the three original-destination resolvers
# (SO_ORIGINAL_DST, TPROXY, eBPF map lookup). Mirrors upstream's Docker-gated
# SoOriginalDstEndToEndIntegrationTest / TproxyEndToEndIntegrationTest /
# EbpfOriginalDestinationEndToEndIntegrationTest: a release binary plus iptables/iproute2/bpftool, driven by
# scripts/proxy-resolver-e2e.sh (`make proxy-resolver-e2e`). No dashboard UI stage — build.rs embeds nothing
# without one (a `cargo:warning`, not a failure) and these cases never touch `/mockserver/dashboard`.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY plugins ./plugins
# a workspace member (the admission webhook's crate): cargo reads every member's manifest, builds only the server here
COPY k8s-webhook ./k8s-webhook
COPY spec/mockserver/schema ./spec/mockserver/schema
COPY spec/mockserver/mockserver-openapi.yaml ./spec/mockserver/mockserver-openapi.yaml
COPY build.rs ./
COPY third_party ./third_party
COPY grafana ./grafana
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/mock-server /mock-server && strip /mock-server

# A glibc distro (not the builder's alpine) for bpftool/iptables/iproute2 packaging reliability; the binary itself
# is a static musl build, so the final stage's libc does not matter.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iptables iproute2 curl bpftool ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /mock-server /mock-server
