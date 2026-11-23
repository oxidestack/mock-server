# Drop-in for mockserver/mockserver: same port, env vars, CLI arguments and /config layout.
# MockServer's dashboard UI, built as upstream's `build-ui` Maven profile does (same node version); build.rs embeds it.
# The node version is mockserver-ui/.nvmrc's. The working directory keeps upstream's sibling layout: build-constants.ts
# reads ../mockserver-client-rust/Cargo.toml (scripts/build-dashboard.sh's `siblings`).
FROM node:22.23.1-bookworm-slim AS ui
WORKDIR /ui/mockserver-ui
COPY upstream/mockserver/mockserver-client-rust/Cargo.toml /ui/mockserver-client-rust/Cargo.toml
COPY upstream/mockserver/mockserver-ui/package.json upstream/mockserver/mockserver-ui/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY upstream/mockserver/mockserver-ui ./
RUN npm run build

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
# cargo-auditable embeds the binary's crate list in it, which is how an SBOM of the image (syft) sees the crates in a
# static binary; the release ships one per architecture.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-auditable --version 0.7.7 --locked
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
# our Grafana dashboards, embedded for `migrate --replace-dashboards`
COPY grafana ./grafana
COPY --from=ui /ui/mockserver-ui/build /dashboard
ENV MOCK_SERVER_DASHBOARD_DIR=/dashboard
# The commit `mock_server_native_build_info{git_hash}` reports (`make image` passes it; `unknown` without it). build.rs reads
# it from the environment, which a build argument is in for the RUN steps after it.
ARG MOCK_SERVER_GIT_HASH=
# Cargo features, empty for every published image; bench/run.sh's allocation count builds with `alloc-count`.
ARG CARGO_FEATURES=
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo auditable build --profile image --locked ${CARGO_FEATURES:+--features "$CARGO_FEATURES"} \
    && cp target/image/mock-server /mock-server

FROM scratch AS standard
COPY --from=build /mock-server /mock-server
COPY --from=build --chown=65532:65532 /tmp /config
COPY LICENSE NOTICE DASHBOARD-THIRD-PARTY-NOTICES.txt /licenses/
USER 65532:65532
ENV SERVER_PORT=1080
# Callback plugins mount here, where MockServer's image takes callback jars (`/libs`) and extension jars
# (`/extensions`); the static binary loads WASM ones and names a jar on stderr.
ENV MOCKSERVER_CALLBACK_PLUGINS=/libs:/extensions
# What upstream's image sets (`docker/local/Dockerfile`), so `/mockserver/config` reports it from the environment.
ENV MOCKSERVER_DASHBOARD_ANALYTICS_DISTRIBUTION=docker-standard
EXPOSE 1080
HEALTHCHECK --interval=5s --timeout=3s CMD ["/mock-server", "healthcheck"]
ENTRYPOINT ["/mock-server", "-Dmockserver.propertyFile=/config/mockserver.properties"]
CMD []

# The `clustered-<version>` tags: clustering is in every image , so this differs from the
# standard image only in the distribution upstream's `docker/clustered/Dockerfile` sets. `make image` builds it.
FROM standard AS clustered
ENV MOCKSERVER_DASHBOARD_ANALYTICS_DISTRIBUTION=docker-clustered

# The default target.
FROM standard
