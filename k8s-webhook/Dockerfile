# The admission webhook's image, a drop-in for upstream's mockserver/mockserver-webhook (docker/webhook/Dockerfile):
# same port, environment and TLS file paths, no shell (as upstream's distroless image). Built from the repository root:
#
#   docker build -f k8s-webhook/Dockerfile -t mock-server-webhook .      (make webhook-image)
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
# the whole workspace's manifests (cargo resolves every member), but only the webhook is compiled
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY plugins ./plugins
COPY k8s-webhook ./k8s-webhook
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=mock-server-webhook-target,target=/src/target \
    cargo build --profile image --locked -p mock-server-k8s-webhook \
    && cp target/image/mock-server-webhook /mock-server-webhook

FROM scratch
COPY --from=build /mock-server-webhook /mock-server-webhook
COPY LICENSE NOTICE /licenses/
USER 65532:65532
EXPOSE 8443
# overridden by the Helm chart's webhook-deployment.yaml; no HEALTHCHECK (Kubernetes probes GET /healthz over HTTPS)
ENV WEBHOOK_PORT=8443
ENV WEBHOOK_TLS_CERT_FILE=/etc/webhook/tls/tls.crt
ENV WEBHOOK_TLS_KEY_FILE=/etc/webhook/tls/tls.key
ENTRYPOINT ["/mock-server-webhook"]
