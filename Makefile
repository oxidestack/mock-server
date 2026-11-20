IMAGE ?= mock-server
include oracle.env

.PHONY: cluster-tests test image oracle oracle-stop record conformance container-tests bench plugins dashboard broker-tests blob-tests proxy-resolver-e2e webhook-image java-launcher

test:
	cargo test

PY ?= python3

.PHONY: tools-test release-check release-notes

tools-test: ## the tests of tools/
	$(PY) -m unittest discover -s tools/tests
	$(PY) -m unittest discover -s tools/public
	$(PY) -m unittest discover -s tools/lint
	$(PY) -m unittest discover -s tools/release

release-notes: ## draft the next release's section at the top of CHANGELOG.md (git-cliff in Docker); REPO=<dir> drafts another repository's
	sh tools/release/release-notes.sh $(REPO)

release-check: ## the release gate for the upgrade guide: its tests, then the Unreleased section
	$(PY) -m unittest discover -s scripts
	sh scripts/release-check.sh

# The publication gate (tools/public/public_check.py): no company's name, nothing of the author's environment, no
# internal host, no local path and no reference to the private planning repository (a ticket, decision record or
# research number, one of its paths) in a tracked file or an unpushed commit message. The denylist names the private things and so lives outside
# the repository: PUBLIC_DENYLIST, default ~/.config/oxidestack/public-denylist (one per organisation);
# PUBLIC_DENYLIST=none runs the built-in local-path and internal-host patterns and the worklog rule alone. The
# pre-push hook calls it with PUSH=<remote> and git's ref lines on stdin.
.PHONY: public-check commits-check hooks
HOOKS_DIR ?= $(shell git rev-parse --git-path hooks)

public-check: ## fail on a private name, a local path, an internal host or a worklog reference in a tracked file or an unpushed commit message; PUBLIC_DENYLIST=<file>|none
	$(if $(PUBLIC_DENYLIST),PUBLIC_DENYLIST='$(PUBLIC_DENYLIST)') $(PY) tools/public/public_check.py $(if $(PUSH),--pre-push $(PUSH))

# The commit-message gate (tools/lint/commits.py, CONTRIBUTING.md "Commit messages"): its fixtures, then every commit
# after the base. The pre-push hook calls it with PUSH=<remote> and git's ref lines on stdin: the pushed commits after
# the base. On the host, as the hook runs: python3 and git.
commits-check: ## the commit messages after the base; PUSH=<remote> with git's pre-push ref lines on stdin: the pushed ones
	$(PY) tools/lint/commits.py $(if $(PUSH),--pre-push $(PUSH))

hooks: ## install the pre-push hook: make public-check and make commits-check before every push
	@mkdir -p '$(HOOKS_DIR)'
	@if [ -e '$(HOOKS_DIR)/pre-push' ] && ! cmp -s tools/public/pre-push '$(HOOKS_DIR)/pre-push'; then \
		echo "hooks: $(HOOKS_DIR)/pre-push exists and differs from tools/public/pre-push; move it away first" >&2; exit 1; fi
	install -m 755 tools/public/pre-push '$(HOOKS_DIR)/pre-push'

# The CNCF licence gate, as the `licenses` CI job runs it : third_party/ unmodified and licensed as
# third_party/MANIFEST records, then the Cargo graph against deny.toml (`cargo install cargo-deny --locked`), then the dashboard's npm packages and
# java-launcher's Maven dependencies (tools/check-noncargo-licenses.py).
.PHONY: licenses
licenses:
	sh tools/check-third-party.sh
	cargo deny --locked check licenses
	python3 tools/check-noncargo-licenses.py npm
	mvn -B -q -f java-launcher/pom.xml dependency:list -DincludeScope=runtime -DoutputFile=$(CURDIR)/target/java-launcher-deps.txt
	python3 tools/check-noncargo-licenses.py maven --list target/java-launcher-deps.txt

# The AsyncAPI live-broker ports (tests/upstream/*_live_broker.rs) against Mosquitto, RabbitMQ and Kafka containers
# (upstream's Testcontainers images); plain `cargo test` skips them.
broker-tests:
	MOCK_SERVER_BROKER_TESTS=1 cargo test --test upstream live_broker

# The cloud blob store ports (tests/upstream/blob_*.rs) against MinIO, fake-gcs-server and Azurite containers;
# plain `cargo test` skips them.
blob-tests:
	MOCK_SERVER_BLOB_TESTS=1 cargo test --test upstream blob_

# The integration-testing callback classes as plugins (docs/callback-plugins.md): a native library in
# target/release and a WASM module in target/wasm. The WASM build needs a rustup toolchain with the
# wasm32-unknown-unknown target: stable, or the one MOCK_SERVER_WASM_TOOLCHAIN names (as for tests/oracle.rs).
PLUGIN := mock-server-integration-testing-callbacks
MOCK_SERVER_WASM_TOOLCHAIN ?= stable
plugins:
	cargo build --release -p $(PLUGIN)
	RUSTC=$$(rustup which rustc --toolchain $(MOCK_SERVER_WASM_TOOLCHAIN)) $$(dirname $$(rustup which rustc --toolchain $(MOCK_SERVER_WASM_TOOLCHAIN)))/cargo build --release -p $(PLUGIN) --target wasm32-unknown-unknown --target-dir target/wasm

# The documentation site (site/README.md): Astro Starlight over README.md and docs/guide/, built into site/dist/ in the
# node image pinned here by digest (node 22), so no host needs node. A broken internal link or anchor fails it. The
# The CI gate calls this target.
SITE_NODE_IMAGE ?= node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a
.PHONY: site
site:
	docker run --rm --name mock-server-site-$$$$ --user "$$(id -u):$$(id -g)" -e HOME=/tmp -v "$(CURDIR):/src" -w /src \
		$(SITE_NODE_IMAGE) sh site/build.sh

# Every release's documentation under target/site/pages/ as GitHub Pages serves it: the latest at the root, each minor
# under /<x.y>/, a version picker and an outdated-version banner (site/README.md, "Versions"). With no release tag it
# builds the working tree at the root alone. extract.sh needs git, so it runs on the host; build.sh in the node image.
.PHONY: site-versions
site-versions:
	sh site/versions/extract.sh
	docker run --rm --name mock-server-site-versions-$$$$ --user "$$(id -u):$$(id -g)" -e HOME=/tmp -v "$(CURDIR):/src" -w /src \
		$(SITE_NODE_IMAGE) sh site/versions/build.sh

# MockServer's dashboard UI (upstream/mockserver/mockserver-ui, node 22) into dashboard/, which build.rs embeds into
# the binary; without it the binary answers /mockserver/dashboard with 404. The script skips the build when the bundle
# is current (FORCE=1 rebuilds). The image builds the UI in its own stage and does not need this.
dashboard:
	scripts/build-dashboard.sh

# The commit goes in as a build argument (the build context has no `.git`), for `mock_server_native_build_info{git_hash}`.
# The `clustered` target is the same image with upstream's clustered distribution value, tagged as upstream tags it.
image:
	docker build --build-arg MOCK_SERVER_GIT_HASH=$(shell git rev-parse --short=8 HEAD 2>/dev/null) -t $(IMAGE):latest -t $(IMAGE):$(ORACLE_VERSION) -t $(IMAGE):mockserver-$(ORACLE_VERSION) .
	docker build --build-arg MOCK_SERVER_GIT_HASH=$(shell git rev-parse --short=8 HEAD 2>/dev/null) --target clustered -t $(IMAGE):clustered-latest -t $(IMAGE):clustered-$(ORACLE_VERSION) -t $(IMAGE):clustered-mockserver-$(ORACLE_VERSION) .

# The Kubernetes admission webhook's image, upstream's mockserver/mockserver-webhook: its own binary,
# built from k8s-webhook/Dockerfile.
WEBHOOK_IMAGE ?= $(IMAGE)-webhook
webhook-image:
	docker build -f k8s-webhook/Dockerfile -t $(WEBHOOK_IMAGE):latest .

# Start the oracle (oracle.env) on :$(ORACLE_PORT) for recording scenario goldens. A second worktree records at the
# same time with its own ORACLE_PORT and ORACLE_NAME (one oracle per worktree); `record` names the
# property-scoped oracles and UDP sidecars it starts after ORACLE_NAME too.
ORACLE_PORT ?= 18080
ORACLE_NAME ?= mock-server-oracle
# ORACLE_QUIC=1 starts the oracle's http3 variant. Since 9.2.0 the standard image serves an `http3Port` too, and
# recording uses it for a scenario with `"quic": true` (tests/scenarios/README.md). Docker on macOS
# forwards no UDP: reach the HTTP/3 port from a container sharing the oracle's network namespace.
ORACLE_QUIC ?=
# `--mount type=bind`, not `-v`: `-v` mounts a source the Docker VM cannot see as an empty directory, so
# the oracle read no tests/files and said so only in its log; `--mount` refuses to start ("bind source path does not exist").
# ORACLE_JVM_OPTIONS pins the processors and heap the oracle sizes its defaults from (oracle.env), so a
# recording does not move with the Docker VM's CPUs or memory.
ORACLE_JVM_OPTIONS = -XX:ActiveProcessorCount=$(ORACLE_ACTIVE_PROCESSORS) -Xmx$(ORACLE_MAX_HEAP_BYTES)
oracle:
	docker run -d --rm --name $(ORACLE_NAME) -p $(ORACLE_PORT):1080 -e 'JDK_JAVA_OPTIONS=$(ORACLE_JVM_OPTIONS)' --mount 'type=bind,"source=$(CURDIR)/tests/files","target=$(CURDIR)/tests/files",readonly' $(if $(ORACLE_QUIC),$(ORACLE_HTTP3_IMAGE),$(ORACLE_IMAGE))

oracle-stop:
	docker rm -f $(ORACLE_NAME)

record:
	MOCK_SERVER_RECORD_ORACLE=http://localhost:$(ORACLE_PORT) MOCK_SERVER_ORACLE_NAME=$(ORACLE_NAME) cargo test --test oracle

# The Java client suite against both images.
# DOCKER_HOST defaults to the active docker context (a Docker VM, OrbStack, Docker Desktop), for Testcontainers.
DOCKER_HOST ?= $(shell docker context inspect --format '{{.Endpoints.docker.Host}}')
# Upstream's MockServerContainerIntegrationTest (run here unmodified) starts TestcontainersImages.PINNED_MOCKSERVER_IMAGE
# (mockserver/mockserver:mockserver-9.1.0 at 9.2.0; read from the submodule): that tag names our image while
# the suite runs, and afterwards whatever it named before (scripts/with-image-tags.sh).
UPSTREAM_PINNED_IMAGE = $(shell sed -n 's/.*PINNED_MOCKSERVER_IMAGE = "\([^"]*\)".*/\1/p' upstream/mockserver/mockserver/mockserver-testcontainers/src/test/java/org/mockserver/testcontainers/TestcontainersImages.java)
conformance: image
	test -n "$(UPSTREAM_PINNED_IMAGE)"
	cd conformance/java && DOCKER_HOST=$(DOCKER_HOST) TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock \
		../../scripts/with-image-tags.sh $(IMAGE):latest $(UPSTREAM_PINNED_IMAGE) -- mvn -q test

# Upstream's container integration tests (docker-compose and helm on k3d) against our image, or TARGET=oracle
# CONTAINER_GROUPS=docker|helm and CASES=a,b narrow the run; results in conformance/containers/target.
CONTAINER_TARGET ?= rs
CONTAINER_GROUPS ?= docker,helm
CASES ?=
container-tests:
	IMAGE=$(IMAGE) WEBHOOK_IMAGE=$(WEBHOOK_IMAGE) CONTAINER_GROUPS=$(CONTAINER_GROUPS) CASES=$(CASES) conformance/containers/run.sh $(CONTAINER_TARGET)

# Mixed-cluster gate: our image and the oracle's clustered image (oracle.env) in one JGroups cluster, both
# join orders. CLUSTER_ORDER = rs-first | java-first | all. Names carry the suffix 158 (SUFFIX=...); one at a time.
CLUSTER_ORDER ?= all
cluster-tests: image
	IMAGE=$(IMAGE):clustered-latest JAVA_IMAGE=$(ORACLE_CLUSTERED_IMAGE) conformance/cluster/run.sh $(CLUSTER_ORDER)

# Upstream MockServer suites. TARGET = oracle-jvm | oracle-process | rs-process.
# TEST narrows to surefire test sets (RemoteControlPlaneTest, T2Test, ...); CLASSES to upstream classes of a tranche,
# METHODS to test methods of those classes.
# Per-test results: conformance/upstream/results.py list|diff|tally.
TARGET ?= rs-process
TEST ?=
CLASSES ?=
METHODS ?=
upstream-tests: dashboard
	cargo build --release
	cargo build --release -p $(PLUGIN)
	cd conformance/upstream && mvn -q test -Dtarget=$(TARGET) $(if $(TEST),-Dtest=$(TEST) -Dsurefire.failIfNoSpecifiedTests=false) $(if $(CLASSES),-Dclasses=$(CLASSES) -DreportSuffix=-partial) $(if $(METHODS),-Dmethods=$(METHODS))

# The Java launcher (docs/java-launcher.md): MockServer's ClientAndServer, JUnit rule, JUnit 5 extension,
# Spring test listener and Spring Boot starter over the binary. Runs upstream's own tests of those classes against a
# release build and installs io.github.oxidestack:mockserver-netty into the local Maven repository (not published).
java-launcher:
	cargo build --release
	cargo build --release -p $(PLUGIN)
	cd java-launcher && mvn -q install -DmockServerBin=$(CURDIR)/target/release/mock-server -DrsCallbackPluginDir=$(CURDIR)/target/release

# Privileged Linux-container end-to-end proof of the three original-destination resolvers (SO_ORIGINAL_DST,
# TPROXY, eBPF map lookup) that `transparentProxyEnabled` tries before DNS-intent — containers named
# mock-server-126-*, built from a native release binary (scripts/proxy-resolver-e2e.Dockerfile) plus
# iptables/iproute2/bpftool, mirroring upstream's Docker-gated So/Tproxy/Ebpf*EndToEndIntegrationTest. Needs a Docker VM
# (or another docker context) that allows --privileged/--cap-add=NET_ADMIN containers; a kernel that lacks a feature
# (no xt_TPROXY, no BPF) SKIPs that case rather than failing. CASE narrows to one of so-original-dst|tproxy|ebpf.
CASE ?= all
proxy-resolver-e2e:
	DOCKER_HOST=$(DOCKER_HOST) scripts/proxy-resolver-e2e.sh $(CASE)

# Extra targets live in mk/*.mk, so concurrent work never edits the Makefile.
-include mk/*.mk
