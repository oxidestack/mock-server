# 运维

<!-- languages:begin -->
[English](../../../guide/operations.md) · [Русский](../../ru/guide/operations.md) · **中文** · [Español](../../es/guide/operations.md)
<!-- languages:end -->
<!-- translation of docs/guide/operations.md: deaa667ae962 -->

运行 mock-server：容器、健康、内存、日志、指标、TLS 和插件。事实来自 `Dockerfile`、代码以及各节所列的测量。

## 容器

镜像（`make image`，参见[安装](installation.md)）基于 `FROM scratch`：一个静态二进制文件，没有 shell 和包管理器，所以
`docker exec <name> sh` 无法工作；`docker exec <name> /mock-server healthcheck` 可以。它以用户 `65532:65532` 运行，监听
`SERVER_PORT=1080`。`/config` 对该用户可写，入口点正是在这里查找 `mockserver.properties`。

以只读方式挂载属性文件或期望 JSON，并指明其路径：

```sh
docker run --rm -p 1080:1080 -v "$PWD/init:/init:ro" \
  -e MOCKSERVER_INITIALIZATION_JSON_PATH=/init/expectations.json quay.io/oxidestack/mock-server:9.2.0-rc.1
```

## 健康检查

- 存活检测和镜像的 `HEALTHCHECK`：`PUT /mockserver/status`（返回 200 及端口）。`healthcheck` 子命令把它发往 `localhost`
  上 `MOCKSERVER_SERVER_PORT` 的第一个端口，否则是 `SERVER_PORT`，否则是 1080，收到 200 时以 0 退出（`src/main.rs`）。
- 就绪检测：`GET /mockserver/ready` 返回 `{"status":"READY"}`（`src/control.rs`）。
- 等待日志行的客户端可以等待 `started on port: 1080`：它仍会打印，Testcontainers 的
  等待策略读取的就是它。

## 内存

常驻内存由 `MOCKSERVER_MAX_LOG_ENTRIES`（`maxLogEntries`）限定：每保留一条日志条目约增加 4.6 KiB。默认值与 MockServer 一样
由可用堆内存推导而来，上限为 250,000 条。`maxEventLogSizeInBytes` 在这里不是内存的限制。请把 `MOCKSERVER_MAX_LOG_ENTRIES`
设为容器内存限制所允许的值。测量数据及其机器和负载见[基准测试](https://oxidestack.github.io/mock-server/benchmarks/)页面。

镜像使用 mimalloc 分配内存（`src/main.rs`），因为静态 musl 构建的默认分配器会取一把全局锁

## 日志

`logLevel`（`MOCKSERVER_LOG_LEVEL`、`-l`、`-logLevel`）和 `logLevelOverrides` 决定记录哪些事件，与上游相同。控制台是 Rust
原生的：一行形如
`<UTC timestamp>  INFO mock_server::server: port=1080 started on port: 1080`。`RUST_LOG` 按目标过滤，例如
`RUST_LOG=mock_server=info,mock_server::matching=off`。日志配置文件不会被读取。`PUT /mockserver/retrieve?type=logs`
返回的事件日志是基准的，而不是控制台的。

## 指标与仪表盘

设置 `MOCKSERVER_METRICS_ENABLED=true` 并抓取 `GET /mockserver/metrics`；`MOCKSERVER_OTEL_METRICS_ENABLED=true` 通过 OTLP
导出。这些序列包括进程、构建、tokio 运行时、HTTP 服务器、连接、转发连接池，以及上游自己的指标族。
`grafana/` 中的两个 Grafana 仪表盘（服务器的和负载注入的）基于它们。
`scripts/verify-otlp-metrics.sh` 解码 OTLP 导出以供检查。

## TLS

HTTPS 以及到服务器的 TLS 所用的叶子证书由 MockServer 内置的 CA 签发（`src/tls/`），因此为 MockServer 信任它的客户端在这里
也信任它。`--proxy-setup`（或 `MOCKSERVER_PROXY_SETUP=true`）则生成一个私有 CA，并打印一段可供客户端复制粘贴的内容。
用于你自己证书的属性（`privateKeyPath`、`x509CertificatePath`、`certificateAuthorityCertificate`，以及控制面的 TLS 属性）
是上游的：`spec/mockserver/manual/mock_server/HTTPS_TLS.html`。

## 回调插件

类回调通过 `MOCKSERVER_CALLBACK_PLUGINS` 中列出的插件加载（镜像中为 `/libs:/extensions`）。静态镜像无法加载原生插件
（`.so`、`.dylib`、`.dll`）；WASM 插件（`.wasm`）可以。把它们挂载到 `/libs` 或 `/extensions`。每个插件在加载时会在 stderr 上
报告，加载失败的插件会被报告并跳过（`docs/callback-plugins.md`）。

## 集群

集群（`clusterEnabled`）包含在每个镜像中，使用 MockServer 所用的 JGroups 和 Infinispan 线路协议。`make container-tests`
的容器测试用例针对它运行上游的 docker-compose 和 Helm 用例。

## 停止

`PUT /mockserver/stop` 停止监听器，并让处理中的请求最多排空 `stopDrainMillis`。`SIGTERM`
（`docker stop`）按其默认动作结束进程，在排队的控制台日志行写完之后（`src/main.rs`）；它不排空请求。

## 升级

每个版本的步骤见[升级](upgrading.md)。
