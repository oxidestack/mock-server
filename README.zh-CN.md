# mock-server

<!-- languages:begin -->
[English](README.md) · [Русский](README.ru.md) · **中文** · [Español](README.es.md)
<!-- languages:end -->
<!-- translation of README.md: cc9078521959 -->

[MockServer](https://www.mock-server.com) 的直接替代品（drop-in），用 Rust 编写。它像 MockServer 9.2.0 镜像一样响应
MockServer 的 REST API，并接受其命令行、环境变量和属性，因此驱动 MockServer 的客户端（Java、Node、Python、Ruby、
原生 REST）、Testcontainers 模块和 Helm chart 只需改动镜像名称即可驱动它：单个静态二进制文件，没有 JVM。

**文档：[oxidestack.github.io/mock-server](https://oxidestack.github.io/mock-server/)**

## 快速开始

```sh
docker run --rm -p 1080:1080 quay.io/oxidestack/mock-server:9.2.0-rc.1
```

启动后，在另一个终端中：

```sh
curl -X PUT localhost:1080/mockserver/expectation -d '{
  "httpRequest":  {"method": "GET", "path": "/hello"},
  "httpResponse": {"statusCode": 200, "body": "world"}
}'
curl -i localhost:1080/hello                              # 200, world
```

仪表盘位于 `http://localhost:1080/mockserver/dashboard`。每个版本都经过签名，并附带其 SBOM 和构建来源证明
（provenance）；[验证镜像](docs/i18n/zh/guide/installation.md#验证镜像)介绍如何用 `cosign` 和
`gh attestation verify` 检查它。

## 它提供什么

- **直接替换。** 与 MockServer 的 `/mockserver/*` 控制面通信的客户端无需修改即可工作，命令行、环境变量、属性和
  `/config` 布局都与 MockServer 相同。`oracle.env` 中固定的 MockServer 镜像是基准：它与这里的任何文档不一致时，
  以它为准；行为尚未完全一致之处，[`docs/divergences.md`](docs/divergences.md) 都有说明。
- **单个静态二进制文件。** 没有 JVM，也没有垃圾回收器；容器镜像基于 `FROM scratch`，支持 `linux/amd64` 和
  `linux/arm64`，以非 root 用户运行。内存由 `MOCKSERVER_MAX_LOG_ENTRIES` 限定（[运维](docs/i18n/zh/guide/operations.md#内存)），
  [基准测试](https://oxidestack.github.io/mock-server/benchmarks/)页面在相同负载下将它与 MockServer 镜像进行比较。
- **不止 HTTP/1.1。** HTTP/2、HTTP/3、TLS、gRPC、DNS、AsyncAPI 消息代理、代理转发、混沌（chaos）注入、集群以及
  MockServer 仪表盘（[API 参考](docs/i18n/zh/guide/api.md)）。
- **面向 Java 测试套件。** 通过 Testcontainers 使用该镜像，或使用 `java-launcher/`——`mockserver-netty` 的直接
  替代品，它在 `ClientAndServer` 以及 JUnit 和 Spring 集成之后启动该二进制文件
  （[安装](docs/i18n/zh/guide/installation.md#在-java-测试中使用)）。

## 文档

指南发布在 [oxidestack.github.io/mock-server](https://oxidestack.github.io/mock-server/)，最新版本位于根路径，每个
版本位于其版本号之下；同样的页面（`main` 上的状态）位于 `docs/guide/`（译文位于 `docs/i18n/zh/guide/`）：

- [安装](docs/i18n/zh/guide/installation.md)——`docker run`、Docker Compose、Kubernetes、从源代码构建以及在 Java
  测试中使用
- [升级](docs/i18n/zh/guide/upgrading.md)——每个版本对部署的要求，以及如何从 MockServer 镜像迁移
- [配置](docs/i18n/zh/guide/configuration.md)——设置如何读取、命令行、属性文件
- [API 参考](docs/i18n/zh/guide/api.md)——控制面、健康检查、指标、仪表盘和其他协议
- [运维](docs/i18n/zh/guide/operations.md)——容器、健康检查、内存、日志、指标、TLS、插件
- [故障排除](docs/i18n/zh/guide/troubleshooting.md)——各种症状、其含义以及应对方法
- [基准测试](https://oxidestack.github.io/mock-server/benchmarks/)——与 MockServer 镜像对比的每秒请求数和内存，
  数据来自已提交的 `bench/run.sh` 结果（英文）
- [Changelog](CHANGELOG.md)——每个版本的变更

## 构建与测试

本仓库以 git 子模块的形式包含 MockServer 的单体仓库，测试和仪表盘构建会读取它（本项目自己的 Rust 库是 crates.io
上的依赖），因此请连同子模块一起克隆：

```sh
git clone --recursive https://github.com/oxidestack/mock-server.git
```

如果克隆时没有使用 `--recursive`，请执行一次 `git submodule update --init`。

- `cargo build --release` 构建服务器，即 `target/release/mock-server`。
- `make image` 为本机架构构建容器镜像，标记为 `mock-server:latest`；需要 Docker。
- `cargo test` 运行单元测试、MockServer 自身测试的 Rust 移植版以及所有已录制的场景；不需要 MockServer 容器。
  [CONTRIBUTING.md](CONTRIBUTING.md) 列出了较慢的测试套件以及每个 pull request 都要通过的检查。

## 获取帮助

关于服务器如何工作的问题，可以先去 [DeepWiki](https://deepwiki.com/oxidestack/mock-server)：它根据本仓库的代码和
文档作答，若与文档不一致，以文档为准。它无法解答的问题请到
[Discussions](https://github.com/oxidestack/mock-server/discussions)，缺陷请提交到
[issues](https://github.com/oxidestack/mock-server/issues)，安全漏洞请私下报告（[SECURITY.md](SECURITY.md)）。
[CONTRIBUTING.md](CONTRIBUTING.md) 说明了如何构建、测试和提交修改。

## 许可证

代码采用 [Apache License, Version 2.0](LICENSE)（`Apache-2.0`）许可。文档——本 README 和 `docs/` 下的指南——采用
[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)（`CC-BY-4.0`）
许可；其法律文本见 [`LICENSE-docs`](LICENSE-docs)。`spec/mockserver/` 包含 MockServer 自己的 schema、OpenAPI 文档
和手册页面：它们属于上游，而不是本项目的文档，仍采用 Apache-2.0。取自其他来源的材料保留其自身的许可证，并在
[`NOTICE`](NOTICE) 中注明出处。
