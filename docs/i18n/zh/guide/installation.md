# 安装

<!-- languages:begin -->
[English](../../../guide/installation.md) · [Русский](../../ru/guide/installation.md) · **中文** · [Español](../../es/guide/installation.md)
<!-- languages:end -->
<!-- translation of docs/guide/installation.md: c9c1323a95fd -->

mock-server 是一个静态可执行文件 `mock-server`，在网络协议层面的行为与 MockServer 一致。本页运行它的镜像、从源代码
构建它，并说明 Java 测试套件如何连接到它。这里的每条命令都由仓库定义（`Makefile`、`Dockerfile`、`Cargo.toml`），
或由其版本发布。

## 运行镜像

```sh
docker run --rm -p 1080:1080 quay.io/oxidestack/mock-server:9.2.0-rc.1
```

镜像以同一个标签发布到 quay.io，支持 `linux/amd64` 和 `linux/arm64`，并以相同的摘要、签名和证明镜像到
`ghcr.io/oxidestack/mock-server`。版本号跟随它所对应的 MockServer 版本：`9.2.0` 可直接替代 MockServer 9.2.0 镜像。
正式版本带有 `<version>`、`mockserver-<version>`（MockServer 自己的镜像所带的标签）和 `latest` 标签；候选版本
`9.2.0-rc.1` 只带其版本号标签。

镜像名之后的参数就是服务器的参数，与 MockServer 镜像相同：
`docker run --rm -p 1081:1081 quay.io/oxidestack/mock-server:9.2.0-rc.1 -serverPort 1081`。

镜像设置的内容（`Dockerfile`）：

| | |
|---|---|
| 端口 | `SERVER_PORT=1080`、`EXPOSE 1080` |
| 入口点 | `/mock-server -Dmockserver.propertyFile=/config/mockserver.properties` |
| 用户 | `65532:65532`，`/config` 归其所有 |
| 回调插件 | `MOCKSERVER_CALLBACK_PLUGINS=/libs:/extensions`（见[运维](operations.md)） |
| 健康检查 | `/mock-server healthcheck`，每 5 秒一次，超时 3 秒 |
| 许可证 | `/licenses/`（`LICENSE`、`NOTICE`、`DASHBOARD-THIRD-PARTY-NOTICES.txt`） |

## 验证镜像

每个已发布的镜像都由 `oxidestack/mock-server` 的发布工作流用 cosign 以无密钥（keyless）方式签名，并以证明的形式
附带 SLSA 构建来源证明和每个架构的 SPDX SBOM。使用 [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
和 [GitHub CLI](https://cli.github.com/)：

```sh
cosign verify quay.io/oxidestack/mock-server:9.2.0-rc.1 \
  --certificate-identity https://github.com/oxidestack/mock-server/.github/workflows/release.yml@refs/tags/v9.2.0-rc.1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://quay.io/oxidestack/mock-server:9.2.0-rc.1 --repo oxidestack/mock-server
```

每个版本在 GitHub 上的发布页面都给出了针对其版本的相同命令，并以文件形式附带其 SBOM。

## Docker Compose

```yaml
services:
  mockserver:
    image: quay.io/oxidestack/mock-server:9.2.0-rc.1
    ports:
      - "1080:1080"
    environment:
      MOCKSERVER_LOG_LEVEL: INFO
```

任何 `mockserver.*` 属性都对应环境变量 `MOCKSERVER_<NAME>`（[配置](configuration.md)）。

## Kubernetes

项目不提供自己的 Helm chart；用户使用的是 MockServer 的 chart，通过 `image.repositoryNameAndTag` 配合本镜像运行，
容器测试用例（`make container-tests`）也是这样运行它的：

```sh
helm repo add mockserver https://www.mock-server.com
helm upgrade --install --namespace mockserver --create-namespace \
  --set image.repositoryNameAndTag=quay.io/oxidestack/mock-server:9.2.0-rc.1 \
  mockserver mockserver/mockserver
```

准入 webhook 有自己的 crate 和镜像，由 `make webhook-image` 构建（`k8s-webhook/`）；它尚未发布。

## 构建二进制文件

需要 Rust 工具链（依赖版本锁定在 `Cargo.lock` 中）和 git 子模块：

```sh
git clone --recursive https://github.com/oxidestack/mock-server.git
cd mock-server
cargo build --release
```

如果克隆时没有使用 `--recursive`，请执行一次 `git submodule update --init`。可执行文件是
`target/release/mock-server`。MockServer 仪表盘（`/mockserver/dashboard`）由 `build.rs` 嵌入二进制文件；没有 UI
包时，二进制文件对该路径返回 404。`make dashboard` 构建该包（需要 node 22 和 `upstream/mockserver` 子模块）。子模块
和 node 22 都在时，`build.rs` 会自行构建它；否则会发出警告且不嵌入任何内容（`Makefile`，目标 `dashboard`）。

启动它：

```sh
target/release/mock-server -serverPort 1080
```

命令行与 MockServer 相同（`mock-server run -p 1080` 与旧式的 `-serverPort 1080` 等价）。见[配置](configuration.md)。

## 构建容器镜像

`make image` 为本机架构构建 `Dockerfile`。镜像基于 `FROM scratch`，只包含一个二进制文件，以用户 65532 运行，并在
单独的阶段中构建仪表盘：

```sh
make image                 # tags mock-server:latest, :<MockServer version>, :mockserver-<MockServer version>
make image IMAGE=mine/mock-server
docker run --rm -p 1080:1080 mock-server:latest
```

`make image` 还会把 `clustered` 目标构建为 `clustered-latest` 和 `clustered-<version>`：同一个镜像，唯一的区别是
`MOCKSERVER_DASHBOARD_ANALYTICS_DISTRIBUTION` 的值（`Dockerfile`；集群功能本身在每个镜像中都有）。版本只发布普通
镜像。

## 在 Java 测试中使用

两种方式，都无需修改测试代码（`docs/java-launcher.md`）：

- **Testcontainers。** 对该镜像使用 `MockServerContainer`，并声明它可替代 MockServer 的镜像：
  `DockerImageName.parse("quay.io/oxidestack/mock-server:9.2.0-rc.1").asCompatibleSubstituteFor("mockserver/mockserver")`。
  `make conformance` 就是这样运行 MockServer 的 Java 客户端测试套件的。
- **在 JVM 中。** `java-launcher/` 是 `org.mock-server:mockserver-netty` 的直接替代品：`ClientAndServer`、JUnit 4 规则、
  JUnit 5 扩展和 Spring 监听器在相同的 API 之后把二进制文件作为进程启动。排除 `mockserver-netty` 并加入该 launcher；
  二进制文件的查找顺序是系统属性 `mockServer.binary`、环境变量 `MOCK_SERVER_BINARY`，然后是 `PATH` 中的
  `mock-server`。`make java-launcher` 运行它的测试并将其安装到本地 Maven 仓库；该构件尚未发布。其局限列于
  `docs/java-launcher.md`。

## 验证

```sh
curl -s -X PUT localhost:1080/mockserver/status
```

会返回一个列出监听端口的 JSON 正文。在容器中，`docker exec <name> /mock-server healthcheck` 在该请求返回 200 时以
0 退出（`src/main.rs`，`healthcheck`）。

下一步：[配置](configuration.md)、[API](api.md)、[运维](operations.md)、[故障排除](troubleshooting.md)。
