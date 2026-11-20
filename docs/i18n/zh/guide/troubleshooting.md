# 故障排查

<!-- languages:begin -->
[English](../../../guide/troubleshooting.md) · [Русский](../../ru/guide/troubleshooting.md) · **中文** · [Español](../../es/guide/troubleshooting.md)
<!-- languages:end -->
<!-- translation of docs/guide/troubleshooting.md: 157b402a3de1 -->

每一条都是本仓库能够解释的一种症状。如果你看到的行为与 MockServer 不同，那是缺陷或已列出的差异：请查看
`docs/divergences.md`，并与基准（`oracle.env` 中固定的镜像）对比，二者不一致时以基准为准。

## 服务器无法启动

**需要 `-p` 或端口。** `mock-server run` 需要来自 `-p`、`MOCKSERVER_SERVER_PORT`、`mockserver.serverPort` 或属性文件的端口
（`src/cli_usage/run.txt`）。镜像设置 `SERVER_PORT=1080`。

**指定了属性文件但无法读取。** 由 `mockserver.propertyFile` 或 `MOCKSERVER_PROPERTY_FILE` 指定却无法读取的文件会在启动时报告；
默认的 `mockserver.properties` 只在存在时才读取（`src/config.rs`，`load_property_file`）。

**启动时关于未知键或仅限 JVM 的设置的提示。** 未知的 `mockserver.*` 或 `MOCKSERVER_*` 键按上游的方式报告。
`JVM-only settings have no effect in mock-server: [...]` 点出被接受但被忽略的 JVM 标志（`-Xmx`、`JAVA_TOOL_OPTIONS` 等）：
内存由容器限制和 `maxLogEntries` 限定。

## 健康检查失败

`mock-server healthcheck` 连接 `localhost` 上 `MOCKSERVER_SERVER_PORT` 的第一个端口，否则是 `SERVER_PORT`，否则是 1080。
服务器监听其他端口时检查会失败：把 `SERVER_PORT`（或 `MOCKSERVER_SERVER_PORT`）设为服务器实际监听的端口（`src/main.rs`）。

## 内存持续增长

在达到 `maxLogEntries` 之前，每保留一条日志条目，常驻内存约增加 4.6 KiB。请把 `MOCKSERVER_MAX_LOG_ENTRIES` 设低一些
（[运维](operations.md#内存)）。`maxEventLogSizeInBytes` 并不限制它。

## `/mockserver/dashboard` 返回 404

二进制文件是在没有 UI 包的情况下构建的。`make dashboard`（node 22，`upstream/mockserver` 子模块）把它构建到 `dashboard/`，
下一次构建会嵌入它；镜像在自己的阶段中构建它（`Makefile`、`Dockerfile`）。

## 类回调失败

mock-server 不加载 Java 类。类回调的名称通过回调插件解析（`MOCKSERVER_CALLBACK_PLUGINS`）：进程内注册、原生插件或
WASM 插件。静态镜像无法加载原生插件，插件目录中的 `.jar` 会在 stderr 上报告且不会加载（`Dockerfile`、
`docs/callback-plugins.md`）。`initializationClass` 是 Java 类，同样无法加载。JavaScript 模板的失败方式与基准完全
相同，基准没有 GraalJS。

## 转发到服务器自身永不返回

目标是其自身路径的转发会在 MockServer 内部循环，基准也是如此；`reset` 之后它仍会继续写日志。请重启服务器，并把转发指向
其他主机或路径。

## 在 Java 测试中

- **launcher 找不到二进制文件。** 启动失败，消息中列出它查找过的三个位置：系统属性 `mockServer.binary`、
  `MOCK_SERVER_BINARY`、`PATH` 中的 `mock-server`（`docs/java-launcher.md`）。
- **`mockserver-netty-no-dependencies` jar 仍然启动 JVM 内的服务器。** 这些打包（shaded）的 jar 内含上游的
  `ClientAndServer`；请使用未打包的模块并排除 `mockserver-netty`（`docs/java-launcher.md`）。
- **JVM 死亡后仍有进程在运行。** 被 `SIGKILL` 杀死的 JVM 不会运行关闭钩子，所以启动的进程会留下来
  （`docs/java-launcher.md`）。
- **`UnsupportedOperationException: in-JVM: ...`。** 该方法读取的是 JVM 内服务器的内部状态，而进程没有这些
  （`registerListener`、`setLogEventListener`、`getScheduler` 以及 `docs/java-launcher.md` 中的其他方法）。
- **Testcontainers 不接受该镜像。** 把它声明为替代品：
  `DockerImageName.parse(...).asCompatibleSubstituteFor("mockserver/mockserver")`（`conformance/java/.../Images.java`）。

## 行为与 MockServer 不同

1. 用相同的请求在基准上重现它。如果基准的响应相同，那就不是差异。
2. 在 `docs/divergences.md` 和 `docs/coverage.md` 中查找已知的条目。
3. 否则它就是缺陷：项目的测试把基准的响应记录为 golden 场景（`tests/scenarios/`），附有请求和两边响应的缺陷报告会成为这样的场景。

问题请先到 [DeepWiki](https://deepwiki.com/oxidestack/mock-server)，它根据代码和文档作答（两者不一致时以文档为准），再到
[Discussions](https://github.com/oxidestack/mock-server/discussions)；缺陷请提交到 [issues](https://github.com/oxidestack/mock-server/issues)。
