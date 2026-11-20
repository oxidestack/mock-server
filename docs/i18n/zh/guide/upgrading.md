# 升级

<!-- languages:begin -->
[English](../../../guide/upgrading.md) · [Русский](../../ru/guide/upgrading.md) · **中文** · [Español](../../es/guide/upgrading.md)
<!-- languages:end -->
<!-- translation of docs/guide/upgrading.md: afacd85342c0 -->

如何把部署从当前运行的版本迁移到较新的版本，或从 MockServer 镜像迁移到 mock-server。找出每个比你的版本更新的版本的章节，
并从最旧的开始依次应用：从 9.2.0 升到更晚的版本，意味着先看中间每个版本的章节，再看你想要的那个版本的章节。没有需要改动之处的版本
会如此说明。然后[一步升级](#如何升级)到最新版本：从不需要先安装某个中间版本。

每个章节列出该版本对部署或客户端的要求：**Action required** 下是在升级之前或升级时要做的更改；**Deprecated** 下是仍然可用、
但会在以后的版本中停止的内容；**Removed** 下是已经停止的内容。该版本改动的其余一切见
[变更日志](https://github.com/oxidestack/mock-server/blob/main/CHANGELOG.md)。只有正式版本才有章节：候选版本（`-rc.N`）
在其 GitHub release 上说明，其改动写在发布它的正式版本之下。

你所运行版本的文档也在本站：每个页面顶部的版本选择器可以在各版本之间切换，旧版本的页面会链接到最新版本中的同一页面。

## 如何升级

mock-server 与 MockServer 一样，把期望和事件日志保存在内存中，除非你配置了持久化或录制，否则不会写入自己的任何文件。
升级只是替换容器（或二进制文件），别无其他，回滚则是用旧版本重复同样的步骤。启动时没有重新加载的期望
（`initializationJsonPath`、客户端的 `ClientAndServer` 设置）在重启后会丢失，与 MockServer 相同。

1. 阅读下面每个比你的版本更新的版本的章节，并把其中的更改应用到你的配置、环境、chart 值或客户端。
2. 替换容器：
   - `docker run` 或 Docker Compose：更改镜像的标签（`quay.io/oxidestack/mock-server:<version>`）并重新启动
     （`docker compose up -d`）。端口（`1080`）、环境变量、命令行参数和 `/config` 布局都与 MockServer 镜像相同。
   - Testcontainers：更改传给 `MockServerContainer` 的镜像名（通过 `asCompatibleSubstituteFor` 声明它与
     `mockserver/mockserver` 兼容）。
   - Helm：使用上游的 MockServer chart，把 `image.repositoryNameAndTag` 设为新镜像，并使用你自己的 values 文件；没有单独的 chart。
3. 观察最初几分钟：容器的健康检查、最初几个请求的状态，以及（如果你抓取它的话）`/mockserver/metrics`。要回滚，用你原来的版本重复第 2 步。

如果你来自 Java 的 MockServer 镜像，请先对你的配置、compose 文件、Helm values 和测试源码运行 `mock-server migrate`：它会报告每个需要
更改的设置或构建文件，`--write` 会应用其中的机械性改动。

## 升级到 X.Y.Z（首个版本，版本号和日期尚未确定）

<!-- Placeholder: replace "X.Y.Z" in this heading and the Unreleased heading of CHANGELOG.md with the first release's
     number when it is cut (tags follow upstream; the first is expected to be 9.2.0). Every later release gets its
     own section above this one. -->

mock-server 的首个版本：MockServer 9.2.0 镜像的直接替代品。控制面、数据面和客户端（Java、Node、Python、Ruby、原生 REST）
在网络协议层面的行为与 9.2.0 镜像一致，包括 `version` 头，因此为 MockServer 9.2.0 构建的客户端无需任何更改。与该镜像的差异
列于 [`docs/divergences.md`](https://github.com/oxidestack/mock-server/blob/main/docs/divergences.md)，它是权威清单；
下面是部署必须采取行动的那些。

### Action required

- **JavaScript 模板。** `JAVASCRIPT` 响应模板会失败，与没有 GraalJS 的标准 MockServer 镜像一样。mock-server 从不附带 JavaScript
  引擎；请用 Velocity 或 Mustache 重写这类模板。运行过 `graaljs` 镜像变体的部署必须这样做，因为不存在这个变体。
- **从类路径加载的 Java 类。** 在 MockServer 镜像上，回调类（`httpResponseClassCallback`、`httpForwardClassCallback`）、
  `initializationClass` 和服务器扩展来自 `/libs` 或 `/extensions` 中的 jar。这里没有类路径：放在那里的 jar 会在警告中被点名并被忽略，
  回调或初始化器由回调插件提供（原生或 WASM；`MOCKSERVER_CALLBACK_PLUGINS`）。依赖这类类的部署在迁移之前需要一个插件。
- **JVM 设置。** `JAVA_TOOL_OPTIONS`、`JAVA_OPTS`、`MOCKSERVER_JAVA_OPTS`、线程池数量和 `javascript*` 键都没有作用；服务器在启动时
  写一行 WARN 指出它们。内存由容器的限制以及 `maxExpectations` 和 `maxLogEntries`（每保留一条日志条目约 4.6 KiB 常驻内存）限定：
  请把这些变量中的 `-Dmockserver.<key>=<value>` 迁移到 `MOCKSERVER_<KEY>` 或属性文件。`mock-server migrate` 会完成这一改写。
- **基于 JVM 指标构建的仪表盘和告警。** `/mockserver/metrics` 提供 Prometheus 标准进程收集器的 `process_*` 序列和
  一个 `*_build_info` 序列，取代 `jvm_gc_*`、`jvm_memory_*` 和 `jvm_threads_*`；`mock_server_*` 的请求和混沌序列与上游相同。
  请修改读取 `jvm_*` 序列的任何面板或告警。

### Deprecated

无。

### Removed

- 镜像变体 `graaljs`、`snapshot`、`root`、`root-snapshot`、`local`、`aot` 和 `clustered`：每个版本只发布一个镜像，
  覆盖两个平台。集群功能就在其中；MockServer 的 `clustered` 镜像与普通镜像的区别仅在于
  `MOCKSERVER_DASHBOARD_ANALYTICS_DISTRIBUTION` 的值。
- `mockserver-war` 和 `mockserver-proxy-war` Tomcat 包：请把容器运行在 servlet 容器旁边。
- 向上游 PostHog 项目发送仪表盘分析：镜像中的 `MOCKSERVER_DASHBOARD_ANALYTICS_ENDPOINT` 和
  `MOCKSERVER_DASHBOARD_ANALYTICS_KEY` 为空，所以除非你把两者都设置，否则不会发送任何分析数据。
- JVM 的控制台日志格式：控制台行是 Rust 原生的（`tracing`），但 Testcontainers 等待策略所读取的行（`started on port: 1080`）
  予以保留。事件日志（`retrieve?type=LOGS`、`LOG_ENTRIES`、仪表盘）不变。解析其他控制台行的流水线需要新的匹配模式。
