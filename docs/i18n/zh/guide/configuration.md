# 配置

<!-- languages:begin -->
[English](../../../guide/configuration.md) · [Русский](../../ru/guide/configuration.md) · **中文** · [Español](../../es/guide/configuration.md)
<!-- languages:end -->
<!-- translation of docs/guide/configuration.md: f513115c0a70 -->

mock-server 读取 MockServer 的配置：相同的属性名、环境变量、命令行和属性文件。本页与基准（oracle，即 `oracle.env` 中
固定的 MockServer 镜像）不一致时，以基准为准。属性参考以上游为准：
`spec/mockserver/manual/mock_server/configuration_properties.html`（Apache-2.0，上游自己的页面）。

## 值是如何读取的

属性 `mockserver.fooBarBaz` 同时也是环境变量 `MOCKSERVER_FOO_BAR_BAZ`（`src/config.rs` 中的 `env_name`；少数名称是例外，
`src/effective_config_properties.txt` 列出了每个属性及其环境变量）。值可以来自以下来源（普通属性在它们之间的优先级与
上游相同，见上面的手册页面；下面四项设置按所述方式解析）：

1. 命令行（`-p`、`-serverPort`、`-D<key>=<value>` ……）；
2. 系统属性选项 `-Dmockserver.<name>=<value>`；
3. 环境变量 `MOCKSERVER_<NAME>`；
4. 属性文件（见下）。

对于启动器自己解析的设置，即 `serverPort`、`proxyRemoteHost`、`proxyRemotePort` 和 `logLevel`，`src/config.rs`
（`cli_owned`）中的顺序是：命令行选项、系统属性、`MOCKSERVER_<NAME>`、简短的环境变量名（`SERVER_PORT`、
`PROXY_REMOTE_HOST`、`PROXY_REMOTE_PORT`、`LOG_LEVEL`），最后是属性文件。空白值视为未设置。镜像设置 `SERVER_PORT=1080`，
属性文件中的 `mockserver.serverPort` 会覆盖它。

要查看某条命令行和环境最终解析成什么，请加上 `--print-config` 运行：服务器打印生效的配置，每个属性一行
`name = value   [source]`，然后退出，不开始监听。

```sh
MOCKSERVER_MAX_LOG_ENTRIES=100000 mock-server --print-config
```

服务器不认识的键，按上游的方式报告（`findUnknownConfigurationKeys`）。

## 命令行

二进制文件具有 MockServer 的 picocli 命令树（`src/cli_usage/`）。下面的用法文本来自基准：

| 命令 | 作用 |
|---|---|
| `run`（默认） | 启动服务器：`-p/--port`、`-l/--log-level`、`--init`、`--openapi`、`--persist`、`--proxy-to`、`--validate-openapi`、`--validate-enforce`、`--watch`、`--dev`、`--proxy-setup`、`-D<key>=<value>` |
| `ui` | 启动并在浏览器中打开仪表盘 |
| `proxy --to <host[:port]>` | 以端口转发模式启动 |
| `openapi <spec>` | 用 OpenAPI 规范中的期望（expectation）启动 |
| `import <file> -p <port>` | 把 JSON 文件中的期望加载到运行中的服务器（用 `-H` 指定主机） |
| `lint <file>...` | 检查期望 JSON 中永远无法匹配的期望；`--json`、`--strict`；不需要服务器 |
| `demo` | 带几个示例期望启动 |
| `version`、`help` | |

旧式标志 `-serverPort`、`-proxyRemotePort`、`-proxyRemoteHost` 和 `-logLevel` 仍然有效。有两个命令是我们自己的，不在该命令树
之内：`mock-server healthcheck`（镜像的健康检查）和 `mock-server migrate`（找出仓库中依赖 MockServer 的 JVM 打包方式
的内容，并应用机械性的改写；`src/migrate/`）。

## 属性文件

由 `mockserver.propertyFile` 或 `MOCKSERVER_PROPERTY_FILE` 指定的文件在启动时读取（默认是工作目录中的
`mockserver.properties`；镜像把它指向 `/config/mockserver.properties`，该目录由镜像创建，归服务器用户所有）。以 `.json`
结尾的文件按 JSON 读取。运维人员指定的文件若无法读取，会在启动时报告（`src/config.rs`，`load_property_file`）。属性文件
从不提供 `logLevel`；JSON 文件可以。

## 限制内存的属性

`maxLogEntries` 和 `maxExpectations`（`MOCKSERVER_MAX_LOG_ENTRIES`、`MOCKSERVER_MAX_EXPECTATIONS`）限制事件日志和所保留的期望
数量。它们的默认值与上游一样由可用堆内存推导而来，并有上限（250,000 条日志条目；`src/config.rs` 中的
`default_max_log_entries`）。`--dev` 把二者都降到 1,000。[运维](operations.md#内存)说明了对常驻内存的影响。

## Rust 原生的设置

服务器把每一个仅限 JVM 的输入分为支持、映射、警告和拒绝四类：

- 服务器不读取 `JAVA_TOOL_OPTIONS` 中的 `-Dmockserver.<key>`（`migrate` 会把它改写为环境变量）。`-Xmx`、`-Xms`、
  `-XX:*RAMPercentage` 及其他 JVM 标志没有作用；出现这类设置时，服务器在启动时打印一行 WARN 指出它们。
- `nioEventLoopThreadCount` 设置工作线程数；未设置时，等于可用核心数。
- `useNativeTransport` 和 `javascript*` 设置会被接受，但没有作用（差异记录在 `docs/divergences.md`）。
- 日志配置文件（`logback.xml`、`logging.properties`）没有对应物；级别来自 `logLevel` 和 `logLevelOverrides`。控制台是
  Rust 原生的：`RUST_LOG` 过滤事件（`src/log.rs`）。

## 插件

`mockserver.callbackPlugins`（`MOCKSERVER_CALLBACK_PLUGINS`）列出提供类回调的插件文件和目录，像类路径那样用分隔符隔开
（`docs/callback-plugins.md`）。Docker 镜像把它设为 `/libs:/extensions`。

## 仪表盘分析

仪表盘分析默认关闭：镜像中的 `MOCKSERVER_DASHBOARD_ANALYTICS_ENDPOINT` 和 `MOCKSERVER_DASHBOARD_ANALYTICS_KEY` 为空，
项目从不向上游的账号发送数据。
