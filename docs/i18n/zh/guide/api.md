# API 参考

<!-- languages:begin -->
[English](../../../guide/api.md) · [Русский](../../ru/guide/api.md) · **中文** · [Español](../../es/guide/api.md)
<!-- languages:end -->
<!-- translation of docs/guide/api.md: be145730f8e2 -->

API 就是 MockServer 的 API：`/mockserver/*` 下的控制面，以及数据面——它根据你创建的期望（expectation）回答所有其他请求。
契约是上游的 OpenAPI 文档，原样收录于 `spec/mockserver/mockserver-openapi.yaml`，服务器通过 `GET /mockserver/openapi.yaml`
提供它。控制面的输入依据 `spec/mockserver/schema/` 中上游的模式校验，错误文本与基准一致。本页列出常见操作；完整参考是该文档
本身，而基准的行为与它不同时，以基准为准。

任何语言中与 MockServer 控制面通信的客户端无需修改即可工作。同样的操作也在旧式的裸路径（`PUT /expectation`、
`PUT /reset` 等）上响应（`src/control.rs`）。

## 创建期望

```sh
curl -X PUT localhost:1080/mockserver/expectation -d '{
  "httpRequest":  {"method": "GET", "path": "/hello"},
  "httpResponse": {"statusCode": 200, "body": "world"}
}'
curl -i localhost:1080/hello
```

`PUT /mockserver/expectation` 接受一个期望或一个数组，并返回 201，正文是基准的规范形式的期望。匹配、动作（响应、转发、
回调、错误）、次数、优先级和其他字段都是上游 `expectation` 模式（`spec/mockserver/schema/expectation.json`）中的那些。

创建期望的其他方式：`PUT /mockserver/openapi`（来自 OpenAPI 或 Swagger 规范）、`PUT /mockserver/import`（HAR、Postman、
WireMock、Mountebank、Mockoon、录制的流量）、命令行选项 `--init` 和 `--openapi`，以及初始化属性
（`initializationJsonPath`、`initializationOpenAPIPath`）。

## 查看、验证、清除

| 操作 | 路径 | 说明 |
|---|---|---|
| 检索 | `PUT /mockserver/retrieve?type=` | `requests`（默认）、`request_responses`、`recorded_expectations`、`active_expectations`、`logs`、`metrics`；`format=` 取 `json`（默认）、`log_entries`、`har`、代码生成器、导出 |
| 验证请求次数 | `PUT /mockserver/verify` | 满足时返回 202，否则返回 406 并附带不匹配信息 |
| 验证顺序 | `PUT /mockserver/verifySequence` | |
| 清除 | `PUT /mockserver/clear?type=` | `all`（默认）、`log`、`expectations`；正文是请求匹配器 |
| 重置 | `PUT /mockserver/reset` | 清除所有期望和已记录的请求 |
| 端口 | `PUT /mockserver/status` | 正在监听的端口的 JSON |
| 更多端口 | `PUT /mockserver/bind` | |
| 停止 | `PUT /mockserver/stop` | 停止服务器；处理中的请求最多排空 `stopDrainMillis` |
| Lint | `PUT /mockserver/lint` | 报告永远无法匹配的期望；与 `mock-server lint` 的报告相同 |
| 配置 | `GET`/`PUT /mockserver/configuration` | 在运行时读取或更改配置 |

每一行的来源：`spec/mockserver/mockserver-openapi.yaml`，停止与排空行为见 `src/control.rs`。其语义由
`spec/mockserver/manual/mock_server/` 下的手册页面 `clearing_and_resetting.html`、`debugging_issues.html` 和
`importing_expectations.html` 描述。

## 健康与就绪

- 服务器启动后，`PUT /mockserver/status` 返回 200 及正在监听的端口。镜像的 `HEALTHCHECK`（`mock-server healthcheck`）
  把它发往 `MOCKSERVER_SERVER_PORT` 的第一个端口，否则是 `SERVER_PORT`，否则是 1080。
- `GET /mockserver/ready` 返回 200 和 `{"status":"READY"}`（`src/control.rs`）。

## 指标

当 `metricsEnabled=true` 时，服务器以 Prometheus 文本格式响应 `GET /mockserver/metrics`，`PUT /mockserver/retrieve?type=METRICS`
返回同样的计数。指标族与上游相同，只是 JVM 的指标（`jvm_*`）被进程、tokio 运行时、HTTP 服务器和连接的序列取代。启用 `otelMetricsEnabled` 后，同样的数据通过 OTLP 导出。`grafana/` 中有两个 Grafana 仪表盘。

## 仪表盘

`GET /mockserver/dashboard` 提供嵌入在二进制文件中的 MockServer UI。

## 协议与其他操作

除 HTTP/1.1 之外，服务器还支持 HTTP/2、HTTP/3（`http3Port`）、使用由 MockServer 的 CA 签发的证书的 TLS、
gRPC（`/mockserver/grpc/*`）、DNS（`dnsEnabled`、`dnsPort`）、AsyncAPI 消息代理（`/mockserver/asyncapi`）以及二进制协议。
控制面还有混沌注入（`serviceChaos`、`tcpChaos`、`grpcChaos`）、CRUD 存储（`crud`）、文件存储（`files/*`）、时钟控制
（`clock`）、漂移（`drift`）、场景（`scenario`）和 MCP 端点（`mcp`）。每一项都在 OpenAPI 文档或上游手册
（`spec/mockserver/manual/`）中；`src/control.rs`（`OPERATIONS`）是服务器响应的清单。`docs/coverage.md` 和
`docs/divergences.md` 说明了哪些行为尚未与基准一致。

## 回调插件

类回调（`httpResponseClassCallback`、`httpForwardClassCallback`）指定一个类名，mock-server 通过回调提供者而不是 JVM 类路径
来解析它：参见 `docs/callback-plugins.md`。
