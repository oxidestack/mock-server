# Справочник API

<!-- languages:begin -->
[English](../../../guide/api.md) · **Русский** · [中文](../../zh/guide/api.md) · [Español](../../es/guide/api.md)
<!-- languages:end -->
<!-- translation of docs/guide/api.md: be145730f8e2 -->

API — это API MockServer: control plane под `/mockserver/*` и data plane, который отвечает на все остальные запросы по
созданным вами ожиданиям. Контракт — документ OpenAPI upstream, включённый без изменений в
`spec/mockserver/mockserver-openapi.yaml`; сервер отдаёт его по `GET /mockserver/openapi.yaml`. Вход control plane
проверяется по схемам upstream из `spec/mockserver/schema/` с текстом ошибок эталона. Эта страница перечисляет
типичные операции; полный справочник — сам документ, а где эталон ведёт себя иначе, чем он, прав эталон.

Клиенты на любом языке, работающие с control plane MockServer, продолжают работать без изменений. Те же
операции отвечают и по прежним коротким путям (`PUT /expectation`, `PUT /reset`, …) (`src/control.rs`).

## Создание ожиданий

```sh
curl -X PUT localhost:1080/mockserver/expectation -d '{
  "httpRequest":  {"method": "GET", "path": "/hello"},
  "httpResponse": {"statusCode": 200, "body": "world"}
}'
curl -i localhost:1080/hello
```

`PUT /mockserver/expectation` принимает одно ожидание или массив и отвечает 201 с ожиданиями в каноническом виде
эталона. Сопоставление, действия (ответ, перенаправление, обратный вызов, ошибка), число срабатываний, приоритет и
остальные поля — те же, что в схеме `expectation` upstream (`spec/mockserver/schema/expectation.json`).

Другие способы их создать: `PUT /mockserver/openapi` (из спецификации OpenAPI или Swagger), `PUT /mockserver/import`
(HAR, Postman, WireMock, Mountebank, Mockoon, записанный трафик), параметры командной строки `--init` и `--openapi`
и свойства инициализации (`initializationJsonPath`, `initializationOpenAPIPath`).

## Просмотр, проверка, очистка

| Операция | Путь | Примечания |
|---|---|---|
| Получить | `PUT /mockserver/retrieve?type=` | `requests` (по умолчанию), `request_responses`, `recorded_expectations`, `active_expectations`, `logs`, `metrics`; `format=` `json` (по умолчанию), `log_entries`, `har`, генераторы кода, экспорт |
| Проверить число запросов | `PUT /mockserver/verify` | 202, если условие выполнено, иначе 406 с описанием расхождения |
| Проверить порядок | `PUT /mockserver/verifySequence` | |
| Очистить | `PUT /mockserver/clear?type=` | `all` (по умолчанию), `log`, `expectations`; тело — сопоставитель запроса |
| Сбросить | `PUT /mockserver/reset` | удаляет все ожидания и записанные запросы |
| Порты | `PUT /mockserver/status` | JSON с прослушиваемыми портами |
| Дополнительные порты | `PUT /mockserver/bind` | |
| Остановить | `PUT /mockserver/stop` | останавливает сервер; запросы в обработке дорабатываются до `stopDrainMillis` |
| Линтер | `PUT /mockserver/lint` | сообщает об ожиданиях, которые никогда не сработают; тот же отчёт, что у `mock-server lint` |
| Конфигурация | `GET`/`PUT /mockserver/configuration` | чтение или изменение конфигурации во время работы |

Источник для каждой строки: `spec/mockserver/mockserver-openapi.yaml`, а для остановки и дорабатывания запросов —
`src/control.rs`. Семантику описывают страницы руководства `clearing_and_resetting.html`, `debugging_issues.html` и
`importing_expectations.html` в `spec/mockserver/manual/mock_server/`.

## Работоспособность и готовность

- `PUT /mockserver/status` отвечает 200 с прослушиваемыми портами, когда сервер запущен. `HEALTHCHECK` образа
  (`mock-server healthcheck`) отправляет его на первый порт из `MOCKSERVER_SERVER_PORT`, иначе из `SERVER_PORT`,
  иначе на 1080.
- `GET /mockserver/ready` отвечает 200 и `{"status":"READY"}` (`src/control.rs`).

## Метрики

При `metricsEnabled=true` сервер отвечает на `GET /mockserver/metrics` в текстовом формате Prometheus, а на
`PUT /mockserver/retrieve?type=METRICS` — теми же значениями. Семейства метрик — как у upstream, но вместо метрик
JVM (`jvm_*`) идут серии процесса, среды выполнения tokio, HTTP-сервера и соединений. При `otelMetricsEnabled` те же данные экспортируются по OTLP. Две панели Grafana
лежат в `grafana/`.

## Панель

`GET /mockserver/dashboard` отдаёт интерфейс MockServer, встроенный в бинарный файл.

## Протоколы и другие операции

Помимо HTTP/1.1 сервер говорит по HTTP/2, HTTP/3 (`http3Port`), TLS с сертификатами, выпускаемыми от CA MockServer,
gRPC (`/mockserver/grpc/*`), DNS (`dnsEnabled`, `dnsPort`), с брокерами AsyncAPI (`/mockserver/asyncapi`) и по
двоичным протоколам. В control plane есть также chaos (`serviceChaos`, `tcpChaos`, `grpcChaos`), хранилища CRUD
(`crud`), файловое хранилище (`files/*`), управление часами (`clock`), дрейф (`drift`), сценарии (`scenario`) и
конечная точка MCP (`mcp`). Каждая из них описана в документе OpenAPI или в руководстве upstream
(`spec/mockserver/manual/`); `src/control.rs` (`OPERATIONS`) — перечень того, на что отвечает сервер. В
`docs/coverage.md` и `docs/divergences.md` сказано, где поведение пока не совпадает с эталоном.

## Плагины обратных вызовов

Обратный вызов по классу (`httpResponseClassCallback`, `httpForwardClassCallback`) называет класс, который
mock-server находит через провайдеры обратных вызовов, а не через путь к классам JVM: см.
`docs/callback-plugins.md`.
