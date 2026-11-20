# Эксплуатация

<!-- languages:begin -->
[English](../../../guide/operations.md) · **Русский** · [中文](../../zh/guide/operations.md) · [Español](../../es/guide/operations.md)
<!-- languages:end -->
<!-- translation of docs/guide/operations.md: deaa667ae962 -->

Запуск mock-server: контейнер, работоспособность, память, журналы, метрики, TLS и плагины. Факты взяты из
`Dockerfile`, кода и измерений, названных в каждом разделе.

## Контейнер

Образ (`make image`, см. [Установку](installation.md)) собран `FROM scratch`: один статический бинарный файл, без
оболочки и менеджера пакетов, поэтому `docker exec <name> sh` не работает, а `docker exec <name> /mock-server healthcheck`
работает. Он запускается от пользователя `65532:65532` и слушает `SERVER_PORT=1080`. Каталог `/config` доступен этому
пользователю на запись, и именно там точка входа ищет `mockserver.properties`.

Файл свойств или JSON ожиданий монтируйте только для чтения и называйте явно:

```sh
docker run --rm -p 1080:1080 -v "$PWD/init:/init:ro" \
  -e MOCKSERVER_INITIALIZATION_JSON_PATH=/init/expectations.json quay.io/oxidestack/mock-server:9.2.0-rc.1
```

## Проверки работоспособности

- Живость и `HEALTHCHECK` образа: `PUT /mockserver/status` (200 с портами). Подкоманда `healthcheck` отправляет его
  на `localhost` на первый порт из `MOCKSERVER_SERVER_PORT`, иначе из `SERVER_PORT`, иначе на 1080, и завершается с
  кодом 0 при ответе 200 (`src/main.rs`).
- Готовность: `GET /mockserver/ready` отвечает `{"status":"READY"}` (`src/control.rs`).
- Клиент, который ждёт строку журнала, может ждать `started on port: 1080`: она по-прежнему выводится, и именно её читает стратегия ожидания Testcontainers.

## Память

Резидентная память ограничивается параметром `MOCKSERVER_MAX_LOG_ENTRIES` (`maxLogEntries`): она растёт примерно на
4,6 КиБ на каждую сохранённую запись журнала. Значение по умолчанию выводится из доступной кучи, как у MockServer, с
верхним пределом 250 000 записей. `maxEventLogSizeInBytes` здесь память не ограничивает. Задайте
`MOCKSERVER_MAX_LOG_ENTRIES` по тому, что позволяет лимит памяти контейнера. Измерения, с их машиной и
нагрузкой, — на странице [Бенчмарки](https://oxidestack.github.io/mock-server/benchmarks/).

Образ выделяет память через mimalloc (`src/main.rs`), потому что аллокатор по умолчанию в статической
сборке на musl берёт одну глобальную блокировку.

## Журналирование

`logLevel` (`MOCKSERVER_LOG_LEVEL`, `-l`, `-logLevel`) и `logLevelOverrides` определяют, какие события попадают в
журнал, как у upstream. Консоль устроена по-своему, на Rust: строка выглядит так:
`<UTC timestamp>  INFO mock_server::server: port=1080 started on port: 1080`. `RUST_LOG` фильтрует по цели, например
`RUST_LOG=mock_server=info,mock_server::matching=off`. Файлы конфигурации журналирования не читаются. Журнал
событий, который возвращает `PUT /mockserver/retrieve?type=logs`, — это журнал эталона, а не консоли.

## Метрики и панели

Задайте `MOCKSERVER_METRICS_ENABLED=true` и забирайте `GET /mockserver/metrics`; `MOCKSERVER_OTEL_METRICS_ENABLED=true`
включает экспорт по OTLP. Серии: процесс, сборка, среда выполнения tokio,
HTTP-сервер, соединения, пул перенаправления, а также собственные семейства upstream.
Две панели Grafana в `grafana/`, для сервера и для нагрузки, построены поверх них.
`scripts/verify-otlp-metrics.sh` декодирует экспорт OTLP для проверки.

## TLS

Листовые сертификаты для HTTPS и для TLS к серверу выпускаются от встроенного CA MockServer (`src/tls/`), поэтому
клиент, доверяющий ему для MockServer, доверяет ему и здесь. `--proxy-setup` (или `MOCKSERVER_PROXY_SETUP=true`)
вместо этого создаёт частный CA и выводит блок для копирования на стороне клиента. Свойства для ваших собственных
сертификатов (`privateKeyPath`, `x509CertificatePath`, `certificateAuthorityCertificate`, свойства TLS control plane)
— свойства upstream: `spec/mockserver/manual/mock_server/HTTPS_TLS.html`.

## Плагины обратных вызовов

Обратные вызовы по классам загружаются через плагины, перечисленные в `MOCKSERVER_CALLBACK_PLUGINS` (в образе —
`/libs:/extensions`). Статический образ не может загружать нативные плагины (`.so`, `.dylib`, `.dll`); плагины WASM
(`.wasm`) работают. Монтируйте их в `/libs` или `/extensions`. О каждом плагине при загрузке сообщается в stderr, а
плагин, который не загрузился, сообщается и пропускается (`docs/callback-plugins.md`).

## Кластеризация

Кластеризация (`clusterEnabled`) есть в каждом образе и говорит на протоколах JGroups и Infinispan, как у MockServer
Контейнерные сценарии `make container-tests` запускают против неё docker-compose и Helm-сценарии upstream.

## Остановка

`PUT /mockserver/stop` останавливает слушатели и даёт запросам в обработке завершиться в течение `stopDrainMillis`. `SIGTERM` (`docker stop`) завершает процесс действием по умолчанию, после того как
записаны строки консоли из очереди (`src/main.rs`); запросы он не дорабатывает.

## Обновление

Шаги для каждого выпуска описаны в разделе [Обновление](upgrading.md).
