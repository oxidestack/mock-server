# Конфигурация

<!-- languages:begin -->
[English](../../../guide/configuration.md) · **Русский** · [中文](../../zh/guide/configuration.md) · [Español](../../es/guide/configuration.md)
<!-- languages:end -->
<!-- translation of docs/guide/configuration.md: f513115c0a70 -->

mock-server читает конфигурацию MockServer: те же имена свойств, переменные окружения, командную строку и файл
свойств. Где эта страница и эталон (oracle, образ MockServer, закреплённый в `oracle.env`) расходятся, прав эталон.
Справочник по свойствам — это справочник upstream: `spec/mockserver/manual/mock_server/configuration_properties.html`
(Apache-2.0, страница самого upstream).

## Как читается значение

Свойство `mockserver.fooBarBaz` — это также переменная окружения `MOCKSERVER_FOO_BAR_BAZ` (`env_name` в
`src/config.rs`; у нескольких имён есть исключения, а `src/effective_config_properties.txt` перечисляет каждое
свойство с его переменной окружения). Значение может прийти из следующих источников (старшинство среди них для
обычного свойства — как у upstream, на странице руководства выше; четыре настройки ниже разрешаются так, как сказано):

1. командная строка (`-p`, `-serverPort`, `-D<key>=<value>` …);
2. параметр системного свойства `-Dmockserver.<name>=<value>`;
3. переменная окружения `MOCKSERVER_<NAME>`;
4. файл свойств (ниже).

Для настроек, которые разрешает сам запускатель, — `serverPort`, `proxyRemoteHost`, `proxyRemotePort` и `logLevel` —
порядок в `src/config.rs` (`cli_owned`) такой: параметр командной строки, системное свойство, `MOCKSERVER_<NAME>`,
короткое имя переменной окружения (`SERVER_PORT`, `PROXY_REMOTE_HOST`, `PROXY_REMOTE_PORT`, `LOG_LEVEL`), затем файл
свойств. Пустое значение считается незаданным. Образ задаёт `SERVER_PORT=1080`, а он уступает `mockserver.serverPort`
из файла свойств.

Чтобы увидеть, что получается из конкретной командной строки и окружения, запустите её с `--print-config`: сервер
выводит действующую конфигурацию, по строке `name = value   [source]` на свойство, и завершается, не начав слушать порт.

```sh
MOCKSERVER_MAX_LOG_ENTRIES=100000 mock-server --print-config
```

Неизвестные серверу ключи сообщаются так же, как сообщает upstream (`findUnknownConfigurationKeys`).

## Командная строка

У бинарного файла то же дерево команд picocli, что у MockServer (`src/cli_usage/`). Текст справки ниже взят у эталона:

| Команда | Что делает |
|---|---|
| `run` (по умолчанию) | запускает сервер: `-p/--port`, `-l/--log-level`, `--init`, `--openapi`, `--persist`, `--proxy-to`, `--validate-openapi`, `--validate-enforce`, `--watch`, `--dev`, `--proxy-setup`, `-D<key>=<value>` |
| `ui` | запускает сервер и открывает панель в браузере |
| `proxy --to <host[:port]>` | запускает сервер в режиме перенаправления портов |
| `openapi <spec>` | запускает сервер с ожиданиями (expectations) из спецификации OpenAPI |
| `import <file> -p <port>` | загружает ожидания из файла JSON в запущенный сервер (`-H` для хоста) |
| `lint <file>...` | проверяет JSON ожиданий на такие, что никогда не сработают; `--json`, `--strict`; сервер не нужен |
| `demo` | запускает сервер с несколькими примерами ожиданий |
| `version`, `help` | |

Прежние флаги `-serverPort`, `-proxyRemotePort`, `-proxyRemoteHost` и `-logLevel` по-прежнему работают. Две команды
наши и стоят вне этого дерева: `mock-server healthcheck` (проверка работоспособности образа) и
`mock-server migrate` (находит в репозитории то, что зависит от JVM-упаковки MockServer, и применяет механические
правки; `src/migrate/`).

## Файл свойств

Файл, названный в `mockserver.propertyFile` или `MOCKSERVER_PROPERTY_FILE`, читается при запуске (по умолчанию
`mockserver.properties` в рабочем каталоге; образ указывает на `/config/mockserver.properties`, каталог, который
создаёт образ и которым владеет пользователь сервера). Файл с именем на `.json` читается как JSON. О нечитаемом файле,
который назвал оператор, сообщается при запуске (`src/config.rs`, `load_property_file`). Файл свойств никогда не
задаёт `logLevel`; файл JSON может.

## Свойства, ограничивающие память

`maxLogEntries` и `maxExpectations` (`MOCKSERVER_MAX_LOG_ENTRIES`, `MOCKSERVER_MAX_EXPECTATIONS`) ограничивают журнал
событий и число хранимых ожиданий. Их значения по умолчанию выводятся из доступной кучи, как у upstream, с верхним
пределом (250 000 записей журнала; `default_max_log_entries` в `src/config.rs`). `--dev` снижает оба до 1 000. Последствия для
резидентной памяти описывает [Эксплуатация](operations.md#память).

## Настройки, свойственные Rust

Сервер разносит каждый вход, существующий только в JVM, на четыре категории: поддержать, отобразить, предупредить и
отклонить:

- `-Dmockserver.<key>` внутри `JAVA_TOOL_OPTIONS` сервер не читает (`migrate` переписывает его в переменную
  окружения). `-Xmx`, `-Xms`, `-XX:*RAMPercentage` и другие флаги JVM не действуют; когда такие настройки есть, сервер
  при запуске выводит одну строку WARN с их перечнем.
- `nioEventLoopThreadCount` задаёт число рабочих потоков; если не задан, оно равно числу доступных ядер.
- Настройки `useNativeTransport` и `javascript*` принимаются и не действуют (расхождение описано в
  `docs/divergences.md`).
- Файлов конфигурации журналирования (`logback.xml`, `logging.properties`) аналога нет; уровни берутся из `logLevel`
  и `logLevelOverrides`. Консоль устроена по-своему, на Rust: `RUST_LOG` фильтрует события (`src/log.rs`).

## Плагины

`mockserver.callbackPlugins` (`MOCKSERVER_CALLBACK_PLUGINS`) перечисляет файлы и каталоги плагинов, дающих обратные
вызовы по классам, через разделитель, как в пути к классам (`docs/callback-plugins.md`). Образ Docker задаёт его как
`/libs:/extensions`.

## Аналитика панели

Аналитика панели по умолчанию выключена: `MOCKSERVER_DASHBOARD_ANALYTICS_ENDPOINT` и
`MOCKSERVER_DASHBOARD_ANALYTICS_KEY` в образе пусты, и проект никогда не отправляет данные в учётную запись upstream.
