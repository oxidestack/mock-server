# Устранение неполадок

<!-- languages:begin -->
[English](../../../guide/troubleshooting.md) · **Русский** · [中文](../../zh/guide/troubleshooting.md) · [Español](../../es/guide/troubleshooting.md)
<!-- languages:end -->
<!-- translation of docs/guide/troubleshooting.md: 157b402a3de1 -->

Каждая запись — это симптом, который можно объяснить по этому репозиторию. Если наблюдаемое поведение отличается от
поведения MockServer, это ошибка или записанное расхождение: загляните в `docs/divergences.md` и сравните с эталоном
(образом, закреплённым в `oracle.env`), который прав, когда они расходятся.

## Сервер не запускается

**Требуется `-p` или порт.** `mock-server run` нужен порт из `-p`, `MOCKSERVER_SERVER_PORT`,
`mockserver.serverPort` или файла свойств (`src/cli_usage/run.txt`). Образ задаёт `SERVER_PORT=1080`.

**Файл свойств назван, но не читается.** О файле, названном в `mockserver.propertyFile` или
`MOCKSERVER_PROPERTY_FILE`, который не удаётся прочитать, сообщается при запуске; `mockserver.properties` по умолчанию
читается, только если он есть (`src/config.rs`, `load_property_file`).

**Сообщение при запуске о неизвестных ключах или настройках, существующих только в JVM.** О неизвестном ключе
`mockserver.*` или `MOCKSERVER_*` сообщается так же, как у upstream. `JVM-only settings have no effect in mock-server: [...]`
называет флаги JVM (`-Xmx`, `JAVA_TOOL_OPTIONS`, …), которые принимаются и игнорируются: память ограничивают лимит
контейнера и `maxLogEntries`.

## Проверка работоспособности не проходит

`mock-server healthcheck` подключается к `localhost` на первый порт из `MOCKSERVER_SERVER_PORT`, иначе из
`SERVER_PORT`, иначе на 1080. Сервер на другом порту проверку не проходит: задайте `SERVER_PORT` (или
`MOCKSERVER_SERVER_PORT`) равным порту, который слушает сервер (`src/main.rs`).

## Растёт память

Резидентная память растёт примерно на 4,6 КиБ на каждую сохранённую запись журнала, пока не достигнут `maxLogEntries`.
Задайте `MOCKSERVER_MAX_LOG_ENTRIES` меньше ([Эксплуатация](operations.md#память)). `maxEventLogSizeInBytes` её не
ограничивает.

## `/mockserver/dashboard` отвечает 404

Бинарный файл собран без пакета UI. `make dashboard` (node 22, подмодуль `upstream/mockserver`) собирает его в
`dashboard/`, и следующая сборка его встраивает; образ собирает его в своей отдельной стадии (`Makefile`, `Dockerfile`).

## Обратный вызов по классу не работает

mock-server не загружает классы Java. Имя класса обратного вызова разрешается через плагины обратных вызовов
(`MOCKSERVER_CALLBACK_PLUGINS`): регистрацию внутри процесса, нативный плагин или плагин WASM. Статический образ не
может загружать нативные плагины, а `.jar`, названный в каталоге плагинов, сообщается в stderr и не загружается
(`Dockerfile`, `docs/callback-plugins.md`). `initializationClass` — класс Java, и его тоже нельзя загрузить.
Шаблоны JavaScript падают точно так же, как в эталоне, где нет GraalJS.

## Перенаправление на сам сервер не возвращается

Перенаправление, целью которого служит его собственный путь, зацикливается внутри MockServer, и эталон тоже; он
продолжает писать в журнал и после `reset`. Перезапустите сервер и направьте перенаправление на другой хост или путь.

## Из Java-тестов

- **Лаунчер не находит бинарный файл.** Запуск завершается сообщением с тремя местами, где он искал: системное
  свойство `mockServer.binary`, `MOCK_SERVER_BINARY`, `mock-server` в `PATH` (`docs/java-launcher.md`).
- **JAR `mockserver-netty-no-dependencies` по-прежнему запускает сервер внутри JVM.** Эти упакованные JAR содержат
  `ClientAndServer` upstream; используйте неупакованный модуль и исключите `mockserver-netty`
  (`docs/java-launcher.md`).
- **После гибели JVM остаётся запущенный процесс.** JVM, убитая сигналом `SIGKILL`, не запускает свои обработчики
  завершения, и запущенный процесс остаётся (`docs/java-launcher.md`).
- **`UnsupportedOperationException: in-JVM: ...`.** Метод читает внутренности сервера, работающего внутри JVM, а у
  процесса их нет (`registerListener`, `setLogEventListener`, `getScheduler` и другие в `docs/java-launcher.md`).
- **Testcontainers не принимает образ.** Объявите его заменой:
  `DockerImageName.parse(...).asCompatibleSubstituteFor("mockserver/mockserver")` (`conformance/java/.../Images.java`).

## Поведение отличается от MockServer

1. Воспроизведите его на эталоне тем же запросом. Если эталон отвечает так же, это не расхождение.
2. Поищите известную строку в `docs/divergences.md` и `docs/coverage.md`.
3. Иначе это ошибка: тесты проекта записывают ответ эталона как golden-сценарий (`tests/scenarios/`), а отчёт об
   ошибке с запросом и обоими ответами становится таким сценарием.

Вопросы — сначала в [DeepWiki](https://deepwiki.com/oxidestack/mock-server), который отвечает по коду и документации (где они расходятся, права
документация), затем в [Discussions](https://github.com/oxidestack/mock-server/discussions); ошибки — в [issues](https://github.com/oxidestack/mock-server/issues).
