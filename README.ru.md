# mock-server

<!-- languages:begin -->
[English](README.md) · **Русский** · [中文](README.zh-CN.md) · [Español](README.es.md)
<!-- languages:end -->
<!-- translation of README.md: cc9078521959 -->

Замена [MockServer](https://www.mock-server.com) без изменений в клиентах (drop-in), написанная на Rust. Она отвечает
на REST API MockServer и принимает его командную строку, переменные окружения и свойства так же, как образ
MockServer 9.2.0, поэтому клиенты (Java, Node, Python, Ruby, чистый REST), модули Testcontainers и Helm-чарт, которые
управляют MockServer, управляют и ею — меняется только имя образа. Один статический исполняемый файл, без JVM.

> **Ещё не опубликовано.** Образ и сайт документации названы здесь так, как они будут называться с первого выпуска,
> `v9.2.0-rc.1`. Пока он не вышел, соберите образ из исходников ([Сборка и тесты](#сборка-и-тесты)).

**Документация: [oxidestack.github.io/mock-server](https://oxidestack.github.io/mock-server/)**

## Быстрый старт

```sh
docker run --rm -p 1080:1080 quay.io/oxidestack/mock-server:9.2.0-rc.1
```

В другом терминале, когда он запустится:

```sh
curl -X PUT localhost:1080/mockserver/expectation -d '{
  "httpRequest":  {"method": "GET", "path": "/hello"},
  "httpResponse": {"statusCode": 200, "body": "world"}
}'
curl -i localhost:1080/hello                              # 200, world
```

Панель (dashboard) — по адресу `http://localhost:1080/mockserver/dashboard`. Каждый выпуск подписан и несёт свои
SBOM и происхождение сборки (provenance); [Проверка образа](docs/i18n/ru/guide/installation.md#проверка-образа)
проверяет его с помощью `cosign` и `gh attestation verify`.

## Что он даёт

- **Замена без изменений.** Клиент, работающий с управляющим API MockServer `/mockserver/*`, работает без изменений,
  с командной строкой, переменными окружения, свойствами и раскладкой `/config` MockServer. Эталон — образ
  MockServer, закреплённый в `oracle.env`: где он и любой здешний документ расходятся, прав он, а где поведение пока
  не идентично, это сказано в [`docs/divergences.md`](docs/divergences.md).
- **Один статический исполняемый файл.** Ни JVM, ни сборщика мусора; образ контейнера — `FROM scratch`, для
  `linux/amd64` и `linux/arm64`, запускается не от root. Память ограничивается `MOCKSERVER_MAX_LOG_ENTRIES`
  ([Эксплуатация](docs/i18n/ru/guide/operations.md#память)), а страница
  [Бенчмарки](https://oxidestack.github.io/mock-server/benchmarks/) сравнивает его с образом MockServer под той же
  нагрузкой.
- **Не только HTTP/1.1.** HTTP/2, HTTP/3, TLS, gRPC, DNS, брокеры AsyncAPI, проксирование, chaos, кластеризация и
  панель MockServer ([Справочник API](docs/i18n/ru/guide/api.md)).
- **Для тестов на Java.** Testcontainers с образом или `java-launcher/` — замена `mockserver-netty`, которая
  запускает исполняемый файл за `ClientAndServer` и интеграциями JUnit и Spring
  ([Установка](docs/i18n/ru/guide/installation.md#из-тестов-на-java)).

## Документация

Руководство опубликовано на [oxidestack.github.io/mock-server](https://oxidestack.github.io/mock-server/): последний
выпуск — в корне, каждый выпуск — под своей версией; те же страницы в том виде, в каком они есть в `main`, лежат в
`docs/guide/` (переводы — в `docs/i18n/ru/guide/`):

- [Установка](docs/i18n/ru/guide/installation.md) — `docker run`, Docker Compose, Kubernetes, из исходников и из
  тестов на Java
- [Обновление](docs/i18n/ru/guide/upgrading.md) — что каждый выпуск требует от развёртывания и как перейти с образа
  MockServer
- [Конфигурация](docs/i18n/ru/guide/configuration.md) — как читаются настройки, командная строка, файл свойств
- [Справочник API](docs/i18n/ru/guide/api.md) — управляющий API, здоровье, метрики, панель и другие протоколы
- [Эксплуатация](docs/i18n/ru/guide/operations.md) — контейнер, проверки здоровья, память, журналирование, метрики,
  TLS, плагины
- [Устранение неполадок](docs/i18n/ru/guide/troubleshooting.md) — симптомы, что каждый значит и что делать
- [Бенчмарки](https://oxidestack.github.io/mock-server/benchmarks/) — запросы в секунду и память против образа
  MockServer, по закоммиченным результатам `bench/run.sh` (на английском)
- [Changelog](CHANGELOG.md) — что изменил каждый выпуск

## Сборка и тесты

Репозиторий содержит монорепозиторий MockServer как git-подмодуль, который читают тесты и сборка панели
(собственные Rust-библиотеки проекта — зависимости с crates.io), поэтому клонируйте его вместе с подмодулем:

```sh
git clone --recursive https://github.com/oxidestack/mock-server.git
```

В клоне, сделанном без `--recursive`, один раз выполните `git submodule update --init`.

- `cargo build --release` собирает сервер, `target/release/mock-server`.
- `make image` собирает образ контейнера для архитектуры вашей машины как `mock-server:latest`; нужен Docker.
- `cargo test` запускает модульные тесты, Rust-порты собственных тестов MockServer и все записанные сценарии;
  контейнер MockServer ему не нужен. [CONTRIBUTING.md](CONTRIBUTING.md) перечисляет более медленные наборы тестов и
  проверки, которые проходит каждый pull request.

## Помощь

Вопрос о том, как работает сервер, можно сначала задать [DeepWiki](https://deepwiki.com/oxidestack/mock-server): он
отвечает по коду и документации этого репозитория, а где он расходится с документацией, права документация. Вопросы,
которые он не решает, — в [Discussions](https://github.com/oxidestack/mock-server/discussions), ошибки — в
[issues](https://github.com/oxidestack/mock-server/issues), уязвимости — закрытым сообщением
([SECURITY.md](SECURITY.md)). [CONTRIBUTING.md](CONTRIBUTING.md) рассказывает, как собрать, протестировать и
отправить изменение.

## Лицензия

Код распространяется под [Apache License, Version 2.0](LICENSE) (`Apache-2.0`). Документация — этот README и
руководства в `docs/` — распространяется под
[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/) (`CC-BY-4.0`); её
юридический текст — в [`LICENSE-docs`](LICENSE-docs). `spec/mockserver/` содержит собственные схемы, документ
OpenAPI и страницы руководства MockServer: это материалы upstream, а не документация этого проекта, и они остаются
под Apache-2.0. Материалы, взятые из других источников, сохраняют свои лицензии и указаны в [`NOTICE`](NOTICE).
