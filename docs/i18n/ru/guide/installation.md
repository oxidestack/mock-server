# Установка

<!-- languages:begin -->
[English](../../../guide/installation.md) · **Русский** · [中文](../../zh/guide/installation.md) · [Español](../../es/guide/installation.md)
<!-- languages:end -->
<!-- translation of docs/guide/installation.md: c9c1323a95fd -->

mock-server — один статический исполняемый файл `mock-server`, который на уровне протокола ведёт себя как
MockServer. Эта страница запускает его образ, собирает его из исходников и описывает, как к нему подключается набор
Java-тестов. Каждая команда здесь определена в репозитории (`Makefile`, `Dockerfile`, `Cargo.toml`) или публикуется
его выпуском.

## Запуск образа

```sh
docker run --rm -p 1080:1080 quay.io/oxidestack/mock-server:9.2.0-rc.1
```

Образ публикуется на quay.io для `linux/amd64` и `linux/arm64` под одним тегом и зеркалируется — с тем же
дайджестом, подписью и аттестациями — в `ghcr.io/oxidestack/mock-server`. Версия следует выпуску MockServer, которому
она соответствует: `9.2.0` заменяет образ MockServer 9.2.0. Выпуск получает теги `<version>`, `mockserver-<version>`
(тег, который несёт собственный образ MockServer) и `latest`; кандидат в выпуск, `9.2.0-rc.1`, — только тег своей
версии.

Аргументы после имени образа — это аргументы сервера, как и у образа MockServer:
`docker run --rm -p 1081:1081 quay.io/oxidestack/mock-server:9.2.0-rc.1 -serverPort 1081`.

Что задаёт образ (`Dockerfile`):

| | |
|---|---|
| Порт | `SERVER_PORT=1080`, `EXPOSE 1080` |
| Точка входа | `/mock-server -Dmockserver.propertyFile=/config/mockserver.properties` |
| Пользователь | `65532:65532`, которому принадлежит `/config` |
| Плагины обратных вызовов | `MOCKSERVER_CALLBACK_PLUGINS=/libs:/extensions` (см. [Эксплуатацию](operations.md)) |
| Проверка работоспособности | `/mock-server healthcheck` каждые 5 с, тайм-аут 3 с |
| Лицензии | `/licenses/` (`LICENSE`, `NOTICE`, `DASHBOARD-THIRD-PARTY-NOTICES.txt`) |

## Проверка образа

Каждый выпущенный образ подписан cosign без ключа (keyless) процессом выпуска `oxidestack/mock-server` и несёт
происхождение сборки SLSA и SBOM в формате SPDX для каждой архитектуры как аттестации. С
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) и [GitHub CLI](https://cli.github.com/):

```sh
cosign verify quay.io/oxidestack/mock-server:9.2.0-rc.1 \
  --certificate-identity https://github.com/oxidestack/mock-server/.github/workflows/release.yml@refs/tags/v9.2.0-rc.1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://quay.io/oxidestack/mock-server:9.2.0-rc.1 --repo oxidestack/mock-server
```

Страница каждого выпуска на GitHub содержит те же команды для его версии, а его SBOM — файлами.

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

Любое свойство `mockserver.*` — это переменная окружения `MOCKSERVER_<NAME>` ([Конфигурация](configuration.md)).

## Kubernetes

У проекта нет собственного Helm-чарта: пользователи берут чарт MockServer и запускают его с этим образом через
`image.repositoryNameAndTag`; контейнерные сценарии (`make container-tests`) запускают его именно так:

```sh
helm repo add mockserver https://www.mock-server.com
helm upgrade --install --namespace mockserver --create-namespace \
  --set image.repositoryNameAndTag=quay.io/oxidestack/mock-server:9.2.0-rc.1 \
  mockserver mockserver/mockserver
```

У admission webhook есть свой крейт и образ, его собирает `make webhook-image` (`k8s-webhook/`); он пока не
публикуется.

## Сборка бинарного файла

Нужны набор инструментов Rust (версии зависимостей зафиксированы в `Cargo.lock`) и git-подмодули:

```sh
git clone --recursive https://github.com/oxidestack/mock-server.git
cd mock-server
cargo build --release
```

В клоне, сделанном без `--recursive`, один раз выполните `git submodule update --init`. Исполняемый файл —
`target/release/mock-server`. Панель MockServer (`/mockserver/dashboard`) встраивается в бинарный файл скриптом
`build.rs`; без пакета UI на этот путь бинарный файл отвечает 404. `make dashboard` собирает пакет (нужны node 22 и
подмодуль `upstream/mockserver`). Если подмодуль и node 22 есть, `build.rs` собирает его сам; иначе он выводит
предупреждение и ничего не встраивает (`Makefile`, цель `dashboard`).

Запуск:

```sh
target/release/mock-server -serverPort 1080
```

Командная строка — как у MockServer (`mock-server run -p 1080` и прежний `-serverPort 1080` равнозначны). См.
[Конфигурацию](configuration.md).

## Сборка образа контейнера

`make image` собирает `Dockerfile` под архитектуру вашей машины. Образ собран `FROM scratch`, содержит один
бинарный файл, работает от пользователя 65532, а панель собирает в своей отдельной стадии:

```sh
make image                 # tags mock-server:latest, :<MockServer version>, :mockserver-<MockServer version>
make image IMAGE=mine/mock-server
docker run --rm -p 1080:1080 mock-server:latest
```

`make image` также собирает цель `clustered` как `clustered-latest` и `clustered-<version>`: тот же образ, который
отличается только значением `MOCKSERVER_DASHBOARD_ANALYTICS_DISTRIBUTION` (`Dockerfile`; сама кластеризация есть в
каждом образе). Выпуск публикует только обычный образ.

## Из тестов на Java

Два пути, оба без изменения кода тестов (`docs/java-launcher.md`):

- **Testcontainers.** Используйте `MockServerContainer` с этим образом, объявив его совместимой заменой образа
  MockServer:
  `DockerImageName.parse("quay.io/oxidestack/mock-server:9.2.0-rc.1").asCompatibleSubstituteFor("mockserver/mockserver")`.
  `make conformance` запускает набор тестов Java-клиента MockServer именно так.
- **В JVM.** `java-launcher/` — замена `org.mock-server:mockserver-netty`: `ClientAndServer`, правило JUnit 4,
  расширение JUnit 5 и слушатель Spring запускают бинарный файл как процесс за тем же API. Исключите
  `mockserver-netty` и добавьте лаунчер; бинарный файл ищется по системному свойству `mockServer.binary`, затем по
  переменной окружения `MOCK_SERVER_BINARY`, затем как `mock-server` в `PATH`. `make java-launcher` запускает его
  тесты и устанавливает его в локальный репозиторий Maven; артефакт пока не публикуется. Ограничения перечислены в
  `docs/java-launcher.md`.

## Проверка

```sh
curl -s -X PUT localhost:1080/mockserver/status
```

отвечает телом JSON с перечнем портов, которые слушает сервер. В контейнере `docker exec <name> /mock-server healthcheck`
завершается с кодом 0, когда этот запрос получает ответ 200 (`src/main.rs`, `healthcheck`).

Дальше: [Конфигурация](configuration.md), [API](api.md), [Эксплуатация](operations.md), [Устранение неполадок](troubleshooting.md).
