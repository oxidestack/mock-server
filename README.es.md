# mock-server

<!-- languages:begin -->
[English](README.md) · [Русский](README.ru.md) · [中文](README.zh-CN.md) · **Español**
<!-- languages:end -->
<!-- translation of README.md: cc9078521959 -->

Un sustituto directo (drop-in) de [MockServer](https://www.mock-server.com), escrito en Rust. Responde a la API REST de
MockServer y acepta su línea de comandos, sus variables de entorno y sus propiedades como lo hace la imagen de
MockServer 9.2.0, de modo que los clientes (Java, Node, Python, Ruby, REST directo), los módulos de Testcontainers y el
chart de Helm que manejan MockServer lo manejan a él con solo cambiar el nombre de la imagen: un único binario
estático, sin JVM.

**Documentación: [oxidestack.github.io/mock-server](https://oxidestack.github.io/mock-server/)**

## Inicio rápido

```sh
docker run --rm -p 1080:1080 quay.io/oxidestack/mock-server:9.2.0-rc.1
```

En otra terminal, una vez arrancado:

```sh
curl -X PUT localhost:1080/mockserver/expectation -d '{
  "httpRequest":  {"method": "GET", "path": "/hello"},
  "httpResponse": {"statusCode": 200, "body": "world"}
}'
curl -i localhost:1080/hello                              # 200, world
```

El panel (dashboard) está en `http://localhost:1080/mockserver/dashboard`. Cada versión está firmada y lleva sus SBOM y
su procedencia de compilación (provenance); [Verificar una imagen](docs/i18n/es/guide/installation.md#verificar-una-imagen)
la comprueba con `cosign` y `gh attestation verify`.

## Qué ofrece

- **Un sustituto directo.** Un cliente que habla con el plano de control `/mockserver/*` de MockServer funciona sin
  cambios, con la línea de comandos, las variables de entorno, las propiedades y la estructura de `/config` de
  MockServer. La imagen de MockServer fijada en `oracle.env` es la referencia: donde ella y cualquier documento de aquí
  discrepan, tiene razón ella, y donde el comportamiento aún no es idéntico, [`docs/divergences.md`](docs/divergences.md)
  lo dice.
- **Un único binario estático.** Ni JVM ni recolector de basura; la imagen de contenedor es `FROM scratch`, para
  `linux/amd64` y `linux/arm64`, y se ejecuta con un usuario que no es root. La memoria la acota
  `MOCKSERVER_MAX_LOG_ENTRIES` ([Operación](docs/i18n/es/guide/operations.md#memoria)), y la página
  [Pruebas de rendimiento](https://oxidestack.github.io/mock-server/benchmarks/) lo compara con la imagen de
  MockServer bajo la misma carga.
- **Más allá de HTTP/1.1.** HTTP/2, HTTP/3, TLS, gRPC, DNS, brokers de AsyncAPI, proxy, caos, clúster y el panel de
  MockServer ([Referencia de la API](docs/i18n/es/guide/api.md)).
- **Para suites de pruebas de Java.** Testcontainers con la imagen, o `java-launcher/`, un sustituto de
  `mockserver-netty` que arranca el binario detrás de `ClientAndServer` y de las integraciones de JUnit y Spring
  ([Instalación](docs/i18n/es/guide/installation.md#desde-pruebas-de-java)).

## Documentación

La guía está publicada en [oxidestack.github.io/mock-server](https://oxidestack.github.io/mock-server/): la última
versión en la raíz y cada versión bajo su número; las mismas páginas, tal como están en `main`, están en `docs/guide/`
(las traducciones, en `docs/i18n/es/guide/`):

- [Instalación](docs/i18n/es/guide/installation.md) — `docker run`, Docker Compose, Kubernetes, desde el código
  fuente y desde pruebas de Java
- [Actualización](docs/i18n/es/guide/upgrading.md) — qué pide cada versión a un despliegue, y cómo pasar desde la
  imagen de MockServer
- [Configuración](docs/i18n/es/guide/configuration.md) — cómo se leen los ajustes, la línea de comandos, el archivo
  de propiedades
- [Referencia de la API](docs/i18n/es/guide/api.md) — el plano de control, la salud, las métricas, el panel y los
  demás protocolos
- [Operación](docs/i18n/es/guide/operations.md) — el contenedor, las comprobaciones de salud, la memoria, los
  registros, las métricas, TLS, los plugins
- [Solución de problemas](docs/i18n/es/guide/troubleshooting.md) — síntomas, qué significa cada uno y qué hacer
- [Pruebas de rendimiento](https://oxidestack.github.io/mock-server/benchmarks/) — peticiones por segundo y memoria
  frente a la imagen de MockServer, a partir de los resultados confirmados de `bench/run.sh` (en inglés)
- [Changelog](CHANGELOG.md) — qué cambió cada versión

## Compilar y probar

El repositorio incluye el monorepositorio de MockServer como submódulo de git, que leen las pruebas y la compilación
del panel (las bibliotecas de Rust propias del proyecto son dependencias de crates.io), así que clónalo con su
submódulo:

```sh
git clone --recursive https://github.com/oxidestack/mock-server.git
```

En un clon hecho sin `--recursive`, ejecuta `git submodule update --init` una vez.

- `cargo build --release` compila el servidor, `target/release/mock-server`.
- `make image` construye la imagen de contenedor para la arquitectura de tu máquina como `mock-server:latest`;
  necesita Docker.
- `cargo test` ejecuta las pruebas unitarias, los ports a Rust de las pruebas propias de MockServer y todos los
  escenarios grabados; no necesita ningún contenedor de MockServer. [CONTRIBUTING.md](CONTRIBUTING.md) enumera las
  suites más lentas y las comprobaciones que pasa cada pull request.

## Obtener ayuda

Una pregunta sobre cómo funciona el servidor puede ir primero a [DeepWiki](https://deepwiki.com/oxidestack/mock-server):
responde a partir del código y la documentación de este repositorio, y donde discrepa de la documentación, la
documentación tiene razón. Las preguntas que no resuelve van a
[Discussions](https://github.com/oxidestack/mock-server/discussions), los errores a
[issues](https://github.com/oxidestack/mock-server/issues), las vulnerabilidades a un informe privado
([SECURITY.md](SECURITY.md)). [CONTRIBUTING.md](CONTRIBUTING.md) explica cómo compilar, probar y enviar un cambio.

## Licencia

El código se distribuye bajo la [Apache License, Version 2.0](LICENSE) (`Apache-2.0`). La documentación — este README
y las guías de `docs/` — se distribuye bajo
[Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/) (`CC-BY-4.0`); su
texto legal está en [`LICENSE-docs`](LICENSE-docs). `spec/mockserver/` contiene los esquemas, el documento OpenAPI y
las páginas del manual propios de MockServer: son de upstream, no documentación de este proyecto, y siguen bajo
Apache-2.0. El material tomado de otras fuentes conserva su propia licencia, atribuida en [`NOTICE`](NOTICE).
