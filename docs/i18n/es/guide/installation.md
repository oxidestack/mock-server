# Instalación

<!-- languages:begin -->
[English](../../../guide/installation.md) · [Русский](../../ru/guide/installation.md) · [中文](../../zh/guide/installation.md) · **Español**
<!-- languages:end -->
<!-- translation of docs/guide/installation.md: c9c1323a95fd -->

mock-server es un único ejecutable estático, `mock-server`, que se comporta como MockServer a nivel de protocolo.
Esta página ejecuta su imagen, lo compila desde el código fuente y explica cómo llega a él una suite de pruebas de
Java. Cada comando de aquí es uno que define el repositorio (`Makefile`, `Dockerfile`, `Cargo.toml`) o que publica una
de sus versiones.

## Ejecutar la imagen

```sh
docker run --rm -p 1080:1080 quay.io/oxidestack/mock-server:9.2.0-rc.1
```

La imagen se publica en quay.io para `linux/amd64` y `linux/arm64` bajo una sola etiqueta, y se replica, con el mismo
digest, la misma firma y las mismas atestaciones, en `ghcr.io/oxidestack/mock-server`. Una versión sigue a la versión
de MockServer a la que corresponde: `9.2.0` sustituye a la imagen de MockServer 9.2.0. Una versión lleva las
etiquetas `<version>`, `mockserver-<version>` (la etiqueta que lleva la propia imagen de MockServer) y `latest`; una
versión candidata, `9.2.0-rc.1`, solo la de su versión.

Los argumentos tras el nombre de la imagen son los del servidor, como con la imagen de MockServer:
`docker run --rm -p 1081:1081 quay.io/oxidestack/mock-server:9.2.0-rc.1 -serverPort 1081`.

Qué fija la imagen (`Dockerfile`):

| | |
|---|---|
| Puerto | `SERVER_PORT=1080`, `EXPOSE 1080` |
| Punto de entrada | `/mock-server -Dmockserver.propertyFile=/config/mockserver.properties` |
| Usuario | `65532:65532`, propietario de `/config` |
| Plugins de callback | `MOCKSERVER_CALLBACK_PLUGINS=/libs:/extensions` (véase [Operación](operations.md)) |
| Comprobación de salud | `/mock-server healthcheck` cada 5 s, 3 s de timeout |
| Licencias | `/licenses/` (`LICENSE`, `NOTICE`, `DASHBOARD-THIRD-PARTY-NOTICES.txt`) |

## Verificar una imagen

Cada imagen publicada está firmada con cosign, sin clave (keyless), por el flujo de publicación de
`oxidestack/mock-server`, y lleva como atestaciones su procedencia de compilación SLSA y un SBOM SPDX por arquitectura.
Con [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) y la [CLI de GitHub](https://cli.github.com/):

```sh
cosign verify quay.io/oxidestack/mock-server:9.2.0-rc.1 \
  --certificate-identity https://github.com/oxidestack/mock-server/.github/workflows/release.yml@refs/tags/v9.2.0-rc.1 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://quay.io/oxidestack/mock-server:9.2.0-rc.1 --repo oxidestack/mock-server
```

La página de cada versión en GitHub lleva los mismos comandos para su versión, y sus SBOM como archivos.

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

Cualquier propiedad `mockserver.*` es la variable de entorno `MOCKSERVER_<NAME>` ([Configuración](configuration.md)).

## Kubernetes

El proyecto no distribuye un chart de Helm propio: el chart de MockServer es el que usan los usuarios, ejecutado con
esta imagen mediante `image.repositoryNameAndTag`, y los casos de contenedor (`make container-tests`) lo ejecutan así:

```sh
helm repo add mockserver https://www.mock-server.com
helm upgrade --install --namespace mockserver --create-namespace \
  --set image.repositoryNameAndTag=quay.io/oxidestack/mock-server:9.2.0-rc.1 \
  mockserver mockserver/mockserver
```

El admission webhook tiene su propio crate e imagen, que construye `make webhook-image` (`k8s-webhook/`); aún no se
publica.

## Compilar el binario

Necesitas una toolchain de Rust (las versiones de las dependencias están fijadas en `Cargo.lock`) y los submódulos de
git:

```sh
git clone --recursive https://github.com/oxidestack/mock-server.git
cd mock-server
cargo build --release
```

En un clon hecho sin `--recursive`, ejecuta `git submodule update --init` una vez. El ejecutable es
`target/release/mock-server`. El panel de MockServer (`/mockserver/dashboard`) se incrusta en el binario mediante
`build.rs`; sin el paquete de la UI, el binario responde 404 en esa ruta. `make dashboard` construye el paquete (node 22
y el submódulo `upstream/mockserver`). Cuando están el submódulo y node 22, `build.rs` lo construye por sí mismo; si
no, avisa y no incrusta ninguno (`Makefile`, objetivo `dashboard`).

Arráncalo:

```sh
target/release/mock-server -serverPort 1080
```

La línea de comandos es la de MockServer (`mock-server run -p 1080` y el antiguo `-serverPort 1080` son lo mismo).
Véase [Configuración](configuration.md).

## Construir la imagen de contenedor

`make image` construye el `Dockerfile` para la arquitectura de tu máquina. La imagen es `FROM scratch`, contiene el
único binario, se ejecuta como el usuario 65532 y construye el panel en su propia etapa:

```sh
make image                 # tags mock-server:latest, :<MockServer version>, :mockserver-<MockServer version>
make image IMAGE=mine/mock-server
docker run --rm -p 1080:1080 mock-server:latest
```

`make image` también construye el objetivo `clustered` como `clustered-latest` y `clustered-<version>`: la misma
imagen, cuya única diferencia es el valor de `MOCKSERVER_DASHBOARD_ANALYTICS_DISTRIBUTION` (`Dockerfile`; el clúster en
sí está en todas las imágenes). La publicación solo incluye la imagen normal.

## Desde pruebas de Java

Dos vías, ambas sin cambiar el código de las pruebas (`docs/java-launcher.md`):

- **Testcontainers.** Usa `MockServerContainer` con la imagen, declarada como sustituta de la de MockServer:
  `DockerImageName.parse("quay.io/oxidestack/mock-server:9.2.0-rc.1").asCompatibleSubstituteFor("mockserver/mockserver")`.
  `make conformance` ejecuta así la suite del cliente Java de MockServer.
- **En la JVM.** `java-launcher/` es un sustituto de `org.mock-server:mockserver-netty`: `ClientAndServer`, la regla de
  JUnit 4, la extensión de JUnit 5 y el listener de Spring arrancan el binario como proceso detrás de la misma API.
  Excluye `mockserver-netty` y añade el launcher; el binario se busca en la propiedad del sistema `mockServer.binary`,
  luego en la variable de entorno `MOCK_SERVER_BINARY` y después como `mock-server` en el `PATH`.
  `make java-launcher` ejecuta sus pruebas y lo instala en el repositorio local de Maven; el artefacto aún no se
  publica. Las limitaciones están en `docs/java-launcher.md`.

## Verificar

```sh
curl -s -X PUT localhost:1080/mockserver/status
```

responde con un cuerpo JSON que nombra los puertos en escucha. En un contenedor, `docker exec <name> /mock-server healthcheck`
termina con 0 cuando esa petición responde 200 (`src/main.rs`, `healthcheck`).

Siguiente: [Configuración](configuration.md), [API](api.md), [Operación](operations.md), [Solución de problemas](troubleshooting.md).
