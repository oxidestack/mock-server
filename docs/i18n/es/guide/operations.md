# Operaciones

<!-- languages:begin -->
[English](../../../guide/operations.md) · [Русский](../../ru/guide/operations.md) · [中文](../../zh/guide/operations.md) · **Español**
<!-- languages:end -->
<!-- translation of docs/guide/operations.md: deaa667ae962 -->

Ejecutar mock-server: el contenedor, la salud, la memoria, los registros, las métricas, TLS y los plugins. Los hechos
proceden del `Dockerfile`, el código y las mediciones citadas en cada sección.

## El contenedor

La imagen (`make image`, véase [Instalación](installation.md)) es `FROM scratch`: un binario estático, sin shell ni
gestor de paquetes, así que `docker exec <name> sh` no funciona; `docker exec <name> /mock-server healthcheck` sí.
Se ejecuta como el usuario `65532:65532` y escucha en `SERVER_PORT=1080`. `/config` es escribible por ese usuario, y es
donde el punto de entrada busca `mockserver.properties`.

Monta un archivo de propiedades o un JSON de expectativas en solo lectura e indícalo:

```sh
docker run --rm -p 1080:1080 -v "$PWD/init:/init:ro" \
  -e MOCKSERVER_INITIALIZATION_JSON_PATH=/init/expectations.json quay.io/oxidestack/mock-server:9.2.0-rc.1
```

## Comprobaciones de salud

- Vivacidad y el `HEALTHCHECK` de la imagen: `PUT /mockserver/status` (200 con los puertos). El subcomando
  `healthcheck` lo envía a `localhost` en el primer puerto de `MOCKSERVER_SERVER_PORT`, si no el de `SERVER_PORT`, si no
  el 1080, y termina con 0 ante un 200 (`src/main.rs`).
- Disponibilidad: `GET /mockserver/ready` responde `{"status":"READY"}` (`src/control.rs`).
- Un cliente que espere una línea de registro puede esperar `started on port: 1080`: se sigue imprimiendo, y es lo que lee la estrategia de espera de Testcontainers.

## Memoria

La memoria residente está acotada por `MOCKSERVER_MAX_LOG_ENTRIES` (`maxLogEntries`): crece unos 4,6 KiB por cada entrada
de registro conservada. El valor por defecto se deriva del heap disponible, como el de MockServer, con un techo de
250 000 entradas. `maxEventLogSizeInBytes` no es aquí un límite de memoria. Fija `MOCKSERVER_MAX_LOG_ENTRIES` según lo
que permita el límite de memoria del contenedor. La página
[Pruebas de rendimiento](https://oxidestack.github.io/mock-server/benchmarks/) tiene las mediciones, con su máquina y su carga.

La imagen asigna memoria con mimalloc (`src/main.rs`), porque el asignador por defecto de la compilación
estática con musl toma un único bloqueo global.

## Registro

`logLevel` (`MOCKSERVER_LOG_LEVEL`, `-l`, `-logLevel`) y `logLevelOverrides` deciden qué eventos se registran, como en
upstream. La consola es propia de Rust: una línea tiene este aspecto:
`<UTC timestamp>  INFO mock_server::server: port=1080 started on port: 1080`. `RUST_LOG` filtra por destino, por
ejemplo `RUST_LOG=mock_server=info,mock_server::matching=off`. Los archivos de configuración de registro no se
leen. El registro de eventos que devuelve `PUT /mockserver/retrieve?type=logs` es el del oráculo, no el de la consola.

## Métricas y paneles

Fija `MOCKSERVER_METRICS_ENABLED=true` y recoge `GET /mockserver/metrics`; `MOCKSERVER_OTEL_METRICS_ENABLED=true`
exporta por OTLP. Las series son proceso, compilación, runtime de tokio, servidor
HTTP, conexiones, pool de reenvío, además de las familias propias de upstream.
Los dos paneles de Grafana de `grafana/`, el del servidor y el de la inyección de carga, se construyen sobre ellas.
`scripts/verify-otlp-metrics.sh` decodifica una exportación OTLP para comprobarla.

## TLS

Los certificados hoja de HTTPS y de TLS hacia el servidor se emiten desde la CA incluida de MockServer (`src/tls/`), de
modo que un cliente que confía en ella para MockServer confía en ella aquí. `--proxy-setup` (o
`MOCKSERVER_PROXY_SETUP=true`) genera en su lugar una CA privada e imprime un bloque para copiar y pegar en el lado del
cliente. Las propiedades para tus propios certificados (`privateKeyPath`, `x509CertificatePath`,
`certificateAuthorityCertificate`, las de TLS del plano de control) son las de upstream:
`spec/mockserver/manual/mock_server/HTTPS_TLS.html`.

## Plugins de callback

Los callbacks de clase se cargan mediante los plugins enumerados en `MOCKSERVER_CALLBACK_PLUGINS` (`/libs:/extensions`
en la imagen). La imagen estática no puede cargar plugins nativos (`.so`, `.dylib`, `.dll`); los plugins WASM (`.wasm`)
funcionan. Móntalos en `/libs` o `/extensions`. Cada plugin se notifica por stderr al cargarse, y uno que no se carga se
notifica y se omite (`docs/callback-plugins.md`).

## Clustering

El clustering (`clusterEnabled`) está en todas las imágenes y habla los protocolos de JGroups e Infinispan de MockServer. Los casos de contenedor de `make container-tests` ejecutan contra él los casos de docker-compose y Helm de
upstream.

## Detención

`PUT /mockserver/stop` detiene los listeners y deja que las peticiones en curso se drenen hasta `stopDrainMillis`. `SIGTERM` (`docker stop`) termina el proceso con su acción por defecto, después de escribir
las líneas de consola en cola (`src/main.rs`); no drena.

## Actualización

Los pasos de cada versión están en [Actualización](upgrading.md).
