# Referencia de la API

<!-- languages:begin -->
[English](../../../guide/api.md) · [Русский](../../ru/guide/api.md) · [中文](../../zh/guide/api.md) · **Español**
<!-- languages:end -->
<!-- translation of docs/guide/api.md: be145730f8e2 -->

La API es la de MockServer: el plano de control bajo `/mockserver/*` y el plano de datos, que responde a cualquier otra
petición a partir de las expectativas (expectations) que hayas creado. El contrato es el documento OpenAPI de upstream,
incluido sin cambios en `spec/mockserver/mockserver-openapi.yaml`, y el servidor lo sirve en
`GET /mockserver/openapi.yaml`. La entrada del plano de control se valida con los esquemas de upstream de
`spec/mockserver/schema/`, con el texto de error del oráculo. Esta página enumera las operaciones habituales; el
documento es la referencia completa, y donde el oráculo se comporta de otro modo, gana el oráculo.

Los clientes en cualquier lenguaje que hablen con el plano de control de MockServer funcionan sin cambios.
Las mismas operaciones se responden también en las rutas heredadas sin prefijo (`PUT /expectation`, `PUT /reset`, …)
(`src/control.rs`).

## Crear expectativas

```sh
curl -X PUT localhost:1080/mockserver/expectation -d '{
  "httpRequest":  {"method": "GET", "path": "/hello"},
  "httpResponse": {"statusCode": 200, "body": "world"}
}'
curl -i localhost:1080/hello
```

`PUT /mockserver/expectation` acepta una expectativa o un array y responde 201 con las expectativas en la forma
canónica del oráculo. La coincidencia, las acciones (respuesta, reenvío, callback, error), las veces, la prioridad y
los demás campos son los del esquema `expectation` de upstream (`spec/mockserver/schema/expectation.json`).

Otras formas de crearlas: `PUT /mockserver/openapi` (desde una especificación OpenAPI o Swagger),
`PUT /mockserver/import` (HAR, Postman, WireMock, Mountebank, Mockoon, tráfico grabado), las opciones de línea de
comandos `--init` y `--openapi`, y las propiedades de inicialización (`initializationJsonPath`,
`initializationOpenAPIPath`).

## Inspeccionar, verificar, limpiar

| Operación | Ruta | Notas |
|---|---|---|
| Recuperar | `PUT /mockserver/retrieve?type=` | `requests` (por defecto), `request_responses`, `recorded_expectations`, `active_expectations`, `logs`, `metrics`; `format=` `json` (por defecto), `log_entries`, `har`, generadores de código, exportaciones |
| Verificar el número de peticiones | `PUT /mockserver/verify` | 202 si se cumple; si no, 406 con la discrepancia |
| Verificar un orden | `PUT /mockserver/verifySequence` | |
| Limpiar | `PUT /mockserver/clear?type=` | `all` (por defecto), `log`, `expectations`; el cuerpo es un matcher de petición |
| Restablecer | `PUT /mockserver/reset` | borra todas las expectativas y peticiones registradas |
| Puertos | `PUT /mockserver/status` | JSON de los puertos en escucha |
| Más puertos | `PUT /mockserver/bind` | |
| Detener | `PUT /mockserver/stop` | detiene el servidor; las peticiones en curso se drenan hasta `stopDrainMillis` |
| Lint | `PUT /mockserver/lint` | informa de expectativas que nunca pueden coincidir; el mismo informe que `mock-server lint` |
| Configuración | `GET`/`PUT /mockserver/configuration` | lee o cambia la configuración en tiempo de ejecución |

Fuente de cada fila: `spec/mockserver/mockserver-openapi.yaml`, y `src/control.rs` para el comportamiento de detención y
drenaje. Las páginas del manual `clearing_and_resetting.html`, `debugging_issues.html` e `importing_expectations.html`
de `spec/mockserver/manual/mock_server/` describen la semántica.

## Salud y disponibilidad

- `PUT /mockserver/status` responde 200 con los puertos en escucha cuando el servidor está en marcha. El `HEALTHCHECK`
  de la imagen (`mock-server healthcheck`) lo envía al primer puerto de `MOCKSERVER_SERVER_PORT`, si no al de
  `SERVER_PORT`, si no al 1080.
- `GET /mockserver/ready` responde 200 con `{"status":"READY"}` (`src/control.rs`).

## Métricas

Con `metricsEnabled=true` el servidor responde a `GET /mockserver/metrics` en el formato de texto de Prometheus y a
`PUT /mockserver/retrieve?type=METRICS` con los mismos recuentos. Las familias son las de upstream, salvo que las de la
JVM (`jvm_*`) se sustituyen por series de proceso, del runtime de tokio, del servidor HTTP y de conexiones. Con `otelMetricsEnabled` los mismos datos se exportan por OTLP. Hay dos
paneles de Grafana en `grafana/`.

## Panel

`GET /mockserver/dashboard` sirve la interfaz de MockServer, incrustada en el binario.

## Protocolos y otras operaciones

Además de HTTP/1.1, el servidor habla HTTP/2, HTTP/3 (`http3Port`), TLS con certificados emitidos por la CA de
MockServer, gRPC (`/mockserver/grpc/*`), DNS (`dnsEnabled`, `dnsPort`), brokers AsyncAPI (`/mockserver/asyncapi`) y
protocolos binarios. El plano de control tiene también caos (`serviceChaos`, `tcpChaos`, `grpcChaos`), almacenes CRUD
(`crud`), almacenamiento de archivos (`files/*`), control del reloj (`clock`), deriva (`drift`), escenarios
(`scenario`) y un endpoint MCP (`mcp`). Cada uno está en el documento OpenAPI o en el manual de upstream
(`spec/mockserver/manual/`); `src/control.rs` (`OPERATIONS`) es la lista a la que responde el servidor.
`docs/coverage.md` y `docs/divergences.md` indican dónde el comportamiento aún no es idéntico al del oráculo.

## Plugins de callback

Un callback de clase (`httpResponseClassCallback`, `httpForwardClassCallback`) nombra una clase que mock-server
resuelve mediante proveedores de callbacks en lugar de un class path de la JVM: véase `docs/callback-plugins.md`.
