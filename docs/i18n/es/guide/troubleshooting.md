# Solución de problemas

<!-- languages:begin -->
[English](../../../guide/troubleshooting.md) · [Русский](../../ru/guide/troubleshooting.md) · [中文](../../zh/guide/troubleshooting.md) · **Español**
<!-- languages:end -->
<!-- translation of docs/guide/troubleshooting.md: 157b402a3de1 -->

Cada entrada es un síntoma que este repositorio puede explicar. Cuando el comportamiento que ves difiere del de
MockServer, es un error o una divergencia registrada: consulta `docs/divergences.md` y compara con el oráculo (la imagen
fijada en `oracle.env`), que tiene razón cuando ambos discrepan.

## El servidor no arranca

**Se requiere `-p` o el puerto.** `mock-server run` necesita un puerto de `-p`, `MOCKSERVER_SERVER_PORT`,
`mockserver.serverPort` o el archivo de propiedades (`src/cli_usage/run.txt`). La imagen fija `SERVER_PORT=1080`.

**Se indica un archivo de propiedades pero no se puede leer.** Un archivo indicado por `mockserver.propertyFile` o
`MOCKSERVER_PROPERTY_FILE` que no se puede leer se notifica al arrancar; el `mockserver.properties` por defecto solo se
lee si existe (`src/config.rs`, `load_property_file`).

**Un aviso al arrancar sobre claves desconocidas u opciones exclusivas de la JVM.** Una clave `mockserver.*` o
`MOCKSERVER_*` desconocida se notifica como lo hace upstream. `JVM-only settings have no effect in mock-server: [...]`
nombra los indicadores de la JVM (`-Xmx`, `JAVA_TOOL_OPTIONS`, …) que se aceptan y se ignoran: la memoria está acotada
por el límite del contenedor y por `maxLogEntries`.

## La comprobación de salud falla

`mock-server healthcheck` se conecta a `localhost` en el primer puerto de `MOCKSERVER_SERVER_PORT`, si no el de
`SERVER_PORT`, si no el 1080. Un servidor en otro puerto no pasa la comprobación: fija `SERVER_PORT` (o
`MOCKSERVER_SERVER_PORT`) al puerto en el que escucha el servidor (`src/main.rs`).

## La memoria crece

La memoria residente crece unos 4,6 KiB por cada entrada de registro conservada hasta que se alcanza `maxLogEntries`.
Fija `MOCKSERVER_MAX_LOG_ENTRIES` más bajo ([Operaciones](operations.md#memoria)). `maxEventLogSizeInBytes` no la acota.

## `/mockserver/dashboard` responde 404

El binario se compiló sin el paquete de la interfaz. `make dashboard` (node 22, el submódulo `upstream/mockserver`) lo
compila en `dashboard/`, y la siguiente compilación lo incrusta; la imagen lo compila en su propia etapa (`Makefile`,
`Dockerfile`).

## Falla un callback de clase

mock-server no carga clases de Java. El nombre de un callback de clase se resuelve mediante plugins de callback
(`MOCKSERVER_CALLBACK_PLUGINS`): un registro en proceso, un plugin nativo o un plugin WASM. La imagen estática no puede
cargar plugins nativos, y un `.jar` indicado en un directorio de plugins se notifica por stderr y no se carga
(`Dockerfile`, `docs/callback-plugins.md`). `initializationClass` es una clase de Java y tampoco se puede cargar. Las plantillas de JavaScript fallan exactamente como en el oráculo, que no tiene GraalJS.

## Un reenvío al propio servidor nunca vuelve

Un reenvío cuyo destino es su propia ruta entra en bucle dentro de MockServer, y el oráculo también; sigue escribiendo
en su registro después de `reset`. Reinicia el servidor y apunta el reenvío a otro host o ruta.

## Desde pruebas de Java

- **El launcher no encuentra el binario.** El arranque falla con un mensaje que nombra los tres sitios donde buscó: la
  propiedad del sistema `mockServer.binary`, `MOCK_SERVER_BINARY` y `mock-server` en el `PATH`
  (`docs/java-launcher.md`).
- **Un jar `mockserver-netty-no-dependencies` sigue arrancando un servidor en la JVM.** Esos jar empaquetados (shaded)
  incluyen el `ClientAndServer` de upstream; usa el módulo sin empaquetar y excluye `mockserver-netty`
  (`docs/java-launcher.md`).
- **Queda un proceso en ejecución tras morir la JVM.** Una JVM terminada con `SIGKILL` no ejecuta ningún shutdown hook,
  así que el proceso lanzado permanece (`docs/java-launcher.md`).
- **`UnsupportedOperationException: in-JVM: ...`.** El método lee las entrañas de un servidor en la JVM, que un proceso
  no tiene (`registerListener`, `setLogEventListener`, `getScheduler` y los demás de `docs/java-launcher.md`).
- **Testcontainers no acepta la imagen.** Decláralo sustituta:
  `DockerImageName.parse(...).asCompatibleSubstituteFor("mockserver/mockserver")` (`conformance/java/.../Images.java`).

## El comportamiento difiere del de MockServer

1. Reprodúcelo contra el oráculo con la misma petición. Si el oráculo responde igual, no es una divergencia.
2. Busca una fila conocida en `docs/divergences.md` y `docs/coverage.md`.
3. Si no, es un error: las pruebas del proyecto registran la respuesta del oráculo como un escenario golden
   (`tests/scenarios/`), y un informe de error con la petición y ambas respuestas se convierte en uno.

Las preguntas van primero a [DeepWiki](https://deepwiki.com/oxidestack/mock-server), que responde a partir del código y la documentación (donde
discrepan, la documentación tiene razón), y después a [Discussions](https://github.com/oxidestack/mock-server/discussions); los errores, a
[issues](https://github.com/oxidestack/mock-server/issues).
