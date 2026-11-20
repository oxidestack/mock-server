# Actualización

<!-- languages:begin -->
[English](../../../guide/upgrading.md) · [Русский](../../ru/guide/upgrading.md) · [中文](../../zh/guide/upgrading.md) · **Español**
<!-- languages:end -->
<!-- translation of docs/guide/upgrading.md: afacd85342c0 -->

Cómo pasar un despliegue de la versión que ejecuta a una más nueva, o de la imagen de MockServer a mock-server.
Busca la sección de cada versión más nueva que la tuya y aplícalas de la más antigua a la más reciente: pasar de la
9.2.0 a una versión posterior significa la sección de cada versión intermedia y después la de la versión que quieres.
Una versión sin nada que cambiar lo dice. Después [actualiza](#cómo-actualizar) a la versión más reciente de una sola
vez: una versión nunca necesita que se instale antes una intermedia.

Cada sección enumera lo que la versión pide a un despliegue o a un cliente: bajo **Action required**, un cambio que hay
que hacer antes de la actualización o con ella; bajo **Deprecated**, algo que aún funciona y dejará de hacerlo en una
versión posterior; bajo **Removed**, algo que ha dejado de funcionar. El
[changelog](https://github.com/oxidestack/mock-server/blob/main/CHANGELOG.md) dice todo lo demás que cambió cada
versión. Solo las versiones tienen sección: una release candidate (`-rc.N`) se describe en su release de GitHub, y lo que
cambia se escribe aquí bajo la versión que la distribuye.

La documentación de la versión que ejecutas está también en este sitio: el selector de versiones de la parte superior de
cada página cambia entre versiones, y una página de una versión anterior enlaza la misma página en la última.

## Cómo actualizar

mock-server guarda las expectativas y el registro de eventos en memoria, como MockServer, y no escribe archivos
propios salvo que configures persistencia o grabación. Una actualización sustituye el contenedor (o el binario) y nada
más, y una reversión es el mismo paso con la versión anterior. Las expectativas que no se vuelven a cargar al arrancar
(`initializationJsonPath`, la configuración de `ClientAndServer` de un cliente) desaparecen tras un reinicio, como en
MockServer.

1. Lee las secciones de abajo de cada versión más nueva que la tuya y aplica sus cambios a tu configuración, entorno,
   valores del chart o clientes.
2. Sustituye el contenedor:
   - `docker run` o Docker Compose: cambia la etiqueta de la imagen (`quay.io/oxidestack/mock-server:<version>`) y
     arráncala de nuevo (`docker compose up -d`). El puerto (`1080`), las variables de entorno, los argumentos de
     línea de comandos y la estructura de `/config` son los de la imagen de MockServer.
   - Testcontainers: cambia el nombre de imagen que se da a `MockServerContainer` (decláralo compatible con
     `mockserver/mockserver` mediante `asCompatibleSubstituteFor`).
   - Helm: usa el chart de MockServer de upstream con `image.repositoryNameAndTag` fijado a la nueva imagen y tu propio
     archivo de valores; no hay un chart aparte.
3. Vigila los primeros minutos: la comprobación de salud del contenedor, el estado de tus primeras peticiones y, si lo
   recoges, `/mockserver/metrics`. Para revertir, ejecuta el paso 2 con la versión que tenías.

Si vienes de la imagen de MockServer para Java, ejecuta primero `mock-server migrate` sobre tu configuración, tus
archivos compose, los valores de Helm y las fuentes de tus pruebas: informa de cada opción o archivo de compilación que
necesita un cambio, y `--write` aplica los mecánicos.

## Actualización a X.Y.Z (primera versión, versión y fecha aún sin fijar)

<!-- Placeholder: replace "X.Y.Z" in this heading and the Unreleased heading of CHANGELOG.md with the first release's
     number when it is cut (tags follow upstream; the first is expected to be 9.2.0). Every later release gets its
     own section above this one. -->

La primera versión de mock-server: un sustituto directo de la imagen de MockServer 9.2.0. El plano de control, el
plano de datos y los clientes (Java, Node, Python, Ruby, REST directo) se comportan como la imagen 9.2.0 a nivel de
protocolo, incluida la cabecera `version`, de modo que un cliente creado para MockServer 9.2.0 no necesita cambios. Las
diferencias con la imagen se enumeran en
[`docs/divergences.md`](https://github.com/oxidestack/mock-server/blob/main/docs/divergences.md), que es la lista
autorizada; las de abajo son aquellas ante las que un despliegue tiene que actuar.

### Action required

- **Plantillas de JavaScript.** Una plantilla de respuesta `JAVASCRIPT` falla, como en la imagen estándar de MockServer,
  que no tiene GraalJS. mock-server nunca incluye un motor de JavaScript; reescribe esas plantillas en Velocity o
  Mustache. Los despliegues que ejecutaban la variante de imagen `graaljs` deben hacerlo, ya que no existe tal variante.
- **Clases de Java cargadas desde el class path.** Las clases de callback (`httpResponseClassCallback`,
  `httpForwardClassCallback`), `initializationClass` y las extensiones del servidor vienen de jars en `/libs` o
  `/extensions` en la imagen de MockServer. Aquí no hay class path: un jar ahí se nombra en un aviso y se ignora, y un
  callback o inicializador lo proporciona un plugin de callback (nativo o WASM; `MOCKSERVER_CALLBACK_PLUGINS`). Un
  despliegue que dependa de esas clases necesita un plugin antes de migrar.
- **Opciones de la JVM.** `JAVA_TOOL_OPTIONS`, `JAVA_OPTS`, `MOCKSERVER_JAVA_OPTS`, los números de hilos de los pools y
  las claves `javascript*` no tienen efecto; el servidor escribe al arrancar una línea WARN que los nombra. La memoria
  está acotada por el límite del contenedor y por `maxExpectations` y `maxLogEntries` (unos 4,6 KiB de memoria residente
  por entrada de registro conservada): mueve cualquier `-Dmockserver.<key>=<value>` dentro de esas variables a
  `MOCKSERVER_<KEY>` o al archivo de propiedades. `mock-server migrate` hace esa reescritura.
- **Paneles y alertas basados en métricas de la JVM.** `/mockserver/metrics` tiene las series `process_*` del colector de
  procesos estándar de Prometheus y una serie `*_build_info` en lugar de `jvm_gc_*`, `jvm_memory_*` y
  `jvm_threads_*`; las series de peticiones y caos `mock_server_*` son las de upstream. Cambia cualquier panel o alerta
  que lea una serie `jvm_*`.

### Deprecated

Nada.

### Removed

- Las variantes de imagen `graaljs`, `snapshot`, `root`, `root-snapshot`, `local`, `aot` y `clustered`: se publica
  una imagen por versión, para ambas plataformas. La agrupación en clúster está en ella; la imagen `clustered` de
  MockServer solo se diferencia de la normal en el valor de `MOCKSERVER_DASHBOARD_ANALYTICS_DISTRIBUTION`.
- Los paquetes de Tomcat `mockserver-war` y `mockserver-proxy-war`: ejecuta el contenedor junto al contenedor de
  servlets.
- La analítica del panel hacia el proyecto PostHog de upstream: `MOCKSERVER_DASHBOARD_ANALYTICS_ENDPOINT` y
  `MOCKSERVER_DASHBOARD_ANALYTICS_KEY` de la imagen están vacías, así que no se envía analítica salvo que definas ambas.
- El formato de registro de consola de la JVM: las líneas de consola son propias de Rust (`tracing`), pero se conservan
  las que lee una estrategia de espera de Testcontainers (`started on port: 1080`). El registro de eventos
  (`retrieve?type=LOGS`, `LOG_ENTRIES`, el panel) no cambia. Una canalización que analice las demás líneas de consola
  necesita un patrón nuevo.
