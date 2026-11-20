# Configuración

<!-- languages:begin -->
[English](../../../guide/configuration.md) · [Русский](../../ru/guide/configuration.md) · [中文](../../zh/guide/configuration.md) · **Español**
<!-- languages:end -->
<!-- translation of docs/guide/configuration.md: f513115c0a70 -->

mock-server lee la configuración de MockServer: los mismos nombres de propiedades, variables de entorno, línea de
comandos y archivo de propiedades. Donde esta página y el oráculo (oracle, la imagen de MockServer fijada en
`oracle.env`) discrepan, el oráculo tiene razón. La referencia de propiedades es la de upstream:
`spec/mockserver/manual/mock_server/configuration_properties.html` (Apache-2.0, página del propio upstream).

## Cómo se lee un valor

Una propiedad `mockserver.fooBarBaz` es también la variable de entorno `MOCKSERVER_FOO_BAR_BAZ` (`env_name` en
`src/config.rs`; unos pocos nombres son excepciones, y `src/effective_config_properties.txt` enumera cada propiedad con
su variable de entorno). Un valor puede venir de estas fuentes (la precedencia entre ellas para una propiedad
corriente es la de upstream, en la página del manual indicada arriba; las cuatro opciones siguientes se resuelven como
se indica):

1. la línea de comandos (`-p`, `-serverPort`, `-D<key>=<value>` …);
2. una opción de propiedad del sistema `-Dmockserver.<name>=<value>`;
3. la variable de entorno `MOCKSERVER_<NAME>`;
4. el archivo de propiedades (más abajo).

Para las opciones que resuelve el propio lanzador, `serverPort`, `proxyRemoteHost`, `proxyRemotePort` y `logLevel`, el
orden en `src/config.rs` (`cli_owned`) es: la opción de la línea de comandos, la propiedad del sistema,
`MOCKSERVER_<NAME>`, el nombre corto de la variable de entorno (`SERVER_PORT`, `PROXY_REMOTE_HOST`,
`PROXY_REMOTE_PORT`, `LOG_LEVEL`) y, por último, el archivo de propiedades. Un valor en blanco cuenta como no definido.
La imagen fija `SERVER_PORT=1080`, que cede ante un `mockserver.serverPort` del archivo de propiedades.

Para ver a qué se resuelven una línea de comandos y un entorno dados, ejecútalos con `--print-config`: el servidor
imprime la configuración efectiva, una línea `name = value   [source]` por propiedad, y termina sin ponerse a escuchar.

```sh
MOCKSERVER_MAX_LOG_ENTRIES=100000 mock-server --print-config
```

Las claves que el servidor no conoce se notifican como las notifica upstream (`findUnknownConfigurationKeys`).

## Línea de comandos

El binario tiene el árbol de comandos picocli de MockServer (`src/cli_usage/`). El texto de uso de abajo es el del oráculo:

| Comando | Qué hace |
|---|---|
| `run` (por defecto) | arranca el servidor: `-p/--port`, `-l/--log-level`, `--init`, `--openapi`, `--persist`, `--proxy-to`, `--validate-openapi`, `--validate-enforce`, `--watch`, `--dev`, `--proxy-setup`, `-D<key>=<value>` |
| `ui` | arranca y abre el panel en un navegador |
| `proxy --to <host[:port]>` | arranca en modo de reenvío de puertos |
| `openapi <spec>` | arranca con expectativas (expectations) de una especificación OpenAPI |
| `import <file> -p <port>` | carga expectativas de un archivo JSON en un servidor en ejecución (`-H` para el host) |
| `lint <file>...` | comprueba el JSON de expectativas por si alguna no puede coincidir nunca; `--json`, `--strict`; no necesita servidor |
| `demo` | arranca con algunas expectativas de ejemplo |
| `version`, `help` | |

Los indicadores antiguos `-serverPort`, `-proxyRemotePort`, `-proxyRemoteHost` y `-logLevel` siguen funcionando. Dos
comandos son nuestros y quedan fuera de ese árbol: `mock-server healthcheck` (la comprobación de salud de la imagen)
y `mock-server migrate` (encuentra en un repositorio lo que depende del empaquetado JVM de MockServer y aplica
reescrituras mecánicas; `src/migrate/`).

## Archivo de propiedades

El archivo indicado por `mockserver.propertyFile` o `MOCKSERVER_PROPERTY_FILE` se lee al arrancar (por defecto
`mockserver.properties` en el directorio de trabajo; la imagen apunta a `/config/mockserver.properties`, un directorio
que crea la imagen y que pertenece al usuario del servidor). Un archivo cuyo nombre termina en `.json` se lee como
JSON. Un archivo ilegible que el operador indicó se notifica al arrancar (`src/config.rs`, `load_property_file`). Un
archivo de propiedades nunca aporta `logLevel`; uno JSON sí.

## Propiedades que acotan la memoria

`maxLogEntries` y `maxExpectations` (`MOCKSERVER_MAX_LOG_ENTRIES`, `MOCKSERVER_MAX_EXPECTATIONS`) acotan el registro de
eventos y las expectativas conservadas. Sus valores por defecto se derivan del heap disponible, como los deriva upstream,
con un techo (250 000 entradas de registro; `default_max_log_entries` en `src/config.rs`). `--dev` baja ambos a 1 000.
[Operaciones](operations.md#memoria) explica la consecuencia para la memoria residente.

## Opciones propias de Rust

El servidor clasifica cada entrada exclusiva de la JVM en soportar, mapear, avisar y rechazar:

- El servidor no lee `-Dmockserver.<key>` dentro de `JAVA_TOOL_OPTIONS` (`migrate` lo reescribe como variable de
  entorno). `-Xmx`, `-Xms`, `-XX:*RAMPercentage` y otros indicadores de la JVM no tienen efecto; cuando hay opciones
  así, el servidor imprime al arrancar una línea WARN que las nombra.
- `nioEventLoopThreadCount` fija el número de hilos de trabajo; sin definir, es el número de núcleos disponibles.
- `useNativeTransport` y las opciones `javascript*` se aceptan y no tienen efecto (la divergencia está en
  `docs/divergences.md`).
- Los archivos de configuración de registro (`logback.xml`, `logging.properties`) no tienen equivalente; los niveles
  vienen de `logLevel` y `logLevelOverrides`. La consola es propia de Rust: `RUST_LOG` filtra eventos (`src/log.rs`).

## Plugins

`mockserver.callbackPlugins` (`MOCKSERVER_CALLBACK_PLUGINS`) enumera los archivos y directorios de plugins que
proporcionan callbacks de clase, separados como un class path (`docs/callback-plugins.md`). La imagen de Docker lo fija
en `/libs:/extensions`.

## Analítica del panel

La analítica del panel está desactivada por defecto: `MOCKSERVER_DASHBOARD_ANALYTICS_ENDPOINT` y
`MOCKSERVER_DASHBOARD_ANALYTICS_KEY` están vacías en la imagen, y el proyecto nunca envía datos a la cuenta de upstream.
