# Callback plugins

A class callback (`httpResponseClassCallback`, `httpForwardClassCallback`) names a callback class. MockServer loads
that class from its JVM's class path. mock-server resolves the name through its callback providers, in order:

1. **In-process registry.** An embedding application registers Rust callbacks with `Config::with_callback_class`
   or `Server::register_callback_class`.
2. **Native plugins.** `.so`, `.dylib` or `.dll` files. The static Docker image cannot load these.
3. **WASM plugins.** `.wasm` modules, run by the `wasmi` interpreter, with no host imports.
4. **The foreign runtime.** A JVM, in a later release.

`mockserver.callbackPlugins` (or `MOCKSERVER_CALLBACK_PLUGINS`) lists plugin files and directories, separated like
a class path (`:`). A directory contributes every plugin file in it; a path that does not exist is skipped. The
Docker image sets `MOCKSERVER_CALLBACK_PLUGINS=/libs:/extensions`, where MockServer's image takes callback and extension jars
(no provider exports extensions yet, so a name in `extensions` refuses start-up). Plugins load when the server starts. Each one
is reported on stderr; one that fails to load is reported and skipped.

## Writing a plugin

Depend on `mock-server-callback-sdk`, build with `crate-type = ["cdylib"]`, and export the classes:

```rust
use mock_server_callback_sdk::{CallbackClass, Value, json};

fn classes() -> Vec<(String, CallbackClass)> {
    vec![("com.example.Hello".into(), CallbackClass::new().with_response(|_: &Value| Ok(json!({"body": "hello"}))))]
}

mock_server_callback_sdk::export_callback_classes!(classes());
```

Build natively for a native plugin, or with `--target wasm32-unknown-unknown` for a WASM one.
`plugins/integration-testing` is a complete example: the callback classes MockServer's own tests use. `make
plugins` builds it both ways.

The callbacks exchange MockServer's JSON model:

| Interface | Receives | Returns |
|---|---|---|
| `ExpectationResponseCallback` | the request (as `HttpRequest` serialises) | a response (expectation input JSON) |
| `ExpectationForwardCallback` | the request | the request to forward |
| `ExpectationForwardAndResponseCallback` | the request; then the request sent and the upstream's response | the request to forward; then the response to return |

An `Err` is the exception the callback throws, a `CallbackError`: a Java class name, a message, an optional cause and
optional `properties` (`CallbackError::new(message)` is a `java.lang.RuntimeException`; a `String` converts into one).
The server logs it as upstream logs a throwing callback, with the chain as the ERROR entry's throwable.

The throwable in `retrieve?type=LOG_ENTRIES` is the exception's Jackson bean. The server derives `cause`,
`localizedMessage`, `message` and `stackTrace` (always empty, see `docs/divergences.md`), plus the members the JDK's
XML exceptions add: `exception` (the cause) on a `TransformerException`, `SAXException` or `SAXParseException`, and
`messageAndLocation` on a `TransformerException`. `properties` are the bean's other getters, which the server cannot
derive, e.g. a `SAXParseException`'s `lineNumber` and `columnNumber`. Add one per getter with
`CallbackError::with_property(name, value)`, where `name` is the getter's property name. A property replaces a derived
member of the same name, and the last of two with one name wins. The bean's members are in alphabetical order, and a
member whose value is `null` is dropped, so a `null` property removes a derived member.

```rust
Err(CallbackError::of("org.xml.sax.SAXParseException", "Content is not allowed in prolog.")
    .with_property("columnNumber", 1)
    .with_property("lineNumber", 1)
    .with_property("publicId", Value::Null)
    .with_property("systemId", Value::Null))
```

logs this throwable:

```json
{"columnNumber": 1, "lineNumber": 1, "localizedMessage": "Content is not allowed in prolog.",
 "message": "Content is not allowed in prolog.", "stackTrace": []}
```

## ABI

Both kinds of plugin speak one JSON protocol.

The **descriptor** lists the classes:

```json
{"abiVersion": 1, "classes": [{"name": "com.example.Hello", "interfaces": ["ExpectationResponseCallback"]}]}
```

A **call** names a class, an interface and a method:

```json
{"class": "…", "interface": "ExpectationForwardAndResponseCallback", "method": "handleResponse", "request": {…}, "response": {…}}
```

- `method` is `handle` or `handleResponse`.
- `response` is present only for `handleResponse`.

The reply is `{"result": …}` or `{"error": "message", "exception": {"class": "…", "message": "…", "cause": {…}, "properties": {…}}}`.
`exception` carries the chain, `message` and `cause` optional; a host reads a reply without it, from
an older plugin, as a `java.lang.RuntimeException` with the `error` message. `properties` is an
optional object of further bean members, on any exception of the chain (a `cause` has its own); a plugin omits it when
there are none, and a host reads an exception without it as having none. `abiVersion` stays 1.

**Native exports** (C ABI, UTF-8, NUL-terminated):

- `char *mockserver_callback_describe(void)`
- `char *mockserver_callback_invoke(const char *call)`
- `void mockserver_callback_free(char *)` releases every string returned by the two functions above.

**WASM exports:**

- `memory`
- `i32 mockserver_alloc(i32 len)`: the host writes the call there. `mockserver_invoke` frees it.
- `i64 mockserver_describe()` and `i64 mockserver_invoke(i32 ptr, i32 len)`: each returns `(ptr << 32) | len` of its
  output.
- `mockserver_free(i32 ptr, i32 len)` releases an output once the host has read it.

A module keeps one instance for the server's lifetime, and its calls run one at a time. That is how a Java
callback class's static state behaves.
