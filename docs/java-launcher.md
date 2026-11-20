# Java launcher: in-JVM MockServer entry points over the binary

Users of `ClientAndServer`, the JUnit 4 rule (`MockServerRule`), the JUnit 5
extension (`MockServerExtension`, `@MockServerSettings`), the Spring test listener (`@MockServerTest`,
`MockServerTestExecutionListener`) and the Spring Boot starter start MockServer inside their JVM. The launcher keeps
that API and starts the mock-server binary as a process behind it. The module is `java-launcher/`;
`make java-launcher` runs its tests and installs it into the local Maven repository.

## Decision 1: a drop-in `mockserver-netty`, not a separate artifact with an adapter

The artifact replaces `org.mock-server:mockserver-netty`. It has the same classes, each backed by a process:

| Class | In the launcher |
|---|---|
| `org.mockserver.integration.ClientAndServer` | same constructors and `startClientAndServer` overloads; the client half is upstream's `MockServerClient` |
| `org.mockserver.netty.MockServer` | same constructors; starts the binary on the requested ports (free ports for none or 0) |
| `org.mockserver.lifecycle.LifeCycle`, `ExpectationsListener` | the public surface only (`src/main/netty-api`), without the Netty server |

Upstream's integrations stay unchanged. `mockserver-junit-rule`, `mockserver-junit-jupiter`,
`mockserver-spring-test-listener` and `mockserver-spring-boot-starter` reach the server only through
`ClientAndServer.startClientAndServer(...)` (and `MockServerClient`). Their compiled classes link against whichever
`ClientAndServer` is on the class path. The user excludes `mockserver-netty` and adds the launcher:

```xml
<dependency>
    <groupId>org.mock-server</groupId>
    <artifactId>mockserver-junit-jupiter</artifactId>
    <version>8.0.0</version>
    <scope>test</scope>
    <exclusions>
        <exclusion><groupId>org.mock-server</groupId><artifactId>mockserver-netty</artifactId></exclusion>
    </exclusions>
</dependency>
<dependency>
    <groupId>io.github.oxidestack</groupId>               <!-- local coordinates; publishing is undecided -->
    <artifactId>mockserver-netty</artifactId>
    <version>0.1.0</version>
    <scope>test</scope>
</dependency>
```

A user who calls `ClientAndServer` directly replaces `mockserver-netty` with the launcher and changes no code.

Why the drop-in wins over a separate artifact with an adapter:

- An adapter (our own `NativeMockServerExtension`, `RsClientAndServer`, …) means re-shipping the rule, the extension,
  the Spring listener and the starter under new names. That is four upstream modules to keep in step, and every user
  would have to edit imports and annotations. With the drop-in, upstream's own modules are the integrations.
- Upstream's own tests of those modules then test the launcher unmodified (below). An adapter has no such oracle.
- The classes already existed as conformance/upstream's process-backed stand-ins. conformance/upstream
  now compiles the launcher's sources in their place, so `make upstream-tests` exercises the launcher's
  `MockServer` and `ClientAndServer` through tranches T2–T5 on both process targets.

Limits of the drop-in:

- The shaded `*-no-dependencies` jars (`mockserver-netty-no-dependencies`,
  `mockserver-junit-jupiter-no-dependencies`, …) bundle upstream's `ClientAndServer`, and an exclusion cannot remove
  that. Their users switch to the unshaded module plus the exclusion.
- Methods that read an in-JVM server's internals throw `UnsupportedOperationException` ("in-JVM: …"):
  `registerListener`, `ClientAndServer.setLogEventListener`, `getScheduler`, `getDnsPort`,
  `getRequestsInFlight`, `requestProcessingStarted`/`Complete`. Code that needs them needs the in-JVM server.
- A `Configuration` object reaches the process as `-Dmockserver.*` properties. A field that has no property form
  throws when it is passed. So do `Configuration` fields that hold Java objects.
- Configuration is read when the server starts, as in-JVM: the process gets this JVM's `mockserver.*` system
  properties at that moment (what `ConfigurationProperties` setters write).
- The process is stopped by `stop()`, and at JVM exit by a shutdown hook. A JVM killed with `SIGKILL` leaves it
  running.
- The binary loads no Java classes. Class callbacks (`httpResponseClassCallback`, `withCallbackClass(...)`) name
  callback providers instead (`docs/callback-plugins.md`, `-Dmockserver.callbackPlugins`). Resources are
  another matter: the launcher hands the process this JVM's `java.class.path` (or the
  `mockServer.classPath` system property, blank for none) in `MOCK_SERVER_CLASS_PATH`, and the binary reads
  resources from its directories and jars in order, before the working directory, as `FileReader` does in-JVM. So a
  class-path-relative location (an OpenAPI spec, a file body, a template file, an initializer and its globs) in
  `src/test/resources` or in a dependency jar resolves as it does in-JVM. Locations the binary still reads from the
  file system only are listed in `docs/divergences.md`.

## Decision 2: how the binary is found, a path property, then the environment, then `PATH`

`BinaryLauncher` runs, in this order:

1. the `mockServer.binary` system property (surefire's `systemPropertyVariables`, `-D` on the command line);
2. the `MOCK_SERVER_BINARY` environment variable;
3. `mock-server` (`mock-server.exe` on Windows) on `PATH`.

If none of these exists, starting a server fails, and the message names all three. The property is deliberately
not `mockserver.*`, because every `mockserver.*` property is forwarded to the server as configuration.

The server's output goes to the file named by `mockServer.log` (appended), or to this JVM's standard output,
where the in-JVM server logs too. The launcher copies it there itself and keeps its last 16 KiB, so a server that exits
before it is ready fails the start with what it wrote. A DNS listener that could not start (`dnsEnabled`, `dnsPort`)
fails it with upstream's `org.mockserver.netty.dns.DnsStartupException` (its own source root, `src/main/netty-api`,
as `LifeCycle`), rebuilt from the process's one-line message, as the in-JVM constructor throws it. It runs in the directory named by `mockServer.workingDirectory`, or in this
JVM's working directory.

Per-platform binaries in classifier jars (`mockserver-netty-<ver>-macos-aarch64.jar`, …, unpacked on first use)
are **not** built now. They make sense only together with publishing: without a repository to fetch them from,
a classifier jar is just a binary the user already has. They are left for when the user decides where the artifact and
the image are published. The lookup order above stays the same then, with the unpacked classifier
binary as a fourth fallback.

`ServerLauncher` is the seam. It is a `ServiceLoader` interface that turns ports, properties and a proxy target into
a `Process`. conformance/upstream registers `TargetLauncher`, which also starts MockServer 8.0.0's jar for the
`oracle-process` target and logs per test class.

## Decision 3: Maven plugin goals `start`, `stop`, `runForked`, not offered; Testcontainers and the launcher cover them

- `mockserver-maven-plugin`'s `start`/`stop` run `new org.mockserver.netty.MockServer(...)` inside the Maven JVM, and
  `runForked` forks `java -cp <plugin class path> org.mockserver.cli.Main`. A user cannot exclude a plugin's own
  `mockserver-netty`; Maven lets `<plugin><dependencies>` add artifacts or change versions of the same coordinates,
  not swap one artifact for another. So the launcher cannot be slid under upstream's plugin the way it slides under
  the JUnit and Spring modules. Offering the goals means a plugin of our own with new coordinates.
- What the goals are for is a server around the `integration-test` phase. Two existing ways cover it, and
  neither needs a new artifact. Testcontainers' `MockServerContainer` with our image (`asCompatibleSubstituteFor`, what
  `make conformance` proves) does it per test class. So does the launcher's `ClientAndServer` behind
  `@MockServerSettings`/`MockServerRule` in a JVM. A build that wants one server outside the tests can run the
  binary itself, because it is a static executable with MockServer's command line (`mock-server -serverPort 1080`).
  The plugin's `initializationJson` is the server's `-Dmockserver.initializationJsonPath`. `initializationClass` is a
  Java class, which the binary cannot load. Expectations set from the test, or the JSON initializer, replace it.
- A launcher-backed plugin can be built if a user's build needs `start`/`stop` goals as such. It would be a small
  mojo over `MockServerProcess`. It is proposed as a follow-up, not built speculatively.

## Tests

`java-launcher`'s `mvn install` compiles upstream's own tests from the submodule, unmodified, against the launcher.
It builds against the oracle's version (`mockserver.version` is `ORACLE_VERSION`, 8.0.1-SNAPSHOT, the artifacts
`mvn install`ed from the pinned commit as for conformance/upstream), because the submodule's tests use that
version's API.
`mockserver-netty` is absent from the class path, and each server is the binary named by `-DmockServerBin`
(default `target/debug/mock-server`; `make java-launcher` builds and passes the release binary):

- `mockserver-junit-rule/src/test`: `MockServerRuleTest`, `…ClientGetterTest`, `…SubClassTest`, `…TestWithMocks`,
  `MockServerClassRuleTestWithMocks`, `JUnitRuleIntegrationTest`, `JUnitClassRuleIntegrationTest`;
- `mockserver-junit-jupiter/src/test`: the `MockServerExtension*Test` classes and the `JUnitJupiter*IntegrationTest` classes;
- `mockserver-spring-test-listener/src/test`: `MockServerTestExecutionListener*Test`, `MockServerPropertyCustomizer*Test`,
  `MockServerTestFullSampleTest`, `MockServerTestExecutionListenerIntegrationTest`;
- `mockserver-spring-boot-starter/src/test`: `MockServerAutoConfigurationTest`;
- `mockserver-netty/src/integration-tests/maven-netty-jar-with-dependencies-dependency`: `ClientAndServerMockTest`,
  `ClientAndServerProxyTest` (upstream's smoke test of the `ClientAndServer` jar).

Upstream runs `*IntegrationTest` with failsafe and the rest with surefire. Here surefire runs both, and JUnit 4
classes run on the vintage engine. On 2026-10-18 the run was 471 tests in 38 classes (the launcher's own
`MockServerProcessPortRaceTest` and `DnsStartFailureOutputTest` among them), with 0 failures and 0 skips. The test
environment differs from upstream's in one way, and it is the binary's, not the tests': the callback
classes the suites name come from `plugins/integration-testing`'s native plugin (`-Dmockserver.callbackPlugins`,
as conformance/upstream does). The OpenAPI specs the suites name are read as in-JVM, from mockserver-integration-testing's
jar on the test class path, which the launcher passes to each server. No `mockserver.logLevel` is set for the tests. With
`WARN`, the server's log has no "matched expectation" entries, and `shouldRetrieveRecordedLogMessages` reads them. `ClientAndServerMockingIntegrationTest` (68 tests) and the other netty classes that
start `ClientAndServer` run through conformance/upstream's tranches.
