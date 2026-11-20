//! The subcommands of `org.mockserver.cli.Main` that act on a running server: `import`, `demo` and the
//! `run` flags that reach the server through its configuration. Argument parsing and the texts it prints are checked
//! against the oracle by `tests/process_scenarios/cli_*.json`.

use std::collections::HashMap;
use std::io::{Read, Write};

use mock_server::cli::{self, Action, After, ImportPlan};

fn call(port: u16, method: &str, path: &str) -> String {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "{method} {path} HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

async fn started(args: &[&str]) -> (mock_server::Server, After) {
    // the CLI turns `proxySetupLogging` on, which writes mockserver-ca.pem into the working directory
    let mut all: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    all.push("-Dmockserver.proxySetupLogging=false".into());
    let planned = cli::plan(&all, &HashMap::new());
    let Action::Start(start) = planned.action else { panic!("not a start: out={:?} err={:?}", planned.out, planned.err) };
    let after = start.after;
    (mock_server::Server::start(start.config).await.unwrap(), after)
}

/// `MainCliTest.shouldImportExpectationsFromFileIntoRunningServer`: a single expectation object and an array both load.
#[tokio::test(flavor = "multi_thread")]
async fn import_loads_a_file_of_expectations_into_a_running_server() {
    let (server, _) = started(&["-p", "0"]).await;
    let port = server.ports()[0];
    let dir = std::env::temp_dir().join(format!("msrs-cli-import-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let single = dir.join("single.json");
    std::fs::write(&single, r#"{"httpRequest": {"path": "/one"}, "httpResponse": {"body": "1"}}"#).unwrap();
    let many = dir.join("many.json");
    std::fs::write(&many, r#"[{"httpRequest": {"path": "/two"}, "httpResponse": {"body": "2"}}, {"httpRequest": {"path": "/three"}, "httpResponse": {"body": "3"}}]"#).unwrap();

    for (file, count) in [(&single, 1), (&many, 2)] {
        let plan = ImportPlan { file: file.display().to_string(), host: "localhost".into(), port: i32::from(port) };
        let (out, err, code) = tokio::task::spawn_blocking(move || cli::run_import(&plan)).await.unwrap();
        assert_eq!((code, err.as_str()), (0, ""));
        assert_eq!(out, format!("Imported {count} expectation(s) from {} into localhost:{port}\n", file.display()));
    }
    for (path, body) in [("/one", "1"), ("/two", "2"), ("/three", "3")] {
        let response = tokio::task::spawn_blocking(move || call(port, "GET", path)).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200") && response.ends_with(body), "{path}: {response}");
    }
    std::fs::remove_dir_all(dir).unwrap();
    server.shutdown().await;
}

/// `MainCliTest.shouldReturnNonZeroExitCodeWhenImportFails` / `shouldReportErrorWhenImportFileMissing`.
#[test]
fn import_failures_exit_one_with_the_reason_on_stderr() {
    let plan = ImportPlan { file: "/nonexistent/expectations.json".into(), host: "localhost".into(), port: 1 };
    // the failure line is a console event, caught here by a subscriber of the test's own
    let console = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = console.clone();
    let subscriber = tracing_subscriber::fmt().with_ansi(false).with_writer(move || Sink(sink.clone())).finish();
    let (out, err, code) = tracing::subscriber::with_default(subscriber, || cli::run_import(&plan));
    assert_eq!(code, 1);
    assert_eq!(out, "");
    let console = String::from_utf8(console.lock().unwrap().clone()).unwrap();
    assert!(console.contains(" ERROR mock_server::general: exception while importing expectations from /nonexistent/expectations.json into localhost:1:{}\nException while loading"), "{console}");
    assert_eq!(err, "\nERROR:  could not import expectations from /nonexistent/expectations.json into localhost:1 \u{2014} Exception while loading \"/nonexistent/expectations.json\"\n\n");
}

/// A console writer into a shared buffer.
struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `MainCliTest.shouldStartDemoSeedExamplesAndPrintInstructions`: the two example expectations answer.
#[tokio::test(flavor = "multi_thread")]
async fn demo_seeds_the_example_expectations() {
    let (server, after) = started(&["demo", "-p", "0"]).await;
    assert_eq!(after, After::Demo);
    let port = server.ports()[0];
    for expectation in cli::DEMO_EXPECTATIONS {
        let (status, _) = tokio::task::spawn_blocking(move || cli::put_json("localhost", i32::from(port), "/mockserver/expectation", expectation)).await.unwrap().unwrap();
        assert_eq!(status, 201);
    }
    let hello = tokio::task::spawn_blocking(move || call(port, "GET", "/hello")).await.unwrap();
    assert!(hello.starts_with("HTTP/1.1 200") && hello.ends_with(r#"{"message":"Hello from MockServer!"}"#), "{hello}");
    let user = tokio::task::spawn_blocking(move || call(port, "GET", "/users/42")).await.unwrap();
    assert!(user.starts_with("HTTP/1.1 200") && user.ends_with(r#"{"id":1,"name":"Example User"}"#), "{user}");
    let other = tokio::task::spawn_blocking(move || call(port, "GET", "/users/abc")).await.unwrap();
    assert!(other.starts_with("HTTP/1.1 404"), "{other}");
    assert_eq!(
        cli::demo_instructions(port),
        format!("\nMockServer demo is running with example expectations.\n\n  Getting started: http://localhost:{port}/hello\n  Dashboard UI:    http://localhost:{port}/mockserver/dashboard\n\n  Try it:\n    curl http://localhost:{port}/hello\n    curl http://localhost:{port}/users/1\n\n")
    );
    server.shutdown().await;
}

/// `MainCliTest.shouldEnableWatchInitializationJsonViaWatchFlag` and `…LiveReloadExpectationsWhenWatchedFileChanges`.
#[tokio::test(flavor = "multi_thread")]
async fn watch_flag_reloads_the_initializer_file() {
    let dir = std::env::temp_dir().join(format!("msrs-cli-watch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("init.json");
    std::fs::write(&file, r#"[{"httpRequest": {"path": "/before"}, "httpResponse": {"body": "b"}}]"#).unwrap();
    let path = file.display().to_string();
    let (server, _) = started(&["-p", "0", "--init", &path, "--watch", "-Dmockserver.watchInitializationJsonPollPeriodMillis=100"]).await;
    let port = server.ports()[0];
    let active = |port| move || call(port, "PUT", "/mockserver/retrieve?type=ACTIVE_EXPECTATIONS");
    assert!(tokio::task::spawn_blocking(active(port)).await.unwrap().contains("/before"));
    std::fs::write(&file, r#"[{"httpRequest": {"path": "/after"}, "httpResponse": {"body": "a"}}]"#).unwrap();
    let mut reloaded = false;
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        if tokio::task::spawn_blocking(active(port)).await.unwrap().contains("/after") {
            reloaded = true;
            break;
        }
    }
    assert!(reloaded, "the watched file's new expectation never appeared");
    std::fs::remove_dir_all(dir).unwrap();
    server.shutdown().await;
}

/// `MainCliTest.shouldApplyDSystemPropertyFromCommandLine` and the dev flag: both end up as properties.
#[test]
fn flags_become_properties() {
    let args: Vec<String> = ["ui", "-p", "0", "--dev", "-Dmockserver.metricsEnabled=true"].iter().map(|a| a.to_string()).collect();
    let planned = cli::plan(&args, &HashMap::new());
    let Action::Start(start) = planned.action else { panic!("{:?}", planned.err) };
    assert_eq!(start.after, After::Ui);
    assert_eq!(start.config.property("devMode").as_deref(), Some("true"));
    assert_eq!(start.config.property("metricsEnabled").as_deref(), Some("true"));
    assert_eq!(start.config.ports, vec![0]);
    let dump = start.dump.expect("INFO is on");
    assert!(dump.contains("mockserver.devMode=true") && dump.contains("mockserver.metricsEnabled=true") && dump.contains("serverPort=0"), "{dump}");
}

/// The dump lists a map in `HashMap` order: `System.getProperties()` order only decides keys sharing a bucket, and
/// there the 128-slot table orders `persistExpectations` before `initializationOpenAPIPath` (recorded from the oracle).
#[test]
fn startup_dump_orders_entries_like_a_java_hash_map() {
    let args: Vec<String> =
        ["-p", "1080", "--watch", "--persist", "x.json", "--validate-openapi", "s.yaml", "--validate-enforce", "--openapi", "s.yaml"].iter().map(|a| a.to_string()).collect();
    let planned = cli::plan(&args, &HashMap::new());
    let Action::Start(start) = planned.action else { panic!("{:?}", planned.err) };
    let dump = start.dump.unwrap();
    let keys: Vec<&str> = dump.lines().filter_map(|l| l.trim().strip_prefix("mockserver.")).map(|l| l.split('=').next().unwrap()).collect();
    assert_eq!(
        keys,
        ["persistExpectations", "initializationOpenAPIPath", "watchInitializationJson", "persistedExpectationsPath", "proxySetupLogging", "validateProxyOpenAPISpec", "validateProxyEnforce"]
    );
}

/// The binary writes console lines from a thread of its own, and a `SIGTERM` still ends it by that signal
/// only after every line logged so far is on stdout: two lines per unmatched request, in their order.
#[cfg(unix)]
#[test]
fn sigterm_ends_the_binary_after_the_queued_console_lines_are_written() {
    use std::io::BufRead;
    use std::os::unix::process::ExitStatusExt;
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_mock-server"))
        .args(["-serverPort", "0", "-Dmockserver.proxySetupLogging=false"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = std::io::BufReader::new(child.stdout.take().unwrap()).lines();
    let port: u16 = loop {
        let line = lines.next().expect("started on port").unwrap();
        if let Some(at) = line.find("started on port: ") {
            break line[at + "started on port: ".len()..].trim().parse().unwrap();
        }
    };
    let requests = 200;
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    for i in 0..requests {
        write!(s, "GET /r{i} HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Length: 0\r\n\r\n").unwrap();
    }
    // the 200 answers (404s), then SIGTERM at once
    let mut seen = Vec::new();
    let mut buffer = [0u8; 65536];
    while seen.windows(15).filter(|w| w == b"HTTP/1.1 404 No").count() < requests {
        let n = s.read(&mut buffer).unwrap();
        assert!(n > 0, "connection closed early");
        seen.extend_from_slice(&buffer[..n]);
    }
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let rest: Vec<String> = lines.map(Result::unwrap).collect();
    let status = child.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
    let order: Vec<&str> = rest.iter().filter_map(|l| ["received request:", "no expectation for:"].into_iter().find(|t| l.contains(&format!(" port={port} {t}")))).collect();
    assert_eq!(order, ["received request:", "no expectation for:"].repeat(requests));
    for (i, path) in (0..requests).map(|i| format!("\"path\" : \"/r{i}\"")).enumerate() {
        assert!(rest.iter().any(|l| l.contains(&path)), "request {i} missing");
    }
}
