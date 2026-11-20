//! `initializationJsonPath` at the server boundary: files and globs preload expectations with stable ids.

use std::io::{Read, Write};

fn put(port: u16, path: &str) -> String {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "PUT {path} HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn glob_initialisation_loads_every_file_with_stable_ids() {
    let dir = std::env::temp_dir().join(format!("msrs-init-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.json"), r#"{"httpRequest": {"path": "/a"}, "httpResponse": {"body": "a"}}"#).unwrap();
    std::fs::write(dir.join("b.json"), r#"[{"id": "fixed", "httpRequest": {"path": "/b"}, "httpResponse": {"body": "b"}}]"#).unwrap();
    let glob = format!("{}/*.json", dir.display());

    let mut ids = Vec::new();
    for _ in 0..2 {
        let config = mock_server::Config::for_tests().with_property("initializationJsonPath", &glob);
        let server = mock_server::Server::start(config).await.unwrap();
        let port = server.ports()[0];
        let body = tokio::task::spawn_blocking(move || put(port, "/mockserver/retrieve?type=ACTIVE_EXPECTATIONS")).await.unwrap();
        assert!(body.contains("\"path\" : \"/a\"") && body.contains("\"id\" : \"fixed\""), "{body}");
        ids.push(body.split("\"id\" : \"").nth(1).unwrap().split('"').next().unwrap().to_string());
        server.shutdown().await;
    }
    assert_eq!(ids[0], ids[1], "generated ids are stable across restarts");
    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn watcher_reloads_glob_matched_files_only() {
    // `ExpectationFileWatcherTest.shouldDetectModifiedInitialiserJsonOnAddWithGlob`: the files exist (empty) when the
    // watcher starts, then are written; `{One,Two}` brace alternatives exclude the other files.
    let dir = std::env::temp_dir().join(format!("msrs-watch-glob-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = |k: &str| dir.join(format!("init_{k}.json"));
    for k in ["main", "One", "Two", "Three"] {
        std::fs::write(file(k), "").unwrap();
    }
    let glob = format!("{}/init_{{One,Two}}*.json", dir.display());
    let config = mock_server::Config::for_tests()
        .with_property("initializationJsonPath", &glob)
        .with_property("watchInitializationJson", "true")
        .with_property("watchInitializationJsonPollPeriodMillis", "200");
    let server = mock_server::Server::start(config).await.unwrap();
    let port = server.ports()[0];
    // the watcher takes its baseline fingerprint on its own task; let it do so before the files change
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    for (k, p) in [("main", "/m"), ("One", "/one"), ("Two", "/two"), ("Three", "/three")] {
        std::fs::write(file(k), format!(r#"[{{"httpRequest": {{"path": "{p}"}}, "httpResponse": {{"body": "{k}"}}}}]"#)).unwrap();
    }
    let mut body = String::new();
    for _ in 0..50 {
        body = tokio::task::spawn_blocking(move || put(port, "/mockserver/retrieve?type=ACTIVE_EXPECTATIONS")).await.unwrap();
        if body.contains("\"/one\"") && body.contains("\"/two\"") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(body.contains("\"path\" : \"/one\"") && body.contains("\"path\" : \"/two\""), "{body}");
    assert!(!body.contains("\"/m\"") && !body.contains("\"/three\""), "{body}");
    server.shutdown().await;
    std::fs::remove_dir_all(dir).unwrap();
}
