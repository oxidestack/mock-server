//! `TemplateSandboxDefaultIntegrationTest` (GHSA-7pwj-xvc2-hfpc). A template registered through the control plane
//! tries to reach `java.lang.Runtime` and run a command that creates a marker file. Upstream's negative control
//! runs it on a server with `velocityDisallowClassLoading=false`, where the JVM executes it. mock-server has no
//! JVM to reach, so that server keeps templates sandboxed and says so in its log.

use std::time::{Duration, Instant};

use serde_json::json;

use crate::common;

fn class_loading_template(marker: &std::path::Path) -> String {
    format!("{{\n    'statusCode': 200,\n    'body': \"$!request.class.classLoader.loadClass('java.lang.Runtime').getRuntime().exec('touch {}')\"\n}}", marker.display())
}

fn marker(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("msrs-sandbox-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let marker = dir.join(name);
    let _ = std::fs::remove_file(&marker);
    marker
}

/// Polled, as upstream polls: `Runtime.exec` is asynchronous there.
async fn appears(file: &std::path::Path, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while !file.exists() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    file.exists()
}

async fn serve_class_loading_template(properties: &[(&str, &str)], marker: &std::path::Path) -> (common::Running, common::Response) {
    let server = common::start(properties).await;
    common::expect(server.port, &json!({
        "httpRequest": {"path": "/rce-test"},
        "httpResponseTemplate": {"templateType": "VELOCITY", "template": class_loading_template(marker)}
    }))
    .await;
    let response = common::send(server.port, "GET", "/rce-test", "").await;
    (server, response)
}

#[tokio::test(flavor = "multi_thread")]
async fn should_not_execute_os_command_from_response_template_on_default_server() {
    let marker = marker("default-server-marker");
    let (server, response) = serve_class_loading_template(&[], &marker).await;
    assert!(!appears(&marker, Duration::from_millis(2000)).await, "template executed an OS command on a default server");
    assert_eq!(response.status, 200, "unexpected response: {}", response.head);
    assert_eq!(response.body, "");
    server.server.shutdown().await;
}

/// Upstream: `shouldExecuteOsCommandWhenSandboxExplicitlyDisabled`.
#[tokio::test(flavor = "multi_thread")]
async fn should_keep_templates_sandboxed_when_class_loading_is_allowed_without_a_foreign_runtime() {
    let marker = marker("unsandboxed-server-marker");
    let (server, response) = serve_class_loading_template(&[("velocityDisallowClassLoading", "false")], &marker).await;
    assert!(!appears(&marker, Duration::from_millis(2000)).await, "a template executed an OS command without a JVM");
    assert_eq!(response.status, 200, "unexpected response: {}", response.head);
    assert_eq!(response.body, "");
    let logs = common::logs(server.port).await;
    assert_eq!(logs.matches(mock_server::foreign::NO_RUNTIME_FOR_CLASS_LOADING).count(), 1, "{logs}");
    server.server.shutdown().await;
}
