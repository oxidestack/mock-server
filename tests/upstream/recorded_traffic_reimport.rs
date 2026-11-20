//! `RecordedTrafficReimportHttpStateTest` (mockserver-core, in-JVM): `PUT /mockserver/import?format=recording` from
//! the body and from `persistedRecordedRequestsPath`, against an in-process server, since the disk archive has to
//! be where the server runs.

use crate::common;

fn line(path: &str, status: u16, body: &str) -> String {
    format!(r#"{{"httpRequest":{{"method":"GET","path":"{path}","headers":{{"host":["example.com"]}}}},"httpResponse":{{"statusCode":{status},"body":"{body}"}}}}"#)
}

fn archive(name: &str, content: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let file = std::env::temp_dir().join(format!("{name}-{nanos}.ndjson"));
    std::fs::write(&file, content).unwrap();
    file
}

async fn request_responses(port: u16) -> String {
    common::send(port, "PUT", "/mockserver/retrieve?type=REQUEST_RESPONSES&format=JSON", "").await.body
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reimport_archive_from_request_body_and_make_it_retrievable() {
    let server = common::start(&[]).await;
    let body = format!("{}\n{}\n", line("/api/forwarded", 200, "forwarded-body"), line("/api/mocked", 201, "mocked-body"));
    let imported = common::send(server.port, "PUT", "/mockserver/import?format=recording&redactSensitiveData=false", &body).await;
    assert_eq!(imported.status, 201);
    assert!(imported.body.contains("/api/forwarded") && imported.body.contains("/api/mocked"), "{}", imported.body);
    let retrieved = request_responses(server.port).await;
    for expected in ["/api/forwarded", "forwarded-body", "/api/mocked", "mocked-body"] {
        assert!(retrieved.contains(expected), "{expected} in {retrieved}");
    }
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_reimport_archive_from_disk_when_source_is_disk() {
    let file = archive("reimportFromDisk", &format!("{}\n", line("/api/on-disk", 200, "disk-body")));
    let server = common::start(&[("persistedRecordedRequestsPath", &file.to_string_lossy())]).await;
    let imported = common::send(server.port, "PUT", "/mockserver/import?format=recording&source=disk&redactSensitiveData=false", "").await;
    assert_eq!(imported.status, 201, "{}", imported.body);
    let retrieved = request_responses(server.port).await;
    assert!(retrieved.contains("/api/on-disk") && retrieved.contains("disk-body"), "{retrieved}");
    server.server.shutdown().await;
    let _ = std::fs::remove_file(file);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_redact_sensitive_data_on_reimport_by_default() {
    let server = common::start(&[]).await;
    let body = r#"{"httpRequest":{"method":"GET","path":"/api/secured","headers":{"host":["example.com"],"Authorization":["Bearer TOPSECRET"]}},"httpResponse":{"statusCode":200,"body":"ok"}}"#;
    let imported = common::send(server.port, "PUT", "/mockserver/import?format=recording", body).await;
    assert_eq!(imported.status, 201);
    assert!(!imported.body.contains("TOPSECRET"), "{}", imported.body);
    assert!(!request_responses(server.port).await.contains("TOPSECRET"));
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_return_bad_request_when_disk_archive_missing() {
    let missing = std::env::temp_dir().join("does-not-exist-reimport.ndjson");
    let server = common::start(&[("persistedRecordedRequestsPath", &missing.to_string_lossy())]).await;
    let imported = common::send(server.port, "PUT", "/mockserver/import?format=recording&source=disk", "").await;
    assert_eq!(imported.status, 400);
    assert!(imported.body.contains("no persisted recorded requests archive"), "{}", imported.body);
    server.server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn should_return_empty_for_empty_disk_archive() {
    let file = archive("emptyArchive", "");
    let server = common::start(&[("persistedRecordedRequestsPath", &file.to_string_lossy())]).await;
    let imported = common::send(server.port, "PUT", "/mockserver/import?format=recording&source=disk", "").await;
    assert_eq!(imported.status, 201);
    assert_eq!(imported.body.split_whitespace().collect::<String>(), "[]");
    server.server.shutdown().await;
    let _ = std::fs::remove_file(file);
}

#[tokio::test(flavor = "multi_thread")]
async fn should_recover_intact_exchanges_from_truncated_disk_archive() {
    let (first, second) = (line("/api/recovered1", 200, "body1"), line("/api/recovered2", 200, "body2"));
    let truncated = &second[..second.len() / 2];
    let file = archive("truncatedArchive", &format!("{first}\n{second}\n{truncated}"));
    let server = common::start(&[("persistedRecordedRequestsPath", &file.to_string_lossy())]).await;
    let imported = common::send(server.port, "PUT", "/mockserver/import?format=recording&source=disk&redactSensitiveData=false", "").await;
    assert_eq!(imported.status, 201);
    assert!(imported.body.contains("/api/recovered1") && imported.body.contains("/api/recovered2"), "{}", imported.body);
    assert!(imported.head.to_lowercase().contains("x-mockserver-recorded-requests-skipped: 1"), "{}", imported.head);
    let retrieved = request_responses(server.port).await;
    assert!(retrieved.contains("/api/recovered1") && retrieved.contains("/api/recovered2"), "{retrieved}");
    server.server.shutdown().await;
    let _ = std::fs::remove_file(file);
}
