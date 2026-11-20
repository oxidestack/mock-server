//! `mockserver-k8s-webhook`'s tests (`AdmissionReviewHandlerTest`, `SidecarPatchBuilderTest`, `WebhookServerTest`)
//! against the `k8s-webhook` crate, one function per upstream test, named `<class>_<nested class>_<test>`. The server
//! tests start a real HTTPS server on an ephemeral port with a freshly minted self-signed certificate (upstream
//! mints one with `keytool`) and send real requests over TLS.

use base64::Engine;
use jackson::JsonNode;
use k8s_webhook::config::{self, SidecarInjectionConfig};
use k8s_webhook::patch::{self as patch_mod, SidecarPatchBuilder};
use k8s_webhook::{AdmissionReviewHandler, WebhookServer, tls};
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn node(json: &str) -> JsonNode {
    jackson::json::read_tree(json, jackson::json::ReadFeatures::default()).unwrap()
}

fn value(node: &JsonNode) -> Value {
    serde_json::from_str(&jackson::convert::node_to_json_string(node, false, false)).unwrap()
}

fn quiet() {
    k8s_webhook::log::silence();
}

/// `buildAdmissionReview(uid, optIn, alreadyInjected)` of both upstream test classes.
fn build_admission_review(uid: &str, opt_in: bool, already_injected: bool) -> String {
    let mut annotations = String::new();
    if opt_in || already_injected {
        annotations.push_str(r#","annotations": {"mockserver.org/inject": "true""#);
        if already_injected {
            annotations.push_str(r#","mockserver.org/injected": "true""#);
        }
        annotations.push('}');
    }
    format!(
        r#"{{"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "request": {{"uid": "{uid}",
        "kind": {{"group": "", "version": "v1", "kind": "Pod"}}, "resource": {{"group": "", "version": "v1", "resource": "pods"}},
        "operation": "CREATE", "object": {{"apiVersion": "v1", "kind": "Pod",
        "metadata": {{"name": "test-pod", "namespace": "default"{annotations}}},
        "spec": {{"containers": [{{"name": "app", "image": "myapp:latest"}}]}}}}}}}}"#
    )
}

fn handler() -> AdmissionReviewHandler {
    quiet();
    AdmissionReviewHandler::new(SidecarInjectionConfig::default())
}

fn review(handler: &AdmissionReviewHandler, uid: &str, opt_in: bool, already_injected: bool) -> Value {
    let reply = handler.handle_admission_review_bytes(build_admission_review(uid, opt_in, already_injected).as_bytes()).unwrap();
    serde_json::from_slice(&reply).unwrap()
}

fn decoded_patch(response: &Value) -> Value {
    let bytes = base64::engine::general_purpose::STANDARD.decode(response["response"]["patch"].as_str().unwrap()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ============================================================
// AdmissionReviewHandlerTest
// ============================================================

#[test]
fn admission_review_handler_handle_admission_review_opted_in_pod_gets_patch() {
    let response = review(&handler(), "test-uid-1", true, false);
    assert_eq!(response["apiVersion"], "admission.k8s.io/v1");
    assert_eq!(response["kind"], "AdmissionReview");
    let admission = &response["response"];
    assert_eq!(admission["uid"], "test-uid-1");
    assert_eq!(admission["allowed"], true);
    assert_eq!(admission["patchType"], "JSONPatch");
    let patch = decoded_patch(&response);
    assert!(!patch.as_array().unwrap().is_empty());
    let has_sidecar = patch.as_array().unwrap().iter().any(|op| {
        op["path"].as_str().unwrap().contains("containers") && op["value"].is_object() && op["value"]["name"] == "mockserver-sidecar"
    });
    assert!(has_sidecar, "patch should contain mockserver-sidecar container");
}

#[test]
fn admission_review_handler_handle_admission_review_non_opted_pod_is_allowed_without_patch() {
    let response = review(&handler(), "test-uid-2", false, false);
    let admission = &response["response"];
    assert_eq!(admission["uid"], "test-uid-2");
    assert_eq!(admission["allowed"], true);
    assert!(admission.get("patch").is_none());
    assert!(admission.get("patchType").is_none());
}

#[test]
fn admission_review_handler_handle_admission_review_already_injected_pod_is_allowed_without_patch() {
    let response = review(&handler(), "test-uid-3", true, true);
    let admission = &response["response"];
    assert_eq!(admission["uid"], "test-uid-3");
    assert_eq!(admission["allowed"], true);
    assert!(admission.get("patch").is_none(), "already-injected pod should not get a patch");
}

#[test]
fn admission_review_handler_handle_admission_review_uid_is_passed_through() {
    let response = review(&handler(), "unique-request-id-12345", false, false);
    assert_eq!(response["response"]["uid"], "unique-request-id-12345");
}

#[test]
fn admission_review_handler_handle_admission_review_handles_json_node_input() {
    let request = node(&build_admission_review("json-node-uid", true, false));
    let response: Value = serde_json::from_slice(&handler().handle_admission_review(&request).unwrap()).unwrap();
    assert_eq!(response["response"]["allowed"], true);
    assert!(response["response"].get("patch").is_some());
}

#[test]
fn admission_review_handler_allow_responses_create_allow_response() {
    let response: Value = serde_json::from_slice(&handler().create_allow_response("allow-uid")).unwrap();
    assert_eq!(response["apiVersion"], "admission.k8s.io/v1");
    assert_eq!(response["kind"], "AdmissionReview");
    assert_eq!(response["response"]["uid"], "allow-uid");
    assert_eq!(response["response"]["allowed"], true);
    assert!(response["response"].get("patch").is_none());
}

#[test]
fn admission_review_handler_allow_responses_create_allow_with_message() {
    let response: Value = serde_json::from_slice(&handler().create_allow_with_message("msg-uid", "test message")).unwrap();
    assert_eq!(response["response"]["uid"], "msg-uid");
    assert_eq!(response["response"]["allowed"], true);
    assert_eq!(response["response"]["status"]["message"], "test message");
}

#[test]
fn admission_review_handler_patch_content_patch_is_valid_base64_encoded_json() {
    let response = review(&handler(), "b64-uid", true, false);
    let encoded = response["response"]["patch"].as_str().unwrap();
    let decoded = base64::engine::general_purpose::STANDARD.decode(encoded).expect("valid base64");
    let patch: Value = serde_json::from_slice(&decoded).expect("valid JSON");
    assert!(patch.is_array());
}

#[test]
fn admission_review_handler_patch_content_patch_operations_have_correct_format() {
    let patch = decoded_patch(&review(&handler(), "format-uid", true, false));
    for op in patch.as_array().unwrap() {
        assert!(op.get("op").is_some(), "each operation must have 'op' field");
        assert!(op.get("path").is_some(), "each operation must have 'path' field");
        assert!(op.get("value").is_some(), "each operation must have 'value' field");
        assert_eq!(op["op"], "add");
    }
}

#[test]
fn admission_review_handler_patch_content_patch_contains_iptables_init_and_sidecar() {
    let patch = decoded_patch(&review(&handler(), "full-patch-uid", true, false));
    let (mut init, mut sidecar, mut marker) = (false, false, false);
    for op in patch.as_array().unwrap() {
        let path = op["path"].as_str().unwrap();
        let value = &op["value"];
        if path.contains("initContainers") {
            let items: Vec<&Value> = match value.as_array() {
                Some(items) => items.iter().collect(),
                None => vec![value],
            };
            init |= items.iter().any(|i| i["name"] == "mockserver-iptables-init");
        }
        if path.contains("containers") && !path.contains("initContainers") && value.is_object() && value["name"] == "mockserver-sidecar" {
            sidecar = true;
        }
        marker |= path.contains("mockserver.org~1injected");
    }
    assert!(init, "patch should contain iptables init container");
    assert!(sidecar, "patch should contain sidecar container");
    assert!(marker, "patch should contain idempotency marker");
}

// ============================================================
// SidecarPatchBuilderTest
// ============================================================

fn builder() -> SidecarPatchBuilder {
    builder_with(SidecarInjectionConfig::default())
}

fn builder_with(config: SidecarInjectionConfig) -> SidecarPatchBuilder {
    quiet();
    SidecarPatchBuilder::new(config)
}

/// `createPod(null, null)`: a pod with one `app` container and no annotations.
fn create_pod() -> Value {
    serde_json::json!({"metadata": {"name": "test-pod"}, "spec": {"containers": [{"name": "app", "image": "myapp:latest"}]}})
}

fn create_pod_with_annotations(annotations: Value) -> Value {
    let mut pod = create_pod();
    pod["metadata"]["annotations"] = annotations;
    pod
}

fn create_pod_with_annotation(key: &str, value: &str) -> Value {
    create_pod_with_annotations(serde_json::json!({ key: value }))
}

fn create_opted_in_pod() -> Value {
    create_pod_with_annotation(config::INJECT_ANNOTATION, "true")
}

fn to_node(pod: &Value) -> JsonNode {
    node(&pod.to_string())
}

fn should_inject(pod: &Value) -> bool {
    builder().should_inject(Some(&to_node(pod)))
}

fn build_patch(builder: &SidecarPatchBuilder, pod: &Value) -> Vec<Value> {
    value(&builder.build_patch(&to_node(pod)).unwrap()).as_array().unwrap().clone()
}

fn find_op_by_path_suffix<'a>(patch: &'a [Value], suffix: &str) -> Option<&'a Value> {
    patch.iter().find(|op| op["path"].as_str().unwrap().ends_with(suffix))
}

fn find_op_by_path<'a>(patch: &'a [Value], path: &str) -> Option<&'a Value> {
    patch.iter().find(|op| op["path"] == path)
}

fn find_env_value<'a>(env: &'a Value, name: &str) -> Option<&'a str> {
    env.as_array().unwrap().iter().find(|e| e["name"] == name).and_then(|e| e["value"].as_str())
}

/// The init container of a patch, whether added as a new array or appended.
fn init_container(patch: &[Value]) -> Value {
    let op = find_op_by_path_suffix(patch, "initContainers").or_else(|| find_op_by_path_suffix(patch, "initContainers/-")).unwrap();
    if op["value"].is_array() { op["value"][0].clone() } else { op["value"].clone() }
}

fn sidecar(patch: &[Value]) -> Value {
    find_op_by_path_suffix(patch, "containers/-").expect("patch should add sidecar to containers")["value"].clone()
}

#[test]
fn sidecar_patch_builder_should_inject_returns_false_for_null_pod() {
    assert!(!builder().should_inject(None));
}

#[test]
fn sidecar_patch_builder_should_inject_returns_false_for_pod_without_annotations() {
    assert!(!should_inject(&create_pod()));
}

#[test]
fn sidecar_patch_builder_should_inject_returns_false_when_inject_annotation_missing() {
    assert!(!should_inject(&create_pod_with_annotation("other.annotation", "true")));
}

#[test]
fn sidecar_patch_builder_should_inject_returns_false_when_inject_annotation_is_false() {
    assert!(!should_inject(&create_pod_with_annotation(config::INJECT_ANNOTATION, "false")));
}

#[test]
fn sidecar_patch_builder_should_inject_returns_false_when_inject_annotation_is_empty() {
    assert!(!should_inject(&create_pod_with_annotation(config::INJECT_ANNOTATION, "")));
}

#[test]
fn sidecar_patch_builder_should_inject_returns_true_when_inject_annotation_is_true() {
    assert!(should_inject(&create_pod_with_annotation(config::INJECT_ANNOTATION, "true")));
}

#[test]
fn sidecar_patch_builder_should_inject_returns_true_case_insensitive() {
    assert!(should_inject(&create_pod_with_annotation(config::INJECT_ANNOTATION, "True")));
}

#[test]
fn sidecar_patch_builder_should_inject_returns_false_when_already_injected() {
    let pod = create_pod_with_annotations(serde_json::json!({config::INJECT_ANNOTATION: "true", config::INJECTED_ANNOTATION: "true"}));
    assert!(!should_inject(&pod));
}

#[test]
fn sidecar_patch_builder_should_inject_returns_true_when_injected_annotation_present_but_not_true() {
    let pod = create_pod_with_annotations(serde_json::json!({config::INJECT_ANNOTATION: "true", config::INJECTED_ANNOTATION: "false"}));
    assert!(should_inject(&pod));
}

#[test]
fn sidecar_patch_builder_build_patch_patch_contains_idempotency_marker_annotation() {
    let patch = build_patch(&builder(), &create_opted_in_pod());
    let ops: Vec<&Value> = patch.iter().filter(|op| op["path"].as_str().unwrap().contains("mockserver.org~1injected")).collect();
    assert!(!ops.is_empty(), "patch should contain injected annotation");
    for op in ops {
        assert_eq!(op["op"], "add");
        assert_eq!(op["value"], "true");
    }
}

#[test]
fn sidecar_patch_builder_build_patch_patch_contains_status_annotation() {
    let patch = build_patch(&builder(), &create_opted_in_pod());
    let ops: Vec<&Value> = patch.iter().filter(|op| op["path"].as_str().unwrap().contains("mockserver.org~1status")).collect();
    assert!(!ops.is_empty(), "patch should contain status annotation");
    for op in ops {
        assert_eq!(op["op"], "add");
        assert_eq!(op["value"], "injected");
    }
}

#[test]
fn sidecar_patch_builder_build_patch_patch_adds_iptables_init_container() {
    let patch = build_patch(&builder(), &create_opted_in_pod());
    let op = find_op_by_path_suffix(&patch, "initContainers").expect("patch should add initContainers");
    assert!(op["value"].is_array(), "initContainers value should be an array");
    let init = &op["value"][0];
    assert_eq!(init["name"], "mockserver-iptables-init");
    assert_eq!(init["image"], "alpine:3.19");
    let security = &init["securityContext"];
    assert_eq!(security["runAsUser"], 0);
    assert_eq!(security["runAsNonRoot"], false);
    let caps = &security["capabilities"]["add"];
    assert!(caps.is_array());
    assert_eq!(caps[0], "NET_ADMIN");
    assert_eq!(caps[1], "NET_RAW");
}

#[test]
fn sidecar_patch_builder_build_patch_iptables_init_container_has_uid_exclusion() {
    let init = init_container(&build_patch(&builder(), &create_opted_in_pod()));
    let command = init["command"].as_array().unwrap();
    assert_eq!(command.len(), 3);
    assert_eq!(command[0], "sh");
    assert_eq!(command[1], "-c");
    let script = command[2].as_str().unwrap();
    let uid_exclusion = script.find("--uid-owner 65534 -j RETURN").expect("script should contain UID exclusion rule");
    let redirect = script.find("-j REDIRECT").expect("script should contain REDIRECT rule");
    assert!(uid_exclusion > 0 && redirect > 0);
    assert!(uid_exclusion < redirect, "UID exclusion must come BEFORE REDIRECT rules to prevent loop");
}

#[test]
fn sidecar_patch_builder_build_patch_iptables_init_container_redirects_configured_ports() {
    let init = init_container(&build_patch(&builder(), &create_opted_in_pod()));
    let script = init["command"][2].as_str().unwrap();
    assert!(script.contains("--dport 80 -j REDIRECT --to-ports 1080"));
    assert!(script.contains("--dport 443 -j REDIRECT --to-ports 1080"));
}

#[test]
fn sidecar_patch_builder_build_patch_patch_adds_sidecar_container() {
    let patch = build_patch(&builder(), &create_opted_in_pod());
    let op = find_op_by_path_suffix(&patch, "containers/-").expect("patch should add sidecar to containers");
    assert_eq!(op["op"], "add");
    assert_eq!(op["value"]["name"], "mockserver-sidecar");
    assert_eq!(op["value"]["image"], "mockserver/mockserver:mockserver-6.1.1-SNAPSHOT");
}

#[test]
fn sidecar_patch_builder_build_patch_sidecar_has_transparent_proxy_enabled() {
    let sidecar = sidecar(&build_patch(&builder(), &create_opted_in_pod()));
    assert_eq!(find_env_value(&sidecar["env"], "MOCKSERVER_TRANSPARENT_PROXY_ENABLED"), Some("true"));
}

#[test]
fn sidecar_patch_builder_build_patch_sidecar_has_net_admin_capability() {
    let sidecar = sidecar(&build_patch(&builder(), &create_opted_in_pod()));
    assert_eq!(sidecar["securityContext"]["capabilities"]["add"][0], "NET_ADMIN");
}

#[test]
fn sidecar_patch_builder_build_patch_sidecar_runs_as_configured_uid() {
    let sidecar = sidecar(&build_patch(&builder(), &create_opted_in_pod()));
    assert_eq!(sidecar["securityContext"]["runAsUser"], 65534);
}

#[test]
fn sidecar_patch_builder_build_patch_sidecar_has_probes() {
    let sidecar = sidecar(&build_patch(&builder(), &create_opted_in_pod()));
    assert!(sidecar.get("readinessProbe").is_some(), "sidecar should have readiness probe");
    assert!(sidecar.get("livenessProbe").is_some(), "sidecar should have liveness probe");
    assert_eq!(sidecar["readinessProbe"]["httpGet"]["path"], "/liveness/probe");
}

#[test]
fn sidecar_patch_builder_build_patch_appends_to_existing_init_containers() {
    let mut pod = create_opted_in_pod();
    pod["spec"]["initContainers"] = serde_json::json!([{"name": "existing-init", "image": "busybox"}]);
    let patch = build_patch(&builder(), &pod);
    let op = find_op_by_path_suffix(&patch, "initContainers/-").expect("should append to existing initContainers with /-");
    assert!(op["value"].is_object(), "when appending, value should be a single container object");
    assert_eq!(op["value"]["name"], "mockserver-iptables-init");
}

#[test]
fn sidecar_patch_builder_build_patch_creates_annotations_object_when_missing() {
    let pod = serde_json::json!({"metadata": {"name": "test-pod"}, "spec": {"containers": [{"name": "app", "image": "myapp:latest"}]}});
    let patch = build_patch(&builder(), &pod);
    let op = find_op_by_path(&patch, "/metadata/annotations").expect("should create annotations object");
    assert_eq!(op["op"], "add");
    let annotations = &op["value"];
    assert!(annotations.is_object());
    assert_eq!(annotations["mockserver.org/injected"], "true");
    assert_eq!(annotations["mockserver.org/status"], "injected");
}

#[test]
fn sidecar_patch_builder_custom_config_custom_mockserver_image() {
    let builder = builder_with(SidecarInjectionConfig { mockserver_image: "custom/mockserver:latest".into(), ..Default::default() });
    let sidecar = sidecar(&build_patch(&builder, &create_opted_in_pod()));
    assert_eq!(sidecar["image"], "custom/mockserver:latest");
}

#[test]
fn sidecar_patch_builder_custom_config_custom_iptables_image() {
    let builder = builder_with(SidecarInjectionConfig { iptables_image: "custom/iptables:latest".into(), ..Default::default() });
    let init = init_container(&build_patch(&builder, &create_opted_in_pod()));
    assert_eq!(init["image"], "custom/iptables:latest");
}

#[test]
fn sidecar_patch_builder_custom_config_custom_port_and_uid() {
    let builder = builder_with(SidecarInjectionConfig {
        server_port: 8080,
        run_as_user: 1000,
        redirect_ports: "80,443,8443".into(),
        ..Default::default()
    });
    let patch = build_patch(&builder, &create_opted_in_pod());
    let script = init_container(&patch)["command"][2].as_str().unwrap().to_string();
    assert!(script.contains("--uid-owner 1000 -j RETURN"));
    assert!(script.contains("--to-ports 8080"));
    assert!(script.contains("--dport 8443"));
    let sidecar = sidecar(&patch);
    assert_eq!(sidecar["securityContext"]["runAsUser"], 1000);
    assert_eq!(sidecar["ports"][0]["containerPort"], 8080);
}

#[test]
fn sidecar_patch_builder_port_validation_valid_ports_are_accepted() {
    for port in ["80", "443", "1", "65535"] {
        assert!(patch_mod::validate_port(port).is_ok(), "{port}");
    }
}

#[test]
fn sidecar_patch_builder_port_validation_non_numeric_port_throws_illegal_argument() {
    let e = patch_mod::validate_port("abc").unwrap_err();
    assert_eq!(e.class, "java.lang.IllegalArgumentException");
    assert!(e.message_text().contains("not numeric"));
    assert!(e.message_text().contains("abc"));
}

#[test]
fn sidecar_patch_builder_port_validation_port_with_special_chars_throws_illegal_argument() {
    assert_eq!(patch_mod::validate_port("80;rm -rf /").unwrap_err().class, "java.lang.IllegalArgumentException");
}

#[test]
fn sidecar_patch_builder_port_validation_port_zero_throws_illegal_argument() {
    let e = patch_mod::validate_port("0").unwrap_err();
    assert_eq!(e.class, "java.lang.IllegalArgumentException");
    assert!(e.message_text().contains("out of range"));
}

#[test]
fn sidecar_patch_builder_port_validation_port_above65535_throws_illegal_argument() {
    let e = patch_mod::validate_port("65536").unwrap_err();
    assert_eq!(e.class, "java.lang.IllegalArgumentException");
    assert!(e.message_text().contains("out of range"));
}

#[test]
fn sidecar_patch_builder_port_validation_build_patch_rejects_non_numeric_redirect_ports() {
    let builder = builder_with(SidecarInjectionConfig { redirect_ports: "80,abc,443".into(), ..Default::default() });
    let e = builder.build_patch(&to_node(&create_opted_in_pod())).unwrap_err();
    assert_eq!(e.class, "java.lang.IllegalArgumentException");
}

#[test]
fn sidecar_patch_builder_json_pointer_escaping_escapes_slash() {
    assert_eq!(patch_mod::escape_json_pointer("mockserver.org/inject"), "mockserver.org~1inject");
}

#[test]
fn sidecar_patch_builder_json_pointer_escaping_escapes_tilde() {
    assert_eq!(patch_mod::escape_json_pointer("key~value"), "key~0value");
}

#[test]
fn sidecar_patch_builder_json_pointer_escaping_escapes_both() {
    assert_eq!(patch_mod::escape_json_pointer("a~b/c"), "a~0b~1c");
}

#[test]
fn sidecar_patch_builder_json_pointer_escaping_no_escape_needed() {
    assert_eq!(patch_mod::escape_json_pointer("simple-key"), "simple-key");
}

#[test]
fn sidecar_patch_builder_iptables_init_container_container_spec() {
    let container = value(&builder().build_iptables_init_container().unwrap());
    assert_eq!(container["name"], "mockserver-iptables-init");
    assert_eq!(container["image"], "alpine:3.19");
    assert_eq!(container["securityContext"]["runAsUser"], 0);
}

#[test]
fn sidecar_patch_builder_iptables_init_container_script_order_is_correct() {
    let container = value(&builder().build_iptables_init_container().unwrap());
    let script = container["command"][2].as_str().unwrap();
    assert!(script.starts_with("set -e\n"), "script should start with set -e");
    let uid = script.find("-I OUTPUT -m owner --uid-owner").unwrap();
    let redirect = script.find("-A OUTPUT -p tcp --dport").unwrap();
    assert!(uid < redirect, "UID exclusion (INSERT) must precede port REDIRECT (APPEND)");
}

#[test]
fn sidecar_patch_builder_sidecar_container_container_spec() {
    let container = value(&builder().build_sidecar_container());
    assert_eq!(container["name"], "mockserver-sidecar");
    assert_eq!(container["imagePullPolicy"], "IfNotPresent");
}

#[test]
fn sidecar_patch_builder_sidecar_container_environment_variables() {
    let container = value(&builder().build_sidecar_container());
    let env = &container["env"];
    assert_eq!(find_env_value(env, "MOCKSERVER_TRANSPARENT_PROXY_ENABLED"), Some("true"));
    assert_eq!(find_env_value(env, "MOCKSERVER_LOG_LEVEL"), Some("INFO"));
    assert_eq!(find_env_value(env, "SERVER_PORT"), Some("1080"));
    assert_eq!(find_env_value(env, "MOCKSERVER_LIVENESS_HTTP_GET_PATH"), Some("/liveness/probe"));
}

#[test]
fn sidecar_patch_builder_sidecar_container_security_context() {
    let container = value(&builder().build_sidecar_container());
    let security = &container["securityContext"];
    assert_eq!(security["runAsUser"], 65534);
    assert_eq!(security["readOnlyRootFilesystem"], false);
    assert_eq!(security["allowPrivilegeEscalation"], false);
}

// ============================================================
// WebhookServerTest
// ============================================================

/// A webhook server on 127.0.0.1 and an ephemeral port, serving a self-signed certificate for `localhost`, and a
/// client configuration that trusts exactly that certificate.
struct TestServer {
    server: WebhookServer,
    client: Arc<rustls::ClientConfig>,
}

async fn start_server() -> TestServer {
    quiet();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap().self_signed(&key).unwrap();
    let key_der = tls::load_private_key(&key.serialize_pem()).unwrap().der;
    let server_config = tls::server_config(vec![cert.der().clone()], key_der).unwrap();
    let mut server = WebhookServer::bind("127.0.0.1:0".parse().unwrap(), server_config, SidecarInjectionConfig::default()).await.unwrap();
    server.start();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TestServer { server, client: Arc::new(client) }
}

struct Reply {
    status: u16,
    body: Vec<u8>,
}

impl TestServer {
    async fn send(&self, method: &str, path: &str, body: Option<&[u8]>) -> Reply {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", self.server.port())).await.unwrap();
        let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let mut stream = tokio_rustls::TlsConnector::from(self.client.clone()).connect(name, tcp).await.unwrap();
        let mut request = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
        if let Some(body) = body {
            request.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()));
        }
        request.push_str("\r\n");
        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(body.unwrap_or_default());
        stream.write_all(&bytes).await.unwrap();
        let mut raw = Vec::new();
        let _ = stream.read_to_end(&mut raw).await;
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("response head");
        let head = String::from_utf8_lossy(&raw[..split]).to_string();
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        Reply { status, body: raw[split + 4..].to_vec() }
    }

    async fn post_inject(&self, body: &[u8]) -> Value {
        let reply = self.send("POST", "/inject", Some(body)).await;
        assert_eq!(reply.status, 200);
        serde_json::from_slice(&reply.body).unwrap()
    }

    async fn stop(self) {
        self.server.stop(std::time::Duration::ZERO).await;
    }
}

#[tokio::test]
async fn webhook_server_health_endpoint_healthz_returns200() {
    let server = start_server().await;
    let reply = server.send("GET", "/healthz", None).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, b"ok");
    server.stop().await;
}

#[tokio::test]
async fn webhook_server_inject_endpoint_opted_in_pod_gets_injected() {
    let server = start_server().await;
    let response = server.post_inject(build_admission_review("test-uid-inject", true, false).as_bytes()).await;
    assert_eq!(response["apiVersion"], "admission.k8s.io/v1");
    assert_eq!(response["kind"], "AdmissionReview");
    let admission = &response["response"];
    assert_eq!(admission["uid"], "test-uid-inject");
    assert_eq!(admission["allowed"], true);
    assert!(admission.get("patch").is_some(), "should have patch");
    assert_eq!(admission["patchType"], "JSONPatch");
    let patch = decoded_patch(&response);
    assert!(!patch.as_array().unwrap().is_empty());
    server.stop().await;
}

#[tokio::test]
async fn webhook_server_inject_endpoint_non_opted_pod_is_allowed() {
    let server = start_server().await;
    let response = server.post_inject(build_admission_review("test-uid-noopt", false, false).as_bytes()).await;
    assert_eq!(response["response"]["allowed"], true);
    assert!(response["response"].get("patch").is_none());
    server.stop().await;
}

#[tokio::test]
async fn webhook_server_inject_endpoint_empty_body_returns_allow_with_message() {
    let server = start_server().await;
    let response = server.post_inject(b"").await;
    assert_eq!(response["response"]["allowed"], true);
    assert!(response["response"]["status"]["message"].as_str().unwrap().contains("empty request body"));
    server.stop().await;
}

#[tokio::test]
async fn webhook_server_inject_endpoint_malformed_json_returns_allow_with_error() {
    let server = start_server().await;
    let response = server.post_inject(b"{not valid json").await;
    assert_eq!(response["response"]["allowed"], true, "malformed body should still allow pod (fail-open)");
    assert!(response["response"]["status"].get("message").is_some());
    server.stop().await;
}

#[tokio::test]
async fn webhook_server_inject_endpoint_get_method_returns405() {
    let server = start_server().await;
    assert_eq!(server.send("GET", "/inject", None).await.status, 405);
    server.stop().await;
}

#[test]
fn webhook_server_config_from_env_default_config_values() {
    let config = SidecarInjectionConfig::default();
    assert_eq!(config.server_port, 1080);
    assert_eq!(config.redirect_ports, "80,443");
    assert_eq!(config.run_as_user, 65534);
    assert_eq!(config.log_level, "INFO");
}

// Throwaway keys generated with openssl, one per standard unencrypted PEM form (upstream's test vectors).

const PKCS8_RSA: &str = "-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDF0C1/qG+p8swV
/iZyzEI4/x7/CfEvcrawiVcwSCN3yM/BNMO5IWNi5aV0z3RpnordHCMkRAeIalXh
Hwm1tQw1teHBsX4pEETp1VEYzdjIySLwhOBZj/abg50gfWwHi3X1AbwZ7lJ7sWi8
SST8fCsYcaU5rYXdm5MNONYMOvI8gTu4TaXJFqBwCSI5e8bjwzXzt5l9G038CM5w
E6saieDjxtF1JS02C96DTg11kYeAhYLFhIZGjl/JnWTdk0j4xeAySWVp9TMSRqLf
4hZCsgxK5iM8KCPQ3rqveS4b03dzoxiBWftdfWvocP+s8IoCVhdUb3bEVLogh025
dIEjldNFAgMBAAECggEAKwTZiDwswJRtXtENMoUKV9PfvU4/tfZoFZ9gpz7g+8Ff
sSBU+lNxBkZ0A6HEKt4QTAK8/7uNudSKRbGWzn4HoDykUpfTnIGNwx6hitflb9ES
OKVlFwUwd+SZDMJJ9qAVMInGiwshxAWyhdQQZ5pnUuMQMCl1Bds6ETONlU5SdOax
0Yv9sAMPMElT4uF2DX6XPXYJ8RxxBITcq4k8LfmzkTRP6p336LH4QXzWyk5SKjvA
4RQ/EKIOFsXGDxyqI/ouSaoh32yPIqEsS6ADYihueuPxAdQElJXRGcXWIqwPzUZK
NI+KjfpFkGGl/qe4Q4r9YZF6Vb2RR6pmEUdu6obwMQKBgQDzw1sxNIJNV+/3ZXZX
0Km4vpXCcXp3dVFIGax2SCUIBAJdm85LXdCq4VR//+IRsWQ1uVCpv9D3CACcokTy
DyFzcJ15nagDw8vZRhfRdjaIfuvUJmtretCwoigLo9k1E9JblG5AhVFYKLVmptnt
dWT9o2KEUOM79Z8TErls/B3eqQKBgQDPvk+S7T5B2DnaxyLrWAZ2n6Y/M/aoL4PD
uUHlWKRsC6QjHLUAWYpHezGUTO/oUsX2oK5k27b+LJ9BQpOWJ0pOUGpFKnC4mAlX
pV6yEzXSGrJUOeKBF8iD0nmvWgE85h0jgf1ycv8nbqrlQcxghINfkh9581eAdmf8
pzBUYI29PQKBgQCZZgTLMDoXphEy5LzWgk9sHTNtS7A/4Kon71Ail0AGjU9XzSbD
MuSPxIFCk6qWa8WeMWJbkIRWEMkhyNQOaAsq9GGFGPuUcvCjaIKwo+2pdAXAWfUb
jAwsO79ro86aokCstPm0zLDmA6g0UyetUUUegGUM00JMh0N140ChHv9FEQKBgQDG
cjl5VP+/zlmVz9xfjDrAXklk3rKkfp8T/IgiGccXHxewIuAUcXRSTDBURhp2h3tr
2Jo+5lOsAdwvbvWk3etxXAfoAl6jNzjVbLdEzG0BQ1dOde0U/C8jHY/4HbZJAlib
brU4+vkaJfFCBtTA7lTAmslOqVHQ+UrkYqEcOQ+s0QKBgQC06krsihf2tJCHPLoM
1hFcYeVsDngoX1rAsPdA/p5Q6qWEEIwvD0ZbufjBM6E0p0lRaBdLj6Xb3tGfziZo
s4iCEoQY1bFF+3MSF3t0n7M4CQ6C4sOxzYCBIbHBHt9tI5LQyKkh8jAuaSW8K4c9
IsZmglTNjl7gu/U7vRzW3UdWbg==
-----END PRIVATE KEY-----
";

const PKCS1_RSA: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA6lmaTCvEn2VWSxb1ftqKt2JtpbwxEI+s8Ln7ASLcLl0LCfzY
i2KcItj7PO/6MfEGdU/uxoUoDqPo5OHx6vaxAY8K4bK+WcJc1lijw3b3yJmQ9qWA
QPaB0CU56aL5nbMWb0AT/sh/JCqf9jgncgkBpWoMKFinuADuYUvFz6/jQTycYRk4
qS4SSDJ63KeV46nvSqEI9bM2BiPFrWA1pFQmrbBLbHjVIjM1DxYJtTYw7L0kbQkI
u3xhNy62VmWCC/Yj2hKNXYGoCam3WVXTzKpOdFw8Y7wcVxX/MwOLpKnXfAgsNING
uIZeJs6+D1mk0wx0FrT1vyFmBJE3YSjz7zSMFQIDAQABAoIBAB7c9BQqA3gWiXnU
KTqun2wtW1FjanbK5TTC2Yq5w5Obj1OeaApbT0LLnrLUy/d9zaLvhvvAF5lt/sL9
+rU+Deutofo9ZxI9JarY+6BHb7SMfOnuu+hSTqBR9sGNRCB/sGmwX7HDR/NEZdKw
bIl5JC1bvQQnQNdb0AkiSIfkmyJBD7N0NC1XPyvhAEO5vJsyfQVipHdu91byQ6Tk
ZPnboR8eV7gQf3yedzBeZD0HSKHBUpl/xdiKHgKQTJSy4vFmcmsxKV30a/aBRlz9
IEySqVtp1UFj7A39OQ+ffUF7r01Ci9npTNSVlltEiaMUoA6oIlDfbioWa8Yo9R5h
XluYP4ECgYEA+kWlqD2dUFGQyQRh62vY9vWz7XJ2M25asmDiG0Hq6HRAKwDPTk81
zItP1RhgO7zE+A4tre/ph8E55yhDC0KK6GMFmhdDI12AHiRMeQky9Y+Ms13rTOpP
RIDJg20o93CtHWTQ0Tg7NS9CVrQ3oR2fVRuA+XHs5UpwtQp4Kjln9aECgYEA77aq
84eNa6XFm/480TTmOuxiAQYHRaDX+iRcWnGUT424LUf5YtetepU6IWjqE+KG8tWb
RxdjFGfbver4Jik196RiYrw13B0pe9Xe/aNvGouOeEmdRtc/1OuxRWCsirZxLmp2
E+vjvEuM2fm/5LSASFPs28c9pHNlBEV5F93h2fUCgYEA5VCFjhcOmnZyFE3Irt49
iWLuPwXe2hcmUUVGR7VpWR6TYRO330fiwo1vU5CnNHUtgR/0qOgncTUSKgSREbMh
9fYtPthLsw7MAlI+I7TTFX83a24F2I7knJ7ohVyy6a47YLBsSRed4Ihx32H3is/K
mz+9OFIzvpArnyZ9nirFX6ECgYEA5aEaygcEFibK0dAN+mquUau3hjt8I9sciebj
AVDkPgEIeXgFEgaBjHf/I5oZActycpTlFoj0xMto2NmJtSStKfkytlqNTboxzwrl
fhtdhxRA+kGqg/4Wi6TsQAWHw6lZaplZW2QQ2IOW/ggdJr0yVhbvQuntxucz0Y+r
nI1UmTECgYAutbgN5BDD+JJvzh/x6iHTiRKH4unbOvVlTNCjdcgNynwmQykNMl3G
T1gKHfFoSGbJ+oAXLqZ9EC6nzhdTVdmdjmdJilvJsn2lxq3YYq7kS/jvRsrcrgsz
f2TSztlxQyRi0xT6s/f/7wueFbuD+Bvr4aUEsoQssM12VX6r99bN6Q==
-----END RSA PRIVATE KEY-----
";

const PKCS8_EC: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgb/8uKvlcw3gdsnxF
bqOpdGeZoUnu3lkNeK/kCn30LaChRANCAATUG8vWtNU83xr4cGEcSqQlIWjJkehC
jjrV2JVIQKkZg36F1bFkG/ZHW7rUulizCgBottUq3cY4nKaRrd5bv2kr
-----END PRIVATE KEY-----
";

const SEC1_EC: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFLFm37VkhZvEMzRpv/RBtP4pwYpNtiyucmjZV11kwVIoAoGCCqGSM49
AwEHoUQDQgAENY2vl7hRGfgerolj9DND2mR2VZRQv9YrwzbL1rgmsyUX6uk4uS56
uP+IKIruIAn2pMo5w/xeiHcYwFcwVXgC2w==
-----END EC PRIVATE KEY-----
";

/// The key loads, reports `algorithm`, and the TLS stack accepts it as a signing key.
fn assert_key(pem: &str, algorithm: &str) {
    let key = tls::load_private_key(pem).unwrap();
    assert_eq!(key.algorithm, algorithm);
    rustls::crypto::ring::sign::any_supported_type(&key.der).expect("a usable signing key");
}

#[test]
fn webhook_server_private_key_loading_pkcs8_rsa_key_is_accepted() {
    assert_key(PKCS8_RSA, "RSA");
}

#[test]
fn webhook_server_private_key_loading_pkcs1_rsa_key_is_accepted() {
    assert_key(PKCS1_RSA, "RSA");
}

#[test]
fn webhook_server_private_key_loading_pkcs8_ec_key_is_accepted() {
    assert_key(PKCS8_EC, "EC");
}

#[test]
fn webhook_server_private_key_loading_sec1_ec_key_is_accepted() {
    assert_key(SEC1_EC, "EC");
}

#[test]
fn webhook_server_private_key_loading_non_key_pem_is_rejected_with_clear_message() {
    let e = tls::load_private_key("this file contains no PEM private key\n").unwrap_err();
    assert_eq!(e.class, "java.lang.IllegalArgumentException");
    assert!(e.message_text().contains("no supported PEM private key"));
}
