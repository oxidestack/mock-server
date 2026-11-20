//! Rust ports of upstream tests that cannot run unmodified against a separate server process: they share the
//! JVM with the server, and here the server runs inside the test process instead. `skips/not-applicable/`
//! (`conformance/upstream`) lists each upstream test together with its port here.

#[path = "../support/scratch_cwd.rs"]
mod scratch_cwd;
#[path = "../support/tcp_port.rs"]
mod tcp_port;
#[path = "../support/udp_port.rs"]
mod udp_port;
mod aws_sigv4;
mod amqp_live_broker;
mod asyncapi_broker_config;
mod asyncapi_control_plane;
mod asyncapi_examples;
mod asyncapi_http_expectations;
mod asyncapi_orchestrator;
mod asyncapi_spec;
mod asyncapi_amqp_subscriber;
mod asyncapi_kafka_security;
mod asyncapi_kafka_startup_only;
mod asyncapi_kafka_subscriber;
mod asyncapi_mqtt5_security;
mod asyncapi_mqtt5_subscriber;
mod asyncapi_mqtt_security;
mod asyncapi_mqtt_stub;
mod asyncapi_mqtt_subscriber;
mod asyncapi_serde;
mod asyncapi_store;
mod asyncapi_amqp_publisher;
mod asyncapi_kafka_publishers;
mod asyncapi_mqtt_publishers;
mod asyncapi_publish_options;
mod asyncapi_stubs;
mod asyncapi_validation;
mod asyncapi_verify;
mod binary_proxy;
mod binary_relay;
mod blob_azure;
mod blob_gcs;
mod blob_s3;
mod blob_stores;
mod brokers;
mod callback_client_id_takeover;
mod cassette_replay;
mod class_callbacks;
mod common;
mod configuration_instance_enforcement;
mod configuration_runtime;
mod connect_loopback_streaming;
mod connect_tunnel_protocols;
mod control_plane_oidc;
mod connection_chaos;
mod reset_connection;
mod chaos_connection_reset;
mod dashboard_model;
mod dashboard_websocket;
mod dns;
mod drift_alerts;
mod forward_actions;
mod forward_client_certificate;
mod no_proxy_hosts;
mod streamed_decode_bound;
mod forward_pool_per_server;
mod forward_header_limit_h2;
mod forwarding_fidelity;
mod gen_ai_spans;
mod llm_stream_usage;
mod grpc_bidi_breakpoints;
mod grpc_chaos;
mod grpc_data_plane_corpus;
mod grpc_derived_headers;
mod inbound_connections;
mod h2_request_model;
mod http1_connection_fixes;
mod http2_head_response;
mod http2_tunnel_streamed;
mod http3_head_response;
mod http_state_scheduler_shutdown;
mod idp_key_generation;
mod http3_mcp;
mod k8s_webhook;
mod k8s_webhook_dsa;
mod k8s_webhook_oracle;
mod kafka_live_broker;
mod lifecycle_bind_retry;
mod lifecycle_hooks;
mod llm_agent_runs;
mod llm_drift;
mod llm_mcp_tools;
mod mqtt_live_broker;
mod load_scenarios;
mod local_callbacks;
mod main_lint_command;
mod mcp_contract;
mod mcp_http2;
mod mcp_registry;
mod namespaces;
mod native_transport;
mod openapi_tools;
mod persistence_restore;
mod recorded_traffic_reimport;
mod relay_after_failed_write;
mod relay_http2_tunnel_close;
mod relay_raw_bytes_error;
mod relay_tunnel_first_bytes;
mod response_write_stall;
mod request_matchers_backend;
mod request_after_failed_write;
mod respond_before_body;
mod schema_registry_client;
mod shared_configuration;
mod socks4_proxy;
mod log_redaction;
mod loopback_shadow_probe;
mod cluster_fanin;
mod cluster_state_backend;
mod state_backend;
mod stateful_scenarios;
mod stop_drain;
mod stop_held_sockets;
mod stream_breakpoints;
mod streamed_response_abandon;
mod template_sandbox;
mod tls_certificate_generation;
mod tls_fixed_certificate_validation;
mod tls_forward_trust;
mod tls_handshake_timeout;
mod tls_runtime_reconfiguration;
mod udp_start_failure;
mod websocket_callbacks;
mod websocket_headerless_registration;
mod websocket_proxy_handshake;
mod zstd_coding;
mod websocket_relay_end_of_connection;

/// Every `skips/not-applicable/` entry names a function that exists here (`results.py ports` checks the same).
#[test]
fn not_applicable_entries_name_existing_ports() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("conformance/upstream/src/test/resources/skips/not-applicable");
    let mut missing = Vec::new();
    for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let class = entry.file_name().to_string_lossy().trim_end_matches(".txt").to_string();
        for line in std::fs::read_to_string(entry.path()).unwrap().lines() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let (method, reason) = line.split_once('#').unwrap_or((line, ""));
            let port = reason.split_whitespace().next().unwrap_or("");
            let (file, function) = port.split_once("::").unwrap_or((port, ""));
            let source = std::fs::read_to_string(root.join(file)).unwrap_or_default();
            if !file.starts_with("tests/upstream/") || function.is_empty() || !source.contains(&format!("fn {function}(")) {
                missing.push(format!("{class}#{} -> {port}", method.trim()));
            }
        }
    }
    assert!(missing.is_empty(), "not-applicable entries without a port:\n{}", missing.join("\n"));
}
