//! `WebhookServer.main`: port, TLS files and sidecar settings from the environment (the chart's
//! `webhook-deployment.yaml`), then serve until SIGTERM or SIGINT, stopping with a 3 second drain.

use k8s_webhook::config::{self, DEFAULT_CERT_PATH, DEFAULT_KEY_PATH, DEFAULT_PORT, ENV_PORT, ENV_TLS_CERT, ENV_TLS_KEY};
use k8s_webhook::java::{JavaException, parse_int};
use k8s_webhook::{WebhookServer, log, tls};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::TcpListener;
use std::path::Path;
use std::time::Duration;

const CLASS: &str = "org.mockserver.webhook.WebhookServer";

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        // an exception escaping main: the JVM prints it and exits with status 1
        eprintln!("Exception in thread \"main\" {}", e.stack_trace());
        std::process::exit(1);
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

async fn run() -> Result<(), JavaException> {
    let mut port = DEFAULT_PORT;
    if let Some(value) = env(ENV_PORT) {
        match parse_int(&value) {
            Ok(p) => port = p,
            Err(e) => config::invalid_integer(ENV_PORT, &value, DEFAULT_PORT, "main", &e),
        }
    }
    let cert_path = env(ENV_TLS_CERT).unwrap_or_else(|| DEFAULT_CERT_PATH.to_string());
    let key_path = env(ENV_TLS_KEY).unwrap_or_else(|| DEFAULT_KEY_PATH.to_string());

    log::info(CLASS, "main", &format!("loading TLS certificate from {cert_path} and key from {key_path}"));
    let tls_config = tls::build_tls_config(Path::new(&cert_path), Path::new(&key_path))?;

    let sidecar = config::config_from_env(&|name| std::env::var(name).ok());
    log::info(
        CLASS,
        "main",
        &format!(
            "sidecar config: image={}, port={}, redirectPorts={}, uid={}, logLevel={}",
            sidecar.mockserver_image, sidecar.server_port, sidecar.redirect_ports, sidecar.run_as_user, sidecar.log_level
        ),
    );

    // new InetSocketAddress("0.0.0.0", port): a port outside 0-65535 is an IllegalArgumentException, and the JVM
    // binds the wildcard dual-stack (IPv6 when the host has it, IPv4 otherwise)
    let port = u16::try_from(port).map_err(|_| JavaException::illegal_argument(format!("port out of range:{port}")))?;
    let listener = match TcpListener::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))).await {
        Ok(listener) => listener,
        Err(_) => TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            .await
            .map_err(|e| JavaException::new("java.net.BindException", e.to_string()))?,
    };
    let mut server = WebhookServer::from_listener(listener, tls_config, sidecar).map_err(|e| JavaException::new("java.io.IOException", e.to_string()))?;
    server.start();

    let signal = shutdown_signal().await;
    server.stop(Duration::from_secs(3)).await;
    // the JVM, stopped by a signal after its shutdown hooks, exits with 128 + the signal number
    std::process::exit(128 + signal);
}

/// Waits for SIGTERM (15) or SIGINT (2) and returns its number.
async fn shutdown_signal() -> i32 {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = term.recv() => 15,
        _ = tokio::signal::ctrl_c() => 2,
    }
}
