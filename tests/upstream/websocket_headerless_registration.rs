//! `CallbackWebSocketServerHandlerHeaderlessRegistrationTest`: a client that connects to the callback WebSocket
//! with or without an `X-CLIENT-REGISTRATION-ID` header is registered and sent a `WebSocketClientIdDTO` envelope.
//! Upstream drives `WebSocketClientRegistry.registerClient` on an `EmbeddedChannel`; these read the first frame a
//! real WebSocket client receives and `Server::metric`.

use futures_util::StreamExt;
use serde_json::Value;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::common;

const CLIENTS: &str = "WEBSOCKET_CALLBACK_CLIENTS_COUNT";
const CLIENT_ID_DTO: &str = "org.mockserver.serialization.model.WebSocketClientIdDTO";

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Connects, optionally naming itself, and returns the socket with the client id of the first frame.
async fn register(port: u16, id: Option<&str>) -> (Socket, String, Value) {
    let mut request = format!("ws://127.0.0.1:{port}/_mockserver_callback_websocket").into_client_request().unwrap();
    if let Some(id) = id {
        request.headers_mut().insert("X-CLIENT-REGISTRATION-ID", id.parse().unwrap());
    }
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.expect("callback websocket");
    let frame = socket.next().await.expect("registration frame").expect("registration message");
    let envelope: Value = serde_json::from_str(frame.to_text().expect("a text frame")).unwrap();
    let dto: Value = serde_json::from_str(envelope["value"].as_str().expect("the value is JSON text")).unwrap();
    (socket, dto["clientId"].as_str().expect("a clientId").to_string(), envelope)
}

#[tokio::test(flavor = "multi_thread")]
async fn register_client_sends_web_socket_client_id_dto() {
    let server = common::start(&[("metricsEnabled", "true")]).await;
    let (_socket, id, envelope) = register(server.port, Some("test-header-less-client-id")).await;
    assert_eq!(envelope["type"], CLIENT_ID_DTO);
    assert_eq!(id, "test-header-less-client-id");
    assert!(common::eventually(|| server.server.metric(CLIENTS) == Some(1)).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn register_client_with_server_generated_id_sends_correct_dto() {
    let server = common::start(&[("metricsEnabled", "true")]).await;
    let (_socket, id, envelope) = register(server.port, None).await;
    assert_eq!(envelope["type"], CLIENT_ID_DTO);
    assert!(uuid::Uuid::parse_str(&id).is_ok(), "a server-generated client id is a UUID: {id}");
    assert!(common::eventually(|| server.server.metric(CLIENTS) == Some(1)).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn multiple_clients_can_register_independently() {
    let server = common::start(&[("metricsEnabled", "true")]).await;
    let (_first, first_id, _) = register(server.port, Some("language-client-id")).await;
    let (_second, second_id, _) = register(server.port, None).await;
    assert_eq!(first_id, "language-client-id");
    assert_ne!(first_id, second_id);
    assert!(common::eventually(|| server.server.metric(CLIENTS) == Some(2)).await);
}
