//! Paho's MQTT 3.1 fallback. A client left at `MqttConnectOptions.MQTT_VERSION_DEFAULT` (as upstream leaves it)
//! connects as MQTT 3.1.1 and, when that attempt fails for any reason, tries once more as MQTT 3.1 (protocol name
//! `MQIsdp`, level 3; `ConnectActionListener.onFailure`). rumqttc writes 3.1.1 only, so the retry runs it against a
//! loopback relay that dials the broker as the failed attempt did (TCP, TLS, or a WebSocket over either), rewrites
//! the client's CONNECT to 3.1, and then passes the packets through unchanged: the other MQTT 3.1 packets are the
//! 3.1.1 ones.

use std::time::Duration;

use bytes::{Buf, BytesMut};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use super::tls::Stream;

/// The broker connection the relay writes to.
pub(super) enum Upstream {
    /// TCP or TLS: MQTT packets as bytes.
    Raw(Box<dyn Stream>),
    /// A WebSocket (`ws`/`wss`): MQTT bytes in binary messages.
    Ws(Box<WebSocketStream<Box<dyn Stream>>>),
}

/// Opens the WebSocket Paho's `WebSocketNetworkModule` opens (subprotocol `mqtt`) over a dialed stream.
pub(super) async fn websocket(stream: Box<dyn Stream>, url: &str) -> Result<Upstream, String> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = url.into_client_request().map_err(|e| e.to_string())?;
    request.headers_mut().insert("Sec-WebSocket-Protocol", "mqtt".parse().expect("static header value"));
    let (socket, _) = tokio_tungstenite::client_async(request, stream).await.map_err(|e| e.to_string())?;
    Ok(Upstream::Ws(Box::new(socket)))
}

/// Starts a relay to `upstream` on a loopback port and returns the port; it serves one connection, which it
/// expects within `accept_within`.
pub(super) async fn relay(upstream: Upstream, accept_within: Duration) -> std::io::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    super::broker::spawn(async move {
        let Ok(Ok((client, _))) = tokio::time::timeout(accept_within, listener.accept()).await else { return };
        drop(listener);
        let _ = client.set_nodelay(true);
        let _ = pump(client, upstream).await;
    });
    Ok(port)
}

/// Reads the client's first packet, sends it on as 3.1, then relays both ways until either side closes.
async fn pump(mut client: tokio::net::TcpStream, upstream: Upstream) -> std::io::Result<()> {
    let mut pending = BytesMut::new();
    let connect = loop {
        if let Some(length) = packet_length(&pending) && pending.len() >= length {
            break pending.split_to(length);
        }
        if client.read_buf(&mut pending).await? == 0 {
            return Ok(());
        }
    };
    let connect = as_mqtt31(&connect).unwrap_or_else(|| connect.to_vec());
    match upstream {
        Upstream::Raw(mut broker) => {
            broker.write_all(&connect).await?;
            broker.write_all(&pending).await?;
            broker.flush().await?;
            tokio::io::copy_bidirectional(&mut client, &mut broker).await?;
        }
        Upstream::Ws(mut broker) => {
            let mut first = BytesMut::from(&connect[..]);
            first.extend_from_slice(&pending);
            broker.send(Message::Binary(first.freeze())).await.map_err(std::io::Error::other)?;
            let mut buf = vec![0u8; 16384];
            loop {
                tokio::select! {
                    n = client.read(&mut buf) => {
                        let n = n?;
                        if n == 0 {
                            let _ = SinkExt::close(&mut broker).await;
                            return Ok(());
                        }
                        broker.send(Message::Binary(bytes::Bytes::copy_from_slice(&buf[..n]))).await.map_err(std::io::Error::other)?;
                    }
                    message = broker.next() => match message {
                        Some(Ok(Message::Binary(data))) => client.write_all(&data).await?,
                        Some(Ok(Message::Close(_))) | None => return Ok(()),
                        Some(Ok(_)) => {}
                        Some(Err(e)) => return Err(std::io::Error::other(e)),
                    },
                }
            }
        }
    }
    Ok(())
}

/// The fixed header's length and the remaining length it announces, once the header is in.
fn fixed_header(data: &[u8]) -> Option<(usize, usize)> {
    let mut remaining = 0usize;
    for (i, byte) in data.iter().skip(1).take(4).enumerate() {
        remaining |= ((byte & 0x7f) as usize) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((i + 2, remaining));
        }
    }
    None
}

/// The length of the MQTT packet at the start of `data`, once its fixed header is in.
fn packet_length(data: &[u8]) -> Option<usize> {
    fixed_header(data).map(|(header, remaining)| header + remaining)
}

/// A 3.1.1 CONNECT (`MQTT`, level 4) as Paho writes it for 3.1 (`MQIsdp`, level 3); None for anything else.
fn as_mqtt31(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.first() != Some(&0x10) {
        return None;
    }
    let (header, _) = fixed_header(packet)?;
    let mut body = &packet[header..];
    if body.len() < 7 || &body[..7] != b"\x00\x04MQTT\x04" {
        return None;
    }
    body.advance(7);
    let mut out_body = b"\x00\x06MQIsdp\x03".to_vec();
    out_body.extend_from_slice(body);
    let mut out = vec![0x10];
    let mut length = out_body.len();
    loop {
        let mut byte = (length % 128) as u8;
        length /= 128;
        if length > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if length == 0 {
            break;
        }
    }
    out.extend_from_slice(&out_body);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_is_rewritten_to_mqtt31() {
        // CONNECT, clean session, keep alive 60, client id "c".
        let v4 = b"\x10\x0d\x00\x04MQTT\x04\x02\x00\x3c\x00\x01c";
        assert_eq!(packet_length(v4), Some(v4.len()));
        assert_eq!(as_mqtt31(v4).unwrap(), b"\x10\x0f\x00\x06MQIsdp\x03\x02\x00\x3c\x00\x01c");
        // A remaining length crossing 127 grows its own header.
        let mut long = b"\x10\x7e\x00\x04MQTT\x04\x02\x00\x3c\x00\x72".to_vec();
        long.extend(std::iter::repeat_n(b'x', 0x72));
        assert_eq!(packet_length(&long), Some(long.len()));
        let rewritten = as_mqtt31(&long).unwrap();
        assert_eq!(&rewritten[..3], b"\x10\x80\x01");
        assert_eq!(packet_length(&rewritten), Some(rewritten.len()));
        assert_eq!(as_mqtt31(b"\x30\x02\x00\x00"), None);
    }
}
