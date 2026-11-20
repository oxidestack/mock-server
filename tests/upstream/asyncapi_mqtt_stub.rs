//! A stand-in for the mocked Paho `MqttClient` of the MQTT subscriber tests: an MQTT 3.1.1 or 5 broker on a local
//! port that accepts one client, acknowledges its CONNECT, SUBSCRIBEs (remembering each filter and QoS) and
//! UNSUBSCRIBEs, and delivers what a test hands it — the `messageArrived` and `disconnected` callbacks of the mock.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[derive(Default)]
struct Seen {
    subscriptions: Vec<(String, u8)>,
    disconnects: usize,
}

pub struct StubMqttBroker {
    pub url: String,
    v5: bool,
    seen: Arc<Mutex<Seen>>,
    outgoing: mpsc::UnboundedSender<Option<Vec<u8>>>,
}

fn remaining_length(mut n: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (n % 128) as u8;
        n /= 128;
        if n > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}

fn packet(first: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![first];
    remaining_length(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

fn string(s: &str, out: &mut Vec<u8>) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn read_string(body: &[u8], at: &mut usize) -> String {
    let len = u16::from_be_bytes([body[*at], body[*at + 1]]) as usize;
    let s = String::from_utf8_lossy(&body[*at + 2..*at + 2 + len]).into_owned();
    *at += 2 + len;
    s
}

/// Skips an MQTT 5 property block (a variable-byte length, then the properties).
fn skip_properties(body: &[u8], at: &mut usize) {
    let (mut len, mut shift) = (0usize, 0);
    loop {
        let byte = body[*at];
        *at += 1;
        len |= ((byte & 0x7f) as usize) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    *at += len;
}

impl StubMqttBroker {
    /// Listens on a free local port for one MQTT 3.1.1 (`v5 == false`) or MQTT 5 client.
    pub async fn start(v5: bool) -> StubMqttBroker {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("tcp://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let seen = Arc::new(Mutex::new(Seen::default()));
        let (outgoing, mut to_client) = mpsc::unbounded_channel::<Option<Vec<u8>>>();
        let replies = outgoing.clone();
        let record = seen.clone();
        tokio::spawn(async move {
            let Ok((socket, _)) = listener.accept().await else { return };
            let (mut reader, mut writer) = socket.into_split();
            tokio::spawn(async move {
                // `None` ends the connection.
                while let Some(Some(bytes)) = to_client.recv().await {
                    if writer.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
                let _ = writer.shutdown().await;
            });
            loop {
                let Ok(first) = reader.read_u8().await else { return };
                let (mut len, mut shift) = (0usize, 0);
                loop {
                    let Ok(byte) = reader.read_u8().await else { return };
                    len |= ((byte & 0x7f) as usize) << shift;
                    shift += 7;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
                let mut body = vec![0; len];
                if reader.read_exact(&mut body).await.is_err() {
                    return;
                }
                let reply = match first >> 4 {
                    // CONNECT → CONNACK (accepted; MQTT 5 with no properties).
                    1 => Some(if v5 { packet(0x20, &[0, 0, 0]) } else { packet(0x20, &[0, 0]) }),
                    // SUBSCRIBE → SUBACK granting each filter its QoS.
                    8 => {
                        let mut at = 2;
                        if v5 {
                            skip_properties(&body, &mut at);
                        }
                        let mut granted = Vec::new();
                        while at < body.len() {
                            let filter = read_string(&body, &mut at);
                            let qos = body[at] & 0x03;
                            at += 1;
                            record.lock().subscriptions.push((filter, qos));
                            granted.push(qos);
                        }
                        let mut ack = body[..2].to_vec();
                        if v5 {
                            ack.push(0);
                        }
                        ack.extend(granted);
                        Some(packet(0x90, &ack))
                    }
                    // UNSUBSCRIBE → UNSUBACK.
                    10 => {
                        let mut at = 2;
                        if v5 {
                            skip_properties(&body, &mut at);
                        }
                        let mut count = 0;
                        while at < body.len() {
                            read_string(&body, &mut at);
                            count += 1;
                        }
                        let mut ack = body[..2].to_vec();
                        if v5 {
                            ack.push(0);
                            ack.extend(std::iter::repeat_n(0, count));
                        }
                        Some(packet(0xb0, &ack))
                    }
                    // PINGREQ → PINGRESP.
                    12 => Some(vec![0xd0, 0]),
                    // DISCONNECT.
                    14 => {
                        record.lock().disconnects += 1;
                        let _ = replies.send(None);
                        return;
                    }
                    _ => None,
                };
                if let Some(reply) = reply {
                    let _ = replies.send(Some(reply));
                }
            }
        });
        StubMqttBroker { url, v5, seen, outgoing }
    }

    /// `callback.messageArrived(topic, message)`: a QoS 0 PUBLISH, with MQTT 5 user properties.
    pub fn deliver(&self, topic: &str, payload: &str, user_properties: &[(&str, &str)]) {
        let mut body = Vec::new();
        string(topic, &mut body);
        if self.v5 {
            let mut properties = Vec::new();
            for (k, v) in user_properties {
                properties.push(0x26);
                string(k, &mut properties);
                string(v, &mut properties);
            }
            remaining_length(properties.len(), &mut body);
            body.extend(properties);
        }
        body.extend_from_slice(payload.as_bytes());
        let _ = self.outgoing.send(Some(packet(0x30, &body)));
    }

    /// `callback.disconnected(…)`: the broker ends the session (an MQTT 5 DISCONNECT first) and closes the connection.
    pub fn disconnect(&self) {
        if self.v5 {
            let _ = self.outgoing.send(Some(vec![0xe0, 0]));
        }
        let _ = self.outgoing.send(None);
    }

    /// The filters and QoS the client subscribed with, in order.
    pub fn subscriptions(&self) -> Vec<(String, u8)> {
        self.seen.lock().subscriptions.clone()
    }

    pub fn disconnects(&self) -> usize {
        self.seen.lock().disconnects
    }
}

/// Waits (up to 5 s) until `done` holds, as the asynchronous delivery replaces the mock's synchronous callback.
pub async fn eventually(mut done: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    done()
}
