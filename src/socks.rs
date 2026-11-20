//! SOCKS4/4a and SOCKS5 on the shared port (`SocksDetector`, `Socks4ProxyHandler`, `Socks5ProxyHandler`): after the
//! handshake the tunnel is served as MockServer itself with the SOCKS destination as the connection's remote socket,
//! over TLS when the client's first tunnelled bytes are a TLS record (`RelayTlsDetectionHandler`).

use std::sync::Arc;

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::handler::Connection;
use crate::rewind::Rewind;
use crate::server::Io;
use crate::state::State;

const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_GSSAPI: u8 = 0x01;
const SOCKS5_PASSWORD: u8 = 0x02;
const SOCKS5_UNACCEPTED: u8 = 0xff;

#[derive(Debug, PartialEq)]
pub enum Sniff {
    Socks4,
    Socks5,
    /// Not SOCKS.
    No,
    /// Could still be SOCKS: read more.
    More,
}

/// `SocksDetector.isSocks4` / `isSocks5`: the buffered bytes are exactly one SOCKS4 request or SOCKS5 greeting.
pub fn sniff(buf: &[u8]) -> Sniff {
    match buf.first() {
        Some(4) => match socks4_request(buf) {
            Some(Ok(len)) if len == buf.len() => Sniff::Socks4,
            Some(Ok(_)) | Some(Err(())) => Sniff::No,
            None => Sniff::More,
        },
        Some(5) => {
            let Some(&n) = buf.get(1) else { return Sniff::More };
            let methods = &buf[2..buf.len().min(2 + n as usize)];
            if methods.iter().any(|m| ![SOCKS5_NO_AUTH, SOCKS5_GSSAPI, SOCKS5_PASSWORD].contains(m)) {
                return Sniff::No;
            }
            match buf.len().cmp(&(2 + n as usize)) {
                std::cmp::Ordering::Less => Sniff::More,
                std::cmp::Ordering::Equal => Sniff::Socks5,
                std::cmp::Ordering::Greater => Sniff::No,
            }
        }
        Some(_) => Sniff::No,
        None => Sniff::More,
    }
}

/// The length of the SOCKS4(a) request at the front of `buf`: `None` while incomplete, `Err` when it is not one.
/// Usernames and SOCKS4a hostnames are NUL-terminated within 256 bytes.
fn socks4_request(buf: &[u8]) -> Option<Result<usize, ()>> {
    let command = *buf.get(1)?;
    if command != 1 && command != 2 {
        return Some(Err(()));
    }
    let ip = buf.get(4..8)?;
    let socks4a = ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0;
    let mut i = 8;
    let terminated = |from: usize, allow_empty: bool| -> Option<Result<usize, ()>> {
        if !allow_empty && *buf.get(from)? == 0 {
            return Some(Err(()));
        }
        for j in from..from + 256 {
            if *buf.get(j)? == 0 {
                return Some(Ok(j + 1));
            }
        }
        Some(Err(()))
    };
    i = match terminated(i, true)? {
        Ok(next) => next,
        Err(()) => return Some(Err(())),
    };
    if socks4a {
        i = match terminated(i, false)? {
            Ok(next) => next,
            Err(()) => return Some(Err(())),
        };
    }
    Some(Ok(i))
}

/// Netty reads SOCKS hosts as US-ASCII: a byte above 0x7F decodes to U+FFFD.
fn ascii(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| if b < 0x80 { b as char } else { '\u{FFFD}' }).collect()
}

/// Reads until `buf` holds at least `n` bytes; `false` at end of stream.
async fn fill(io: &mut Box<dyn Io>, buf: &mut BytesMut, n: usize) -> bool {
    while buf.len() < n {
        buf.reserve(n - buf.len());
        match io.read_buf(buf).await {
            Ok(0) | Err(_) => return false,
            Ok(_) => {}
        }
    }
    true
}

/// A SOCKS4(a) CONNECT (BIND is refused), then the tunnel.
pub async fn serve4(state: Arc<State>, conn: Connection, mut io: Box<dyn Io>, mut buf: BytesMut, secure: bool) {
    conn.idle.socks_handshake();
    let Some(Ok(len)) = socks4_request(&buf) else { return };
    let request = buf.split_to(len);
    let ip = [request[4], request[5], request[6], request[7]];
    let socks4a = ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0;
    let host = if socks4a {
        let user_end = request[8..].iter().position(|b| *b == 0).map_or(8, |p| 8 + p + 1);
        ascii(&request[user_end..request.len() - 1])
    } else {
        std::net::Ipv4Addr::from(ip).to_string()
    };
    // Netty's `Socks4ServerDecoder` builds a `DefaultSocks4CommandRequest`, which refuses a host `IDN.toASCII` rejects
    // and port 0; its failure message (`fail`) keeps the host and carries port 65535 instead. With a refused host that
    // fails again, and the decoder's exception closes the connection unanswered.
    if socks4a && crate::dns::idn_to_ascii(&host).is_err() {
        return;
    }
    let port = match u16::from_be_bytes([request[2], request[3]]) {
        0 => 65535,
        port => port,
    };
    // `Socks4ConnectHandler.socks4Response`: an IPv4 destination is echoed back, a hostname becomes 0.0.0.0:0.
    let reply = |status: u8, echo: bool| -> Vec<u8> {
        let mut r = vec![0x00, status];
        if echo && !socks4a {
            r.extend_from_slice(&port.to_be_bytes());
            r.extend_from_slice(&ip);
        } else {
            r.extend_from_slice(&[0; 6]);
        }
        r
    };
    if request[1] != 1 {
        let _ = io.write_all(&reply(0x5b, false)).await;
        return;
    }
    // the loopback leg refused by `maxInboundConnections` (`server::OpenConnections::loopback_leg`)
    let Some(loopback_leg) = state.connections.loopback_leg(&state, conn.remote) else {
        let _ = io.write_all(&reply(0x5b, true)).await;
        let _ = io.shutdown().await;
        return;
    };
    if io.write_all(&reply(0x5a, true)).await.is_err() {
        return;
    }
    tunnel(state, Connection { event_loop: loopback_leg.event_loop, ..conn }, io, buf, secure, host, port).await;
    drop(loopback_leg);
}

/// A SOCKS5 greeting, optional username/password authentication and CONNECT, then the tunnel.
pub async fn serve5(state: Arc<State>, conn: Connection, mut io: Box<dyn Io>, mut buf: BytesMut, secure: bool) {
    conn.idle.socks_handshake();
    let n = buf[1] as usize;
    let mut offered: Vec<u8> = buf[2..2 + n].to_vec();
    // Netty's `Socks5InitialRequestDecoder` cannot build a request with no methods; its failure message carries NO_AUTH.
    if offered.is_empty() {
        offered.push(SOCKS5_NO_AUTH);
    }
    buf.advance(2 + n);
    let non_blank = |name: &str| state.config.property(name).filter(|v| !v.trim().is_empty());
    let credentials = non_blank("proxyAuthenticationUsername").zip(non_blank("proxyAuthenticationPassword"));
    // `handleInitialRequest`: NO_AUTH when offered, PASSWORD when only that is offered and credentials are set.
    let required = if !offered.contains(&SOCKS5_NO_AUTH) && offered.contains(&SOCKS5_PASSWORD) && credentials.is_some() {
        SOCKS5_PASSWORD
    } else {
        SOCKS5_NO_AUTH
    };
    let chosen = if offered.contains(&required) { required } else { SOCKS5_UNACCEPTED };
    if io.write_all(&[5, chosen]).await.is_err() {
        return;
    }
    if chosen == SOCKS5_UNACCEPTED {
        // No decoder follows the refusal: the `PortUnificationHandler` behind the SOCKS handlers classifies the next
        // bytes afresh (another greeting, HTTP, ...).
        conn.idle.socks_done();
        return crate::server::serve_unified(state, conn, Rewind { prefix: buf, inner: io }, secure).await;
    }
    if chosen == SOCKS5_PASSWORD {
        // RFC 1929: VER ULEN UNAME PLEN PASSWD.
        if !fill(&mut io, &mut buf, 2).await {
            return;
        }
        let ulen = buf[1] as usize;
        if !fill(&mut io, &mut buf, 2 + ulen + 1).await {
            return;
        }
        let plen = buf[2 + ulen] as usize;
        if !fill(&mut io, &mut buf, 3 + ulen + plen).await {
            return;
        }
        let message = buf.split_to(3 + ulen + plen);
        let username = String::from_utf8_lossy(&message[2..2 + ulen]).into_owned();
        let password = String::from_utf8_lossy(&message[3 + ulen..]).into_owned();
        let (expected_user, expected_password) = credentials.clone().unwrap_or_default();
        if crate::auth::constant_time_eq(username.as_bytes(), expected_user.as_bytes())
            & crate::auth::constant_time_eq(password.as_bytes(), expected_password.as_bytes())
        {
            if io.write_all(&[1, 0x00]).await.is_err() {
                return;
            }
        } else {
            let _ = io.write_all(&[1, 0xff]).await;
            if state.info_enabled() {
                let entry = crate::recorded::LogEntry::new(crate::recorded::Kind::AuthenticationFailed, "proxy authentication failed so returning SOCKS FAILURE response");
                // Upstream's SOCKS handler logs it without a port.
                state.log.message(entry.without_port());
            }
            return;
        }
    }
    // VER CMD RSV ATYP DST.ADDR DST.PORT
    if !fill(&mut io, &mut buf, 5).await {
        return;
    }
    let address_length = match buf[3] {
        1 => Some(4),
        3 => Some(1 + buf[4] as usize),
        4 => Some(16),
        _ => None,
    };
    let decoded = match address_length {
        Some(address_length) => {
            if !fill(&mut io, &mut buf, 4 + address_length + 2).await {
                return;
            }
            let message = buf.split_to(4 + address_length + 2);
            let address = &message[4..4 + address_length];
            let host = match message[3] {
                1 => std::net::Ipv4Addr::new(address[0], address[1], address[2], address[3]).to_string(),
                3 => ascii(&address[1..]),
                _ => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(address).unwrap_or_default()).to_string(),
            };
            let port = u16::from_be_bytes([message[4 + address_length], message[5 + address_length]]);
            Some((message[1], host, port)).filter(|(_, host, _)| crate::dns::idn_to_ascii(host).is_ok())
        }
        None => None,
    };
    // `Socks5CommandRequestDecoder.fail`: an unknown address type, or a domain `DefaultSocks5CommandRequest` refuses
    // (`IDN.toASCII`), becomes a CONNECT to 0.0.0.0:1, and the decoder, now in its FAILURE state, discards whatever else
    // it had buffered.
    let (command, host, port) = decoded.unwrap_or_else(|| {
        buf.clear();
        (1, "0.0.0.0".to_string(), 1)
    });
    // `DefaultSocks5CommandResponse(status, DOMAIN, host, port)`.
    let reply = |status: u8, host: &str, port: u16| -> Vec<u8> {
        let mut r = vec![5, status, 0x00, 0x03, host.len() as u8];
        r.extend_from_slice(host.as_bytes());
        r.extend_from_slice(&port.to_be_bytes());
        r
    };
    if command != 1 {
        let _ = io.write_all(&reply(0x07, "", 0)).await;
        return;
    }
    // `Socks5ConnectHandler.failureResponse` when the loopback leg is refused
    let Some(loopback_leg) = state.connections.loopback_leg(&state, conn.remote) else {
        let _ = io.write_all(&reply(0x01, &host, port)).await;
        let _ = io.shutdown().await;
        return;
    };
    if io.write_all(&reply(0x00, &host, port)).await.is_err() {
        return;
    }
    tunnel(state, Connection { event_loop: loopback_leg.event_loop, ..conn }, io, buf, secure, host, port).await;
    drop(loopback_leg);
}

/// The SOCKS relay's tunnel: the target becomes the connection's remote socket, and the first tunnelled bytes decide
/// what is served (`server::serve_tunnel`, shared with CONNECT).
async fn tunnel(state: Arc<State>, mut conn: Connection, io: Box<dyn Io>, buf: BytesMut, secure: bool, host: String, port: u16) {
    if let Some(tls) = state.tls.as_ref() {
        tls.add_subject_alternative_name(&host);
    }
    conn.proxy_target = Some((host, port));
    // the relay handlers sit behind the idle handler
    conn.idle.socks_done();
    crate::server::serve_tunnel(state, conn, Box::new(Rewind { prefix: buf, inner: io }), secure).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_socks4_socks4a_and_socks5_greetings() {
        assert_eq!(sniff(&[4, 1, 0, 80, 127, 0, 0, 1, b'u', 0]), Sniff::Socks4);
        assert_eq!(sniff(&[4, 1, 0, 80, 0, 0, 0, 1, 0, b'h', 0]), Sniff::Socks4);
        assert_eq!(sniff(&[4, 1, 0, 80, 0, 0, 0, 1, 0, b'h']), Sniff::More);
        assert_eq!(sniff(&[4, 3, 0, 80, 127, 0, 0, 1, 0]), Sniff::No);
        assert_eq!(sniff(&[5, 2, 0, 2]), Sniff::Socks5);
        assert_eq!(sniff(&[5, 2, 0]), Sniff::More);
        assert_eq!(sniff(&[5, 1, 9]), Sniff::No);
        assert_eq!(sniff(b"GET / HTTP/1.1"), Sniff::No);
    }
}
