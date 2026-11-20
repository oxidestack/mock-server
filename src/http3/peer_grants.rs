//! The client's flow-control grants from its QUIC transport parameters, as Netty reads them with
//! `QuicChannel.peerTransportParameters()` for `Http3StreamWriteStallHandler.holderBytes`. quinn keeps the decoded
//! parameters to itself, so the server's TLS sessions are wrapped: a session answers `handshake_data` with its
//! inner handshake data and the grants read from `transport_parameters` (whose fields are crate-private, so they are
//! written back out and the two varints read from the wire form).

use std::any::Any;
use std::sync::Arc;

use quinn::crypto::{self, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, UnsupportedVersion};
use quinn::{ConnectionId, Side};
use quinn_proto::TransportError;
use quinn_proto::transport_parameters::TransportParameters;

/// `initial_max_data` (RFC 9000 section 18.2).
const INITIAL_MAX_DATA: u64 = 0x04;
/// `initial_max_stream_data_bidi_local`: the credit the client grants each stream it opens, so each request stream.
const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;

/// What the client granted: the connection's credit and each request stream's.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct Grants {
    pub(crate) initial_max_data: u64,
    pub(crate) initial_max_stream_data_bidi_local: u64,
}

/// The grants of `connection`'s client, `None` before its first flight was read (never, for an accepted connection).
pub(crate) fn of(connection: &quinn::Connection) -> Option<Grants> {
    connection.handshake_data()?.downcast::<Handshake>().ok()?.grants
}

/// The server's QUIC TLS configuration, its sessions wrapped in [`GrantsSession`].
pub(super) struct GrantsServerConfig(pub(super) Arc<quinn::crypto::rustls::QuicServerConfig>);

impl crypto::ServerConfig for GrantsServerConfig {
    fn initial_keys(&self, version: u32, dst_cid: &ConnectionId) -> Result<Keys, UnsupportedVersion> {
        self.0.initial_keys(version, dst_cid)
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.0.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(self: Arc<Self>, version: u32, params: &TransportParameters) -> Box<dyn crypto::Session> {
        Box::new(GrantsSession(self.0.clone().start_session(version, params)))
    }
}

/// [`GrantsSession::handshake_data`]: the inner session's, and the client's grants.
pub(crate) struct Handshake {
    #[allow(dead_code)]
    pub(crate) inner: Box<dyn Any>,
    pub(crate) grants: Option<Grants>,
}

struct GrantsSession(Box<dyn crypto::Session>);

impl GrantsSession {
    fn grants(&self) -> Option<Grants> {
        let params = self.0.transport_parameters().ok()??;
        let mut wire = Vec::new();
        params.write(&mut wire);
        Some(decode(&wire))
    }
}

/// The two grants of a transport parameters' wire form (`id`, `length`, value, each id and the values varints); one
/// left out is 0, its default.
fn decode(wire: &[u8]) -> Grants {
    let mut grants = Grants::default();
    let mut at = 0;
    while let Some((id, next)) = varint(wire, at) {
        let Some((length, next)) = varint(wire, next) else { break };
        let end = next + length as usize;
        let Some(value) = wire.get(next..end) else { break };
        let read = || varint(value, 0).map(|(v, _)| v).unwrap_or(0);
        match id {
            INITIAL_MAX_DATA => grants.initial_max_data = read(),
            INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => grants.initial_max_stream_data_bidi_local = read(),
            _ => {}
        }
        at = end;
    }
    grants
}

fn varint(buf: &[u8], at: usize) -> Option<(u64, usize)> {
    let first = *buf.get(at)?;
    let size = 1usize << (first >> 6);
    let bytes = buf.get(at..at + size)?;
    let value = bytes[1..].iter().fold(u64::from(first & 0x3f), |v, b| (v << 8) | u64::from(*b));
    Some((value, at + size))
}

impl crypto::Session for GrantsSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        self.0.initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        let inner = self.0.handshake_data()?;
        Some(Box::new(Handshake { inner, grants: self.grants() }))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.0.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        self.0.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.0.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.0.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.0.read_handshake(buf)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.0.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        self.0.write_handshake(buf)
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.0.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.0.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(&self, output: &mut [u8], label: &[u8], context: &[u8]) -> Result<(), ExportKeyingMaterialError> {
        self.0.export_keying_material(output, label, context)
    }
}
