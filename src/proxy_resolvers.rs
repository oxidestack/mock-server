//! Original-destination resolvers for `transparentProxyEnabled`, matching upstream's
//! `CompositeOriginalDestinationResolver` default chain (`TproxyOriginalDestinationResolver`,
//! `EbpfOriginalDestinationResolver`, `SoOriginalDstResolver`, then `ConntrackOriginalDestinationResolver` and
//! `DnsIntentOriginalDestinationResolver`). `server.rs` tries, in order: [`tproxy`], [`linux::ebpf`],
//! [`linux::so_original_dst`], then its own existing DNS-intent lookup, before an explicit PROXY protocol header
//! (read from the first bytes, tried last) overrides whatever the chain resolved — exactly upstream's ordering
//! (`TransparentProxyHandler`'s Javadoc: the channel-level chain resolves at `channelActive`, a PROXY header
//! resolved from inbound bytes always wins).
//!
//! `ConntrackOriginalDestinationResolver` (`/proc/net/nf_conntrack` table scan) is **not** ported: the scope is the three
//! resolvers named here (SO_ORIGINAL_DST, TPROXY, eBPF).
//!
//! SO_ORIGINAL_DST and eBPF are Linux-only (raw `getsockopt`/`bpf()` syscalls, gated behind `mod linux` and
//! `#[cfg(target_os = "linux")]`); on every other OS they simply do not exist, so [`tproxy`] alone (a portable
//! function — TPROXY's "resolution" is just reading the accepted socket's local address, no syscall involved) is
//! reachable, and `server.rs`'s DNS-intent + PROXY-protocol path continues to work everywhere it does today.

use std::net::SocketAddr;
#[cfg(any(target_os = "linux", test))]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::Config;

/// `TproxyOriginalDestinationResolver.resolve`: with TPROXY iptables rules (not REDIRECT) and `IP_TRANSPARENT` set
/// on the listening socket (`bind_transparent` below), the kernel preserves the original destination as the
/// accepted socket's own local address — no syscall needed, `local` already *is* it. Returns `None` (falls through
/// to the next strategy) unless `transparentProxyTproxy` is set, exactly like upstream.
pub fn tproxy(config: &Config, local: SocketAddr) -> Option<SocketAddr> {
    config.bool_property("transparentProxyTproxy", false).then_some(local)
}

/// `EbpfOriginalDestinationResolver.decodeMapValue`: a 6-byte BPF map value, 4-byte IPv4 address followed by a
/// 2-byte port, both network byte order. Extra trailing bytes are ignored (the map's value size is fixed at 6, but
/// a caller may still hand over a longer slice); fewer than 6 bytes cannot be decoded.
#[cfg(any(target_os = "linux", test))]
pub fn decode_ebpf_map_value(value: &[u8]) -> Option<SocketAddr> {
    if value.len() < 6 {
        return None;
    }
    let addr = Ipv4Addr::new(value[0], value[1], value[2], value[3]);
    let port = u16::from_be_bytes([value[4], value[5]]);
    Some(SocketAddr::new(IpAddr::V4(addr), port))
}

#[cfg(any(target_os = "linux", test))]
const AF_INET: u16 = 2;
#[cfg(any(target_os = "linux", test))]
const AF_INET6: u16 = 10;

/// `SoOriginalDstResolver.decodeSockaddr`: a raw `sockaddr_in` (16 bytes) or `sockaddr_in6` (28 bytes) as
/// `getsockopt(SO_ORIGINAL_DST)` returns it. `sa_family` (bytes 0-1) is the platform's **native** byte order (a
/// `sa_family_t`, not a protocol field); `sin_port`/`sin6_port` (bytes 2-3) and the address that follows are network
/// byte order, as for every other socket-address field. IPv6's `sin6_addr` is at bytes 8-23 (bytes 4-7 are
/// `sin6_flowinfo`, skipped, matching upstream).
#[cfg(any(target_os = "linux", test))]
pub fn decode_so_original_dst_sockaddr(sockaddr: &[u8]) -> Option<SocketAddr> {
    if sockaddr.len() < 4 {
        return None;
    }
    let family = u16::from_ne_bytes([sockaddr[0], sockaddr[1]]);
    match family {
        AF_INET if sockaddr.len() >= 16 => {
            let port = u16::from_be_bytes([sockaddr[2], sockaddr[3]]);
            let addr = Ipv4Addr::new(sockaddr[4], sockaddr[5], sockaddr[6], sockaddr[7]);
            Some(SocketAddr::new(IpAddr::V4(addr), port))
        }
        AF_INET6 if sockaddr.len() >= 28 => {
            let port = u16::from_be_bytes([sockaddr[2], sockaddr[3]]);
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&sockaddr[8..24]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => None,
    }
}

/// The chain `server.rs` tries at connection-accept, before its existing DNS-intent lookup: TPROXY (needs only
/// `local`, works on every OS the same function runs on — it is gated purely on configuration), then eBPF and
/// SO_ORIGINAL_DST (Linux-only; compiled out, so effectively skipped, elsewhere).
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub fn resolve(config: &Config, local: SocketAddr, fd: std::os::fd::RawFd) -> Option<SocketAddr> {
    if let Some(addr) = tproxy(config, local) {
        return Some(addr);
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(addr) = linux::ebpf(config, fd) {
            return Some(addr);
        }
        if !config.skips_so_original_dst()
            && let Some(addr) = linux::so_original_dst(fd, local.is_ipv6())
        {
            return Some(addr);
        }
    }
    None
}

/// Sets `IP_TRANSPARENT` (Linux: `SOL_IP = 0, IP_TRANSPARENT = 19`) on a not-yet-bound listening socket, the way
/// `MockServerIpTransparentHelper.applyEpollIpTransparent` sets it on the Netty server bootstrap. The caller
/// (`server.rs`'s listener bind) is the one that checks `transparentProxyTproxy`/`transparentProxyEnabled` and logs
/// accordingly — this function unconditionally attempts the syscall (Linux) or no-ops (`Ok(false)`, every other OS,
/// matching upstream's epoll-unavailable no-op). A `setsockopt` failure (most likely missing `CAP_NET_ADMIN`) is
/// propagated as an `Err`, exactly like upstream: "the Netty channel bind will fail" — this is deliberate, not a
/// soft fallback, because a server that was asked for TPROXY and cannot get it would otherwise silently misbehave.
#[cfg(target_os = "linux")]
pub fn bind_transparent(socket: &socket2::Socket) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;
    const SOL_IP: libc::c_int = 0;
    const IP_TRANSPARENT: libc::c_int = 19;
    let value: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            SOL_IP,
            IP_TRANSPARENT,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(true)
}

#[cfg(not(target_os = "linux"))]
pub fn bind_transparent(_socket: &socket2::Socket) -> std::io::Result<bool> {
    Ok(false)
}

/// Linux-only syscalls: `SO_ORIGINAL_DST` (`getsockopt`) and the eBPF pinned-map lookup (`bpf()` via the raw
/// `syscall()` entry point — no BPF loader crate needed, matching upstream's "no new dependencies" JNA approach).
#[cfg(target_os = "linux")]
pub mod linux {
    use std::net::SocketAddr;
    use std::os::fd::RawFd;

    use crate::config::Config;

    /// `SoOriginalDstResolver.resolve`, minus the Netty `EpollSocketChannel` gate (this crate always has the
    /// accepted connection's raw fd, epoll transport or not): `getsockopt(fd, SOL_IP|SOL_IPV6, SO_ORIGINAL_DST,
    /// ...)`. Never panics; any failure (no REDIRECT rule, not a redirected socket, …) is `None`, the same
    /// "fall through to the next strategy" contract as upstream.
    pub fn so_original_dst(fd: RawFd, ipv6: bool) -> Option<SocketAddr> {
        const SOL_IP: libc::c_int = 0;
        const SO_ORIGINAL_DST: libc::c_int = 80;
        const SOL_IPV6: libc::c_int = 41;
        const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;
        let (level, optname, size): (libc::c_int, libc::c_int, usize) =
            if ipv6 { (SOL_IPV6, IP6T_SO_ORIGINAL_DST, 28) } else { (SOL_IP, SO_ORIGINAL_DST, 16) };
        let mut buf = [0u8; 28];
        let mut len: libc::socklen_t = size as libc::socklen_t;
        let rc = unsafe { libc::getsockopt(fd, level, optname, buf.as_mut_ptr() as *mut libc::c_void, &mut len) };
        if rc != 0 {
            return None;
        }
        super::decode_so_original_dst_sockaddr(&buf[..len as usize])
    }

    // Linux syscall numbers for `bpf()` (no stable libc constant for this on every target, so — like upstream's
    // JNA binding — we hardcode the two architectures this project builds for).
    #[cfg(target_arch = "aarch64")]
    const SYS_BPF: libc::c_long = 280;
    #[cfg(not(target_arch = "aarch64"))]
    const SYS_BPF: libc::c_long = 321;

    const BPF_MAP_LOOKUP_ELEM: i32 = 1;
    const BPF_MAP_DELETE_ELEM: i32 = 3;
    const BPF_OBJ_GET: i32 = 7;
    const SOL_SOCKET: libc::c_int = 1;
    const SO_COOKIE: libc::c_int = 57;
    /// Byte size of the `bpf_attr` union scratch buffer: large enough for every field either `bpf()` command below
    /// touches, small enough that the kernel's tail-zero check accepts it (matches upstream's `BPF_ATTR_SIZE_*`).
    const BPF_ATTR_SIZE: usize = 64;

    /// `EbpfOriginalDestinationResolver.resolve`: reads the socket cookie (`SO_COOKIE`), looks it up in the pinned
    /// BPF hash map at `transparentProxyEbpfMapPath` (`bpf(BPF_OBJ_GET)` then `bpf(BPF_MAP_LOOKUP_ELEM)`), deletes
    /// the consumed entry (best-effort — a failed delete does not fail the lookup), and decodes the 6-byte value.
    /// `None` (config disabled, map missing, no matching cookie, anything else) falls through to the next strategy.
    pub fn ebpf(config: &Config, fd: RawFd) -> Option<SocketAddr> {
        if !config.bool_property("transparentProxyEbpf", false) {
            return None;
        }
        let path = config.property("transparentProxyEbpfMapPath").filter(|p| !p.trim().is_empty()).unwrap_or_else(|| "/sys/fs/bpf/mockserver_orig_dst".to_string());
        let map_fd = bpf_obj_get(&path)?;
        let cookie = socket_cookie(fd)?;
        let value = bpf_map_lookup(map_fd, cookie)?;
        bpf_map_delete(map_fd, cookie);
        super::decode_ebpf_map_value(&value)
    }

    fn bpf_obj_get(path: &str) -> Option<RawFd> {
        let cpath = std::ffi::CString::new(path).ok()?;
        let mut attr = [0u8; BPF_ATTR_SIZE];
        // `struct { __aligned_u64 pathname; ... }`: the pathname pointer at offset 0.
        attr[0..8].copy_from_slice(&(cpath.as_ptr() as u64).to_ne_bytes());
        let rc = unsafe { libc::syscall(SYS_BPF, BPF_OBJ_GET, attr.as_ptr() as *const libc::c_void, BPF_ATTR_SIZE as u32) };
        if rc < 0 { None } else { Some(rc as RawFd) }
    }

    fn socket_cookie(fd: RawFd) -> Option<u64> {
        let mut cookie: u64 = 0;
        let mut len: libc::socklen_t = 8;
        let rc = unsafe { libc::getsockopt(fd, SOL_SOCKET, SO_COOKIE, &mut cookie as *mut u64 as *mut libc::c_void, &mut len) };
        if rc != 0 { None } else { Some(cookie) }
    }

    fn bpf_map_lookup(map_fd: RawFd, cookie: u64) -> Option<[u8; 6]> {
        let mut value = [0u8; 6];
        let mut attr = [0u8; BPF_ATTR_SIZE];
        // `struct { __u32 map_fd; __u32 pad0; __aligned_u64 key; __aligned_u64 value; ... }`.
        attr[0..4].copy_from_slice(&(map_fd as u32).to_ne_bytes());
        attr[8..16].copy_from_slice(&(&cookie as *const u64 as u64).to_ne_bytes());
        attr[16..24].copy_from_slice(&(value.as_mut_ptr() as u64).to_ne_bytes());
        let rc = unsafe { libc::syscall(SYS_BPF, BPF_MAP_LOOKUP_ELEM, attr.as_ptr() as *const libc::c_void, BPF_ATTR_SIZE as u32) };
        if rc != 0 { None } else { Some(value) }
    }

    /// Best-effort: a failed delete does not fail the lookup that already succeeded (matches upstream exactly).
    fn bpf_map_delete(map_fd: RawFd, cookie: u64) {
        let mut attr = [0u8; BPF_ATTR_SIZE];
        attr[0..4].copy_from_slice(&(map_fd as u32).to_ne_bytes());
        attr[8..16].copy_from_slice(&(&cookie as *const u64 as u64).to_ne_bytes());
        unsafe {
            libc::syscall(SYS_BPF, BPF_MAP_DELETE_ELEM, attr.as_ptr() as *const libc::c_void, BPF_ATTR_SIZE as u32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- decode_so_original_dst_sockaddr: IPv4 (SoOriginalDstResolverTest.shouldDecodeIpv4Sockaddr et al.) ---

    fn ipv4_sockaddr(port: u16, a: u8, b: u8, c: u8, d: u8) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        buf[2..4].copy_from_slice(&port.to_be_bytes());
        buf[4..8].copy_from_slice(&[a, b, c, d]);
        buf
    }

    fn ipv6_sockaddr(port: u16, addr: [u8; 16]) -> [u8; 28] {
        let mut buf = [0u8; 28];
        buf[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        buf[2..4].copy_from_slice(&port.to_be_bytes());
        buf[8..24].copy_from_slice(&addr);
        buf
    }

    #[test]
    fn decodes_ipv4() {
        let result = decode_so_original_dst_sockaddr(&ipv4_sockaddr(80, 93, 184, 216, 34)).unwrap();
        assert_eq!(result, "93.184.216.34:80".parse().unwrap());
    }

    #[test]
    fn decodes_ipv4_high_port() {
        let result = decode_so_original_dst_sockaddr(&ipv4_sockaddr(8443, 10, 0, 0, 1)).unwrap();
        assert_eq!(result, "10.0.0.1:8443".parse().unwrap());
    }

    #[test]
    fn decodes_ipv4_max_port() {
        let result = decode_so_original_dst_sockaddr(&ipv4_sockaddr(65535, 127, 0, 0, 1)).unwrap();
        assert_eq!(result, "127.0.0.1:65535".parse().unwrap());
    }

    #[test]
    fn decodes_ipv4_port_zero() {
        let result = decode_so_original_dst_sockaddr(&ipv4_sockaddr(0, 1, 2, 3, 4)).unwrap();
        assert_eq!(result, "1.2.3.4:0".parse().unwrap());
    }

    #[test]
    fn decodes_ipv4_all_zeros_address() {
        let result = decode_so_original_dst_sockaddr(&ipv4_sockaddr(80, 0, 0, 0, 0)).unwrap();
        assert_eq!(result, "0.0.0.0:80".parse().unwrap());
    }

    #[test]
    fn decodes_ipv4_with_extra_padding() {
        let mut buf = vec![0u8; 32];
        buf[..16].copy_from_slice(&ipv4_sockaddr(80, 8, 8, 8, 8));
        let result = decode_so_original_dst_sockaddr(&buf).unwrap();
        assert_eq!(result, "8.8.8.8:80".parse().unwrap());
    }

    #[test]
    fn decodes_ipv6() {
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[2] = 0x0d;
        addr[3] = 0xb8;
        addr[15] = 0x01;
        let result = decode_so_original_dst_sockaddr(&ipv6_sockaddr(8080, addr)).unwrap();
        assert_eq!(result, "[2001:db8::1]:8080".parse().unwrap());
    }

    #[test]
    fn decodes_ipv6_loopback() {
        let mut addr = [0u8; 16];
        addr[15] = 0x01;
        let result = decode_so_original_dst_sockaddr(&ipv6_sockaddr(443, addr)).unwrap();
        assert_eq!(result, "[::1]:443".parse().unwrap());
    }

    #[test]
    fn decodes_ipv6_full_address() {
        let addr: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0xff, 0xfe, 0x23, 0x45, 0x67, 0x89, 0x0a];
        let result = decode_so_original_dst_sockaddr(&ipv6_sockaddr(1234, addr)).unwrap();
        assert_eq!(result, "[fe80::1ff:fe23:4567:890a]:1234".parse().unwrap());
    }

    #[test]
    fn rejects_null_length_inputs() {
        assert_eq!(decode_so_original_dst_sockaddr(&[]), None);
        assert_eq!(decode_so_original_dst_sockaddr(&[0, 0, 0]), None);
    }

    #[test]
    fn rejects_unknown_family() {
        let mut buf = [0u8; 16];
        buf[0..2].copy_from_slice(&99u16.to_ne_bytes());
        assert_eq!(decode_so_original_dst_sockaddr(&buf), None);
    }

    #[test]
    fn rejects_truncated_ipv4() {
        let mut buf = [0u8; 8];
        buf[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        assert_eq!(decode_so_original_dst_sockaddr(&buf), None);
    }

    #[test]
    fn rejects_truncated_ipv6() {
        let mut buf = [0u8; 16];
        buf[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        assert_eq!(decode_so_original_dst_sockaddr(&buf), None);
    }

    // --- decode_ebpf_map_value (EbpfOriginalDestinationResolverTest) ---

    #[test]
    fn decodes_ebpf_map_value() {
        let result = decode_ebpf_map_value(&[0xC0, 0x00, 0x02, 0x01, 0x1F, 0x90]).unwrap();
        assert_eq!(result, "192.0.2.1:8080".parse().unwrap());
    }

    #[test]
    fn decodes_ebpf_map_value_localhost() {
        let result = decode_ebpf_map_value(&[0x7F, 0x00, 0x00, 0x01, 0x01, 0xBB]).unwrap();
        assert_eq!(result, "127.0.0.1:443".parse().unwrap());
    }

    #[test]
    fn decodes_ebpf_map_value_high_port() {
        let result = decode_ebpf_map_value(&[0xC0, 0xA8, 0x01, 0x64, 0xFF, 0xFF]).unwrap();
        assert_eq!(result, "192.168.1.100:65535".parse().unwrap());
    }

    #[test]
    fn ebpf_map_value_rejects_short_or_empty() {
        assert_eq!(decode_ebpf_map_value(&[]), None);
        assert_eq!(decode_ebpf_map_value(&[0xC0, 0x00, 0x02, 0x01, 0x1F]), None);
    }

    #[test]
    fn ebpf_map_value_ignores_extra_trailing_bytes() {
        let result = decode_ebpf_map_value(&[0xC0, 0x00, 0x02, 0x01, 0x1F, 0x90, 0x00, 0x00]).unwrap();
        assert_eq!(result, "192.0.2.1:8080".parse().unwrap());
    }

    // --- tproxy gating (TproxyOriginalDestinationResolverTest) ---

    #[test]
    fn tproxy_returns_local_address_when_enabled() {
        let config = Config::for_tests().with_property("transparentProxyTproxy", "true");
        let local: SocketAddr = "192.0.2.1:8080".parse().unwrap();
        assert_eq!(tproxy(&config, local), Some(local));
    }

    #[test]
    fn tproxy_returns_none_when_disabled() {
        let config = Config::for_tests();
        let local: SocketAddr = "192.0.2.1:8080".parse().unwrap();
        assert_eq!(tproxy(&config, local), None);
    }

    #[test]
    fn tproxy_handles_ipv6_local_address() {
        let config = Config::for_tests().with_property("transparentProxyTproxy", "true");
        let local: SocketAddr = "[::1]:443".parse().unwrap();
        assert_eq!(tproxy(&config, local), Some(local));
    }
}
