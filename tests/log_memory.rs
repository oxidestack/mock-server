//! What the event log retains per matched request at INFO, measured with a counting allocator. The only
//! test in its binary, so nothing else allocates while it measures.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicIsize, Ordering};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(new_size as isize - layout.size() as isize, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Sends `n` requests like `ab -k` does on one keep-alive connection, reading each response before the next.
fn hammer(port: u16, n: usize) {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut buf = vec![0u8; 4096];
    for _ in 0..n {
        write!(s, "GET /e0 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUser-Agent: ApacheBench/2.3\r\nAccept: */*\r\n\r\n").unwrap();
        let mut got = Vec::new();
        loop {
            let k = s.read(&mut buf).unwrap();
            assert!(k > 0, "connection closed");
            got.extend_from_slice(&buf[..k]);
            // a 200 with the two-byte body `e0`
            if got.ends_with(b"\r\n\r\ne0") {
                break;
            }
        }
    }
}

fn request(port: u16, method: &str, path: &str, body: &str) {
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(s, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn info_event_log_retains_a_bounded_amount_per_matched_request() {
    // three entries per matched request at INFO (received, matched, response): 3000 entries hold the last 1000
    // the console is off: the test harness captures what the server's threads print, which would count as retained
    let config = mock_server::Config::for_tests()
        .with_property("maxLogEntries", "3000")
        .with_property("logLevel", "INFO")
        .with_property("disableLogging", "true");
    let server = mock_server::Server::start(config).await.unwrap();
    let port = server.ports()[0];
    let per_request = tokio::task::spawn_blocking(move || {
        request(port, "PUT", "/mockserver/expectation", r#"{"httpRequest":{"method":"GET","path":"/e0"},"httpResponse":{"body":"e0"}}"#);
        hammer(port, 200);
        let before = LIVE.load(Ordering::Relaxed);
        hammer(port, 800);
        let full = LIVE.load(Ordering::Relaxed);
        hammer(port, 2000);
        let after = LIVE.load(Ordering::Relaxed);
        let per_request = (full - before) / 800;
        eprintln!("retained per matched INFO request: {per_request} bytes; full log {full}, after 2000 more {after}");
        // the log is full: more requests replace entries, they do not add to them
        assert!(after - full < 1000 * per_request / 10, "the full log grew from {full} to {after} bytes");
        per_request
    })
    .await
    .unwrap();
    // 27.2 KB when the request's logged JSON was held four times and the expectation's twice per request and
    // again for every request, 11.1 KB after it is held once; the 8.0.0 oracle's heap holds ~7 KB per request for the same load
    assert!(per_request < 14 * 1024, "{per_request} bytes retained per matched INFO request");
    server.shutdown().await;
}

