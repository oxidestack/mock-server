//! What a failing verification costs in memory, measured with a counting allocator, while the event log holds
//! many large requests: its failure answer, its `VERIFICATION_FAILED` entry and its console line must not each hold
//! a copy of the whole log. The only test in its binary, so nothing else allocates while it measures.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicIsize, Ordering};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);
static PEAK: AtomicIsize = AtomicIsize::new(0);

fn grew(size: isize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        grew(layout.size() as isize);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        grew(layout.size() as isize);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        grew(new_size as isize - layout.size() as isize);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// bench/run.sh's `order_body`: ~4 KiB of JSON.
fn order_body(id: &str) -> String {
    let items: Vec<String> = (0..29)
        .map(|i| {
            format!(
                r#"{{"sku":"SKU-{i:05}","name":"Item number {i} with a descriptive name","quantity":{},"unitPrice":{}.99,"tags":["standard","warehouse-a"]}}"#,
                i % 7 + 1,
                i + 9
            )
        })
        .collect();
    format!(
        r#"{{"order":{{"id":"{id}","customer":{{"id":"c-1042","name":"Jane Example","email":"jane@example.com"}},"items":[{}],"currency":"EUR","note":"deliver to the back door"}}}}"#,
        items.join(",")
    )
}

/// Reads one response off a keep-alive connection: its status and body.
fn response(s: &mut std::net::TcpStream) -> (u16, String) {
    let mut got = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&got[..end]).to_string();
            let length: usize = head
                .lines()
                .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
                .unwrap_or(0);
            if got.len() >= end + 4 + length {
                let status = head[9..12].parse().unwrap();
                return (status, String::from_utf8_lossy(&got[end + 4..end + 4 + length]).to_string());
            }
        }
        let k = s.read(&mut buf).unwrap();
        assert!(k > 0, "connection closed");
        got.extend_from_slice(&buf[..k]);
    }
}

fn call(s: &mut std::net::TcpStream, method: &str, path: &str, body: &str) -> (u16, String) {
    write!(s, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    response(s)
}

const ORDERS: usize = 400;
const VERIFICATIONS: usize = 20;
const FAILING: &str = r#"{"httpRequest":{"method":"POST","path":"/none"},"times":{"atLeast":1}}"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_verification_holds_no_copy_of_the_logged_requests() {
    // INFO: the failure is printed to the console and retained in the event log, as by default
    let config = mock_server::Config::for_tests().with_property("logLevel", "INFO");
    let server = mock_server::Server::start(config).await.unwrap();
    let port = server.ports()[0];
    let (peak, retained, logged) = tokio::task::spawn_blocking(move || {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (status, _) = call(&mut s, "PUT", "/mockserver/expectation", r#"{"httpRequest":{"method":"POST","path":"/orders/[0-9]+"},"httpResponse":{"statusCode":201}}"#);
        assert_eq!(status, 201);
        let order = order_body("fill");
        for i in 0..ORDERS {
            assert_eq!(call(&mut s, "POST", &format!("/orders/{i:04}"), &order).0, 201);
        }
        let logged = ORDERS * order.len();
        // one failing verification first, so what any first one sets up once is not counted
        let (status, first) = call(&mut s, "PUT", "/mockserver/verify", FAILING);
        assert_eq!(status, 406, "{first}");
        let before = LIVE.load(Ordering::Relaxed);
        PEAK.store(before, Ordering::Relaxed);
        for _ in 0..VERIFICATIONS {
            let (status, answer) = call(&mut s, "PUT", "/mockserver/verify", FAILING);
            assert_eq!(status, 406);
            assert_eq!(answer, first);
        }
        let peak = PEAK.load(Ordering::Relaxed) - before;
        let retained = LIVE.load(Ordering::Relaxed) - before;
        assert!(first.contains(&format!("but was found 0 times among {ORDERS} total requests")), "{first}");
        (peak, retained, logged)
    })
    .await
    .unwrap();
    eprintln!("{VERIFICATIONS} failing verifications over {ORDERS} logged orders ({logged} body bytes): peak {peak} bytes, retained {retained} bytes");
    // each failure's two entries, which quote the logged requests without copying them: 20 MB per failure over these
    // 400 orders when its entry held their rendered JSON and text
    assert!(retained < VERIFICATIONS as isize * 16 * 1024, "{VERIFICATIONS} failing verifications retained {retained} bytes over {logged} logged body bytes");
    // what one failure builds and lets go, its console line among it (which quotes every logged request)
    assert!(peak < 4 * logged as isize, "failing verifications peaked at {peak} bytes over {logged} logged body bytes");
    server.shutdown().await;
}
