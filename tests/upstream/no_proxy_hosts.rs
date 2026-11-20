//! `NoProxyHostsBypassesUpstreamProxyIntegrationTest.shouldStillBlockPrivateNetworkForHostOnTheList` (master): a destination on `noProxyHosts` is connected to directly, so `forwardProxyBlockPrivateNetworks` refuses a
//! private one as it would without an upstream proxy: `502`, and neither the destination nor either upstream proxy
//! is reached.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

use crate::common;

/// `RecordingUpstreamProxy`: counts the connections it is sent and answers none.
async fn recording_proxy() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            drop(tcp);
        }
    });
    (port, connections)
}

#[tokio::test(flavor = "multi_thread")]
async fn should_still_block_private_network_for_host_on_the_list() {
    let destination = common::start(&[]).await;
    common::expect(destination.port, &json!({"httpRequest": {"path": "/target"}, "httpResponse": {"statusCode": 200, "body": "destination"}})).await;
    let (http_proxy, http_seen) = recording_proxy().await;
    let (https_proxy, https_seen) = recording_proxy().await;
    let (http_proxy, https_proxy) = (format!("127.0.0.1:{http_proxy}"), format!("127.0.0.1:{https_proxy}"));
    let proxy = common::start(&[
        ("forwardHttpProxy", http_proxy.as_str()),
        ("forwardHttpsProxy", https_proxy.as_str()),
        ("noProxyHosts", "localhost"),
        ("forwardProxyBlockPrivateNetworks", "true"),
    ])
    .await;
    for (path, secure) in [("/clear", false), ("/secure", true)] {
        let target = json!({"path": "/target", "secure": secure, "headers": {"Host": [format!("localhost:{}", destination.port)]}});
        common::expect(proxy.port, &json!({"httpRequest": {"path": path}, "httpOverrideForwardedRequest": {"httpRequest": target}})).await;
    }
    for path in ["/clear", "/secure"] {
        let r = common::send(proxy.port, "GET", path, "").await;
        assert_eq!(r.status, 502, "{path}: {}\n{}", r.head, r.body);
    }
    let verify = json!({"httpRequest": {"path": "/target"}, "times": {"atLeast": 0, "atMost": 0}});
    let verified = common::send(destination.port, "PUT", "/mockserver/verify", &verify.to_string()).await;
    assert_eq!(verified.status, 202, "{}", verified.body);
    assert_eq!((http_seen.load(Ordering::SeqCst), https_seen.load(Ordering::SeqCst)), (0, 0));
}
