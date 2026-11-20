//! Smoke tests of the clustered backend on the in-process SHARED_LOOPBACK stack. The full port of the
//! 115-test `mockserver-state-infinispan` suite is `tests/upstream/cluster_state_backend.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn unique_cluster() -> String {
    format!("unit-cluster-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed))
}

fn node(cluster: &str, log: Arc<Mutex<Vec<String>>>) -> ClusterStateBackend {
    let mut options = ClusterOptions::new(cluster, 1000);
    options.log = Arc::new(move |line| log.lock().push(line));
    ClusterStateBackend::start(options).expect("the node starts")
}

fn entry(id: &str) -> ExpectationEntry {
    ExpectationEntry { id: id.into(), priority: 0, created: 1, remaining_times: -1, expectation_json: serde_json::json!({"id": id, "httpRequest": {"path": "/x"}}) }
}

#[test]
fn two_nodes_share_a_put() {
    let cluster = unique_cluster();
    let a = node(&cluster, Default::default());
    let b = node(&cluster, Default::default());
    assert_eq!(a.put_state("s", "Filled"), 1);
    assert_eq!(b.scenario_states().get("s").map(|v| (v.value, v.version)), Some(("Filled".to_string(), 1)));
    assert_eq!(b.expectations().put("e1", entry("e1")), 1);
    assert_eq!(a.expectations().get("e1").map(|v| v.value.id), Some("e1".to_string()));
}

impl ClusterStateBackend {
    fn put_state(&self, k: &str, v: &str) -> u64 {
        self.scenario_states().put(k, v.to_string())
    }
}
