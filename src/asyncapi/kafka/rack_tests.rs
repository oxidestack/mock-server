//! Kafka 4.3.1's rack-aware assignor tests, ported: `RangeAssignorTest` (`testRackAware*`,
//! `testCoPartitionedAssignmentWithSameSubscription`), `AbstractStickyAssignorTest` (`testRackAware*`, in the
//! `CooperativeStickyAssignor` variant) and `AbstractPartitionAssignorTest.testUseRackAwareAssignment`, with that
//! class's `verifyRackAssignment` fixture: brokers `0..n` on the given racks, replica `j` of partition `i` on broker
//! `(i + j + offset) % n` where `offset` counts the partitions of the topics before it in name order, consumers
//! `consumer0…` subscribed in a `HashMap` sized for them.

use std::collections::{BTreeMap, BTreeSet};

use super::range;
use super::sticky::{CooperativeSticky, ReplicaRacks, Subscription, Tp, use_rack_aware};

const ALL_RACKS: [&str; 6] = ["a", "b", "c", "d", "e", "f"];

fn racks(n: usize) -> Vec<Option<String>> {
    (0..n).map(|i| Some(ALL_RACKS[i % ALL_RACKS.len()].to_string())).collect()
}

fn null_racks(n: usize) -> Vec<Option<String>> {
    vec![None; n]
}

fn named(names: &[Option<&str>]) -> Vec<Option<String>> {
    names.iter().map(|r| r.map(str::to_string)).collect()
}

fn string_hash(s: &str) -> i32 {
    s.encode_utf16().fold(0i32, |h, u| h.wrapping_mul(31).wrapping_add(u as i32))
}

/// The iteration order of `new HashMap<>(keys.len())` filled with `keys` in order.
fn sized_hashmap_order(keys: &[String]) -> Vec<String> {
    let mut capacity = keys.len().max(1).next_power_of_two();
    while keys.len() as f64 > capacity as f64 * 0.75 {
        capacity *= 2;
    }
    let mut out = keys.to_vec();
    out.sort_by_key(|k| {
        let h = string_hash(k) as u32;
        ((h ^ (h >> 16)) as usize) & (capacity - 1)
    });
    out
}

/// `AbstractPartitionAssignorTest.partitionsPerTopic`: the partition counts and every partition's replica racks.
fn partitions_per_topic(topics: &[(&str, usize)], replication: usize, broker_racks: &[Option<String>]) -> (BTreeMap<String, usize>, ReplicaRacks) {
    let counts: BTreeMap<String, usize> = topics.iter().map(|(t, n)| (t.to_string(), *n)).collect();
    let mut racks = ReplicaRacks::new();
    let mut next = 0;
    for (topic, n) in &counts {
        for i in 0..*n {
            let replicas = (0..replication).filter_map(|j| broker_racks[(i + j + next) % broker_racks.len()].clone()).collect();
            racks.insert((topic.clone(), i as i32), replicas);
        }
        next += n;
    }
    (counts, racks)
}

fn parse_partitions(list: &str) -> Vec<Tp> {
    list.split(", ").filter(|s| !s.is_empty()).map(|s| {
        let (t, p) = s.rsplit_once('-').unwrap();
        (t.to_string(), p.parse().unwrap())
    }).collect()
}

fn sorted_string(list: &[Tp]) -> String {
    let mut parts: Vec<String> = list.iter().map(|(t, p)| format!("{t}-{p}")).collect();
    parts.sort();
    parts.join(", ")
}

/// One assignor instance across a test's calls, as in Java, with its `preferRackAwareLogic`.
struct Assignor {
    range: bool,
    prefer: bool,
    sticky: CooperativeSticky,
}

impl Assignor {
    fn range() -> Assignor {
        Assignor { range: true, prefer: false, sticky: CooperativeSticky::default() }
    }

    fn sticky() -> Assignor {
        Assignor { range: false, prefer: false, sticky: CooperativeSticky::default() }
    }

    fn assign(&mut self, counts: &BTreeMap<String, usize>, racks: &ReplicaRacks, members: &[(String, Subscription)]) -> BTreeMap<String, Vec<Tp>> {
        if self.range {
            range::assign_with(counts, racks, members, self.prefer).into_iter().collect()
        } else {
            self.sticky.prefer_rack_aware_logic = self.prefer;
            let ids: Vec<String> = members.iter().map(|(id, _)| id.clone()).collect();
            self.sticky.assign_in_order(counts, racks, members, sized_hashmap_order(&ids)).unwrap().into_iter().collect()
        }
    }

    /// `verifyRackAssignment` (a negative `mismatches` skips counting partitions off their consumer's rack).
    #[allow(clippy::too_many_arguments)]
    fn verify(
        &mut self,
        topics: &[(&str, usize)],
        replication: usize,
        broker_racks: Vec<Option<String>>,
        consumer_racks: Vec<Option<String>>,
        consumer_topics: &[&[&str]],
        owned: &[&str],
        expected: &[&str],
        mismatches: i64,
    ) {
        let (counts, replica_racks) = partitions_per_topic(topics, replication, &broker_racks);
        let members: Vec<(String, Subscription)> = consumer_topics
            .iter()
            .enumerate()
            .map(|(i, topics)| {
                (format!("consumer{i}"), Subscription {
                    topics: topics.iter().map(|t| t.to_string()).collect(),
                    owned: owned.get(i).map(|o| parse_partitions(o)).unwrap_or_default(),
                    rack: consumer_racks[i].clone(),
                    ..Default::default()
                })
            })
            .collect();
        let assignment = self.assign(&counts, &replica_racks, &members);
        let actual: BTreeMap<String, String> = assignment.iter().map(|(id, l)| (id.clone(), sorted_string(l))).collect();
        let wanted: BTreeMap<String, String> = expected.iter().enumerate().map(|(i, e)| (format!("consumer{i}"), e.to_string())).collect();
        assert_eq!(actual, wanted, "replication {replication}, broker racks {broker_racks:?}, consumer racks {consumer_racks:?}, owned {owned:?}");
        if mismatches >= 0 {
            let mut off_rack = Vec::new();
            for (i, rack) in consumer_racks.iter().enumerate() {
                let Some(rack) = rack else { continue };
                for tp in &assignment[&format!("consumer{i}")] {
                    if !replica_racks[tp].contains(rack) {
                        off_rack.push(tp.clone());
                    }
                }
            }
            assert_eq!(off_rack.len() as i64, mismatches, "partitions with rack mismatch {off_rack:?}");
        }
    }
}

const T1_T2_T3: &[(&str, usize)] = &[("t1", 6), ("t2", 7), ("t3", 2)];
const ALL3: &[&str] = &["t1", "t2", "t3"];

#[test]
fn use_rack_aware_assignment() {
    let set = |r: &[&str]| r.iter().map(|s| s.to_string()).collect::<BTreeSet<String>>();
    let all = set(&["a", "b", "c"]);
    let two = set(&["a", "b"]);
    let empty = BTreeSet::new();
    let on_all: Vec<BTreeSet<String>> = (0..10).map(|_| all.clone()).collect();
    let on_subset: Vec<BTreeSet<String>> = (0..10).map(|i| set(&[["a", "b", "c"][i % 3]])).collect();
    let none: Vec<BTreeSet<String>> = Vec::new();
    for prefer in [false, true] {
        assert!(!use_rack_aware(&empty, &empty, on_all.iter(), prefer));
        assert!(!use_rack_aware(&empty, &all, on_all.iter(), prefer));
        assert!(!use_rack_aware(&all, &empty, none.iter(), prefer));
        assert!(!use_rack_aware(&set(&["d"]), &all, on_all.iter(), prefer));
        assert_eq!(use_rack_aware(&all, &all, on_all.iter(), prefer), prefer);
        assert_eq!(use_rack_aware(&two, &all, on_all.iter(), prefer), prefer);
        assert!(use_rack_aware(&all, &all, on_subset.iter(), prefer));
        assert!(use_rack_aware(&two, &all, on_subset.iter(), prefer));
    }
    assert!(!use_rack_aware(&set(&["a", "d"]), &all, on_all.iter(), false));
    assert!(use_rack_aware(&set(&["a", "d"]), &all, on_subset.iter(), false));
}

// ---- RangeAssignorTest ----

/// `verifyNonRackAwareAssignment`.
fn range_non_rack_aware(topics: &[(&str, usize)], consumer_topics: &[&[&str]], expected: &[&str]) {
    let mut a = Assignor::range();
    a.verify(topics, 3, null_racks(3), racks(3), consumer_topics, &[], expected, -1);
    a.verify(topics, 3, racks(3), null_racks(3), consumer_topics, &[], expected, -1);
    a.verify(topics, 3, racks(3), racks(3), consumer_topics, &[], expected, 0);
    a.verify(topics, 4, racks(4), racks(3), consumer_topics, &[], expected, 0);
    a.verify(topics, 3, racks(3), named(&[Some("d"), Some("e"), Some("f")]), consumer_topics, &[], expected, -1);
    a.verify(topics, 3, racks(3), named(&[None, Some("e"), Some("f")]), consumer_topics, &[], expected, -1);
    a.prefer = true;
    a.verify(topics, 3, racks(3), racks(3), consumer_topics, &[], expected, 0);
}

#[test]
fn range_rack_aware_static_member_assignment_persists_after_member_id_changes() {
    // `partitionInfos(topic, 5, 2, 3, 0)`: six brokers on racks a, b, c, a, b, c; both topics start at broker 0.
    let brokers = ["a", "b", "c", "a", "b", "c"];
    let mut racks = ReplicaRacks::new();
    for topic in ["topic1", "topic2"] {
        for i in 0..5 {
            racks.insert((topic.to_string(), i as i32), (0..2).map(|j| brokers[(i + j) % 6].to_string()).collect());
        }
    }
    let counts: BTreeMap<String, usize> = [("topic1".to_string(), 5), ("topic2".to_string(), 5)].into_iter().collect();
    let sub = |instance: &str, rack: &str| Subscription {
        topics: vec!["topic1".into(), "topic2".into()],
        rack: Some(rack.into()),
        instance_id: Some(instance.into()),
        ..Default::default()
    };
    let by_instance = |members: &[(String, Subscription)]| -> BTreeMap<String, Vec<Tp>> {
        let assigned: BTreeMap<String, Vec<Tp>> = range::assign_with(&counts, &racks, members, true).into_iter().collect();
        members.iter().map(|(id, s)| (s.instance_id.clone().unwrap(), assigned[id].clone())).collect()
    };
    let members = vec![
        ("consumer1".to_string(), sub("instance1", "a")),
        ("consumer2".to_string(), sub("instance2", "b")),
        ("consumer3".to_string(), sub("instance3", "c")),
    ];
    let first = by_instance(&members);
    let tps = |l: &str| parse_partitions(&l.replace("t1", "topic1").replace("t2", "topic2"));
    let expected: BTreeMap<String, Vec<Tp>> = [
        ("instance1".to_string(), tps("t1-0, t1-2, t2-0, t2-2")),
        ("instance2".to_string(), tps("t1-1, t1-3, t2-1, t2-3")),
        ("instance3".to_string(), tps("t1-4, t2-4")),
    ]
    .into_iter()
    .collect();
    assert_eq!(first, expected);
    let renamed = vec![
        ("consumer1".to_string(), sub("instance1", "a")),
        ("consumer5".to_string(), sub("instance2", "b")),
        ("consumer4".to_string(), sub("instance3", "c")),
    ];
    assert_eq!(by_instance(&renamed), first);
}

#[test]
fn range_rack_aware_assignment_with_uniform_subscription() {
    let consumer_topics: &[&[&str]] = &[ALL3, ALL3, ALL3];
    range_non_rack_aware(T1_T2_T3, consumer_topics, &["t1-0, t1-1, t2-0, t2-1, t2-2, t3-0", "t1-2, t1-3, t2-3, t2-4, t3-1", "t1-4, t1-5, t2-5, t2-6"]);
    let mut a = Assignor::range();
    a.verify(T1_T2_T3, 1, racks(3), racks(3), consumer_topics, &[], &["t1-0, t1-3, t2-0, t2-3, t2-6", "t1-1, t1-4, t2-1, t2-4, t3-0", "t1-2, t1-5, t2-2, t2-5, t3-1"], 0);
    a.verify(T1_T2_T3, 2, racks(3), racks(3), consumer_topics, &[], &["t1-0, t1-2, t2-0, t2-2, t2-3, t3-1", "t1-1, t1-3, t2-1, t2-4, t3-0", "t1-4, t1-5, t2-5, t2-6"], 1);
    a.verify(T1_T2_T3, 3, racks(2), racks(3), consumer_topics, &[], &["t1-0, t1-1, t2-0, t2-1, t2-2, t3-0", "t1-2, t1-3, t2-3, t2-4, t3-1", "t1-4, t1-5, t2-5, t2-6"], 4);
}

#[test]
fn range_rack_aware_assignment_with_non_equal_subscription() {
    let consumer_topics: &[&[&str]] = &[ALL3, ALL3, &["t1", "t3"]];
    range_non_rack_aware(T1_T2_T3, consumer_topics, &["t1-0, t1-1, t2-0, t2-1, t2-2, t2-3, t3-0", "t1-2, t1-3, t2-4, t2-5, t2-6, t3-1", "t1-4, t1-5"]);
    let mut a = Assignor::range();
    a.verify(T1_T2_T3, 1, racks(3), racks(3), consumer_topics, &[], &["t1-0, t1-3, t2-0, t2-2, t2-3, t2-6", "t1-1, t1-4, t2-1, t2-4, t2-5, t3-0", "t1-2, t1-5, t3-1"], 2);
    a.verify(T1_T2_T3, 2, racks(3), racks(3), consumer_topics, &[], &["t1-0, t1-2, t2-0, t2-2, t2-3, t2-5, t3-1", "t1-1, t1-3, t2-1, t2-4, t2-6, t3-0", "t1-4, t1-5"], 0);
    a.verify(T1_T2_T3, 3, racks(2), racks(3), consumer_topics, &[], &["t1-0, t1-1, t2-0, t2-1, t2-2, t2-3, t3-0", "t1-2, t1-3, t2-4, t2-5, t2-6, t3-1", "t1-4, t1-5"], 2);
}

#[test]
fn range_rack_aware_assignment_with_uniform_partitions() {
    let topics: &[(&str, usize)] = &[("t1", 5), ("t2", 5), ("t3", 5)];
    let consumer_topics: &[&[&str]] = &[ALL3, ALL3, ALL3];
    let non_rack_aware = ["t1-0, t1-1, t2-0, t2-1, t3-0, t3-1", "t1-2, t1-3, t2-2, t2-3, t3-2, t3-3", "t1-4, t2-4, t3-4"];
    range_non_rack_aware(topics, consumer_topics, &non_rack_aware);
    let mut a = Assignor::range();
    a.verify(topics, 1, racks(3), racks(3), consumer_topics, &[], &non_rack_aware, 10);
    a.verify(topics, 2, racks(3), racks(3), consumer_topics, &[], &non_rack_aware, 5);
    a.verify(topics, 3, racks(2), racks(3), consumer_topics, &[], &non_rack_aware, 3);
}

#[test]
fn range_rack_aware_assignment_with_uniform_partitions_non_equal_subscription() {
    let topics: &[(&str, usize)] = &[("t1", 5), ("t2", 5), ("t3", 5)];
    let consumer_topics: &[&[&str]] = &[ALL3, ALL3, &["t1", "t3"]];
    range_non_rack_aware(topics, consumer_topics, &["t1-0, t1-1, t2-0, t2-1, t2-2, t3-0, t3-1", "t1-2, t1-3, t2-3, t2-4, t3-2, t3-3", "t1-4, t3-4"]);
    let mut a = Assignor::range();
    a.verify(topics, 1, racks(3), racks(3), consumer_topics, &[], &["t1-0, t1-1, t2-0, t2-1, t2-4, t3-0, t3-1", "t1-2, t1-3, t2-2, t2-3, t3-2, t3-3", "t1-4, t3-4"], 9);
    a.verify(topics, 2, racks(3), racks(3), consumer_topics, &[], &["t1-2, t2-0, t2-1, t2-3, t3-2", "t1-0, t1-3, t2-2, t2-4, t3-0, t3-3", "t1-1, t1-4, t3-1, t3-4"], 0);
    a.verify(topics, 3, racks(2), racks(3), consumer_topics, &[], &["t1-0, t1-1, t2-0, t2-1, t2-2, t3-0, t3-1", "t1-2, t1-3, t2-3, t2-4, t3-2, t3-3", "t1-4, t3-4"], 2);
}

#[test]
fn range_rack_aware_assignment_with_co_partitioning() {
    let topics: &[(&str, usize)] = &[("t1", 6), ("t2", 6), ("t3", 2), ("t4", 2)];
    let consumer_racks = named(&[Some("a"), Some("b"), Some("b"), Some("a")]);
    let mut a = Assignor::range();
    let split: &[&[&str]] = &[&["t1", "t2"], &["t1", "t2"], &["t3", "t4"], &["t3", "t4"]];
    let non_rack_aware = ["t1-0, t1-1, t1-2, t2-0, t2-1, t2-2", "t1-3, t1-4, t1-5, t2-3, t2-4, t2-5", "t3-0, t4-0", "t3-1, t4-1"];
    a.verify(topics, 3, racks(2), consumer_racks.clone(), split, &[], &non_rack_aware, -1);
    a.verify(topics, 3, racks(2), consumer_racks.clone(), split, &[], &non_rack_aware, -1);
    a.verify(topics, 2, racks(2), consumer_racks.clone(), split, &[], &non_rack_aware, 0);
    a.verify(topics, 1, racks(2), consumer_racks.clone(), split, &[], &["t1-0, t1-2, t1-4, t2-0, t2-2, t2-4", "t1-1, t1-3, t1-5, t2-1, t2-3, t2-5", "t3-1, t4-1", "t3-0, t4-0"], 0);

    let all: &[&str] = &["t1", "t2", "t3", "t4"];
    let same: &[&[&str]] = &[all, all, all, all];
    let non_rack_aware = ["t1-0, t1-1, t2-0, t2-1, t3-0, t4-0", "t1-2, t1-3, t2-2, t2-3, t3-1, t4-1", "t1-4, t2-4", "t1-5, t2-5"];
    a.verify(topics, 3, racks(2), consumer_racks.clone(), same, &[], &non_rack_aware, -1);
    a.verify(topics, 3, racks(2), consumer_racks.clone(), same, &[], &non_rack_aware, -1);
    a.verify(topics, 2, racks(2), consumer_racks.clone(), same, &[], &non_rack_aware, 0);
    a.verify(topics, 1, racks(2), consumer_racks.clone(), same, &[], &["t1-0, t1-2, t2-0, t2-2, t3-0, t4-0", "t1-1, t1-3, t2-1, t2-3, t3-1, t4-1", "t1-5, t2-5", "t1-4, t2-4"], 0);
    a.verify(topics, 1, racks(3), consumer_racks, same, &[], &["t1-0, t1-3, t2-0, t2-3, t3-0, t4-0", "t1-1, t1-4, t2-1, t2-4, t3-1, t4-1", "t1-2, t2-2", "t1-5, t2-5"], 6);
}

#[test]
fn range_co_partitioned_assignment_with_same_subscription() {
    let topics: &[(&str, usize)] = &[("t1", 6), ("t2", 6), ("t3", 2), ("t4", 2), ("t5", 4), ("t6", 4)];
    let list: &[&str] = &["t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9"];
    let consumer_topics: &[&[&str]] = &[list, list, list];
    let consumer_racks = racks(3);
    let non_rack_aware = [
        "t1-0, t1-1, t2-0, t2-1, t3-0, t4-0, t5-0, t5-1, t6-0, t6-1",
        "t1-2, t1-3, t2-2, t2-3, t3-1, t4-1, t5-2, t6-2",
        "t1-4, t1-5, t2-4, t2-5, t5-3, t6-3",
    ];
    let mut a = Assignor::range();
    a.verify(topics, 3, null_racks(3), consumer_racks.clone(), consumer_topics, &[], &non_rack_aware, -1);
    a.prefer = true;
    a.verify(topics, 3, racks(3), consumer_racks.clone(), consumer_topics, &[], &non_rack_aware, 0);
    a.verify(topics, 2, racks(3), consumer_racks, consumer_topics, &[], &[
        "t1-0, t1-2, t2-0, t2-2, t3-0, t4-0, t5-1, t6-1",
        "t1-1, t1-3, t2-1, t2-3, t3-1, t4-1, t5-2, t6-2",
        "t1-4, t1-5, t2-4, t2-5, t5-0, t5-3, t6-0, t6-3",
    ], 0);
}

// ---- AbstractStickyAssignorTest, as CooperativeStickyAssignorTest runs it ----

impl Assignor {
    /// `verifyUniformSubscription` and `verifyNonEqualSubscription`: from nothing owned, then from the result.
    #[allow(clippy::too_many_arguments)]
    fn verify_twice(
        &mut self,
        topics: &[(&str, usize)],
        replication: usize,
        broker_racks: Vec<Option<String>>,
        consumer_racks: Vec<Option<String>>,
        consumer_topics: &[&[&str]],
        expected: &[&str],
        mismatches: i64,
    ) {
        self.verify(topics, replication, broker_racks.clone(), consumer_racks.clone(), consumer_topics, &[], expected, mismatches);
        self.verify(topics, replication, broker_racks, consumer_racks, consumer_topics, expected, expected, mismatches);
    }
}

#[test]
fn sticky_rack_aware_assignment_with_uniform_subscription() {
    let consumer_topics: &[&[&str]] = &[ALL3, ALL3, ALL3];
    let non_rack_aware = ["t1-0, t1-3, t2-0, t2-3, t2-6", "t1-1, t1-4, t2-1, t2-4, t3-0", "t1-2, t1-5, t2-2, t2-5, t3-1"];
    let mut a = Assignor::sticky();
    a.verify_twice(T1_T2_T3, 3, null_racks(3), racks(3), consumer_topics, &non_rack_aware, -1);
    a.verify_twice(T1_T2_T3, 3, racks(3), null_racks(3), consumer_topics, &non_rack_aware, -1);
    a.prefer = true;
    a.verify_twice(T1_T2_T3, 3, racks(3), racks(3), consumer_topics, &non_rack_aware, 0);
    a.verify_twice(T1_T2_T3, 4, racks(4), racks(3), consumer_topics, &non_rack_aware, 0);
    a.prefer = false;
    a.verify_twice(T1_T2_T3, 3, racks(3), racks(3), consumer_topics, &non_rack_aware, 0);
    a.verify_twice(T1_T2_T3, 3, racks(3), named(&[Some("d"), Some("e"), Some("f")]), consumer_topics, &non_rack_aware, -1);
    a.verify_twice(T1_T2_T3, 3, racks(3), named(&[None, Some("e"), Some("f")]), consumer_topics, &non_rack_aware, -1);

    a.verify_twice(T1_T2_T3, 1, racks(3), racks(3), consumer_topics, &non_rack_aware, 0);
    a.verify_twice(T1_T2_T3, 2, racks(3), racks(3), consumer_topics, &non_rack_aware, 0);
    // One consumer on a rack with no partitions: misaligned partitions keep the balance.
    a.verify_twice(T1_T2_T3, 3, racks(2), racks(3), consumer_topics, &non_rack_aware, 5);

    // Owned partitions off their consumer's rack are revoked.
    let owned = ["t1-0, t1-1, t1-2, t1-3, t1-4", "t1-5, t2-0, t2-1, t2-2, t2-3", "t2-4, t2-5, t2-6, t3-0, t3-1"];
    a.verify(T1_T2_T3, 1, racks(3), racks(3), consumer_topics, &owned, &["t1-0, t1-3", "t2-1", "t2-5, t3-1"], 0);
    // Stickiness is kept when racks match.
    a.prefer = true;
    a.verify(T1_T2_T3, 3, racks(3), racks(3), consumer_topics, &non_rack_aware, &non_rack_aware, 0);
}

#[test]
fn sticky_rack_aware_assignment_with_non_equal_subscription() {
    let consumer_topics: &[&[&str]] = &[ALL3, ALL3, &["t1", "t3"]];
    let non_rack_aware = ["t1-5, t2-0, t2-2, t2-4, t2-6", "t1-3, t2-1, t2-3, t2-5, t3-0", "t1-0, t1-1, t1-2, t1-4, t3-1"];
    let mut a = Assignor::sticky();
    a.verify_twice(T1_T2_T3, 3, null_racks(3), racks(3), consumer_topics, &non_rack_aware, -1);
    a.verify_twice(T1_T2_T3, 3, racks(3), null_racks(3), consumer_topics, &non_rack_aware, -1);
    a.prefer = true;
    a.verify_twice(T1_T2_T3, 3, racks(3), racks(3), consumer_topics, &non_rack_aware, 0);
    a.verify_twice(T1_T2_T3, 4, racks(4), racks(3), consumer_topics, &non_rack_aware, 0);
    a.prefer = false;
    a.verify_twice(T1_T2_T3, 3, racks(3), racks(3), consumer_topics, &non_rack_aware, 0);
    a.verify_twice(T1_T2_T3, 3, racks(3), named(&[Some("d"), Some("e"), Some("f")]), consumer_topics, &non_rack_aware, -1);
    a.verify_twice(T1_T2_T3, 3, racks(3), named(&[None, Some("e"), Some("f")]), consumer_topics, &non_rack_aware, -1);

    // Rack alignment is best-effort when there are few rack choices.
    a.verify_twice(T1_T2_T3, 1, racks(3), racks(3), consumer_topics, &["t1-3, t2-0, t2-2, t2-3, t2-6", "t1-4, t2-1, t2-4, t2-5, t3-0", "t1-0, t1-1, t1-2, t1-5, t3-1"], 4);
    a.verify_twice(T1_T2_T3, 2, racks(3), racks(3), consumer_topics, &["t1-3, t2-0, t2-2, t2-5, t2-6", "t1-0, t2-1, t2-3, t2-4, t3-0", "t1-1, t1-2, t1-4, t1-5, t3-1"], 0);
    a.verify_twice(T1_T2_T3, 3, racks(2), racks(3), consumer_topics, &non_rack_aware, 5);

    // Owned partitions off their consumer's rack are revoked first, then reassigned.
    let owned = ["t1-0, t1-1, t1-2, t1-3, t1-4", "t1-5, t2-0, t2-1, t2-2, t2-3", "t2-4, t2-5, t2-6, t3-0, t3-1"];
    let intermediate = ["t1-3", "t2-1", "t3-1"];
    a.verify(T1_T2_T3, 1, racks(3), racks(3), consumer_topics, &owned, &intermediate, 0);
    a.verify(T1_T2_T3, 1, racks(3), racks(3), consumer_topics, &intermediate, &["t1-3, t2-0, t2-2, t2-3, t2-6", "t1-4, t2-1, t2-4, t2-5, t3-0", "t1-0, t1-1, t1-2, t1-5, t3-1"], 4);

    // With every rack matching, the result is the rack-unaware one.
    let assignment = ["t1-2, t1-3, t1-4, t2-4, t2-5", "t2-0, t2-1, t2-2, t2-3, t2-6", "t1-0, t1-1, t1-5, t3-0, t3-1"];
    let intermediate = ["t1-2, t1-3, t1-4", "t2-0, t2-1, t2-2, t2-3", "t3-0, t3-1"];
    for prefer in [false, true] {
        a.prefer = prefer;
        a.verify(T1_T2_T3, 3, racks(3), racks(3), consumer_topics, &owned, &intermediate, 0);
        a.verify(T1_T2_T3, 3, racks(3), racks(3), consumer_topics, &intermediate, &assignment, 0);
    }
}

// ---- Differential vectors ----

fn tps(v: &serde_json::Value) -> Vec<Tp> {
    v.as_array().unwrap().iter().map(|tp| (tp[0].as_str().unwrap().to_string(), tp[1].as_i64().unwrap() as i32)).collect()
}

/// Vectors recorded from kafka-clients 4.3.1 (`tests/files/kafka/RackGen.java`): `RangeAssignor` and rounds of
/// `CooperativeStickyAssignor` rebalances on brokers with random racks and replica placement, members with and
/// without `client.rack`; every member's list must match in content and order.
#[test]
fn matches_kafka_clients_rack_aware_vectors() {
    let path = format!("{}/tests/files/kafka/rack_aware_vectors.json", env!("CARGO_MANIFEST_DIR"));
    let cases: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut failures = Vec::new();
    let mut rounds = 0;
    for (c, case) in cases.iter().enumerate() {
        let range = case["assignor"] == "range";
        let mut sticky = CooperativeSticky::default();
        for (r, round) in case["rounds"].as_array().unwrap().iter().enumerate() {
            rounds += 1;
            let mut counts = BTreeMap::new();
            let mut racks = ReplicaRacks::new();
            for (topic, partitions) in round["partitions"].as_object().unwrap() {
                let partitions = partitions.as_array().unwrap();
                counts.insert(topic.clone(), partitions.len());
                for (p, replicas) in partitions.iter().enumerate() {
                    racks.insert((topic.clone(), p as i32), replicas.as_array().unwrap().iter().map(|r| r.as_str().unwrap().to_string()).collect());
                }
            }
            let members: Vec<(String, Subscription)> = round["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| {
                    let generation = m["generation"].as_i64().unwrap() as i32;
                    (m["id"].as_str().unwrap().to_string(), Subscription {
                        topics: m["topics"].as_array().unwrap().iter().map(|t| t.as_str().unwrap().to_string()).collect(),
                        owned: tps(&m["owned"]),
                        generation: (generation >= 0).then_some(generation),
                        user_data: (!range).then(|| generation.to_be_bytes().to_vec()),
                        rack: m["rack"].as_str().map(str::to_string),
                        instance_id: m["instance"].as_str().map(str::to_string),
                    })
                })
                .collect();
            let expected: BTreeMap<String, Vec<Tp>> = round["result"].as_object().unwrap().iter().map(|(id, l)| (id.clone(), tps(l))).collect();
            let actual = if range { Ok(range::assign(&counts, &racks, &members)) } else { sticky.assign(&counts, &racks, &members) };
            match actual {
                Ok(actual) => {
                    let actual: BTreeMap<String, Vec<Tp>> = actual.into_iter().collect();
                    if actual != expected {
                        failures.push(format!("case {c} round {r}: expected {expected:?}, got {actual:?}"));
                    }
                }
                Err(e) => failures.push(format!("case {c} round {r}: {e}")),
            }
        }
    }
    assert!(failures.is_empty(), "{} of {rounds} rounds differ:\n{}", failures.len(), failures.iter().take(5).cloned().collect::<Vec<_>>().join("\n"));
}
