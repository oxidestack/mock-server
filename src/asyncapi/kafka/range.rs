//! kafka-clients 4.3.1's `RangeAssignor`, which the classic group member runs as leader when the group chose `range`:
//! per topic, its partitions in order split into contiguous ranges over the members subscribed to it (static members
//! by `group.instance.id` first, then by member id), the first members taking one extra each. When members set
//! `client.rack` and some partition's replicas are not on every rack, partitions that can be aligned on racks are
//! assigned first, keeping per-topic balance and the co-partitioning of topics with the same subscribers and
//! partition count; the rest follow as ranges.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::sticky::{ReplicaRacks, Subscription, Tp, use_rack_aware};

/// `AbstractPartitionAssignor.MemberInfo.compareTo`.
fn member_order(a: &(String, Subscription), b: &(String, Subscription)) -> Ordering {
    match (&a.1.instance_id, &b.1.instance_id) {
        (Some(x), Some(y)) => x.cmp(y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => a.0.cmp(&b.0),
    }
}

/// `RangeAssignor.TopicAssignmentState`.
struct TopicState {
    topic: String,
    /// The topic's subscribers in `MemberInfo` order, with their racks.
    consumers: Vec<(String, Option<String>)>,
    needs_rack_aware: bool,
    /// Each partition's replica racks; empty when no subscriber has a rack.
    partition_racks: BTreeMap<i32, BTreeSet<String>>,
    unassigned: Vec<i32>,
    assigned: HashMap<String, usize>,
    per_consumer: usize,
    with_extra: i64,
}

impl TopicState {
    fn new(topic: &str, count: usize, racks: &ReplicaRacks, members: &[(String, Subscription)], prefer: bool) -> TopicState {
        let mut subscribers: Vec<&(String, Subscription)> = members.iter().filter(|(_, s)| s.topics.iter().any(|t| t == topic)).collect();
        subscribers.sort_by(|a, b| member_order(a, b));
        let consumers: Vec<(String, Option<String>)> = subscribers.iter().map(|(id, s)| (id.clone(), s.rack().map(str::to_string))).collect();
        let consumer_racks: BTreeSet<String> = consumers.iter().filter_map(|(_, r)| r.clone()).collect();
        let mut partition_racks = BTreeMap::new();
        let mut all_partition_racks = BTreeSet::new();
        if !consumer_racks.is_empty() {
            for p in 0..count as i32 {
                let set: BTreeSet<String> = racks.get(&(topic.to_string(), p)).into_iter().flatten().cloned().collect();
                all_partition_racks.extend(set.iter().cloned());
                partition_racks.insert(p, set);
            }
        }
        let needs_rack_aware = use_rack_aware(&consumer_racks, &all_partition_racks, partition_racks.values(), prefer);
        let n = consumers.len();
        TopicState {
            topic: topic.to_string(),
            assigned: consumers.iter().map(|(id, _)| (id.clone(), 0)).collect(),
            consumers,
            needs_rack_aware,
            partition_racks,
            unassigned: (0..count as i32).collect(),
            per_consumer: count.checked_div(n).unwrap_or(0),
            with_extra: if n == 0 { 0 } else { (count % n) as i64 },
        }
    }

    fn rack_of(&self, consumer: &str) -> Option<&str> {
        self.consumers.iter().find(|(id, _)| id == consumer).and_then(|(_, r)| r.as_deref())
    }

    /// `racksMatch`: the consumer has no rack, or a replica of the partition is on it.
    fn racks_match(&self, consumer: &str, partition: i32) -> bool {
        match self.rack_of(consumer) {
            None => true,
            Some(rack) => self.partition_racks.get(&partition).is_some_and(|set| set.contains(rack)),
        }
    }

    fn max_assignable(&self, consumer: &str) -> usize {
        let max = self.per_consumer as i64 + i64::from(self.with_extra > 0) - self.assigned[consumer] as i64;
        max.max(0) as usize
    }

    fn assign(&mut self, consumer: &str, partitions: &[i32], assignment: &mut HashMap<String, Vec<Tp>>) {
        assignment.get_mut(consumer).expect("every member").extend(partitions.iter().map(|p| (self.topic.clone(), *p)));
        let count = self.assigned.get_mut(consumer).expect("a subscriber");
        *count += partitions.len();
        if *count > self.per_consumer {
            self.with_extra -= 1;
        }
        self.unassigned.retain(|p| !partitions.contains(p));
    }

    /// `assignRanges`: each subscriber in order takes the first unassigned partitions it may (on its rack when
    /// `rack_match`), up to what it can still take.
    fn assign_ranges(&mut self, rack_match: bool, assignment: &mut HashMap<String, Vec<Tp>>) {
        for i in 0..self.consumers.len() {
            if self.unassigned.is_empty() {
                break;
            }
            let consumer = self.consumers[i].0.clone();
            let limit = self.max_assignable(&consumer);
            let partitions: Vec<i32> =
                self.unassigned.iter().copied().filter(|p| !rack_match || self.racks_match(&consumer, *p)).take(limit).collect();
            if !partitions.is_empty() {
                self.assign(&consumer, &partitions, assignment);
            }
        }
    }
}

/// `assignCoPartitionedWithRackMatching`: partition `p` of every topic in the group goes to the first remaining
/// consumer whose rack all of them match and that can take one more of each.
fn assign_co_partitioned(states: &mut [TopicState], group: &[usize], partitions: usize, assignment: &mut HashMap<String, Vec<Tp>>) {
    let mut remaining: Vec<String> = states[group[0]].consumers.iter().map(|(id, _)| id.clone()).collect();
    for p in 0..partitions as i32 {
        let found = remaining
            .iter()
            .find(|c| group.iter().all(|s| states[*s].racks_match(c, p) && states[*s].max_assignable(c) > 0))
            .cloned();
        let Some(consumer) = found else { continue };
        for s in group {
            states[*s].assign(&consumer, &[p], assignment);
        }
        if group.iter().all(|s| states[*s].max_assignable(&consumer) == 0) {
            remaining.retain(|c| *c != consumer);
            if remaining.is_empty() {
                break;
            }
        }
    }
}

/// `assignWithRackMatching`: the topics grouped by their subscribers, then by the number of partitions with known
/// racks; groups of several topics are assigned co-partitioned, a lone topic as rack-matched ranges.
fn assign_with_rack_matching(states: &mut [TopicState], assignment: &mut HashMap<String, Vec<Tp>>) {
    // (the subscribers with their racks, the partitions with known racks, the topics' indexes)
    type Subscribers = Vec<(String, Option<String>)>;
    let mut groups: Vec<(Subscribers, usize, Vec<usize>)> = Vec::new();
    for (i, state) in states.iter().enumerate() {
        let key = (&state.consumers, state.partition_racks.len());
        match groups.iter_mut().find(|(c, n, _)| (c, *n) == key) {
            Some((_, _, members)) => members.push(i),
            None => groups.push((state.consumers.clone(), state.partition_racks.len(), vec![i])),
        }
    }
    for (_, partitions, group) in groups {
        if group.len() > 1 {
            assign_co_partitioned(states, &group, partitions, assignment);
        } else if states[group[0]].needs_rack_aware {
            states[group[0]].assign_ranges(true, assignment);
        }
    }
}

/// `RangeAssignor.assignPartitions` for the members in `JoinGroup` order, the subscribed topics' partition counts and
/// their replicas' racks. Members come out sorted by id; each member's partitions are grouped by topic in the order
/// of Java's `HashMap` of topics, or sorted by topic and partition when the assignment was rack-aware.
pub fn assign(partitions: &BTreeMap<String, usize>, racks: &ReplicaRacks, members: &[(String, Subscription)]) -> Vec<(String, Vec<Tp>)> {
    assign_with(partitions, racks, members, false)
}

pub(super) fn assign_with(partitions: &BTreeMap<String, usize>, racks: &ReplicaRacks, members: &[(String, Subscription)], prefer: bool) -> Vec<(String, Vec<Tp>)> {
    // `AbstractPartitionAssignor.assign`: the topics, as the members in `HashMap` order first name them, go into a
    // `HashSet` and from it into a `HashMap`; within a bin they keep that first-appearance order.
    let ids: Vec<String> = members.iter().map(|(id, _)| id.clone()).collect();
    let mut topics: Vec<String> = Vec::new();
    for i in crate::recorded::java_hashmap_order(&ids) {
        for t in &members[i].1.topics {
            if partitions.get(t).is_some_and(|n| *n > 0) && !topics.contains(t) {
                topics.push(t.clone());
            }
        }
    }
    let mut states: Vec<TopicState> = crate::recorded::java_hashmap_order(&topics)
        .into_iter()
        .map(|i| TopicState::new(&topics[i], partitions[&topics[i]], racks, members, prefer))
        .collect();
    let mut assignment: HashMap<String, Vec<Tp>> = members.iter().map(|(id, _)| (id.clone(), Vec::new())).collect();
    let rack_aware = states.iter().any(|s| s.needs_rack_aware);
    if rack_aware {
        assign_with_rack_matching(&mut states, &mut assignment);
    }
    for state in &mut states {
        state.assign_ranges(false, &mut assignment);
    }
    let mut out: Vec<(String, Vec<Tp>)> = assignment.into_iter().collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    if rack_aware {
        for (_, list) in &mut out {
            list.sort();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(id: &str, topics: &[&str]) -> (String, Subscription) {
        (id.to_string(), Subscription { topics: topics.iter().map(|t| t.to_string()).collect(), ..Default::default() })
    }

    #[test]
    fn range_assignment_gives_the_first_members_the_extra_partitions() {
        let members = vec![member("b", &["t"]), member("a", &["t"])];
        let counts: BTreeMap<String, usize> = [("t".to_string(), 3)].into_iter().collect();
        let assigned = assign(&counts, &ReplicaRacks::new(), &members);
        assert_eq!(assigned, vec![("a".to_string(), vec![("t".to_string(), 0), ("t".to_string(), 1)]), ("b".to_string(), vec![("t".to_string(), 2)])]);
    }

    /// `testOneStaticConsumerAndOneDynamicConsumerTwoTopicsSixPartitions`: a static member sorts before dynamic ones.
    #[test]
    fn static_members_take_the_first_ranges() {
        let a = member("consumer-a", &["t1", "t2"]);
        let mut b = member("consumer-b", &["t1", "t2"]);
        b.1.instance_id = Some("instance-b".into());
        let counts: BTreeMap<String, usize> = [("t1".to_string(), 3), ("t2".to_string(), 3)].into_iter().collect();
        let mut assigned: BTreeMap<String, Vec<Tp>> = assign(&counts, &ReplicaRacks::new(), &[a, b]).into_iter().collect();
        assigned.values_mut().for_each(|l| l.sort());
        let tp = |t: &str, p: i32| (t.to_string(), p);
        assert_eq!(assigned["consumer-b"], vec![tp("t1", 0), tp("t1", 1), tp("t2", 0), tp("t2", 1)]);
        assert_eq!(assigned["consumer-a"], vec![tp("t1", 2), tp("t2", 2)]);
    }
}
