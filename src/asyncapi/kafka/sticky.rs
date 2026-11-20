//! kafka-clients 4.3.1's `CooperativeStickyAssignor` (`AbstractStickyAssignor` and the cooperative adjustment), which the
//! classic group member runs as leader when the group agreed on `cooperative-sticky`. Iteration over Java hash maps is
//! reproduced where it decides the outcome: member ids in `HashMap<String, …>` order, and the first element of a
//! `HashSet<TopicPartition>` in partition movements. Rack-aware assignment (`RackInfo`) applies when members set
//! `client.rack` on a cluster whose brokers have racks; MockServer's own member never sets one.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub type Tp = (String, i32);

const DEFAULT_GENERATION: i32 = -1;

/// A member's `ConsumerPartitionAssignor.Subscription`, as the leader reads it from `JoinGroup`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Subscription {
    pub topics: Vec<String>,
    pub owned: Vec<Tp>,
    /// `generationId` (protocol v2 and later), absent when negative.
    pub generation: Option<i32>,
    pub user_data: Option<Vec<u8>>,
    /// `rackId` (protocol v3 and later): the member's `client.rack`.
    pub rack: Option<String>,
    /// `groupInstanceId`, from the `JoinGroup` member (`group.instance.id`).
    pub instance_id: Option<String>,
}

impl Subscription {
    /// `rackId().filter(r -> !r.isEmpty())`.
    pub fn rack(&self) -> Option<&str> {
        self.rack.as_deref().filter(|r| !r.is_empty())
    }
}

/// The racks of each partition's replicas whose broker has a rack, as the metadata gives them; a partition missing
/// here has none.
pub type ReplicaRacks = HashMap<Tp, Vec<String>>;

/// `AbstractPartitionAssignor.useRackAwareAssignment`: some consumer rack has replicas, and the replicas of some
/// partition are not on every rack (or the tests' `preferRackAwareLogic`).
pub fn use_rack_aware<'a>(
    consumer_racks: &BTreeSet<String>,
    partition_racks: &BTreeSet<String>,
    mut racks_per_partition: impl Iterator<Item = &'a BTreeSet<String>>,
    prefer: bool,
) -> bool {
    if consumer_racks.is_empty() || consumer_racks.is_disjoint(partition_racks) {
        false
    } else if prefer {
        true
    } else {
        !racks_per_partition.all(|r| r == partition_racks)
    }
}

/// `AbstractStickyAssignor.RackInfo`: the consumers' and partitions' racks when rack-aware assignment is used (both
/// empty otherwise), and how many consumers share a rack with each partition's replicas (counted whenever some
/// consumer has a rack).
#[derive(Default)]
struct RackInfo {
    consumer_racks: HashMap<String, String>,
    partition_racks: HashMap<Tp, BTreeSet<String>>,
    consumers_by_partition: HashMap<Tp, usize>,
}

impl RackInfo {
    fn new(partitions: &BTreeMap<String, usize>, racks: &ReplicaRacks, subs: &HashMap<String, Subscription>, prefer: bool) -> RackInfo {
        let mut consumers_by_rack: HashMap<String, Vec<String>> = HashMap::new();
        for (id, sub) in subs {
            if let Some(rack) = sub.rack() {
                consumers_by_rack.entry(rack.to_string()).or_default().push(id.clone());
            }
        }
        if consumers_by_rack.is_empty() {
            return RackInfo::default();
        }
        let mut partition_racks: HashMap<Tp, BTreeSet<String>> = HashMap::new();
        let mut all_partition_racks: BTreeSet<String> = BTreeSet::new();
        for (topic, count) in partitions {
            for p in 0..*count as i32 {
                let tp = (topic.clone(), p);
                let set: BTreeSet<String> = racks.get(&tp).into_iter().flatten().cloned().collect();
                all_partition_racks.extend(set.iter().cloned());
                partition_racks.insert(tp, set);
            }
        }
        let consumers_by_partition = partition_racks
            .iter()
            .map(|(tp, set)| (tp.clone(), set.iter().map(|r| consumers_by_rack.get(r).map_or(0, Vec::len)).sum()))
            .collect();
        let consumer_rack_set: BTreeSet<String> = consumers_by_rack.keys().cloned().collect();
        if use_rack_aware(&consumer_rack_set, &all_partition_racks, partition_racks.values(), prefer) {
            let consumer_racks = consumers_by_rack.iter().flat_map(|(rack, ids)| ids.iter().map(move |id| (id.clone(), rack.clone()))).collect();
            RackInfo { consumer_racks, partition_racks, consumers_by_partition }
        } else {
            RackInfo { consumers_by_partition, ..RackInfo::default() }
        }
    }

    /// `racksMismatch`: the consumer has a rack and no replica of the partition is on it.
    fn mismatch(&self, consumer: &str, tp: &Tp) -> bool {
        match self.consumer_racks.get(consumer) {
            None => false,
            Some(rack) => !self.partition_racks.get(tp).is_some_and(|set| set.contains(rack)),
        }
    }

    /// `sortPartitionsByRackConsumers`: a stable sort by the number of consumers on the partition's racks.
    fn sort_by_rack_consumers(&self, partitions: &mut [Tp]) {
        if !self.consumers_by_partition.is_empty() {
            partitions.sort_by_key(|tp| self.consumers_by_partition.get(tp).copied().unwrap_or(0));
        }
    }

    /// `nextRackConsumer`: from `first` round the list, the first consumer on one of the partition's racks.
    fn next_rack_consumer(&self, tp: &Tp, consumers: &[String], first: usize) -> Option<usize> {
        let racks = self.partition_racks.get(tp).filter(|r| !r.is_empty())?;
        (0..consumers.len()).map(|i| (first + i) % consumers.len()).find(|i| self.consumer_racks.get(&consumers[*i]).is_some_and(|r| racks.contains(r)))
    }
}

impl Subscription {
    /// The generation of `CooperativeStickyAssignor.memberData`: the subscription's own, else the user data's int32.
    fn member_generation(&self) -> Option<i32> {
        if self.generation.is_some() {
            return self.generation;
        }
        match &self.user_data {
            None => None,
            Some(d) if d.len() >= 4 => Some(i32::from_be_bytes([d[0], d[1], d[2], d[3]])),
            Some(_) => Some(DEFAULT_GENERATION),
        }
    }
}

/// The assignor instance: `maxGeneration` only ever grows over the consumer's lifetime, as in Java.
pub struct CooperativeSticky {
    max_generation: i32,
    /// `AbstractPartitionAssignor.preferRackAwareLogic`, set only by tests.
    pub prefer_rack_aware_logic: bool,
}

impl Default for CooperativeSticky {
    fn default() -> Self {
        CooperativeSticky { max_generation: DEFAULT_GENERATION, prefer_rack_aware_logic: false }
    }
}

fn string_hash(s: &str) -> i32 {
    s.encode_utf16().fold(0i32, |h, u| h.wrapping_mul(31).wrapping_add(u as i32))
}

/// `TopicPartition.hashCode`.
fn tp_hash(tp: &Tp) -> i32 {
    31i32.wrapping_mul(31i32.wrapping_add(tp.1)).wrapping_add(string_hash(&tp.0))
}

fn bucket(hash: i32, capacity: usize) -> usize {
    let h = hash as u32;
    ((h ^ (h >> 16)) as usize) & (capacity - 1)
}

/// A `HashSet<TopicPartition>` reduced to what decides `iterator().next()`: bins by hash at the current capacity, and
/// within a bin the insertion order.
#[derive(Default)]
struct JavaSet {
    items: Vec<(Tp, u64)>,
    capacity: usize,
    seq: u64,
}

impl JavaSet {
    fn insert(&mut self, tp: Tp) {
        if self.capacity == 0 {
            self.capacity = 16;
        }
        if self.items.iter().any(|(t, _)| *t == tp) {
            return;
        }
        self.seq += 1;
        self.items.push((tp, self.seq));
        if self.items.len() as f64 > self.capacity as f64 * 0.75 {
            self.capacity *= 2;
        }
    }

    fn remove(&mut self, tp: &Tp) {
        self.items.retain(|(t, _)| t != tp);
    }

    fn first(&self) -> Option<&Tp> {
        self.items.iter().min_by_key(|(t, seq)| (bucket(tp_hash(t), self.capacity), *seq)).map(|(t, _)| t)
    }
}

/// `List.remove(Object)`: the first occurrence.
fn remove_first(list: &mut Vec<Tp>, tp: &Tp) -> bool {
    match list.iter().position(|t| t == tp) {
        Some(i) => {
            list.remove(i);
            true
        }
        None => false,
    }
}

impl CooperativeSticky {
    /// `CooperativeStickyAssignor.assignPartitions`: `members` in `JoinGroup` order, `partitions` the subscribed topics'
    /// partition counts, `racks` their replicas' racks. The result is in `HashMap` iteration order of the member ids
    /// (`ConsumerCoordinator` collects the subscriptions in a default `HashMap`). An error stands for an exception the
    /// Java assignor would throw.
    pub fn assign(&mut self, partitions: &BTreeMap<String, usize>, racks: &ReplicaRacks, members: &[(String, Subscription)]) -> Result<Vec<(String, Vec<Tp>)>, String> {
        let ids: Vec<String> = members.iter().map(|(id, _)| id.clone()).collect();
        let order: Vec<String> = crate::recorded::java_hashmap_order(&ids).into_iter().map(|i| ids[i].clone()).collect();
        self.assign_in_order(partitions, racks, members, order)
    }

    /// The same with the member ids' `HashMap` iteration order given.
    pub(super) fn assign_in_order(
        &mut self,
        partitions: &BTreeMap<String, usize>,
        racks: &ReplicaRacks,
        members: &[(String, Subscription)],
        order: Vec<String>,
    ) -> Result<Vec<(String, Vec<Tp>)>, String> {
        let subs: HashMap<String, Subscription> = members.iter().cloned().collect();
        // `AbstractPartitionAssignor.assign`: only subscribed topics with partitions.
        let partitions: BTreeMap<String, usize> = partitions
            .iter()
            .filter(|(t, n)| **n > 0 && subs.values().any(|s| s.topics.contains(t)))
            .map(|(t, n)| (t.clone(), *n))
            .collect();
        let rack = RackInfo::new(&partitions, racks, &subs, self.prefer_rack_aware_logic);
        let mut owned: HashMap<String, Vec<Tp>> = HashMap::new();
        let mut multi: HashSet<Tp> = HashSet::new();
        let equal = self.all_subscriptions_equal(&partitions, &order, &subs, &mut owned, &mut multi);
        let (mut assignment, transferring) = if equal {
            let mut transferring = HashMap::new();
            let assignment = constrained(&partitions, &rack, &order, &owned, &multi, &mut transferring)?;
            (assignment, transferring)
        } else {
            let assignment = General::new(&partitions, &rack, &order, &subs, owned, self.max_generation).build()?;
            let transferring = transferring_ownership(&subs, &order, &assignment);
            (assignment, transferring)
        };
        for (tp, consumer) in &transferring {
            if let Some(list) = assignment.get_mut(consumer) {
                remove_first(list, tp);
            }
        }
        Ok(order.iter().filter_map(|id| assignment.remove(id).map(|a| (id.clone(), a))).collect())
    }

    /// `allSubscriptionsEqual`: also each member's previously owned, still subscribed partitions (a partition claimed
    /// twice goes to the higher generation, or to nobody on a tie).
    fn all_subscriptions_equal(
        &mut self,
        partitions: &BTreeMap<String, usize>,
        order: &[String],
        subs: &HashMap<String, Subscription>,
        owned: &mut HashMap<String, Vec<Tp>>,
        multi: &mut HashSet<Tp>,
    ) -> bool {
        let mut equal = true;
        let mut subscribed: HashSet<String> = HashSet::new();
        let mut previous_owner: HashMap<Tp, String> = HashMap::new();
        for consumer in order {
            let sub = &subs[consumer];
            if subscribed.is_empty() {
                subscribed.extend(sub.topics.iter().cloned());
            } else if equal && !(sub.topics.len() == subscribed.len() && sub.topics.iter().all(|t| subscribed.contains(t))) {
                equal = false;
            }
            let generation = sub.member_generation().unwrap_or(DEFAULT_GENERATION);
            self.max_generation = self.max_generation.max(generation);
            owned.insert(consumer.clone(), Vec::new());
            for tp in &sub.owned {
                if !partitions.contains_key(&tp.0) {
                    continue;
                }
                match previous_owner.get(tp).cloned() {
                    None => {
                        owned.get_mut(consumer).expect("inserted").push(tp.clone());
                        previous_owner.insert(tp.clone(), consumer.clone());
                    }
                    Some(other) => {
                        let other_generation = subs[&other].generation.unwrap_or(DEFAULT_GENERATION);
                        if generation == other_generation {
                            multi.insert(tp.clone());
                            remove_first(owned.get_mut(&other).expect("seen"), tp);
                            previous_owner.insert(tp.clone(), consumer.clone());
                        } else if generation > other_generation {
                            owned.get_mut(consumer).expect("inserted").push(tp.clone());
                            remove_first(owned.get_mut(&other).expect("seen"), tp);
                            previous_owner.insert(tp.clone(), consumer.clone());
                        }
                    }
                }
            }
        }
        equal
    }
}

/// `CooperativeStickyAssignor.computePartitionsTransferringOwnership`, for the general case.
fn transferring_ownership(subs: &HashMap<String, Subscription>, order: &[String], assignment: &HashMap<String, Vec<Tp>>) -> HashMap<Tp, String> {
    let mut added: HashMap<Tp, String> = HashMap::new();
    let mut revoked: HashSet<Tp> = HashSet::new();
    for consumer in order {
        let Some(assigned) = assignment.get(consumer) else { continue };
        let owned = &subs[consumer].owned;
        for tp in assigned {
            if !owned.contains(tp) {
                added.insert(tp.clone(), consumer.clone());
            }
        }
        for tp in owned {
            if !assigned.contains(tp) {
                revoked.insert(tp.clone());
            }
        }
    }
    added.retain(|tp, _| revoked.contains(tp));
    added
}

/// `ConstrainedAssignmentBuilder`: every member subscribes to the same topics.
fn constrained(
    partitions: &BTreeMap<String, usize>,
    rack: &RackInfo,
    order: &[String],
    current: &HashMap<String, Vec<Tp>>,
    multi: &HashSet<Tp>,
    transferring: &mut HashMap<Tp, String>,
) -> Result<HashMap<String, Vec<Tp>>, String> {
    let total: usize = partitions.values().sum();
    let members = order.len();
    let min_quota = total / members;
    let max_quota = total.div_ceil(members);
    let expected_over = total % members;
    let mut current_over = 0usize;
    let mut assignment: HashMap<String, Vec<Tp>> = order.iter().map(|c| (c.clone(), Vec::new())).collect();
    let mut assigned: Vec<Tp> = Vec::new();
    let mut maybe_revoked: HashMap<Tp, String> = HashMap::new();
    let mut under: Vec<String> = Vec::new();
    let mut exact: Vec<String> = Vec::new();

    // assignOwnedPartitions: owned partitions off the member's rack may be revoked.
    for consumer in order {
        let mut owned: Vec<Tp> = Vec::new();
        for tp in &current[consumer] {
            if rack.mismatch(consumer, tp) {
                maybe_revoked.insert(tp.clone(), consumer.clone());
            } else {
                owned.push(tp.clone());
            }
        }
        owned.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        for doubly in multi {
            remove_first(&mut owned, doubly);
        }
        let target = assignment.get_mut(consumer).expect("every member");
        if owned.len() < min_quota {
            target.extend(owned.iter().cloned());
            assigned.extend(owned);
            under.push(consumer.clone());
        } else if owned.len() >= max_quota && current_over < expected_over {
            current_over += 1;
            if current_over == expected_over {
                exact.clear();
            }
            target.extend(owned[..max_quota].iter().cloned());
            assigned.extend(owned[..max_quota].iter().cloned());
            for tp in &owned[max_quota..] {
                maybe_revoked.insert(tp.clone(), consumer.clone());
            }
        } else {
            target.extend(owned[..min_quota].iter().cloned());
            assigned.extend(owned[..min_quota].iter().cloned());
            for tp in &owned[min_quota..] {
                maybe_revoked.insert(tp.clone(), consumer.clone());
            }
            if current_over < expected_over {
                exact.push(consumer.clone());
            }
        }
    }

    // getUnassignedPartitions: the two-pointer walk over the sorted topics' partitions.
    let mut unassigned: Vec<Tp> = if assigned.is_empty() {
        partitions.iter().flat_map(|(t, n)| (0..*n as i32).map(move |p| (t.clone(), p))).collect()
    } else {
        assigned.sort();
        let mut out = Vec::new();
        let mut add_directly = false;
        let mut iter = assigned.iter();
        let mut next = iter.next().expect("not empty");
        for (topic, count) in partitions {
            for i in 0..*count as i32 {
                if add_directly || !(next.0 == *topic && next.1 == i) {
                    out.push((topic.clone(), i));
                } else {
                    match iter.next() {
                        Some(n) => next = n,
                        None => add_directly = true,
                    }
                }
            }
        }
        out
    };
    under.sort();
    exact.sort();
    rack.sort_by_rack_consumers(&mut unassigned);

    // assignNewPartition: the count it now has.
    let mut assign_new = |tp: &Tp, consumer: &str, assignment: &mut HashMap<String, Vec<Tp>>| -> usize {
        let list = assignment.get_mut(consumer).expect("every member");
        list.push(tp.clone());
        if maybe_revoked.get(tp).is_some_and(|c| c != consumer) || multi.contains(tp) {
            transferring.insert(tp.clone(), consumer.to_string());
        }
        list.len()
    };

    // assignRackAwareRoundRobin: within racks, up to maxQuota, else minQuota; what cannot be aligned stays.
    if !rack.consumer_racks.is_empty() {
        let mut next_unfilled = 0usize;
        let mut i = 0usize;
        while i < unassigned.len() {
            let tp = unassigned[i].clone();
            let mut consumer: Option<String> = None;
            if let Some(mut next) = rack.next_rack_consumer(&tp, &under, next_unfilled) {
                let c = under[next].clone();
                let count = assignment[&c].len() + 1;
                if count >= min_quota {
                    under.retain(|u| *u != c);
                    if count < max_quota && current_over < expected_over {
                        exact.push(c.clone());
                    }
                } else {
                    next += 1;
                }
                next_unfilled = if under.is_empty() { 0 } else { next % under.len() };
                consumer = Some(c);
            } else if !exact.is_empty() && let Some(first) = rack.next_rack_consumer(&tp, &exact, 0) {
                let c = exact[first].clone();
                if assignment[&c].len() + 1 == max_quota {
                    exact.remove(first);
                    current_over += 1;
                    if current_over == expected_over {
                        exact.clear();
                    }
                }
                consumer = Some(c);
            }
            match consumer {
                Some(c) => {
                    assign_new(&tp, &c, &mut assignment);
                    unassigned.remove(i);
                }
                None => i += 1,
            }
        }
    }

    // assignRoundRobin, with `under`'s iterator as a cursor (`pos` is the next index, `last` the last one returned).
    let mut pos = 0usize;
    let mut last: Option<usize> = None;
    for tp in &unassigned {
        let consumer = if pos < under.len() {
            last = Some(pos);
            pos += 1;
            under[pos - 1].clone()
        } else if under.is_empty() && exact.is_empty() {
            return Err("No more unfilled consumers to be assigned.".into());
        } else if under.is_empty() {
            exact.remove(0)
        } else {
            pos = 1;
            last = Some(0);
            under[0].clone()
        };
        let count = assign_new(tp, &consumer, &mut assignment);
        if count == min_quota {
            if let Some(l) = last.take() {
                under.remove(l);
                pos -= 1;
            }
            exact.push(consumer);
        } else if count == max_quota {
            current_over += 1;
        }
    }

    // verifyUnfilledMembers
    if !under.is_empty() {
        if current_over != expected_over {
            return Err("We haven't reached the expected number of members with more than the minQuota partitions, but no more partitions to be assigned".into());
        }
        if let Some(m) = under.iter().find(|m| assignment[*m].len() != min_quota) {
            return Err(format!("Consumer: [{m}] doesn't reach minQuota partitions, and no more partitions to be assigned"));
        }
    }
    Ok(assignment)
}

/// `PartitionMovements`.
#[derive(Default)]
struct Movements {
    by_topic: HashMap<String, HashMap<(String, String), JavaSet>>,
    movements: HashMap<Tp, (String, String)>,
}

impl Movements {
    fn remove_record(&mut self, tp: &Tp) -> (String, String) {
        let pair = self.movements.remove(tp).expect("recorded");
        let topic = self.by_topic.get_mut(&tp.0).expect("recorded");
        let set = topic.get_mut(&pair).expect("recorded");
        set.remove(tp);
        if set.items.is_empty() {
            topic.remove(&pair);
        }
        if topic.is_empty() {
            self.by_topic.remove(&tp.0);
        }
        pair
    }

    fn add_record(&mut self, tp: &Tp, pair: (String, String)) {
        self.movements.insert(tp.clone(), pair.clone());
        self.by_topic.entry(tp.0.clone()).or_default().entry(pair).or_default().insert(tp.clone());
    }

    fn move_partition(&mut self, tp: &Tp, old: &str, new: &str) {
        if self.movements.contains_key(tp) {
            let existing = self.remove_record(tp);
            if existing.0 != new {
                self.add_record(tp, (existing.0, new.to_string()));
            }
        } else {
            self.add_record(tp, (old.to_string(), new.to_string()));
        }
    }

    fn actual_partition_to_move(&self, tp: &Tp, old: &str, new: &str) -> Tp {
        let Some(topic) = self.by_topic.get(&tp.0) else { return tp.clone() };
        let old = match self.movements.get(tp) {
            Some((src, _)) => src.as_str(),
            None => old,
        };
        match topic.get(&(new.to_string(), old.to_string())) {
            Some(set) => set.first().cloned().unwrap_or_else(|| tp.clone()),
            None => tp.clone(),
        }
    }
}

/// `GeneralAssignmentBuilder`: the members subscribe to different topics.
struct General<'a> {
    partitions: &'a BTreeMap<String, usize>,
    rack: &'a RackInfo,
    order: &'a [String],
    subs: &'a HashMap<String, Subscription>,
    max_generation: i32,
    total: usize,
    current: HashMap<String, Vec<Tp>>,
    topic_consumers: HashMap<String, Vec<String>>,
    consumer_topics: HashMap<String, Vec<String>>,
    partition_consumer: HashMap<Tp, String>,
    sorted_all: Vec<Tp>,
    sorted: BTreeSet<(usize, String)>,
    revocation_required: bool,
    movements: Movements,
}

impl<'a> General<'a> {
    fn new(
        partitions: &'a BTreeMap<String, usize>,
        rack: &'a RackInfo,
        order: &'a [String],
        subs: &'a HashMap<String, Subscription>,
        mut current: HashMap<String, Vec<Tp>>,
        max_generation: i32,
    ) -> Self {
        let mut topic_consumers: HashMap<String, Vec<String>> = partitions.keys().map(|t| (t.clone(), Vec::new())).collect();
        let mut consumer_topics: HashMap<String, Vec<String>> = HashMap::new();
        for consumer in order {
            let mut topics = Vec::new();
            for t in subs[consumer].topics.iter().filter(|t| partitions.contains_key(*t)) {
                topics.push(t.clone());
                topic_consumers.get_mut(t).expect("every topic").push(consumer.clone());
            }
            consumer_topics.insert(consumer.clone(), topics);
            current.entry(consumer.clone()).or_default();
        }
        let mut partition_consumer = HashMap::new();
        for consumer in order {
            for tp in &current[consumer] {
                partition_consumer.insert(tp.clone(), consumer.clone());
            }
        }
        let mut sorted_topics: Vec<&String> = topic_consumers.keys().collect();
        sorted_topics.sort_by(|a, b| topic_consumers[*a].len().cmp(&topic_consumers[*b].len()).then_with(|| a.cmp(b)));
        let sorted_all = sorted_topics.iter().flat_map(|t| (0..partitions[*t] as i32).map(move |p| ((*t).clone(), p))).collect();
        General {
            partitions,
            rack,
            order,
            subs,
            max_generation,
            total: partitions.values().sum(),
            current,
            topic_consumers,
            consumer_topics,
            partition_consumer,
            sorted_all,
            sorted: BTreeSet::new(),
            revocation_required: false,
            movements: Movements::default(),
        }
    }

    fn size(&self, consumer: &str) -> Result<usize, String> {
        self.current.get(consumer).map(Vec::len).ok_or_else(|| "NullPointerException".to_string())
    }

    fn tree_remove(&mut self, consumer: &str) {
        if let Some(n) = self.current.get(consumer).map(Vec::len) {
            self.sorted.remove(&(n, consumer.to_string()));
        }
    }

    fn tree_add(&mut self, consumer: &str) {
        if let Some(n) = self.current.get(consumer).map(Vec::len) {
            self.sorted.insert((n, consumer.to_string()));
        }
    }

    fn build(mut self) -> Result<HashMap<String, Vec<Tp>>, String> {
        let mut prev: HashMap<Tp, (String, i32)> = HashMap::new();
        self.prepopulate(&mut prev);
        let assigned = self.assign_owned();
        let mut unassigned = self.unassigned(assigned);
        let keys: Vec<String> = self.current.keys().cloned().collect();
        for k in keys {
            self.tree_add(&k);
        }
        self.balance(&prev, &mut unassigned)?;
        Ok(self.current)
    }

    fn prepopulate(&self, prev: &mut HashMap<Tp, (String, i32)>) {
        let mut update = |partitions: &[Tp], consumer: &str, generation: i32| {
            for tp in partitions {
                match prev.get(tp) {
                    Some((_, g)) if generation <= *g => {}
                    _ => {
                        prev.insert(tp.clone(), (consumer.to_string(), generation));
                    }
                }
            }
        };
        for consumer in self.order {
            let sub = &self.subs[consumer];
            match sub.member_generation() {
                Some(g) if g < self.max_generation => update(&sub.owned, consumer, g),
                None if self.max_generation > DEFAULT_GENERATION => update(&sub.owned, consumer, DEFAULT_GENERATION),
                _ => {}
            }
        }
    }

    fn assign_owned(&mut self) -> Vec<Tp> {
        let mut assigned = Vec::new();
        for consumer in self.order {
            let Some(list) = self.current.get_mut(consumer) else { continue };
            let sub = &self.subs[consumer];
            let mut kept = Vec::new();
            for tp in list.drain(..) {
                if !self.topic_consumers.contains_key(&tp.0) {
                    self.partition_consumer.remove(&tp);
                } else if !sub.topics.contains(&tp.0) || self.rack.mismatch(consumer, &tp) {
                    self.revocation_required = true;
                } else {
                    assigned.push(tp.clone());
                    kept.push(tp);
                }
            }
            *list = kept;
        }
        assigned
    }

    fn partition_order(&self, a: &Tp, b: &Tp) -> std::cmp::Ordering {
        self.topic_consumers[&a.0].len().cmp(&self.topic_consumers[&b.0].len()).then_with(|| a.0.cmp(&b.0)).then_with(|| a.1.cmp(&b.1))
    }

    fn unassigned(&self, mut assigned: Vec<Tp>) -> Vec<Tp> {
        if assigned.is_empty() {
            return self.sorted_all.clone();
        }
        assigned.sort_by(|a, b| self.partition_order(a, b));
        let mut out = Vec::new();
        let mut add_directly = false;
        let mut iter = assigned.iter();
        let mut next = iter.next().expect("not empty");
        for tp in &self.sorted_all {
            if add_directly || next != tp {
                out.push(tp.clone());
            } else {
                match iter.next() {
                    Some(n) => next = n,
                    None => add_directly = true,
                }
            }
        }
        out
    }

    fn max_assignment_size(&self, topics: &[String]) -> usize {
        if topics.len() == self.partitions.len() {
            self.total
        } else {
            topics.iter().map(|t| self.partitions[t]).sum()
        }
    }

    fn is_balanced(&self) -> Result<bool, String> {
        let (Some(first), Some(last)) = (self.sorted.first(), self.sorted.last()) else {
            return Err("NoSuchElementException".into());
        };
        if self.size(&first.1)? + 1 >= self.size(&last.1)? {
            return Ok(true);
        }
        let mut all: HashMap<&Tp, &String> = HashMap::new();
        for (consumer, list) in &self.current {
            for tp in list {
                all.insert(tp, consumer);
            }
        }
        for (_, consumer) in &self.sorted {
            let count = self.size(consumer)?;
            let topics = &self.consumer_topics[consumer];
            if count == self.max_assignment_size(topics) {
                continue;
            }
            for topic in topics {
                for i in 0..self.partitions[topic] as i32 {
                    let tp = (topic.clone(), i);
                    if !self.current[consumer].contains(&tp) {
                        let other = all.get(&tp).ok_or("NullPointerException")?;
                        if count + 1 < self.size(other)? {
                            return Ok(false);
                        }
                    }
                }
            }
        }
        Ok(true)
    }

    fn balance_score(assignment: &HashMap<String, Vec<Tp>>) -> i64 {
        let sizes: Vec<i64> = assignment.values().map(|l| l.len() as i64).collect();
        let mut score = 0;
        for i in 0..sizes.len() {
            for j in i + 1..sizes.len() {
                score += (sizes[i] - sizes[j]).abs();
            }
        }
        score
    }

    /// `maybeAssignPartition`: to the least loaded subscriber, on the partition's racks when `rack_match`.
    fn maybe_assign_partition(&mut self, tp: &Tp, rack_match: bool) -> bool {
        let found = self
            .sorted
            .iter()
            .find(|(_, c)| self.consumer_topics[c].contains(&tp.0) && !(rack_match && self.rack.mismatch(c, tp)))
            .map(|(_, c)| c.clone());
        match found {
            Some(consumer) => {
                self.tree_remove(&consumer);
                self.current.get_mut(&consumer).expect("in tree").push(tp.clone());
                self.partition_consumer.insert(tp.clone(), consumer.clone());
                self.tree_add(&consumer);
                true
            }
            None => false,
        }
    }

    fn topic_can_move(&self, topic: &str) -> bool {
        self.topic_consumers[topic].len() >= 2
    }

    fn consumer_can_move(&self, consumer: &str) -> bool {
        let list = &self.current[consumer];
        if list.len() < self.max_assignment_size(&self.consumer_topics[consumer]) {
            return true;
        }
        list.iter().any(|tp| self.topic_can_move(&tp.0))
    }

    fn balance(&mut self, prev: &HashMap<Tp, (String, i32)>, unassigned: &mut Vec<Tp>) -> Result<(), String> {
        let last = self.sorted.last().map(|(_, c)| c.clone()).ok_or("NoSuchElementException")?;
        let initializing = self.current[&last].is_empty();
        // First within racks, then what is left anywhere.
        let mut to_assign = unassigned.clone();
        if !self.rack.consumer_racks.is_empty() {
            to_assign.retain(|tp| self.topic_consumers[&tp.0].is_empty() || !self.maybe_assign_partition(tp, true));
        }
        for tp in to_assign {
            if self.topic_consumers[&tp.0].is_empty() {
                continue;
            }
            self.maybe_assign_partition(&tp, false);
        }
        let fixed: HashSet<Tp> = self
            .topic_consumers
            .keys()
            .filter(|t| !self.topic_can_move(t))
            .flat_map(|t| (0..self.partitions[t] as i32).map(move |p| (t.clone(), p)))
            .collect();
        self.sorted_all.retain(|tp| !fixed.contains(tp));
        unassigned.retain(|tp| !fixed.contains(tp));
        let mut fixed_assignments: Vec<(String, Vec<Tp>)> = Vec::new();
        for consumer in self.order {
            if !self.consumer_can_move(consumer) {
                self.tree_remove(consumer);
                let list = self.current.remove(consumer).expect("every member");
                fixed_assignments.push((consumer.clone(), list));
            }
        }
        let pre_balance = self.current.clone();
        let pre_partition_consumer = self.partition_consumer.clone();
        if !self.revocation_required {
            self.perform_reassignments(&unassigned.clone(), prev)?;
        }
        let performed = self.perform_reassignments(&self.sorted_all.clone(), prev)?;
        if !initializing && performed && Self::balance_score(&self.current) >= Self::balance_score(&pre_balance) {
            self.current = pre_balance;
            self.partition_consumer = pre_partition_consumer;
        }
        for (consumer, list) in fixed_assignments {
            self.current.insert(consumer.clone(), list);
            self.tree_add(&consumer);
        }
        Ok(())
    }

    fn perform_reassignments(&mut self, partitions: &[Tp], prev: &HashMap<Tp, (String, i32)>) -> Result<bool, String> {
        let mut performed = false;
        loop {
            let mut modified = false;
            for tp in partitions {
                if self.is_balanced()? {
                    break;
                }
                let consumer = self.partition_consumer.get(tp).cloned().ok_or("NullPointerException")?;
                if let Some((prev_consumer, _)) = prev.get(tp) && self.size(&consumer)? > self.size(prev_consumer)? + 1 {
                    self.reassign_to(tp, prev_consumer);
                    performed = true;
                    modified = true;
                    continue;
                }
                // Java first looks among the subscribers on the partition's racks, then among all; both searches end
                // in the same `reassignPartition(partition)`, so the outcome is that of the second alone.
                let mut better = false;
                for other in &self.topic_consumers[&tp.0] {
                    if self.size(&consumer)? > self.size(other)? + 1 {
                        better = true;
                        break;
                    }
                }
                if better {
                    let new = self.sorted.iter().find(|(_, c)| self.consumer_topics[c].contains(&tp.0)).map(|(_, c)| c.clone());
                    if let Some(new) = new {
                        self.reassign_to(tp, &new);
                    }
                    performed = true;
                    modified = true;
                }
            }
            if !modified {
                break;
            }
        }
        Ok(performed)
    }

    fn reassign_to(&mut self, tp: &Tp, new: &str) {
        let consumer = self.partition_consumer[tp].clone();
        let actual = self.movements.actual_partition_to_move(tp, &consumer, new);
        let old = self.partition_consumer[&actual].clone();
        self.tree_remove(&old);
        self.tree_remove(new);
        self.movements.move_partition(&actual, &old, new);
        if let Some(list) = self.current.get_mut(&old) {
            remove_first(list, &actual);
        }
        if let Some(list) = self.current.get_mut(new) {
            list.push(actual.clone());
        }
        self.partition_consumer.insert(actual, new.to_string());
        self.tree_add(new);
        self.tree_add(&old);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(topics: &[&str], owned: &[(&str, i32)], generation: i32) -> Subscription {
        Subscription {
            topics: topics.iter().map(|t| t.to_string()).collect(),
            owned: owned.iter().map(|(t, p)| (t.to_string(), *p)).collect(),
            generation: (generation >= 0).then_some(generation),
            user_data: Some(generation.to_be_bytes().to_vec()),
            ..Default::default()
        }
    }

    /// The round robin over sorted members when nothing is owned yet.
    #[test]
    fn a_new_group_gets_the_partitions_round_robin() {
        let partitions: BTreeMap<String, usize> = [("t".to_string(), 4)].into_iter().collect();
        let members = vec![("b".to_string(), sub(&["t"], &[], -1)), ("a".to_string(), sub(&["t"], &[], -1))];
        let mut assigned = CooperativeSticky::default().assign(&partitions, &ReplicaRacks::new(), &members).unwrap();
        assigned.sort();
        assert_eq!(assigned, vec![("a".into(), vec![("t".into(), 0), ("t".into(), 2)]), ("b".into(), vec![("t".into(), 1), ("t".into(), 3)])]);
    }

    /// A partition another member still owns is held back for the next rebalance.
    #[test]
    fn owned_partitions_moving_to_a_new_member_are_held_back() {
        let partitions: BTreeMap<String, usize> = [("t".to_string(), 4)].into_iter().collect();
        let members = vec![("a".to_string(), sub(&["t"], &[("t", 0), ("t", 1), ("t", 2), ("t", 3)], 1)), ("b".to_string(), sub(&["t"], &[], -1))];
        let mut assigned = CooperativeSticky::default().assign(&partitions, &ReplicaRacks::new(), &members).unwrap();
        assigned.sort();
        assert_eq!(assigned, vec![("a".into(), vec![("t".into(), 0), ("t".into(), 1)]), ("b".into(), vec![])]);
    }

    fn tps(v: &serde_json::Value) -> Vec<Tp> {
        v.as_array().unwrap().iter().map(|tp| (tp[0].as_str().unwrap().to_string(), tp[1].as_i64().unwrap() as i32)).collect()
    }

    /// Vectors recorded from kafka-clients 4.3.1 (`tests/files/kafka/Gen.java`): each case is a series of rebalances
    /// on one assignor instance, with members joining, leaving, owning stale partitions and sending eager (empty)
    /// owned partitions; every member's list must match in content and order.
    #[test]
    fn matches_kafka_clients_vectors() {
        let path = format!("{}/tests/files/kafka/cooperative_sticky_vectors.json", env!("CARGO_MANIFEST_DIR"));
        let cases: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let mut failures = Vec::new();
        let mut rounds = 0;
        for (c, case) in cases.iter().enumerate() {
            let mut assignor = CooperativeSticky::default();
            for (r, round) in case.as_array().unwrap().iter().enumerate() {
                rounds += 1;
                let partitions: BTreeMap<String, usize> =
                    round["partitions"].as_object().unwrap().iter().map(|(t, n)| (t.clone(), n.as_u64().unwrap() as usize)).collect();
                let members: Vec<(String, Subscription)> = round["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|m| {
                        let generation = m["generation"].as_i64().unwrap() as i32;
                        let user_data = m["userData"].as_i64().unwrap() as i32;
                        (m["id"].as_str().unwrap().to_string(), Subscription {
                            topics: m["topics"].as_array().unwrap().iter().map(|t| t.as_str().unwrap().to_string()).collect(),
                            owned: tps(&m["owned"]),
                            generation: (generation >= 0).then_some(generation),
                            user_data: Some(user_data.to_be_bytes().to_vec()),
                            ..Default::default()
                        })
                    })
                    .collect();
                let expected: BTreeMap<String, Vec<Tp>> = round["result"].as_object().unwrap().iter().map(|(id, l)| (id.clone(), tps(l))).collect();
                match assignor.assign(&partitions, &ReplicaRacks::new(), &members) {
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
}
