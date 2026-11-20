//! A classic consumer-group member (`KafkaConsumer` with `group.id`): find the coordinator, join with the `range`
//! and `cooperative-sticky` protocols, assign as leader with the protocol the group chose (`RangeAssignor` in
//! `range.rs`, or `CooperativeStickyAssignor` in `sticky.rs`, both rack-aware from the members' `client.rack` and the
//! metadata's replica racks), resume from committed offsets or the earliest
//! (`auto.offset.reset=earliest`), fetch, heartbeat every 3 s, auto-commit every 5 s, and on close commit and leave.
//!
//! The member side is EAGER whichever protocol the group chose: `ConsumerCoordinator` takes the newest rebalance
//! protocol that every configured assignor supports, and `RangeAssignor` supports only EAGER. So before every join it
//! commits and gives up all its partitions (its subscription owns none), and it never rejoins to finish a
//! cooperative revocation.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use kafka_protocol::messages::{
    ApiKey, ConsumerProtocolAssignment, ConsumerProtocolSubscription, FetchRequest, FindCoordinatorRequest, GroupId, HeartbeatRequest, JoinGroupRequest,
    LeaveGroupRequest, ListOffsetsRequest, OffsetCommitRequest, OffsetFetchRequest, SyncGroupRequest, TopicName, consumer_protocol_assignment,
    fetch_request, join_group_request::JoinGroupRequestProtocol, leave_group_request::MemberIdentity,
    list_offsets_request, offset_commit_request, offset_fetch_request, sync_group_request::SyncGroupRequestAssignment,
};
use kafka_protocol::protocol::StrBytes;
use parking_lot::Mutex;

use super::super::broker::Error;
use super::range;
use super::sticky::{self, CooperativeSticky};
use super::wire::{self, Cluster};
use super::{ConsumerRecord, Recording};

const SESSION_TIMEOUT_MS: i32 = 45000;
const REBALANCE_TIMEOUT_MS: i32 = 300000;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);
const AUTO_COMMIT_INTERVAL: Duration = Duration::from_secs(5);
const METADATA_MAX_AGE: Duration = Duration::from_secs(300);
const FETCH_MAX_WAIT_MS: i32 = 500;
/// `request.timeout.ms`, which `ListOffsets` carries as its `timeout_ms`.
const REQUEST_TIMEOUT_MS: i32 = 30000;
const RETRY: Duration = Duration::from_millis(100);

pub struct PollLoop {
    pub cluster: Arc<Cluster>,
    pub group: String,
    pub topics: Arc<Mutex<Vec<String>>>,
    pub changed: Arc<tokio::sync::Notify>,
    pub recording: Arc<Recording>,
    pub failed: Arc<AtomicBool>,
    pub stop: tokio::sync::watch::Receiver<bool>,
}

fn s(text: &str) -> StrBytes {
    StrBytes::from_string(text.to_string())
}

fn topic_name(t: &str) -> TopicName {
    TopicName(s(t))
}

/// What the member holds between polls.
#[derive(Default)]
struct Member {
    coordinator: Option<i32>,
    member_id: String,
    generation: i32,
    protocol: Option<String>,
    joined_topics: Vec<String>,
    assignment: Vec<(String, i32)>,
    positions: BTreeMap<(String, i32), i64>,
    /// `FetchPosition.offsetEpoch` of each position: the leader epoch of the last batch consumed (or the committed or
    /// listed offset's), -1 when unknown. `OffsetCommit` sends it as the committed leader epoch.
    epochs: BTreeMap<(String, i32), i32>,
    /// The incremental fetch session with each leader (`FetchSessionHandler`).
    fetch_sessions: BTreeMap<i32, FetchSession>,
    committed: BTreeMap<(String, i32), i64>,
    partition_counts: BTreeMap<String, usize>,
    /// The `CooperativeStickyAssignor` instance (its `maxGeneration` lives as long as the consumer).
    sticky: CooperativeSticky,
    /// `CooperativeStickyAssignor.generation`: the generation of the last assignment it was chosen for.
    sticky_generation: i32,
}

type PartitionKey = (String, i32);

/// What a `Fetch` asks of a partition; a session sends a partition again only when this changed.
#[derive(Clone, Copy, PartialEq)]
struct FetchPosition {
    offset: i64,
    leader_epoch: i32,
}

/// One broker's incremental fetch session (KIP-227, `FetchSessionHandler`): `session_epoch` 0 with no session id is a
/// full fetch, which the broker answers with a session id; every later request carries that id and the next epoch
/// (wrapping past `i32::MAX` to 1) and names only the partitions that changed, plus the ones it forgets.
#[derive(Clone, Default)]
struct FetchSession {
    id: i32,
    epoch: i32,
    /// What the broker holds for the session, in the order it was sent.
    partitions: Vec<(PartitionKey, FetchPosition)>,
}

impl FetchSession {
    /// The partitions to send (altered ones in session order, then added ones) and the ones to forget.
    fn delta(&self, wanted: &[(PartitionKey, FetchPosition)]) -> (Vec<(PartitionKey, FetchPosition)>, Vec<PartitionKey>) {
        if self.id == 0 {
            return (wanted.to_vec(), Vec::new());
        }
        let mut send = Vec::new();
        let mut forgotten = Vec::new();
        for (key, held) in &self.partitions {
            match wanted.iter().find(|(k, _)| k == key) {
                Some((_, now)) if now != held => send.push((key.clone(), *now)),
                Some(_) => {}
                None => forgotten.push(key.clone()),
            }
        }
        for (key, now) in wanted {
            if !self.partitions.iter().any(|(k, _)| k == key) {
                send.push((key.clone(), *now));
            }
        }
        (send, forgotten)
    }

    /// The session after a response that carried `session_id`: none when the broker made no session.
    fn next(&self, session_id: i32, wanted: Vec<(PartitionKey, FetchPosition)>) -> FetchSession {
        if session_id == 0 {
            return FetchSession::default();
        }
        let epoch = if self.epoch == i32::MAX { 1 } else { self.epoch + 1 };
        FetchSession { id: session_id, epoch, partitions: wanted }
    }
}

enum Rejoin {
    Now,
    Reset,
}

impl PollLoop {
    fn stopped(&self) -> bool {
        *self.stop.borrow()
    }

    pub async fn run(mut self) {
        let mut member = Member { generation: -1, sticky_generation: -1, ..Member::default() };
        let mut joined = false;
        let mut last_heartbeat = Instant::now();
        let mut last_commit = Instant::now();
        let mut last_metadata = Instant::now();
        while !self.stopped() {
            let topics = self.topics.lock().clone();
            if topics.is_empty() {
                tokio::select! {
                    _ = self.changed.notified() => {}
                    _ = self.stop.changed() => {}
                }
                continue;
            }
            if !joined || member.joined_topics != topics {
                self.prepare_join(&mut member).await;
                let mut stop = self.stop.clone();
                let outcome = tokio::select! {
                    r = self.join(&mut member, &topics) => r,
                    _ = stop.changed() => break,
                };
                match outcome {
                    Ok(()) => {
                        joined = true;
                        last_heartbeat = Instant::now();
                        last_metadata = Instant::now();
                    }
                    Err(e) => {
                        // An authentication failure, or a subscribed topic the metadata reports invalid or
                        // unauthorised (`InvalidTopicException`, `TopicAuthorizationException`): the poll loop dies.
                        if self.cluster.fatal().is_some() || topics.iter().any(|t| matches!(self.cluster.partitions(t), Some((17 | 29, _)))) {
                            self.failed.store(true, Ordering::SeqCst);
                            return;
                        }
                        let _ = e;
                        self.pause(RETRY * 5).await;
                        continue;
                    }
                }
            }
            self.fetch(&mut member).await;
            if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
                last_heartbeat = Instant::now();
                match self.heartbeat(&member).await {
                    Some(Rejoin::Now) => joined = false,
                    Some(Rejoin::Reset) => {
                        member.member_id.clear();
                        member.generation = -1;
                        joined = false;
                    }
                    None => {}
                }
            }
            if last_commit.elapsed() >= AUTO_COMMIT_INTERVAL {
                last_commit = Instant::now();
                self.commit(&mut member).await;
            }
            // `metadata.max.age.ms`, and sooner while a subscribed topic has no partitions yet: a changed partition
            // count means a new assignment.
            let missing = topics.iter().any(|t| member.partition_counts.get(t).copied().unwrap_or(0) == 0);
            if last_metadata.elapsed() >= METADATA_MAX_AGE || (missing && last_metadata.elapsed() >= Duration::from_secs(1)) {
                last_metadata = Instant::now();
                if let Ok(counts) = self.partition_counts(&topics).await && counts != member.partition_counts {
                    joined = false;
                }
            }
        }
        // `close`: commit, then leave the group (also in the middle of a join).
        if joined {
            self.commit(&mut member).await;
        }
        if !member.member_id.is_empty() && let Some(coordinator) = member.coordinator {
            let request = LeaveGroupRequest::default().with_group_id(GroupId(s(&self.group))).with_member_id(s(&member.member_id)).with_members(vec![
                MemberIdentity::default().with_member_id(s(&member.member_id)).with_reason(Some(s("the consumer is being closed"))),
            ]);
            let _ = tokio::time::timeout(Duration::from_secs(5), self.cluster.send(coordinator, request)).await;
        }
    }

    async fn pause(&mut self, d: Duration) {
        tokio::select! {
            _ = tokio::time::sleep(d) => {}
            _ = self.stop.changed() => {}
            _ = self.changed.notified() => {}
        }
    }

    async fn coordinator(&self, member: &mut Member) -> Result<i32, Error> {
        if let Some(c) = member.coordinator {
            return Ok(c);
        }
        // v4+ batches the keys: the group sits in `coordinator_keys` and the answer in `coordinators`.
        let group = self.group.clone();
        let (asked, response) = self
            .cluster
            .send_any_with(|v| {
                let request = FindCoordinatorRequest::default().with_key_type(0);
                if v >= 4 { request.with_coordinator_keys(vec![s(&group)]) } else { request.with_key(s(&group)) }
            })
            .await?;
        let batched = self.cluster.version(asked, ApiKey::FindCoordinator as i16).await.is_some_and(|v| v >= 4);
        let (error_code, node, host, port) = if batched {
            let Some(c) = response.coordinators.first() else { return Err(Error::new("empty FindCoordinator response")) };
            (c.error_code, c.node_id.0, c.host.clone(), c.port)
        } else {
            (response.error_code, response.node_id.0, response.host.clone(), response.port)
        };
        if error_code != 0 {
            return Err(Error::new(wire::error_message(error_code)));
        }
        self.cluster.add_broker(node, host.to_string(), port as u16);
        member.coordinator = Some(node);
        Ok(node)
    }

    async fn partition_counts(&self, topics: &[String]) -> Result<BTreeMap<String, usize>, Error> {
        self.cluster.refresh(topics).await?;
        Ok(topics
            .iter()
            .map(|t| (t.clone(), self.cluster.partitions(t).filter(|(e, _)| *e == 0).map(|(_, p)| p.len()).unwrap_or(0)))
            .collect())
    }

    /// The racks of the replicas of `topics`' partitions, from the metadata `partition_counts` just fetched.
    fn replica_racks(&self, topics: &[String]) -> sticky::ReplicaRacks {
        let mut racks = sticky::ReplicaRacks::new();
        for t in topics {
            if let Some((0, partitions)) = self.cluster.partitions(t) {
                for p in partitions {
                    racks.insert((t.clone(), p.partition), p.replica_racks);
                }
            }
        }
        racks
    }

    /// `onJoinPrepare` (EAGER): auto-commit while the generation is valid, then revoke every partition, or lose them
    /// after the generation was reset.
    async fn prepare_join(&self, member: &mut Member) {
        if member.generation >= 0 && !member.member_id.is_empty() {
            self.commit(member).await;
        }
        member.assignment.clear();
        member.positions.clear();
        member.epochs.clear();
    }

    /// One protocol's metadata (`ConsumerCoordinator.metadata`): no owned partitions (they were all revoked), and the
    /// assignor's user data, which `CooperativeStickyAssignor` fills with its generation.
    fn subscription(&self, topics: &[String], member: &Member, protocol: &str) -> Result<Bytes, Error> {
        let user_data = (protocol == "cooperative-sticky").then(|| Bytes::copy_from_slice(&member.sticky_generation.to_be_bytes()));
        let subscription = ConsumerProtocolSubscription::default()
            .with_topics(topics.iter().map(|t| s(t)).collect())
            .with_user_data(user_data)
            .with_generation_id(member.generation);
        wire::write_versioned(&subscription, 3)
    }

    /// `JoinGroup`, then as leader the `RangeAssignor`, then `SyncGroup`, then the starting positions.
    async fn join(&self, member: &mut Member, topics: &[String]) -> Result<(), Error> {
        member.partition_counts = self.partition_counts(topics).await?;
        if let Some(bad) = topics.iter().find(|t| matches!(self.cluster.partitions(t), Some((17 | 29, _)))) {
            return Err(Error::new(format!("Invalid topics: [{bad}]")));
        }
        let coordinator = self.coordinator(member).await?;
        let range = self.subscription(topics, member, "range")?;
        let cooperative = self.subscription(topics, member, "cooperative-sticky")?;
        let response = loop {
            let request = JoinGroupRequest::default()
                .with_group_id(GroupId(s(&self.group)))
                .with_session_timeout_ms(SESSION_TIMEOUT_MS)
                .with_rebalance_timeout_ms(REBALANCE_TIMEOUT_MS)
                .with_member_id(s(&member.member_id))
                .with_protocol_type(s("consumer"))
                .with_protocols(vec![
                    JoinGroupRequestProtocol::default().with_name(s("range")).with_metadata(range.clone()),
                    JoinGroupRequestProtocol::default().with_name(s("cooperative-sticky")).with_metadata(cooperative.clone()),
                ]);
            let response = match self.cluster.send(coordinator, request).await {
                Ok(r) => r,
                Err(e) => {
                    member.coordinator = None;
                    return Err(e);
                }
            };
            match response.error_code {
                0 => break response,
                // MEMBER_ID_REQUIRED: join again with the id the coordinator gave.
                79 => member.member_id = response.member_id.to_string(),
                25 | 22 => member.member_id.clear(),
                14..=16 => {
                    member.coordinator = None;
                    return Err(Error::new(wire::error_message(response.error_code)));
                }
                27 => tokio::time::sleep(RETRY).await,
                code => return Err(Error::new(wire::error_message(code))),
            }
        };
        member.member_id = response.member_id.to_string();
        member.generation = response.generation_id;
        member.protocol = response.protocol_name.as_ref().map(|p| p.to_string());
        let assignments = if response.leader == response.member_id {
            let mut members: Vec<(String, sticky::Subscription)> = Vec::new();
            for m in &response.members {
                let (_, sub) = wire::read_versioned::<ConsumerProtocolSubscription>(m.metadata.clone())?;
                members.push((m.member_id.to_string(), sticky::Subscription {
                    topics: sub.topics.iter().map(|t| t.to_string()).collect(),
                    owned: sub.owned_partitions.iter().flat_map(|tp| tp.partitions.iter().map(move |p| (tp.topic.0.to_string(), *p))).collect(),
                    generation: (sub.generation_id >= 0).then_some(sub.generation_id),
                    user_data: sub.user_data.as_ref().map(|d| d.to_vec()),
                    rack: sub.rack_id.as_ref().map(|r| r.to_string()),
                    instance_id: m.group_instance_id.as_ref().map(|i| i.to_string()),
                }));
            }
            let mut all_topics: Vec<String> = members.iter().flat_map(|(_, sub)| sub.topics.clone()).collect();
            all_topics.sort();
            all_topics.dedup();
            let counts = self.partition_counts(&all_topics).await?;
            let racks = self.replica_racks(&all_topics);
            let assigned = if member.protocol.as_deref() == Some("cooperative-sticky") {
                member.sticky.assign(&counts, &racks, &members).map_err(Error::new)?
            } else {
                range::assign(&counts, &racks, &members)
            };
            assigned
                .into_iter()
                .map(|(id, parts)| {
                    // `ConsumerProtocol.serializeAssignment`: topics in order of first appearance.
                    let mut by_topic: Vec<(String, Vec<i32>)> = Vec::new();
                    for (t, p) in parts {
                        match by_topic.iter_mut().find(|(name, _)| *name == t) {
                            Some((_, list)) => list.push(p),
                            None => by_topic.push((t, vec![p])),
                        }
                    }
                    let assignment = ConsumerProtocolAssignment::default().with_assigned_partitions(
                        by_topic
                            .into_iter()
                            .map(|(t, p)| consumer_protocol_assignment::TopicPartition::default().with_topic(topic_name(&t)).with_partitions(p))
                            .collect(),
                    );
                    wire::write_versioned(&assignment, 3).map(|a| SyncGroupRequestAssignment::default().with_member_id(s(&id)).with_assignment(a))
                })
                .collect::<Result<Vec<_>, Error>>()?
        } else {
            Vec::new()
        };
        let request = SyncGroupRequest::default()
            .with_group_id(GroupId(s(&self.group)))
            .with_generation_id(member.generation)
            .with_member_id(s(&member.member_id))
            .with_protocol_type(Some(s("consumer")))
            .with_protocol_name(member.protocol.as_deref().map(s))
            .with_assignments(assignments);
        let response = self.cluster.send(coordinator, request).await?;
        if response.error_code != 0 {
            if matches!(response.error_code, 25 | 22) {
                member.member_id.clear();
            }
            return Err(Error::new(wire::error_message(response.error_code)));
        }
        let assigned: Vec<(String, i32)> = if response.assignment.is_empty() {
            Vec::new()
        } else {
            let (_, assignment) = wire::read_versioned::<ConsumerProtocolAssignment>(response.assignment.clone())?;
            assignment.assigned_partitions.iter().flat_map(|tp| tp.partitions.iter().map(move |p| (tp.topic.0.to_string(), *p))).collect()
        };
        // `ConsumerProtocol.serializeAssignment` groups the partitions by topic in a `HashMap`, and the consumer
        // fetches (and so records) in that order.
        let mut names: Vec<String> = Vec::new();
        for (t, _) in &assigned {
            if !names.contains(t) {
                names.push(t.clone());
            }
        }
        let assigned: Vec<(String, i32)> =
            crate::recorded::java_hashmap_order(&names)
                .into_iter()
                .flat_map(|i| assigned.iter().filter(|(t, _)| *t == names[i]).cloned().collect::<Vec<_>>())
                .collect();
        // `onAssignment` of the chosen assignor.
        if member.protocol.as_deref() == Some("cooperative-sticky") {
            member.sticky_generation = member.generation;
        }
        member.joined_topics = topics.to_vec();
        member.assignment = assigned;
        self.start_positions(member, coordinator).await?;
        Ok(())
    }

    /// Committed offsets (`OffsetFetch`), else the earliest (`ListOffsets`, timestamp -2).
    async fn start_positions(&self, member: &mut Member, coordinator: i32) -> Result<(), Error> {
        let missing: Vec<(String, i32)> = member.assignment.iter().filter(|k| !member.positions.contains_key(*k)).cloned().collect();
        if missing.is_empty() {
            return Ok(());
        }
        let mut by_topic: BTreeMap<String, Vec<i32>> = BTreeMap::new();
        for (t, p) in &missing {
            by_topic.entry(t.clone()).or_default().push(*p);
        }
        // v8+ batches groups (KIP-709): the topics move into the group's entry and the answer is per group. A consumer
        // asks for stable offsets (`RequireStable`, v7+), as kafka-clients 4.4.0's capture shows.
        let group = self.group.clone();
        let response = self
            .cluster
            .send_with(coordinator, |v| {
                if v >= 8 {
                    OffsetFetchRequest::default().with_groups(vec![offset_fetch_request::OffsetFetchRequestGroup::default()
                        .with_group_id(GroupId(s(&group)))
                        .with_member_epoch(-1)
                        .with_topics(Some(
                            by_topic
                                .iter()
                                .map(|(t, p)| offset_fetch_request::OffsetFetchRequestTopics::default().with_name(topic_name(t)).with_partition_indexes(p.clone()))
                                .collect(),
                        ))])
                    .with_require_stable(true)
                } else {
                    let request = OffsetFetchRequest::default().with_group_id(GroupId(s(&group))).with_topics(Some(
                        by_topic
                            .iter()
                            .map(|(t, p)| offset_fetch_request::OffsetFetchRequestTopic::default().with_name(topic_name(t)).with_partition_indexes(p.clone()))
                            .collect(),
                    ));
                    if v >= 7 { request.with_require_stable(true) } else { request }
                }
            })
            .await?;
        let mut committed: Vec<((String, i32), i64, i32)> = Vec::new();
        for t in &response.topics {
            committed.extend(t.partitions.iter().map(|p| ((t.name.0.to_string(), p.partition_index), p.committed_offset, p.committed_leader_epoch)));
        }
        for g in &response.groups {
            for t in &g.topics {
                committed.extend(t.partitions.iter().map(|p| ((t.name.0.to_string(), p.partition_index), p.committed_offset, p.committed_leader_epoch)));
            }
        }
        let mut need_earliest = Vec::new();
        for (key, offset, epoch) in committed {
            if offset >= 0 {
                member.positions.insert(key.clone(), offset);
                member.epochs.insert(key.clone(), epoch.max(-1));
                member.committed.insert(key, offset);
            } else {
                need_earliest.push(key);
            }
        }
        for key in &missing {
            if !member.positions.contains_key(key) && !need_earliest.contains(key) {
                need_earliest.push(key.clone());
            }
        }
        let mut by_leader: HashMap<i32, Vec<(String, i32)>> = HashMap::new();
        for key in need_earliest {
            let leader = self.leader(&key.0, key.1);
            by_leader.entry(leader.unwrap_or(-1)).or_default().push(key);
        }
        for (leader, keys) in by_leader {
            if leader < 0 {
                continue;
            }
            let mut topics: BTreeMap<String, Vec<i32>> = BTreeMap::new();
            for (t, p) in &keys {
                topics.entry(t.clone()).or_default().push(*p);
            }
            let request = ListOffsetsRequest::default().with_replica_id((-1).into()).with_timeout_ms(REQUEST_TIMEOUT_MS).with_topics(
                topics
                    .iter()
                    .map(|(t, ps)| {
                        list_offsets_request::ListOffsetsTopic::default()
                            .with_name(topic_name(t))
                            .with_partitions(
                                ps.iter()
                                    .map(|p| {
                                        list_offsets_request::ListOffsetsPartition::default()
                                            .with_partition_index(*p)
                                            .with_timestamp(-2)
                                            .with_current_leader_epoch(self.leader_epoch(t, *p))
                                    })
                                    .collect(),
                            )
                    })
                    .collect(),
            );
            let response = self.cluster.send(leader, request).await?;
            for t in &response.topics {
                for p in &t.partitions {
                    if p.error_code == 0 {
                        let key = (t.name.0.to_string(), p.partition_index);
                        member.epochs.insert(key.clone(), p.leader_epoch);
                        member.positions.insert(key, p.offset);
                    }
                }
            }
        }
        Ok(())
    }

    fn leader(&self, topic: &str, partition: i32) -> Option<i32> {
        self.cluster.partitions(topic)?.1.iter().find(|m| m.partition == partition).map(|m| m.leader).filter(|l| *l >= 0)
    }

    /// The leader epoch the metadata gave the partition (`Metadata.LeaderAndEpoch`), -1 when it did not say: what
    /// `Fetch` and `ListOffsets` send as `current_leader_epoch`.
    fn leader_epoch(&self, topic: &str, partition: i32) -> i32 {
        self.cluster.partitions(topic).and_then(|(_, ps)| ps.iter().find(|m| m.partition == partition).map(|m| m.leader_epoch)).unwrap_or(-1)
    }

    /// One `Fetch` round per leader, each waiting up to `fetch.max.wait.ms`.
    async fn fetch(&mut self, member: &mut Member) {
        // each leader with the partitions to fetch from it and their offsets
        type Fetches = Vec<(PartitionKey, i64)>;
        let mut by_leader: Vec<(i32, Fetches)> = Vec::new();
        for key in &member.assignment {
            let Some(position) = member.positions.get(key).copied() else { continue };
            match self.leader(&key.0, key.1) {
                Some(leader) => match by_leader.iter_mut().find(|(l, _)| *l == leader) {
                    Some((_, list)) => list.push((key.clone(), position)),
                    None => by_leader.push((leader, vec![(key.clone(), position)])),
                },
                None => {
                    let _ = self.cluster.refresh(std::slice::from_ref(&key.0)).await;
                }
            }
        }
        if by_leader.is_empty() {
            self.pause(Duration::from_millis(FETCH_MAX_WAIT_MS as u64)).await;
            return;
        }
        let mut reset = Vec::new();
        for (leader, partitions) in by_leader {
            let wanted: Vec<(PartitionKey, FetchPosition)> =
                partitions.iter().map(|(key, offset)| (key.clone(), FetchPosition { offset: *offset, leader_epoch: self.leader_epoch(&key.0, key.1) })).collect();
            let session = member.fetch_sessions.entry(leader).or_default().clone();
            let (to_send, forgotten) = session.delta(&wanted);
            let mut topics: Vec<(String, Vec<fetch_request::FetchPartition>)> = Vec::new();
            for ((t, p), position) in &to_send {
                if !topics.iter().any(|(name, _)| name == t) {
                    topics.push((t.clone(), Vec::new()));
                }
                topics.iter_mut().find(|(name, _)| name == t).expect("just added").1.push(
                    fetch_request::FetchPartition::default()
                        .with_partition(*p)
                        .with_fetch_offset(position.offset)
                        .with_partition_max_bytes(1048576)
                        .with_current_leader_epoch(position.leader_epoch)
                        .with_log_start_offset(-1),
                );
            }
            let mut dropped: Vec<(String, Vec<i32>)> = Vec::new();
            for (t, p) in &forgotten {
                match dropped.iter_mut().find(|(name, _)| name == t) {
                    Some((_, list)) => list.push(*p),
                    None => dropped.push((t.clone(), vec![*p])),
                }
            }
            let build = |v: i16| {
                // Sessions came with Fetch v7: older versions send the sessionless -1.
                let (session_id, session_epoch) = if v >= 7 { (session.id, session.epoch) } else { (0, -1) };
                FetchRequest::default()
                    .with_replica_id((-1).into())
                    .with_max_wait_ms(FETCH_MAX_WAIT_MS)
                    .with_min_bytes(1)
                    .with_max_bytes(52428800)
                    .with_isolation_level(0)
                    .with_session_id(session_id)
                    .with_session_epoch(session_epoch)
                    .with_topics(
                        topics
                            .iter()
                            .map(|(t, ps)| {
                                let topic = fetch_request::FetchTopic::default().with_partitions(ps.clone());
                                // v13+ names the topic by its id.
                                if v >= 13 { topic.with_topic_id(self.cluster.topic_id(t)) } else { topic.with_topic(topic_name(t)) }
                            })
                            .collect(),
                    )
                    .with_forgotten_topics_data(
                        dropped
                            .iter()
                            .map(|(t, ps)| {
                                let topic = fetch_request::ForgottenTopic::default().with_partitions(ps.clone());
                                if v >= 13 { topic.with_topic_id(self.cluster.topic_id(t)) } else { topic.with_topic(topic_name(t)) }
                            })
                            .collect(),
                    )
            };
            let fetched = tokio::select! {
                r = self.cluster.send_with(leader, build) => r,
                _ = self.stop.changed() => return,
            };
            let Ok(response) = fetched else {
                // The broker may or may not hold the session; start a new one.
                member.fetch_sessions.insert(leader, FetchSession::default());
                tokio::time::sleep(RETRY).await;
                continue;
            };
            // `FetchSessionHandler.handleResponse`: a session error (FETCH_SESSION_ID_NOT_FOUND, INVALID_FETCH_SESSION_EPOCH)
            // starts over with a full fetch; otherwise the session advances.
            if matches!(response.error_code, 70 | 71) {
                member.fetch_sessions.insert(leader, FetchSession::default());
                continue;
            }
            member.fetch_sessions.insert(leader, session.next(response.session_id, wanted));
            for topic in &response.responses {
                let name = if topic.topic.0.is_empty() { self.cluster.topic_name(topic.topic_id).unwrap_or_default() } else { topic.topic.0.to_string() };
                for partition in &topic.partitions {
                    let key = (name.clone(), partition.partition_index);
                    match partition.error_code {
                        0 => {}
                        1 => {
                            reset.push(key);
                            continue;
                        }
                        _ => {
                            let _ = self.cluster.refresh(std::slice::from_ref(&name)).await;
                            continue;
                        }
                    }
                    let Some(records) = &partition.records else { continue };
                    let mut buf = records.clone();
                    let position = member.positions.get(&key).copied().unwrap_or(0);
                    let mut next = position;
                    // `CompletedFetch.lastEpoch`: the leader epoch of the last batch entered, -1 for a batch without one.
                    let mut epoch = -1;
                    while bytes::Buf::has_remaining(&buf) {
                        let Ok(set) = wire::decode_record_batch(&mut buf) else { break };
                        if let Some(first) = set.records.first() {
                            epoch = first.partition_leader_epoch.max(-1);
                        }
                        for record in set.records {
                            if record.offset < position {
                                continue;
                            }
                            next = next.max(record.offset + 1);
                            if record.control {
                                continue;
                            }
                            let headers = record.headers.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
                            self.recording.record(ConsumerRecord { topic: name.clone(), key: record.key, value: record.value, headers }).await;
                        }
                    }
                    if next > position {
                        member.epochs.insert(key.clone(), epoch);
                    }
                    member.positions.insert(key, next);
                }
            }
        }
        if !reset.is_empty() {
            for key in reset {
                member.positions.remove(&key);
                member.epochs.remove(&key);
            }
            if let Some(coordinator) = member.coordinator {
                let _ = self.start_positions(member, coordinator).await;
            }
        }
    }

    async fn heartbeat(&self, member: &Member) -> Option<Rejoin> {
        let coordinator = member.coordinator?;
        let request = HeartbeatRequest::default()
            .with_group_id(GroupId(s(&self.group)))
            .with_generation_id(member.generation)
            .with_member_id(s(&member.member_id));
        match self.cluster.send(coordinator, request).await {
            Ok(r) => match r.error_code {
                0 => None,
                27 => Some(Rejoin::Now),
                25 | 22 => Some(Rejoin::Reset),
                _ => Some(Rejoin::Now),
            },
            Err(_) => None,
        }
    }

    /// `OffsetCommit` of the positions that moved since the last commit.
    async fn commit(&self, member: &mut Member) {
        let Some(coordinator) = member.coordinator else { return };
        let changed: Vec<((String, i32), i64, i32)> = member.positions
            .iter()
            .filter(|(k, v)| member.committed.get(*k) != Some(*v))
            .map(|(k, v)| (k.clone(), *v, member.epochs.get(k).copied().unwrap_or(-1)))
            .collect();
        if changed.is_empty() {
            return;
        }
        let mut topics: BTreeMap<String, Vec<offset_commit_request::OffsetCommitRequestPartition>> = BTreeMap::new();
        for ((t, p), offset, epoch) in &changed {
            topics.entry(t.clone()).or_default().push(
                offset_commit_request::OffsetCommitRequestPartition::default()
                    .with_partition_index(*p)
                    .with_committed_offset(*offset)
                    .with_committed_leader_epoch(*epoch)
                    .with_committed_metadata(Some(s(""))),
            );
        }
        let request = OffsetCommitRequest::default()
            .with_group_id(GroupId(s(&self.group)))
            .with_generation_id_or_member_epoch(member.generation)
            .with_member_id(s(&member.member_id))
            .with_retention_time_ms(-1)
            .with_topics(
                topics
                    .into_iter()
                    .map(|(t, ps)| offset_commit_request::OffsetCommitRequestTopic::default().with_name(topic_name(&t)).with_partitions(ps))
                    .collect(),
            );
        if let Ok(response) = self.cluster.send(coordinator, request).await {
            for t in &response.topics {
                for p in &t.partitions {
                    if p.error_code == 0 {
                        let key = (t.name.0.to_string(), p.partition_index);
                        if let Some(offset) = member.positions.get(&key) {
                            member.committed.insert(key, *offset);
                        }
                    }
                }
            }
        }
    }
}
