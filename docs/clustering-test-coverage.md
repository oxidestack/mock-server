# Clustering test coverage

Where each upstream test class behind MockServer 8.0.0's clustered state is checked in mock-server: JGroups 5.2.28, Infinispan 14.0.35, Caffeine 3.1.8 and MockServer's own clustered tests. The library tests run as Rust ports in the ported crates' own repositories ([jgroups](https://github.com/oxidestack/jgroups), [infinispan-rs](https://github.com/oxidestack/infinispan-rs), [caffeine-rs](https://github.com/oxidestack/caffeine-rs)); MockServer's own go in `tests/upstream/cluster_state_backend.rs`. None runs unmodified, because every one of them drives JVM classes directly (JChannel, `EmbeddedCacheManager`, `HttpState`). Only the reached surface is ported: the two shipped JGroups stacks plus TCPPING, REPL_SYNC non-transactional caches, topology and state transfer, and POST-only listeners. Transactions, REPL_ASYNC, DIST, persistence, FLUSH and the rest of JGroups stay out.

As of 2026-10-01, main `fe4324e` (then built from jgroups `cf7842b` and infinispan-rs `3cdb313`, in their repositories).

Statuses: **ported** (every method in the reached surface; Java-only methods named), **partial** (some methods ported, the rest named with a reason), **out of reach** (the class tests something MockServer cannot reach, with the reason), **open** (to do). A "ported" row names the file; the Rust fn is named after the upstream method only in `tests/upstream/`, so method-level counts in the crates are the ports' own claims (see "Verification").

| Library | Classes | Ported | Partial | Out of reach | Open | Rust tests in the crate |
|---|---|---|---|---|---|---|
| JGroups 5.2.28 | 55 | 20 | 12 | 21 | 2 | 605 `#[test]` in the tree |
| Infinispan 14.0.35 | 28 | 18 | 5 | 5 | 0 | 312 |
| Caffeine 3.1.8 | 4 | 1 | 2 | 1 | 0 | 31 |
| MockServer clustered | 17 | 9 | 0 | 1 | 7 | 125 in `tests/upstream/cluster_state_backend.rs`, 11 in `src/state_backend/cluster/` |

Class counts are rows of the tables below (a row naming several classes in one family is split, except the UNICAST_* and NAKACK_* families, which are counted per class). Upstream method counts are the pinned sources' (several differ from the first inventory of them).

## JGroups ([jgroups](https://github.com/oxidestack/jgroups))

Files are in the [jgroups](https://github.com/oxidestack/jgroups) repository.

| Class (methods) | Status | Where / reason |
|---|---|---|
| TableTest (59) | partial, 48 ported | `src/util/table.rs`. Out: the 13 `MessageBatch`/`List<LongTuple>` bulk `add` variants, `testForEach`, `testConcurrentAddAndRemove` (one frame at a time here) |
| UtilTest (46) | out of reach | a grab-bag of Java helpers; the reached pieces are tested where they live (`protocols/discovery/resolver.rs`, `wire/bits.rs`, `conf/bind_addr.rs`) |
| MessageBatchTest (44) | partial, 17 ported | `src/wire/batch.rs`. Out: the mutable batch API (only the wire form is reached) |
| MessageTest (38) | partial, 28 ported | `src/wire/message.rs` (`size_matches_writeto_length`). Out: ObjectMessage, `testComputeFragOffsets*` (in `protocols/frag2.rs`), three Java-API methods |
| DigestTest (35) | partial, 25 ported | `src/util/digest.rs`. Out: constructors, copy, immutability of Java's `Digest` |
| ByteArrayDataInputOutputStreamTest (31) | out of reach | a Java stream class; the crate writes into `Vec<u8>` and reads through `WireReader` (`src/wire/stream.rs`) |
| SizeTest (30) | partial | sizes taken from the real jar. Out: headers of protocols in no stack (COMPRESS, RELAY, ENCRYPT, DH, GossipData, FD_SOCK, FD) |
| ViewTest (21) | ported, 23 cases | `src/wire/view.rs`; `testCopy`, `testConstructor` are Java-only |
| BitsTest (20) | partial | `src/wire/bits.rs`, the wire-relevant methods; plain float/double/char/short/int and `ByteBuffer` variants are `to_be_bytes` |
| SeqnoListTest (15) | ported | `src/util/seqno_list.rs` |
| FragTest (14) | partial, 5 ported | `src/protocols/frag2.rs`, `tests/shared_loopback_test.rs`. Out: FRAG/FRAG3/FRAG4 parametrisations, Object/Nio/CompositeMessage methods |
| VersionTest (6) | partial, 2 ported | `src/wire/version.rs`; manifest/jar tests out |
| BitmapTest (2) | ported | `src/protocols/fd_all3.rs` |
| FlowControlUnitTest (8) | out of reach | needs `RpcDispatcher`, `UFC_NB`/`MFC_NB`, live `insertProtocol`, JVM `Thread.State`; behaviour covered by 26 unit and channel tests |
| MFC_Test (2), UFC_Test (2) | out of reach (one row each) | same reason and coverage |
| CreditMapTest (10) | ported | `src/util/credit_map.rs` |
| ViewHandlerTest (23) | ported | `src/protocols/gms/view_handler.rs` |
| MembershipTest (16) | ported, 15 | `src/util/membership.rs`; `testClone` is Rust `Clone` |
| MergerTest (7) | ported | `src/protocols/gms/merger.rs` |
| GMS_MergeTest (14 with the `WithFlush` twins) | partial, 5 ported | `tests/failure_detection_test.rs`: simple merge, concurrent merge of two partitions and of four pairs, both asymmetric tests (with DISCARD, message counts and STABLE gc). Out: the six `WithFlush` twins (no FLUSH). Open: `testMergeRequestTimeout` (no `MergeCanceller` in the tree) |
| VERIFY_SUSPECT_Test (4) | ported, adapted | `tests/failure_detection_test.rs` (`testMultipleSuspectEvents`), `src/protocols/verify_suspect2.rs` (the other three, as VERIFY_SUSPECT2 tests with batching; the old VERIFY_SUSPECT is in no stack) |
| dns/DNS_PINGTest (5) | ported | `src/protocols/discovery/dns_ping.rs`, `tests/jgroups_kubernetes_test.rs` |
| DiscoveryTest (2) | out of reach | the leak tests need a persistent per-request-id map |
| UNICAST_ConnectionTests, UNICAST_ContentionTest, UNICAST_DropFirstAndLastTest, UNICAST_DroppedAckTest, UNICAST_MessagesToSelfTest, UNICAST_RetransmitTest (6 classes) | out of reach (one row each) | they drive `UNICAST`/`UNICAST2`, SHUFFLE and JVM threads; `protocols/unicast3.rs` has its own tests |
| UNICAST_OOB_Test (6) | partial, 2 ported | `tests/oob_test.rs` (testRegularMessages, testOutOfBandMessages). Out: the 4 `_testSecondMessageReceivedFirst` variants, which need the REVERSE and MAKE_BATCH test protocols and `removeReceiveConnection`/`removeSendConnection` |
| UNICAST3_Test (1) | ported | `src/protocols/unicast3.rs` |
| UnicastUnitTest (9) | partial, 6 ported | `src/protocols/unicast3.rs`; the three `*Batching` methods need `MAKE_BATCH` |
| NAKACK_Test, NAKACK_Delivery_Test, NAKACK_REBROADCAST_Test, NAKACK_RetransmitTest, NAKACK_SET_DIGEST_Test, NAKACK_StressTest (6 classes) | out of reach (one row each) | they exercise `NAKACK`/`NAKACK3`, in no MockServer stack; `protocols/nakack2.rs` has its own tests |
| NAKACK2_RetransmissionTest (1) | ported | `src/protocols/nakack2.rs` |
| NAKACK2_NoRetransmissionTest (2) | out of reach | `testJoinerGettingCorrectDigest` needs `become_server_queue` and a view-delaying protocol (the digest start is covered by `set_digest` and `joiner_receives_the_coordinators_next_multicast_without_waiting_for_history`); `testThreadPoolDiscardingMessages` is a JVM `RejectedExecutionHandler` |
| STABLE_Test (1) | ported | `tests/shared_loopback_test.rs` |
| ServerUnitTest (10), ConcurrentConnectTest (1), TcpServerTest (1) | ported (one row each) | `tests/server_unit_test.rs`, `concurrent_connect_test.rs`, `tcp_server_test.rs` |
| ChannelTest (10) | partial, 9 ported | `tests/channel_test.rs` (connected/closed state, `close()`, ordering, no view after disconnect). Out: `testNullMessage` (a Java null); reconnect of the same channel after `disconnect()` is unsupported (a `JChannel` is single-use) |
| OOBTest (8) | ported | `tests/oob_test.rs` (OOB delivery in NAKACK2/UNICAST3, TP's `MaxOneThreadPerSender` delivery policy, NAKACK2's `LastSeqnoResender`; testRandomRegularAndOOBMulticasts runs its 5 invocations in one test) |
| ConcurrentStartupTest (3) | partial, 1 ported | `tests/shared_loopback_test.rs` as a 3/5-way race. Out: the literal 10-node scenario (needs a receiver-callback API), UDP/LOCAL_PING/PING variants |
| JoinTest (8) | ported | `tests/shared_loopback_test.rs` |
| OverlappingMergeTest (6) | ported | `tests/failure_detection_test.rs`; `testRegularMessageSending` is in `tests/reliability_test.rs` |
| OverlappingUnicastMergeTest (5) | ported | `tests/overlapping_unicast_merge_test.rs` |
| ReconciliationTest (4) | out of reach | needs FLUSH (8 references; "various tests for the FLUSH protocol"), in no MockServer stack |
| MergeTest4 (10) | ported | `tests/merge_test4.rs` (MERGE3 `send_info`/`check_inconsistencies`/info-sender hooks, DISCARD) |
| OrderingTest (2) | open | needs DISCARD, FLUSH and SHUFFLE; DISCARD exists, SHUFFLE is not in the tree |
| BaseLeaveTest (13) | ported | `tests/leave_test.rs` (the six `MyViewHandler` tests through `Gms::install_view_handler_test_hook`) |

Not covered by an upstream class, and not ported in the merge: FLUSH, `SUSPEND_STABLE`, `INSTALL_MERGE_VIEW_OK`; `GET_DIGEST_REQ` goes unicast per member instead of a NAKACK2 multicast. A mixed merge with a JVM peer is not exercised (see below).

## Infinispan ([infinispan-rs](https://github.com/oxidestack/infinispan-rs))

Files are under `tests/` of the [infinispan-rs](https://github.com/oxidestack/infinispan-rs) repository.

| Class (methods) | Status | Where / reason |
|---|---|---|
| ReplicatedAPITest (6) | ported | `replicated_api_test.rs`; `putAll` is not a MockServer command, tx methods out |
| SyncReplTest (4) | partial, 3 ported | `sync_repl_test.rs`. Out: `testMixingSyncAndAsyncOnSameTransport` (REPL_ASYNC) |
| SyncLockingTest (5), SyncCacheListenerTest (5), ReplicationExceptionTest (5) | ported (one row each) | `sync_locking_test.rs`, `sync_cache_listener_test.rs`, `replication_exception_test.rs`; tx tests out |
| ReplaceWithValueChangedTest (4) | partial, 2 ported | the other two assert what a suspended transaction's commit does |
| ConditionalOperationsConcurrentTest (3) | ported | `conditional_operations_concurrent_test.rs` |
| ReplCommandRetryTest (5) | partial, 1 ported | `repl_command_retry_test.rs`; the four tx variants (lock control, prepare, commit) out |
| ReplCommandForwardingTest (1) | out of reach | REPL_ASYNC only |
| StateTransferFunctionalTest (9) | partial, 7 ported | `state_transfer_functional_test.rs`; two tx tests out |
| OperationsDuringStateTransferTest (4), StateConsumerTest (2), StateProviderTest (2) | ported (one row each) | the files of the same names |
| RemoteGetDuringStateTransferTest (25) | out of reach | DIST `numOwners=1` remote-get retry matrix; REPL members read locally |
| ClusterTopologyManagerTest (7) | partial, 6 ported | `topology_cluster.rs`; `testLeaveDuringGetTransactions` needs tx state transfer |
| ClusterTopologyManagerImplTest (2), ClusterCacheStatusTest (1), TopologyUnorderedJoinTest (1), ThreeNodesReplicatedSplitAndMergeTest (3), ConcurrentStartWithReplTest (4) | ported (one row each) | `cluster_topology_manager_impl.rs`, `cluster_cache_status.rs`, `topology_cluster.rs` |
| ClusterListenerReplTest (2) + AbstractClusterListenerTest (38) | ported | `cluster_listener_repl_test.rs`, `cluster_listener_retry_test.rs`, `cluster_listener_expiration_test.rs`; tx and include-current-state variants out |
| CacheNotifierImplTest (13), ListenerRegistrationTest (14) | ported (one row each) | `cache_notifier_impl_test.rs`, `listener_registration_test.rs` |
| PrimitivesTest (2) | ported, adapted | `primitives_test.rs`: `testReadAndWrite` as `read_and_write_every_primitive_type`; `testLargeArray` is an `OutOfMemoryError` on `write(bytes, 0, Integer.MAX_VALUE)`, replaced by the read-side length check (`an_array_length_the_buffer_cannot_hold_is_an_error_not_an_allocation`) |
| VersionAwareMarshallerTest (29) | out of reach | tests the general-purpose `GlobalMarshaller`; MockServer's values travel as `ID_UNKNOWN` (JDK serialization, `src/marshall/wrapped_message.rs`, `java_serial.rs`, vectors from the real classes) |
| MarshallExternalizersTest (2) | out of reach | same reason; commands have codecs with real-Java vectors (`write_commands_wire.rs`, `state_transfer_wire.rs`, `topology_wire.rs`) |
| ReplicatedConsistentHashFactoryTest (1) | ported by vector | `ch_replicated_factory_test.rs`, `ch_replicated.rs`, `ch_sync_consistent_hash.rs`, `ch_murmur.rs` (bytes from the unmodified Java classes) |
| the rest of `distribution/ch/` (AffinityPartitionerTest, CapacityFactorsFunctionalTest, `*PersistenceTest`, TopologyAwareSyncConsistentHashFactoryKeyDistributionTest) | out of reach (one row) | DIST-only, persistence, topology-aware |

## Caffeine ([caffeine-rs](https://github.com/oxidestack/caffeine-rs))

Eviction is per node and nothing about the victim crosses the wire, so the policy is checked by properties, not by byte-matching Caffeine's victims (`docs/divergences.md`, "Which entry Caffeine evicts").

| Class | Status | Where / reason |
|---|---|---|
| FrequencySketchTest | ported | `src/frequency_sketch.rs` tests, plus tables byte-exact against the real 3.1.8 jar (`tests/vectors`). Out: `ensureCapacity_maximum` (upstream's own isolated test, about 2 GB) |
| CacheTest (invalidate) | partial | `tests/removal.rs`: `invalidate` absent/present, `invalidateAll` empty/partial/full. Out: weighted, expiry, stats, async |
| EvictionTest | partial | `tests/removal.rs`: eviction with `maximum` 0/1/full, SIZE notifications exclusive, `evictionListenerFails`'s `setMaximum(0)`. Out: the listener-throws cases (a Rust panic is not a swallowed exception) |
| BoundedLocalCache policy (admission window, SLRU, hill climbing) | out of reach as a test class | the policy is ported at unit weight and run synchronously; checked by property tests in `src/eviction.rs` (`size_bound_under_sustained_insertion`, `frequent_entries_survive_preferentially`, `climb_is_gated_by_sample_size`, `climb_first_adjustment_shrinks_the_window`, `size_bound_holds_while_climbing`). No MockServer-reachable cache uses a weigher |

## MockServer clustered tests

`mockserver-state-infinispan` and the core state tests. Ports are in `tests/upstream/cluster_state_backend.rs` unless noted.

| Class (@Test) | Status | Where / reason |
|---|---|---|
| KeyValueStoreContract (22) | ported | run against node A's `scenarioStates` store with node B a member (upstream runs it on a LOCAL cache) |
| ClusteredTwoNodeTest (26) | ported | 12 backend-level cases; the data-plane cases through two real servers (matchability, clear and reset propagation, shared `Times`); 6 `ScenarioManager` cases and the seventh (served exactly once across two nodes) |
| DeserializationAllowListTest (18) | ported | against `ClassAllowList` and the Java serialization codec |
| InfinispanBlobStoreTest (14) | ported | on the clustered `blobs` cache; the null-metadata case passes none (Rust has no null map) |
| ClusteredTwoNodeChaosTest (10) | ported | `chaos::HostRegistry` and the gRPC registry over `chaos-service`, `chaos-tcp`, `chaos-grpc` |
| InfinispanStateBackendTest (10) | ported | CLUSTERED mode; the LOCAL-only `clusterInfo` case became the two-member case |
| JGroupsKubernetesStackTest (6) | ported | against the embedded stack and the crate's XML parser |
| ClusteredTwoNodeCrossProtocolBusTest (4) | ported | `scenario::CrossProtocolBus` |
| InfinispanKeyValueStoreConcurrencyTest (1) | ported | on the clustered store |
| InfinispanStateBackendRegistrarTest (2) | out of reach | `StateBackendFactory`'s reflective classpath discovery; this binary has no plugin registry (`src/state_backend/infinispan.rs`) |
| ClusteredExpectationPersistenceReloadTest (2) | open | late-joiner restore from `blobs` through `src/persistence.rs`; today a late joiner's matchers stay empty until the first change anywhere (`a_late_joiner_is_not_populated_by_state_transfer_events`) |
| ClusterFanInTest (8), HttpClusterPeerAccessorTest (9), HttpStateClusterFanInTest (6), HttpStateClusteredListenerWiringTest (2) | ported | `tests/upstream/cluster_fanin.rs` against `src/cluster_fanin.rs`; the peer accessor carries JSON items, the `HttpState` ones run on a real server with the coordinator replaced (`Server::set_cluster_fan_in`) and a spy backend (`Server::start_with_state_backend`). Adapted: a non-clustered backend registers no listener here (the `Store` is authoritative) where upstream registers one. The oracle side is the `cluster_verify_fan_in*` scenarios, with a second node as the peer (`"peer": true`) |
| RequestMatchersStateBackendTest (20), RequestMatchersReconcileParityTest (7) | ported | `tests/upstream/request_matchers_backend.rs` through a real server, both `clustered` rows; backend-content assertions run on the clustered row, because a non-clustered server never writes its backend. `batchUpdateKeepsBackendInSync` and `responseInProgressSurvivesUpdate` are unit tests in `src/store.rs`. `maxExpectations` eviction of a non-clustered store landed with it (`max_expectations_eviction` scenario) |

The 13-class `state` and `state/contract` SPI tests, `ExpectationStoreFactoryTest`, `BlobStoreRoutedPersistenceTest` and `ExpectationBlobStoreRestoreTest` are not tracked in this table. Also open and not test classes: the saved-profile and load-scenario registries, the DNS and binary match scans on the clustered path, and timed scenario transitions surviving `reset`; the `ISPN000093` or `ISPN000094` line for a `MergeView`.

## Container and conformance cases

| Case | Status |
|---|---|
| `helm_clustered_convergence`, `helm_jgroups_dns_ping` | passing unmodified on our image, 2 pods each |
| Mixed cluster with `mockserver/mockserver:clustered-8.0.0`, both join orders (the conformance gate for clustering) | open. It has no result and never ran. Partial live interop is checked: REPL_SYNC non-tx put/get/remove/putIfAbsent/clear and state transfer, both join orders |

## Verification

Each file cited above exists, and every Rust fn named here was found by `rg "fn <name>"`: `test_multiple_caches_on_shared_transport`, `clustered_listener_never_registers_the_evicted_handler`, `joiner_receives_the_coordinators_next_multicast_without_waiting_for_history`, `size_matches_writeto_length`, `a_late_joiner_is_not_populated_by_state_transfer_events`, `encodings_are_byte_identical_to_the_recorded_java_streams`, `scenario_step_should_be_served_exactly_once_across_two_nodes`, `scenario_states_belong_to_one_server`, `removed_keys_no_longer_take_capacity` and the caffeine-rs property tests, as are the APIs it names (`reject_unsupported`, `install_view_handler_test_hook`, `JChannel::discard`, `merge_view_subgroups`, `clear_view`, `check_inconsistencies`).

Per-method counts ("ported 25") cannot be checked from the tree. The upstream sources are not checked out (the crates' `upstream/` submodules are empty in their checkouts), and most ports are not named after the upstream method; one Rust test often covers several (`digest.rs` holds 15 `#[test]` against 25 methods claimed, `message.rs` 11 against 28, `batch.rs` 9 against 17). Those counts rest on a name scan corrected by hand.

## Where the counts are soft

- Test totals: jgroups-rs counts 605 `#[test]` attributes in the tree (some may be filtered or ignored; not run here), infinispan-rs 312. The tree holds 125 `#[test]` in `cluster_state_backend.rs`.
- ClusteredTwoNodeTest: 26 `@Test` upstream, 33 in the port's own header (12 backend + 14 through `RequestMatchers` + the 6 scenario cases and the seventh). The class is ported; the count is not settled.
- OrderingTest (2) is marked open, since SHUFFLE is still missing.
- A mixed cluster with a JVM peer has never run, so "real divergence versus bug" for the clustering rows rests on the partial interop alone.
