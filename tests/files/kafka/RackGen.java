import java.nio.ByteBuffer;
import java.util.*;
import org.apache.kafka.clients.consumer.ConsumerPartitionAssignor.Subscription;
import org.apache.kafka.clients.consumer.CooperativeStickyAssignor;
import org.apache.kafka.clients.consumer.RangeAssignor;
import org.apache.kafka.common.Node;
import org.apache.kafka.common.PartitionInfo;
import org.apache.kafka.common.TopicPartition;

/**
 * Differential vectors for rack-aware RangeAssignor and CooperativeStickyAssignor (kafka-clients 4.3.1): brokers on
 * random racks (some without), random replica placement, members with and without client.rack (some on racks no
 * broker has), static members for range, and for cooperative-sticky rounds of rebalances owning what the last round
 * assigned. Replayed by src/asyncapi/kafka/rack_tests.rs. Regenerate with kafka-clients-4.3.1.jar and slf4j-api on
 * the class path:
 * javac -cp kafka-clients-4.3.1.jar:slf4j-api.jar RackGen.java
 * java -cp kafka-clients-4.3.1.jar:slf4j-api.jar:. RackGen 300 664 > rack_aware_vectors.json
 */
public class RackGen {
    static String q(String s) { return s == null ? "null" : "\"" + s + "\""; }

    static String tps(List<TopicPartition> l) {
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < l.size(); i++) {
            if (i > 0) b.append(",");
            b.append("[").append(q(l.get(i).topic())).append(",").append(l.get(i).partition()).append("]");
        }
        return b.append("]").toString();
    }

    static String strings(Collection<String> l) {
        StringBuilder b = new StringBuilder("[");
        for (String s : l) b.append(b.length() > 1 ? "," : "").append(q(s));
        return b.append("]").toString();
    }

    public static void main(String[] args) {
        int cases = Integer.parseInt(args[0]);
        Random r = new Random(Long.parseLong(args[1]));
        String[] topicNames = {"orders", "t0", "payments", "topic-3", "a", "zz-events"};
        String[] rackNames = {"a", "b", "c", "d"};
        String[] prefixes = {"consumer-g-1-", "console-consumer-", "consumer-mockserver-2-"};
        int[] counts = {1, 2, 3, 4, 6, 7};
        StringBuilder out = new StringBuilder("[\n");
        for (int c = 0; c < cases; c++) {
            boolean range = c % 2 == 0;
            int nRacks = 1 + r.nextInt(4);
            int nBrokers = 1 + r.nextInt(6);
            Node[] nodes = new Node[nBrokers];
            for (int i = 0; i < nBrokers; i++) {
                String rack = r.nextInt(10) == 0 ? null : rackNames[r.nextInt(nRacks)];
                nodes[i] = new Node(i, "", 9092, rack);
            }
            int rf = 1 + r.nextInt(Math.min(3, nBrokers));
            int nTopics = 1 + r.nextInt(4);
            List<String> topics = new ArrayList<>();
            Map<String, List<PartitionInfo>> infos = new TreeMap<>();
            for (int i = 0; i < nTopics; i++) {
                String topic = topicNames[(i + c) % topicNames.length];
                topics.add(topic);
                infos.put(topic, partitionInfos(topic, counts[r.nextInt(counts.length)], nodes, rf, r));
            }
            boolean sameTopics = r.nextBoolean();
            List<String> members = new ArrayList<>();
            Map<String, List<String>> memberTopics = new HashMap<>();
            Map<String, String> memberRack = new HashMap<>();
            Map<String, String> memberInstance = new HashMap<>();
            Map<String, List<TopicPartition>> lastAssignment = new HashMap<>();
            Map<String, Integer> lastGeneration = new HashMap<>();
            CooperativeStickyAssignor sticky = new CooperativeStickyAssignor();
            RangeAssignor rangeAssignor = new RangeAssignor();
            int rounds = range ? 1 : 2 + r.nextInt(3);
            out.append(c == 0 ? "" : ",\n").append("{\"assignor\":").append(q(range ? "range" : "cooperative-sticky")).append(",\"rounds\":[");
            for (int round = 0; round < rounds; round++) {
                int joins = round == 0 ? 1 + r.nextInt(5) : r.nextInt(3);
                for (int j = 0; j < joins; j++) {
                    String id = prefixes[r.nextInt(prefixes.length)] + new UUID(r.nextLong(), r.nextLong());
                    members.add(id);
                    List<String> ts = new ArrayList<>();
                    if (sameTopics) ts.addAll(topics);
                    else for (String t : topics) if (r.nextBoolean()) ts.add(t);
                    if (ts.isEmpty()) ts.add(topics.get(r.nextInt(topics.size())));
                    memberTopics.put(id, ts);
                    int k = r.nextInt(10);
                    memberRack.put(id, k < 3 ? null : k == 3 ? "" : k == 4 ? "z" : rackNames[r.nextInt(nRacks)]);
                    if (range && r.nextInt(4) == 0) memberInstance.put(id, "instance-" + r.nextInt(100));
                }
                if (round > 0 && members.size() > 1 && r.nextInt(3) == 0) members.remove(r.nextInt(members.size()));
                List<String> joinOrder = new ArrayList<>(members);
                Collections.shuffle(joinOrder, r);
                Map<String, Subscription> subscriptions = new HashMap<>();
                StringBuilder ms = new StringBuilder("[");
                for (String id : joinOrder) {
                    int generation = lastGeneration.getOrDefault(id, -1);
                    List<TopicPartition> owned = new ArrayList<>(lastAssignment.getOrDefault(id, List.of()));
                    owned.sort(Comparator.comparing(TopicPartition::topic).thenComparing(TopicPartition::partition));
                    String rack = memberRack.get(id);
                    ByteBuffer userData = range ? null : ByteBuffer.allocate(4).putInt(0, generation);
                    Subscription s = new Subscription(memberTopics.get(id), userData, owned, generation, Optional.ofNullable(rack));
                    s.setGroupInstanceId(Optional.ofNullable(memberInstance.get(id)));
                    subscriptions.put(id, s);
                    if (ms.length() > 1) ms.append(",");
                    ms.append("{\"id\":").append(q(id)).append(",\"topics\":").append(strings(memberTopics.get(id)))
                        .append(",\"owned\":").append(tps(owned)).append(",\"generation\":").append(generation)
                        .append(",\"rack\":").append(q(rack)).append(",\"instance\":").append(q(memberInstance.get(id))).append("}");
                }
                ms.append("]");
                // AbstractPartitionAssignor.assign(Cluster, …): the subscribed topics, in a HashSet's order, into a HashMap.
                Set<String> subscribed = new HashSet<>();
                for (Subscription s : subscriptions.values()) subscribed.addAll(s.topics());
                Map<String, List<PartitionInfo>> partitionsPerTopic = new HashMap<>();
                for (String t : subscribed) partitionsPerTopic.put(t, infos.get(t));
                StringBuilder ps = new StringBuilder("{");
                for (Map.Entry<String, List<PartitionInfo>> e : infos.entrySet()) {
                    ps.append(ps.length() > 1 ? "," : "").append(q(e.getKey())).append(":[");
                    for (int i = 0; i < e.getValue().size(); i++) {
                        List<String> racks = new ArrayList<>();
                        for (Node n : e.getValue().get(i).replicas()) if (n.rack() != null) racks.add(n.rack());
                        ps.append(i > 0 ? "," : "").append(strings(racks));
                    }
                    ps.append("]");
                }
                ps.append("}");
                String result;
                try {
                    Map<String, List<TopicPartition>> a = range ? rangeAssignor.assignPartitions(partitionsPerTopic, subscriptions)
                        : sticky.assignPartitions(partitionsPerTopic, subscriptions);
                    StringBuilder rs = new StringBuilder("{");
                    for (Map.Entry<String, List<TopicPartition>> e : a.entrySet()) {
                        rs.append(rs.length() > 1 ? "," : "").append(q(e.getKey())).append(":").append(tps(e.getValue()));
                    }
                    result = rs.append("}").toString();
                    for (String id : members) {
                        lastAssignment.put(id, a.getOrDefault(id, List.of()));
                        lastGeneration.put(id, round + 1);
                    }
                } catch (Exception e) {
                    result = "{\"error\":" + q(e.getClass().getSimpleName()) + "}";
                }
                out.append(round == 0 ? "" : ",").append("\n {\"partitions\":").append(ps).append(",\"members\":").append(ms)
                    .append(",\"result\":").append(result).append("}");
            }
            out.append("]}");
        }
        System.out.println(out.append("\n]"));
    }

    static List<PartitionInfo> partitionInfos(String topic, int n, Node[] nodes, int rf, Random r) {
        List<PartitionInfo> list = new ArrayList<>();
        for (int p = 0; p < n; p++) {
            List<Node> shuffled = new ArrayList<>(Arrays.asList(nodes));
            Collections.shuffle(shuffled, r);
            Node[] replicas = shuffled.subList(0, rf).toArray(new Node[0]);
            list.add(new PartitionInfo(topic, p, replicas[0], replicas, replicas));
        }
        return list;
    }
}
