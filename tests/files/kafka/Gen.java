import java.nio.ByteBuffer;
import java.util.*;
import org.apache.kafka.clients.consumer.ConsumerPartitionAssignor.Subscription;
import org.apache.kafka.clients.consumer.CooperativeStickyAssignor;
import org.apache.kafka.common.TopicPartition;

/**
 * Differential vectors for CooperativeStickyAssignor (kafka-clients 4.3.1): rounds of rebalances per case, replayed by
 * src/asyncapi/kafka/sticky.rs. Regenerate with kafka-clients-4.3.1.jar and slf4j-api on the class path:
 * javac -cp kafka-clients-4.3.1.jar:slf4j-api.jar Gen.java
 * java -cp kafka-clients-4.3.1.jar:slf4j-api.jar:. Gen 120 409 > cooperative_sticky_vectors.json
 */
public class Gen {
    static String q(String s) { return "\"" + s + "\""; }

    static String tps(List<TopicPartition> l) {
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < l.size(); i++) {
            if (i > 0) b.append(",");
            b.append("[").append(q(l.get(i).topic())).append(",").append(l.get(i).partition()).append("]");
        }
        return b.append("]").toString();
    }

    public static void main(String[] args) {
        int cases = Integer.parseInt(args[0]);
        Random r = new Random(Long.parseLong(args[1]));
        String[] topicNames = {"orders", "t0", "payments", "topic-3", "a", "zz-events"};
        String[] prefixes = {"consumer-g-1-", "console-consumer-", "consumer-mockserver-2-", "rdkafka-"};
        StringBuilder out = new StringBuilder("[\n");
        for (int c = 0; c < cases; c++) {
            CooperativeStickyAssignor assignor = new CooperativeStickyAssignor();
            int nTopics = 1 + r.nextInt(4);
            Map<String, Integer> partitions = new TreeMap<>();
            List<String> topics = new ArrayList<>();
            for (int i = 0; i < nTopics; i++) {
                topics.add(topicNames[(i + c) % topicNames.length]);
                partitions.put(topics.get(i), 1 + r.nextInt(8));
            }
            boolean sameTopics = r.nextBoolean();
            List<String> members = new ArrayList<>();
            Map<String, List<String>> memberTopics = new HashMap<>();
            Map<String, Boolean> eager = new HashMap<>();
            Map<String, List<TopicPartition>> lastAssignment = new HashMap<>();
            Map<String, Integer> lastGeneration = new HashMap<>();
            Map<String, List<TopicPartition>> olderAssignment = new HashMap<>();
            int rounds = 2 + r.nextInt(4);
            out.append(c == 0 ? "" : ",\n").append("[");
            for (int round = 0; round < rounds; round++) {
                // membership changes
                int joins = round == 0 ? 1 + r.nextInt(4) : r.nextInt(3);
                for (int j = 0; j < joins; j++) {
                    String id = prefixes[r.nextInt(prefixes.length)] + new UUID(r.nextLong(), r.nextLong());
                    members.add(id);
                    List<String> ts = new ArrayList<>();
                    if (sameTopics) ts.addAll(topics);
                    else for (String t : topics) if (r.nextBoolean()) ts.add(t);
                    if (ts.isEmpty()) ts.add(topics.get(r.nextInt(topics.size())));
                    memberTopics.put(id, ts);
                    eager.put(id, r.nextInt(3) == 0);
                }
                if (round > 0 && members.size() > 1 && r.nextInt(3) == 0) members.remove(r.nextInt(members.size()));
                if (round > 0 && r.nextInt(5) == 0) partitions.put(topics.get(0), partitions.get(topics.get(0)) + 1);
                List<String> joinOrder = new ArrayList<>(members);
                Collections.shuffle(joinOrder, r);
                Map<String, Subscription> subscriptions = new HashMap<>();
                StringBuilder ms = new StringBuilder("[");
                for (String id : joinOrder) {
                    int generation = lastGeneration.getOrDefault(id, -1);
                    List<TopicPartition> owned = eager.get(id) ? new ArrayList<>() : new ArrayList<>(lastAssignment.getOrDefault(id, List.of()));
                    if (!eager.get(id) && olderAssignment.containsKey(id) && r.nextInt(6) == 0) {
                        owned = new ArrayList<>(olderAssignment.get(id));
                        generation = Math.max(-1, generation - 1);
                    }
                    owned.sort(Comparator.comparing(TopicPartition::topic).thenComparing(TopicPartition::partition));
                    boolean withField = r.nextInt(5) != 0;
                    ByteBuffer userData = ByteBuffer.allocate(4).putInt(0, generation);
                    Subscription s = new Subscription(memberTopics.get(id), userData, owned, withField ? generation : -1, Optional.empty());
                    subscriptions.put(id, s);
                    if (ms.length() > 1) ms.append(",");
                    ms.append("{\"id\":").append(q(id)).append(",\"topics\":[");
                    List<String> ts = memberTopics.get(id);
                    for (int i = 0; i < ts.size(); i++) ms.append(i > 0 ? "," : "").append(q(ts.get(i)));
                    ms.append("],\"owned\":").append(tps(owned)).append(",\"generation\":").append(withField ? generation : -1)
                        .append(",\"userData\":").append(generation).append("}");
                }
                ms.append("]");
                StringBuilder ps = new StringBuilder("{");
                for (Map.Entry<String, Integer> e : partitions.entrySet()) ps.append(ps.length() > 1 ? "," : "").append(q(e.getKey())).append(":").append(e.getValue());
                ps.append("}");
                String result;
                try {
                    // AbstractPartitionAssignor.assign(Cluster, …): only the topics some member subscribes to.
                    Map<String, Integer> subscribed = new HashMap<>();
                    for (Subscription s : subscriptions.values()) for (String t : s.topics()) subscribed.put(t, partitions.get(t));
                    Map<String, List<TopicPartition>> a = assignor.assign(subscribed, subscriptions);
                    StringBuilder rs = new StringBuilder("{");
                    for (Map.Entry<String, List<TopicPartition>> e : a.entrySet()) {
                        rs.append(rs.length() > 1 ? "," : "").append(q(e.getKey())).append(":").append(tps(e.getValue()));
                    }
                    result = rs.append("}").toString();
                    int generation = round + 1;
                    for (String id : members) {
                        if (lastAssignment.containsKey(id)) olderAssignment.put(id, lastAssignment.get(id));
                        lastAssignment.put(id, a.getOrDefault(id, List.of()));
                        lastGeneration.put(id, generation);
                    }
                } catch (Exception e) {
                    result = "{\"error\":" + q(e.getClass().getSimpleName()) + "}";
                }
                out.append(round == 0 ? "" : ",").append("\n {\"partitions\":").append(ps).append(",\"members\":").append(ms)
                    .append(",\"result\":").append(result).append("}");
            }
            out.append("]");
        }
        System.out.println(out.append("\n]"));
    }
}
