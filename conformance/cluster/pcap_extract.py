#!/usr/bin/env python3
"""Wire assertions on tap.py pcaps: the Cache.compute lambda both nodes put on the JGroups wire.

Reassembles the TCP byte stream of every directed flow, finds each `SerializedLambda` of MockServer's
`InfinispanKeyValueStore.put` (the window from the lambda tag byte (0x08) to the end of instantiatedMethodType) and checks:
  * the Java node sent one and the Rust node sent one (direction by source address), so a Java-originated compute was
    received by our node and a Rust-originated compute was replayed by the Java backup;
  * every window equals the golden descriptor in tests/files/cluster/write_commands.hex (the `compute:store-put-new`
    vector, a copy of infinispan-rs' tests/vectors/write_commands.hex), byte for byte.
Usage: pcap_extract.py [--vectors <write_commands.hex>] [--dump <dir>] [--gms] <file.pcap>...
With --dump, each distinct window and each directed stream's first compute frame are written as hex files (golden
candidates). With --gms, the GMS messages each side sent are counted by kind (`gms <who> <KIND> <n>` lines): a GMS
header on the wire is GMS' protocol id (12), the GmsHeader magic id (55), then the type byte, the same five bytes
whatever message carries it; MERGE3's (38, MergeHeader 75) are counted the same way. Every frame carrying a GMS VIEW or
GET_DIGEST_REQ is also classified (`gmscast <who> <KIND> msg_mcast=<n> msg_ucast=<n> xmit_mcast=<n> xmit_ucast=<n>
unicast3=<n> bare=<n>` lines): `msg_*` frames carry a NAKACK2 MSG header (NAKACK2 41/NakAckHeader2 78,
type 1), `xmit_*` a NAKACK2 XMIT_RSP header (type 3: a retransmission, NAKACK2.sendXmitRsp), each split by TP's
MULTICAST flag (2); `unicast3` frames carry a UNICAST3 header (48/UnicastHeader3 82), `bare` ones no NAKACK2 header. Exit 1 when an assertion fails."""
import argparse
import os
import struct
import sys

START = b"org/mockserver/state/infinispan/InfinispanKeyValueStore"
INST = b"(Ljava/lang/String;Lorg/mockserver/state/infinispan/VersionedWrapper;)Lorg/mockserver/state/infinispan/VersionedWrapper;"
LAMBDA = b"lambda$put$"
FRAMES_PER_STREAM = 6  # frames kept per sender in --dump
GMS_HEADER = b"\x00\x0c\x00\x37"  # PROT_ID_GMS 12, MAGIC GmsHeader 55
GMS_KINDS = {1: "JOIN_REQ", 2: "JOIN_RSP", 3: "LEAVE_REQ", 4: "LEAVE_RSP", 5: "VIEW", 6: "MERGE_REQ", 7: "MERGE_RSP",
             8: "INSTALL_MERGE_VIEW", 9: "CANCEL_MERGE", 10: "VIEW_ACK", 11: "JOIN_REQ_WITH_STATE_TRANSFER",
             12: "INSTALL_MERGE_VIEW_OK", 13: "GET_DIGEST_REQ", 14: "GET_DIGEST_RSP", 15: "INSTALL_DIGEST",
             16: "GET_CURRENT_VIEW"}
MERGE3_HEADER = b"\x00\x26\x00\x4b"  # PROT_ID_MERGE3 38, MAGIC MergeHeader 75
MERGE3_KINDS = {0: "MERGE3_INFO", 1: "MERGE3_VIEW_REQ", 2: "MERGE3_VIEW_RSP"}
NAKACK2_HEADER = b"\x00\x29\x00\x4e"  # PROT_ID_NAKACK2 41, MAGIC NakAckHeader2 78
UNICAST3_HEADER = b"\x00\x30\x00\x52"  # PROT_ID_UNICAST3 48, MAGIC UnicastHeader3 82
CAST_KINDS = {5: "VIEW", 13: "GET_DIGEST_REQ"}


def all_frames(buf):
    """Every length-prefixed frame of a directed stream, after the connecting side's handshake."""
    if buf[:4] == b"bela":
        buf = buf[8 + struct.unpack("!H", buf[6:8])[0]:]
    out = []
    while len(buf) >= 4:
        n = struct.unpack("!I", buf[:4])[0]
        if len(buf) < 4 + n:
            break
        out.append(buf[4:4 + n])
        buf = buf[4 + n:]
    return out


def ip4(b):
    return ".".join(str(x) for x in b)


def streams(path):
    """{(src, sport, dst, dport): bytes}: TCP payloads in sequence order, retransmissions dropped."""
    data = open(path, "rb").read()
    pos, segs = 24, {}
    while pos + 16 <= len(data):
        _, _, n, _ = struct.unpack("<IIII", data[pos:pos + 16])
        pkt = data[pos + 16:pos + 16 + n]
        pos += 16 + n
        ip = pkt[14:]
        ihl = (ip[0] & 0x0F) * 4
        sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
        seq = struct.unpack("!I", ip[ihl + 4:ihl + 8])[0]
        off = (ip[ihl + 12] >> 4) * 4
        payload = ip[ihl + off:struct.unpack("!H", ip[2:4])[0]]
        if payload:
            segs.setdefault((ip4(ip[12:16]), sport, ip4(ip[16:20]), dport), {})[seq] = payload
    out = {}
    for key, by_seq in segs.items():
        buf, nxt = b"", None
        for seq in sorted(by_seq):
            p = by_seq[seq]
            if nxt is not None and seq < nxt:
                p = p[nxt - seq:] if seq + len(by_seq[seq]) > nxt else b""
                seq = nxt
            buf += p
            nxt = seq + len(p)
        out[key] = buf
    return out


def windows(buf):
    found, i = [], 0
    while True:
        i = buf.find(LAMBDA, i)
        if i < 0:
            return found
        s = buf.rfind(START, 0, i)  # implClass; capturingClass is the START before it
        s = buf.rfind(START, 0, s) if s > 0 else s
        e = buf.find(INST, i)
        if s >= 0 and e >= 0:
            found.append(buf[s - 5:e + len(INST)])  # from the lambda tag byte and the 4-byte length of the first name
        i += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vectors")
    ap.add_argument("--dump")
    ap.add_argument("--gms", action="store_true")
    ap.add_argument("pcaps", nargs="+")
    a = ap.parse_args()
    golden = None
    if a.vectors:
        for line in open(a.vectors):
            label, _, hx = line.strip().partition("\t")
            if label == "compute:store-put-new":
                v = bytes.fromhex(hx)
                s, e = v.find(START), v.find(INST)
                golden = v[s - 5:e + len(INST)]
    sent = {"java": [], "rs": []}
    gms = {"java": {}, "rs": {}}
    casts = {"java": {}, "rs": {}}
    handshakes, frames = {"java": [], "rs": []}, {"java": [], "rs": []}
    for path in a.pcaps:
        java_ip = open(path[:-5] + ".ip").read().strip()  # written by run.sh next to the pcap
        for (src, sport, dst, dport), buf in streams(path).items():
            who = "java" if src == java_ip else "rs"
            for w in windows(buf):
                sent[who].append(w)
            for header, kinds in ((GMS_HEADER, GMS_KINDS), (MERGE3_HEADER, MERGE3_KINDS)):
                i = buf.find(header)
                while 0 <= i < len(buf) - 4:
                    kind = kinds.get(buf[i + 4])
                    if kind:
                        gms[who][kind] = gms[who].get(kind, 0) + 1
                    i = buf.find(header, i + 1)
            for f in all_frames(buf):
                # a frame too short for the flags byte (an empty frame once crashed the run), or a message list
                # (Java's bundler): not a single GMS message
                if len(f) < 3 or f[2] & 1:
                    continue
                i = f.find(GMS_HEADER)
                kind = CAST_KINDS.get(f[i + 4]) if 0 <= i < len(f) - 4 else None
                if kind:
                    c = casts[who].setdefault(kind, dict.fromkeys(
                        ("msg_mcast", "msg_ucast", "xmit_mcast", "xmit_ucast", "unicast3", "bare"), 0))
                    n = f.find(NAKACK2_HEADER)
                    nak = {1: "msg", 3: "xmit"}.get(f[n + 4]) if 0 <= n < len(f) - 4 else None
                    if nak:
                        c[nak + ("_mcast" if f[2] & 2 else "_ucast")] += 1
                    else:
                        c["bare"] += 1
                    c["unicast3"] += UNICAST3_HEADER in f
            if buf[:4] == b"bela":  # the connecting side: cookie, version, size, address, then frames
                size = struct.unpack("!H", buf[6:8])[0]
                handshakes[who].append(buf[:8 + size])
                buf = buf[8 + size:]
            fs = []
            while len(buf) >= 4 and len(fs) < FRAMES_PER_STREAM:
                n = struct.unpack("!I", buf[:4])[0]
                if len(buf) < 4 + n:
                    break
                fs.append(buf[4:4 + n])
                buf = buf[4 + n:]
            frames[who].extend(fs)
    fails = 0
    for who in ("java", "rs"):
        n = len(sent[who])
        print(f"  {'ok  ' if n else 'FAIL'} {who} node put {n} compute lambda descriptor(s) on the wire")
        fails += 0 if n else 1
        for w in set(sent[who]):
            if golden is not None and w != golden:
                print(f"  FAIL {who} descriptor differs from the golden vector ({len(w)} vs {len(golden)} bytes)")
                fails += 1
            elif golden is not None:
                print(f"  ok   {who} descriptor equals the golden vector ({len(w)} bytes)")
    if a.gms:
        for who in ("java", "rs"):
            for kind, n in sorted(gms[who].items()):
                print(f"  gms {who} {kind} {n}")
            for kind, c in sorted(casts[who].items()):
                print(f"  gmscast {who} {kind} " + " ".join(f"{k}={v}" for k, v in c.items()))
    if a.dump:
        os.makedirs(a.dump, exist_ok=True)
        for who in sent:
            for k, w in enumerate(sorted(set(sent[who]))):
                open(os.path.join(a.dump, f"compute-lambda-{who}-{k}.hex"), "w").write(w.hex() + "\n")
        with open(os.path.join(a.dump, "jgroups-frames.vectors"), "w") as f:
            for who in handshakes:
                for k, h in enumerate(sorted(set(handshakes[who]))[:1]):
                    f.write(f"{who}.handshake={h.hex()}\n")
                for k, fr in enumerate(frames[who][:FRAMES_PER_STREAM]):
                    f.write(f"{who}.frame.{k}={fr.hex()}\n")
    return 1 if fails else 0


sys.exit(main())
