#!/usr/bin/env python3
"""Summarise tap.py pcaps: per direction (src ip:port -> dst ip:port) segment count, payload bytes, and the first
payload bytes (hex) of the flow, which is where JGroups' TCP transport writes its cookie/version/address handshake.
Usage: pcap_summary.py <file.pcap>..."""
import struct
import sys


def ip4(b):
    return ".".join(str(x) for x in b)


for path in sys.argv[1:]:
    data = open(path, "rb").read()
    pos, flows = 24, {}
    while pos + 16 <= len(data):
        _, _, n, _ = struct.unpack("<IIII", data[pos:pos + 16])
        pkt = data[pos + 16:pos + 16 + n]
        pos += 16 + n
        ip = pkt[14:]
        ihl = (ip[0] & 0x0F) * 4
        sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
        off = (ip[ihl + 12] >> 4) * 4
        payload = ip[ihl + off:struct.unpack("!H", ip[2:4])[0]]
        key = (ip4(ip[12:16]), sport, ip4(ip[16:20]), dport)
        segs, size, head = flows.get(key, (0, 0, b""))
        flows[key] = (segs + 1, size + len(payload), head or payload[:48])
    print(f"== {path}: {len(flows)} directed flows")
    for (a, ap, b, bp), (segs, size, head) in sorted(flows.items()):
        print(f"  {a}:{ap} -> {b}:{bp}  segments={segs} payload={size}B  head={head.hex()}")
