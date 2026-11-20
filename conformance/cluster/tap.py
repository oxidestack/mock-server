#!/usr/bin/env python3
"""Frame tap: runs in a sidecar that shares a node's network namespace
(docker run --network container:<node> --cap-add NET_RAW) and writes every TCP segment of the JGroups port
(default 7800) the node sends or receives into a classic pcap (Ethernet link type), flushed per packet.
Usage: tap.py <out.pcap> [port]. Stops on SIGTERM. No dependencies."""
import signal
import socket
import struct
import sys
import time

out = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 else 7800
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
f = open(out, "wb", buffering=0)
f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
while True:
    data, _ = s.recvfrom(65535)
    if len(data) < 54 or data[12:14] != b"\x08\x00" or data[23] != 6:
        continue
    ihl = (data[14] & 0x0F) * 4
    sport, dport = struct.unpack("!HH", data[14 + ihl:18 + ihl])
    if port not in (sport, dport):
        continue
    t = time.time()
    f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(data), len(data)) + data)
