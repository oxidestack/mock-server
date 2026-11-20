#!/usr/bin/env python3
"""Records tests/files/k8s-webhook-tls13/second_hello.txt from the mockserver-webhook image (the oracle:
ORACLE_WEBHOOK_IMAGE of oracle.env) serving a DSA pair, with hand-made TLS 1.3 ClientHellos:

    probe.py <port> > tests/files/k8s-webhook-tls13/second_hello.txt

One line per case: `<kind> <dimensions> => <outcome>`. `first` cases send one ClientHello; `second` cases send a first
ClientHello that gets a HelloRetryRequest (no key share, session id 0x11 * 32, random 0x22 * 32, suite 0x1302), then a
ChangeCipherSpec and the second ClientHello the dimensions describe. The outcome is the alert's description, or `flight`
with the ServerHello's suite and session id and the record lengths. tests/upstream/k8s_webhook_dsa.rs builds the same
ClientHellos (`MatrixHello`) and compares.

Dimensions: ck cookie (none, echo of the HelloRetryRequest's, other, empty, raw1: extension data of one byte, trunc:
a length prefix past the data), sh key shares (usable: x25519, other: x448, empty list, absent extension, unknown: group
99, both: group 99 then x25519), sc signature scheme (ok: rsa_pss_rsae_sha256, bad: rsa_pkcs1_sha256), su suite (same:
1302, other: 1301, none: 1304), gr supported_groups (29, empty, 99), rn random (same, other), sd session id (same, other, empty).
"""
import socket, struct, sys, time

port = int(sys.argv[1])


def ext(k, d): return struct.pack(">HH", k, len(d)) + d
def sized(b): return struct.pack(">H", len(b)) + b
def lst(items): return b"".join(struct.pack(">H", i) for i in items)


SHARES = {
    "usable": [(29, b"\x01" * 32)],
    "other": [(30, b"\x01" * 56)],
    "empty": [],
    "absent": None,
    "unknown": [(99, b"a")],
    "both": [(99, b"a"), (29, b"\x01" * 32)],
}
GROUPS = {"29": [29], "empty": [], "99": [99]}
SUITES = {"same": 0x1302, "other": 0x1301, "none": 0x1304}
SCHEMES = {"ok": 0x0804, "bad": 0x0401}
SIDS = {"same": b"\x11" * 32, "other": b"\x44" * 32, "empty": b""}
RANDOMS = {"same": 0x22, "other": 0x33}


def hello(d, issued):
    e = ext(0x2B, bytes([2, 3, 4])) + ext(0x0A, sized(lst(GROUPS[d["gr"]]))) + ext(0x0D, sized(lst([SCHEMES[d["sc"]]])))
    shares = SHARES[d["sh"]]
    if shares is not None:
        e += ext(0x33, sized(b"".join(struct.pack(">H", g) + sized(s) for g, s in shares)))
    ck = d["ck"]
    if ck == "echo": e += ext(0x2C, sized(issued))
    elif ck == "other": e += ext(0x2C, sized(b"\x00" * 99))
    elif ck == "empty": e += ext(0x2C, sized(b""))
    elif ck == "raw1": e += ext(0x2C, b"\x00")
    elif ck == "trunc": e += ext(0x2C, b"\x00\x05abc")
    sid = SIDS[d["sd"]]
    b = b"\x03\x03" + bytes([RANDOMS[d["rn"]]]) * 32 + bytes([len(sid)]) + sid + sized(lst([SUITES[d["su"]]])) + bytes([1, 0]) + sized(e)
    m = bytes([1]) + len(b).to_bytes(3, "big") + b
    return b"\x16\x03\x01" + struct.pack(">H", len(m)) + m


def read_all(s, seconds=4):
    # an idle second ends the read: a HelloRetryRequest leaves the server waiting for the second ClientHello
    s.settimeout(1)
    got, t = b"", time.time()
    try:
        while time.time() - t < seconds:
            c = s.recv(4096)
            if not c: break
            got += c
    except Exception:
        pass
    return got


def outcome(got):
    recs, r = [], got
    while len(r) >= 5:
        n = struct.unpack(">H", r[3:5])[0]
        recs.append((r[0], n, r[5:5 + n]))
        r = r[5 + n:]
    if recs and recs[-1][0] == 21 and recs[-1][1] == 2 and recs[0][0] == 21:
        return f"alert {recs[-1][2][1]}"
    if recs and recs[0][0] == 22:
        b = recs[0][2][4:]
        sl = b[34]
        tail = ",".join(str(n) for _, n, _ in recs)
        if b[2:34] == bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"):
            return f"retry {tail}"
        return f"flight suite={b[35 + sl:37 + sl].hex()} sid={b[35:35 + sl].hex()[:2]}/{sl} {tail}"
    return "other " + ",".join(f"{k}/{n}" for k, n, _ in recs)


def first_hello_cases():
    for ck in ["none", "other", "empty", "raw1", "trunc"]:
        for sh in SHARES:
            for sc in SCHEMES:
                for su in ["same", "none"]:
                    for gr in GROUPS:
                        yield dict(ck=ck, sh=sh, sc=sc, su=su, gr=gr, rn="same", sd="same")


def second_hello_cases():
    for ck in ["none", "echo", "other", "empty", "raw1", "trunc"]:
        for sh in SHARES:
            for sc in SCHEMES:
                for su in SUITES:
                    for gr in GROUPS:
                        yield dict(ck=ck, sh=sh, sc=sc, su=su, gr=gr, rn="same", sd="same")
    for ck in ["none", "echo", "other"]:
        for sh in ["usable", "empty", "absent"]:
            for su in ["same", "other"]:
                for rn, sd in [("other", "same"), ("same", "other"), ("same", "empty"), ("other", "other")]:
                    yield dict(ck=ck, sh=sh, sc="ok", su=su, gr="29", rn=rn, sd=sd)


FIRST = dict(ck="none", sh="empty", sc="ok", su="same", gr="29", rn="same", sd="same")


def run(kind, d):
    s = socket.create_connection(("127.0.0.1", port))
    s.settimeout(4)
    if kind == "first":
        s.sendall(hello(d, b""))
        return outcome(read_all(s))
    s.sendall(hello(FIRST, b""))
    first = b""
    while len(first) < 5 + 193 + 6:
        c = s.recv(4096)
        if not c: break
        first += c
    body = first[9:]
    at = 2 + 32 + 1 + body[34] + 2 + 1
    rest, end = at + 2, at + 2 + struct.unpack(">H", body[at:at + 2])[0]
    issued = b""
    while rest < end:
        k, n = struct.unpack(">HH", body[rest:rest + 4])
        if k == 0x2C: issued = body[rest + 6:rest + 4 + n]
        rest += 4 + n
    s.sendall(b"\x14\x03\x03\x00\x01\x01" + hello(d, issued))
    got = read_all(s)
    s.close()
    return outcome(got)


for kind, cases in [("first", first_hello_cases()), ("second", second_hello_cases())]:
    for d in cases:
        name = " ".join(f"{k}={v}" for k, v in d.items())
        print(f"{kind} {name} => {run(kind, d)}", flush=True)
