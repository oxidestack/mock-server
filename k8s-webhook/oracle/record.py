#!/usr/bin/env python3
"""Sends cases.json's requests to a running webhook over TLS and prints the exchanges as JSON.

    record.py <cases.json> <config> <port>

A case's body is `body` (sent as UTF-8) or `bodyHex` (raw bytes). Each request goes on its own connection with `Connection: close`; the response is kept as received, its header
names in their wire case, without `Date`.
"""
import json
import socket
import ssl
import sys


def exchange(port, method, path, body):
    raw = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n".encode()
    payload = b""
    if body is not None:
        payload = body if isinstance(body, bytes) else body.encode("utf-8")
        raw += f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n".encode()
    raw += b"\r\n" + payload
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=10) as tcp:
        with context.wrap_socket(tcp, server_hostname="localhost") as tls:
            tls.sendall(raw)
            received = b""
            while True:
                try:
                    chunk = tls.recv(65536)
                except (ssl.SSLError, ConnectionResetError):
                    break
                if not chunk:
                    break
                received += chunk
    head, _, rest = received.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split(" ")[1])
    headers = [line.split(": ", 1) for line in lines[1:]]
    length = next((int(v) for k, v in headers if k.lower() == "content-length"), None)
    body_bytes = rest if length is None else rest[:length]
    return {
        "status": status,
        "headers": [[k, v] for k, v in headers if k.lower() != "date"],
        "body": body_bytes.decode("utf-8"),
    }


def main():
    cases_file, config, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    spec = json.load(open(cases_file))
    wanted = None if config == "default" else set(spec["otherConfigCases"])
    out = []
    for case in spec["cases"]:
        if wanted is not None and case["name"] not in wanted:
            continue
        body = bytes.fromhex(case["bodyHex"]) if "bodyHex" in case else case["body"]
        response = exchange(port, case["method"], case["path"], body)
        out.append({"config": config, "name": case["name"], "response": response})
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


main()
