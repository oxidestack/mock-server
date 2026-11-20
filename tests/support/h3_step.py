# An `"h3"` step's client for recording (tests/oracle.rs, `send_h3`): one HTTP/3 request on a fresh QUIC connection,
# written and read as raw HTTP/3 frames over aioquic's QUIC layer, so that whatever the server sends (even DATA before
# any HEADERS) is seen as sent. The same exchange as tests/support/h3_step.rs, which replay uses.
#
# argv[1]: JSON {"host", "port", "method", "path", "authority", "headers": [[name, value], ...], "body": base64,
#                "timeout": seconds, "stall": seconds | null}, or "-" to read it from stdin (a body of
#                megabytes outgrows the argument list)
# stdout:  JSON {"frames": [{"headers": [[name, value], ...]} | {"data": base64} | {"frame": type}], "end": text}
#
# "trailers": [[name, value], ...] sends a trailer section after the body, and "repeat": [name, value,
# count] adds that field count times after "headers"; the answer also carries "settings" ({"<id>": value}, the server's
# SETTINGS frame) and, when the server closed the connection (waiting up to "closeWait" seconds after the stream ended),
# "closed" ({"application": bool, "code": n, "reason": text}).
#
# With "streams": [{"method", "path", "authority", "headers", "body"}, ...] in place of the request's own
# fields, each request goes on one connection, the next 0.05 s after the first bytes of the one before (`exchange_streams`
# in h3_step.rs); "stall" then grants the connection 96 KiB and each stream 1 MiB and nothing more for that long, timed
# from the first request. stdout: {"streams": [{"frames", "end"}, ...]}.
import asyncio
import base64
import json
import ssl
import sys

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived, StreamReset
from pylsqpack import Decoder

NEXT_STREAM_PAUSE = 0.05


def varint(n):
    if n < 0x40:
        return bytes([n])
    if n < 0x4000:
        return (n | 0x4000).to_bytes(2, "big")
    if n < 0x40000000:
        return (n | 0x80000000).to_bytes(4, "big")
    return (n | 0xC000000000000000).to_bytes(8, "big")


def read_varint(buf, at):
    first = buf[at]
    size = 1 << (first >> 6)
    value = first & 0x3F
    for b in buf[at + 1 : at + size]:
        value = (value << 8) | b
    return value, at + size


# RFC 9204 Appendix A: the fields a request's section indexes whole (as h3_step.rs does).
STATIC = {
    (b':authority', b''): 0,
    (b':path', b'/'): 1,
    (b'age', b'0'): 2,
    (b'content-disposition', b''): 3,
    (b'content-length', b'0'): 4,
    (b'cookie', b''): 5,
    (b'date', b''): 6,
    (b'etag', b''): 7,
    (b'if-modified-since', b''): 8,
    (b'if-none-match', b''): 9,
    (b'last-modified', b''): 10,
    (b'link', b''): 11,
    (b'location', b''): 12,
    (b'referer', b''): 13,
    (b'set-cookie', b''): 14,
    (b':method', b'CONNECT'): 15,
    (b':method', b'DELETE'): 16,
    (b':method', b'GET'): 17,
    (b':method', b'HEAD'): 18,
    (b':method', b'OPTIONS'): 19,
    (b':method', b'POST'): 20,
    (b':method', b'PUT'): 21,
    (b':scheme', b'http'): 22,
    (b':scheme', b'https'): 23,
    (b':status', b'103'): 24,
    (b':status', b'200'): 25,
    (b':status', b'304'): 26,
    (b':status', b'404'): 27,
    (b':status', b'503'): 28,
    (b'accept', b'*/*'): 29,
    (b'accept', b'application/dns-message'): 30,
    (b'accept-encoding', b'gzip, deflate, br'): 31,
    (b'accept-ranges', b'bytes'): 32,
    (b'access-control-allow-headers', b'cache-control'): 33,
    (b'access-control-allow-headers', b'content-type'): 34,
    (b'access-control-allow-origin', b'*'): 35,
    (b'cache-control', b'max-age=0'): 36,
    (b'cache-control', b'max-age=2592000'): 37,
    (b'cache-control', b'max-age=604800'): 38,
    (b'cache-control', b'no-cache'): 39,
    (b'cache-control', b'no-store'): 40,
    (b'cache-control', b'public, max-age=31536000'): 41,
    (b'content-encoding', b'br'): 42,
    (b'content-encoding', b'gzip'): 43,
    (b'content-type', b'application/dns-message'): 44,
    (b'content-type', b'application/javascript'): 45,
    (b'content-type', b'application/json'): 46,
    (b'content-type', b'application/x-www-form-urlencoded'): 47,
    (b'content-type', b'image/gif'): 48,
    (b'content-type', b'image/jpeg'): 49,
    (b'content-type', b'image/png'): 50,
    (b'content-type', b'text/css'): 51,
    (b'content-type', b'text/html; charset=utf-8'): 52,
    (b'content-type', b'text/plain'): 53,
    (b'content-type', b'text/plain;charset=utf-8'): 54,
    (b'range', b'bytes=0-'): 55,
    (b'strict-transport-security', b'max-age=31536000'): 56,
    (b'strict-transport-security', b'max-age=31536000; includesubdomains'): 57,
    (b'strict-transport-security', b'max-age=31536000; includesubdomains; preload'): 58,
    (b'vary', b'accept-encoding'): 59,
    (b'vary', b'origin'): 60,
    (b'x-content-type-options', b'nosniff'): 61,
    (b'x-xss-protection', b'1; mode=block'): 62,
    (b':status', b'100'): 63,
    (b':status', b'204'): 64,
    (b':status', b'206'): 65,
    (b':status', b'302'): 66,
    (b':status', b'400'): 67,
    (b':status', b'403'): 68,
    (b':status', b'421'): 69,
    (b':status', b'425'): 70,
    (b':status', b'500'): 71,
    (b'accept-language', b''): 72,
    (b'access-control-allow-credentials', b'FALSE'): 73,
    (b'access-control-allow-credentials', b'TRUE'): 74,
    (b'access-control-allow-headers', b'*'): 75,
    (b'access-control-allow-methods', b'get'): 76,
    (b'access-control-allow-methods', b'get, post, options'): 77,
    (b'access-control-allow-methods', b'options'): 78,
    (b'access-control-expose-headers', b'content-length'): 79,
    (b'access-control-request-headers', b'content-type'): 80,
    (b'access-control-request-method', b'get'): 81,
    (b'access-control-request-method', b'post'): 82,
    (b'alt-svc', b'clear'): 83,
    (b'authorization', b''): 84,
    (b'content-security-policy', b"script-src 'none'; object-src 'none'; base-uri 'none'"): 85,
    (b'early-data', b'1'): 86,
    (b'expect-ct', b''): 87,
    (b'forwarded', b''): 88,
    (b'if-range', b''): 89,
    (b'origin', b''): 90,
    (b'purpose', b'prefetch'): 91,
    (b'server', b''): 92,
    (b'timing-allow-origin', b'*'): 93,
    (b'upgrade-insecure-requests', b'1'): 94,
    (b'user-agent', b''): 95,
    (b'x-forwarded-for', b''): 96,
    (b'x-frame-options', b'deny'): 97,
    (b'x-frame-options', b'sameorigin'): 98,
}


def integer(flags, prefix, value):
    top = (1 << prefix) - 1
    if value < top:
        return bytes([flags | value])
    out = bytearray([flags | top])
    value -= top
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def field_section(fields):
    """A field section as h3_step.rs encodes one: no dynamic table, a field the static table holds whole
    as an indexed line, any other as a literal name and value without Huffman coding, so a section is as long on the
    wire whichever client sends it (pylsqpack also refuses a field over about 4 KiB)."""
    out = bytearray(b"\x00\x00")
    for name, value in fields:
        name = name.lower()
        index = STATIC.get((name, value))
        if index is not None:
            out += integer(0xC0, 6, index)
        else:
            out += integer(0x20, 3, len(name)) + name + integer(0x00, 7, len(value)) + value
    return bytes(out)


def frame(kind, payload):
    return varint(kind) + varint(len(payload)) + payload


class Stream:
    def __init__(self):
        self.received = bytearray()
        self.end = None
        self.done = asyncio.Event()
        self.first_bytes = asyncio.Event()

    def finish(self, end):
        if self.end is None:
            self.end = end
        self.done.set()
        self.first_bytes.set()


class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.streams = {}
        self.uni = {}
        self.closed = None

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived) and event.stream_id % 4 == 3:
            self.uni.setdefault(event.stream_id, bytearray()).extend(event.data)
        elif isinstance(event, StreamDataReceived) and event.stream_id in self.streams:
            stream = self.streams[event.stream_id]
            stream.received += event.data
            if event.data:
                stream.first_bytes.set()
            if event.end_stream:
                stream.finish("fin")
        elif isinstance(event, StreamReset) and event.stream_id in self.streams:
            self.streams[event.stream_id].finish("reset %d" % event.error_code)
        elif isinstance(event, ConnectionTerminated):
            if self.closed is None:
                self.closed = {"application": event.frame_type is None, "code": event.error_code, "reason": event.reason_phrase}
            for stream in self.streams.values():
                stream.finish("connection closed")


def frames(stream_id, buf):
    frames = []
    at = 0
    decoder = Decoder(0, 0)
    while at < len(buf):
        try:
            kind, at = read_varint(buf, at)
            length, at = read_varint(buf, at)
        except IndexError:
            break
        payload = buf[at : at + length]
        at += length
        if kind == 0x01:
            _, headers = decoder.feed_header(stream_id, payload)
            frames.append({"headers": [[k.decode(), v.decode("utf-8", "replace")] for k, v in headers]})
        elif kind == 0x00:
            frames.append({"data": base64.b64encode(payload).decode()})
        else:
            frames.append({"frame": kind})
    return frames


def settings(uni):
    for buf in uni.values():
        try:
            kind, at = read_varint(buf, 0)
            if kind != 0x00:
                continue
            kind, at = read_varint(buf, at)
            length, at = read_varint(buf, at)
            if kind != 0x04:
                continue
            out = {}
            end = at + length
            while at < end:
                key, at = read_varint(buf, at)
                value, at = read_varint(buf, at)
                out[str(key)] = value
            return out
        except IndexError:
            continue
    return {}


async def main(spec):
    configuration = QuicConfiguration(is_client=True, alpn_protocols=["h3"], verify_mode=ssl.CERT_NONE, server_name="localhost")
    stall = spec.get("stall")
    many = "streams" in spec
    requests = spec["streams"] if many else [spec]
    if stall and many:
        # The connection is granted 96 KiB, each stream 1 MiB, then nothing more until the stall ends
        configuration.max_data = 96 * 1024
        configuration.max_stream_data = 1024 * 1024
    elif stall:
        # The stream is granted 64 KiB, then nothing more until the stall ends, as a client that stopped reading
        configuration.max_stream_data = 64 * 1024
    async with connect(spec["host"], spec["port"], configuration=configuration, create_protocol=Client) as client:
        quic = client._quic
        loop = asyncio.get_running_loop()
        control = quic.get_next_available_stream_id(is_unidirectional=True)
        quic.send_stream_data(control, b"\x00" + frame(0x04, b""))
        if stall:
            # aioquic raises MAX_STREAM_DATA and MAX_DATA as data arrives, not as it is read: those grants are held back
            quic._write_stream_limits = lambda *args, **kwargs: None
            if many:
                quic._write_connection_limits = lambda *args, **kwargs: None
        until = loop.time() + (stall or 0)
        ids = []
        for i, request in enumerate(requests):
            stream_id = quic.get_next_available_stream_id()
            ids.append(stream_id)
            stream = client.streams[stream_id] = Stream()
            fields = [(b":method", request["method"].encode()), (b":scheme", b"https"), (b":authority", request["authority"].encode()), (b":path", request["path"].encode())]
            fields += [(k.encode(), v.encode()) for k, v in request["headers"]]
            if request.get("repeat"):
                name, value, count = request["repeat"]
                fields += [(name.encode(), value.encode())] * count
            block = field_section(fields)
            body = base64.b64decode(request["body"])
            payload = frame(0x01, block) + (frame(0x00, body) if body else b"")
            if request.get("trailers"):
                trailers = field_section([(k.encode(), v.encode()) for k, v in request["trailers"]])
                payload += frame(0x01, trailers)
            quic.send_stream_data(stream_id, payload, end_stream=True)
            client.transmit()
            if i + 1 < len(requests):
                try:
                    await asyncio.wait_for(stream.first_bytes.wait(), spec["timeout"])
                except asyncio.TimeoutError:
                    stream.finish("timeout")
                await asyncio.sleep(NEXT_STREAM_PAUSE)
        streams = [client.streams[i] for i in ids]

        def all_done():
            return all(s.done.is_set() for s in streams)

        async def wait_all(timeout):
            await asyncio.wait_for(asyncio.gather(*(s.done.wait() for s in streams)), timeout)

        if stall:
            # PINGs every second, as the replay client's keep-alive, so the server's idle timeout cannot end the stall
            while not all_done() and loop.time() < until:
                try:
                    await wait_all(min(1.0, until - loop.time()))
                except asyncio.TimeoutError:
                    quic.send_ping(0)
                    client.transmit()
            del quic._write_stream_limits
            if many:
                del quic._write_connection_limits
            client.transmit()
        try:
            await wait_all(spec["timeout"])
        except asyncio.TimeoutError:
            for s in streams:
                if s.end is None:
                    s.end = "timeout"
        results = [{"frames": frames(i, bytes(s.received)), "end": s.end} for i, s in zip(ids, streams)]
        if not many:
            # "closeWait": how long to wait, once the stream has ended, for the server to close the connection
            until = loop.time() + (spec.get("closeWait") or 0)
            while client.closed is None and loop.time() < until:
                await asyncio.sleep(0.01)
            results[0]["settings"] = settings(client.uni)
            if client.closed is not None:
                results[0]["closed"] = client.closed
        print(json.dumps({"streams": results} if many else results[0]))
        client.close()


asyncio.run(main(json.load(sys.stdin) if sys.argv[1] == "-" else json.loads(sys.argv[1])))
