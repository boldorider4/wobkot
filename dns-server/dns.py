#!/usr/bin/env python3
"""Fake DNS server for PS5 exploit hosting. Python stdlib only.

    sudo python3 dns.py [options]

The allowlisted exploit-host domains (manuals.playstation.net) are answered
with this machine's LAN IP (where host.py and the 443 doorman run).
PlayStation/Sony domains are NXDOMAINed to stop updates and PSN traffic.
Everything else is forwarded verbatim to an upstream resolver so the console
can reach the real internet (catalogue art, provider pages) while the
Sony blocklist stays intact.

Options:
  --ip <addr>        answer with this address  (default: auto-detect LAN IP)
  --port <n>         UDP port to bind          (default: 53, needs root)
  --upstream <addr>  resolver to forward to    (default: 8.8.8.8)
  --no-block-psn     answer PlayStation/Sony domains with the IP instead of NXDOMAIN
  --help
"""

import argparse
import asyncio
import errno
import socket
import struct
import sys
from dataclasses import dataclass
from urllib.parse import urlparse

# const WHITELIST_HOSTS = ["ecode.np.cs.playstation.net", "smetrics.aem.playstation.com", "www.playstation.com"];
WHITELIST_HOSTS = [""]
BLOCK_PATTERNS = ["playstation", "sonyentertainmentnetwork", "sony.com"]
ALLOWED_HOSTS = {"manuals.playstation.net", "manuals.playstation.sony.com"}

UP_TIMEOUT = 3.0
UPSTREAM_PORT = 53

PORT = 53
FIX_IP = None
BLOCK = True
UPSTREAM = "8.8.8.8"


@dataclass
class Question:
    name: str
    type: int


@dataclass
class Query:
    id: int
    flags: int
    questions: list
    end: int


def read_u16(buf, off):
    return (buf[off] << 8) | buf[off + 1]


def read_u32(buf, off):
    return (buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]


def matches_pattern(name, pattern):
    labels = name.split(".")
    pat = pattern.split(".")
    if len(pat) > len(labels):
        return False
    for i in range(len(labels) - len(pat) + 1):
        if all(labels[i + j] == pat[j] for j in range(len(pat))):
            return True
    return False


def detect_ip():
    # Same approach as host.py: ask the routing table which local address
    # reaches a public resolver.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def parse_name(buf, off, depth=0):
    if depth > 64:
        return None
    parts = []
    while True:
        if off >= len(buf):
            return None
        length = buf[off]
        off += 1
        if length == 0:
            return ".".join(parts), off
        if length > 63:
            if (length & 0xC0) != 0xC0 or off >= len(buf):
                return None
            tail = parse_name(buf, ((length & 0x3F) << 8) | buf[off], depth + 1)
            if tail is None:
                return None
            if tail[0]:
                parts.append(tail[0])
            return ".".join(parts), off + 1
        if off + length > len(buf):
            return None
        parts.append(buf[off:off + length].decode("latin-1").lower())
        off += length


def parse_query(msg):
    if len(msg) < 12 or (read_u16(msg, 2) & 0x8000):
        return None
    qd = read_u16(msg, 4)
    off = 12
    questions = []
    for _ in range(qd):
        parsed = parse_name(msg, off)
        if parsed is None or parsed[1] + 4 > len(msg):
            return None
        name, end = parsed
        cls = read_u16(msg, end + 2)
        if cls != 1:
            return None
        questions.append(Question(name, read_u16(msg, end)))
        off = end + 4
    return Query(read_u16(msg, 0), read_u16(msg, 2), questions, off)


def header_for(q, rcode, an, ns):
    flags = 0x8000 | (q.flags & 0x7900) | 0x0080 | (rcode & 0xF)
    return struct.pack("!HHHHHH", q.id, flags, len(q.questions), an, ns, 0)


def enc_name(name):
    out = bytearray()
    for label in name.split("."):
        if label:
            out.append(len(label))
            out.extend(label.encode("latin-1"))
    out.append(0)
    return bytes(out)


def rr_prefix(name, rtype, rdlength, ttl):
    return enc_name(name) + struct.pack("!HHIH", rtype, 1, ttl, rdlength)


def a_record(name):
    ip = bytes(int(part) for part in IP.split("."))
    return rr_prefix(name, 1, 4, 60) + ip


def skip_name(buf, off):
    while True:
        if off >= len(buf):
            return None
        length = buf[off]
        off += 1
        if length == 0:
            return off
        if (length & 0xC0) == 0xC0:
            return off + 1
        off += length


def first_answer_ip(buf):
    try:
        qd = read_u16(buf, 4)
        an = read_u16(buf, 6)
        off = 12
        for _ in range(qd):
            off = skip_name(buf, off)
            if off is None or off + 4 > len(buf):
                return None
            off += 4
        for _ in range(an):
            off = skip_name(buf, off)
            if off is None or off + 10 > len(buf):
                return None
            rtype = read_u16(buf, off)
            rdlength = read_u16(buf, off + 8)
            off += 10
            if rtype == 1 and rdlength == 4 and off + 4 <= len(buf):
                return ".".join(str(byte) for byte in buf[off:off + 4])
            off += rdlength
    except (IndexError, ValueError):
        pass
    return None


def soa_record(name):
    fields = struct.pack("!IIIII", 1, 600, 600, 86400, 60)
    ns = enc_name("ns." + name)
    root = enc_name("root." + name)
    return rr_prefix(name, 6, len(ns) + len(root) + 20, 60) + ns + root + fields


def normalize_host(entry):
    try:
        if "://" in entry:
            return (urlparse(entry).hostname or entry).lower()
        return entry.lower()
    except ValueError:
        return entry.lower()


WHITELIST_SET = {normalize_host(entry) for entry in WHITELIST_HOSTS}


class DNSServer(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        q = parse_query(data)
        if q is None or not q.questions:
            return
        first = q.questions[0]

        # Check if the query matches any whitelisted domain or subdomain.
        whitelisted = any(
            first.name == domain or first.name.endswith("." + domain)
            for domain in WHITELIST_SET
        )
        if whitelisted:
            pass  # reserved: forwardQuery(q, data, addr)

        local = first.name in ALLOWED_HOSTS or (
            not BLOCK and any(matches_pattern(first.name, p) for p in BLOCK_PATTERNS)
        )
        blocked = BLOCK and not local and any(
            matches_pattern(first.name, p) for p in BLOCK_PATTERNS
        )

        if blocked:
            out = header_for(q, 3, 0, 1) + data[12:q.end] + soa_record(first.name)
            verdict = "NXDOMAIN"
        elif local and first.type == 1:
            out = header_for(q, 0, 1, 0) + data[12:q.end] + a_record(first.name)
            verdict = IP
        elif local:
            out = header_for(q, 0, 0, 0) + data[12:q.end]
            verdict = "NODATA"
        else:
            asyncio.create_task(forward_query(self, q, data, addr))
            return

        self.transport.sendto(out, addr)
        print(f"[dns] {addr[0]} {first.name} type={first.type} -> {verdict}", flush=True)


async def forward_query(server, q, req, addr):
    loop = asyncio.get_running_loop()
    first = q.questions[0]

    def send(out, verdict):
        server.transport.sendto(out, addr)
        print(f"[dns] {addr[0]} {first.name} type={first.type} -> {verdict}", flush=True)

    def servfail(verdict):
        send(header_for(q, 2, 0, 0) + req[12:q.end], verdict)

    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up.setblocking(False)
    try:
        up.connect((UPSTREAM, UPSTREAM_PORT))
        await loop.sock_sendall(up, req)
        res = await asyncio.wait_for(loop.sock_recv(up, 65535), timeout=UP_TIMEOUT)
        ip = first_answer_ip(res)
        verdict = (
            f"{ip} (forwarded via {UPSTREAM})" if ip
            else f"forwarded via {UPSTREAM}, no A record"
        )
        send(res, verdict)
    except asyncio.TimeoutError:
        servfail(f"TIMEOUT({UPSTREAM})")
    except OSError:
        servfail(f"ERROR({UPSTREAM})")
    finally:
        up.close()


def parse_args(argv):
    p = argparse.ArgumentParser(
        description="Fake DNS server for PS5 exploit hosting.",
        add_help=False,
    )
    p.add_argument("--ip", help="address to answer with (default: auto-detect LAN IP)")
    p.add_argument("--port", type=int, default=53, help="UDP port to bind (default: 53, needs root)")
    p.add_argument("--upstream", default="8.8.8.8", help="resolver to forward to (default: 8.8.8.8)")
    p.add_argument("--no-block-psn", action="store_true",
                   help="answer PlayStation/Sony domains with the IP instead of NXDOMAIN")
    p.add_argument("--help", action="help", help="show this help message and exit")
    return p.parse_args(argv)


async def async_main():
    loop = asyncio.get_running_loop()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", PORT))
    except OSError as e:
        sock.close()
        if e.errno == errno.EACCES:
            print(f"cannot bind udp/{PORT} - retry with: sudo python3 {sys.argv[0]}", file=sys.stderr)
        elif e.errno == errno.EADDRINUSE:
            print(f"udp/{PORT} already in use", file=sys.stderr)
        else:
            print(e, file=sys.stderr)
        raise SystemExit(1)

    await loop.create_datagram_endpoint(DNSServer, sock=sock)
    print(
        f"[dns] udp/{PORT} allow {len(ALLOWED_HOSTS)} host(s) -> {IP}, "
        f"sony blocked {'on' if BLOCK else 'off'}, forwarding to {UPSTREAM}",
        flush=True,
    )
    await asyncio.Future()  # run forever


def main(argv=None):
    global PORT, FIX_IP, BLOCK, UPSTREAM, IP

    args = parse_args(sys.argv[1:] if argv is None else argv)
    PORT = args.port
    FIX_IP = args.ip
    BLOCK = not args.no_block_psn
    UPSTREAM = args.upstream
    IP = FIX_IP or detect_ip()

    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
