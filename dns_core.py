"""
Shared DNS packet building / parsing primitives.
Used by every attack module so wire-format logic is in one place.
"""

import random
import socket
import struct
import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# DNS constants
# ---------------------------------------------------------------------------
TYPE_A     = 1
TYPE_NS    = 2
TYPE_CNAME = 5
TYPE_SOA   = 6
TYPE_PTR   = 12
TYPE_MX    = 15
TYPE_TXT   = 16
TYPE_AAAA  = 28

CLASS_IN = 1

RCODE_NOERROR  = 0
RCODE_FORMERR  = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP   = 4
RCODE_REFUSED  = 5

TYPE_NAMES = {1:"A",2:"NS",5:"CNAME",6:"SOA",12:"PTR",15:"MX",16:"TXT",28:"AAAA",255:"ANY"}
RCODE_NAMES = {0:"NOERROR",1:"FORMERR",2:"SERVFAIL",3:"NXDOMAIN",4:"NOTIMP",5:"REFUSED"}

DNS_PORT = 53


# ---------------------------------------------------------------------------
# DNS name wire encoding / decoding
# ---------------------------------------------------------------------------
def encode_name(name: str) -> bytes:
    """Encode a domain name to DNS wire format."""
    buf = b""
    for label in name.rstrip(".").split("."):
        enc = label.encode("ascii")
        if len(enc) > 63:
            raise ValueError(f"Label too long: {label}")
        buf += bytes([len(enc)]) + enc
    return buf + b"\x00"


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name from wire format. Returns (name, new_offset)."""
    labels = []
    visited = set()
    original_offset = None
    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if original_offset is None:
                original_offset = offset + 2
            offset = ptr
        else:
            offset += 1
            if offset + length > len(data):
                break
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
    if original_offset is not None:
        offset = original_offset
    return ".".join(labels), offset


# ---------------------------------------------------------------------------
# DNS Header
# ---------------------------------------------------------------------------
def build_header(txid: int, flags: int, qdcount: int = 1,
                 ancount: int = 0, nscount: int = 0, arcount: int = 0) -> bytes:
    return struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)


def parse_header(data: bytes) -> dict:
    if len(data) < 12:
        raise ValueError("Packet too short for DNS header")
    txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    return {
        "txid":    txid,
        "flags":   flags,
        "qr":      (flags >> 15) & 1,
        "opcode":  (flags >> 11) & 0xF,
        "aa":      (flags >> 10) & 1,
        "tc":      (flags >> 9)  & 1,
        "rd":      (flags >> 8)  & 1,
        "ra":      (flags >> 7)  & 1,
        "rcode":   flags & 0xF,
        "qdcount": qd,
        "ancount": an,
        "nscount": ns,
        "arcount": ar,
    }


# Flags presets
FLAGS_QUERY    = 0x0100   # Standard query, RD=1
FLAGS_RESPONSE = 0x8180   # QR=1 AA=1 RD=1 RA=1
FLAGS_NXDOMAIN = 0x8183   # QR=1 AA=1 RD=1 RA=1 RCODE=3
FLAGS_REFUSED  = 0x8185   # QR=1 AA=1 RD=1 RA=1 RCODE=5
FLAGS_SERVFAIL = 0x8182


# ---------------------------------------------------------------------------
# Question section
# ---------------------------------------------------------------------------
def build_question(qname: str, qtype: int = TYPE_A, qclass: int = CLASS_IN) -> bytes:
    return encode_name(qname) + struct.pack("!HH", qtype, qclass)


def parse_question(data: bytes, offset: int) -> tuple[dict, int]:
    qname, offset = decode_name(data, offset)
    if offset + 4 > len(data):
        return {"qname": qname, "qtype": 0, "qclass": 0}, offset
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    return {"qname": qname, "qtype": qtype, "qclass": qclass}, offset + 4


# ---------------------------------------------------------------------------
# Resource records
# ---------------------------------------------------------------------------
def build_a_record(name: str, ip: str, ttl: int = 60) -> bytes:
    rdata = socket.inet_aton(ip)
    return (
        encode_name(name)
        + struct.pack("!HHIH", TYPE_A, CLASS_IN, ttl, 4)
        + rdata
    )


def build_a_record_compressed(ttl: int = 60, ip: str = "127.0.0.1") -> bytes:
    """A record using compression pointer (0xC00C) for name — saves space."""
    rdata = socket.inet_aton(ip)
    return b"\xc0\x0c" + struct.pack("!HHIH", TYPE_A, CLASS_IN, ttl, 4) + rdata


def build_txt_record(name: str, txt: str, ttl: int = 0) -> bytes:
    rdata = txt.encode("ascii")
    wire  = bytes([len(rdata)]) + rdata
    return (
        encode_name(name)
        + struct.pack("!HHIH", TYPE_TXT, CLASS_IN, ttl, len(wire))
        + wire
    )


def build_txt_compressed(txt: str, ttl: int = 0) -> bytes:
    rdata = txt.encode("ascii")
    wire  = bytes([len(rdata)]) + rdata
    return b"\xc0\x0c" + struct.pack("!HHIH", TYPE_TXT, CLASS_IN, ttl, len(wire)) + wire


def build_ns_record(name: str, ns_name: str, ttl: int = 300) -> bytes:
    rdata = encode_name(ns_name)
    return (
        encode_name(name)
        + struct.pack("!HHIH", TYPE_NS, CLASS_IN, ttl, len(rdata))
        + rdata
    )


def build_cname_record(name: str, cname: str, ttl: int = 300) -> bytes:
    rdata = encode_name(cname)
    return (
        encode_name(name)
        + struct.pack("!HHIH", TYPE_CNAME, CLASS_IN, ttl, len(rdata))
        + rdata
    )


# ---------------------------------------------------------------------------
# Full DNS packet builders
# ---------------------------------------------------------------------------
def build_query(qname: str, qtype: int = TYPE_A, txid: int | None = None) -> bytes:
    txid = txid if txid is not None else random.randint(0, 65535)
    hdr  = build_header(txid, FLAGS_QUERY, qdcount=1)
    q    = build_question(qname, qtype)
    return hdr + q


def build_a_response(txid: int, qname: str, ip: str, ttl: int = 60) -> bytes:
    hdr = build_header(txid, FLAGS_RESPONSE, qdcount=1, ancount=1)
    q   = build_question(qname, TYPE_A)
    rr  = build_a_record_compressed(ttl=ttl, ip=ip)
    return hdr + q + rr


def build_nxdomain_response(txid: int, qname: str) -> bytes:
    hdr = build_header(txid, FLAGS_NXDOMAIN, qdcount=1, ancount=0)
    q   = build_question(qname, TYPE_A)
    return hdr + q


def build_txt_response(txid: int, qname: str, txt: str) -> bytes:
    hdr = build_header(txid, FLAGS_RESPONSE, qdcount=1, ancount=1)
    q   = build_question(qname, TYPE_TXT)
    rr  = build_txt_compressed(txt, ttl=0)
    return hdr + q + rr


# ---------------------------------------------------------------------------
# DNS socket helper
# ---------------------------------------------------------------------------
class DNSSocket:
    """Simple UDP DNS socket wrapper."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def query(self, server: str, port: int, packet: bytes) -> bytes | None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        try:
            s.sendto(packet, (server, port))
            resp, _ = s.recvfrom(4096)
            return resp
        except (socket.timeout, OSError):
            return None
        finally:
            s.close()

    def query_name(self, server: str, qname: str,
                   qtype: int = TYPE_A, port: int = DNS_PORT) -> bytes | None:
        pkt = build_query(qname, qtype)
        return self.query(server, port, pkt)


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------
@dataclass
class DNSRecord:
    name:  str
    rtype: int
    rclass: int
    ttl:   int
    rdata: bytes
    value: str = ""


@dataclass
class DNSMessage:
    header:   dict
    questions: list = field(default_factory=list)
    answers:   list = field(default_factory=list)
    authority: list = field(default_factory=list)
    additional: list = field(default_factory=list)


def parse_message(data: bytes) -> DNSMessage | None:
    try:
        hdr    = parse_header(data)
        offset = 12
        questions = []
        for _ in range(hdr["qdcount"]):
            q, offset = parse_question(data, offset)
            questions.append(q)

        answers = []
        for _ in range(hdr["ancount"]):
            rec, offset = _parse_rr(data, offset)
            answers.append(rec)

        return DNSMessage(header=hdr, questions=questions, answers=answers)
    except Exception:
        return None


def _parse_rr(data: bytes, offset: int) -> tuple[DNSRecord, int]:
    name, offset = decode_name(data, offset)
    if offset + 10 > len(data):
        return DNSRecord(name=name, rtype=0, rclass=0, ttl=0, rdata=b""), offset
    rtype, rclass, ttl, rdlen = struct.unpack("!HHiH", data[offset:offset + 10])
    offset += 10
    rdata  = data[offset:offset + rdlen]
    offset += rdlen

    # Decode value
    value = ""
    if rtype == TYPE_A and len(rdata) == 4:
        value = socket.inet_ntoa(rdata)
    elif rtype == TYPE_AAAA and len(rdata) == 16:
        value = socket.inet_ntop(socket.AF_INET6, rdata)
    elif rtype in (TYPE_NS, TYPE_CNAME, TYPE_PTR):
        value, _ = decode_name(data, offset - rdlen)
    elif rtype == TYPE_TXT and rdata:
        tlen  = rdata[0]
        value = rdata[1:1 + tlen].decode("ascii", errors="replace")

    return DNSRecord(name=name, rtype=rtype, rclass=rclass,
                     ttl=ttl, rdata=rdata, value=value), offset


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------
def random_txid() -> int:
    return random.randint(1, 65535)


def random_local_port() -> int:
    return random.randint(1024, 65535)


def format_dns_type(t: int) -> str:
    return TYPE_NAMES.get(t, f"TYPE{t}")


def resolve(hostname: str, server: str = "8.8.8.8",
            port: int = DNS_PORT, timeout: float = 3.0) -> str | None:
    """Simple A record lookup. Returns IP string or None."""
    sock = DNSSocket(timeout=timeout)
    resp = sock.query_name(server, hostname, TYPE_A, port)
    if not resp:
        return None
    msg = parse_message(resp)
    if msg and msg.answers:
        for ans in msg.answers:
            if ans.rtype == TYPE_A:
                return ans.value
    return None
