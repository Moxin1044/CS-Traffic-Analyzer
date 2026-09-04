"""Create a readable report of decrypted Cobalt Strike HTTP Beacon traffic.

Use only with PCAPs and keys obtained during authorized analysis.
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import IP, IPv6, Raw, TCP, rdpcap

import javaobj.v2 as javaobj
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

MAGIC = b"\x00\x00\xbe\xef"
IV = b"abcdefghijklmnop"


def load_private_key(path):
    data = path.read_bytes()
    if data.lstrip().startswith(b"-----BEGIN"):
        return RSA.import_key(data)
    with path.open("rb") as stream:
        obj = javaobj.load(stream)
    der = bytes(value & 0xff for value in obj.array.value.privateKey.encoded.data)
    return RSA.import_key(der)


def base64_candidates(value):
    if not isinstance(value, bytes):
        return []
    return [match.group(0) for match in re.finditer(rb"[A-Za-z0-9+/]{32,}={0,2}", value)]


def http_messages(stream):
    position = 0
    while True:
        header_end = stream.find(b"\r\n\r\n", position)
        if header_end < 0:
            return
        header = stream[position:header_end]
        first_line, *lines = header.split(b"\r\n")
        headers = {}
        for line in lines:
            if b":" in line:
                name, value = line.split(b":", 1)
                headers[name.lower()] = value.strip()
        length = int(headers.get(b"content-length", b"0"))
        body_start = header_end + 4
        body_end = body_start + length
        if body_end > len(stream):
            return
        kind = "request" if re.match(rb"(?:GET|POST|PUT|HEAD)\s", first_line) else "response"
        yield kind, first_line, headers, stream[body_start:body_end]
        position = body_end


def decrypt_metadata(value, rsa):
    try:
        encrypted = value if len(value) == 128 else base64.b64decode(value, validate=True)
        plain = rsa.decrypt(encrypted, b"")
    except (ValueError, binascii.Error):
        return None
    if not plain.startswith(MAGIC) or len(plain) < 24:
        return None
    digest = hashlib.sha256(plain[8:24]).digest()
    return digest[:16], digest[16:], plain


def discover_metadata(parts, rsa):
    for part in parts:
        for candidate in base64_candidates(part):
            result = decrypt_metadata(candidate, rsa)
            if result:
                return result
    return None


def decrypt_frame(frame, aes_key, hmac_key):
    if len(frame) < 20:
        return None
    declared = struct.unpack(">I", frame[:4])[0]
    if declared < 16 or declared > len(frame) - 4:
        return None
    ciphertext = frame[4:4 + declared - 16]
    signature = frame[4 + declared - 16:4 + declared]
    if not ciphertext or len(ciphertext) % 16:
        return None
    if not hmac.compare_digest(hmac.new(hmac_key, ciphertext, hashlib.sha256).digest()[:16], signature):
        return None
    return AES.new(aes_key, AES.MODE_CBC, IV).decrypt(ciphertext)


def stream_records(path):
    packets = rdpcap(str(path))
    flows = {}
    for packet in packets:
        if TCP not in packet or Raw not in packet:
            continue
        network = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
        if network is None:
            continue
        tcp = packet[TCP]
        flow = (network.src, int(tcp.sport), network.dst, int(tcp.dport))
        record = flows.setdefault(flow, {"segments": [], "time": packet.time})
        record["segments"].append((int(tcp.seq), bytes(packet[Raw].load)))

    for flow, record in flows.items():
        data = bytearray()
        end = None
        for sequence, payload in sorted(record["segments"]):
            if end is None:
                data.extend(payload)
                end = sequence + len(payload)
            elif sequence + len(payload) > end:
                data.extend(payload[max(0, end - sequence):])
                end = sequence + len(payload)
        yield flow, bytes(data), record["time"]


def parse_metadata(data):
    """Parse stable Beacon metadata fields used by common CS versions."""
    result = {"hostname": "unknown", "username": "unknown", "process": "unknown"}
    if len(data) < 60:
        return result

    # After the 24-byte header, the metadata contains network/session fields.
    # The trailing values are encoded using the Beacon's configured charset and
    # are separated by tabs: hostname, username, process image.
    tail = data[59:].split(b"\x00", 1)[0]
    strings = [x for x in tail.split(b"\t") if x]
    if len(strings) >= 3:
        result["hostname"], result["username"], result["process"] = (
            value.decode("latin-1", "replace") for value in strings[-3:]
        )
    elif strings:
        result["process"] = strings[-1].decode("latin-1", "replace")
    return result


def parse_plaintext(data):
    info = {"counter": None, "length": None, "type": None, "text": ""}
    if len(data) >= 12:
        info["counter"], info["length"], info["type"] = struct.unpack(">III", data[:12])
        declared_end = min(len(data), max(12, info["length"]))
        payload = data[12:declared_end]
        payload = payload.rstrip(b"\x00")
        if payload.count(b"\x00") > len(payload) // 8 and len(payload) % 2 == 0:
            info["text"] = payload.decode("utf-16le", "replace")
        else:
            try:
                info["text"] = payload.decode("utf-8")
            except UnicodeDecodeError:
                info["text"] = payload.decode("gb18030", "replace")
    return info


def timestamp(value):
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).astimezone().isoformat(sep=" ")
    except (TypeError, ValueError, OverflowError, OSError):
        return str(value)


def decrypt_metadata_plaintext(parts, rsa):
    """Return the RSA plaintext that discover_metadata accepted."""
    for part in parts:
        for candidate in base64_candidates(part):
            try:
                plaintext = rsa.decrypt(base64.b64decode(candidate), b"")
            except (ValueError, binascii.Error):
                continue
            if plaintext.startswith(b"\x00\x00\xbe\xef"):
                return plaintext
    return b""


def session_for(flow, sessions):
    return sessions.get((flow[0], flow[2], flow[3])) or sessions.get(
        (flow[2], flow[0], flow[1])
    )


def traffic_direction(flow, sessions):
    if (flow[0], flow[2], flow[3]) in sessions:
        return "回传"
    if (flow[2], flow[0], flow[1]) in sessions:
        return "传入"
    return "未知"


def build_report(pcap: Path, beacon_keys: Path) -> str:
    rsa = PKCS1_v1_5.new(load_private_key(beacon_keys))
    messages = []
    sessions = {}
    reported_metadata = set()
    for flow, stream, first_seen in stream_records(pcap):
        for kind, first_line, headers, body in http_messages(stream):
            parts = [first_line, body, *headers.values()]
            keys = discover_metadata(parts, rsa)
            if keys:
                sessions[(flow[0], flow[2], flow[3])] = keys
                metadata = decrypt_metadata_plaintext(parts, rsa)
                metadata_id = (flow[0], flow[2], metadata[8:24])
                if metadata_id not in reported_metadata:
                    reported_metadata.add(metadata_id)
                    messages.append((first_seen, flow, "metadata", metadata, None))
            messages.append((first_seen, flow, kind, body, session_for(flow, sessions)))

    report = []
    for first_seen, flow, kind, body, keys in sorted(messages, key=lambda item: float(item[0])):
        if kind == "metadata":
            meta = parse_metadata(body)
            report.extend([
                f"C2机器：{flow[2]}:{flow[3]}",
                f"被控机器：{flow[0]} | {meta['hostname']} | {meta['process']}",
                f"用户名：{meta['username']}",
                "",
            ])
            continue
        if not body or not keys:
            continue
        for offset in range(len(body) - 3):
            plain = decrypt_frame(body[offset:], keys[0], keys[1])
            if plain is None:
                continue
            direction = traffic_direction(flow, sessions)
            parsed = parse_plaintext(plain)
            report.extend([
                f"{timestamp(first_seen)} | {flow[0]}:{flow[1]} -> {flow[2]}:{flow[3]}",
                f"方向：{direction}",
                f"类型：{parsed['type']} | Counter：{parsed['counter']} | 长度：{parsed['length']}",
                f"内容：{parsed['text']}",
                f"HEX：{plain.hex()}",
                "",
            ])

    return "\n".join(report) or "未发现可解密的 Beacon 数据。\n"


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(description="Report decrypted Cobalt Strike HTTP Beacon traffic")
    parser.add_argument("pcap", type=Path)
    parser.add_argument("-k", "--beacon-keys", type=Path, default=Path("cobaltstrike.beacon_keys"))
    parser.add_argument("-o", "--output", type=Path, help="also save the report to this file; the report is always printed")
    args = parser.parse_args()

    report_text = build_report(args.pcap, args.beacon_keys)
    print(report_text, end="" if report_text.endswith("\n") else "\n")
    if args.output:
        args.output.write_text(report_text, encoding="utf-8")
        print(f"\n[+] report written to {args.output}")


if __name__ == "__main__":
    main()
