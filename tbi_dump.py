#!/usr/bin/env python3
"""Conservative structural dumper for TeraByte Image (TBI) files.

Recovered from Image for Linux 3.41.  This intentionally stops at the first
non-metadata region; compressed/encrypted sector payload decoding is not yet
implemented.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


RECORD_HEADER = struct.Struct("<III")
FILE_HEADER = struct.Struct("<8sIIIII")

RECORD_NAMES = {
    0: "file_header",
    1: "volume_descriptor",
    2: "description",
    5: "image_flags",
    6: "auxiliary_header",
    7: "image_set_id",
    0xFFFFFFFF: "end",
}


def rol32(value: int, count: int = 1) -> int:
    value &= 0xFFFFFFFF
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def payload_hash32(data: bytes) -> int:
    """Exact hash used by imagel at 0x820E790."""
    result = 0
    whole = len(data) & ~3
    for offset in range(0, whole, 4):
        word = int.from_bytes(data[offset : offset + 4], "little")
        result = word ^ rol32(word + result)
    if whole != len(data):
        word = int.from_bytes(data[whole:], "little")
        result = word ^ rol32(word + result)
    return result & 0xFFFFFFFF


def checksum(record_type: int, payload: bytes) -> int:
    return ((record_type + len(payload)) ^ payload_hash32(payload)) & 0xFFFFFFFF


def decode_payload(record_type: int, payload: bytes) -> dict:
    if record_type == 0 and len(payload) == FILE_HEADER.size:
        magic, set_lo, set_hi, flags, max_type, version = FILE_HEADER.unpack(payload)
        return {
            "magic_hex": magic.hex(),
            "magic_ascii": magic.rstrip(b"\0").decode("ascii", "replace"),
            "image_set_id": (set_hi << 32) | set_lo,
            "flags": f"0x{flags:08x}",
            "max_record_type": max_type or 8,
            "format_version_raw": f"0x{version:08x}",
        }
    if record_type == 2:
        return {"text": payload.split(b"\0", 1)[0].decode("utf-8", "replace")}
    if record_type == 5 and len(payload) >= 4:
        return {"flags": f"0x{struct.unpack_from('<I', payload)[0]:08x}"}
    if record_type == 7 and len(payload) == 8:
        return {"image_set_id": struct.unpack("<Q", payload)[0]}
    return {"preview_hex": payload[:64].hex()}


def dump(path: Path, maximum: int) -> list[dict]:
    records: list[dict] = []
    with path.open("rb") as stream:
        for index in range(maximum):
            offset = stream.tell()
            raw = stream.read(RECORD_HEADER.size)
            if not raw:
                break
            if len(raw) != RECORD_HEADER.size:
                records.append({"offset": offset, "error": "truncated record header"})
                break
            record_type, length, stored = RECORD_HEADER.unpack(raw)
            if record_type == 0xFFFFFFFF:
                records.append({"index": index, "offset": offset, "type": "end"})
                break
            # Metadata records seen by the parser are small.  This guard avoids
            # interpreting a sector-data block as an enormous typed record.
            if length > 64 * 1024 * 1024:
                records.append({"offset": offset, "error": "implausible length", "length": length})
                break
            payload = stream.read(length)
            if len(payload) != length:
                records.append({"offset": offset, "error": "truncated payload", "length": length})
                break
            calculated = checksum(record_type, payload)
            records.append(
                {
                    "index": index,
                    "offset": offset,
                    "type_id": record_type,
                    "type": RECORD_NAMES.get(record_type, "unknown"),
                    "length": length,
                    "checksum_stored": f"0x{stored:08x}",
                    "checksum_calculated": f"0x{calculated:08x}",
                    "checksum_ok": stored == calculated,
                    "payload": decode_payload(record_type, payload),
                }
            )
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--max-records", type=int, default=4096)
    args = parser.parse_args()
    print(json.dumps(dump(args.image, args.max_records), indent=2))


if __name__ == "__main__":
    main()
