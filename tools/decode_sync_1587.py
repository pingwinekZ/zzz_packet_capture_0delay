#!/usr/bin/env python3
"""Temporary tool: decode sync_1587.bin (PlayerSyncScNotify wire dumps) for Phase 4a validation.

Format: repeated records of [uint32 LE payload length][protobuf wire bytes].
Run: python tools/decode_sync_1587.py [path to sync_1587.bin]
"""

import json
import os
import struct
import sys
from collections import Counter

RECORD_LEN = 4

# production (nap.json) leaf field numbers from datamine.json
DISC_UID = 6
WEAPON_UID = 10
AVATAR_ID = 13


def load_descriptors():
    """Classify sync fields from assets/nap.json (production descriptors)."""
    base = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(base, "..", "assets", "nap.json"), encoding="utf-8") as fh:
        nap = json.load(fh)
    by_name = {e["name"]: e for e in nap}

    def fmap(msg):
        return {f["number"]: f for f in msg["fields"]}

    avatar_f = fmap(by_name["GBBNCJDDDFP"])   # AvatarSync-like
    item_f = fmap(by_name["OHHBBCJGABO"])     # ItemSync-like
    return avatar_f, item_f


AVATAR_F, ITEM_F = load_descriptors()


def is_message_field(fdesc):
    return not fdesc["is_native_type"] and fdesc["repeated"]


class Field:
    __slots__ = ("number", "wire", "value", "children")

    def __init__(self, number, wire, value=None, children=None):
        self.number = number
        self.wire = wire
        self.value = value
        self.children = children

    def __repr__(self):
        return f"Field({self.number}, wire={self.wire})"


def read_varint(data, pos, end):
    result = 0
    shift = 0
    while pos < end:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
    raise ValueError("truncated varint")


def decode(data, pos=0, end=None):
    """Decode protobuf wire format into Field tree. Returns (fields, pos)."""
    if end is None:
        end = len(data)
    fields = []
    while pos < end:
        key, pos = read_varint(data, pos, end)
        number = key >> 3
        wire = key & 7
        if number == 0:
            raise ValueError("invalid field number 0")
        if wire == 0:  # varint
            val, pos = read_varint(data, pos, end)
            fields.append(Field(number, wire, val))
        elif wire == 1:  # fixed64
            if pos + 8 > end:
                raise ValueError("truncated fixed64")
            val = struct.unpack_from("<Q", data, pos)[0]
            pos += 8
            fields.append(Field(number, wire, val))
        elif wire == 2:  # length-delimited
            length, pos = read_varint(data, pos, end)
            if pos + length > end:
                raise ValueError("truncated length-delimited")
            payload = data[pos:pos + length]
            pos += length
            children = None
            try:
                children, _ = decode(payload)
            except ValueError:
                pass
            fields.append(Field(number, wire, payload, children))
        elif wire == 5:  # fixed32
            if pos + 4 > end:
                raise ValueError("truncated fixed32")
            val = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            fields.append(Field(number, wire, val))
        elif wire in (3, 4):  # groups (unexpected, but tolerate)
            raise ValueError("group wire type unsupported")
        else:
            raise ValueError(f"unknown wire type {wire}")
    return fields, pos


def format_field(f, indent, compact=False):
    pad = "  " * indent
    if f.wire == 0:
        return f"{pad}{f.number}: varint {f.value}"
    if f.wire == 1:
        return f"{pad}{f.number}: fixed64 0x{f.value:016X}"
    if f.wire == 5:
        return f"{pad}{f.number}: fixed32 0x{f.value:08X}"
    if f.wire == 2:
        if f.children is not None:
            lines = [f"{pad}{f.number} {{"]
            for c in f.children:
                lines.append(format_field(c, indent + 1, compact))
            lines.append(f"{pad}}}")
            return "\n".join(lines)
        payload = f.value
        text = payload.decode("utf-8", errors="replace")
        if text.isprintable() and len(payload) < 64:
            return f"{pad}{f.number}: \"{text}\" ({len(payload)} bytes)"
        hexpart = payload.hex() if len(payload) <= 32 else payload[:16].hex() + f"...({len(payload)}b)"
        return f"{pad}{f.number}: bytes {hexpart}"
    return f"{pad}{f.number}: wire={f.wire}"


def collect_uids(fields, list_numbers, leaf_uid_field):
    """Collect leaf uid values from repeated message fields (each field instance is one entry)."""
    out = {}
    for f in fields:
        if f.wire != 2 or f.children is None or f.number not in list_numbers:
            continue
        for c in f.children:
            if c.number == leaf_uid_field and c.wire == 0:
                out.setdefault(f.number, []).append(c.value)
    return out


def packed_u32s(fields, candidate_numbers):
    """Repeated uint32 lists (wire-2 fields whose payload is packed varints)."""
    out = {}
    for f in fields:
        if f.wire != 2 or f.children is None or f.number not in candidate_numbers:
            continue
        if all(c.wire == 0 for c in f.children):
            out[f.number] = [c.value for c in f.children]
    return out


def find_submsg(fields, num):
    for f in fields:
        if f.number == num and f.wire == 2 and f.children is not None:
            return f.children
    return None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "sync_1587.bin"
    only = [int(x) for x in sys.argv[2:]] or None
    with open(path, "rb") as fh:
        data = fh.read()

    records = []
    pos = 0
    while pos + RECORD_LEN <= len(data):
        (length,) = struct.unpack_from("<I", data, pos)
        pos += RECORD_LEN
        if pos + length > len(data):
            print(f"truncated record at offset {pos - RECORD_LEN}: need {length} bytes")
            break
        records.append(data[pos:pos + length])
        pos += length

    print(f"{len(records)} record(s), {len(data)} bytes\n")

    for i, rec in enumerate(records):
        try:
            fields, consumed = decode(rec)
        except ValueError as e:
            print(f"record {i}: decode failed: {e}")
            continue
        print(f"===== record {i} ({len(rec)} bytes, top-level fields: "
              f"{', '.join(f'{num}(x{count})' for num, count in Counter(f.number for f in fields).most_common())}) =====")
        if only is None or i in only:
            for f in fields:
                print(format_field(f, 1))
        else:
            print("(full tree omitted; see summary below)")
        print()

    print("===== top-level field frequency across all records =====")
    freq = Counter()
    for rec in records:
        try:
            fields, _ = decode(rec)
        except ValueError:
            continue
        for f in fields:
            freq[f.number] += 1
    print(", ".join(f"{num}(x{count})" for num, count in freq.most_common()))

    print("===== summary: per-record sync contents =====")
    print("avatarSync(9): avatar list 12 -> avatar ids; uint32 lists (possible del uids)")
    print("itemSync(15):  equip list 15 -> disc uids; weapon list 1 -> weapon uids; uint32 lists (possible del uids)")
    for i, rec in enumerate(records):
        try:
            fields, _ = decode(rec)
        except ValueError:
            continue
        avatar_sync = find_submsg(fields, 9)
        item_sync = find_submsg(fields, 15)
        av = collect_uids(avatar_sync or [], [n for n, d in AVATAR_F.items() if is_message_field(d)], AVATAR_ID).get(12, [])
        eq = collect_uids(item_sync or [], [n for n, d in ITEM_F.items() if is_message_field(d)], DISC_UID).get(15, [])
        wp = collect_uids(item_sync or [], [n for n, d in ITEM_F.items() if is_message_field(d)], WEAPON_UID).get(1, [])
        av_u32 = packed_u32s(avatar_sync or [], [n for n, d in AVATAR_F.items() if d["repeated"] and d["is_native_type"]])
        item_u32 = packed_u32s(item_sync or [], [n for n, d in ITEM_F.items() if d["repeated"] and d["is_native_type"]])
        line = f"record {i}: avatars={av} equips={eq} weapons={wp}"
        if av_u32:
            line += " | avatarSync uint32-lists: " + ", ".join(
                f"{k}=[{','.join(map(str, v[:8]))}{'...' if len(v) > 8 else ''}]" for k, v in sorted(av_u32.items()))
        if item_u32:
            line += " | itemSync uint32-lists: " + ", ".join(
                f"{k}=[{','.join(map(str, v[:8]))}{'...' if len(v) > 8 else ''}]" for k, v in sorted(item_u32.items()))
        print(line)


if __name__ == "__main__":
    main()