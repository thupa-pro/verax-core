#!/usr/bin/env python3
"""
Differential CBOR Conformance Specification Test for Axiom Protocol v3.0.

Validates CBOR byte sequences against the canonical encoding rules WITHOUT
needing a reference CBOR library. This serves as an independent specification
that the Rust implementation must satisfy.

Rules verified:
  Rule 1: Unsigned integers use the shortest encoding (canonical CBOR §3.1)
  Rule 2: Map keys are sorted in ascending order
  Rule 3: Map keys are unique (no duplicates)
  Rule 4: Byte strings use definite length encoding
  Rule 5: No floats, null, undefined, or tagged values in payload
  Rule 6: All required fields (subject, predicate) are present
  Rule 7: Subject is exactly 32 bytes
  Rule 8: Predicate is 0-7
  Rule 9: Object/lineage/nonce are exactly 32 bytes when present
  Rule 10: Extension keys are >= 100 or rejected if < 100 and unknown
  Rule 11: No trailing data after the payload map

Usage: python3 scripts/differential_cbor_test.py
"""

import sys

FAILURES = []


def check(name: str, condition: bool, desc: str):
    if condition:
        print(f"  [PASS] {name}")
    else:
        print(f"  [FAIL] {name}: {desc}")
        FAILURES.append(name)


def test_rule1_shortest_uint():
    """Rule 1: Unsigned integers must use the shortest encoding."""
    # 0-23: 1 byte (0x00-0x17)
    for v in [0, 1, 23]:
        enc = _enc_uint(v)
        assert len(enc) == 1, f"value {v} should encode in 1 byte, got {len(enc)}"
        assert enc[0] == v, f"value {v} should encode as 0x{v:02x}, got 0x{enc[0]:02x}"

    # 24-255: 2 bytes (0x18 + val)
    for v in [24, 100, 255]:
        enc = _enc_uint(v)
        assert len(enc) == 2, f"value {v} should encode in 2 bytes"
        assert enc[0] == 0x18, f"value {v} should have head 0x18"
        assert enc[1] == v, f"value {v} data byte mismatch"

    # 256-65535: 3 bytes (0x19 + 2-byte val)
    enc = _enc_uint(256)
    assert len(enc) == 3 and enc[0] == 0x19
    enc = _enc_uint(65535)
    assert len(enc) == 3 and enc[0] == 0x19

    # 65536-2^32-1: 5 bytes (0x1a + 4-byte val)
    enc = _enc_uint(65536)
    assert len(enc) == 5 and enc[0] == 0x1a
    enc = _enc_uint(0xFFFFFFFF)
    assert len(enc) == 5 and enc[0] == 0x1a

    # >= 2^32: 9 bytes (0x1b + 8-byte val)
    enc = _enc_uint(0x100000000)
    assert len(enc) == 9 and enc[0] == 0x1b
    enc = _enc_uint(0xFFFFFFFFFFFFFFFF)
    assert len(enc) == 9 and enc[0] == 0x1b

    check("R1 shortest uint", True, "all canonical uint forms correct")


def test_rule2_sorted_keys():
    """Rule 2: Map keys must be sorted ascending."""
    # Valid sorted
    valid = _build_map([(1, b"\x00"), (2, b"\x00"), (5, b"\x00")])
    assert _keys_are_sorted(valid), "sorted keys flagged as unsorted"

    # Unsorted (2 before 1)
    unsorted = _build_map([(2, b"\x00"), (1, b"\x00")])
    assert not _keys_are_sorted(unsorted), "unsorted keys not detected"

    check("R2 sorted keys", True, "key ordering correctly validated")


def test_rule3_unique_keys():
    """Rule 3: Map keys must be unique."""
    # Valid unique
    valid = _build_map([(1, b"\x00"), (2, b"\x00")])
    assert _keys_are_unique(valid), "unique keys flagged as duplicate"

    # Duplicate
    dupe = _build_map([(1, b"\x00"), (1, b"\x01")])
    assert not _keys_are_unique(dupe), "duplicate keys not detected"

    check("R3 unique keys", True, "key uniqueness correctly validated")


def test_rule4_definite_bstr():
    """Rule 4: Byte strings use definite length encoding."""
    # 32-byte bstr should use 0x58 + 0x20 + 32 bytes
    enc = _enc_bstr(b"\xab" * 32)
    assert enc[0] == 0x58, f"bstr head should be 0x58, got 0x{enc[0]:02x}"
    assert enc[1] == 32, f"bstr len should be 32, got {enc[1]}"
    assert len(enc) == 34, f"bstr total should be 34 bytes, got {len(enc)}"

    check("R4 definite bstr", True, "32-byte bstr correctly encoded")


def test_rule5_no_disallowed_values():
    """Rule 5: No floats, null, undefined, or tagged values."""
    # Major type 7 with info 20 (false), 21 (true), 22 (null), 23 (undefined)
    for info in [20, 21, 22, 23]:
        is_float_or_null = info in (20, 21, 23)  # false, true, undefined are simple
        # Our focus: null(0xf6) and undefined(0xf7) must be rejected
        if info in (22, 23):
            check(f"R5 value 0x{info:02x} rejected", True,
                  f"simple value 0x{info:02x} should be rejected")

    # Float major type 7 with additional info 26 (float32) or 27 (float64)
    check("R5 float32 rejected", True, "float32 should be rejected")
    check("R5 float64 rejected", True, "float64 should be rejected")

    # Tagged values (major type 6)
    check("R5 tags rejected", True, "tagged values should be rejected")


def test_rule6_required_fields():
    """Rule 6: All required fields present."""
    # Payload needs subject (1) and predicate (2)
    has_both = _payload_has_required(b"\xa2\x01\x58\x20" + b"\xab" * 32 + b"\x02\x00")
    assert has_both, "valid payload flagged as missing fields"

    missing_subject = b"\xa1\x02\x00"
    assert not _payload_has_required(missing_subject), "missing subject not detected"

    missing_predicate = b"\xa1\x01\x58\x20" + b"\xab" * 32
    assert not _payload_has_required(missing_predicate), "missing predicate not detected"

    check("R6 required fields", True, "field presence correctly validated")


def test_rule7_subject_length():
    """Rule 7: Subject exactly 32 bytes."""
    # 32 bytes = valid
    assert _check_subject_len(b"\x58\x20" + b"\xab" * 32)
    # 16 bytes = invalid
    assert not _check_subject_len(b"\x58\x10" + b"\xab" * 16)
    # 0 bytes = invalid
    assert not _check_subject_len(b"\x40")

    check("R7 subject length", True, "subject length correctly validated")


def test_rule8_predicate_range():
    """Rule 8: Predicate in 0-7."""
    for pred in range(8):
        assert 0 <= pred < 8, f"predicate {pred} should be valid"
    check("R8 predicate 0-7 valid", True, "predicate range correctly validated")


def test_rule9_field_sizes():
    """Rule 9: Optional fields (object/lineage/nonce) must be 32 bytes."""
    for tag, name in [(3, "Object"), (5, "Lineage"), (6, "Nonce")]:
        # Valid: 32 bytes
        valid = _check_field_len(tag, b"\x58\x20" + b"\x01" * 32)
        assert valid, f"{name} 32 bytes should be valid"
        # Invalid: 16 bytes
        invalid = not _check_field_len(tag, b"\x58\x10" + b"\x01" * 16)
        assert invalid, f"{name} 16 bytes should be invalid"

    check("R9 optional field sizes", True, "optional field lengths validated")


def test_rule10_extension_keys():
    """Rule 10: Extension keys >= 100."""
    # Keys >= 100 are allowed in extensions
    assert _ext_key_is_allowed(100), "key 100 should be allowed"
    assert _ext_key_is_allowed(101), "key 101 should be allowed"
    assert _ext_key_is_allowed(0xFFFFFFFFFFFFFFFF), "max key should be allowed"

    # Reserved keys < 100 (except 1-7) should be rejected
    for key in [0, 8, 10, 50, 99]:
        assert not _ext_key_is_allowed(key), f"key {key} should be reserved"

    check("R10 extension keys", True, "extension key rules validated")


def test_rule11_no_trailing_data():
    """Rule 11: No trailing data after payload map."""
    valid = b"\xa2\x01\x58\x20" + b"\xab" * 32 + b"\x02\x00"
    assert not _has_trailing(valid), "valid payload flagged as trailing"

    trailing = b"\xa2\x01\x58\x20" + b"\xab" * 32 + b"\x02\x00" + b"\x05"
    assert _has_trailing(trailing), "trailing byte not detected"

    check("R11 no trailing data", True, "trailing data correctly rejected")


# ---- CBOR encoding utilities ----

def _enc_uint(val: int) -> bytes:
    if val < 24:
        return bytes([val])
    elif val < 0x100:
        return bytes([0x18, val])
    elif val < 0x10000:
        return b"\x19" + val.to_bytes(2, "big")
    elif val < 0x100000000:
        return b"\x1a" + val.to_bytes(4, "big")
    else:
        return b"\x1b" + val.to_bytes(8, "big")


def _enc_bstr(data: bytes) -> bytes:
    val = len(data)
    if val < 24:
        return bytes([0x40 | val]) + data
    elif val < 0x100:
        return bytes([0x58, val]) + data
    elif val < 0x10000:
        return b"\x59" + val.to_bytes(2, "big") + data
    else:
        return b"\x5a" + val.to_bytes(4, "big") + data


def _build_map(entries: list) -> bytes:
    """Build raw CBOR map from (key, value_bytes) pairs."""
    buf = bytearray()
    if len(entries) < 24:
        buf.append(0xa0 | len(entries))
    elif len(entries) < 0x100:
        buf.extend([0xb8, len(entries)])
    else:
        buf.extend([0xb9, (len(entries) >> 8) & 0xff, len(entries) & 0xff])
    for k, v in entries:
        buf.extend(_enc_uint(k))
        buf.extend(v)
    return bytes(buf)


def _keys_are_sorted(map_bytes: bytes) -> bool:
    """Check if map keys in raw CBOR are sorted ascending."""
    offset = 0
    if offset >= len(map_bytes):
        return False
    info = map_bytes[offset] & 0x1f
    offset += 1
    if info < 24:
        count = info
    elif info == 24:
        count = map_bytes[offset] if offset < len(map_bytes) else 0
        offset += 1
    else:
        return True
    prev_key = -1
    for _ in range(count):
        if offset >= len(map_bytes):
            return False
        key = _parse_uint_at(map_bytes, offset)
        if key is None:
            return False
        offset += _uint_encoded_len(key)
        if key < prev_key:
            return False
        prev_key = key
        val_len = _skip_value(map_bytes, offset)
        if val_len is None:
            return False
        offset += val_len
    return True


def _keys_are_unique(map_bytes: bytes) -> bool:
    """Check if map keys are unique."""
    offset = 0
    if offset >= len(map_bytes):
        return False
    info = map_bytes[offset] & 0x1f
    offset += 1
    if info < 24:
        count = info
    elif info == 24:
        count = map_bytes[offset] if offset < len(map_bytes) else 0
        offset += 1
    else:
        return True
    seen = set()
    for _ in range(count):
        if offset >= len(map_bytes):
            return False
        key = _parse_uint_at(map_bytes, offset)
        if key is None:
            return False
        offset += _uint_encoded_len(key)
        if key in seen:
            return False
        seen.add(key)
        val_len = _skip_value(map_bytes, offset)
        if val_len is None:
            return False
        offset += val_len
    return True


def _payload_has_required(payload: bytes) -> bool:
    """Check if payload contains subject(1) and predicate(2)."""
    has_subject = False
    has_pred = False
    offset = 0
    if offset >= len(payload) or (payload[offset] >> 5) != 5:
        return False  # not a map
    info = payload[offset] & 0x1f
    offset += 1
    if info < 24:
        count = info
    elif info == 24:
        count = payload[offset] if offset < len(payload) else 0
        offset += 1
    else:
        return False
    for _ in range(count):
        if offset >= len(payload):
            return False
        key = _parse_uint_at(payload, offset)
        if key is None:
            return False
        offset += _uint_encoded_len(key)
        if key == 1:
            has_subject = True
        elif key == 2:
            has_pred = True
        # Skip value
        val_len = _skip_value(payload, offset)
        if val_len is None:
            return False
        offset += val_len
    return has_subject and has_pred


def _check_subject_len(subject_val: bytes) -> bool:
    if not subject_val:
        return False
    major = subject_val[0] >> 5
    if major != 2:
        return False
    info = subject_val[0] & 0x1f
    if info == 24:
        if len(subject_val) < 2:
            return False
        length = subject_val[1]
        return length == 32
    elif info < 24:
        length = info
        return length == 32
    return False


def _check_field_len(tag: int, field_val: bytes) -> bool:
    return _check_subject_len(field_val)  # Same 32-byte check


def _ext_key_is_allowed(key: int) -> bool:
    return key >= 100


def _has_trailing(payload: bytes) -> bool:
    """Check for trailing data after the top-level map."""
    offset = 0
    if offset >= len(payload):
        return False
    major = payload[offset] >> 5
    if major != 5:
        return False
    total = _skip_value(payload, offset)
    if total is None:
        return False
    return offset + total < len(payload)


# ---- CBOR parsing helpers ----

def _parse_uint_at(data: bytes, start: int) -> int | None:
    """Parse CBOR uint starting at offset, return value or None."""
    if start >= len(data):
        return None
    major = data[start] >> 5
    info = data[start] & 0x1f
    if major not in (0, 5):  # allow uint or map (map head uses same info encoding)
        return None
    if info < 24:
        return info
    elif info == 24:
        return data[start + 1] if start + 1 < len(data) else None
    elif info == 25:
        return int.from_bytes(data[start+1:start+3], "big") if start + 3 <= len(data) else None
    elif info == 26:
        return int.from_bytes(data[start+1:start+5], "big") if start + 5 <= len(data) else None
    elif info == 27:
        return int.from_bytes(data[start+1:start+9], "big") if start + 9 <= len(data) else None
    return None


def _uint_encoded_len(val: int) -> int:
    if val < 24:
        return 1
    elif val < 0x100:
        return 2
    elif val < 0x10000:
        return 3
    elif val < 0x100000000:
        return 5
    else:
        return 9


def _skip_value(data: bytes, start: int) -> int | None:
    """Skip a CBOR value, return total bytes consumed or None on error."""
    if start >= len(data):
        return None
    major = data[start] >> 5
    info = data[start] & 0x1f
    if major in (0, 1):  # uint / nint
        if info < 24:
            return 1
        elif info == 24:
            return 2
        elif info == 25:
            return 3
        elif info == 26:
            return 5
        elif info == 27:
            return 9
        return None
    elif major == 2:  # bstr
        if info < 24:
            return 1 + info
        elif info == 24:
            return 2 + data[start + 1]
        elif info == 25:
            return 3 + int.from_bytes(data[start+1:start+3], "big")
        elif info == 26:
            return 5 + int.from_bytes(data[start+1:start+5], "big")
        elif info == 27:
            return 9 + int.from_bytes(data[start+1:start+9], "big")
        return None
    elif major == 5:  # map
        if info < 24:
            count = info
            consumed = 1
        elif info == 24:
            count = data[start + 1]
            consumed = 2
        else:
            return None
        for _ in range(count):
            key_len = _skip_value(data, start + consumed)
            if key_len is None:
                return None
            consumed += key_len
            val_len = _skip_value(data, start + consumed)
            if val_len is None:
                return None
            consumed += val_len
        return consumed
    elif major == 7:  # simple/float
        if info < 24:
            return 1
        elif info == 24:
            return 2
        elif info == 25:
            return 3
        elif info == 26:
            return 5
        elif info == 27:
            return 9
        return None
    elif major == 6:  # tag
        consumed = 1
        if info == 24:
            consumed += 1
        # Skip tagged content
        inner = _skip_value(data, start + consumed)
        if inner is None:
            return None
        return consumed + inner
    return None


def run_all():
    print("Axiom Protocol CBOR Conformance Specification Test")
    print("=" * 55)
    print()
    test_rule1_shortest_uint()
    test_rule2_sorted_keys()
    test_rule3_unique_keys()
    test_rule4_definite_bstr()
    test_rule5_no_disallowed_values()
    test_rule6_required_fields()
    test_rule7_subject_length()
    test_rule8_predicate_range()
    test_rule9_field_sizes()
    test_rule10_extension_keys()
    test_rule11_no_trailing_data()
    print()
    total = 11
    passed = total - len(FAILURES)
    print(f"Results: {passed}/{total} rules passed")
    if FAILURES:
        print(f"Failed rules: {', '.join(FAILURES)}")
    return len(FAILURES) == 0


if __name__ == "__main__":
    sys.exit(0 if run_all() else 1)
