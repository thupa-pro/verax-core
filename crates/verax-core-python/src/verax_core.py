"""Python bindings for Verax Protocol Core.

Uses ctypes to load the shared library (libverax_core_ffi.so) and wraps
the C FFI functions in a Pythonic interface.
"""

import ctypes
import json
import os
from pathlib import Path
from typing import Optional


class VeraxError(Exception):
    """Verax protocol error with numeric error code."""

    _NAMES = {
        1: "MalformedCose",
        2: "NonCanonicalEncoding",
        3: "InvalidSignature",
        4: "BrokenLineage",
        5: "LineageSubjectMismatch",
        6: "TimestampMonotonicityViolation",
        7: "RevokeIssuerMismatch",
        8: "InvalidLogProof",
        9: "Revoked",
        10: "InvalidField",
        11: "Crypto",
        12: "Decode",
        13: "HashLength",
        14: "Io",
        15: "Payload",
        16: "Encode",
        17: "SpecError",
        18: "RecoveryGuardianMismatch",
    }

    def __init__(self, code: int):
        self.code = code
        self.name = self._NAMES.get(code, f"Unknown({code})")
        super().__init__(f"[{self.name}] Verax error {code}")


class _VeraxLib:
    """Lazily loaded singleton for the shared library."""

    _lib = None

    @classmethod
    def _find_lib(cls):
        search_paths = [
            Path(os.environ.get("VERAX_LIB_PATH", "")),
            Path.cwd(),
            Path.cwd() / "target" / "debug",
            Path.cwd() / "target" / "release",
            Path("/usr/local/lib"),
            Path("/usr/lib"),
        ]
        for d in search_paths:
            so = d / "libverax_core_ffi.so"
            if so.exists():
                return str(so)
        raise RuntimeError(
            "libverax_core_ffi.so not found. "
            "Set VERAX_LIB_PATH or run from the repo root."
        )

    @classmethod
    def lib(cls):
        if cls._lib is None:
            path = cls._find_lib()
            cls._lib = ctypes.CDLL(path)
            cls._setup()
        return cls._lib

    @classmethod
    def _setup(cls):
        lib = cls._lib

        lib.axiom_version.restype = ctypes.c_char_p

        lib.axiom_verify_ed25519.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
            ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.axiom_verify_ed25519.restype = ctypes.c_int

        lib.axiom_free.argtypes = [ctypes.c_void_p]
        lib.axiom_free.restype = None

        lib.axiom_verify_composite.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
            ctypes.POINTER(ctypes.c_size_t),
        ]
        lib.axiom_verify_composite.restype = ctypes.c_int

        lib.axiom_payload_decode.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.POINTER(ctypes.c_uint8),    # out_has_timestamp
            ctypes.POINTER(ctypes.c_uint64),   # out_timestamp
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(ctypes.c_uint8),
        ]
        lib.axiom_payload_decode.restype = ctypes.c_int


def version() -> str:
    """Return the library version string."""
    return _VeraxLib.lib().axiom_version().decode("utf-8")


def verify_ed25519(
    cose_bytes: bytes, pubkey: bytes
) -> bytes:
    """Verify an Ed25519 COSE_Sign1 message.

    Args:
        cose_bytes: The raw COSE_Sign1 bytes.
        pubkey: The 32-byte Ed25519 public key.

    Returns:
        The payload bytes on success.

    Raises:
        VeraxError: If verification fails.
    """
    lib = _VeraxLib.lib()

    cose_arr = (ctypes.c_uint8 * len(cose_bytes)).from_buffer_copy(cose_bytes)
    pk_arr = (ctypes.c_uint8 * len(pubkey)).from_buffer_copy(pubkey)
    out_payload = ctypes.POINTER(ctypes.c_uint8)()
    out_len = ctypes.c_size_t()

    rc = lib.axiom_verify_ed25519(
        cose_arr,
        len(cose_bytes),
        pk_arr,
        len(pubkey),
        ctypes.byref(out_payload),
        ctypes.byref(out_len),
    )

    if rc != 0:
        raise VeraxError(rc)

    payload_bytes = bytes(out_payload[: out_len.value])
    lib.axiom_free(out_payload)
    return payload_bytes


def verify_composite(
    cose_bytes: bytes, ed_pubkey: bytes, ml_dsa_pubkey: bytes
) -> bytes:
    """Verify a composite (Ed25519 + ML-DSA-65) COSE_Sign1 message.

    Args:
        cose_bytes: The raw COSE_Sign1 bytes.
        ed_pubkey: The 32-byte Ed25519 public key.
        ml_dsa_pubkey: The 1952-byte ML-DSA-65 public key.

    Returns:
        The payload bytes on success.

    Raises:
        VeraxError: If verification fails.
    """
    lib = _VeraxLib.lib()

    cose_arr = (ctypes.c_uint8 * len(cose_bytes)).from_buffer_copy(cose_bytes)
    ed_arr = (ctypes.c_uint8 * len(ed_pubkey)).from_buffer_copy(ed_pubkey)
    ml_arr = (ctypes.c_uint8 * len(ml_dsa_pubkey)).from_buffer_copy(ml_dsa_pubkey)
    out_payload = ctypes.POINTER(ctypes.c_uint8)()
    out_len = ctypes.c_size_t()

    rc = lib.axiom_verify_composite(
        cose_arr,
        len(cose_bytes),
        ed_arr,
        len(ed_pubkey),
        ml_arr,
        len(ml_dsa_pubkey),
        ctypes.byref(out_payload),
        ctypes.byref(out_len),
    )

    if rc != 0:
        raise VeraxError(rc)

    payload_bytes = bytes(out_payload[: out_len.value])
    lib.axiom_free(out_payload)
    return payload_bytes


class Payload:
    """Decoded Verax payload fields."""

    __slots__ = (
        "subject", "predicate", "timestamp",
        "object", "nonce", "lineage",
    )

    def __init__(self, subject, predicate, timestamp,
                 object_=None, nonce=None, lineage=None):
        self.subject = subject
        self.predicate = predicate
        self.timestamp = timestamp
        self.object = object_
        self.nonce = nonce
        self.lineage = lineage

    def __repr__(self):
        return (
            f"Payload(subject={self.subject.hex()}, "
            f"predicate={self.predicate})"
        )


def decode_payload(cbor_bytes: bytes) -> Payload:
    """Decode a Verax CBOR payload into structured fields.

    Args:
        cbor_bytes: Raw CBOR-encoded payload bytes.

    Returns:
        A Payload namedtuple-like object.
    """
    lib = _VeraxLib.lib()

    cbor_arr = (ctypes.c_uint8 * len(cbor_bytes)).from_buffer_copy(cbor_bytes)

    subject = (ctypes.c_uint8 * 32)()
    predicate = ctypes.c_uint32()
    has_timestamp = ctypes.c_uint8()
    timestamp = ctypes.c_uint64()
    has_object = ctypes.c_uint8()
    object_ = (ctypes.c_uint8 * 32)()
    has_nonce = ctypes.c_uint8()
    nonce = (ctypes.c_uint8 * 32)()
    has_lineage = ctypes.c_uint8()
    lineage = (ctypes.c_uint8 * 32)()

    rc = lib.axiom_payload_decode(
        cbor_arr,
        len(cbor_bytes),
        subject,
        predicate,
        has_timestamp,
        timestamp,
        has_object,
        object_,
        has_nonce,
        nonce,
        has_lineage,
        lineage,
    )

    if rc != 0:
        raise VeraxError(rc)

    return Payload(
        subject=bytes(subject),
        predicate=predicate.value,
        timestamp=timestamp.value if has_timestamp.value else None,
        object_=bytes(object_) if has_object.value else None,
        nonce=bytes(nonce) if has_nonce.value else None,
        lineage=bytes(lineage) if has_lineage.value else None,
    )


def test_from_vectors(vector_path: str, pubkey_hex: str) -> int:
    """Test all valid vectors from the JSON test vector file.

    Args:
        vector_path: Path to test_vectors.json.
        pubkey_hex: Hex-encoded 32-byte Ed25519 public key.

    Returns:
        Number of vectors tested.
    """
    with open(vector_path) as f:
        data = json.load(f)

    pubkey = bytes.fromhex(pubkey_hex)
    tested = 0

    for vec in data["vectors"]:
        if not vec["is_valid"]:
            continue

        cose = bytes.fromhex(vec["cose_hex"])
        payload_bytes = verify_ed25519(cose, pubkey)
        assert payload_bytes == bytes.fromhex(vec["payload_cbor_hex"]), (
            f"Mismatch for {vec['name']}"
        )

        payload = decode_payload(payload_bytes)
        assert payload.subject == bytes.fromhex(vec["payload"]["subject_hex"])

        tested += 1

    return tested


if __name__ == "__main__":
    import sys

    repo_root = Path(__file__).resolve().parent.parent.parent.parent
    vectors = repo_root / "tests" / "test_vectors.json"

    pubkey = (
        "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
    )

    n = test_from_vectors(str(vectors), pubkey)
    print(f"verax-core {version()}: {n} test vectors PASS")
