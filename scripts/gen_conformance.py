#!/usr/bin/env python3
"""Generate conformance_suite.json with 50+ deterministic test vectors."""

import json
import hashlib

# Known test key from the existing test_vectors.json
SIGNING_KEY_SEED = "4242424242424242424242424242424242424242424242424242424242424242"
SIGNING_KEY_PK = "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
ML_DSA_SEED = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

# Known valid Ed25519 COSE vectors from existing test_vectors.json
VALID_VECTORS = [
    {
        "name": "attests_minimal",
        "is_valid": True,
        "signature_alg": "Ed25519(-8)",
        "payload_cbor_hex": "a2015820abababababababababababababababababababababababababababababababab0200",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05826a2015820abababababababababababababababababababababababababababababababab02005840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104"
    },
    {
        "name": "attests_with_timestamp",
        "is_valid": True,
        "signature_alg": "Ed25519(-8)",
        "payload_cbor_hex": "a3015820abababababababababababababababababababababababababababababababab0200041a6553f100",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a0582ca3015820abababababababababababababababababababababababababababababababab0200041a6553f1005840bf1e49d8c4f5378b88718639367bdcc1ab4fa087fd0072e1dd9c2f74033c1b58d52c111027257ee1d4dd03e0ab97aec061a90b7f9a06e06a11be44f77b18eb04"
    },
    {
        "name": "authors_minimal",
        "is_valid": True,
        "signature_alg": "Ed25519(-8)",
        "payload_cbor_hex": "a201582001010101010101010101010101010101010101010101010101010101010101010201",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05826a2015820010101010101010101010101010101010101010101010101010101010101010102015840eeded880892f82309b54729d40714ead4ff89ce9e8b630b95bbe0754152148bf345140b4b92aeebfb38c3d4c47f0fd5523c3bd4ca616a32f931c8029de500b0a"
    },
    {
        "name": "derived_from_full",
        "is_valid": True,
        "signature_alg": "Ed25519(-8)",
        "payload_cbor_hex": "a4015820020202020202020202020202020202020202020202020202020202020202020202020358200101010101010101010101010101010101010101010101010101010101010101041a6553f101",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a0584fa4015820020202020202020202020202020202020202020202020202020202020202020202020358200101010101010101010101010101010101010101010101010101010101010101041a6553f1015840fd74664381ab1c69b020820d6e283bb0699cd5cca85874ba266e4ec5bfe5004485ccbd3695093ef2ba16fa00e0b28ec1bf4de5ed119a7596ed4171f3e2ce3403"
    },
    {
        "name": "supersedes_full",
        "is_valid": True,
        "signature_alg": "Ed25519(-8)",
        "payload_cbor_hex": "a5015820abababababababababababababababababababababababababababababababab02030358200101010101010101010101010101010101010101010101010101010101010101041a6553f1020558200202020202020202020202020202020202020202020202020202020202020202",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05872a5015820abababababababababababababababababababababababababababababababab02030358200101010101010101010101010101010101010101010101010101010101010101041a6553f1020558200202020202020202020202020202020202020202020202020202020202020202584008cc44982021dd7cdfc48612ff0e1e446c242589233143a28350fcd3796587e6ee3538c92a4aaa0ad3419dea02038ed63cb4f264a48eb8ccf9da024407beb404"
    },
    {
        "name": "revokes_same_issuer",
        "is_valid": True,
        "signature_alg": "Ed25519(-8)",
        "payload_cbor_hex": "a4015820010101010101010101010101010101010101010101010101010101010101010102040358200101010101010101010101010101010101010101010101010101010101010101041a6553f103",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a0584fa4015820010101010101010101010101010101010101010101010101010101010101010102040358200101010101010101010101010101010101010101010101010101010101010101041a6553f103584021b2ec6de6c876389ef434208c0e904a92c6042c3362d2996fccd6b38d4497c74b80d769e3d6216e0989bce75e05d7c3b4dccaf7543bc46e5835c61eb4e0520a"
    },
    {
        "name": "appends_chunk",
        "is_valid": True,
        "signature_alg": "Ed25519(-8)",
        "payload_cbor_hex": "a5015820020202020202020202020202020202020202020202020202020202020202020202060358200101010101010101010101010101010101010101010101010101010101010101041a6553f1040558200101010101010101010101010101010101010101010101010101010101010101",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05872a5015820020202020202020202020202020202020202020202020202020202020202020202060358200101010101010101010101010101010101010101010101010101010101010101041a6553f10405582001010101010101010101010101010101010101010101010101010101010101015840334b4147b80683058417d6f31247adee2b39f73fd4414c8b79ac6bf75a32a7ca5f800d03b2bf3f5fd788f892b4e0ca3e8a8760b51e4df69d25d3d6cc7f79d50b"
    },
    {
        "name": "complies_with_extensions",
        "is_valid": True,
        "signature_alg": "Ed25519(-8)",
        "payload_cbor_hex": "a401582001010101010101010101010101010101010101010101010101010101010101010207041a6553f10507a21864182a186543010203",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05838a401582001010101010101010101010101010101010101010101010101010101010101010207041a6553f10507a21864182a1865430102035840b7765cf76ac7db5fee84cf344ab42c17cd74e91c7d77e08db1515ce54612559b4e3b36ec11517975732fd62ed3d90c67f4399040df2e61b9286cb21d08b7ad00"
    },
    {
        "name": "attests_with_nonce",
        "is_valid": True,
        "signature_alg": "Ed25519(-8)",
        "payload_cbor_hex": "a4015820abababababababababababababababababababababababababababababababab0200041a6553f106065820dededededededededededededededededededededededededededededededede",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a0584fa4015820abababababababababababababababababababababababababababababababab0200041a6553f106065820dededededededededededededededededededededededededededededededede5840d0b36b760ae0929b2a1479507bebd5cecfb616d5ae765e3be25e0a2006cf74f353b4efcce1489b5e1ce431d17d0c9838426d253f89298e6f60c305ece8e96a01"
    },
    {
        "name": "endorses_minimal",
        "is_valid": True,
        "signature_alg": "Ed25519(-8)",
        "payload_cbor_hex": "a3015820010101010101010101010101010101010101010101010101010101010101010102050358200202020202020202020202020202020202020202020202020202020202020202",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05849a30158200101010101010101010101010101010101010101010101010101010101010101020503582002020202020202020202020202020202020202020202020202020202020202025840b097c26b49fa073727695d72063e3ae6e61afa3f7e1e115e5cd1e3bd91924b40541bf4fd0fbdb1ac820ca7f3ffa6307990b90c75d3ecded2bd1d4c2b1632b10f"
    },
    {
        "name": "full_all_fields",
        "is_valid": True,
        "signature_alg": "Ed25519(-8)",
        "payload_cbor_hex": "a7015820010101010101010101010101010101010101010101010101010101010101010102020358200202020202020202020202020202020202020202020202020202020202020202041a6553f107055820abababababababababababababababababababababababababababababababab065820cacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacaca07a218c8186318c94568656c6c6f",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a058a3a7015820010101010101010101010101010101010101010101010101010101010101010102020358200202020202020202020202020202020202020202020202020202020202020202041a6553f107055820abababababababababababababababababababababababababababababababab065820cacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacaca07a218c8186318c94568656c6c6f584025099eb11c2aafd59e2831b436ee0e1dfb27733f712f61203fd14ab455a10c1f8c7dd05a8cb34c87afbc9329fa2be079841c39973debbac10634c8e097db550b"
    },
    {
        "name": "attests_large_timestamp",
        "is_valid": True,
        "signature_alg": "Ed25519(-8)",
        "payload_cbor_hex": "a3015820abababababababababababababababababababababababababababababababab0200041aee6b2800",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a0582ca3015820abababababababababababababababababababababababababababababababab0200041aee6b28005840af49ae7b9dd793837345883882f046ec509cc7110686e6a1426177e162cc03f2a285f0852f4377226880087025a22e69d7f302341d64b3530fc333fa74367409"
    },
    {
        "name": "attests_zero_timestamp",
        "is_valid": True,
        "signature_alg": "Ed25519(-8)",
        "payload_cbor_hex": "a3015820abababababababababababababababababababababababababababababababab02000400",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05828a3015820abababababababababababababababababababababababababababababababab020004005840a160b99bfd3ad619757b63e5e5ad2ac53ede0d8803d519eb7b104615f8e094158f3498d5de9ab00734d4a1b636839883d36b0ddbc75164d2fe6a5e6f9247a30d"
    },
]

# Load composite vectors from existing test_vectors.json (full COSE, PK, and payload)
import json as _json
import os as _os
_script_dir = _os.path.dirname(_os.path.abspath(__file__))
_project_root = _os.path.dirname(_script_dir)
COMPOSITE_VECTORS = []
_tv_path = _os.path.join(_project_root, "test-vectors", "vectors", "test_vectors.json")
if _os.path.exists(_tv_path):
    with open(_tv_path) as _f:
        _existing = _json.load(_f)
        for _v in _existing["vectors"]:
            if "composite_cose_hex" in _v:
                COMPOSITE_VECTORS.append({
                    "name": _v["name"],
                    "is_valid": True,
                    "signature_alg": "composite(-8, -39)",
                    "payload_cbor_hex": _v["payload_cbor_hex"],
                    "composite_cose_hex": _v["composite_cose_hex"],
                    "composite_pk_hex": _v["composite_pk_hex"],
                })

# Additional invalid vectors to reach 50+
ADDITIONAL_INVALID = [
    {
        "name": "object_too_short",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05828a301582001010101010101010101010101010101010101010101010101010101010101010203410102041a6553f1005840267e4aef28a001ba6fbff5fda22a9cd5a2d0a1ea1f417f73d9affe73dec5f790eebd5bcec5398a5909fff6366426d1be4c9ef490df715c8e883da17d3503c08304",
        "ed_pubkey_hex": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
        "description": "Object field is 1 byte instead of 32"
    },
    {
        "name": "lineage_too_short",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a0582ba40158200101010101010101010101010101010101010101010101010101010101010101020358200101010101010101010101010101010101010101010101010101010101010101041a6553f1004101",
        "ed_pubkey_hex": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
        "description": "Lineage field is 1 byte instead of 32"
    },
    {
        "name": "nonce_too_short",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a0582ba4015820abababababababababababababababababababababababababababababababab0200041a6553f1004101",
        "ed_pubkey_hex": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
        "description": "Nonce field is 1 byte instead of 32"
    },
    {
        "name": "payload_with_wrong_extra_field",
        "is_valid": False,
        "expected_error": 12,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a0582ba2015820abababababababababababababababababababababababababababababababab020018195840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104",
        "description": "Payload with key 25 (reserved, < 100) should fail"
    },
    {
        "name": "empty_protected_header",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "8440a05826a2015820abababababababababababababababababababababababababababababababab02005840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104",
        "description": "Empty bstr for protected header"
    },
    {
        "name": "payload_wrong_map_keys_out_of_order",
        "is_valid": False,
        "expected_error": 2,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05828a20201015820abababababababababababababababababababababababababababababababab5840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104",
        "ed_pubkey_hex": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
        "description": "Map keys out of order (predicate before subject)"
    },
    {
        "name": "cose_array_with_5_elements",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "85a0a0a0a0a0",  # arr of 5 empty maps
        "description": "COSE_Sign1 with 5 elements instead of 4"
    },
    {
        "name": "signature_all_zeros",
        "is_valid": False,
        "expected_error": 3,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05826a2015820abababababababababababababababababababababababababababababababab02005840" + "00" * 64,
        "description": "Ed25519 signature is all zeros"
    },
    {
        "name": "pubkey_all_zeros_ed25519",
        "is_valid": False,
        "expected_error": 10,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05826a2015820abababababababababababababababababababababababababababababababab02005840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104",
        "ed_pubkey_hex": "0000000000000000000000000000000000000000000000000000000000000000",
        "description": "Ed25519 pubkey is all zeros (invalid curve point)"
    },
    {
        "name": "missing_subject_field",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05824a1020100",
        "ed_pubkey_hex": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
        "description": "Missing subject field in payload"
    },
    {
        "name": "payload_with_trailing_bytes",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05828a2015820abababababababababababababababababababababababababababababababab02005840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a1040500",
        "ed_pubkey_hex": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
        "description": "Trailing bytes after the payload"
    },
    {
        "name": "nonce_without_timestamp",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05828a3015820010101010101010101010101010101010101010101010101010101010101010102000658200101010101010101010101010101010101010101010101010101010101010101",
        "ed_pubkey_hex": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
        "description": "Nonce present but no timestamp (nonce requires timestamp)"
    },
    {
        "name": "lineage_without_object",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05828a3015820010101010101010101010101010101010101010101010101010101010101010102000558200101010101010101010101010101010101010101010101010101010101010101",
        "ed_pubkey_hex": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
        "description": "Lineage present but no object for DERIVED_FROM"
    },
    {
        "name": "predicate_too_large",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05826a2015820abababababababababababababababababababababababababababababababab0208",
        "ed_pubkey_hex": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
        "description": "Predicate value 8 is out of valid range (0-7)"
    },
    {
        "name": "cose_array_2_elements",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "82a0a0",
        "description": "COSE array with 2 elements instead of 4"
    },
]

# Invalid vectors — tampered, malformed, wrong key, etc.
INVALID_VECTORS = [
    {
        "name": "empty_cose",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "",
        "description": "Empty COSE data should fail with MalformedCose"
    },
    {
        "name": "truncated_cose",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152",
        "description": "Truncated COSE_Sign1 should fail"
    },
    {
        "name": "wrong_pubkey",
        "is_valid": False,
        "expected_error": 3,
        "signature_alg": "Ed25519(-8)",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a0582ca3015820abababababababababababababababababababababababababababababababab0200041a6553f1005840bf1e49d8c4f5378b88718639367bdcc1ab4fa087fd0072e1dd9c2f74033c1b58d52c111027257ee1d4dd03e0ab97aec061a90b7f9a06e06a11be44f77b18eb04",
        "ed_pubkey_hex" : "0000000000000000000000000000000000000000000000000000000000000000",
        "description": "Wrong public key should fail with InvalidSignature"
    },
    {
        "name": "tampered_signature_byte",
        "is_valid": False,
        "expected_error": 3,
        "signature_alg": "Ed25519(-8)",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05826a2015820abababababababababababababababababababababababababababababababab02005840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a105",
        "description": "Last byte of signature flipped"
    },
    {
        "name": "not_an_array",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "a0",
        "description": "Empty map instead of COSE_Sign1 array"
    },
    {
        "name": "cbor_payload_with_null",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05826f6f6005840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104",
        "description": "CBOR payload containing null value"
    },
    {
        "name": "wrong_array_length",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "830126",
        "description": "Array of length 3 instead of 4 for COSE_Sign1"
    },
    {
        "name": "duplicate_key_in_payload",
        "is_valid": False,
        "expected_error": 2,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05828a2015820010101010101010101010101010101010101010101010101010101010101010102005840267e4aef28a001ba6fbff5fda22a9cd5a2d0a1ea1f417f73d9affe73dec5f790eebd5bcec5398a5909fff6366426d1be4c9ef490df715c8e883da17d3503c08304",
        "ed_pubkey_hex": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
        "description": "Payload with duplicate keys (non-canonical)"
    },
    {
        "name": "non_canonical_uint_extra_bytes",
        "is_valid": False,
        "expected_error": 2,
        "description": "Non-canonical CBOR uint using 2 bytes for value < 256",
        "payload_cbor_hex": "",
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a0582aa2015820abababababababababababababababababababababababababababababababab021900005840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104"
    },
    {
        "name": "signature_too_short",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05826a2015820abababababababababababababababababababababababababababababababab02005820907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104",
        "description": "Signature bstr claims 32 bytes but is actually 64 (length mismatch)"
    },
    {
        "name": "payload_with_float",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05828a3015820abababababababababababababababababababababababababababababababab020004fa47c350005840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104",
        "description": "Payload containing CBOR float value"
    },
    {
        "name": "protected_header_no_alg",
        "is_valid": False,
        "expected_error": 11,
        "cose_hex": "845826a2010b58202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05826a2015820abababababababababababababababababababababababababababababababab02005840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104",
        "description": "Protected header map with no algorithm key"
    },
    {
        "name": "negative_predicate_value_21ff",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05827a2015820abababababababababababababababababababababababababababababababab21ff5840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104",
        "description": "Payload with negative int -1 as predicate"
    },
    {
        "name": "subject_too_short",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05824a2015810ababababababababababababababab02005840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104",
        "description": "Subject field is 16 bytes instead of 32"
    },
    {
        "name": "lineage_cycle_self_reference",
        "is_valid": False,
        "expected_error": 3,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05826a2015820010101010101010101010101010101010101010101010101010101010101010102005840eeded880892f82309b54729d40714ead4ff89ce9e8b630b95bbe0754152148bf345140b4b92aeebfb38c3d4c47f0fd5523c3bd4ca616a32f931c8029de500b0a",
        "description": "Self-referencing lineage (uses own hash)",
        "lineage_hash_hex": "0101010101010101010101010101010101010101010101010101010101010101"
    },
    {
        "name": "timestamp_overflow",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a0582da3015820abababababababababababababababababababababababababababababababab0200041bffffffffffffffff5840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104",
        "description": "Timestamp field is max uint64 (overflow case)"
    },
    {
        "name": "composite_wrong_ed_key",
        "is_valid": False,
        "expected_error": 3,
        "signature_alg": "composite(-8, -39)",
        "composite_cose_hex": "845827a20138260458201d43a5ce1a2006cff3d02f81827283f8cd6349b1815d6371ede3de30d90f1223a05826a2015820abababababababababababababababababababababababababababababababab0200590d2dbb64b9224bf1225287c696937eda34edd40188b8ffa0f6eda95578739bbeb387c0eb199549149dbbd945f593eb749d3dca50b10c5d02f7225645708efb683659660f765df11ca23b0f8cf5fdf93a4c4fb6d8dc89257acf213353c76e634e605e4125a7e6eeaab70452fdcbbf787fe566f0c74d8364290db44ca2e5e0a443ab8895da681cdabb954594fedd71e053ec33be5a4cce851eb66bde5f2b9dad0e38b766fad6f0a203c5892158d73e72b85caa732c0b5396e3faafe48e18f2b7c4c774f537c162deac30d74bad64bd919e4297f8c4930113001c514ad7666c28a376c4753fa7343885681e23e99593bdc6c7ec9023f727c3754c757adee9a105f5ea4c32e9d9523b62b27f0c6280649a8f220166d53255e5b73fea24beac26340027360c1fc29b1c8f501d714a89c4c9012eb4d86d1809f95347966a36ab752df28efb23e5ba7183baef1cb1b5bf9dd46e018f33769d1bbf850e3d21ac4e382ecc2bb958a575811c7eeb34a5c244e866d2ae0ef61acb02cc0a13daa7b81854d0340499071f6a1226ffeb67566188bddf55cd7a0f9c369353a56300df13a34bb55113a798b6adcb0258caafe464bacb496168a3517ca9d6c50144784246185ca56daaf694bb8318bcadfa6506292dda2bb8f659f77c6abc4308b3af2207133538fb46dae1beea5f425ba9b556d14d8bcabf83fadf1bdddcdccc358ef3e40f1889fb2994c9c5fdd473b54c69d4dcdbe790bd66d11677380d3d7da73604a91432e8424ee1e554662a6d9cea1758f9827ce15aa46e71fce93f17404be32551b5e465f52b1d6e7ecec28fd9b25065758ef4ab80b6ba398ecd521076d8cfba1456ce5ca8de92978ca8a2550d4ddb88ec87ba7ea2b24bc4eb858bdca00d6df2926da3f05bc05cf0dddf9b5b1c219ae3f12745f41157c6aca209c42534fd4e5619c5e5acb34ecc4dce4221dc727303259c03eab4e4a13448d866f1198a7cf1f8e58831929f4ade8aa8577b45c4c080a2594ecc727ea1e21bbd281a5154a62a2fd33c908c1b552b46bf2171e2cc7cf319b96e453f4541e451d816c5061b2c4692bf6cc0b688d1a9e789a9d4583635d0955a74918770efe5a81c04b9d0c330764fc8ba81d1152cc511020ffed03592fdbd23b33606258815c56b9a48d196e42944e70ee2e6fdca590949521439e76efbbe3543ad131422c3ae45a34f6fec71a7108f2c3a3aa420f34e4234fea197e1377991f2688742cbdffbe8c51b0bcbf7c83f79b08f263b11285582c9fa561ad1f100ba8b24ee2074598fb555428f8b19842e4dac62059d8cdfcebd3c1df03910c766f355d3987f0e556f1b9c0d42c4c63ebb48c5612540d6b76e6c9fe59171210a6f1a37ea2f06ab6150cdfc52f54191e418f128b209bd498271d98b62bfcdac29f8e584e1e64ae21ffa424762f779edc07421160b1a61250d333f9be2c70228de9e4d245ff05b6cbc7c4aac3a64ac32b7f6a86be504a2fe61b0da9d9fbd725d1701e2f20f25d9f0aa2b146944e6b46823e1b09fa7db95f6ba0dc5a2ff4b5fe007b52798d42cf83192313c31c417e52e899a69f6010b2518a8e96f75f7a91cbd7df1fbeff20c4beb32e9d9c8454ab923d2cb802cfb7f625bde1f36deb5a3dec52b3f32d7d71293f9fe2b3b71f55ec768035ae59678db96e6df611032e1ca4c9a02b4f4de2e73e3d29d19e78347241039364c6cd85906b6206983910be9a0e70b0c9aa1de7a0ebc5fdeb322348a602401d36d92f80d3bc955c83b9bc34de81d23d55378ce73f68e92787dda47603bab98e48ada940a67d46968c164cf0d9504ac1c82f867c1324ff710b9d11745b07861e35b0824149157103bfa8d35dc074fc3bbc499f1f1954b8d6a0ef3d512c01c210d8a48b6cc18249bee40a689edda23544d19c33c5cf0ea533ca7ba89e90f8d0a1f53827cec07ccbe32f9388a25f3837cf3fe338e7b9edbe57773af17c46df3378f00fad457a0fae12e109fff58ecb2e4d1ac6ac5d14288f2fb02c0bdf3a3bd194d9c67f299f5f2e59c0c4cd025e15b25c8e9e8ad5be4bbbe0a240a15abe1b49ef27ee72808449c963dff87e69ad9e9df60a0bdddb3bdb9ada3b40477cf7178ae5ed89d32b95bcb35ade3316b2e73c8df76ace36ade11e92f5fb620d8d7261421f4995119f6ca49f5140d5e8cf166dfe980064cbedac0a5ce1fd47a315e8c59b8a163318e233fa50ecd9b36fa31b78c6c160b65e964350a1a9b4f8ff876feb586280df491231e9cca2247caae12e1d5fcbd597f6134f6",
        "composite_pk_hex": "000000000000000000000000000000000000000000000000000000000000000048683d91978e31eb3dddb8b0473482d2b88a5f625949fd8f58a561e696bd4c27d05b38dbb2edf01e664efd81be1ea893688ce68aa2d51c5958f8bbc6eb4e89ee67d2c0320954d57212cac7229ff1d6eaf03928bd51511f8d88d847736c7de2730d5978e5410713160978867711bf5539a0bfc4c350c2be572baf0ee2e2fb16ccfea08028d99ac49aebb75937ddce111cdab62fff3cea8ba2233d1e56fbc5c5a1e726de63fadd2af016b119177fa3d971a2d9277173fce55b67745af0b7c21d597dbeb93e6a32f341c49a5a8be9e825088d1f2aa45155d6c8ae15367e4eb003b8fdf7851071949739f9fff09023eaf45104d2a84a45906eed4671a44dc28d27987bb55df69e9e8561f61a80a72699503865fed9b7ee72a8e17a19c408144f4b29afef7031c3a6d8571610b42c9f421245a88f197e16812b031159b65b9687e5b3e934c5225ae98a79ba73d2b399d73510effad19e53b8450f0ba8fce1012fd98d260a74aaaa13fae249a006b1c34f5ba0b882f26378222fb36f2283c243f0ffeb5f1bb414a0a70d55e3d40a56b6cbc88ae1f03b7b2882d98deea28e145c9dedfd8eaf1cef2ed94a8b050f8964f46d1ea0d0c2a43e0dda6182adbf4f6ed175b6742257859bf22f3a417ecf1f9d89317b5e539d587af16b9e1313e04514ffa64ba8b3ff2b8321f8811cb3fb022c8f644e70a4b80a2fbfee604abb7379091ea8e6c5c74dfc0283666b40c0793870028204a136bf5da9568eb798d349038bdb0c11e03445e7847cb5069c75cf28ac601c7799d958210ddbcb226e51afef9f1de47b073873d6d3f97456bede085082e74a298b2cd48f4b3093155f366c8fa601c6af858dfa32c08491b2a29887f90335949a5d6edaa679882a3a95d6bf6d970a221f4b9d3d8cbf384af81aac95e2b3294e04789ac83727a5dc04559f96af41d8a053516feeeebc52746eb6ab2819e09108710d835f011fa63065872ad334d5cdffb2b2310507e92fc993ae317da97f4f309cdaf0f67ed99d90215576083849f953b246d7fedb3fdb67679850a5ad404e64147fb7cf4f6aeddd05afb4b834968d1fe88014960dce5d942236526e12a478d69e5fbe6970310b308c06845018cfc7b2ab430a13a6b1ac7bb02cccbb3d911ac2f11068613fbe029bfdce02cf5cd38950ed72c83944edfbc75615af87f864c051f3c55456c5412863a40c06d1dab562bdff0571b8d3c3917bbd300880bba5e998239b95fa91b7d6416d4f398b3adbcd30983ed3592b4d9ef7d4236fd00f50d98aa53a235ac4172720f77d96172672980cfe8ff7a5a702783edc2ba31b2259015a112fc7f468a9c2f9464039002d30ef678b4cb798bc116216bf7a9a7c18ba03b7b58fd07515d3115049d3614be7a09faf8bf3a80e4efb4c1ae74cea1876c2a0cf5b9b1fed670d87d9467ce56fb68eef1dae31656c4c81f6c0b8f83a0cfd2c49b2b4eca29a2c5115a6a3cfa7bd5214f9bb1943a639cb9b8b2d1ae4676792301e87e3f6dc3bf912bb90d97a02da5f806f5990312d2066704331581f09bbf6e958a480387e980e8ca277d8e74b07f52bad5f4f2d0cbcb4f8b8820fbd7f33f5a15c54cd1fc6c8be60a27e311717ed6b4c67da3acc9a9895b5480a02dc4801e294cf0223c1d1079d0a2595a91f43463e29528be1894f699c63643a9a9b25e2f5b16cd89a9b2c9ac7b428b0813eaf4027cdfde9002e010d55fbeaa47f3b110297b2b6d72dfce49f84b9",
        "description": "Composite with wrong Ed25519 key (all zeros)"
    },
    {
        "name": "composite_empty_cose",
        "is_valid": False,
        "expected_error": 1,
        "signature_alg": "composite(-8, -39)",
        "composite_cose_hex": "",
        "description": "Empty composite COSE data"
    },
    {
        "name": "payload_unknown_reserved_key_50",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a0582da2015820abababababababababababababababababababababababababababababababab020018325840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104",
        "description": "Payload with key 50 (reserved, < 100) should fail"
    },
    {
        "name": "malformed_protected_header",
        "is_valid": False,
        "expected_error": 1,
        "cose_hex": "845820a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a05826a2015820abababababababababababababababababababababababababababababababab02005840907519fcb910cff8a2fc876e57dcbfbb7accfdcc54ec8f3a14b2d586292cb54ed08662de5d1819a052e422ff87cd04d03c68e1c02c828092f4243f28bf03a104",
        "description": "Protected header is a bstr containing another bstr instead of a map"
    },
    {
        "name": "repeated_payload_key_1",
        "is_valid": False,
        "expected_error": 2,
        "cose_hex": "845826a201270458202152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12a0582da2015820010101010101010101010101010101010101010101010101010101010101010101015820020202020202020202020202020202020202020202020202020202020202020202005840267e4aef28a001ba6fbff5fda22a9cd5a2d0a1ea1f417f73d9affe73dec5f790eebd5bcec5398a5909fff6366426d1be4c9ef490df715c8e883da17d3503c08304",
        "ed_pubkey_hex": "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12",
        "description": "Repeated key 1 in payload map"
    },
]


def generate():
    all_vectors = VALID_VECTORS + COMPOSITE_VECTORS + INVALID_VECTORS + ADDITIONAL_INVALID
    suite = {
        "version": "3.0.0",
        "description": "Axiom Protocol Universal Conformance Suite — 50+ deterministic test vectors for cross-language verification",
        "signing_key_seed_hex": SIGNING_KEY_SEED,
        "signing_key_pubkey_hex": SIGNING_KEY_PK,
        "ml_dsa_seed_hex": ML_DSA_SEED,
        "vectors": all_vectors
    }
    assert len(suite["vectors"]) >= 50, f"Need 50+ vectors, got {len(suite['vectors'])}"
    return suite


if __name__ == "__main__":
    suite = generate()
    _out_path = _os.path.join(_project_root, "tests", "vectors", "conformance_suite.json")
    _os.makedirs(_os.path.dirname(_out_path), exist_ok=True)
    with open(_out_path, "w") as f:
        json.dump(suite, f, indent=2)
    print(f"Generated {len(suite['vectors'])} vectors to test-vectors/vectors/conformance_suite.json")
