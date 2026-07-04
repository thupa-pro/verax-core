#ifndef AXIOM_CORE_H
#define AXIOM_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns a null-terminated version string (static, no free needed). */
const char* axiom_version(void);

/* ----- Verification ----- */

/* Verify an ML-DSA-65-only COSE_Sign1 message. Returns 0 on success. */
int axiom_verify_mldsa65_only(const uint8_t* cose_data, size_t cose_len,
                               const uint8_t* pubkey_data, size_t pubkey_len,
                               uint8_t** out_payload, size_t* out_len);

/* Verify an Ed25519 COSE_Sign1 message. Returns 0 on success. */
int axiom_verify_ed25519(const uint8_t* cose_data, size_t cose_len,
                          const uint8_t* pubkey_data, size_t pubkey_len,
                          uint8_t** out_payload, size_t* out_len);

/* Verify a composite Ed25519+ML-DSA-65 COSE_Sign1 message. Returns 0 on success. */
int axiom_verify_composite(const uint8_t* cose_data, size_t cose_len,
                            const uint8_t* ed_pubkey_data, size_t ed_pubkey_len,
                            const uint8_t* ml_dsa_pubkey_data, size_t ml_dsa_pubkey_len,
                            uint8_t** out_payload, size_t* out_len);

/* ----- Full Verification (with chain + revocation) ----- */

/* Byte slice descriptor for passing arrays of data. */
typedef struct {
    const uint8_t* data;
    size_t len;
} FfiSlice;

/* Result of axiom_verify_full. */
typedef struct {
    int return_code;
    uint8_t* payload;
    size_t payload_len;
    uint8_t* warnings;
    size_t warnings_len;
} FfiVerifyResult;

/*
 * Full protocol verification with trust store, chain, and revocation cache.
 *
 * Parameters:
 *   cose_data / cose_len       - COSE statement to verify
 *   pubkey_data / pubkey_len   - 32-byte Ed25519 public key
 *   trusted_log_key_data / trusted_log_key_len - 32-byte CT log public key (or 0/null)
 *   chain_slices / chain_count - array of FfiSlice referencing chain statements
 *   revoked_csv               - comma-separated hex hashes of revoked statements (or NULL)
 *   not_revoked_csv            - comma-separated hex hashes of non-revoked statements (or NULL)
 *   checkpoint_timestamp       - STH timestamp for revocation cache (0 to ignore)
 *   out_result                 - receives verification result; payload+warnings must be freed with axiom_free
 *
 * Returns: 0 if statement is valid, non-zero error code otherwise.
 */
int axiom_verify_full(const uint8_t* cose_data, size_t cose_len,
                       const uint8_t* pubkey_data, size_t pubkey_len,
                       const uint8_t* trusted_log_key_data, size_t trusted_log_key_len,
                       const FfiSlice* chain_slices, size_t chain_count,
                       const char* revoked_csv,
                       const char* not_revoked_csv,
                       uint64_t checkpoint_timestamp,
                       FfiVerifyResult* out_result);

/* ----- Signing ----- */

/* Sign a payload CBOR with Ed25519. Returns allocated COSE bytes (free with axiom_free). */
int axiom_sign_ed25519(const uint8_t* payload_data, size_t payload_len,
                        const uint8_t* key_data, size_t key_len,
                        uint8_t** out_sig, size_t* out_sig_len);

/* Sign a payload CBOR with Ed25519 + ML-DSA-65 composite. */
int axiom_sign_composite(const uint8_t* payload_data, size_t payload_len,
                          const uint8_t* ed_key_data, size_t ed_key_len,
                          const uint8_t* ml_seed_data, size_t ml_seed_len,
                          uint8_t** out_sig, size_t* out_sig_len);

/* ----- PII Shredding ----- */

/* Encrypt PII data. Returns allocated ciphertext (free with axiom_free). */
int axiom_encrypt_pii(const uint8_t* key_data, size_t key_len,
                       const uint8_t* plaintext_data, size_t plaintext_len,
                       uint8_t** out_ct, size_t* out_ct_len);

/* Decrypt PII data. Returns allocated plaintext (free with axiom_free). */
int axiom_decrypt_pii(const uint8_t* key_data, size_t key_len,
                       const uint8_t* ct_data, size_t ct_len,
                       uint8_t** out_pt, size_t* out_pt_len);

/* Shredding commit: encrypt + produce commitment. Both outputs must be freed with axiom_free. */
int axiom_shredding_commit(const uint8_t* key_data, size_t key_len,
                            const uint8_t* plaintext_data, size_t plaintext_len,
                            uint8_t** out_ct, size_t* out_ct_len,
                            uint8_t** out_comm, size_t* out_comm_len);

/* ----- Payload ----- */

/* Encode an Axiom payload to CBOR. Returns allocated CBOR bytes (free with axiom_free). */
int axiom_encode_payload(const uint8_t* subject_data, size_t subject_len,
                          uint32_t predicate,
                          uint8_t** out_cbor, size_t* out_cbor_len);

/* Decode a CBOR payload into its fields. */
int axiom_payload_decode(const uint8_t* cbor_data, size_t cbor_len,
                          uint8_t* out_subject,
                          uint32_t* out_predicate,
                          uint64_t* out_timestamp,
                          uint8_t* out_has_object,
                          uint8_t* out_object,
                          uint8_t* out_has_nonce,
                          uint8_t* out_nonce,
                          uint8_t* out_has_lineage,
                          uint8_t* out_lineage);

/* Free memory allocated by any axiom_* function. */
void axiom_free(void* ptr);

#ifdef __cplusplus
}
#endif

#endif /* AXIOM_CORE_H */
