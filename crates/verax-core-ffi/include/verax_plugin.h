#ifndef VERAX_PLUGIN_H
#define VERAX_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Plugin ABI for Verax Protocol ─────────────────────────────────────────
 *
 * Implement these callbacks to provide custom trust store, key resolution,
 * statement fetching, and revocation logic.
 *
 * A plugin is a shared library (.so / .dylib / .dll) that exports a single
 * initializer function:
 *
 *   int verax_plugin_init(verax_plugin_t* plugin, void* userdata);
 *
 * The host calls verax_plugin_init() at load time, passing a zero-initialized
 * verax_plugin_t struct.  The plugin fills in the function pointers it wants
 * to override (any remaining NULL pointers use host defaults).
 */

/* Status / error codes used by plugin callbacks. */
#define VERAX_OK        0
#define VERAX_ERROR     1
#define VERAX_NOT_FOUND 2

/* Revocation status values for check_revoked(). */
#define VERAX_REV_STATUS_NOT_REVOKED 0
#define VERAX_REV_STATUS_REVOKED     1
#define VERAX_REV_STATUS_UNKNOWN     2

/* ─── Callbacks ──────────────────────────────────────────────────────────── */

/* Resolve a public key from its KID (32-byte BLAKE3 hash of the public key).
 *
 * Returns VERAX_OK and writes 32 bytes into out_pubkey on success.
 * Returns VERAX_NOT_FOUND if the KID is unknown.
 */
typedef int (*verax_resolve_key_fn)(
    const uint8_t kid[32],
    uint8_t out_pubkey[32],
    void* userdata
);

/* Fetch a statement (raw COSE bytes) by its BLAKE3 hash.
 *
 * Returns VERAX_OK and allocates out_bytes / sets out_len on success.
 * The caller frees the returned buffer via the free_fn callback.
 * Returns VERAX_NOT_FOUND if the hash is unknown.
 */
typedef int (*verax_fetch_statement_fn)(
    const uint8_t hash[32],
    uint8_t** out_bytes,
    size_t* out_len,
    void* userdata
);

/* Check whether a statement has been revoked in the log.
 *
 * Returns VERAX_OK and writes a status code into out_status:
 *   VERAX_REV_STATUS_NOT_REVOKED — definitively not revoked
 *   VERAX_REV_STATUS_REVOKED     — definitively revoked
 *   VERAX_REV_STATUS_UNKNOWN     — status unknown (offline, no cache)
 * Returns VERAX_ERROR on internal failure.
 */
typedef int (*verax_check_revoked_fn)(
    const uint8_t stmt_hash[32],
    uint64_t after_timestamp,
    int* out_status,
    void* userdata
);

/* Resolve a composite public key (Ed25519 + ML-DSA-65) from its KID.
 *
 * Returns VERAX_OK and writes 64 bytes (32 Ed25519 + 32 ML-DSA) into
 * out_composite_pubkey on success.
 * Returns VERAX_NOT_FOUND if the KID is unknown (Ed25519-only keys are
 * resolved via resolve_key instead).
 */
typedef int (*verax_resolve_composite_key_fn)(
    const uint8_t kid[32],
    uint8_t out_composite_pubkey[64],
    void* userdata
);

/* Free a buffer previously allocated by any plugin callback.
 *
 * Must handle NULL pointers safely (no-op).
 */
typedef void (*verax_free_fn)(
    void* ptr,
    void* userdata
);

/* ─── Plugin Struct ───────────────────────────────────────────────────────── */

typedef struct {
    /* Mandatory — all of these MUST be set by the plugin. */
    verax_resolve_key_fn          resolve_key;
    verax_fetch_statement_fn      fetch_statement;
    verax_check_revoked_fn        check_revoked;
    verax_free_fn                 free_fn;

    /* Optional — set to NULL if not needed. */
    verax_resolve_composite_key_fn resolve_composite_key;

    /* Reserved for future use — must be zeroed. */
    void* reserved[4];
} verax_plugin_t;

/* ─── Initializer ────────────────────────────────────────────────────────────
 *
 * Every plugin MUST export this function.  The host calls it once at load
 * time.  The plugin fills in the plugin struct with its callbacks.
 *
 * Returns VERAX_OK on success, VERAX_ERROR on failure.
 */
int verax_plugin_init(verax_plugin_t* plugin, void* userdata);

#ifdef __cplusplus
}
#endif

#endif /* VERAX_PLUGIN_H */
