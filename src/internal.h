/**
 * internal.h — C++ types and helpers shared across libxmrmsg implementation files.
 * Not part of the public API. Not installed.
 */

#pragma once

#include "libxmrmsg.h"
#include "monero_base58.h"

// Vendored Monero primitives (pure C — platform-independent)
#ifdef __cplusplus
extern "C" {
#endif
#include "crypto-ops.h"  // ge_p3, ge_scalarmult, ge_mul8, sc_reduce32, ...
#include "keccak.h"      // keccak()
#include "memwipe.h"     // memwipe()
#ifdef __cplusplus
}
#endif

#include <cstring>
#include <cstdlib>

// ─── Parsed Monero address ────────────────────────────────────────────────────

struct parsed_address_t {
    bool    is_subaddress;
    uint8_t spend_pk[XMRMSG_KEY_SIZE]; // spend pubkey (B for primary, D for subaddr)
    uint8_t view_pk[XMRMSG_KEY_SIZE];  // view pubkey  (A for primary, C for subaddr)
};

/**
 * Parse a 95-char base58 Monero address string.
 * Returns true on success. Accepts mainnet, stagenet, and testnet addresses,
 * both primary and subaddress.
 */
bool xmrmsg_parse_address(const char *address, parsed_address_t *out);

// ─── Byte helpers ─────────────────────────────────────────────────────────────

static inline void xor_bytes(uint8_t *dst, const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; i++) dst[i] ^= src[i];
}

static inline void secure_zero(void *buf, size_t len) {
    memwipe(buf, len);
}
