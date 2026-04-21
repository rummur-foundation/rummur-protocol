/**
 * internal.h — C++ types and helpers shared across libxmrmsg implementation files.
 * Not part of the public API. Not installed.
 */

#pragma once

#include "libxmrmsg.h"
#include "monero_base58.h"

// Vendored Monero primitives (pure C — platform-independent)
// crypto-ops.h and keccak.h are plain C headers; wrap them for C++ linkage.
// memwipe.h manages its own extern "C" guard (and pulls in C++ templates when
// compiled as C++), so it must be included outside our extern "C" block.
#ifdef __cplusplus
extern "C" {
#endif
#include "crypto-ops.h"  // ge_p3, ge_scalarmult, ge_mul8, sc_reduce32, ...
#include "keccak.h"      // keccak()
#ifdef __cplusplus
}
#endif
#include "memwipe.h"     // memwipe() — has its own extern "C" / C++ guards

#include <cstring>
#include <cstdlib>

// ─── Platform random ──────────────────────────────────────────────────────────
// arc4random_buf: macOS, BSDs, glibc >= 2.36.
// For older Linux fall back to getrandom(2) (kernel 3.17+).
#if defined(__linux__) && !defined(__GLIBC_PREREQ)
#  include <sys/random.h>
#  define PLATFORM_RANDOM(buf, len)  getrandom((buf), (len), 0)
#else
#  include <stdlib.h>
#  define PLATFORM_RANDOM(buf, len)  arc4random_buf((buf), (len))
#endif

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
