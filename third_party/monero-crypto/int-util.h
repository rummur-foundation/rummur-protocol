/**
 * int-util.h — Portable stub replacing Monero's contrib/epee/include/int-util.h.
 *
 * The original includes <byteswap.h> and <endian.h> which are Linux-only.
 * This stub provides the same byte-swap macros using __builtin_bswap{16,32,64},
 * which are available in GCC and Clang on both macOS and Linux.
 *
 * Assumes a little-endian host (x86_64, ARM64 — all macOS and Linux targets
 * relevant to this project). swap*le = identity; swap*be = byte-reverse.
 */

#pragma once

#include <stdint.h>
#include <string.h>

// ─── 16-bit ───────────────────────────────────────────────────────────────────

static inline uint16_t swap16(uint16_t x) {
    return (uint16_t)((x << 8) | (x >> 8));
}
#define IDENT16(x)  ((uint16_t)(x))
#define SWAP16(x)   swap16(x)
#define SWAP16LE    IDENT16
#define SWAP16BE    SWAP16
#define swap16le(x) ((uint16_t)(x))
#define swap16be(x) swap16(x)

// ─── 32-bit ───────────────────────────────────────────────────────────────────

static inline uint32_t swap32(uint32_t x) {
    return __builtin_bswap32(x);
}
#define IDENT32(x)  ((uint32_t)(x))
#define SWAP32(x)   swap32(x)
#define SWAP32LE    IDENT32
#define SWAP32BE    SWAP32
#define swap32le(x) ((uint32_t)(x))
#define swap32be(x) swap32(x)

// ─── 64-bit ───────────────────────────────────────────────────────────────────

static inline uint64_t swap64(uint64_t x) {
    return __builtin_bswap64(x);
}
#define IDENT64(x)  ((uint64_t)(x))
#define SWAP64(x)   swap64(x)
#define SWAP64LE    IDENT64
#define SWAP64BE    SWAP64
#define swap64le(x) ((uint64_t)(x))
#define swap64be(x) swap64(x)

// ─── memcpy_swap64le ──────────────────────────────────────────────────────────
// On a little-endian host, swap64le is a no-op, so this is just memcpy.

static inline void memcpy_swap64le(void *dst, const void *src, size_t count) {
    memcpy(dst, src, count * sizeof(uint64_t));
}
