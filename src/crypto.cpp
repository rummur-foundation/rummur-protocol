/**
 * crypto.cpp — ECDH derivation, keystream generation, and key utilities.
 *
 * Calls vendored crypto-ops.h (curve25519 group operations) and keccak.h
 * directly. Does NOT use Monero's crypto.cpp/crypto.h — those pull in Boost
 * and Linux-only headers that break portability.
 *
 * All operations work on raw 32-byte arrays. No C++ wrapper types.
 */

#include "internal.h"
#include <cstring>

#ifdef __cplusplus
extern "C" {
#endif
#include "crypto-ops.h"  // ge_p3, ge_scalarmult, ge_mul8, sc_reduce32, ...
#include "keccak.h"      // keccak()
#include "memwipe.h"     // memwipe()
#ifdef __cplusplus
}
#endif

// ─── Platform random ──────────────────────────────────────────────────────────
// arc4random_buf is available on macOS, BSDs, and glibc >= 2.36 (Linux).
// For older Linux, fall back to getrandom(2) (available since kernel 3.17).

#if defined(__linux__) && !defined(__GLIBC_PREREQ)
#  include <sys/random.h>
#  define PLATFORM_RANDOM(buf, len)  getrandom((buf), (len), 0)
#else
#  include <stdlib.h>
#  define PLATFORM_RANDOM(buf, len)  arc4random_buf((buf), (len))
#endif

// ─── xmrmsg_derive ────────────────────────────────────────────────────────────
//
// Computes: out = 8 × sec_key × pub_key
//
// This is Monero's generate_key_derivation, implemented directly on top of
// crypto-ops primitives without the Monero crypto.cpp wrapper.

xmrmsg_result_t xmrmsg_derive(
    const uint8_t pub_key[XMRMSG_KEY_SIZE],
    const uint8_t sec_key[XMRMSG_KEY_SIZE],
    uint8_t       out_derivation[XMRMSG_KEY_SIZE])
{
    if (!pub_key || !sec_key || !out_derivation)
        return XMRMSG_ERR_INVALID_ARG;

    ge_p3    point;
    ge_p2    point2;
    ge_p1p1  point3;

    if (ge_frombytes_vartime(&point, pub_key) != 0)
        return XMRMSG_ERR_CRYPTO;

    ge_scalarmult(&point2, sec_key, &point);  // point2 = sec * pub
    ge_mul8(&point3, &point2);               // point3 = 8 * point2
    ge_p1p1_to_p2(&point2, &point3);
    ge_tobytes(out_derivation, &point2);

    return XMRMSG_OK;
}

// ─── xmrmsg_keystream ─────────────────────────────────────────────────────────
//
// Counter-mode Keccak-256: 8 × keccak(derivation || 0x4D || block_idx)
// Per PROTOCOL.md §5.2.

xmrmsg_result_t xmrmsg_keystream(
    const uint8_t derivation[XMRMSG_KEY_SIZE],
    uint8_t       out_keystream[XMRMSG_KEYSTREAM_SIZE])
{
    if (!derivation || !out_keystream)
        return XMRMSG_ERR_INVALID_ARG;

    uint8_t input[34];
    memcpy(input, derivation, XMRMSG_KEY_SIZE); // bytes  0–31
    input[32] = XMRMSG_MAGIC;                   // byte  32: domain separator 0x4D

    for (uint8_t i = 0; i < 8; i++) {
        input[33] = i;  // byte 33: block index
        keccak(input, sizeof(input), out_keystream + (i * XMRMSG_KEY_SIZE), XMRMSG_KEY_SIZE);
    }

    return XMRMSG_OK;
}

// ─── xmrmsg_generate_tx_keypair ───────────────────────────────────────────────

xmrmsg_result_t xmrmsg_generate_tx_keypair(
    uint8_t out_tx_sk[XMRMSG_KEY_SIZE],
    uint8_t out_tx_pk[XMRMSG_KEY_SIZE])
{
    if (!out_tx_sk || !out_tx_pk)
        return XMRMSG_ERR_INVALID_ARG;

    // Random scalar, reduced to be a valid ed25519 scalar
    PLATFORM_RANDOM(out_tx_sk, XMRMSG_KEY_SIZE);
    sc_reduce32(out_tx_sk);

    // Public key = scalar * G
    ge_p3 point;
    ge_scalarmult_base(&point, out_tx_sk);
    ge_p3_tobytes(out_tx_pk, &point);

    return XMRMSG_OK;
}

// ─── xmrmsg_secret_key_to_public_key ─────────────────────────────────────────

xmrmsg_result_t xmrmsg_secret_key_to_public_key(
    const uint8_t sec_key[XMRMSG_KEY_SIZE],
    uint8_t       out_pk[XMRMSG_KEY_SIZE])
{
    if (!sec_key || !out_pk)
        return XMRMSG_ERR_INVALID_ARG;

    ge_p3 point;
    ge_scalarmult_base(&point, sec_key);
    ge_p3_tobytes(out_pk, &point);

    return XMRMSG_OK;
}
