/**
 * monero_base58.h — Portable Monero base58 decoder.
 *
 * Monero uses a block-based base58 variant that is NOT the same as Bitcoin's
 * base58check. Blocks of 8 bytes encode to 11 base58 characters; the final
 * partial block uses a size-dependent character count.
 *
 * This implementation uses only standard C/C++ and __uint128_t (available in
 * GCC and Clang on both macOS and Linux). No platform-specific headers.
 */

#pragma once
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Decode a Monero base58-encoded string into raw bytes.
 *
 * @param enc      Input base58 string (not NUL-terminated; use enc_len).
 * @param enc_len  Length of enc in characters.
 * @param dec      Output buffer.
 * @param dec_len  On input: size of dec. On success: bytes written.
 *
 * @return true on success, false if enc is invalid or dec is too small.
 */
bool monero_base58_decode(const char *enc, size_t enc_len,
                          unsigned char *dec, size_t *dec_len);

#ifdef __cplusplus
}
#endif
