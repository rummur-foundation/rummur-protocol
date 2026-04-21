/**
 * monero_base58.cpp — Portable Monero base58 block decoder.
 *
 * Algorithm reference: src/common/base58.cpp in the Monero source tree.
 * Reimplemented without Linux-only headers (byteswap.h, endian.h) or Boost.
 *
 * Monero base58 block sizes:
 *   decoded bytes  →  encoded chars
 *       1          →       2
 *       2          →       3
 *       3          →       5
 *       4          →       6
 *       5          →       7
 *       6          →       9
 *       7          →      10
 *       8          →      11
 */

#include "monero_base58.h"
#include <cstring>
#include <cstdint>

// ─── Alphabet ─────────────────────────────────────────────────────────────────

static const char ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Lookup: ASCII → base58 digit value, or -1 for invalid character
static const int ALPHA_MAP[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,  // '1'..'9'
    -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,  // 'A'..'O' (no I)
    22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,  // 'P'..'Z'
    -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,  // 'a'..'o' (no l)
    47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,  // 'p'..'z'
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

// ─── Block size tables ────────────────────────────────────────────────────────

// enc_to_dec[encoded_chars] = decoded_bytes  (0 means invalid)
static const int enc_to_dec[12] = { 0, 0, 1, 2, 0, 3, 4, 5, 0, 6, 7, 8 };

// dec_to_enc[decoded_bytes] = encoded_chars  (0 means invalid)
static const int dec_to_enc[9]  = { 0, 2, 3, 5, 6, 7, 9, 10, 11 };

static const int FULL_DEC = 8;  // decoded bytes per full block
static const int FULL_ENC = 11; // encoded chars per full block

// ─── Decode one block ─────────────────────────────────────────────────────────
//
// enc[0..enc_len-1] → dec[0..dec_len-1]  (big-endian)
// Uses __uint128_t for overflow-safe arithmetic — available in GCC and Clang.

static bool decode_block(const char   *enc, size_t enc_len,
                         unsigned char *dec, size_t dec_len)
{
    if (enc_len < 1 || enc_len > (size_t)FULL_ENC) return false;
    if (dec_len < 1 || dec_len > (size_t)FULL_DEC) return false;

    __uint128_t num = 0;
    for (size_t i = 0; i < enc_len; i++) {
        int d = ALPHA_MAP[(unsigned char)enc[i]];
        if (d < 0) return false;
        num = num * 58 + d;
    }

    // num must fit in dec_len bytes
    __uint128_t max_val = (__uint128_t)1 << (dec_len * 8);
    if (num >= max_val) return false;

    // Write big-endian
    for (int i = (int)dec_len - 1; i >= 0; i--) {
        dec[i] = (unsigned char)(num & 0xFF);
        num >>= 8;
    }
    return true;
}

// ─── Encode one block ─────────────────────────────────────────────────────────
//
// dec[0..dec_len-1] → enc[0..enc_len-1]  (big-endian, zero-padded on the left)

static bool encode_block(const unsigned char *dec, size_t dec_len,
                         char *enc, size_t enc_len)
{
    if (dec_len < 1 || dec_len > (size_t)FULL_DEC) return false;
    if (enc_len < 1 || enc_len > (size_t)FULL_ENC) return false;

    __uint128_t num = 0;
    for (size_t i = 0; i < dec_len; i++) {
        num = (num << 8) | dec[i];
    }

    // Fill from the right — pad unused leading positions with ALPHABET[0] = '1'
    for (int i = (int)enc_len - 1; i >= 0; i--) {
        enc[i] = ALPHABET[num % 58];
        num /= 58;
    }
    return num == 0; // should be 0 if value fits in enc_len base-58 digits
}

// ─── Public encode ────────────────────────────────────────────────────────────

bool monero_base58_encode(const unsigned char *dec, size_t dec_len,
                          char *enc, size_t *enc_len)
{
    if (!dec || !enc || !enc_len) return false;
    if (dec_len == 0) { *enc_len = 0; enc[0] = '\0'; return true; }

    size_t full_blocks  = dec_len / FULL_DEC;
    size_t tail_dec_len = dec_len % FULL_DEC;
    size_t tail_enc_len = (tail_dec_len == 0) ? 0 : (size_t)dec_to_enc[tail_dec_len];

    size_t expected_enc = full_blocks * FULL_ENC + tail_enc_len;
    if (*enc_len < expected_enc + 1) return false;

    for (size_t b = 0; b < full_blocks; b++) {
        if (!encode_block(dec + b * FULL_DEC, FULL_DEC,
                          enc + b * FULL_ENC, FULL_ENC))
            return false;
    }

    if (tail_dec_len > 0) {
        if (!encode_block(dec + full_blocks * FULL_DEC, tail_dec_len,
                          enc + full_blocks * FULL_ENC, tail_enc_len))
            return false;
    }

    enc[expected_enc] = '\0';
    *enc_len = expected_enc;
    return true;
}

// ─── Public decode ────────────────────────────────────────────────────────────

bool monero_base58_decode(const char    *enc, size_t enc_len,
                          unsigned char *dec, size_t *dec_len)
{
    if (!enc || !dec || !dec_len) return false;
    if (enc_len == 0) { *dec_len = 0; return true; }

    // Compute expected decoded size
    size_t full_blocks   = enc_len / FULL_ENC;
    size_t tail_enc_len  = enc_len % FULL_ENC;
    size_t tail_dec_len  = (tail_enc_len == 0) ? 0 : (size_t)enc_to_dec[tail_enc_len];

    if (tail_enc_len != 0 && tail_dec_len == 0)
        return false; // invalid partial block size

    size_t expected_dec = full_blocks * FULL_DEC + tail_dec_len;
    if (*dec_len < expected_dec) return false;

    // Decode full blocks
    for (size_t b = 0; b < full_blocks; b++) {
        if (!decode_block(enc + b * FULL_ENC, FULL_ENC,
                          dec + b * FULL_DEC, FULL_DEC))
            return false;
    }

    // Decode tail
    if (tail_dec_len > 0) {
        if (!decode_block(enc + full_blocks * FULL_ENC, tail_enc_len,
                          dec + full_blocks * FULL_DEC, tail_dec_len))
            return false;
    }

    *dec_len = expected_dec;
    return true;
}
