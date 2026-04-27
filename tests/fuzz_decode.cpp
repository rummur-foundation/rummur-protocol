/**
 * fuzz_decode.cpp — libFuzzer harness for xmrmsg_decode_nonce.
 *
 * Build with XMRMSG_BUILD_FUZZ=ON and clang:
 *   cmake -B build -DXMRMSG_BUILD_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++
 *   cmake --build build --target fuzz_decode
 *
 * Run:
 *   ./build/tests/fuzz_decode corpus/ -max_len=512 -jobs=4
 *
 * What this tests:
 *   - No crash, hang, or memory error for any 255-byte input
 *   - xmrmsg_free_message is always called, exercising cleanup paths
 *   - A second decode pass on the same input always produces the same result
 *     (determinism under arbitrary input)
 *
 * The harness uses a fixed weak view key and a small set of candidate tx
 * public keys covering the common cases (all-zeros, known test key, random-
 * looking but fixed). Wrong keys are the overwhelmingly common outcome —
 * XMRMSG_ERR_DECRYPT_FAILED is expected and treated as success.
 */

#include "libxmrmsg.h"
#include <cstring>
#include <cstdint>
#include <cstdlib>

// Fixed weak view key — same as test_core.cpp (all-0xAA with last byte 0x04)
static const uint8_t FUZZ_VIEW_SK[32] = {
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0x04
};

// Known tx_pk derived from TEST_TX_SK (all-0x55) — will actually decrypt a
// fuzz-generated nonce if the fuzzer discovers the matching ciphertext.
static const uint8_t KNOWN_TX_PK[32] = {
    0x9e,0x86,0xbe,0x61,0xf2,0x6c,0x62,0xf6,
    0x2d,0x12,0x30,0xd8,0x55,0xad,0x35,0x2e,
    0xca,0x21,0x98,0x8b,0x17,0xc9,0xf9,0x1c,
    0xef,0x49,0x30,0x5f,0x68,0x99,0xc3,0x4a
};

// All-zeros tx_pk — exercises the invalid-point branch in xmrmsg_derive
static const uint8_t ZERO_TX_PK[32] = { 0 };

// All-ones tx_pk — another degenerate case
static const uint8_t ONES_TX_PK[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

static const uint8_t CANDIDATES[3][XMRMSG_KEY_SIZE] = {
    { 0x9e,0x86,0xbe,0x61,0xf2,0x6c,0x62,0xf6,   // KNOWN_TX_PK
      0x2d,0x12,0x30,0xd8,0x55,0xad,0x35,0x2e,
      0xca,0x21,0x98,0x8b,0x17,0xc9,0xf9,0x1c,
      0xef,0x49,0x30,0x5f,0x68,0x99,0xc3,0x4a },
    { 0 },                                         // ZERO_TX_PK
    { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,     // ONES_TX_PK
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF },
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Feed any 255 bytes as the nonce; pad or truncate as needed.
    uint8_t nonce[XMRMSG_NONCE_SIZE] = { 0 };
    size_t  copy_len = size < XMRMSG_NONCE_SIZE ? size : XMRMSG_NONCE_SIZE;
    memcpy(nonce, data, copy_len);

    // First decode
    xmrmsg_message_t msg1;
    memset(&msg1, 0, sizeof(msg1));
    xmrmsg_result_t rc1 = xmrmsg_decode_nonce(
        nonce, FUZZ_VIEW_SK,
        CANDIDATES, 3,
        &msg1);

    if (rc1 == XMRMSG_OK) {
        // Second decode on same input must produce identical result
        xmrmsg_message_t msg2;
        memset(&msg2, 0, sizeof(msg2));
        xmrmsg_result_t rc2 = xmrmsg_decode_nonce(
            nonce, FUZZ_VIEW_SK,
            CANDIDATES, 3,
            &msg2);

        // Determinism: both calls must succeed and agree
        if (rc2 != XMRMSG_OK)              __builtin_trap();
        if (msg1.text_len != msg2.text_len) __builtin_trap();
        if (msg1.flags    != msg2.flags)    __builtin_trap();
        if (memcmp(msg1.thread_nonce, msg2.thread_nonce, XMRMSG_THREAD_NONCE_SIZE) != 0)
            __builtin_trap();
        if (msg1.text_len > 0 &&
            memcmp(msg1.text, msg2.text, msg1.text_len) != 0)
            __builtin_trap();

        xmrmsg_free_message(&msg2);
    }

    xmrmsg_free_message(&msg1);
    return 0;
}
