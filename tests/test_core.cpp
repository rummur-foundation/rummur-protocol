/**
 * test_core.cpp — Unit tests for the libxmrmsg nonce-level API.
 *
 * No external test framework required. Tests use assert() and print
 * PASS/FAIL to stdout. Exit code 0 = all passed.
 *
 * Run: ./build/tests/test_core
 */

#include "libxmrmsg.h"
#include <cassert>
#include <cstring>
#include <cstdio>
#include <cstdlib>

// ─── Test runner ─────────────────────────────────────────────────────────────

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name)  static void test_##name()
#define RUN(name)   run_test(#name, test_##name)

static void run_test(const char *name, void (*fn)()) {
    printf("  %-60s", name);
    fflush(stdout);
    fn();
    printf("PASS\n");
    g_passed++;
}

// ─── Test key material (weak by design — tests only) ─────────────────────────

// A real stagenet address is needed for tests that exercise address parsing.
// This address was generated from a known seed on stagenet — replace with
// your own test address once the local environment is running.
static const char *STAGENET_ADDR =
    "5BLhHNxbdQVQLmzw24Ew2kCmpFyBtRMKwVv7JK8rmXMC1piGLvzJMVmf8HRMDpMTCxGpJHCXa7P3MJ5KzNkSwA2MUhFqtw";

// A stagenet subaddress for the same wallet at index (0,1)
static const char *STAGENET_SUBADDR =
    "73b4gGGSVxEMfFWYzQSxkBXJzRJJCNZLFAbSs8uAkNBXBvPkMXzJVoEgDhFJGxLhBeA9AQXQKxckKxJvBtJAJ7P2rBkNBj";

// Known tx_sk for deterministic tests (all-0x55 — never use outside tests)
static const uint8_t TEST_TX_SK[32] = {
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x04
    // note: last byte avoids the all-zero scalar which is invalid on ed25519
};

// Known view_sk for deterministic tests (all-0xAA)
static const uint8_t TEST_VIEW_SK[32] = {
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0x04
};

static const uint8_t TEST_THREAD_NONCE[8] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

// ─── Constants ───────────────────────────────────────────────────────────────

TEST(constants) {
    assert(XMRMSG_MAGIC              == 0x4D);
    assert(XMRMSG_NONCE_SIZE         == 255);
    assert(XMRMSG_CIPHERTEXT_OFFSET  == 10);
    assert(XMRMSG_CIPHERTEXT_SIZE    == 245);
    assert(XMRMSG_THREAD_NONCE_SIZE  == 8);
    assert(XMRMSG_ADDRESS_LEN        == 95);
    assert(XMRMSG_KEY_SIZE           == 32);
    assert(XMRMSG_KEYSTREAM_SIZE     == 256);

    // Layout arithmetic
    // 3 header + 242 msg = 245 ✓
    assert(3 + XMRMSG_MAX_MSG_ANON == XMRMSG_CIPHERTEXT_SIZE);
    // 3 header + 147 msg + 95 addr = 245 ✓
    assert(3 + XMRMSG_MAX_MSG_WITH_SENDER + XMRMSG_ADDRESS_LEN == XMRMSG_CIPHERTEXT_SIZE);

    assert(XMRMSG_DEFAULT_DUST_PICONERO >= XMRMSG_MIN_DUST_PICONERO);
}

// ─── Address validation ───────────────────────────────────────────────────────

TEST(validate_address_primary) {
    assert(xmrmsg_validate_address(STAGENET_ADDR) == XMRMSG_OK);
    assert(xmrmsg_is_subaddress(STAGENET_ADDR) == 0);
}

TEST(validate_address_subaddress) {
    assert(xmrmsg_validate_address(STAGENET_SUBADDR) == XMRMSG_OK);
    assert(xmrmsg_is_subaddress(STAGENET_SUBADDR) == 1);
}

TEST(validate_address_invalid) {
    assert(xmrmsg_validate_address(NULL)    == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_validate_address("")      == XMRMSG_ERR_INVALID_ADDRESS);
    assert(xmrmsg_validate_address("short") == XMRMSG_ERR_INVALID_ADDRESS);

    // Corrupt the last character of a valid address
    char bad[XMRMSG_ADDRESS_LEN + 1];
    memcpy(bad, STAGENET_ADDR, XMRMSG_ADDRESS_LEN + 1);
    bad[XMRMSG_ADDRESS_LEN - 1] ^= 0xFF;
    assert(xmrmsg_validate_address(bad) == XMRMSG_ERR_INVALID_ADDRESS);
}

// ─── ECDH derive ─────────────────────────────────────────────────────────────

TEST(derive_basic) {
    uint8_t d[32];
    // Both args required
    assert(xmrmsg_derive(NULL, TEST_VIEW_SK, d)  == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_derive(TEST_TX_SK, NULL, d)    == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_derive(TEST_TX_SK, TEST_VIEW_SK, NULL) == XMRMSG_ERR_INVALID_ARG);
}

TEST(derive_symmetry) {
    // Compute tx_pk = tx_sk * G
    uint8_t tx_pk[32];
    assert(xmrmsg_secret_key_to_public_key(TEST_TX_SK, tx_pk) == XMRMSG_OK);

    // Compute view_pk = view_sk * G
    uint8_t view_pk[32];
    assert(xmrmsg_secret_key_to_public_key(TEST_VIEW_SK, view_pk) == XMRMSG_OK);

    // Sender derivation:    derive(view_pk, tx_sk)  = 8 * tx_sk  * view_pk
    uint8_t deriv_sender[32];
    assert(xmrmsg_derive(view_pk, TEST_TX_SK, deriv_sender) == XMRMSG_OK);

    // Recipient derivation: derive(tx_pk,  view_sk) = 8 * view_sk * tx_pk
    uint8_t deriv_recipient[32];
    assert(xmrmsg_derive(tx_pk, TEST_VIEW_SK, deriv_recipient) == XMRMSG_OK);

    // Must be equal
    assert(memcmp(deriv_sender, deriv_recipient, 32) == 0);
}

// ─── Keystream ────────────────────────────────────────────────────────────────

TEST(keystream_length_and_determinism) {
    uint8_t derivation[32] = {0};
    derivation[0] = 0x42;

    uint8_t ks1[256], ks2[256];
    assert(xmrmsg_keystream(derivation, ks1) == XMRMSG_OK);
    assert(xmrmsg_keystream(derivation, ks2) == XMRMSG_OK);

    // Deterministic
    assert(memcmp(ks1, ks2, 256) == 0);

    // Must not be all zeros
    int all_zero = 1;
    for (int i = 0; i < 256; i++) if (ks1[i]) { all_zero = 0; break; }
    assert(!all_zero);
}

TEST(keystream_different_derivations_differ) {
    uint8_t d1[32] = {0x01}, d2[32] = {0x02};
    uint8_t ks1[256], ks2[256];
    assert(xmrmsg_keystream(d1, ks1) == XMRMSG_OK);
    assert(xmrmsg_keystream(d2, ks2) == XMRMSG_OK);
    assert(memcmp(ks1, ks2, 256) != 0);
}

// ─── Encode / decode roundtrip ────────────────────────────────────────────────

static void do_roundtrip(const char *msg_text,
                         uint8_t     flags,
                         const char *sender_addr,
                         bool        use_subaddr_recipient)
{
    const char *recipient = use_subaddr_recipient ? STAGENET_SUBADDR : STAGENET_ADDR;

    // Encode
    uint8_t nonce[255];
    uint8_t out_thread[8];
    xmrmsg_result_t rc = xmrmsg_encode_nonce(
        recipient,
        TEST_TX_SK,
        reinterpret_cast<const uint8_t *>(msg_text), strlen(msg_text),
        flags,
        sender_addr,
        TEST_THREAD_NONCE,
        nonce,
        out_thread);
    assert(rc == XMRMSG_OK);

    // Thread nonce echoed correctly
    assert(memcmp(out_thread, TEST_THREAD_NONCE, 8) == 0);

    // Magic byte present
    assert(nonce[0] == XMRMSG_MAGIC);

    // Compute the tx_pk that the recipient will see:
    // For a standard address, tx_pk = tx_sk * G
    uint8_t tx_pk[32];
    assert(xmrmsg_secret_key_to_public_key(TEST_TX_SK, tx_pk) == XMRMSG_OK);

    // Decode — extract view_sk from the test address for decryption
    // (In a real scenario the recipient's wallet holds view_sk.
    //  Here we use TEST_VIEW_SK directly since STAGENET_ADDR was generated from it.)
    const uint8_t *candidates[1] = { tx_pk };
    xmrmsg_message_t msg;
    memset(&msg, 0, sizeof(msg));
    rc = xmrmsg_decode_nonce(nonce, TEST_VIEW_SK, candidates, 1, &msg);
    assert(rc == XMRMSG_OK);

    // Content matches
    assert(msg.text_len == strlen(msg_text));
    assert(memcmp(msg.text, msg_text, msg.text_len) == 0);
    assert(msg.flags == flags);
    assert(memcmp(msg.thread_nonce, TEST_THREAD_NONCE, 8) == 0);

    // Sender address field
    if (flags & XMRMSG_FLAG_SENDER_ADDR) {
        assert(msg.has_sender_address == 1);
        assert(memcmp(msg.sender_address, sender_addr, XMRMSG_ADDRESS_LEN) == 0);
    } else {
        assert(msg.has_sender_address == 0);
    }

    xmrmsg_free_message(&msg);
    assert(msg.text == NULL);
}

TEST(roundtrip_anonymous) {
    do_roundtrip("Hello, Rummur.", 0x00, NULL, false);
}

TEST(roundtrip_with_sender) {
    do_roundtrip("Reply to me.", XMRMSG_FLAG_SENDER_ADDR, STAGENET_ADDR, false);
}

TEST(roundtrip_reply) {
    do_roundtrip("Got it.",
                 XMRMSG_FLAG_SENDER_ADDR | XMRMSG_FLAG_IS_REPLY,
                 STAGENET_ADDR, false);
}

TEST(roundtrip_subaddress_recipient) {
    do_roundtrip("Hello subaddress.", 0x00, NULL, true);
}

TEST(roundtrip_max_message_anon) {
    char msg[XMRMSG_MAX_MSG_ANON + 1];
    memset(msg, 'A', XMRMSG_MAX_MSG_ANON);
    msg[XMRMSG_MAX_MSG_ANON] = '\0';
    do_roundtrip(msg, 0x00, NULL, false);
}

TEST(roundtrip_max_message_with_sender) {
    char msg[XMRMSG_MAX_MSG_WITH_SENDER + 1];
    memset(msg, 'B', XMRMSG_MAX_MSG_WITH_SENDER);
    msg[XMRMSG_MAX_MSG_WITH_SENDER] = '\0';
    do_roundtrip(msg, XMRMSG_FLAG_SENDER_ADDR, STAGENET_ADDR, false);
}

// ─── Encode error cases ───────────────────────────────────────────────────────

TEST(encode_errors) {
    uint8_t nonce[255];
    const uint8_t *msg = reinterpret_cast<const uint8_t *>("hi");
    const size_t   len = 2;

    // Missing required args
    assert(xmrmsg_encode_nonce(NULL,         TEST_TX_SK, msg, len, 0, NULL, NULL, nonce, NULL)
           == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_encode_nonce(STAGENET_ADDR, NULL,      msg, len, 0, NULL, NULL, nonce, NULL)
           == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_encode_nonce(STAGENET_ADDR, TEST_TX_SK, msg, len, 0, NULL, NULL, NULL, NULL)
           == XMRMSG_ERR_INVALID_ARG);

    // SENDER_ADDR flag set but no sender_addr pointer
    assert(xmrmsg_encode_nonce(STAGENET_ADDR, TEST_TX_SK, msg, len,
                               XMRMSG_FLAG_SENDER_ADDR, NULL, NULL, nonce, NULL)
           == XMRMSG_ERR_INVALID_ARG);

    // Message too long (anonymous)
    uint8_t big[XMRMSG_MAX_MSG_ANON + 1];
    memset(big, 'X', sizeof(big));
    assert(xmrmsg_encode_nonce(STAGENET_ADDR, TEST_TX_SK, big, sizeof(big),
                               0, NULL, NULL, nonce, NULL)
           == XMRMSG_ERR_MSG_TOO_LONG);

    // Invalid recipient address
    assert(xmrmsg_encode_nonce("not_a_valid_address_at_all_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                               TEST_TX_SK, msg, len, 0, NULL, NULL, nonce, NULL)
           == XMRMSG_ERR_INVALID_ADDRESS);
}

// ─── Decode error cases ───────────────────────────────────────────────────────

TEST(decode_errors) {
    uint8_t nonce[255] = {0};
    const uint8_t tx_pk[32] = {0};
    const uint8_t *candidates[1] = { tx_pk };
    xmrmsg_message_t msg;

    assert(xmrmsg_decode_nonce(NULL,  TEST_VIEW_SK, candidates, 1, &msg)
           == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_decode_nonce(nonce, NULL,         candidates, 1, &msg)
           == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_decode_nonce(nonce, TEST_VIEW_SK, NULL,       1, &msg)
           == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_decode_nonce(nonce, TEST_VIEW_SK, candidates, 0, &msg)
           == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_decode_nonce(nonce, TEST_VIEW_SK, candidates, 1, NULL)
           == XMRMSG_ERR_INVALID_ARG);

    // Wrong magic byte (nonce is all-zero → nonce[0] = 0x00 ≠ 0x4D)
    assert(xmrmsg_decode_nonce(nonce, TEST_VIEW_SK, candidates, 1, &msg)
           == XMRMSG_ERR_WRONG_MAGIC);

    // Unrecognised version
    nonce[0] = XMRMSG_MAGIC;
    nonce[1] = 0xF0; // version = 0xF, flags = 0
    assert(xmrmsg_decode_nonce(nonce, TEST_VIEW_SK, candidates, 1, &msg)
           == XMRMSG_ERR_UNKNOWN_VERSION);

    // Correct magic + version, but all-zero ciphertext won't decrypt to a valid payload_type
    nonce[1] = 0x00;
    assert(xmrmsg_decode_nonce(nonce, TEST_VIEW_SK, candidates, 1, &msg)
           == XMRMSG_ERR_DECRYPT_FAILED);
}

// ─── Wrong key produces decrypt failure ───────────────────────────────────────

TEST(wrong_key_decrypt_failed) {
    uint8_t nonce[255];
    xmrmsg_encode_nonce(STAGENET_ADDR, TEST_TX_SK,
                        reinterpret_cast<const uint8_t *>("secret"), 6,
                        0, NULL, TEST_THREAD_NONCE, nonce, NULL);

    // Correct tx_pk but wrong view_sk
    uint8_t tx_pk[32];
    xmrmsg_secret_key_to_public_key(TEST_TX_SK, tx_pk);

    uint8_t wrong_view_sk[32];
    memset(wrong_view_sk, 0x11, 32);
    wrong_view_sk[31] = 0x04;

    const uint8_t *candidates[1] = { tx_pk };
    xmrmsg_message_t msg;
    assert(xmrmsg_decode_nonce(nonce, wrong_view_sk, candidates, 1, &msg)
           == XMRMSG_ERR_DECRYPT_FAILED);
}

// ─── Every message produces a different nonce (random padding / thread nonce) ─

TEST(encode_different_random_nonces) {
    uint8_t nonce1[255], nonce2[255];
    const uint8_t *msg = reinterpret_cast<const uint8_t *>("same message");
    const size_t   len = 12;

    // NULL thread_nonce_in → random each time
    xmrmsg_encode_nonce(STAGENET_ADDR, TEST_TX_SK, msg, len, 0, NULL, NULL, nonce1, NULL);
    xmrmsg_encode_nonce(STAGENET_ADDR, TEST_TX_SK, msg, len, 0, NULL, NULL, nonce2, NULL);

    // Bytes 2–9 (thread_nonce) should differ between calls
    assert(memcmp(nonce1 + 2, nonce2 + 2, 8) != 0);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(void) {
    printf("libxmrmsg unit tests\n");
    printf("====================\n\n");

    RUN(constants);
    RUN(validate_address_primary);
    RUN(validate_address_subaddress);
    RUN(validate_address_invalid);
    RUN(derive_basic);
    RUN(derive_symmetry);
    RUN(keystream_length_and_determinism);
    RUN(keystream_different_derivations_differ);
    RUN(roundtrip_anonymous);
    RUN(roundtrip_with_sender);
    RUN(roundtrip_reply);
    RUN(roundtrip_subaddress_recipient);
    RUN(roundtrip_max_message_anon);
    RUN(roundtrip_max_message_with_sender);
    RUN(encode_errors);
    RUN(decode_errors);
    RUN(wrong_key_decrypt_failed);
    RUN(encode_different_random_nonces);

    printf("\n%d passed", g_passed);
    if (g_failed) printf(", %d FAILED", g_failed);
    printf("\n");
    return g_failed ? 1 : 0;
}
