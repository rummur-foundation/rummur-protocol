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
    "591vyBazs1675Q3SXLUTFN2LSdnnrjWXF92y27KHL1nLNkmYZUDYhK8VA6ZXkM96RS6h3pDoJWZwuPHFSg7r2CnQ2pND5sj";

// Stagenet subaddress for the same wallet at index (0,1), derived from TEST_VIEW_SK+TEST_TX_SK
static const char *STAGENET_SUBADDR =
    "7BdbAHgZ37kG5Dk6bx9em17jBhYfaDUstWDkWPTCj8BKRyVEXazLyiAWZeTSmF15jbSinj5KSCi9cReM6VhFReEtSdpYAiK";

// Subaddress spend public key D — needed to compute tx_pk = TEST_TX_SK * D for decode
static const uint8_t STAGENET_SUBADDR_D[32] = {
    0xF7,0xAC,0xA3,0xF2,0xAC,0x55,0x7F,0x5A,0x1D,0x36,0x09,0x77,0xF3,0x81,0xDC,0x28,
    0x38,0x52,0x7E,0xA4,0x82,0xD8,0xC3,0xAE,0xB1,0xA6,0x80,0x5C,0xEF,0x3B,0xD2,0x95
};

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
    //   Standard address: tx_pk = tx_sk * G
    //   Subaddress:       tx_pk = tx_sk * D  (subaddr spend pk, not base point G)
    uint8_t tx_pk[32];
    if (use_subaddr_recipient) {
        assert(xmrmsg_scalarmult(TEST_TX_SK, STAGENET_SUBADDR_D, tx_pk) == XMRMSG_OK);
    } else {
        assert(xmrmsg_secret_key_to_public_key(TEST_TX_SK, tx_pk) == XMRMSG_OK);
    }

    // Decode — extract view_sk from the test address for decryption
    // (In a real scenario the recipient's wallet holds view_sk.
    //  Here we use TEST_VIEW_SK directly since STAGENET_ADDR was generated from it.)
    const uint8_t (*candidates)[XMRMSG_KEY_SIZE] = { &tx_pk };
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
    const uint8_t (*candidates)[XMRMSG_KEY_SIZE] = { &tx_pk };
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

    const uint8_t (*candidates)[XMRMSG_KEY_SIZE] = { &tx_pk };
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

// ─── Version string ───────────────────────────────────────────────────────────

TEST(version_string) {
    const char *v = xmrmsg_version_string();
    assert(v != NULL);
    assert(v[0] != '\0');
}

// ─── generate_tx_keypair ──────────────────────────────────────────────────────

TEST(generate_tx_keypair_null_args) {
    uint8_t sk[32], pk[32];
    assert(xmrmsg_generate_tx_keypair(NULL, pk) == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_generate_tx_keypair(sk, NULL) == XMRMSG_ERR_INVALID_ARG);
}

TEST(generate_tx_keypair_consistency) {
    uint8_t tx_sk[32], tx_pk[32];
    assert(xmrmsg_generate_tx_keypair(tx_sk, tx_pk) == XMRMSG_OK);

    // pk should equal secret_key_to_public_key(sk)
    uint8_t expected_pk[32];
    assert(xmrmsg_secret_key_to_public_key(tx_sk, expected_pk) == XMRMSG_OK);
    assert(memcmp(tx_pk, expected_pk, 32) == 0);
}

TEST(generate_tx_keypair_random) {
    uint8_t sk1[32], pk1[32], sk2[32], pk2[32];
    assert(xmrmsg_generate_tx_keypair(sk1, pk1) == XMRMSG_OK);
    assert(xmrmsg_generate_tx_keypair(sk2, pk2) == XMRMSG_OK);
    // Two calls must produce distinct keypairs
    assert(memcmp(sk1, sk2, 32) != 0);
    assert(memcmp(pk1, pk2, 32) != 0);
}

// ─── scalarmult direct ────────────────────────────────────────────────────────

TEST(scalarmult_null_args) {
    uint8_t out[32], pub[32] = {0};
    assert(xmrmsg_scalarmult(NULL,        pub, out) == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_scalarmult(TEST_TX_SK,  NULL, out) == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_scalarmult(TEST_TX_SK,  pub, NULL) == XMRMSG_ERR_INVALID_ARG);
}

TEST(scalarmult_vs_base_point) {
    // scalarmult(sk, G) should equal secret_key_to_public_key(sk)
    // G is the standard ed25519 base point: (4/5, positive) in compressed form
    static const uint8_t G[32] = {
        0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
        0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
    };
    uint8_t via_scalarmult[32], via_sk_to_pk[32];
    assert(xmrmsg_scalarmult(TEST_TX_SK, G, via_scalarmult) == XMRMSG_OK);
    assert(xmrmsg_secret_key_to_public_key(TEST_TX_SK, via_sk_to_pk) == XMRMSG_OK);
    assert(memcmp(via_scalarmult, via_sk_to_pk, 32) == 0);
}

// ─── keystream NULL args ──────────────────────────────────────────────────────

TEST(keystream_null_args) {
    uint8_t derivation[32] = {0x42};
    uint8_t ks[256];
    assert(xmrmsg_keystream(NULL,       ks)  == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_keystream(derivation, NULL) == XMRMSG_ERR_INVALID_ARG);
}

// ─── is_subaddress with invalid inputs ───────────────────────────────────────

TEST(is_subaddress_invalid) {
    assert(xmrmsg_is_subaddress(NULL)    == -1);
    assert(xmrmsg_is_subaddress("")      == -1);
    assert(xmrmsg_is_subaddress("short") == -1);
}

// ─── free_message NULL safety ─────────────────────────────────────────────────

TEST(free_message_null_safe) {
    xmrmsg_free_message(NULL);  // must not crash

    xmrmsg_message_t msg;
    memset(&msg, 0, sizeof(msg));
    xmrmsg_free_message(&msg);  // text == NULL, must not crash
    assert(msg.text == NULL);
}

// ─── Empty message roundtrip ──────────────────────────────────────────────────

TEST(roundtrip_empty_message) {
    uint8_t nonce[255];
    xmrmsg_result_t rc = xmrmsg_encode_nonce(
        STAGENET_ADDR, TEST_TX_SK,
        NULL, 0,
        0, NULL, TEST_THREAD_NONCE,
        nonce, NULL);
    assert(rc == XMRMSG_OK);

    uint8_t tx_pk[32];
    assert(xmrmsg_secret_key_to_public_key(TEST_TX_SK, tx_pk) == XMRMSG_OK);

    const uint8_t (*candidates)[XMRMSG_KEY_SIZE] = { &tx_pk };
    xmrmsg_message_t msg;
    memset(&msg, 0, sizeof(msg));
    assert(xmrmsg_decode_nonce(nonce, TEST_VIEW_SK, candidates, 1, &msg) == XMRMSG_OK);
    assert(msg.text_len == 0);
    assert(msg.text != NULL);  // NUL-terminator is still allocated
    assert(msg.text[0] == '\0');
    xmrmsg_free_message(&msg);
}

// ─── Encode with invalid sender address ──────────────────────────────────────

TEST(encode_invalid_sender_address) {
    uint8_t nonce[255];
    const uint8_t *m = reinterpret_cast<const uint8_t *>("hi");
    // SENDER_ADDR flag set, but sender_addr is malformed
    assert(xmrmsg_encode_nonce(
        STAGENET_ADDR, TEST_TX_SK, m, 2,
        XMRMSG_FLAG_SENDER_ADDR,
        "not_a_valid_address_at_all_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        NULL, nonce, NULL)
        == XMRMSG_ERR_INVALID_ADDRESS);
}

// ─── Decode: correct key not first candidate ──────────────────────────────────

TEST(decode_multiple_candidates_right_key_last) {
    uint8_t nonce[255];
    xmrmsg_encode_nonce(STAGENET_ADDR, TEST_TX_SK,
                        reinterpret_cast<const uint8_t *>("multi"), 5,
                        0, NULL, TEST_THREAD_NONCE, nonce, NULL);

    uint8_t tx_pk[32];
    xmrmsg_secret_key_to_public_key(TEST_TX_SK, tx_pk);

    // First candidate is a decoy (all-zeros public key — will fail derivation or decrypt)
    uint8_t decoy[32] = {0};
    // Build candidates array: [decoy, correct]
    uint8_t candidates[2][XMRMSG_KEY_SIZE];
    memcpy(candidates[0], decoy,  XMRMSG_KEY_SIZE);
    memcpy(candidates[1], tx_pk,  XMRMSG_KEY_SIZE);

    xmrmsg_message_t msg;
    memset(&msg, 0, sizeof(msg));
    assert(xmrmsg_decode_nonce(nonce, TEST_VIEW_SK,
                               (const uint8_t (*)[XMRMSG_KEY_SIZE])candidates,
                               2, &msg) == XMRMSG_OK);
    assert(msg.text_len == 5);
    assert(memcmp(msg.text, "multi", 5) == 0);
    xmrmsg_free_message(&msg);
}

// ─── Wallet API ───────────────────────────────────────────────────────────────

TEST(wallet_from_keys_null_args) {
    xmrmsg_wallet_t *w = NULL;
    // NULL view_sk
    assert(xmrmsg_wallet_from_keys(NULL, NULL, STAGENET_ADDR, 0, NULL, &w)
           == XMRMSG_ERR_INVALID_ARG);
    // NULL primary_address
    assert(xmrmsg_wallet_from_keys(NULL, TEST_VIEW_SK, NULL, 0, NULL, &w)
           == XMRMSG_ERR_INVALID_ARG);
    // NULL out_wallet
    assert(xmrmsg_wallet_from_keys(NULL, TEST_VIEW_SK, STAGENET_ADDR, 0, NULL, NULL)
           == XMRMSG_ERR_INVALID_ARG);
}

TEST(wallet_from_keys_invalid_address) {
    xmrmsg_wallet_t *w = NULL;
    assert(xmrmsg_wallet_from_keys(NULL, TEST_VIEW_SK, "bad_address", 0, NULL, &w)
           == XMRMSG_ERR_INVALID_ADDRESS);
}

TEST(wallet_from_keys_view_only) {
    xmrmsg_wallet_t *w = NULL;
    assert(xmrmsg_wallet_from_keys(NULL, TEST_VIEW_SK, STAGENET_ADDR, 0, NULL, &w)
           == XMRMSG_OK);
    assert(w != NULL);

    // build_tx must fail for view-only wallet
    xmrmsg_pending_tx_t *tx = NULL;
    assert(xmrmsg_build_tx(w, STAGENET_ADDR,
                           reinterpret_cast<const uint8_t *>("hi"), 2,
                           0, NULL, NULL,
                           XMRMSG_DEFAULT_DUST_PICONERO,
                           XMRMSG_PRIORITY_NORMAL,
                           &tx, NULL)
           == XMRMSG_ERR_VIEW_ONLY);

    xmrmsg_wallet_free(w);
}

TEST(wallet_from_keys_with_spend_key) {
    xmrmsg_wallet_t *w = NULL;
    uint8_t spend_sk[32];
    memset(spend_sk, 0x33, 32);
    spend_sk[31] = 0x04;
    assert(xmrmsg_wallet_from_keys(spend_sk, TEST_VIEW_SK, STAGENET_ADDR, 0, NULL, &w)
           == XMRMSG_OK);
    assert(w != NULL);
    xmrmsg_wallet_free(w);
    xmrmsg_wallet_free(NULL);  // NULL-safe
}

TEST(build_tx_null_args) {
    assert(xmrmsg_build_tx(NULL, STAGENET_ADDR, NULL, 0, 0, NULL, NULL, 0,
                           XMRMSG_PRIORITY_NORMAL, NULL, NULL)
           == XMRMSG_ERR_INVALID_ARG);

    xmrmsg_wallet_t *w = NULL;
    xmrmsg_wallet_from_keys(NULL, TEST_VIEW_SK, STAGENET_ADDR, 0, NULL, &w);
    assert(w != NULL);

    xmrmsg_pending_tx_t *tx = NULL;
    assert(xmrmsg_build_tx(w, NULL, NULL, 0, 0, NULL, NULL, 0,
                           XMRMSG_PRIORITY_NORMAL, &tx, NULL)
           == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_build_tx(w, STAGENET_ADDR, NULL, 0, 0, NULL, NULL, 0,
                           XMRMSG_PRIORITY_NORMAL, NULL, NULL)
           == XMRMSG_ERR_INVALID_ARG);

    xmrmsg_wallet_free(w);
}

TEST(build_tx_bad_amount) {
    uint8_t spend_sk[32];
    memset(spend_sk, 0x33, 32);
    spend_sk[31] = 0x04;

    xmrmsg_wallet_t *w = NULL;
    xmrmsg_wallet_from_keys(spend_sk, TEST_VIEW_SK, STAGENET_ADDR, 0, NULL, &w);
    assert(w != NULL);

    xmrmsg_pending_tx_t *tx = NULL;
    // Amount below minimum (but non-zero)
    assert(xmrmsg_build_tx(w, STAGENET_ADDR, NULL, 0, 0, NULL, NULL,
                           XMRMSG_MIN_DUST_PICONERO - 1,
                           XMRMSG_PRIORITY_NORMAL, &tx, NULL)
           == XMRMSG_ERR_INVALID_ARG);

    xmrmsg_wallet_free(w);
}

TEST(tx_id_and_broadcast_null_args) {
    uint8_t txid[32];
    assert(xmrmsg_tx_id(NULL, txid)    == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_tx_id((const xmrmsg_pending_tx_t *)&txid, NULL)
           == XMRMSG_ERR_INVALID_ARG);

    assert(xmrmsg_broadcast_tx(NULL, "http://node:18081", NULL)
           == XMRMSG_ERR_INVALID_ARG);
    assert(xmrmsg_broadcast_tx((const xmrmsg_pending_tx_t *)&txid, NULL, NULL)
           == XMRMSG_ERR_INVALID_ARG);

    xmrmsg_free_pending_tx(NULL);  // must not crash
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(void) {
    printf("libxmrmsg unit tests\n");
    printf("====================\n\n");

    RUN(constants);
    RUN(version_string);
    RUN(validate_address_primary);
    RUN(validate_address_subaddress);
    RUN(validate_address_invalid);
    RUN(is_subaddress_invalid);
    RUN(derive_basic);
    RUN(derive_symmetry);
    RUN(keystream_null_args);
    RUN(keystream_length_and_determinism);
    RUN(keystream_different_derivations_differ);
    RUN(generate_tx_keypair_null_args);
    RUN(generate_tx_keypair_consistency);
    RUN(generate_tx_keypair_random);
    RUN(scalarmult_null_args);
    RUN(scalarmult_vs_base_point);
    RUN(roundtrip_anonymous);
    RUN(roundtrip_with_sender);
    RUN(roundtrip_reply);
    RUN(roundtrip_subaddress_recipient);
    RUN(roundtrip_max_message_anon);
    RUN(roundtrip_max_message_with_sender);
    RUN(roundtrip_empty_message);
    RUN(encode_errors);
    RUN(encode_invalid_sender_address);
    RUN(decode_errors);
    RUN(decode_multiple_candidates_right_key_last);
    RUN(wrong_key_decrypt_failed);
    RUN(encode_different_random_nonces);
    RUN(free_message_null_safe);
    RUN(wallet_from_keys_null_args);
    RUN(wallet_from_keys_invalid_address);
    RUN(wallet_from_keys_view_only);
    RUN(wallet_from_keys_with_spend_key);
    RUN(build_tx_null_args);
    RUN(build_tx_bad_amount);
    RUN(tx_id_and_broadcast_null_args);
    printf("\n%d passed", g_passed);
    if (g_failed) printf(", %d FAILED", g_failed);
    printf("\n");
    return g_failed ? 1 : 0;
}
