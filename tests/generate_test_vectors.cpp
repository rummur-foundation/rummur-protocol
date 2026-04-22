/**
 * generate_test_vectors.cpp — Deterministic test vector output for PROTOCOL.md §13.
 *
 * Uses fixed known inputs (weak keys, chosen for reproducibility — never
 * use these values in production). Run after building to populate §13:
 *
 *   ./build/tests/generate_test_vectors > vectors.txt
 *
 * Then paste the output into PROTOCOL.md §13 and commit.
 */

#include "libxmrmsg.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

// ─── Fixed test inputs ────────────────────────────────────────────────────────
//
// These are the canonical inputs for PROTOCOL.md §13. Do not change them
// after they are published — changing them invalidates all prior test vectors.

// view_sk: all-0xAA with a valid scalar tail byte.
// The corresponding stagenet address (TVEC_ADDR below) was derived from this key
// via gen_test_addrs — no live wallet required.
static const uint8_t TVEC_VIEW_SK[32] = {
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0x04
};

// tx_sk: all-0x42 bytes with a valid scalar tail. Fully deterministic.
static const uint8_t TVEC_TX_SK[32] = {
    0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
    0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
    0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
    0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x04
};

// thread_nonce: bytes 0x01..0x08
static const uint8_t TVEC_THREAD_NONCE[8] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

// Stagenet address whose view public key = TVEC_VIEW_SK × G.
// Spend public key = TVEC_TX_SK × G (all-0x55, last byte 0x04 — test-only key).
// Generated offline by tests/gen_test_addrs. Prefix 24 = stagenet primary.
static const char *TVEC_ADDR =
    "591vyBazs1675Q3SXLUTFN2LSdnnrjWXF92y27KHL1nLNkmYZUDYhK8VA6ZXkM96RS6h3pDoJWZwuPHFSg7r2CnQ2pND5sj";

// ─── Helpers ──────────────────────────────────────────────────────────────────

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%-20s ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

static void print_section(int n, const char *title) {
    printf("\n### Vector %d — %s\n\n", n, title);
}

static void run_vector(int n, const char *title,
                       const char *message_text,
                       uint8_t     flags,
                       const char *sender_addr)
{
    print_section(n, title);

    const uint8_t *msg     = reinterpret_cast<const uint8_t *>(message_text);
    const size_t   msg_len = strlen(message_text);

    // ── Inputs
    printf("**Inputs**\n\n```\n");
    print_hex("tx_sk:   ", TVEC_TX_SK, 32);
    print_hex("view_sk: ", TVEC_VIEW_SK, 32);
    printf("%-20s %s\n", "address: ", TVEC_ADDR);
    printf("%-20s \"%s\"\n", "message: ", message_text);
    printf("%-20s 0x%02x\n", "flags:   ", flags);
    print_hex("thread_nonce:", TVEC_THREAD_NONCE, 8);
    printf("```\n\n");

    // ── Derive tx_pk from tx_sk
    uint8_t tx_pk[32];
    if (xmrmsg_secret_key_to_public_key(TVEC_TX_SK, tx_pk) != XMRMSG_OK) {
        printf("[ERROR: secret_key_to_public_key failed — check TVEC_VIEW_SK is valid]\n");
        return;
    }

    // ── Derivation
    // sender side: derive(recipient_view_pk, tx_sk)
    // We can't compute view_pk from view_sk here without access to the address,
    // so we use the decode side: derive(tx_pk, view_sk) — same result
    uint8_t derivation[32];
    if (xmrmsg_derive(tx_pk, TVEC_VIEW_SK, derivation) != XMRMSG_OK) {
        printf("[ERROR: xmrmsg_derive failed]\n");
        return;
    }

    // ── Keystream
    uint8_t keystream[256];
    if (xmrmsg_keystream(derivation, keystream) != XMRMSG_OK) {
        printf("[ERROR: xmrmsg_keystream failed]\n");
        return;
    }

    printf("**Intermediate values**\n\n```\n");
    print_hex("tx_pk:      ", tx_pk, 32);
    print_hex("derivation: ", derivation, 32);
    print_hex("keystream:  ", keystream, 256);
    printf("```\n\n");

    // ── Full nonce
    uint8_t nonce[255];
    uint8_t out_thread[8];
    xmrmsg_result_t rc = xmrmsg_encode_nonce(
        TVEC_ADDR, TVEC_TX_SK,
        msg, msg_len,
        flags, sender_addr,
        TVEC_THREAD_NONCE,
        nonce, out_thread);

    printf("**Output**\n\n```\n");
    if (rc == XMRMSG_OK) {
        print_hex("nonce[255]: ", nonce, 255);

        // Decode to show plaintext
        const uint8_t (*candidates)[XMRMSG_KEY_SIZE] = { &tx_pk };
        xmrmsg_message_t decoded;
        memset(&decoded, 0, sizeof(decoded));
        if (xmrmsg_decode_nonce(nonce, TVEC_VIEW_SK, candidates, 1, &decoded) == XMRMSG_OK) {
            // XOR back to get plaintext (ciphertext XOR keystream = plaintext)
            uint8_t plaintext[245];
            memcpy(plaintext, nonce + 10, 245);
            for (int i = 0; i < 245; i++) plaintext[i] ^= keystream[i];
            print_hex("plaintext:  ", plaintext, 245);
            xmrmsg_free_message(&decoded);
        }
    } else {
        printf("[PENDING — set TVEC_VIEW_SK and TVEC_ADDR to your stagenet test wallet]\n");
    }
    printf("```\n");
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(void) {
    printf("## 13. Test Vectors\n");
    printf("\n");
    printf("Generated by `tests/generate_test_vectors`.\n");
    printf("See `third_party/monero-crypto/VENDOR_COMMIT` for the Monero source version.\n");
    printf("\n");
    printf("**WARNING**: The keys below are weak by design and exist solely for\n");
    printf("cross-implementation verification. Never use them outside tests.\n");

    run_vector(1, "Anonymous text message",
               "Hello, Rummur.",
               0x00, NULL);

    run_vector(2, "Text message with sender address",
               "Reply to me.",
               XMRMSG_FLAG_SENDER_ADDR, TVEC_ADDR);

    run_vector(3, "Reply message (IS_REPLY + SENDER_ADDR, thread_nonce echoed)",
               "Got it.",
               XMRMSG_FLAG_SENDER_ADDR | XMRMSG_FLAG_IS_REPLY, TVEC_ADDR);

    printf("\n---\n");

    return 0;
}
