/**
 * decode.cpp — Rummur nonce decoding (xmrmsg_decode_nonce, xmrmsg_free_message).
 *
 * Tries each candidate tx public key in turn. The first that produces a
 * recognised payload_type after decryption is accepted.
 */

#include "internal.h"
#include <cstring>
#include <cstdlib>

xmrmsg_result_t xmrmsg_decode_nonce(
    const uint8_t     nonce[XMRMSG_NONCE_SIZE],
    const uint8_t     view_sk[XMRMSG_KEY_SIZE],
    const uint8_t   (*candidate_tx_pks)[XMRMSG_KEY_SIZE],
    size_t            num_candidates,
    xmrmsg_message_t *out_message)
{
    if (!nonce || !view_sk || !candidate_tx_pks || num_candidates == 0 || !out_message)
        return XMRMSG_ERR_INVALID_ARG;

    // Check magic byte
    if (nonce[0] != XMRMSG_MAGIC)
        return XMRMSG_ERR_WRONG_MAGIC;

    // Parse version and flags
    const uint8_t version = nonce[1] >> 4;
    const uint8_t flags   = nonce[1] & 0x0F;

    if (version != XMRMSG_PROTOCOL_VERSION)
        return XMRMSG_ERR_UNKNOWN_VERSION;

    const uint8_t *ciphertext = nonce + XMRMSG_CIPHERTEXT_OFFSET;

    // Try each candidate tx public key
    for (size_t i = 0; i < num_candidates; i++) {
        // Recipient-side derivation: derive(tx_pk_candidate, view_sk)
        uint8_t derivation[XMRMSG_KEY_SIZE];
        if (xmrmsg_derive(candidate_tx_pks[i], view_sk, derivation) != XMRMSG_OK)
            continue;

        uint8_t keystream[XMRMSG_KEYSTREAM_SIZE];
        xmrmsg_result_t rc = xmrmsg_keystream(derivation, keystream);
        secure_zero(derivation, sizeof(derivation));
        if (rc != XMRMSG_OK) continue;

        // Decrypt in place into a local buffer
        uint8_t plaintext[XMRMSG_CIPHERTEXT_SIZE];
        memcpy(plaintext, ciphertext, XMRMSG_CIPHERTEXT_SIZE);
        xor_bytes(plaintext, keystream, XMRMSG_CIPHERTEXT_SIZE);
        secure_zero(keystream, sizeof(keystream));

        // Validate payload_type — wrong value means wrong candidate key
        if (plaintext[0] != XMRMSG_PAYLOAD_TEXT) {
            secure_zero(plaintext, sizeof(plaintext));
            continue;
        }

        // Parse msg_len (big-endian uint16)
        const uint16_t msg_len =
            (static_cast<uint16_t>(plaintext[1]) << 8) |
             static_cast<uint16_t>(plaintext[2]);

        // Validate that message + optional sender address fits within plaintext
        const bool has_sender = (flags & XMRMSG_FLAG_SENDER_ADDR) != 0;
        const size_t required = 3 + msg_len + (has_sender ? XMRMSG_ADDRESS_LEN : 0);
        if (required > XMRMSG_CIPHERTEXT_SIZE) {
            secure_zero(plaintext, sizeof(plaintext));
            continue; // corrupted or wrong key — try next candidate
        }

        // Allocate message text (NUL-terminated)
        uint8_t *text = static_cast<uint8_t *>(malloc(msg_len + 1));
        if (!text) {
            secure_zero(plaintext, sizeof(plaintext));
            return XMRMSG_ERR_ALLOC;
        }
        memcpy(text, plaintext + 3, msg_len);
        text[msg_len] = '\0';

        // Populate output struct
        memset(out_message, 0, sizeof(*out_message));
        out_message->payload_type       = plaintext[0];
        out_message->flags              = flags;
        out_message->text               = text;
        out_message->text_len           = msg_len;
        out_message->has_sender_address = has_sender ? 1 : 0;

        memcpy(out_message->thread_nonce,
               nonce + XMRMSG_THREAD_NONCE_OFFSET,
               XMRMSG_THREAD_NONCE_SIZE);

        if (has_sender) {
            const char *addr = reinterpret_cast<const char *>(plaintext + 3 + msg_len);
            memcpy(out_message->sender_address, addr, XMRMSG_ADDRESS_LEN);
            out_message->sender_address[XMRMSG_ADDRESS_LEN] = '\0';
        }

        secure_zero(plaintext, sizeof(plaintext));
        return XMRMSG_OK;
    }

    return XMRMSG_ERR_DECRYPT_FAILED;
}

void xmrmsg_free_message(xmrmsg_message_t *msg) {
    if (!msg) return;
    if (msg->text) {
        secure_zero(msg->text, msg->text_len);
        free(msg->text);
        msg->text     = nullptr;
        msg->text_len = 0;
    }
}
