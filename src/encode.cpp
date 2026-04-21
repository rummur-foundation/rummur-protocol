/**
 * encode.cpp — Rummur nonce encoding (xmrmsg_encode_nonce).
 *
 * Builds the 255-byte tx_extra_nonce payload per PROTOCOL.md §4–6.
 */

#include "internal.h"
#include <cstring>

xmrmsg_result_t xmrmsg_encode_nonce(
    const char    *recipient_addr,
    const uint8_t  tx_sk[XMRMSG_KEY_SIZE],
    const uint8_t *message,
    size_t         message_len,
    uint8_t        flags,
    const char    *sender_addr,
    const uint8_t  thread_nonce_in[XMRMSG_THREAD_NONCE_SIZE],
    uint8_t        out_nonce[XMRMSG_NONCE_SIZE],
    uint8_t        out_thread_nonce[XMRMSG_THREAD_NONCE_SIZE])
{
    if (!recipient_addr || !tx_sk || (!message && message_len > 0) || !out_nonce)
        return XMRMSG_ERR_INVALID_ARG;

    const bool include_sender = (flags & XMRMSG_FLAG_SENDER_ADDR) != 0;
    if (include_sender && !sender_addr)
        return XMRMSG_ERR_INVALID_ARG;

    const size_t max_msg = include_sender
        ? XMRMSG_MAX_MSG_WITH_SENDER
        : XMRMSG_MAX_MSG_ANON;
    if (message_len > max_msg)
        return XMRMSG_ERR_MSG_TOO_LONG;

    // Parse and validate addresses
    parsed_address_t recipient;
    if (!xmrmsg_parse_address(recipient_addr, &recipient))
        return XMRMSG_ERR_INVALID_ADDRESS;

    if (include_sender) {
        parsed_address_t sender;
        if (!xmrmsg_parse_address(sender_addr, &sender))
            return XMRMSG_ERR_INVALID_ADDRESS;
    }

    // ECDH derivation — sender side: derive(recipient_view_pk, tx_sk)
    uint8_t derivation[XMRMSG_KEY_SIZE];
    xmrmsg_result_t rc = xmrmsg_derive(recipient.view_pk, tx_sk, derivation);
    if (rc != XMRMSG_OK) return rc;

    // Keystream
    uint8_t keystream[XMRMSG_KEYSTREAM_SIZE];
    rc = xmrmsg_keystream(derivation, keystream);
    secure_zero(derivation, sizeof(derivation));
    if (rc != XMRMSG_OK) return rc;

    // ── Build 245-byte plaintext ──────────────────────────────────────────────
    //
    //  [0]      payload_type  (1 byte)
    //  [1..2]   msg_len       (uint16 big-endian)
    //  [3..N]   message       (msg_len bytes)
    //  [N..N+95] sender_addr  (95 bytes, only if SENDER_ADDR flag set)
    //  [rest]   random padding

    uint8_t plaintext[XMRMSG_CIPHERTEXT_SIZE];

    // Fill entire buffer with random padding first — ensures tail is never zero
    PLATFORM_RANDOM(plaintext, XMRMSG_CIPHERTEXT_SIZE);

    size_t pos = 0;
    plaintext[pos++] = XMRMSG_PAYLOAD_TEXT;
    plaintext[pos++] = static_cast<uint8_t>(message_len >> 8);
    plaintext[pos++] = static_cast<uint8_t>(message_len & 0xFF);

    if (message_len > 0)
        memcpy(plaintext + pos, message, message_len);
    pos += message_len;

    if (include_sender)
        memcpy(plaintext + pos, sender_addr, XMRMSG_ADDRESS_LEN);
    // pos not advanced — padding already filled the rest

    // ── Encrypt: ciphertext = plaintext XOR keystream[0..244] ────────────────
    xor_bytes(plaintext, keystream, XMRMSG_CIPHERTEXT_SIZE);
    secure_zero(keystream, sizeof(keystream));

    // ── Thread nonce ──────────────────────────────────────────────────────────
    uint8_t thread_nonce[XMRMSG_THREAD_NONCE_SIZE];
    if (thread_nonce_in) {
        memcpy(thread_nonce, thread_nonce_in, XMRMSG_THREAD_NONCE_SIZE);
    } else {
        PLATFORM_RANDOM(thread_nonce, XMRMSG_THREAD_NONCE_SIZE);
    }

    // ── Assemble 255-byte nonce ───────────────────────────────────────────────
    //  [0]      magic         = 0x4D
    //  [1]      version_flags = (version << 4) | flags
    //  [2..9]   thread_nonce
    //  [10..254] ciphertext
    out_nonce[0] = XMRMSG_MAGIC;
    out_nonce[1] = static_cast<uint8_t>((XMRMSG_PROTOCOL_VERSION << 4) | (flags & 0x0F));
    memcpy(out_nonce + XMRMSG_THREAD_NONCE_OFFSET, thread_nonce, XMRMSG_THREAD_NONCE_SIZE);
    memcpy(out_nonce + XMRMSG_CIPHERTEXT_OFFSET,   plaintext,    XMRMSG_CIPHERTEXT_SIZE);

    if (out_thread_nonce)
        memcpy(out_thread_nonce, thread_nonce, XMRMSG_THREAD_NONCE_SIZE);

    secure_zero(plaintext, sizeof(plaintext));
    return XMRMSG_OK;
}
