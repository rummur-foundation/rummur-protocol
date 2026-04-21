/**
 * libxmrmsg.h — Public C API for the Rummur messaging protocol library
 *
 * All functions return xmrmsg_result_t. XMRMSG_OK (0) means success.
 * Negative values are error codes. No exceptions cross the API boundary.
 *
 * Memory ownership:
 *   - Fixed-size outputs (nonces, keys): caller provides the buffer.
 *   - Variable-size outputs (xmrmsg_message_t::text): library allocates;
 *     caller frees with xmrmsg_free_message().
 *   - Opaque handles: library allocates and owns; caller frees with the
 *     matching xmrmsg_free_*() function.
 */

#ifndef LIBXMRMSG_H
#define LIBXMRMSG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ────────────────────────────────────────────────────────────── */

#define XMRMSG_VERSION_MAJOR            0
#define XMRMSG_VERSION_MINOR            1

#define XMRMSG_NONCE_SIZE             255   /* total nonce content bytes            */
#define XMRMSG_CIPHERTEXT_OFFSET       10   /* ciphertext starts at byte 10         */
#define XMRMSG_CIPHERTEXT_SIZE        245   /* bytes 10–254                         */
#define XMRMSG_THREAD_NONCE_OFFSET      2   /* thread_nonce starts at byte 2        */
#define XMRMSG_THREAD_NONCE_SIZE        8   /* bytes 2–9                            */
#define XMRMSG_ADDRESS_LEN             95   /* base58 address string, no NUL        */
#define XMRMSG_KEY_SIZE                32   /* any 32-byte key or derivation        */
#define XMRMSG_KEYSTREAM_SIZE         256   /* 8 × 32-byte blocks                   */
#define XMRMSG_TXID_SIZE               32   /* transaction ID                       */

#define XMRMSG_MAX_MSG_ANON           242   /* max text bytes, no sender address    */
#define XMRMSG_MAX_MSG_WITH_SENDER    147   /* max text bytes, sender addr included */

#define XMRMSG_DEFAULT_DUST_PICONERO  1000000ULL  /* 0.000001 XMR — default minimum output */
#define XMRMSG_MIN_DUST_PICONERO            1ULL  /* 1 piconero — protocol absolute floor  */

#define XMRMSG_MAGIC                  0x4D  /* 'M' — protocol magic byte            */
#define XMRMSG_PROTOCOL_VERSION       0x00  /* version 0 in upper nibble            */

/* ── Flag bits (lower 4 bits of version_flags, byte 1 of nonce) ─────────── */

#define XMRMSG_FLAG_SENDER_ADDR       0x01  /* bit 0: sender address appended to payload */
#define XMRMSG_FLAG_IS_REPLY          0x02  /* bit 1: reply; thread_nonce echoes original */

/* ── Payload types (plaintext byte 0) ───────────────────────────────────── */

#define XMRMSG_PAYLOAD_TEXT           0x01  /* UTF-8 text message */

/* ── Error codes ─────────────────────────────────────────────────────────── */

typedef enum xmrmsg_result {
    XMRMSG_OK                   =  0,
    XMRMSG_ERR_INVALID_ARG      = -1,  /* NULL or out-of-range argument              */
    XMRMSG_ERR_INVALID_ADDRESS  = -2,  /* address string failed to parse or validate */
    XMRMSG_ERR_MSG_TOO_LONG     = -3,  /* message exceeds capacity for chosen flags  */
    XMRMSG_ERR_DECRYPT_FAILED   = -4,  /* no candidate tx_pk produced a valid payload*/
    XMRMSG_ERR_UNKNOWN_VERSION  = -5,  /* nonce carries an unrecognised protocol ver */
    XMRMSG_ERR_UNKNOWN_PAYLOAD  = -6,  /* decrypted payload_type not recognised      */
    XMRMSG_ERR_ALLOC            = -7,  /* memory allocation failure                  */
    XMRMSG_ERR_CRYPTO           = -8,  /* underlying crypto operation failed         */
    XMRMSG_ERR_WRONG_MAGIC      = -9,  /* nonce[0] != XMRMSG_MAGIC                  */
    XMRMSG_ERR_NONCE_LENGTH     = -10, /* nonce is not exactly XMRMSG_NONCE_SIZE bytes*/
    XMRMSG_ERR_VIEW_ONLY        = -11, /* operation requires spend key; wallet is view-only */
} xmrmsg_result_t;

/* ── Fee priority ────────────────────────────────────────────────────────── */

typedef enum xmrmsg_priority {
    XMRMSG_PRIORITY_SLOW   = 1,
    XMRMSG_PRIORITY_NORMAL = 4,
    XMRMSG_PRIORITY_FAST   = 20,
} xmrmsg_priority_t;

/* ── Decoded message ─────────────────────────────────────────────────────── */

typedef struct xmrmsg_message {
    uint8_t  payload_type;                           /* XMRMSG_PAYLOAD_TEXT etc.          */
    uint8_t  flags;                                  /* flag bits as received             */
    uint8_t  thread_nonce[XMRMSG_THREAD_NONCE_SIZE]; /* conversation grouping hint        */
    uint8_t *text;                                   /* heap-allocated, NUL-terminated    */
    size_t   text_len;                               /* byte length (not char count)      */
    int      has_sender_address;                     /* 1 if SENDER_ADDR flag was set     */
    char     sender_address[XMRMSG_ADDRESS_LEN + 1];/* NUL-terminated; empty if absent   */
} xmrmsg_message_t;

/* ── Opaque handles ──────────────────────────────────────────────────────── */

typedef struct xmrmsg_wallet      xmrmsg_wallet_t;
typedef struct xmrmsg_pending_tx  xmrmsg_pending_tx_t;

/* ════════════════════════════════════════════════════════════════════════════
 * Library metadata
 * ════════════════════════════════════════════════════════════════════════════ */

/** Returns a NUL-terminated version string, e.g. "libxmrmsg 0.1". */
const char *xmrmsg_version_string(void);

/* ════════════════════════════════════════════════════════════════════════════
 * Nonce-level API  (no wallet required — fully testable in isolation)
 * ════════════════════════════════════════════════════════════════════════════ */

/**
 * Build a 255-byte Rummur nonce payload.
 *
 * @param recipient_addr    NUL-terminated 95-char base58 Monero address.
 *                          Primary address or subaddress both accepted.
 * @param tx_sk             32-byte transaction secret key. MUST be unique per
 *                          transaction. Generate with xmrmsg_generate_tx_keypair()
 *                          or equivalent secure RNG.
 * @param message           UTF-8 message bytes.
 * @param message_len       Byte length of message. Must not exceed
 *                          XMRMSG_MAX_MSG_ANON when XMRMSG_FLAG_SENDER_ADDR is
 *                          clear, or XMRMSG_MAX_MSG_WITH_SENDER when set.
 * @param flags             XMRMSG_FLAG_* bitmask.
 * @param sender_addr       NUL-terminated 95-char address to embed in payload.
 *                          Required (non-NULL) when XMRMSG_FLAG_SENDER_ADDR is
 *                          set; ignored otherwise.
 * @param thread_nonce_in   8-byte thread nonce to echo. Pass NULL to generate a
 *                          fresh random nonce (use for the first message in a
 *                          new conversation).
 * @param out_nonce         Output: exactly XMRMSG_NONCE_SIZE (255) bytes.
 * @param out_thread_nonce  Output: thread_nonce written into the nonce — echoed
 *                          back if thread_nonce_in was provided, or the newly
 *                          generated random value if NULL was passed.
 *                          May be NULL if the caller does not need the value.
 *
 * @return XMRMSG_OK on success.
 */
xmrmsg_result_t xmrmsg_encode_nonce(
    const char    *recipient_addr,
    const uint8_t  tx_sk[XMRMSG_KEY_SIZE],
    const uint8_t *message,
    size_t         message_len,
    uint8_t        flags,
    const char    *sender_addr,
    const uint8_t  thread_nonce_in[XMRMSG_THREAD_NONCE_SIZE],
    uint8_t        out_nonce[XMRMSG_NONCE_SIZE],
    uint8_t        out_thread_nonce[XMRMSG_THREAD_NONCE_SIZE]
);

/**
 * Decode a 255-byte Rummur nonce.
 *
 * Tries each candidate tx public key in order. The first candidate that
 * produces a recognised payload_type after decryption is accepted.
 * Returns XMRMSG_ERR_DECRYPT_FAILED if no candidate succeeds — this is the
 * normal result for transactions that are not addressed to this recipient.
 *
 * @param nonce              255-byte nonce content from tx_extra (tag 0x02).
 * @param view_sk            Recipient's 32-byte private view key.
 * @param candidate_tx_pks   Array of 32-byte tx public key candidates.
 *                           Provide the main tx_pk (tag 0x01) first, then any
 *                           additional tx_pks (tag 0x04) in output-index order.
 *                           For standard address transactions, one candidate is
 *                           sufficient. For subaddress transactions, include all
 *                           additional keys.
 * @param num_candidates     Number of entries in candidate_tx_pks.
 * @param out_message        Caller-allocated struct, populated on success.
 *                           out_message->text is heap-allocated; the caller
 *                           MUST free it with xmrmsg_free_message().
 *
 * @return XMRMSG_OK on success.
 */
xmrmsg_result_t xmrmsg_decode_nonce(
    const uint8_t     nonce[XMRMSG_NONCE_SIZE],
    const uint8_t     view_sk[XMRMSG_KEY_SIZE],
    const uint8_t   (*candidate_tx_pks)[XMRMSG_KEY_SIZE],
    size_t            num_candidates,
    xmrmsg_message_t *out_message
);

/**
 * Free heap memory owned by a decoded message (specifically, msg->text).
 * Safe to call with a zero-initialised or already-freed struct.
 */
void xmrmsg_free_message(xmrmsg_message_t *msg);

/* ════════════════════════════════════════════════════════════════════════════
 * Key utilities
 * ════════════════════════════════════════════════════════════════════════════ */

/**
 * Generate a random transaction keypair.
 *   tx_pk = tx_sk × G  (standard address convention)
 *
 * For subaddress recipients, pass tx_sk to xmrmsg_encode_nonce; the wallet
 * derives tx_pk = tx_sk × D during transaction construction.
 *
 * @param out_tx_sk  Output: 32-byte transaction secret key.
 * @param out_tx_pk  Output: 32-byte transaction public key (tx_sk × G).
 */
xmrmsg_result_t xmrmsg_generate_tx_keypair(
    uint8_t out_tx_sk[XMRMSG_KEY_SIZE],
    uint8_t out_tx_pk[XMRMSG_KEY_SIZE]
);

/**
 * Compute the ECDH shared derivation: derivation = 8 × sec_key × pub_key.
 *
 * This wraps Monero's generate_key_derivation(pub_key, sec_key, derivation).
 * The two calling conventions are:
 *
 *   Sender:    xmrmsg_derive(recipient_view_pk, tx_sk,  out)
 *   Recipient: xmrmsg_derive(tx_pk,             view_sk, out)
 *
 * Both produce the same 32-byte derivation for a matching (tx_sk, view_sk) pair.
 * For subaddress recipients, pass the additional tx_pk (tx_sk × D) as pub_key.
 *
 * Exposed for test vector generation and cross-implementation verification.
 *
 * @param pub_key        32-byte public key.
 * @param sec_key        32-byte secret key.
 * @param out_derivation Output: 32-byte derivation.
 */
xmrmsg_result_t xmrmsg_derive(
    const uint8_t pub_key[XMRMSG_KEY_SIZE],
    const uint8_t sec_key[XMRMSG_KEY_SIZE],
    uint8_t       out_derivation[XMRMSG_KEY_SIZE]
);

/**
 * Derive a public key from a secret key: pub = sec × G
 *
 * Used to compute tx_pk from a known tx_sk in tests and by the wallet layer
 * when constructing standard-address transactions.
 *
 * @param sec_key  32-byte secret key.
 * @param out_pk   Output: 32-byte public key.
 */
xmrmsg_result_t xmrmsg_secret_key_to_public_key(
    const uint8_t sec_key[XMRMSG_KEY_SIZE],
    uint8_t       out_pk[XMRMSG_KEY_SIZE]
);

/**
 * Scalar multiplication on the curve: out = sec × pub  (no cofactor).
 *
 * Used by the wallet layer to compute the subaddress transaction public key:
 *   tx_pk = tx_sk × D   (where D is the subaddress spend public key)
 *
 * For standard addresses use xmrmsg_secret_key_to_public_key (sec × G) instead.
 *
 * @param sec_key  32-byte scalar.
 * @param pub_key  32-byte curve point (e.g. a subaddress spend public key D).
 * @param out_pk   Output: 32-byte result point.
 */
xmrmsg_result_t xmrmsg_scalarmult(
    const uint8_t sec_key[XMRMSG_KEY_SIZE],
    const uint8_t pub_key[XMRMSG_KEY_SIZE],
    uint8_t       out_pk[XMRMSG_KEY_SIZE]
);

/**
 * Generate the 256-byte keystream from a derivation (counter-mode cn_fast_hash).
 *
 * Only the first XMRMSG_CIPHERTEXT_SIZE (245) bytes are used for encryption;
 * the full 256-byte output is returned for test vector completeness.
 *
 * Exposed for test vector generation and cross-implementation verification.
 *
 * @param derivation     32-byte derivation from xmrmsg_derive().
 * @param out_keystream  Output: XMRMSG_KEYSTREAM_SIZE (256) bytes.
 */
xmrmsg_result_t xmrmsg_keystream(
    const uint8_t derivation[XMRMSG_KEY_SIZE],
    uint8_t       out_keystream[XMRMSG_KEYSTREAM_SIZE]
);

/* ════════════════════════════════════════════════════════════════════════════
 * Address utilities
 * ════════════════════════════════════════════════════════════════════════════ */

/**
 * Validate a Monero address string.
 * Accepts primary addresses and subaddresses on mainnet, testnet, and stagenet.
 *
 * @return XMRMSG_OK if valid, XMRMSG_ERR_INVALID_ADDRESS otherwise.
 */
xmrmsg_result_t xmrmsg_validate_address(const char *address);

/**
 * Determine whether an address is a subaddress.
 *
 * @return  1 if subaddress, 0 if primary address, -1 if invalid.
 */
int xmrmsg_is_subaddress(const char *address);

/* ════════════════════════════════════════════════════════════════════════════
 * Wallet API  (transaction construction and broadcast)
 * ════════════════════════════════════════════════════════════════════════════ */

/**
 * Create a wallet context from a 25-word Monero seed phrase.
 *
 * @param seed_phrase     NUL-terminated 25-word seed phrase (space-separated).
 * @param restore_height  Blockchain height to restore from. 0 = scan from genesis.
 * @param out_wallet      Output: opaque wallet handle. Free with xmrmsg_wallet_free().
 */
xmrmsg_result_t xmrmsg_wallet_from_seed(
    const char       *seed_phrase,
    uint64_t          restore_height,
    const char       *socks5_proxy,   /* "host:port" for Tor, NULL for direct */
    xmrmsg_wallet_t **out_wallet
);

/**
 * Create a wallet context from raw key material.
 *
 * Intended for use when keys are held in hardware (Secure Enclave / Keystore)
 * and the caller manages key storage independently of this library.
 *
 * @param spend_sk        32-byte private spend key. Pass NULL for a view-only
 *                        wallet (receive/scan only; xmrmsg_build_tx will fail).
 * @param view_sk         32-byte private view key. Must not be NULL.
 * @param primary_address NUL-terminated 95-char primary address for this wallet.
 * @param restore_height  Blockchain height to restore from.
 * @param out_wallet      Output: opaque wallet handle. Free with xmrmsg_wallet_free().
 */
xmrmsg_result_t xmrmsg_wallet_from_keys(
    const uint8_t    *spend_sk,
    const uint8_t     view_sk[XMRMSG_KEY_SIZE],
    const char       *primary_address,
    uint64_t          restore_height,
    const char       *socks5_proxy,   /* "host:port" for Tor, NULL for direct */
    xmrmsg_wallet_t **out_wallet
);

/** Free a wallet handle. Safe to call with NULL. */
void xmrmsg_wallet_free(xmrmsg_wallet_t *wallet);

/**
 * Construct a Rummur message transaction.
 *
 * The RingCT output is directed to recipient_addr with output_amount piconero.
 * The Rummur nonce is encrypted and embedded in tx_extra. The transaction is
 * not broadcast until xmrmsg_broadcast_tx() is called.
 *
 * @param wallet            Wallet context. Must not be view-only.
 * @param recipient_addr    NUL-terminated 95-char recipient address (primary or subaddress).
 * @param message           UTF-8 message bytes.
 * @param message_len       Byte length of message.
 * @param flags             XMRMSG_FLAG_* bitmask.
 * @param sender_addr       NUL-terminated sender address to embed, or NULL.
 * @param thread_nonce_in   8-byte thread nonce, or NULL for a new conversation.
 * @param output_amount     Piconero to send to recipient.
 *                          Pass 0 to use XMRMSG_DEFAULT_DUST_PICONERO.
 *                          Must be >= XMRMSG_MIN_DUST_PICONERO if non-zero.
 * @param priority          Fee priority tier.
 * @param out_tx            Output: opaque pending tx handle. Free with xmrmsg_free_pending_tx().
 * @param out_thread_nonce  Output: thread_nonce used. May be NULL.
 *
 * @return XMRMSG_OK on success.
 */
xmrmsg_result_t xmrmsg_build_tx(
    xmrmsg_wallet_t      *wallet,
    const char           *recipient_addr,
    const uint8_t        *message,
    size_t                message_len,
    uint8_t               flags,
    const char           *sender_addr,
    const uint8_t         thread_nonce_in[XMRMSG_THREAD_NONCE_SIZE],
    uint64_t              output_amount,
    xmrmsg_priority_t     priority,
    xmrmsg_pending_tx_t **out_tx,
    uint8_t               out_thread_nonce[XMRMSG_THREAD_NONCE_SIZE]
);

/**
 * Get the transaction ID of a pending transaction (before broadcast).
 *
 * @param tx        Pending transaction.
 * @param out_txid  Output: 32-byte transaction ID (hash).
 */
xmrmsg_result_t xmrmsg_tx_id(
    const xmrmsg_pending_tx_t *tx,
    uint8_t                    out_txid[XMRMSG_TXID_SIZE]
);

/**
 * Broadcast a pending transaction to the Monero network via daemon RPC.
 *
 * The caller is responsible for routing the connection through Tor.
 * All Rummur client implementations MUST do so — pass a Tor SOCKS proxy URL
 * or a .onion node URL. Clearnet node URLs are permitted only when the user
 * has explicitly opted out of Tor.
 *
 * @param tx            Pending transaction to broadcast.
 * @param node_url      NUL-terminated daemon RPC URL, e.g.
 *                      "http://node.example.com:18081" or a .onion address.
 * @param socks5_proxy  NUL-terminated "host:port" SOCKS5 proxy, or NULL for
 *                      direct connection. Pass the local Tor SOCKS5 port
 *                      (e.g. "127.0.0.1:9050") for all production use.
 *                      Direct connections are permitted only when the user
 *                      has explicitly opted out of Tor.
 */
xmrmsg_result_t xmrmsg_broadcast_tx(
    const xmrmsg_pending_tx_t *tx,
    const char                *node_url,
    const char                *socks5_proxy
);

/** Free a pending transaction handle. Safe to call with NULL. */
void xmrmsg_free_pending_tx(xmrmsg_pending_tx_t *tx);

/* ════════════════════════════════════════════════════════════════════════════
 * Test vector support
 * ════════════════════════════════════════════════════════════════════════════ */

/**
 * Generate deterministic test vectors from fixed known inputs and write them
 * as human-readable hex to out_buf. Used to populate PROTOCOL.md §13.
 *
 * Produces three vectors:
 *   1. Anonymous text message    (SENDER_ADDR clear, IS_REPLY clear)
 *   2. Message with sender addr  (SENDER_ADDR set,   IS_REPLY clear)
 *   3. Reply message             (SENDER_ADDR set,   IS_REPLY set, thread_nonce echoed)
 *
 * Each vector includes: tx_sk, view_sk, tx_pk, message, thread_nonce, flags,
 * derivation (32 bytes), keystream (256 bytes), plaintext (245 bytes),
 * full nonce (255 bytes).
 *
 * @param out_buf   Output buffer for formatted text.
 * @param buf_size  Size of out_buf in bytes.
 *
 * @return XMRMSG_OK on success, XMRMSG_ERR_INVALID_ARG if buf_size is too small.
 */
xmrmsg_result_t xmrmsg_generate_test_vectors(char *out_buf, size_t buf_size);

#ifdef __cplusplus
}
#endif

#endif /* LIBXMRMSG_H */
