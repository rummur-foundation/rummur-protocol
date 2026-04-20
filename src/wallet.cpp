/**
 * wallet.cpp — Wallet context, transaction construction, and broadcast.
 *
 * Phase 1 stub. The nonce-level API (encode/decode) is fully implemented
 * and testable. The wallet functions here compile and return errors until
 * the libwallet integration is completed in Phase 2.
 *
 * Real implementation notes (Phase 2):
 *   - xmrmsg_wallet_t wraps Monero's Wallet2 or WalletImpl from wallet_api.h
 *   - xmrmsg_build_tx calls wallet->createTransaction() with the nonce bytes
 *     inserted into tx_extra via a custom TransactionInfo hook
 *   - xmrmsg_broadcast_tx calls wallet->submitTransaction() routed through
 *     the configured SOCKS5 proxy
 */

#include "internal.h"
#include <cstring>
#include <cstdlib>

// ─── Opaque handle definitions (stubs) ───────────────────────────────────────

struct xmrmsg_wallet {
    uint8_t  view_sk[XMRMSG_KEY_SIZE];
    uint8_t  spend_sk[XMRMSG_KEY_SIZE];
    bool     has_spend_key;
    char    *primary_address;   // heap-allocated, NUL-terminated
    uint64_t restore_height;
    char    *socks5_proxy;      // heap-allocated, NUL-terminated, or NULL
};

struct xmrmsg_pending_tx {
    uint8_t  txid[XMRMSG_TXID_SIZE];
    uint8_t *serialized;        // heap-allocated raw transaction bytes
    size_t   serialized_len;
};

// ─── Library version ─────────────────────────────────────────────────────────

const char *xmrmsg_version_string(void) {
    return "libxmrmsg 0.1";
}

// ─── Wallet creation ──────────────────────────────────────────────────────────

xmrmsg_result_t xmrmsg_wallet_from_seed(
    const char       *seed_phrase,
    uint64_t          restore_height,
    const char       *socks5_proxy,
    xmrmsg_wallet_t **out_wallet)
{
    // Phase 2: derive spend_sk and view_sk from seed phrase using
    // Monero's ElectrumWords / crypto::generate_keys_from_seed
    (void)seed_phrase; (void)restore_height; (void)socks5_proxy; (void)out_wallet;
    return XMRMSG_ERR_INVALID_ARG; // stub
}

xmrmsg_result_t xmrmsg_wallet_from_keys(
    const uint8_t    *spend_sk,
    const uint8_t     view_sk[XMRMSG_KEY_SIZE],
    const char       *primary_address,
    uint64_t          restore_height,
    const char       *socks5_proxy,
    xmrmsg_wallet_t **out_wallet)
{
    if (!view_sk || !primary_address || !out_wallet)
        return XMRMSG_ERR_INVALID_ARG;

    // Validate the primary address
    if (xmrmsg_validate_address(primary_address) != XMRMSG_OK)
        return XMRMSG_ERR_INVALID_ADDRESS;

    auto *w = static_cast<xmrmsg_wallet_t *>(calloc(1, sizeof(xmrmsg_wallet_t)));
    if (!w) return XMRMSG_ERR_ALLOC;

    memcpy(w->view_sk, view_sk, XMRMSG_KEY_SIZE);
    w->restore_height = restore_height;

    if (spend_sk) {
        memcpy(w->spend_sk, spend_sk, XMRMSG_KEY_SIZE);
        w->has_spend_key = true;
    }

    w->primary_address = strdup(primary_address);
    if (!w->primary_address) { free(w); return XMRMSG_ERR_ALLOC; }

    if (socks5_proxy) {
        w->socks5_proxy = strdup(socks5_proxy);
        if (!w->socks5_proxy) { free(w->primary_address); free(w); return XMRMSG_ERR_ALLOC; }
    }

    *out_wallet = w;
    return XMRMSG_OK;
}

void xmrmsg_wallet_free(xmrmsg_wallet_t *wallet) {
    if (!wallet) return;
    secure_zero(wallet->spend_sk, XMRMSG_KEY_SIZE);
    secure_zero(wallet->view_sk,  XMRMSG_KEY_SIZE);
    free(wallet->primary_address);
    free(wallet->socks5_proxy);
    free(wallet);
}

// ─── Transaction construction ─────────────────────────────────────────────────

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
    uint8_t               out_thread_nonce[XMRMSG_THREAD_NONCE_SIZE])
{
    if (!wallet || !recipient_addr || !out_tx)
        return XMRMSG_ERR_INVALID_ARG;
    if (!wallet->has_spend_key)
        return XMRMSG_ERR_VIEW_ONLY;

    // Validate output amount
    if (output_amount == 0)
        output_amount = XMRMSG_DEFAULT_DUST_PICONERO;
    if (output_amount < XMRMSG_MIN_DUST_PICONERO)
        return XMRMSG_ERR_INVALID_ARG;

    // Phase 2: construct a real RingCT transaction via libwallet:
    //   1. xmrmsg_generate_tx_keypair(tx_sk, tx_pk)
    //   2. xmrmsg_encode_nonce(recipient_addr, tx_sk, ...) → nonce[255]
    //   3. wallet->createTransaction(recipient_addr, output_amount, priority)
    //      with nonce inserted into tx_extra
    //   4. Return the pending tx handle

    (void)message; (void)message_len; (void)flags; (void)sender_addr;
    (void)thread_nonce_in; (void)priority; (void)out_thread_nonce;
    return XMRMSG_ERR_INVALID_ARG; // stub
}

xmrmsg_result_t xmrmsg_tx_id(
    const xmrmsg_pending_tx_t *tx,
    uint8_t                    out_txid[XMRMSG_TXID_SIZE])
{
    if (!tx || !out_txid) return XMRMSG_ERR_INVALID_ARG;
    memcpy(out_txid, tx->txid, XMRMSG_TXID_SIZE);
    return XMRMSG_OK;
}

xmrmsg_result_t xmrmsg_broadcast_tx(
    const xmrmsg_pending_tx_t *tx,
    const char                *node_url,
    const char                *socks5_proxy)
{
    if (!tx || !node_url) return XMRMSG_ERR_INVALID_ARG;
    // Phase 2: POST tx->serialized to node_url/sendrawtransaction via
    // libcurl or equivalent, routing through socks5_proxy if non-NULL.
    (void)socks5_proxy;
    return XMRMSG_ERR_INVALID_ARG; // stub
}

void xmrmsg_free_pending_tx(xmrmsg_pending_tx_t *tx) {
    if (!tx) return;
    free(tx->serialized);
    free(tx);
}
