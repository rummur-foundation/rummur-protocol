/**
 * address.cpp — Monero address parsing and validation.
 *
 * Parses the 95-char base58 Monero address format. Uses our portable
 * monero_base58 decoder and cn_fast_hash (via keccak) for checksum verification.
 *
 * Address format (decoded: 69 bytes total):
 *   [0]     prefix byte  (network + address type)
 *   [1..32] spend public key (32 bytes)
 *   [33..64] view public key (32 bytes)
 *   [65..68] checksum: first 4 bytes of keccak-256([0..64])
 */

#include "internal.h"
#include <cstring>

// ─── Network prefix bytes ─────────────────────────────────────────────────────
// Source: src/cryptonote_config.h in the Monero repository

static const uint8_t PREFIXES_PRIMARY[] = { 18, 24, 53 }; // mainnet, stagenet, testnet
static const uint8_t PREFIXES_SUBADDR[] = { 42, 36, 63 }; // mainnet, stagenet, testnet

static const size_t DECODED_ADDR_BYTES = 69;

static bool classify_prefix(uint8_t byte, bool *is_subaddr_out) {
    for (size_t i = 0; i < sizeof(PREFIXES_PRIMARY); i++) {
        if (byte == PREFIXES_PRIMARY[i]) { *is_subaddr_out = false; return true; }
    }
    for (size_t i = 0; i < sizeof(PREFIXES_SUBADDR); i++) {
        if (byte == PREFIXES_SUBADDR[i]) { *is_subaddr_out = true; return true; }
    }
    return false;
}

static bool verify_checksum(const uint8_t *data, size_t total_len) {
    // checksum = first 4 bytes of keccak-256(data[0 .. total_len-5])
    uint8_t hash[32];
    keccak(data, total_len - 4, hash, 32);
    return memcmp(hash, data + total_len - 4, 4) == 0;
}

// ─── Internal helper ─────────────────────────────────────────────────────────

bool xmrmsg_parse_address(const char *address, parsed_address_t *out) {
    if (!address || !out) return false;

    size_t len = strlen(address);
    if (len != XMRMSG_ADDRESS_LEN) return false;

    uint8_t decoded[DECODED_ADDR_BYTES];
    size_t  decoded_len = sizeof(decoded);

    if (!monero_base58_decode(address, len, decoded, &decoded_len))
        return false;
    if (decoded_len != DECODED_ADDR_BYTES)
        return false;

    bool is_sub;
    if (!classify_prefix(decoded[0], &is_sub)) return false;
    if (!verify_checksum(decoded, DECODED_ADDR_BYTES)) return false;

    out->is_subaddress = is_sub;
    memcpy(out->spend_pk, decoded + 1,  XMRMSG_KEY_SIZE);
    memcpy(out->view_pk,  decoded + 33, XMRMSG_KEY_SIZE);
    return true;
}

// ─── Public API ───────────────────────────────────────────────────────────────

xmrmsg_result_t xmrmsg_validate_address(const char *address) {
    if (!address) return XMRMSG_ERR_INVALID_ARG;
    parsed_address_t p;
    return xmrmsg_parse_address(address, &p) ? XMRMSG_OK : XMRMSG_ERR_INVALID_ADDRESS;
}

int xmrmsg_is_subaddress(const char *address) {
    parsed_address_t p;
    if (!xmrmsg_parse_address(address, &p)) return -1;
    return p.is_subaddress ? 1 : 0;
}
