/**
 * gen_test_addrs.cpp — Print the correct STAGENET_ADDR and STAGENET_SUBADDR
 * values for test_core.cpp, derived from TEST_VIEW_SK and TEST_TX_SK.
 *
 * Build target: gen_test_addrs (added to tests/CMakeLists.txt)
 *
 * Primary address layout (69 bytes):
 *   [0]     prefix (18=mainnet, 24=stagenet, 53=testnet)
 *   [1..32] spend public key
 *   [33..64] view public key
 *   [65..68] checksum = keccak256(data[0..64])[0..3]
 *
 * Stagenet subaddress layout (69 bytes):
 *   [0]     prefix (36=stagenet subaddress)
 *   [1..32] D = spend_pk + Hs("SubAddr" || view_sk || major || minor) * G
 *   [33..64] C = view_sk * D
 *   [65..68] checksum
 */

#include <cstdio>
#include <cstdint>
#include <cstring>

extern "C" {
#include "crypto-ops.h"
#include "keccak.h"
}
#include "monero_base58.h"

// ─── Test keys (must match test_core.cpp) ────────────────────────────────────

static const uint8_t TEST_VIEW_SK[32] = {
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0x04
};

static const uint8_t TEST_TX_SK[32] = {
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x04
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

static void sk_to_pk(const uint8_t sk[32], uint8_t pk[32]) {
    ge_p3 point;
    ge_scalarmult_base(&point, sk);
    ge_p3_tobytes(pk, &point);
}

static void make_address(uint8_t prefix,
                         const uint8_t spend_pk[32],
                         const uint8_t view_pk[32],
                         char *out_addr)  // must be >= 96 bytes
{
    uint8_t data[69];
    data[0] = prefix;
    memcpy(data + 1,  spend_pk, 32);
    memcpy(data + 33, view_pk,  32);

    uint8_t hash[32];
    keccak(data, 65, hash, 32);
    memcpy(data + 65, hash, 4);

    size_t enc_len = 96;
    monero_base58_encode(data, 69, out_addr, &enc_len);
}

// Compute subaddress keys for index (major=0, minor=1)
// D = spend_pk + Hs("SubAddr\0" || view_sk || le32(major) || le32(minor)) * G
// C = view_sk * D
static void make_subaddress(const uint8_t view_sk[32],
                            const uint8_t spend_pk[32],
                            uint32_t major, uint32_t minor,
                            uint8_t out_D[32], uint8_t out_C[32])
{
    // Build input for scalar hash: "SubAddr\0" (8 bytes) + view_sk (32) + major (4) + minor (4)
    uint8_t input[48];
    memcpy(input,    "SubAddr\0", 8);
    memcpy(input+8,  view_sk, 32);
    // little-endian 32-bit indices
    input[40] = major & 0xFF;
    input[41] = (major >> 8) & 0xFF;
    input[42] = (major >> 16) & 0xFF;
    input[43] = (major >> 24) & 0xFF;
    input[44] = minor & 0xFF;
    input[45] = (minor >> 8) & 0xFF;
    input[46] = (minor >> 16) & 0xFF;
    input[47] = (minor >> 24) & 0xFF;

    uint8_t m[32]; // scalar
    keccak(input, sizeof(input), m, 32);
    sc_reduce32(m); // reduce mod l

    // D = spend_pk + m*G
    ge_p3 spend_point, mG;
    ge_frombytes_vartime(&spend_point, spend_pk);
    ge_scalarmult_base(&mG, m);

    ge_cached mG_cached;
    ge_p3_to_cached(&mG_cached, &mG);

    ge_p1p1 D_p1p1;
    ge_add(&D_p1p1, &spend_point, &mG_cached);

    ge_p3 D_p3;
    ge_p1p1_to_p3(&D_p3, &D_p1p1);
    ge_p3_tobytes(out_D, &D_p3);

    // C = view_sk * D
    ge_p2 C_p2;
    ge_scalarmult(&C_p2, view_sk, &D_p3);
    ge_tobytes(out_C, &C_p2);
}

int main(void) {
    // Compute public keys
    uint8_t spend_pk[32], view_pk[32];
    sk_to_pk(TEST_TX_SK,  spend_pk);
    sk_to_pk(TEST_VIEW_SK, view_pk);

    // Primary stagenet address (prefix=24)
    char primary_addr[96];
    make_address(24, spend_pk, view_pk, primary_addr);

    // Subaddress (0,1) on stagenet (prefix=36)
    uint8_t D[32], C[32];
    make_subaddress(TEST_VIEW_SK, spend_pk, 0, 1, D, C);
    char sub_addr[96];
    make_address(36, D, C, sub_addr);

    printf("// Paste these into tests/test_core.cpp:\n\n");
    printf("static const char *STAGENET_ADDR =\n    \"%s\";\n\n", primary_addr);
    printf("static const char *STAGENET_SUBADDR =\n    \"%s\";\n\n", sub_addr);

    // Print D (subaddr spend pk) as a C array — needed to compute subaddr tx_pk in tests
    printf("// Subaddress spend public key D (for computing tx_pk = TEST_TX_SK * D):\n");
    printf("static const uint8_t STAGENET_SUBADDR_D[32] = {\n    ");
    for (int i = 0; i < 32; i++) {
        printf("0x%02X%s", D[i], i < 31 ? "," : "");
        if (i == 15) printf("\n    ");
    }
    printf("\n};\n\n");

    // Verify lengths
    printf("// Lengths: primary=%zu subaddr=%zu (both should be 95)\n",
           strlen(primary_addr), strlen(sub_addr));

    return 0;
}
