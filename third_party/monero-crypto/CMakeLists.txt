cmake_minimum_required(VERSION 3.20)

# Vendored Monero cryptographic primitives — pure C, platform-independent.
# Only the curve25519 group operations (crypto-ops) and Keccak are vendored.
# Monero's crypto.cpp/crypto.h (Boost-dependent) and base58.cpp (Linux-only
# headers) are NOT vendored; libxmrmsg provides portable replacements.
#
# Run scripts/setup-dev-env.sh to populate these files from the Monero source.

set(MONERO_CRYPTO_SOURCES
    crypto-ops.c
    crypto-ops-data.c
    keccak.c
    memwipe.c
)

set(MONERO_CRYPTO_HEADERS
    crypto-ops.h
    keccak.h
    memwipe.h
)

# Verify all vendored files are present before attempting to build
foreach(f IN LISTS MONERO_CRYPTO_SOURCES MONERO_CRYPTO_HEADERS)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${f}")
        message(FATAL_ERROR
            "\nVendored file missing: third_party/monero-crypto/${f}\n"
            "Run the setup script first:\n"
            "    ./scripts/setup-dev-env.sh\n")
    endif()
endforeach()

add_library(monero-crypto STATIC ${MONERO_CRYPTO_SOURCES})

target_include_directories(monero-crypto
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)

# Suppress warnings in vendored code that don't indicate correctness issues
target_compile_options(monero-crypto PRIVATE
    -Wno-unused-variable
    -Wno-unused-parameter
    -Wno-unused-function
    $<$<COMPILE_LANGUAGE:CXX>:-Wno-old-style-cast>
)
