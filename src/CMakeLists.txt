set(XMRMSG_SOURCES
    address.cpp
    crypto.cpp
    decode.cpp
    encode.cpp
    monero_base58.cpp
    wallet.cpp
)

add_library(xmrmsg STATIC ${XMRMSG_SOURCES})

target_include_directories(xmrmsg
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}   # exposes libxmrmsg.h to consumers
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}   # internal.h, monero_base58.h
)

target_link_libraries(xmrmsg PUBLIC monero-crypto)

target_compile_options(xmrmsg PRIVATE -Wall -Wextra)
