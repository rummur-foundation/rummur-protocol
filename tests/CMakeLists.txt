# Unit test binary — no external test framework required
add_executable(test_core test_core.cpp)
target_link_libraries(test_core PRIVATE xmrmsg)

foreach(test_name
    constants
    version_string
    validate_address_primary
    validate_address_subaddress
    validate_address_invalid
    is_subaddress_invalid
    derive_basic
    derive_symmetry
    keystream_null_args
    keystream_length_and_determinism
    keystream_different_derivations_differ
    generate_tx_keypair_null_args
    generate_tx_keypair_consistency
    generate_tx_keypair_random
    scalarmult_null_args
    scalarmult_vs_base_point
    roundtrip_anonymous
    roundtrip_with_sender
    roundtrip_reply
    roundtrip_subaddress_recipient
    roundtrip_max_message_anon
    roundtrip_max_message_with_sender
    roundtrip_empty_message
    encode_errors
    encode_invalid_sender_address
    decode_errors
    decode_multiple_candidates_right_key_last
    wrong_key_decrypt_failed
    encode_different_random_nonces
    free_message_null_safe
    wallet_from_keys_null_args
    wallet_from_keys_invalid_address
    wallet_from_keys_view_only
    wallet_from_keys_with_spend_key
    build_tx_null_args
    build_tx_bad_amount
    tx_id_and_broadcast_null_args
)
    add_test(NAME ${test_name} COMMAND test_core --run ${test_name})
endforeach()

# Deterministic test vector generator — output populates PROTOCOL.md §13
add_executable(generate_test_vectors generate_test_vectors.cpp)
target_link_libraries(generate_test_vectors PRIVATE xmrmsg)

# Address generator — computes correct STAGENET_ADDR and STAGENET_SUBADDR
# constants for test_core.cpp from the known test keys
add_executable(gen_test_addrs gen_test_addrs.cpp)
target_link_libraries(gen_test_addrs PRIVATE xmrmsg)

# Fuzz harness — only built when XMRMSG_BUILD_FUZZ=ON with clang
if(XMRMSG_BUILD_FUZZ)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(WARNING "XMRMSG_BUILD_FUZZ requires clang — skipping fuzz target")
    else()
        add_executable(fuzz_decode fuzz_decode.cpp)
        target_link_libraries(fuzz_decode PRIVATE xmrmsg)
        target_compile_options(fuzz_decode PRIVATE -fsanitize=fuzzer,address)
        target_link_options(fuzz_decode PRIVATE -fsanitize=fuzzer,address)
    endif()
endif()
