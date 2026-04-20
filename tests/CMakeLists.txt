# Unit test binary — no external test framework required
add_executable(test_core test_core.cpp)
target_link_libraries(test_core PRIVATE xmrmsg)
add_test(NAME core COMMAND test_core)

# Deterministic test vector generator — output populates PROTOCOL.md §13
add_executable(generate_test_vectors generate_test_vectors.cpp)
target_link_libraries(generate_test_vectors PRIVATE xmrmsg)

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
