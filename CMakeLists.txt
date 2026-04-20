cmake_minimum_required(VERSION 3.20)
project(rummur-protocol VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD   11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(XMRMSG_BUILD_TESTS "Build unit tests and test vector generator" ON)
option(XMRMSG_BUILD_CLI   "Build the reference CLI tool (rummur-cli)"  ON)
option(XMRMSG_BUILD_FUZZ  "Build the libFuzzer fuzz harness (requires clang)" OFF)

add_subdirectory(third_party/monero-crypto)
add_subdirectory(src)

if(XMRMSG_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(XMRMSG_BUILD_CLI)
    add_subdirectory(cli)
endif()
