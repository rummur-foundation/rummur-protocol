/**
 * warnings.h — Portable stub replacing Monero's contrib/epee/include/warnings.h.
 *
 * The original uses Boost.Preprocessor solely to construct _Pragma strings for
 * warning suppression. That functionality is already covered by CMake's
 * target_compile_options on the monero-crypto target.
 *
 * All macros are defined as no-ops here. This is safe: the vendored C files
 * compile correctly without the pragmas; warnings are suppressed at the CMake
 * level instead.
 */

#pragma once

#define PUSH_WARNINGS
#define POP_WARNINGS
#define DISABLE_VS_WARNINGS(w)
#define DISABLE_GCC_WARNING(w)
#define DISABLE_CLANG_WARNING(w)
#define DISABLE_GCC_AND_CLANG_WARNING(w)
