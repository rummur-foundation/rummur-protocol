# Vendored Monero Cryptographic Primitives

libxmrmsg depends on two cryptographic primitives from the Monero source tree:

- **curve25519 group operations** — ECDH key derivation (`8 × sec × pub`) and
  scalar/point arithmetic used by `xmrmsg_derive` and `xmrmsg_scalarmult`
- **Keccak-256** (`cn_fast_hash`) — the keystream KDF and address checksum.
  This is Monero's Keccak variant, which is **not** identical to NIST SHA3-256.

These files are vendored so that libxmrmsg compiles on macOS and Linux without
requiring the full Monero build environment (Boost, CMake superbuild, etc.).

---

## Source version

Target: **Monero v0.18.x "Fluorine Fermi"**.  
The exact commit is recorded in `VENDOR_COMMIT` (written by `setup-dev-env.sh`).

---

## Vendored files (from Monero source)

| File | Monero source path |
|------|--------------------|
| `crypto-ops.h`      | `src/crypto/crypto-ops.h` |
| `crypto-ops.c`      | `src/crypto/crypto-ops.c` |
| `crypto-ops-data.c` | `src/crypto/crypto-ops-data.c` |
| `hash-ops.h`        | `src/crypto/hash-ops.h` |
| `keccak.h`          | `src/crypto/keccak.h` |
| `keccak.c`          | `src/crypto/keccak.c` |
| `memwipe.h`         | `contrib/epee/include/memwipe.h` |
| `memwipe.c`         | `contrib/epee/src/memwipe.c` |

Run `scripts/setup-dev-env.sh` to re-populate these from a Monero checkout and
update `VENDOR_COMMIT`. The files are committed to the repo so a fresh clone
builds without needing the setup script.

---

## Stub files (written by this project, not from Monero)

| File | Purpose |
|------|---------|
| `int-util.h`  | Portable byte-swap macros. Replaces epee's `int-util.h` which requires `<byteswap.h>` and `<endian.h>` (Linux-only). Uses `__builtin_bswap{32,64}` (GCC/Clang, macOS + Linux). |
| `warnings.h`  | No-op warning-suppression macros. Replaces epee's `warnings.h` which uses Boost.Preprocessor. Warnings are suppressed at the CMake level instead. |

---

## What is NOT vendored

- **`crypto.cpp` / `crypto.h`** — Monero's C++ crypto wrappers depend on Boost
  and `common/varint.h`. `libxmrmsg/src/crypto.cpp` calls `crypto-ops.h` directly.

- **`base58.cpp`** — uses `<byteswap.h>` and `<endian.h>` (Linux-only).
  `libxmrmsg/src/monero_base58.cpp` is a portable reimplementation using only
  `__uint128_t`.

- **`wallet2`, `ringct/`, `cryptonote_basic/`** — not needed. Address parsing
  is handled by `src/address.cpp` using only base58 + Keccak.
