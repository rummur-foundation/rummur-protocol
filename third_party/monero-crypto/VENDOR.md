# Vendored Monero Cryptographic Primitives

libxmrmsg depends on two cryptographic primitives from the Monero source tree:

- `generate_key_derivation` — ECDH on Curve25519 with cofactor ×8
- `cn_fast_hash` — Keccak-256 (Monero variant, NOT identical to NIST SHA3-256)

These files are vendored here rather than taken as a build-time dependency so that
libxmrmsg can be compiled cross-platform (iOS, Android, Linux, WASM) without
requiring the full Monero build environment at each target.

---

## Source version

Target: **Monero v0.18.x "Fluorine Fermi"** — the latest stable release in that
series. Must be v0.18.0 or later (HF15 view tags required).

Check the latest tag at: https://github.com/monero-project/monero/releases

Suggested pin: whichever tag is latest at the time you run this step. Record the
exact commit hash in `VENDOR_COMMIT` (create that file alongside this one) so the
vendor step is reproducible.

---

## Files to copy

Run from the root of a checked-out Monero source tree. Copy these files into
`third_party/monero-crypto/` preserving the flat structure (no subdirectories):

```
src/crypto/crypto.h
src/crypto/crypto.cpp
src/crypto/crypto-ops.h
src/crypto/crypto-ops.c
src/crypto/crypto-ops-data.c
src/crypto/hash.h
src/crypto/hash-ops.h
src/crypto/hash.c
src/crypto/keccak.h
src/crypto/keccak.c
src/crypto/random.h
src/crypto/random.c              ← .c not .cpp
src/crypto/generic-ops.h
contrib/epee/include/memwipe.h   ← lives in epee, not src/crypto
contrib/epee/src/memwipe.c       ← lives in epee, not src/crypto
src/common/base58.h
src/common/base58.cpp
```

One-liner (run from the Monero repo root):

```sh
DEST=/path/to/rummur-protocol/third_party/monero-crypto
cp src/crypto/crypto.{h,cpp} \
   src/crypto/crypto-ops.{h,c} \
   src/crypto/crypto-ops-data.c \
   src/crypto/hash.{h,c} \
   src/crypto/hash-ops.h \
   src/crypto/keccak.{h,c} \
   src/crypto/random.{h,c} \
   src/crypto/generic-ops.h \
   contrib/epee/include/memwipe.h \
   contrib/epee/src/memwipe.c \
   src/common/base58.{h,cpp} \
   "$DEST/"
```

Record the commit hash:

```sh
git -C /path/to/monero rev-parse HEAD > "$DEST/VENDOR_COMMIT"
```

---

## Known patches

`crypto.cpp` includes `<config/version.h>` in some Monero versions for the build
version string. This header is not needed by libxmrmsg. If the build fails on that
include, remove or stub it.

`random.cpp` may include Boost headers for platform-specific RNG seeding. On
platforms where Boost is unavailable (WASM, minimal Linux), this can be replaced
with a thin wrapper around `getentropy(2)` or `arc4random(3)`.

---

## What is NOT vendored

- `wallet2.cpp` / `wallet_api.h` — full wallet transaction construction is handled
  by linking against the pre-built Monero wallet library at the platform layer.
  libxmrmsg's wallet API (`xmrmsg_wallet_*`, `xmrmsg_build_tx`) provides a thin
  wrapper; the underlying implementation calls into libwallet.

- `ringct/` — RingCT signing is done by the wallet library, not libxmrmsg.

- `cryptonote_basic/` — address type parsing is handled by libxmrmsg's own
  `address.cpp`, which needs only the base58 decoder and Keccak for the checksum.
