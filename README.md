# Rummur Protocol

**Private messaging. No phone number. No servers. No accounts.**

Rummur is a decentralized messaging protocol and a family of open-source clients. Messages travel as ordinary transactions on an existing peer-to-peer network. There is no application server to shut down, no account database to breach, and no phone number to hand over.

This repository contains the protocol specification, the core C++ library (`libxmrmsg`), and a reference CLI tool.

---

## Contents

- [Building](#building)
- [Goals](#goals)
- [Assumptions](#assumptions)
- [How It Works](#how-it-works)
- [Library Internals](#library-internals)
- [Clients](#clients)
- [This Repo](#this-repo)
- [Current Status](#current-status)
- [Contributing](#contributing)

---

## Building

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| macOS | 13+ | Linux supported; iOS cross-compilation requires macOS |
| Xcode Command Line Tools | any | `xcode-select --install` |
| Homebrew | any | [brew.sh](https://brew.sh) |
| CMake | 3.20+ | `brew install cmake` |
| Ninja | any | `brew install ninja` |
| Boost | 1.74+ | `brew install boost` |
| OpenSSL | 3.x | `brew install openssl` |
| pkg-config | any | `brew install pkg-config` |
| Monero source | v0.18.x | Fetched automatically by the setup script |

The setup script checks for all of these and installs missing Homebrew packages automatically.

### Quick start

```bash
# 1. Clone
git clone https://github.com/rummur/rummur-protocol.git
cd rummur-protocol

# 2. Set up environment
#    - Installs missing Homebrew deps
#    - Clones and pins the Monero source
#    - Vendors the required crypto files into third_party/monero-crypto/
#    - Builds monerod and starts a local stagenet node on port 38081
./scripts/setup-dev-env.sh

# 3. Build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# 4. Run tests
ctest --test-dir build --output-on-failure

# 5. Generate test vectors (writes canonical hex output for PROTOCOL.md §13)
./build/tests/generate_test_vectors
```

The setup script takes 20–40 minutes the first time — mostly the Monero build. Subsequent runs are fast (skips already-done steps).

### Build options

| CMake option | Default | Description |
|---|---|---|
| `XMRMSG_BUILD_TESTS` | `ON` | Build unit tests and the test vector generator |
| `XMRMSG_BUILD_CLI` | `ON` | Build the reference CLI tool (`rummur-cli`) |
| `XMRMSG_BUILD_FUZZ` | `OFF` | Build the libFuzzer fuzz harness (requires clang) |
| `CMAKE_BUILD_TYPE` | `Release` | `Debug` enables address sanitizer and assertions |

Example — library only, no CLI or tests:

```bash
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DXMRMSG_BUILD_TESTS=OFF \
  -DXMRMSG_BUILD_CLI=OFF
cmake --build build
```

### Stagenet testing

The setup script starts a local `monerod` on stagenet (port 38081). To test message sending end-to-end:

```bash
# Check sync status
tail -f ~/.rummur-dev/stagenet/monerod.log

# Open (or create) a stagenet test wallet
~/.rummur-dev/monero-source/build/release/bin/monero-wallet-cli \
  --stagenet \
  --wallet-file ~/.rummur-dev/stagenet/test-wallet \
  --daemon-address 127.0.0.1:38081
```

Stagenet XMR is available from the community faucet at https://community.getmonero.org/faucet/stagenet/ or by running `start_mining 1` inside the wallet CLI.

### iOS cross-compilation (XCFramework)

See `PLAN.md § Phase 1` for the XCFramework build step. Requires Xcode and uses Cake Wallet's CMake toolchain scripts as the starting point.

---

## Goals

These goals are non-negotiable. Any design decision that conflicts with them is rejected.

**1. No servers.**
The delivery network is a live, decentralized peer-to-peer network. There is no relay, no registry, no infrastructure that Rummur controls, and no single point of failure. If every Rummur developer disappeared tomorrow, the protocol would continue to work.

**2. No new identity layer.**
Your cryptographic address is your identity. No registration step. No username claim. No email. No phone number. Whoever holds the keys to an address owns that identity — and only them.

**3. Messages are indistinguishable from payments on-chain.**
Every message looks identical to an ordinary financial transaction to any network observer. The protocol produces no on-chain marker, no message flag, and no new identifier. Privacy is preserved at the network layer, not just the application layer.

**4. No new cryptographic primitives.**
The encryption scheme uses key derivation and cipher operations that are already battle-tested in the underlying network. No experimental cryptography. No trust-us guarantees.

**5. Open protocol, multiple implementations.**
The spec is a public document. Anyone can implement a compatible client without permission from the Rummur project. Multiple independent implementations are a goal.

**6. Spam has a cost; legitimate messaging is affordable.**
Each message requires paying a small network fee — roughly $0.21 at slow priority. This makes unsolicited bulk messaging economically irrational while keeping one-to-one conversation cheap.

---

## Assumptions

These are the design assumptions the protocol is built on. If an assumption is wrong for your use case, Rummur may not be the right tool.

| Assumption | What it means in practice |
|---|---|
| Both parties have wallets | You need a funded wallet address to send messages. Receiving is free. |
| Addresses are shared out-of-band | There is no built-in discovery. You share your address the same way you'd share a PGP key — over a channel you already trust. Optional self-hosted handles are available (see `PROTOCOL.md`). |
| ~2 minute delivery | Block time is ~120 seconds. Rummur is not a real-time chat protocol. It is a private, asynchronous communication channel. |
| 242 bytes per message | The wire format fits ~242 ASCII characters in a single transaction. Longer content uses chained transactions (Phase 7). |
| Users hold their own keys | There is no key recovery service. If you lose your seed phrase, messages sent to that address are permanently inaccessible. |
| Monero is the transport | The underlying network is Monero. Users don't need to understand Monero to use Rummur, but the protocol inherits Monero's properties — and its constraints. |

---

## How It Works

A Rummur message is a standard network transaction carrying an encrypted payload in an optional data field (`tx_extra_nonce`). The payload is encrypted using Elliptic Curve Diffie-Hellman: the sender uses the recipient's address to derive a shared secret without any prior interaction. The recipient scans incoming transactions, attempts to decrypt each nonce payload, and surfaces any that match the Rummur protocol magic byte (`0x4D`).

The recipient's address encodes both public keys needed for this derivation. No separate key exchange step is required. Primary addresses and subaddresses are both supported — using a subaddress per contact prevents multiple senders from correlating that they are messaging the same wallet.

For full wire format, encryption scheme, flag definitions, and test vectors, see [`PROTOCOL.md`](./PROTOCOL.md).

---

## Library Internals

The library is organised in five layers. Reading them bottom-up mirrors the dependency order; reading them top-down mirrors the message flow.

### Layer 1 — Address parsing (`src/address.cpp`)

A Monero address is a 95-character base58 string that encodes 69 bytes:

```
[0]      prefix byte   (identifies network and address type)
[1..32]  spend public key
[33..64] view public key
[65..68] checksum: first 4 bytes of keccak-256 of the above
```

`xmrmsg_parse_address` decodes the string, classifies the prefix (mainnet / stagenet / testnet, primary / subaddress), and verifies the checksum. All downstream code works with the extracted raw keys — the address string is never consulted again.

### Layer 2 — Crypto primitives (`src/crypto.cpp`)

Three operations power the protocol:

**ECDH derivation** (`xmrmsg_derive`): computes `out = 8 × sec_key × pub_key` — Monero's `generate_key_derivation`. The cofactor-8 multiplication maps the point into the prime-order subgroup. Sender calls it as `derive(recipient_view_pk, tx_sk)`; recipient calls it as `derive(tx_pk, view_sk)`. Both produce the same derivation because scalar multiplication commutes.

**Keystream generation** (`xmrmsg_keystream`): counter-mode Keccak-256 over the shared derivation:
```
for i in 0..7:
    output[i*32 .. i*32+32] = keccak(derivation || 0x4D || i)
```
Produces 256 bytes. `0x4D` is the protocol magic byte, used here as a domain separator.

**Curve utilities** (`xmrmsg_scalarmult`, `xmrmsg_secret_key_to_public_key`): raw point operations used to compute subaddress transaction keys (`tx_pk = tx_sk × D`, where D is the subaddress spend key, rather than the base point G used for primary addresses).

All operations sit directly on the vendored Monero `crypto-ops.h` and `keccak.h` — there is no dependency on Monero's `crypto.cpp`.

### Layer 3 — Encoding (`src/encode.cpp`)

`xmrmsg_encode_nonce` builds the 255-byte nonce:

```
[0]       magic = 0x4D
[1]       version_flags = (version << 4) | flags
[2..9]    thread_nonce (8 bytes — conversation grouping hint)
[10..254] ciphertext   (245 bytes)
```

The 245-byte plaintext before encryption:

```
[0]       payload_type = 0x01 (text)
[1..2]    msg_len (big-endian uint16)
[3..N]    message bytes
[N..N+95] sender address (only present when SENDER_ADDR flag is set)
[rest]    random padding
```

The buffer is filled with random bytes first, then the structured fields are written on top — so the tail is never predictably zero. Encryption is XOR with the first 245 bytes of the keystream.

For subaddress recipients the transaction key is computed as `tx_pk = tx_sk × D`; for primary addresses it is `tx_pk = tx_sk × G`. The encode path handles both transparently.

### Layer 4 — Decoding (`src/decode.cpp`)

`xmrmsg_decode_nonce` is the recipient side. It accepts a list of candidate tx public keys because a transaction can have multiple outputs, each with its own key:

1. Check magic byte → `XMRMSG_ERR_WRONG_MAGIC`
2. Check version nibble → `XMRMSG_ERR_UNKNOWN_VERSION`
3. For each candidate tx public key:
   - Derive `derivation = derive(tx_pk_candidate, view_sk)`
   - Generate keystream, XOR ciphertext → plaintext
   - Check `plaintext[0] == 0x01` — a wrong key produces random garbage here, so a mismatch means try the next candidate
   - Validate `msg_len` fits within 245 bytes
   - Allocate and populate `xmrmsg_message_t`
4. If no candidate succeeded → `XMRMSG_ERR_DECRYPT_FAILED`

`XMRMSG_ERR_DECRYPT_FAILED` is the expected result for every transaction that is not addressed to the scanning wallet — not an error condition in normal operation.

### Layer 5 — Wallet (`src/wallet.cpp`)

`xmrmsg_wallet_from_keys` is the only function with real logic in Phase 1: it allocates the wallet struct, validates the address, and copies the keys. Passing `spend_sk = NULL` creates a view-only wallet; `xmrmsg_build_tx` returns `XMRMSG_ERR_VIEW_ONLY` for those. All transaction construction and broadcast functions are Phase 2 stubs pending libwallet integration.

### Test suite (`tests/test_core.cpp`)

37 tests cover every public API function. Each test is registered individually with ctest:

```bash
# Run all tests
ctest --test-dir build --output-on-failure

# Run a subset by name pattern
ctest --test-dir build -R roundtrip

# Run a single test
ctest --test-dir build -R derive_symmetry
```

The test binary also runs standalone:

```bash
./build/tests/test_core           # all 37
./build/tests/test_core --run derive_symmetry  # one by name
```

No live Monero node is required — the unit tests are purely cryptographic and use hardcoded stagenet addresses as test fixtures.

---

## Clients

All clients share the same C++ core library (`libxmrmsg`) from this repo.

| Client | Repo | Status |
|---|---|---|
| iOS (Swift + SwiftUI) | `rummur-ios` | Planned — Phase 3 |
| Android (Kotlin + Jetpack Compose) | `rummur-android` | Planned — Phase 4 |
| Browser extension + PWA (TypeScript + WASM) | `rummur-web` | Planned — Phase 5 |
| Rummur Device (Linux + open hardware) | `rummur-device` | Planned — Phase 6 |
| CLI reference tool | this repo | Planned — Phase 2 |

---

## This Repo

```
rummur-protocol/
  PROTOCOL.md                  Wire format spec, encryption scheme, test vectors
  PLAN.md                      Full product vision and implementation plan
  src/
    libxmrmsg.h                Public C API
    encode.cpp                 Nonce encoding
    decode.cpp                 Nonce decoding
    crypto.cpp                 ECDH derivation and keystream
    address.cpp                Address parsing and validation
    wallet.cpp                 Wallet context and transaction construction
    CMakeLists.txt
  cli/                         Reference CLI tool (rummur-cli)
  tests/
    test_core.cpp              Unit tests — encode, decode, crypto, address
    generate_test_vectors.cpp  Deterministic test vector output for PROTOCOL.md §13
    fuzz_decode.cpp            libFuzzer fuzz harness
    CMakeLists.txt
  third_party/
    monero-crypto/             Vendored Monero crypto primitives (see VENDOR.md)
  scripts/
    setup-dev-env.sh           One-shot development environment setup
```

The detailed product vision — phases, timelines, UX decisions, GTM strategy — is in [`PLAN.md`](./PLAN.md).

The wire format, byte layout, flag definitions, ECDH keystream derivation, and test vectors are in [`PROTOCOL.md`](./PROTOCOL.md).

---

## Current Status

**Phase 1 — Core C++ library (`libxmrmsg`).**

The nonce-level API is complete and fully tested:

- Address parsing and validation (all three networks, primary and subaddress)
- ECDH key derivation and keystream generation
- Nonce encoding and decoding (all flag combinations, subaddress recipients, max-length messages)
- Wallet context creation and view-only enforcement
- 37 unit tests, all passing — run with `ctest --test-dir build --output-on-failure`

Transaction construction and broadcast (`xmrmsg_build_tx`, `xmrmsg_broadcast_tx`) are Phase 2 stubs pending libwallet integration.

Phase 0 (protocol specification) is complete and open for community review. Open an issue against any requirement you disagree with.

---

## Contributing

### Protocol feedback

The spec lives in [`PROTOCOL.md`](./PROTOCOL.md). The best way to comment on it is to open a pull request.

Even if you're not proposing a change — if you think a section is unclear, an assumption is wrong, or a security property is missing — open a PR that edits the relevant section and explains the concern in the PR description. That gives the discussion a concrete anchor and keeps everything in one place.

1. Fork this repo
2. Edit `PROTOCOL.md` directly
3. Open a PR with a clear title: what section, what concern
4. Discussion happens in the PR thread

For broader design questions not tied to specific spec text, open a GitHub Discussion instead.

### Code

- **Bug reports**: open an issue with steps to reproduce
- **Code**: open a PR against `main` — keep changes focused, one concern per PR
- **Security issues**: do not open a public issue; email the maintainers directly

All contributions are MIT licensed. By submitting a PR you agree your contribution is released under MIT.

---

## License

MIT. See [`LICENSE`](./LICENSE).
