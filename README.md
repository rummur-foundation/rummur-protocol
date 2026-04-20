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

The protocol spec is final. The C API header (`src/libxmrmsg.h`) is written. Implementation is in progress.

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
