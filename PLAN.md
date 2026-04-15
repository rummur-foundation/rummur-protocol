# Rummur: Vision & Product Plan

**Version 1.1 — April 2026**

---

## Vision

A fully decentralized, censorship-resistant private messenger. No servers. No accounts. No phone numbers. Your identity is a cryptographic address. Every message is an irreversible, private transaction on a decentralised network.

Monero is the engine. Rummur is the product. Users never need to know how it works — only that it does.

The name is a palindrome: R·U·M·M·U·R. The same forwards and backwards — like the symmetric encryption that protects every message.

---

## Principles (Non-Negotiable)

1. **Monero-first**: No design decision may weaken Monero's privacy model. Every transaction must look identical to a payment transaction on-chain. No new identifiers on-chain.
2. **Zero servers**: No central relay, no registry, no infrastructure that can be seized, shut down, or surveilled. The Monero peer-to-peer network IS the infrastructure.
3. **No new key material**: The same keys already in a Monero wallet are sufficient for encryption, decryption, and identity. No key registration step.
4. **Privacy by default, discoverability by choice**: The system works with zero metadata beyond what a payment already leaks.
5. **Open protocol, open source**: The spec is a public document. Multiple independent implementations are a goal, not a risk.

---

## Core Technical Foundation

Everything required already exists in the Monero source:

| What | Source Location | Detail |
|---|---|---|
| ECDH shared secret | `device_default.cpp:354` | `derivation = 8 × tx_sk × recipient_view_pk` |
| tx_extra nonce | `tx_extra.h:44` | 255 bytes max, arbitrary payload |
| Max tx_extra | `cryptonote_config.h:221` | 1060 bytes hard limit enforced by pool |
| tx_pub_key | Every transaction | Enables recipient to reconstruct derivation |
| View tag scan | HF15 (`wallet2.h:1501`) | ~40% speedup for recipient scanning |
| Min 2 outputs | HF12 (`cryptonote_config.h:187`) | Every tx already has change — no fingerprinting |
| Block time | `cryptonote_config.h:80` | 120 seconds |
| Fee per byte | `cryptonote_config.h:71` | 300,000 piconero/byte |
| OpenAlias | `dns_utils.cpp:398` | Built-in, optional, self-hosted handles |

**Key insight**: A Monero address encodes both `pub_spend_key` and `pub_view_key`. You already have everything needed to encrypt a message to anyone whose address you know. No extra key exchange step required.

---

## The Discovery Problem

This is the hardest design question. The resolution is a layered approach with address sharing as the base and discoverability strictly opt-in.

### The sender identity problem

Standard Monero hides the sender. If Alice sends Bob a message, Bob sees "someone sent me a transaction with a message" but not who. The solution: the first bytes of the encrypted plaintext payload optionally include Alice's return address — by her explicit choice. If omitted, the message is anonymous. This preserves Monero's sender-privacy model.

### Layer 0 — Address as identity (always available)

Your 95-character Monero address IS your handle. Sharing it is like sharing a PGP public key. For privacy-conscious users this is the only layer needed.

```
Message me: 48daf1roBHMrjTJjSriKwQ7biEHMTKzGJLY2jNWZVUHRu3FWHHmXGi9Xzoo...
```

### Layer 1 — Self-hosted OpenAlias (opt-in, no third party)

Already implemented in the wallet source. Add one DNS TXT record to a domain you control:

```
oa1:xmr recipient_address=48daf1roBHMrjTJjSri...;
```

Handle becomes `you@yourdomain.com`. No third party involved. DNSSEC validated. The wallet resolves this natively via `dns_utils.cpp:401`.

### Layer 2 — Nostr contact card (deferred to Phase 8)

Publish a Nostr event (kind `10200`) that maps your Nostr identity to your Monero address. Nostr is a federated gossip network with no single point of failure. You choose which relays to publish to. Monero wallet activity is never exposed — only the address.

**Deferred**: Privacy tradeoffs of publishing a Monero address to a public gossip network need community evaluation before shipping. Not in v1.

```json
{
  "kind": 10200,
  "content": "48daf1roBHMrjTJjSri...",
  "tags": [["monero", "mainnet"]]
}
```

Users find you by your Nostr pubkey (`npub...`) or NIP-05 identifier (`you@domain.com`). The lookup tells an adversary your Monero address — only opt in if you want to be findable.

**No on-chain registry**: Publishing handles on-chain permanently links them to addresses in an immutable, public ledger. This violates Monero principles. We do not do this.

---

## Message Format

### tx_extra_nonce payload (255 bytes total)

```
Byte 0:     0x4D ('M') — protocol magic, avoids collision with 0x00/0x01 payment IDs
Byte 1:     version (bits 7-4) | flags (bits 3-0)
              flag bit 0 = sender_address_included
              flag bit 1 = is_reply (future use)
              flag bit 2 = reserved (future long message innovation)
Bytes 2-9:  thread_nonce — 8 random bytes chosen by sender, echoed in replies
             (links conversations locally, meaningless on-chain)
Bytes 6-254: ECDH-encrypted payload (up to 249 bytes)
```

### Encrypted payload — plaintext structure

```
[1 byte]   payload_type: 0x01 = text, 0x02 = reserved
[2 bytes]  msg_len (uint16, big-endian)
[N bytes]  UTF-8 message text
[optional] [95 bytes] sender's Monero address (if flag bit 0 set)
[remaining] random padding for length obfuscation
```

**Usable message space:**

| Mode | Text capacity |
|---|---|
| Anonymous (no sender address) | ~242 bytes (~242 ASCII chars) |
| With sender address | ~147 bytes |

### ECDH keystream derivation

Extends the existing `encrypt_payment_id` mechanism from `device_default.cpp:354` using counter mode to cover the full 249-byte payload:

```
// Sender — tx_secret_key already exists in every Monero transaction
generate_key_derivation(recipient_view_pub, tx_secret_key, derivation)

// Counter-mode keystream (32 bytes per block, 8 blocks = 256 bytes)
for block_idx in 0..7:
    input = derivation || block_idx || 0x4D   // domain-separated with 'M'
    cn_fast_hash(input, sizeof(input), keystream_block[block_idx])

keystream = keystream_block[0] || ... || keystream_block[7]
ciphertext = plaintext XOR keystream[0..len]
```

The recipient uses `(tx_pub_key from tx_extra, view_secret_key)` to reproduce the identical derivation. No new cryptographic primitives required.

---

## Long Messages

The protocol is intentionally capped at **242 bytes per transaction**. This is a constraint, not a bug — it keeps the system simple, self-contained, and free of external dependencies.

Future approaches for longer content, in order of preference:

1. **Chained transactions** — split a long message across multiple transactions, each carrying 242 bytes. A 1,000-byte message costs ~$1.05 in fees. Everything stays inside the Monero network. No external dependency.

2. **Links** — include a URL or identifier pointing to off-chain content the recipient already has access to. The message is the pointer; the content lives elsewhere by the sender's choice.

3. **Future protocol innovation** — flag bit 2 is reserved. A future version may define a new long-message format that preserves Monero-only transport without introducing centralised dependencies.

IPFS was evaluated and rejected: persistence is not guaranteed without centralised pinning services, IPFS fetch behaviour leaks metadata, and it introduces a second network dependency that cuts against Rummur's zero-servers principle.

---

## What a Message Looks Like On-Chain

To a blockchain observer, a message transaction is:

- A standard RingCT transaction with 16-ring inputs
- 2 outputs (recipient + change — required by HF12)
- `tx_extra` contains: pubkey (33 bytes) + nonce (257 bytes of opaque ciphertext)
- Amount: ~0.000001 XMR (minimum) + fee (~0.0006 XMR at base rate)

**It is identical to any other Monero transaction.** There is no "message" flag visible on-chain. The `0x4D` magic byte is inside the ECDH-encrypted nonce — invisible without the recipient's view key.

---

## Cost Per Message

At the base fee rate of 300,000 piconero/byte and a typical message transaction size of ~2,000 bytes:

| Priority | Multiplier | Fee | At ~$350/XMR |
|---|---|---|---|
| Slow | 1x | ~0.0006 XMR | ~$0.21 |
| Normal | 4x | ~0.0024 XMR | ~$0.84 |
| Fast | 20x | ~0.012 XMR | ~$4.20 |

The cost is a feature: spam is economically irrational. Unsolicited bulk messaging becomes prohibitively expensive while legitimate communication remains affordable.

---

## Architecture

### What the app is NOT

- Not a modified Monero daemon or wallet protocol
- Not a relay — there are no application servers
- Not an account system — no registration, no email, no phone number

### What the app IS

A protocol and a family of clients. Every client shares the same C++ core
library (`libxmrmsg`). The UI layer is native to each platform.

1. Manages wallet keys securely in hardware (Secure Enclave / Keystore / secure element)
2. Scans the blockchain for transactions carrying the `0x4D` message magic
3. Decrypts messages using ECDH with the local view key
4. Constructs and broadcasts outbound message transactions via Tor
5. Presents a native messaging UI — iPhone, Android, browser, or physical device

### Client family

| Client | Primary user | Keys stored | Send | Receive |
|---|---|---|---|---|
| iOS app | iPhone users | Secure Enclave | Yes | Yes |
| Android app | Android / GrapheneOS users | Hardware Keystore | Yes | Yes |
| Browser extension | Desktop users (paired to phone) | None — phone holds keys | Yes | Yes |
| Web app (PWA) | Any browser, read-only | View key only | No | Yes |
| Rummur Device | Privacy-maximum users | Hardware secure element | Yes | Yes |

---

## iOS Technical Stack

### Layer overview

```
+--------------------------------------+
|    SwiftUI (views, animations, UX)   |
+--------------------------------------+
|  Swift actors (WalletActor,          |
|  MessageActor, SyncActor)            |
+--------------------------------------+
|  libxmrmsg  (C++ via XCFramework)    |
|  encrypt / decrypt / build_tx        |
+--------------------------------------+
|  libwallet  (Monero C++ wallet lib)  |
|  key derivation / tx construction    |
+--------------------------------------+
|  Tor.framework  +  remote node RPC   |
+--------------------------------------+
```

### UI: SwiftUI + UIKit where needed

SwiftUI handles the full UI. UIKit escape hatches via `UIViewRepresentable`
for anything SwiftUI cannot express — custom message bubble physics,
camera/QR scanning, blur-on-background. No framework in between Apple
and the pixels.

Key SwiftUI patterns used:
- `@Observable` (Swift 5.9 Observation framework) for reactive state
- `NavigationStack` for conversation flow
- `scrollPosition` + `safeAreaInset` for iMessage-style composer pinning
- `matchedGeometryEffect` for send animations
- `sensoryFeedback` for haptics on send/receive

### Concurrency: Swift actors

All wallet operations run in dedicated Swift actors — no data races,
no manual locking:

```swift
actor WalletActor {
    func importSeed(_ phrase: String) async throws -> WalletKeys
    func buildMessageTx(to: MoneroAddress, text: String) async throws -> PendingTx
    func broadcast(_ tx: PendingTx) async throws -> TxID
}

actor SyncActor {
    func sync(from height: UInt64) async throws
    func scanBlock(_ block: Block) async throws -> [InboundMessage]
}

actor MessageActor {
    func decrypt(tx: Transaction, viewKey: SecretKey) async throws -> Message?
    func conversations() async -> [Conversation]
}
```

Swift Concurrency eliminates callback hell and makes the crypto operations
feel instant to the UI via `async/await` with `Task { }` bridging.

### Key storage: Secure Enclave + Keychain

This is the most important security decision in the entire stack.

| Key | Storage | Access |
|---|---|---|
| Spend private key | Secure Enclave (hardware) | Face ID / Touch ID required |
| View private key | Keychain (encrypted, always-available) | Background sync can access |
| Seed phrase | Never stored — shown once, then user's responsibility | — |
| Contact addresses | Keychain-backed local DB | App unlock |

The Secure Enclave means the spend key **never exists in RAM** in plaintext
on the main processor. Signing operations happen inside the enclave.
Even a compromised app cannot extract the spend key.

The view key lives in the Keychain (accessible without biometrics) so
background sync can scan for incoming messages without waking the user.

### C++ library: XCFramework via Swift Package Manager

The `libxmrmsg` C++ library is compiled for:
- `arm64-apple-ios` (physical devices)
- `arm64-apple-ios-simulator` (Apple Silicon simulators)
- `x86_64-apple-ios-simulator` (Intel simulators, if needed)

Bundled as an `XCFramework` and distributed as a Swift Package local
dependency. Swift calls into C++ via the Swift/C++ interoperability
layer (Swift 5.9+) with a thin bridging header — no Objective-C in the
middle.

Cake Wallet (open source) has already compiled Monero's wallet library
for iOS. Their CMake toolchain scripts are the starting point.

### Tor: Tor.framework

`Tor.framework` (used by Onion Browser and Tor Browser for iOS) provides
an embedded Tor client as a Swift Package. All node RPC traffic routes
through it. No clearnet fallback by default — users explicitly opt out
if they choose to use a clearnet node.

Onion-routed node connectivity means:
- The node operator does not learn the user's IP
- The ISP does not learn the user is connecting to a Monero node
- Message sending and receiving are unlinkable at the network layer

### Background sync: BGTaskScheduler

iOS severely limits background execution. The strategy:

| Mechanism | Time budget | Trigger |
|---|---|---|
| `BGAppRefreshTask` | ~30 seconds | iOS-scheduled, ~every 15 min |
| `BGProcessingTask` | Minutes | Charging + WiFi only |
| Foreground sync | Unlimited | App is open |

The view key (in Keychain) is accessible during background tasks without
user interaction. The sync actor runs a lightweight block scan in the
`BGAppRefreshTask` window. Full sync runs during `BGProcessingTask`.

Optional: self-hosted push proxy. The user runs a tiny server with their
view key. The server monitors the chain and sends a silent APNs push
when a message arrives, waking the app for a background fetch. Zero
trust required — the proxy only has the view key (read-only), never the
spend key. The proxy code is open source.

### Node connectivity — privacy tiers

| Mode | Privacy | Notes |
|---|---|---|
| Own full node via Tor .onion | Maximum | Best — ~150 GB |
| Own pruned node via Tor | High | ~50 GB |
| Community node via Tor | Good | Default |
| Community node clearnet | Weak | Opt-in only |

Default is a curated list of community Tor-accessible nodes, rotated
randomly per session. User can pin their own at any time.

---

## UX Design

### Design language

Native iOS. Follows Apple Human Interface Guidelines. Feels like it came
from Apple — not from a cross-platform toolkit.

- **Typography**: SF Pro throughout. No custom fonts.
- **Color**: System colors + a single Monero-orange accent. Adapts to
  Dark Mode automatically.
- **Motion**: Spring animations matching iOS physics. `matchedGeometryEffect`
  for message send. Subtle haptic confirmation on every send.
- **Icons**: SF Symbols. No icon font, no PNGs.

### Onboarding — three screens maximum

```
Screen 1: "Your wallet is your identity"
  [ Import seed phrase ]   [ Create new wallet ]

Screen 2 (import): Paste or camera-scan 25-word seed
  Restore height field (optional, speeds up sync)

Screen 2 (create): Show seed phrase — large, readable, copy button
  "Write this down. It cannot be recovered."

Screen 3: Face ID prompt → done
```

No email. No username. No password. Three taps to a working messenger.

### Conversation UI

iMessage-style bubble layout. Familiar and immediately understood.

- Outbound messages: right-aligned, orange bubble
- Inbound messages: left-aligned, system grey bubble
- Timestamps: block time shown on long-press (like iMessage)
- "Delivered" indicator: shown once tx is seen in mempool
- "Confirmed" indicator: shown after 1 block (~2 minutes)
- Anonymous sender: avatar shows a Monero logo, label shows truncated address
- Named contact: avatar shows initials or QR-derived identicon

Composer bar pinned to keyboard, expands for long messages, shows live
character counter (246 max for v1). Fee shown in fiat below the counter:
`~$0.21 to send`.

### Sending a message

```
1. Tap contact or paste/scan new address
2. Type message  [246 chars — fee: ~$0.21]
3. Tap send  →  Face ID confirmation for spend key access
4. Message bubble appears immediately (optimistic UI, pending state)
5. "In mempool" indicator (~5 seconds via Tor)
6. "Confirmed" after next block (~2 minutes)
```

### Receiving a message

```
Background task fires  →  sync actor scans recent blocks
  →  message found  →  silent push (if proxy configured)
  →  app opens  →  message decrypted  →  appears in thread
  →  haptic notification
```

No push notification content ever leaves the device unencrypted.
If no proxy: message appears next time app is opened.

### Add a contact

```
Option A: Scan QR code of their address (camera)
Option B: Tap-to-share via AirDrop (sends a contact card)
Option C: Type / paste their address manually
Option D: Type their OpenAlias handle (bob@bobsdomain.com)
```

Contact names are local only — stored in Keychain-backed SQLite.
Never uploaded anywhere.

### Settings

- Node configuration (Tor .onion address or clearnet)
- Background sync toggle + push proxy URL (optional)
- Discoverability: OpenAlias handle (off by default)
- Wallet: view seed phrase, copy view key (read-only sharing)
- Security: change Face ID / fallback PIN
- About: protocol version, open source links

---

## Implementation Phases

Two types of work appear throughout every phase:

- **AI** — code generation, spec writing, debugging from error output, test
  writing, config files. Done in sessions, fast.
- **Human** — running builds, testing on real devices, reviewing AI output,
  making decisions, App Store / Play Store submissions, hardware.

---

### Phase 0 — Protocol Specification (Weeks 1-2)

| Task | Who | Time |
|---|---|---|
| Write `PROTOCOL.md` — nonce format, keystream, flags, test vectors | AI | 1 session |
| Review for cryptographic correctness | Human | 1-2 days |
| Publish, community feedback period | Human | 1 week |

**Bottleneck: community review period.**

---

### Phase 1 — Core C++ Library: `libxmrmsg` (Weeks 3-5)

| Task | Who | Time |
|---|---|---|
| Define C API header (`libxmrmsg.h`) | AI | 1 session (review before proceeding) |
| Write all source files, CMakeLists | AI | 2-3 sessions |
| Write unit tests + fuzz test harness | AI | 1 session |
| Write deterministic test vector generator (fixed inputs → derivation, keystream, plaintext, ciphertext) | AI | part of test session |
| Commit test vector outputs into `PROTOCOL.md §13` | Human + AI | 1 day |
| Set up iOS cross-compilation toolchain | Human | 2-3 days |
| Build, fix compiler errors | Human + AI | 2-3 days |
| Run tests, review results, iterate | Human + AI | 2-3 days |
| Test against Monero stagenet | Human | 2-3 days |
| Build XCFramework for iOS | Human + AI | 1 day |

**Bottleneck: build environment setup and stagenet testing.**

---

### Phase 2 — CLI Tool (Week 6)

| Task | Who | Time |
|---|---|---|
| Write CLI source | AI | 1 session |
| Build + test locally | Human | 1 day |
| End-to-end test on stagenet | Human | 2-3 days |
| Debug real network issues | Human + AI | 1-2 days |

**Bottleneck: real network testing.**
Protocol is proven end-to-end when this phase is done.

---

### Phase 3 — iOS App (Weeks 7-13)

| Task | Who | Time |
|---|---|---|
| Write Swift actors (WalletActor, SyncActor, MessageActor) | AI | 3-4 sessions |
| Write SwiftUI views — all screens | AI | 3-4 sessions |
| Xcode project setup, Swift Package config | Human | 1 day |
| Build + fix issues per feature | Human + AI | 1-2 days per feature |
| Run on real device, review each screen | Human | 2-3 days per feature |
| Tor.framework integration + node testing | Human + AI | 3-4 days |
| Face ID + Secure Enclave integration | Human + AI | 2-3 days |
| Background sync testing | Human | 2-3 days |
| TestFlight setup + beta | Human | 1 week |
| App Store submission | Human | 1 day |
| Apple review wait | Human (waiting) | 1-2 weeks |
| AltStore source file | AI + Human | 1 day |

**Bottleneck: Apple review wait. Nothing compresses that.**

---

### Phase 4 — Android App (Weeks 10-14, parallel with Phase 3)

Starts parallel to Phase 3b — same C++ library, different UI.

| Task | Who | Time |
|---|---|---|
| Write Kotlin + Jetpack Compose source | AI | 3-4 sessions |
| Write JNI bindings for `libxmrmsg` | AI | 1-2 sessions |
| Android Studio setup, Gradle config | Human | 1 day |
| Cross-compile C++ for Android ABI targets | Human + AI | 1-2 days |
| Build + fix issues | Human + AI | 2-3 days |
| Test on device + GrapheneOS | Human | 3-4 days |
| Verify zero GMS dependency | Human | 1 day |
| APK signing + direct download setup | Human | 1 day |
| Google Play submission + review | Human | 1 week |

**Bottleneck: GrapheneOS testing + Play Store review.**
APK direct download ships before Play Store approval.

---

### Phase 5 — Browser Extension + PWA (Weeks 15-18)

| Task | Who | Time |
|---|---|---|
| Compile `libxmrmsg` to WASM via Emscripten | Human + AI | 2-3 days |
| Write TypeScript extension + pairing protocol | AI | 2-3 sessions |
| Write PWA (view-key read-only inbox) | AI | 1-2 sessions |
| Test pairing flow with iOS app | Human | 2-3 days |
| Test in Chrome + Firefox | Human | 2-3 days |
| Chrome Web Store submission + review | Human | 1 week |
| Firefox Add-ons submission + review | Human | 3-5 days |

**Bottleneck: store reviews + pairing protocol real-world testing.**

---

### Phase 6 — Rummur Device (Months 4-10, parallel track)

Hardware does not compress. Runs as a separate track alongside software phases.

**Hardware specification:**

| Component | Spec | Reason |
|---|---|---|
| SoC | Raspberry Pi CM4 or equivalent | Open, available, community support |
| OS | Hardened Debian ARM (`rummur-linux`) | Minimal, auditable, no Google |
| Security chip | ATECC608B secure element | Spend key never leaves chip |
| Display | 4-6 inch E-ink | Weeks of battery, pager aesthetic |
| Keyboard | Full QWERTY (physical, BlackBerry-style) | Fast, tactile, no autocorrect |
| Microphone | MEMS microphone array | Voice input — message by speaking |
| Voice recognition | On-device STT (Whisper.cpp) | Transcribed locally, never sent to cloud |
| Connectivity | WiFi 6 + LTE modem (standard) | Cellular included — WiFi-only mode available for maximum-privacy use |
| Battery | 6000-8000 mAh | Weeks on e-ink + idle radio |
| Storage | 64 GB eMMC | Full Monero node on-device |

**Voice recognition:**
Voice input runs entirely on-device using Whisper.cpp (open source, MIT).
Speech is transcribed locally to text, then encrypted and sent as a normal
text message. No audio ever leaves the device. No cloud speech API.
The recipient receives text — voice is an input method, not a format.
This keeps messages indistinguishable on-chain regardless of how they
were composed.

| Task | Who | Time |
|---|---|---|
| Write `rummur-linux` OS image (Debian config, systemd services) | AI | 2-3 sessions |
| Write e-ink UI layer | AI | 3-4 sessions |
| Integrate Whisper.cpp for on-device STT | AI | 2-3 sessions |
| Voice input UX (hold-to-speak, transcribe, confirm) | AI | 1-2 sessions |
| Hardware design + component sourcing | Human | 4-6 weeks |
| PCB design with microphone array | Human | 4-6 weeks |
| First prototype assembly | Human | 1-2 weeks |
| Flash OS, boot test | Human | 1-2 days |
| Voice recognition tuning + accuracy testing | Human + AI | 1-2 weeks |
| Debug hardware issues | Human + AI | 2-4 weeks |
| Second prototype iteration | Human | 3-4 weeks |
| Small production run | Human | 8-12 weeks (manufacturing) |

**Bottleneck: hardware — physics does not respond to AI assistance.**

---

### Phase 7 — Chained Messages + Double Ratchet (Weeks 50+)

| Task | Who | Time |
|---|---|---|
| Chained transaction support in `libxmrmsg` | AI | 2-3 sessions |
| Double Ratchet implementation | AI | 4-5 sessions |
| Integration testing across all clients | Human + AI | 2-3 weeks |
| Update all client apps | AI + Human | 2-3 weeks |

**Bottleneck: integration testing across five clients simultaneously.**

---

### Phase 8 — Nostr Discovery (Deferred)

Nostr contact discovery deferred until the core product is stable and
the community has had time to evaluate the privacy tradeoffs of
publishing a Monero address to a public gossip network.

| Task | Who | Time |
|---|---|---|
| Nostr relay integration (Tor) | AI | 2-3 sessions |
| `kind:10200` spec + publication | AI | 1 session |
| Integration testing | Human + AI | 1-2 weeks |
| Update all clients | AI + Human | 1-2 weeks |

---

### Realistic Calendar

```
Week 1-2    Protocol spec written + in community review
Week 3-5    libxmrmsg built, tested on stagenet
Week 6      CLI working end-to-end on stagenet
Week 7-9    iOS core (actors, wallet, sync)
Week 10-11  iOS UI first pass
Week 10-12  Android (parallel) — APK shipping by week 12
Week 12-13  iOS polish, TestFlight beta
Week 14+    Apple review (out of your hands — ~2 weeks)
Week 15-18  Browser extension + PWA
Month 4+    Device hardware track running in parallel
Month 6+    Rummur Device first prototype
Month 8-10  Device small production run
```

**Software MVP (iOS + Android + CLI): ~14-16 weeks.**
**Browser clients: ~18 weeks.**
**Rummur Device: ~10 months from start.**


## Repos

| Repo | Contents | Licence |
|---|---|---|
| `rummur-protocol` | Protocol spec, `libxmrmsg` C++ library, CLI tool | MIT |
| `rummur-ios` | Swift + SwiftUI iOS app | MIT |
| `rummur-android` | Kotlin + Jetpack Compose Android app | MIT |
| `rummur-web` | Browser extension + PWA (TypeScript + WASM) | MIT |
| `rummur-device` | Linux OS image + hardware design files | MIT + CERN OHL |

---

## Distribution Strategy

| Channel | Platform | Priority |
|---|---|---|
| App Store | iOS | Primary — mainstream reach |
| AltStore source | iOS | Ships with every release — sideload fallback |
| EU alternative marketplace | iOS | Growing — DMA mandated |
| Direct APK | Android | Primary for privacy community |
| Google Play | Android | Secondary |
| Direct download | macOS | Notarized |
| Homebrew / apt | Linux / macOS | CLI tool |
| Chrome Web Store | Browser | Extension |
| Firefox Add-ons | Browser | Extension |
| Direct URL | Web | PWA — no install required |
| Direct sale | Device | rummur.im or equivalent |

---

## Monetisation (Open Source Compatible)

All code is MIT. Revenue comes from services and hardware, not
licence restrictions.

| Mechanism | Detail |
|---|---|
| **Rummur Device** | Hardware sale at $299-$499. The natural premium tier. Privacy-conscious buyers pay for good hardware. |
| **Protocol dev fee** | Default client includes optional 0.00001 XMR (~$0.0035) per message to a dev fund address. Transparent, forkable. |
| **Hosted infrastructure** | Tor node pool, self-hosted push proxy. Code is open; reliable ops is the product. |
| **Device node edition** | Premium device SKU with more storage and always-on Monero node. |

No mechanism requires users to trust a central party or compromise privacy.

---

## Go-to-Market Strategy

### Monero is an implementation detail — not the brand

Rummur is a private messenger. Monero is how it achieves that. Most users
will never need to know. This separation is intentional and critical to
mainstream adoption.

### Phase 1 — Community launch (Monero-first)

Target: Monero community, privacy advocates, cypherpunks, journalists,
activists, GrapheneOS users.

Message: **"Rummur — private messaging built on Monero."**

- Announce on r/Monero, MoneroTalk, Monero community channels
- Submit to Monero Community Crowdfunding System (CCS)
- GrapheneOS and de-Googled Android users are a natural early audience
- Early adopters stress-test the protocol, file issues, run nodes,
  and evangelise

### Phase 2 — Mainstream expansion

Target: Privacy-conscious Signal/iMessage users, journalists, activists,
anyone who has been burned by phone-number-based identity.

Message: **"Rummur. Private messaging. No phone number. No servers."**

- Lead with outcomes, not technology
- Monero becomes a footnote in the FAQ
- The Rummur Device creates press coverage beyond the crypto world

### Framing in the product

| Avoid | Use instead |
|---|---|
| "Import your Monero wallet" | "Create your identity" |
| "Send 0.0006 XMR" | "Delivery cost: ~$0.21" |
| "Monero blockchain" | "Decentralised delivery network" |
| "Connect wallet" | "Get started" |

XMR balance is managed in the background like a prepaid card.
Users think in dollars. The app handles the rest.

---

## Decisions Log

All major design questions resolved. Recorded here for reference.

| # | Question | Decision | Reason |
|---|---|---|---|
| 1 | Sender identity default | Omit by default. Auto-include after contact replies. | Max privacy on cold messages; natural feel in established conversations. |
| 2 | Thread nonce size | **8 bytes** | Collision-proof in practice. |
| 3 | Minimum send amount | **Output to recipient**, default 0.000001 XMR, configurable | Enables view tag filtering (HF15). Default is safe above economic dust threshold. Configurable so implementations can adjust as fee markets evolve without a protocol version bump. Floor is 1 piconero (protocol absolute minimum). Self-send deferred to a future version. |
| 10 | Subaddress support | **Full support from v0.1** — recipients and senders may use primary or subaddress | Correct Monero privacy model: subaddresses prevent senders from correlating multiple contacts to one wallet. Requires trying all candidate tx public keys during scanning (tag 0x01 + tag 0x04). |
| 4 | Long messages | **242-byte hard limit per tx. IPFS removed.** Chained transactions or links for longer content in Phase 7. | IPFS rejected: no persistence guarantee without centralised pinning, metadata leakage on fetch, external network dependency. |
| 5 | Nostr | **Deferred to Phase 8** | Privacy tradeoffs need community evaluation first. |
| 6 | Read receipts | **Optional, sender-pays** — off by default per conversation | Costs XMR; meaningful when enabled. Sender opts in. |
| 7 | macOS | **Mac Catalyst** (free, shared iOS codebase) | Zero extra code. Pragmatic for v1. Native macOS in Phase 7 if needed. |
| 8 | Device keyboard | **Full QWERTY** | Decided. Fast, tactile, familiar. |
| 9 | Device connectivity | **Cellular standard** | Encryption protects content regardless of transport. WiFi-only available as a mode for maximum-privacy threat models. |

---

## Summary

| Layer | Technology | Repo | Status |
|---|---|---|---|
| Protocol spec | Markdown | `rummur-protocol` | Needs writing |
| Crypto primitives | Monero source | — | Exists today |
| Message transport | `tx_extra_nonce` | — | Exists today |
| Core C++ library | `libxmrmsg` | `rummur-protocol` | Needs building |
| CLI tool | C++ | `rummur-protocol` | Needs building |
| iOS app | Swift + SwiftUI | `rummur-ios` | Needs building |
| Android app | Kotlin + Compose | `rummur-android` | Needs building |
| Browser extension | TypeScript + WASM | `rummur-web` | Needs building |
| Web app (PWA) | TypeScript + WASM | `rummur-web` | Needs building |
| Rummur Device | Linux + open hardware | `rummur-device` | Needs building |
| OpenAlias discovery | Monero wallet source | — | Needs UX wiring |
| Nostr discovery | External integration | — | Phase 8 (deferred) |
| Tor networking | Tor.framework / Tor daemon | all clients | Needs integration |
| Double Ratchet | C++ | `rummur-protocol` | Phase 7 |

The foundation is solid. No changes to Monero consensus rules.
No forks. No permission required. A protocol layer on top of a live,
battle-tested network — with clients for every surface and a physical
device that takes the concept to its logical conclusion.
