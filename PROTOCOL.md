# Rummur Protocol Specification

**Version 0.1 — Draft for community review**
**April 2026**

> This document is the normative specification for the Rummur messaging protocol.
> It is a living draft. Sections marked **[TBD]** are placeholders to be filled
> before the spec is finalised. Community review is open — open an issue against
> any requirement you disagree with.

---

## Contents

1. [Overview](#1-overview)
2. [Terminology](#2-terminology)
3. [Monero Transaction Background](#3-monero-transaction-background)
4. [Wire Format](#4-wire-format)
5. [Encryption](#5-encryption)
6. [Plaintext Payload Format](#6-plaintext-payload-format)
7. [Flag Definitions](#7-flag-definitions)
8. [Thread Model](#8-thread-model)
9. [Discovery](#9-discovery)
10. [On-Chain Transaction Requirements](#10-on-chain-transaction-requirements)
11. [Scanning Algorithm](#11-scanning-algorithm)
12. [Versioning](#12-versioning)
13. [Test Vectors](#13-test-vectors)
14. [Security Considerations](#14-security-considerations)

---

## 1. Overview

A Rummur message is carried as the payload of the `tx_extra_nonce` field of a standard Monero transaction. The payload is encrypted end-to-end using Elliptic Curve Diffie-Hellman key agreement derived from the recipient's existing Monero address. No new key material is introduced. No new cryptographic primitives are introduced. The encrypted nonce is opaque to any observer who does not hold the recipient's private view key.

On-chain, a message transaction is indistinguishable from any other Monero transaction.

---

## 2. Terminology

The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119).

| Term | Meaning |
|---|---|
| **sender** | The party constructing and broadcasting the message transaction |
| **recipient** | The party whose view key is used to encrypt the payload |
| **address** | A 95-character base58-encoded Monero standard address, encoding `pub_spend_key \|\| pub_view_key` |
| **tx_pk** | The one-time public transaction key included in every Monero transaction's `tx_extra` field |
| **tx_sk** | The corresponding private transaction key, known only to the sender |
| **view_sk** | The recipient's private view key |
| **view_pk** | The recipient's public view key (encoded in their address) |
| **derivation** | The 32-byte shared ECDH value `8 × tx_sk × view_pk` |
| **nonce** | The `tx_extra_nonce` payload, up to 255 bytes |
| **thread_nonce** | An 8-byte value chosen by the sender that links messages into a conversation thread locally |
| **cn_fast_hash** | Keccak-256 as used in the Monero source (`crypto/hash.h`) — NOT standard SHA3 |

---

## 3. Monero Transaction Background

### tx_extra structure

Every Monero transaction carries a `tx_extra` field. It is a sequence of tagged fields:

| Tag byte | Field type | Max size |
|---|---|---|
| `0x01` | One-time public transaction key | 33 bytes |
| `0x02` | Nonce | 255 bytes of content |
| `0x03` | Merge mining tag | variable |
| `0x04` | Additional public keys | variable |

The nonce field (tag `0x02`) is followed by a one-byte length, then up to 255 bytes of content. The total `tx_extra` field has an enforced maximum of 1,060 bytes (enforced by the Monero transaction pool).

### Standard nonce sub-tags

When the nonce is used for payment IDs, the first byte acts as a sub-tag:

| First byte | Meaning |
|---|---|
| `0x00` | Unencrypted payment ID (32 bytes follow) |
| `0x01` | Encrypted payment ID (8 bytes follow) |

The Rummur protocol uses `0x4D` as its first byte. This value is not a registered sub-tag and does not conflict with existing Monero usage.

### ECDH derivation in Monero

Monero's key derivation function computes:

```
derivation = 8 × scalar × point
```

Where `×` denotes scalar multiplication on curve25519. The factor of 8 (the cofactor) is applied by the Monero source to clear the small subgroup.

- **Sender computes**: `derivation = 8 × tx_sk × view_pk`
- **Recipient computes**: `derivation = 8 × view_sk × tx_pk`

These produce the same 32-byte value because scalar multiplication is commutative:
`tx_sk × view_sk × 8G = view_sk × tx_sk × 8G`

The function is `generate_key_derivation(public_key, secret_key, derivation)` in `crypto/crypto.h`. The derivation is serialised as a 32-byte little-endian representation of the curve point.

---

## 4. Wire Format

### 4.1. tx_extra_nonce layout

The Rummur protocol occupies the full 255-byte nonce content field. All multi-byte integer fields are big-endian unless stated otherwise.

```
Offset  Length  Field
──────  ──────  ─────────────────────────────────────────────────────────
0       1       magic         = 0x4D ('M')
1       1       version_flags = (version << 4) | flags
2       8       thread_nonce  — random bytes chosen by sender
10      245     ciphertext    — ECDH-encrypted payload (see §5)
```

**Total: 255 bytes.**

The nonce content MUST be exactly 255 bytes. Implementations MUST NOT write a shorter nonce — the full 255 bytes MUST be present. Unused bytes within the ciphertext region are filled with random padding before encryption (see §6.3).

### 4.2. Magic byte

`magic` MUST be `0x4D`. Recipients scanning `tx_extra_nonce` fields MUST skip any nonce whose first byte is not `0x4D`.

### 4.3. version_flags byte

Bits 7–4 carry the protocol version (0–15). Bits 3–0 carry flags (see §7).

```
  7   6   5   4   3   2   1   0
┌───┬───┬───┬───┬───┬───┬───┬───┐
│  version  (4) │      flags    │
└───┴───┴───┴───┴───┴───┴───┴───┘
```

This specification defines version `0x0`. A recipient MUST ignore (not decrypt) any nonce with a version number it does not recognise.

### 4.4. Thread nonce

The 8-byte `thread_nonce` at bytes 2–9 is chosen uniformly at random by the sender for the first message in a conversation. For all replies in the same thread, the sender MUST echo the `thread_nonce` value from the original message.

The thread nonce has no on-chain meaning. It is purely a local grouping hint for the recipient's client. An observer without the view key cannot read it.

### 4.5. Ciphertext

Bytes 10–254 carry the ECDH-encrypted payload (245 bytes). The encryption scheme is defined in §5. The plaintext structure is defined in §6.

---

## 5. Encryption

### 5.1. Key derivation

The sender derives a shared secret using the existing Monero ECDH mechanism:

```
// sender side
generate_key_derivation(recipient.view_pk, tx_sk, derivation)
```

The recipient derives the same shared secret using the one-time transaction public key from `tx_extra`:

```
// recipient side
generate_key_derivation(tx_pk, view_sk, derivation)
```

Both calls produce the same 32-byte `derivation` value.

### 5.2. Keystream generation

A 256-byte keystream is generated from the shared derivation using counter-mode hashing with a protocol-specific domain separator:

```
DOMAIN = 0x4D   // same as magic byte — domain-separates from Monero's own use

for block_idx in 0x00 .. 0x07:  // 8 iterations
    input    = derivation (32 bytes) || DOMAIN (1 byte) || block_idx (1 byte)
    keystream_block[block_idx] = cn_fast_hash(input, 34)

keystream = keystream_block[0] || keystream_block[1] || ... || keystream_block[7]
            // 8 × 32 = 256 bytes total
```

Only the first 245 bytes of the keystream are used (matching the ciphertext region).

`cn_fast_hash` is Keccak-256 as defined in the Monero source (`src/crypto/hash-ops.h`). It is NOT identical to NIST SHA3-256 — the padding differs.

### 5.3. Encryption

```
ciphertext = plaintext XOR keystream[0..244]
```

XOR is applied byte-for-byte. `plaintext` is 245 bytes (the full payload including padding — see §6.3).

### 5.4. Decryption

Decryption is identical to encryption (XOR is its own inverse):

```
plaintext = ciphertext XOR keystream[0..244]
```

After decryption, the recipient MUST verify `plaintext[0]` is a recognised `payload_type` value (§6.1) before processing further. An unrecognised type indicates either a non-message transaction or a failed decryption attempt.

---

## 6. Plaintext Payload Format

### 6.1. Payload structure

The 245-byte plaintext has the following layout:

```
Offset  Length  Field
──────  ──────  ─────────────────────────────────────────────────────────
0       1       payload_type
1       2       msg_len       — uint16 big-endian, byte count of message
3       N       message       — UTF-8 encoded text, N = msg_len
3+N     *       [sender_addr] — 95 bytes, present only if flag bit 0 is set
3+N+95  *       padding       — random bytes to fill remaining space to 245
```

`*` — conditional or variable-length, see below.

**payload_type values:**

| Value | Meaning |
|---|---|
| `0x01` | Text message (UTF-8) |
| `0x02` | Reserved — MUST NOT be written; MUST be ignored on receipt |

All other `payload_type` values are reserved. An implementation that receives an unrecognised `payload_type` after decryption SHOULD silently discard the message and continue scanning.

### 6.2. Message text

`message` is UTF-8 encoded text. `msg_len` is the byte length of the UTF-8 encoding (not the character count — these differ for non-ASCII text).

Implementations MUST reject a message where `msg_len` exceeds the space available in the payload after the fixed header (and optional sender address, if flag bit 0 is set). Implementations MUST NOT write a `msg_len` that would cause the message to overrun the 245-byte plaintext boundary.

**Maximum text capacity:**

| Mode | Available bytes for text |
|---|---|
| Anonymous (flag bit 0 clear) | 242 bytes |
| With sender address (flag bit 0 set) | 147 bytes |

### 6.3. Padding

All bytes in the plaintext after the message (and optional sender address) MUST be filled with cryptographically random bytes before encryption. Padding MUST NOT be all-zero — uniform random padding provides length obfuscation and prevents watermarking.

Implementations MUST generate new random padding for every message, including retransmissions of the same text.

### 6.4. Sender address (optional)

When flag bit 0 is set, the 95-byte ASCII representation of the sender's standard Monero address is appended immediately after the message text. The address MUST be the sender's primary address (not a subaddress).

A recipient who decrypts a message with flag bit 0 set MAY store the sender's address as a contact automatically and send replies to it. A recipient who decrypts a message with flag bit 0 clear receives an anonymous message — no return address is implied.

**Default behaviour:**
- First message sent to a new contact: flag bit 0 is clear (anonymous)
- Subsequent messages after the recipient has replied: flag bit 0 is set
- Replies always echo the thread_nonce and set flag bit 0

This behaviour is a RECOMMENDED default. Implementations MAY expose a user-facing option to override it.

---

## 7. Flag Definitions

The lower 4 bits of `version_flags` (byte 1) are protocol flags:

| Bit | Name | Meaning when set |
|---|---|---|
| 0 | `SENDER_ADDR` | Sender's 95-byte address is appended after message text |
| 1 | `IS_REPLY` | This message is a reply; `thread_nonce` echoes the original |
| 2 | `RESERVED` | Reserved for future use — MUST be 0 in this version |
| 3 | `RESERVED` | Reserved for future use — MUST be 0 in this version |

Implementations MUST write reserved flag bits as 0. Implementations MUST ignore the value of reserved flag bits when reading.

---

## 8. Thread Model

Messages are grouped into threads locally by the `thread_nonce`. No thread information appears on-chain.

**Rules:**

1. The sender of the first message in a new conversation generates a fresh random 8-byte `thread_nonce`.
2. When replying to a message, the sender MUST use the same `thread_nonce` value as the message being replied to and MUST set flag bit 1 (`IS_REPLY`).
3. The recipient's client groups received messages into a thread if they share the same `thread_nonce` value originating from the same address (or, for anonymous messages, the same thread_nonce from the same tx output key context).
4. If a sender begins a new conversation with the same recipient, they MUST generate a new random `thread_nonce`. Reusing a thread_nonce for an unrelated conversation produces incorrect local grouping.

The thread model is intentionally simple. More sophisticated conversation state (read receipts, deletions, reactions) is out of scope for version 0.1.

---

## 9. Discovery

### 9.1. Layer 0 — Address sharing (always available)

A Monero address is sufficient as an identity. No protocol-level discovery is needed. Out-of-band address exchange (QR code, AirDrop, manual copy-paste) is the baseline.

### 9.2. Layer 1 — Self-hosted OpenAlias (opt-in)

OpenAlias is already implemented in the Monero wallet source (`src/common/dns_utils.cpp`). A user who controls a domain MAY publish a DNS TXT record:

```
oa1:xmr recipient_address=<95-char-address>;
```

The record is published at `name.domain.tld` for the handle `name@domain.tld`. DNSSEC validation is RECOMMENDED. The wallet resolves this natively. No third-party service is involved.

OpenAlias discovery is OPTIONAL and strictly opt-in. Implementations MUST NOT resolve OpenAlias without explicit user action.

### 9.3. Layer 2 — Nostr (deferred, not part of v0.1)

Nostr-based contact discovery is deferred to a future version. The privacy tradeoffs of publishing a Monero address to a public gossip network require community evaluation. The protocol reserve no on-wire space for Nostr in this version.

### 9.4. What is explicitly rejected

**On-chain registries**: Publishing handles on-chain permanently and immutably links them to addresses in a public ledger. This violates the Monero privacy model and MUST NOT be implemented.

**Centralised directories**: Any discovery mechanism that requires querying a central server introduces a point of failure, a surveillance vector, and a trust assumption. These are not permitted by design.

---

## 10. On-Chain Transaction Requirements

### 10.1. Transaction type

Rummur messages MUST be sent as standard RingCT transactions. The ring size MUST match the current Monero network default (currently 16 inputs).

### 10.2. Self-send (minimum XMR transfer)

To minimise the XMR that leaves the sender's wallet, the transaction output SHOULD be sent back to the sender's own address. Only the network fee leaves the wallet permanently. The recipient of the *message* is identified by the encryption key, not the transaction output destination.

Specifically: the `generate_key_derivation` call uses the recipient's view key to encrypt the payload; the RingCT output itself may go to any address, including the sender's own. The recipient scans for the magic byte and decrypts using their view key regardless of where the output is directed.

### 10.3. Output count

Every Monero transaction after hard fork 12 (HF12) requires a minimum of 2 outputs. Rummur transactions MUST comply. The second output is the change output back to the sender, which is already produced by standard wallet transaction construction.

### 10.4. tx_extra requirements

The `tx_extra` field MUST include:
1. A one-time public transaction key (tag `0x01`) — required for ECDH decryption
2. The Rummur nonce (tag `0x02`) — exactly 255 bytes of content

No additional `tx_extra` fields are required. Additional fields (e.g., additional public keys for subaddresses) are permitted if required by the wallet.

### 10.5. Fee

The transaction fee is paid at whatever priority the sender selects. The fee is not part of the protocol. For reference at the time of writing:

| Priority | Approx fee | Approx USD at $350/XMR |
|---|---|---|
| Slow | ~0.0006 XMR | ~$0.21 |
| Normal | ~0.0024 XMR | ~$0.84 |
| Fast | ~0.012 XMR | ~$4.20 |

Implementations SHOULD default to slow priority and surface the fee in the user's local currency before sending.

---

## 11. Scanning Algorithm

A recipient scans for incoming Rummur messages by inspecting `tx_extra` nonce fields across transactions:

```
for each transaction tx in block:

    1. Extract tx_pk from tx.extra (tag 0x01)
       If not present: skip tx

    2. Compute derivation = generate_key_derivation(tx_pk, view_sk)
       (Uses recipient's private view key)

    3. For each nonce field in tx.extra (tag 0x02):
       a. If nonce length != 255: skip
       b. If nonce[0] != 0x4D: skip       // wrong magic
       c. Parse version_flags = nonce[1]
       d. version = version_flags >> 4
       e. If version not recognised: skip   // forward compatibility
       f. Generate keystream from derivation (see §5.2)
       g. plaintext = nonce[10..254] XOR keystream[0..244]
       h. If plaintext[0] not a recognised payload_type: skip
       i. Parse payload per §6
       j. Store thread_nonce = nonce[2..9]
       k. Deliver message to application layer

    4. Advance to next transaction
```

The view tag mechanism (Monero HF15) MAY be used to skip transactions that do not match the recipient's view tag before performing the full derivation. This provides approximately 40% scanning speedup. Implementations SHOULD use view tags when available.

Scanning is performed by the recipient's node or wallet. No third party is required to scan on the recipient's behalf, though an optional self-hosted push proxy MAY be used — see `PLAN.md`.

---

## 12. Versioning

The 4-bit version field (bits 7–4 of byte 1) allows 16 protocol versions (0–15).

Version `0x0` is this specification.

A future version MAY:
- Redefine the flag bits
- Change the keystream construction
- Alter the plaintext payload format

A future version MUST NOT:
- Change the magic byte (`0x4D`)
- Change the nonce length (255 bytes)
- Change the offset of the version field

Implementations MUST ignore nonces with unrecognised version numbers. They MUST NOT attempt to decrypt them.

Backwards compatibility: an implementation that supports version `N` is not required to support any prior version.

---

## 13. Test Vectors

**[TBD — to be generated by the reference CLI implementation in Phase 2]**

The following will be provided once the reference implementation is complete:

- A deterministic test transaction (stagenet)
- Known input values: `tx_sk`, `view_sk`, `tx_pk`, message text, `thread_nonce`, flags
- Expected `derivation` (32 bytes hex)
- Expected keystream (256 bytes hex, first 245 bytes used)
- Expected plaintext (245 bytes hex)
- Expected ciphertext / nonce content (255 bytes hex, including magic and header)

Test vectors will be provided for:
- Anonymous text message (flag bit 0 clear)
- Text message with sender address (flag bit 0 set)
- Reply message (flag bit 1 set, thread_nonce echoed)

Until test vectors are published, implementors SHOULD cross-test against the reference CLI tool.

---

## 14. Security Considerations

### 14.1. Key reuse

The ECDH derivation uses the one-time transaction key `tx_sk`, which is unique per transaction. A new `tx_sk` MUST be generated for every message transaction. Reusing `tx_sk` across transactions would allow an attacker who learns one message plaintext to decrypt all messages sent with the same key.

Standard Monero wallet transaction construction generates a fresh one-time key automatically. Implementations MUST NOT manually reuse transaction keys.

### 14.2. Forward secrecy

Version 0.1 does not provide forward secrecy. If a recipient's `view_sk` is compromised, an attacker with access to historical blockchain data can decrypt all past messages. This is a known limitation of the design.

Forward secrecy via Double Ratchet is planned for Phase 7 of the implementation roadmap (see `PLAN.md`). It will be introduced as a new protocol version.

### 14.3. Sender anonymity

When flag bit 0 is clear, the sender's address does not appear in the message. The Monero ring signature mechanism obscures the sending output. A recipient cannot determine the sender's identity from on-chain data alone.

When flag bit 0 is set, the sender's address appears in the encrypted payload. It is not visible on-chain. It is visible to anyone who holds the recipient's view key.

### 14.4. Traffic analysis

Monero's stealth addresses and RingCT ensure that the link between sender and recipient is not visible on-chain. However, a passive network observer who can correlate transaction broadcast timing with IP addresses may be able to identify the sender's node. All Rummur client implementations MUST route transaction broadcast and block scanning through Tor to mitigate this.

### 14.5. Padding and message length

All 245 ciphertext bytes are present in every message regardless of the actual message length. The plaintext is padded to 245 bytes with random data before encryption. This means on-chain observers cannot determine message length from the nonce size (it is always 255 bytes).

However, the overall transaction size (which includes the ciphertext) is visible. Two transactions that are otherwise identical but carry different message lengths will have the same nonce size — but may differ slightly in total transaction size due to other `tx_extra` fields. Implementations SHOULD ensure `tx_extra` construction is consistent regardless of message length.

### 14.6. Spam and denial of service

Each message requires payment of the Monero network fee. This is the primary anti-spam mechanism. There is no protocol-level rate limiting or blocklist — these are application-layer concerns.

### 14.7. Replay attacks

The ECDH derivation is unique per transaction because `tx_sk` is unique per transaction. The same plaintext re-encrypted with a new `tx_sk` produces different ciphertext. Replaying an old transaction on the network is not possible on Monero (the key image mechanism prevents double-spend).

### 14.8. Cryptographic agility

This version of the protocol does not offer cipher negotiation. The keystream construction is fixed. Cipher agility introduces complexity and downgrade attack surface. If the underlying primitives require replacement, that is handled by a new protocol version.

---

*End of specification.*

*For the product vision, implementation phases, and platform architecture, see [`PLAN.md`](./PLAN.md).*
*For community discussion, open an issue in this repository.*
