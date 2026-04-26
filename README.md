# Aegis 2 — Encrypted Container Format

**Aegis 2** is a security-focused encrypted container format for Android/Kotlin applications, designed for protected Bardo Notes exports.

Aegis 2 is not a thin wrapper around a single cipher. It defines a complete binary export format with memory-hard password-based key derivation, KEK/CEK key separation, authenticated chunk encryption, integrity verification, and re-key support.

> **Status:** Technical Preview
> Aegis 2 is published for transparency, implementation review, and feedback before stable integration into Bardo 1.0.

## Overview

Aegis 2 was designed to make encrypted exports safer, more efficient, and easier to evolve over time.

The format uses a TLV-based binary header, allowing future fields and extensions to be introduced without breaking existing readers. Payload data is processed in authenticated chunks, making the format suitable for large exports and memory-constrained mobile environments.

The default cipher is **XChaCha20-Poly1305**. **AES-256-GCM** support is also available for compatibility and controlled migration scenarios.

Password-based key derivation is handled through **Argon2id** with device-adaptive parameters.

## Core Features

Aegis 2 includes the following capabilities:

- XChaCha20-Poly1305 as the default authenticated encryption mode.
- AES-256-GCM support for compatibility.
- Argon2id memory-hard password-based key derivation.
- Device-adaptive KDF parameters for Android and mobile environments.
- KEK/CEK key separation.
- TLV-extensible binary header.
- 64 KB chunked authenticated encryption.
- Sequence-bound AAD for each encrypted chunk.
- HMAC-based key commitment.
- End-of-stream integrity verification.
- Re-key support by re-wrapping the content encryption key.
- Streaming-friendly encryption and decryption.
- Coroutine cancellation support.
- Backward-compatible import paths for earlier Aegis and JSON-based formats.

## Binary Format

Aegis 2 files use the `.aegis` binary format.

The file layout is organized as follows:

1. Magic bytes: `AEGS`
2. Format version: `0x02`
3. Header length
4. TLV header
5. Encrypted chunk stream
6. End-of-stream MAC

The TLV header contains cryptographic and structural metadata, including:

- cipher identifier,
- KDF salt,
- KDF parameters,
- header nonce,
- wrapped CEK,
- key commitment,
- chunk size,
- total chunk count,
- payload size,
- flags,
- and optional file metadata.

Each encrypted chunk contains:

- a per-chunk nonce,
- ciphertext,
- and an authentication tag.

The file ends with an HMAC-SHA256 value used for end-of-stream integrity verification.

## Security Architecture

Aegis 2 separates password-derived key material from payload encryption.

The user password is processed through Argon2id to derive a **KEK**.

The **KEK** is used only to wrap the **CEK**.

The **CEK** is randomly generated and used to encrypt the payload chunks.

A separate Argon2id derivation is used to produce a commitment key. This key is used to calculate an HMAC-based key commitment for the encrypted header state.

This design keeps payload encryption independent from the password itself and allows password rotation without full payload re-encryption.

## Chunk Authentication

Payload data is encrypted in fixed-size chunks.

Each chunk has its own nonce and authenticated data.

The per-chunk AAD binds encrypted data to:

- the chunk index,
- the total chunk count,
- and the expected plaintext size.

This helps detect invalid chunk ordering, malformed chunk boundaries, truncated payloads, and corrupted encrypted data.

## End-of-Stream Integrity

Aegis 2 includes an end-of-stream MAC after the encrypted chunk stream.

This provides an additional integrity check over the encrypted payload structure and helps detect incomplete, truncated, or modified files.

## Re-key Support

Aegis 2 supports password rotation without re-encrypting the entire payload.

During re-keying, the existing CEK is unwrapped using the old password-derived KEK, then wrapped again using a newly derived KEK from the new password.

This allows password changes to be performed by rewriting the header while keeping the encrypted payload unchanged.

## Memory Behavior

Aegis 2 is designed for streaming-friendly payload processing.

The implementation does not require loading the full payload into memory. Large exports can be processed in chunks, making the format more suitable for Android devices and constrained environments.

KDF memory usage depends on the selected Argon2id parameters and is separate from payload streaming overhead.

## Dependencies

Aegis 2 depends on:

- **Kotlinx Coroutines** for cancellation support.
- **Bouncy Castle** for cryptographic primitives.

Bouncy Castle is used for:

- `Argon2BytesGenerator`
- `ChaCha20Poly1305`

Recommended Gradle dependency:

```gradle
implementation("org.bouncycastle:bcprov-jdk15to18:<latest-version>")
```

## Usage

Encrypt a JSON string to an `.aegis` file:

```kotlin
val result = Aegis2.encryptToStream(
    jsonData = myJsonString,
    password = "my-secret-password",
    outputStream = FileOutputStream("data.aegis")
)
```

Decrypt an `.aegis` file:

```kotlin
val decrypted = Aegis2.decryptFromStream(
    inputStream = FileInputStream("data.aegis"),
    password = "my-secret-password"
)

when (decrypted) {
    is Aegis2Result.Success -> println(decrypted.data)
    is Aegis2Result.Error -> println("${decrypted.reason}: ${decrypted.message}")
    else -> {}
}
```

Encrypt a raw file:

```kotlin
Aegis2.encryptFile(
    inputFile = File("document.pdf"),
    outputFile = File("document.pdf.aegis"),
    password = "password"
)
```

Decrypt a raw file:

```kotlin
Aegis2.decryptFile(
    inputFile = File("document.pdf.aegis"),
    outputFile = File("document.pdf"),
    password = "password"
)
```

Change the password without full payload re-encryption:

```kotlin
Aegis2.rekey(
    inputFile = File("data.aegis"),
    outputFile = File("data-new.aegis"),
    oldPassword = "old-password",
    newPassword = "new-password"
)
```

## Security Notice

Aegis 2 has not yet undergone an independent third-party security audit.

The implementation is published for transparency, review, and feedback. Do not describe this project as audited, formally verified, or guaranteed secure unless an independent review has been completed.

Security feedback and implementation review are welcome.

## Created By

Aegis 2 was created by **TypexAI** and **TypexEx**.

Website: https://typexai.dev/TypexEx

## Contact

For official inquiries, please use the appropriate contact address:

- Legal: legal@typexai.dev
- DMCA: dmca@typexai.dev
- Support: support@typexai.dev
- Partnerships: partners@typexai.dev

## License

Apache 2.0
