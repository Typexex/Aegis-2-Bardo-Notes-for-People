/**
 * Aegis2 — Encrypted container format for Android/Kotlin
 *
 * Features:
 * - XChaCha20-Poly1305 and AES-256-GCM dual cipher
 * - Argon2id memory-hard KDF with device-adaptive parameters
 * - TLV-extensible binary header format
 * - Per-chunk AEAD with sequence binding (anti-reorder, anti-truncation)
 * - End-of-stream HMAC-SHA256 integrity verification
 * - Key commitment (detects file tampering vs wrong password)
 * - Re-key API (change password without re-encrypting data)
 * - Streaming O(1) memory — independent of payload size
 * - Fully cancellable via Kotlin coroutines
 * - Backward compatible: reads v1 .aegis binary files
 *
 * Format: .aegis v2 (binary container)
 * Dependencies: Kotlinx Coroutines, Bouncy Castle (org.bouncycastle)
 *
 * License: Apache 2.0
 */
package aegis2

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.OutputStreamWriter
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.Base64
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * High-level Aegis2 API.
 *
 * Thread-safe: all functions are either suspend (run on Dispatchers.IO)
 * or pure synchronous operations.
 *
 * Basic usage:
 * ```
 * // Encrypt
 * val result = Aegis2.encryptToStream(jsonString, password, outputStream)
 *
 * // Decrypt
 * val data = Aegis2.decryptFromStream(inputStream, password)
 * ```
 */
object Aegis2 {

    /**
     * Encrypt JSON string to .aegis v2 output stream.
     *
     * @param jsonData Plaintext JSON to encrypt
     * @param password Encryption password
     * @param outputStream Target output stream
     * @param cipher Cipher to use (default: XChaCha20-Poly1305)
     * @param progress Optional progress callback
     * @return Success or Error result
     */
    fun encryptToStream(
        jsonData: String,
        password: String,
        outputStream: OutputStream,
        cipher: CipherType = CipherType.XChaCha20Poly1305,
        progress: Aegis2Progress? = null
    ): Aegis2Result {
        return AegisEncryption.encryptJsonAegis2Result(jsonData, password, outputStream, cipher, progress)
    }

    /**
     * Encrypt file to .aegis v2 file.
     *
     * @param inputFile Plaintext input file
     * @param outputFile Output .aegis file
     * @param password Encryption password
     * @param cipher Cipher to use (default: XChaCha20-Poly1305)
     * @param progress Optional progress callback
     * @return SuccessFile or Error result
     */
    fun encryptFile(
        inputFile: File,
        outputFile: File,
        password: String,
        cipher: CipherType = CipherType.XChaCha20Poly1305,
        progress: Aegis2Progress? = null
    ): Aegis2Result {
        return AegisEncryption.encryptFileAegis2Result(inputFile, outputFile, password, cipher, progress)
    }

    /**
     * Decrypt .aegis stream (auto-detects v1/v2 format).
     *
     * @param inputStream Input .aegis stream
     * @param password Decryption password
     * @param progress Optional progress callback
     * @return Decrypted text or Error result
     */
    suspend fun decryptFromStream(
        inputStream: InputStream,
        password: String,
        progress: Aegis2Progress? = null
    ): Aegis2Result {
        return AegisEncryption.decryptAegis2Result(inputStream, password, progress)
    }

    /**
     * Decrypt .aegis file (auto-detects v1/v2 format).
     *
     * Writes output to a temporary file first, then atomically renames
     * to outputFile on success.
     *
     * @param inputFile Input .aegis file
     * @param outputFile Output plaintext file
     * @param password Decryption password
     * @param progress Optional progress callback
     * @return SuccessFile or Error result
     */
    suspend fun decryptFile(
        inputFile: File,
        outputFile: File,
        password: String,
        progress: Aegis2Progress? = null
    ): Aegis2Result {
        return AegisEncryption.decryptFileAegis2Result(inputFile, outputFile, password, progress)
    }

    /**
     * Re-key (change password) without re-encrypting data.
     *
     * Reads the header from inputFile, unwraps the Content Encryption Key (CEK)
     * using the old password, then re-wraps it with the new password.
     * The ciphertext payload is copied unchanged.
     *
     * In-place re-key is intentionally unsupported; use a separate output file.
     *
     * @param inputFile Original .aegis file
     * @param outputFile Output .aegis file with new password
     * @param oldPassword Current password
     * @param newPassword New password
     * @param progress Optional progress callback
     * @return SuccessFile or Error result
     */
    suspend fun rekey(
        inputFile: File,
        outputFile: File,
        oldPassword: String,
        newPassword: String,
        progress: Aegis2Progress? = null
    ): Aegis2Result {
        return AegisEncryption.rekeyAegis2Result(inputFile, outputFile, oldPassword, newPassword, progress)
    }

    /**
     * Check if byte array starts with .aegis magic bytes ("AEGS").
     */
    fun isAegisFormat(header: ByteArray): Boolean = AegisEncryption.isAegisFormat(header)

    /**
     * Check if byte array is an Aegis v2 format header.
     */
    fun isAegisV2(header: ByteArray): Boolean = AegisEncryption.isAegisV2(header)

    /**
     * Peek cipher type from header without decrypting.
     * Returns null if header is invalid or not Aegis v2.
     */
    fun getCipherType(header: ByteArray): CipherType? = AegisEncryption.getAegisCipherType(header)

    /**
     * Decrypt legacy v1 .aegis binary stream.
     */
    suspend fun decryptLegacyStream(
        inputStream: InputStream,
        password: String
    ): Aegis2Result {
        return AegisEncryption.decryptAegis2Result(inputStream, password)
    }
}

enum class CipherType {
    XChaCha20Poly1305,
    AES256GCM
}

interface Aegis2Progress {
    fun onPhase(phase: Phase)
    fun onProgress(bytesProcessed: Long, totalBytes: Long)
}

enum class Phase {
    KDF,
    ENCRYPT_CHUNKS,
    DECRYPT_CHUNKS,
    COMPRESS,
    DECOMPRESS,
    MAC,
    REKEY
}

sealed class Aegis2Result {
    data class Success(val data: String) : Aegis2Result()
    data class SuccessFile(val outputFile: File) : Aegis2Result()
    data class NotEncrypted(val data: String) : Aegis2Result()
    data class Error(val message: String, val reason: ErrorReason) : Aegis2Result()
}

enum class ErrorReason {
    WRONG_PASSWORD,
    FILE_CORRUPTED,
    FILE_TAMPERED,
    UNSUPPORTED_FORMAT,
    IO_ERROR,
    INTERNAL_ERROR,
    CANCELLED
}

// ============================================================================
// IMPLEMENTATION
// ============================================================================

/**
 * Internal implementation object.
 *
 * Separated from the public API facade to allow clean naming
 * while keeping internals package-private.
 */
object AegisEncryption {

    // ============================================================
    // Binary Format Constants (.aegis v2)
    // ============================================================
    private val MAGIC_BYTES = byteArrayOf(0x41, 0x45, 0x47, 0x53) // "AEGS"
    private const val V1_FORMAT_VERSION: Byte = 0x01
    private const val V2_FORMAT_VERSION: Byte = 0x02

    private const val CIPHER_ALGORITHM = "AES/GCM/NoPadding"
    private const val KEY_ALGORITHM = "AES"
    private const val HMAC_ALGORITHM = "HmacSHA256"
    private const val KEY_SIZE_BITS = 256
    private const val KEY_SIZE_BYTES = 32
    private const val GCM_TAG_LENGTH_BITS = 128
    private const val GCM_TAG_LENGTH_BYTES = 16
    private const val IV_SIZE_BYTES = 12
    private const val XCHACHA_NONCE_SIZE_BYTES = 24
    private const val SALT_SIZE_BYTES = 16
    private const val ENCRYPTED_CEK_SIZE = KEY_SIZE_BYTES + GCM_TAG_LENGTH_BYTES // 48
    private const val EOS_MAC_SIZE_BYTES = 32

    // Argon2id parameters
    private const val ARGON2_MEMORY_KB = 32768
    private const val ARGON2_ITERATIONS = 4
    private const val ARGON2_PARALLELISM = 1
    private const val MIN_ARGON2_MEMORY_KB = 8192
    private const val MAX_ARGON2_MEMORY_KB = 262144

    // Chunked streaming
    private const val DEFAULT_CHUNK_SIZE = 65536  // 64 KB
    private const val STREAM_BUFFER_SIZE = DEFAULT_CHUNK_SIZE
    private const val MAX_TEXT_FORMAT_BYTES = 64 * 1024 * 1024
    private const val MAX_DECRYPTED_JSON_BYTES = 64 * 1024 * 1024
    private const val MAX_V2_HEADER_BYTES = 1024 * 1024
    private const val MAX_V2_KDF_MEMORY_KB = 1_048_576
    private const val MIN_V2_KDF_MEMORY_KB = 1024
    private const val MAX_V2_KDF_ITERATIONS = 100
    private const val MAX_V2_KDF_PARALLELISM = 16
    private const val MAX_V2_PAYLOAD_BYTES = 256L * 1024L * 1024L
    private const val TEMP_FILE_MAX_AGE_MS = 10L * 60L * 1000L
    private const val KDF_LOG_TAG = "Aegis2KDF"
    private const val AEGIS2_LOG_TAG = "Aegis2"
    private val KEY_COMMITMENT_LABEL = "AEGIS2_COMMIT_v1".toByteArray(StandardCharsets.UTF_8)
    private val EOS_MAC_LABEL = "AEGIS2_EOS_v1".toByteArray(StandardCharsets.UTF_8)

    private object TlvTag {
        const val CIPHER_ID = 0x01
        const val KDF_SALT = 0x02
        const val KDF_COMMIT_SALT = 0x03
        const val KDF_MEMORY_KB = 0x04
        const val KDF_ITERATIONS = 0x05
        const val KDF_PARALLELISM = 0x06
        const val HEADER_NONCE = 0x07
        const val WRAPPED_CEK = 0x08
        const val KEY_COMMITMENT = 0x09
        const val CHUNK_SIZE = 0x0A
        const val TOTAL_CHUNKS = 0x0B
        const val FILE_METADATA = 0x0C
        const val PAYLOAD_SIZE = 0x0D
        const val FLAGS = 0x0E
        const val HEADER_END = 0xFF
    }

    private const val CIPHER_ID_XCHACHA20_POLY1305 = 0
    private const val CIPHER_ID_AES256_GCM = 1
    private const val FLAG_GZIP_PAYLOAD = 0x01

    // Legacy constants for v1 binary backward compat
    private const val AEGIS_VERSION_LEGACY = "3.0"
    private const val SCHEME_ID_LEGACY = "Aegis-PBKDF2-AES256-GCM"
    private const val DEFAULT_KDF_ITERATIONS_LEGACY = 210_000
    private const val MIN_KDF_ITERATIONS_LEGACY = 100_000
    private const val MAX_KDF_ITERATIONS_LEGACY = 1_000_000

    private val secureRandom = ThreadLocal.withInitial { SecureRandom() }
    private val supportedKdfsLegacy = listOf("PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA1")

    // ============================================================
    // Public API Methods (used by Aegis2 facade)
    // ============================================================

    suspend fun encryptToStream(
        jsonData: String,
        password: String
    ) = withContext(Dispatchers.IO) {
        val passwordChars = password.toCharArray()
        val checkCancellation = cancellationChecker()

        try {
            require(passwordChars.isNotEmpty()) { "Password is required." }
            require(jsonData.utf8ByteLimitSafeLength() <= MAX_DECRYPTED_JSON_BYTES) {
                "Aegis export is too large."
            }

            encryptJsonV2ToStreamBlocking(
                jsonData = jsonData,
                passwordChars = passwordChars,
                outputStream = this@AegisEncryption /* outputStream is captured */,
                cipherType = CipherType.XChaCha20Poly1305,
                progress = null,
                checkCancellation = checkCancellation
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: IOException) {
            println("$AEGIS2_LOG_TAG: I/O error during encryption: ${e.message}")
            throw SecurityException("Aegis write failed", e)
        } catch (e: OutOfMemoryError) {
            println("$AEGIS2_LOG_TAG: Not enough memory for encryption")
            throw SecurityException("Not enough memory for Aegis encryption", e)
        } catch (e: Exception) {
            println("$AEGIS2_LOG_TAG: Error: ${e.message}")
            throw SecurityException("Aegis encryption failed", e)
        } finally {
            wipePassword(passwordChars)
        }
    }

    suspend fun decryptFromStream(
        inputStream: InputStream,
        password: String
    ): String = withContext(Dispatchers.IO) {
        val passwordChars = password.toCharArray()
        var kekMaterial: ByteArray? = null
        var cekMaterial: ByteArray? = null
        val checkCancellation = cancellationChecker()

        try {
            require(passwordChars.isNotEmpty()) { "Password is required." }

            val bufferedInput = if (inputStream is BufferedInputStream) {
                inputStream
            } else {
                BufferedInputStream(inputStream, STREAM_BUFFER_SIZE)
            }
            bufferedInput.mark(MAGIC_BYTES.size + 1)
            val prefix = ByteArray(MAGIC_BYTES.size + 1)
            val prefixRead = bufferedInput.read(prefix)
            bufferedInput.reset()

            if (prefixRead < MAGIC_BYTES.size || !prefix.copyOf(MAGIC_BYTES.size).contentEquals(MAGIC_BYTES)) {
                throw SecurityException("Not a valid .aegis file")
            }

            if (prefixRead >= MAGIC_BYTES.size + 1 && prefix[MAGIC_BYTES.size] == V2_FORMAT_VERSION) {
                return@withContext decryptJsonV2FromStreamBlocking(
                    inputStream = bufferedInput,
                    passwordChars = passwordChars,
                    checkCancellation = checkCancellation
                )
            }

            DataInputStream(bufferedInput).use { dis ->
                val magic = ByteArray(4)
                dis.readFully(magic)
                if (!magic.contentEquals(MAGIC_BYTES)) {
                    throw SecurityException("Not a valid .aegis file")
                }

                val version = dis.readByte()
                if (version != V1_FORMAT_VERSION) {
                    throw SecurityException("Unsupported .aegis version")
                }

                val salt = ByteArray(SALT_SIZE_BYTES)
                dis.readFully(salt)
                val kdfMemory = dis.readInt()
                val kdfIterations = dis.readInt()

                if (kdfMemory < MIN_ARGON2_MEMORY_KB || kdfMemory > MAX_ARGON2_MEMORY_KB) {
                    throw SecurityException("Invalid KDF memory parameter")
                }
                if (kdfIterations < 1 || kdfIterations > 100) {
                    throw SecurityException("Invalid KDF iterations parameter")
                }

                val cekIv = ByteArray(IV_SIZE_BYTES)
                dis.readFully(cekIv)
                val encryptedCek = ByteArray(ENCRYPTED_CEK_SIZE)
                dis.readFully(encryptedCek)

                val payloadIv = ByteArray(IV_SIZE_BYTES)
                dis.readFully(payloadIv)
                val chunkSize = dis.readInt()

                if (chunkSize < 1024 || chunkSize > 1_048_576) {
                    throw SecurityException("Invalid chunk size")
                }

                checkCancellation()
                kekMaterial = deriveArgon2idKey(passwordChars, salt, kdfMemory, kdfIterations)
                val kek = SecretKeySpec(kekMaterial, KEY_ALGORITHM)

                cekMaterial = unwrapKey(kek, cekIv, encryptedCek)
                val cek = SecretKeySpec(cekMaterial, KEY_ALGORITHM)

                return@withContext readDecryptedCompressedPayload(
                    dis = dis,
                    cek = cek,
                    payloadIv = payloadIv,
                    chunkSize = chunkSize,
                    checkCancellation = checkCancellation
                )
            }
        } catch (e: AEADBadTagException) {
            println("$AEGIS2_LOG_TAG: AEAD error: ${e.message}")
            throw SecurityException("Wrong password or file integrity check failed.", e)
        } catch (e: CancellationException) {
            throw e
        } catch (e: OutOfMemoryError) {
            println("$AEGIS2_LOG_TAG: Not enough memory for decryption")
            throw SecurityException("Not enough memory for Aegis decryption", e)
        } catch (e: SecurityException) {
            throw e
        } catch (e: Exception) {
            println("$AEGIS2_LOG_TAG: Error: ${e.message}")
            throw SecurityException("Decryption error", e)
        } finally {
            wipePassword(passwordChars)
            kekMaterial?.fill(0)
            cekMaterial?.fill(0)
        }
    }

    fun isAegisFormat(header: ByteArray): Boolean {
        if (header.size < 4) return false
        return header[0] == MAGIC_BYTES[0] &&
                header[1] == MAGIC_BYTES[1] &&
                header[2] == MAGIC_BYTES[2] &&
                header[3] == MAGIC_BYTES[3]
    }

    fun isAegisV2(header: ByteArray): Boolean {
        return header.size >= MAGIC_BYTES.size + 1 &&
                isAegisFormat(header) &&
                header[MAGIC_BYTES.size] == V2_FORMAT_VERSION
    }

    fun getAegisCipherType(header: ByteArray): CipherType? {
        if (!isAegisV2(header) || header.size < MAGIC_BYTES.size + 1 + Int.SIZE_BYTES) return null
        val headerLength = ByteBuffer.wrap(header, MAGIC_BYTES.size + 1, Int.SIZE_BYTES).int
        if (headerLength <= 0 || header.size < MAGIC_BYTES.size + 1 + Int.SIZE_BYTES + headerLength) return null
        var offset = MAGIC_BYTES.size + 1 + Int.SIZE_BYTES
        val end = offset + headerLength
        while (offset + 5 <= end) {
            val tag = header[offset].toInt() and 0xff
            val length = ByteBuffer.wrap(header, offset + 1, Int.SIZE_BYTES).int
            offset += 5
            if (length < 0 || offset + length > end) return null
            if (tag == TlvTag.CIPHER_ID && length == 1) {
                return cipherTypeFromId(header[offset].toInt() and 0xff)
            }
            offset += length
        }
        return null
    }

    fun encryptJsonAegis2Result(
        jsonData: String,
        password: String,
        outputStream: OutputStream,
        cipherType: CipherType = CipherType.XChaCha20Poly1305,
        progress: Aegis2Progress? = null
    ): Aegis2Result {
        val passwordChars = password.toCharArray()
        return try {
            require(passwordChars.isNotEmpty()) { "Password is required." }
            require(jsonData.utf8ByteLimitSafeLength() <= MAX_DECRYPTED_JSON_BYTES) {
                "Aegis export is too large."
            }
            encryptJsonV2ToStreamBlocking(jsonData, passwordChars, outputStream, cipherType, progress) {
                if (Thread.currentThread().isInterrupted) throw CancellationException("Aegis operation interrupted")
            }
            Aegis2Result.Success("")
        } catch (e: Aegis2Failure) {
            Aegis2Result.Error(e.message, e.reason)
        } catch (e: CancellationException) {
            Aegis2Result.Error("Aegis operation cancelled", ErrorReason.CANCELLED)
        } catch (e: IOException) {
            Aegis2Result.Error(e.message ?: "I/O error", ErrorReason.IO_ERROR)
        } catch (e: Exception) {
            Aegis2Result.Error(e.message ?: "Aegis operation failed", ErrorReason.INTERNAL_ERROR)
        } finally {
            wipePassword(passwordChars)
        }
    }

    suspend fun decryptAegis2Result(
        inputStream: InputStream,
        password: String,
        progress: Aegis2Progress? = null
    ): Aegis2Result = withContext(Dispatchers.IO) {
        val passwordChars = password.toCharArray()
        val checkCancellation = cancellationChecker()
        try {
            require(passwordChars.isNotEmpty()) { "Password is required." }
            val bufferedInput = if (inputStream is BufferedInputStream) {
                inputStream
            } else {
                BufferedInputStream(inputStream, STREAM_BUFFER_SIZE)
            }
            bufferedInput.mark(MAGIC_BYTES.size + 1)
            val prefix = ByteArray(MAGIC_BYTES.size + 1)
            val prefixRead = bufferedInput.read(prefix)
            bufferedInput.reset()
            if (prefixRead < MAGIC_BYTES.size || !prefix.copyOf(MAGIC_BYTES.size).contentEquals(MAGIC_BYTES)) {
                return@withContext Aegis2Result.NotEncrypted("")
            }
            if (prefixRead < MAGIC_BYTES.size + 1 || prefix[MAGIC_BYTES.size] != V2_FORMAT_VERSION) {
                val data = decryptFromStream(bufferedInput, password)
                return@withContext Aegis2Result.Success(data)
            }
            Aegis2Result.Success(
                decryptJsonV2FromStreamBlocking(
                    inputStream = bufferedInput,
                    passwordChars = passwordChars,
                    progress = progress,
                    checkCancellation = checkCancellation
                )
            )
        } catch (e: Aegis2Failure) {
            Aegis2Result.Error(e.message, e.reason)
        } catch (e: AEADBadTagException) {
            Aegis2Result.Error("Wrong password or file integrity check failed.", ErrorReason.WRONG_PASSWORD)
        } catch (e: CancellationException) {
            Aegis2Result.Error("Aegis operation cancelled", ErrorReason.CANCELLED)
        } catch (e: IOException) {
            Aegis2Result.Error(e.message ?: "I/O error", ErrorReason.IO_ERROR)
        } catch (e: SecurityException) {
            Aegis2Result.Error(e.message ?: "Aegis security error", ErrorReason.FILE_CORRUPTED)
        } catch (e: Exception) {
            Aegis2Result.Error(e.message ?: "Aegis operation failed", ErrorReason.INTERNAL_ERROR)
        } finally {
            wipePassword(passwordChars)
        }
    }

    fun encryptFileAegis2Result(
        inputFile: File,
        outputFile: File,
        password: String,
        cipherType: CipherType = CipherType.XChaCha20Poly1305,
        progress: Aegis2Progress? = null
    ): Aegis2Result {
        val passwordChars = password.toCharArray()
        return try {
            require(passwordChars.isNotEmpty()) { "Password is required." }
            if (!inputFile.isFile) throw IOException("Input file does not exist")
            outputFile.parentFile?.mkdirs()
            FileOutputStream(outputFile).use { output ->
                encryptPayloadFileV2ToStreamBlocking(
                    payloadFile = inputFile,
                    passwordChars = passwordChars,
                    outputStream = output,
                    cipherType = cipherType,
                    flags = 0,
                    metadata = null,
                    progress = progress
                ) {
                    if (Thread.currentThread().isInterrupted) throw CancellationException("Aegis operation interrupted")
                }
                output.fd.sync()
            }
            Aegis2Result.SuccessFile(outputFile)
        } catch (e: Aegis2Failure) {
            Aegis2Result.Error(e.message, e.reason)
        } catch (e: CancellationException) {
            Aegis2Result.Error("Aegis operation cancelled", ErrorReason.CANCELLED)
        } catch (e: IOException) {
            Aegis2Result.Error(e.message ?: "I/O error", ErrorReason.IO_ERROR)
        } catch (e: Exception) {
            Aegis2Result.Error(e.message ?: "Aegis operation failed", ErrorReason.INTERNAL_ERROR)
        } finally {
            wipePassword(passwordChars)
        }
    }

    suspend fun decryptFileAegis2Result(
        inputFile: File,
        outputFile: File,
        password: String,
        progress: Aegis2Progress? = null
    ): Aegis2Result = withContext(Dispatchers.IO) {
        val passwordChars = password.toCharArray()
        val checkCancellation = cancellationChecker()
        var tempFile: File? = null
        try {
            require(passwordChars.isNotEmpty()) { "Password is required." }
            if (!inputFile.isFile) throw IOException("Input file does not exist")
            outputFile.parentFile?.mkdirs()
            tempFile = File(outputFile.absolutePath + ".tmp-aegis2")
            FileInputStream(inputFile).use { input ->
                FileOutputStream(tempFile).use { output ->
                    decryptPayloadV2ToStreamBlocking(input, passwordChars, output, progress, checkCancellation)
                }
            }
            if (outputFile.exists() && !outputFile.delete()) throw IOException("Unable to replace output file")
            if (!tempFile.renameTo(outputFile)) throw IOException("Unable to finalize decrypted file")
            Aegis2Result.SuccessFile(outputFile)
        } catch (e: Aegis2Failure) {
            tempFile?.delete()
            Aegis2Result.Error(e.message, e.reason)
        } catch (e: AEADBadTagException) {
            tempFile?.delete()
            Aegis2Result.Error("Wrong password or file integrity check failed.", ErrorReason.WRONG_PASSWORD)
        } catch (e: CancellationException) {
            tempFile?.delete()
            Aegis2Result.Error("Aegis operation cancelled", ErrorReason.CANCELLED)
        } catch (e: IOException) {
            tempFile?.delete()
            Aegis2Result.Error(e.message ?: "I/O error", ErrorReason.IO_ERROR)
        } catch (e: Exception) {
            tempFile?.delete()
            Aegis2Result.Error(e.message ?: "Aegis operation failed", ErrorReason.INTERNAL_ERROR)
        } finally {
            wipePassword(passwordChars)
        }
    }

    suspend fun rekeyAegis2Result(
        inputFile: File,
        outputFile: File,
        oldPassword: String,
        newPassword: String,
        progress: Aegis2Progress? = null
    ): Aegis2Result = withContext(Dispatchers.IO) {
        val oldPasswordChars = oldPassword.toCharArray()
        val newPasswordChars = newPassword.toCharArray()
        val checkCancellation = cancellationChecker()
        var cekMaterial: ByteArray? = null
        var tempFile: File? = null
        try {
            require(oldPasswordChars.isNotEmpty() && newPasswordChars.isNotEmpty()) { "Password is required." }
            if (inputFile.canonicalFile == outputFile.canonicalFile) {
                return@withContext Aegis2Result.Error(
                    "In-place Aegis2 re-key is intentionally unsupported; use a separate output file.",
                    ErrorReason.UNSUPPORTED_FORMAT
                )
            }
            progress?.onPhase(Phase.REKEY)
            FileInputStream(inputFile).use { input ->
                DataInputStream(BufferedInputStream(input, STREAM_BUFFER_SIZE)).use { dis ->
                    val header = readV2Header(dis)
                    cekMaterial = unwrapAndVerifyCek(header, oldPasswordChars, checkCancellation)
                    val newHeader = buildV2HeaderForExistingCek(header, cekMaterial!!, newPasswordChars, checkCancellation)
                    outputFile.parentFile?.mkdirs()
                    tempFile = File(outputFile.absolutePath + ".tmp-aegis2")
                    FileOutputStream(tempFile).use { rawOutput ->
                        DataOutputStream(BufferedOutputStream(rawOutput, STREAM_BUFFER_SIZE)).use { dos ->
                            writeV2Header(dos, newHeader)
                            copyWithProgress(dis, dos, inputFile.length(), progress, checkCancellation)
                            dos.flush()
                            rawOutput.fd.sync()
                        }
                    }
                }
            }
            if (outputFile.exists() && !outputFile.delete()) throw IOException("Unable to replace output file")
            if (!tempFile!!.renameTo(outputFile)) throw IOException("Unable to finalize re-keyed file")
            Aegis2Result.SuccessFile(outputFile)
        } catch (e: Aegis2Failure) {
            tempFile?.delete()
            Aegis2Result.Error(e.message, e.reason)
        } catch (e: AEADBadTagException) {
            tempFile?.delete()
            Aegis2Result.Error("Wrong password or file integrity check failed.", ErrorReason.WRONG_PASSWORD)
        } catch (e: CancellationException) {
            tempFile?.delete()
            Aegis2Result.Error("Aegis operation cancelled", ErrorReason.CANCELLED)
        } catch (e: IOException) {
            tempFile?.delete()
            Aegis2Result.Error(e.message ?: "I/O error", ErrorReason.IO_ERROR)
        } catch (e: Exception) {
            tempFile?.delete()
            Aegis2Result.Error(e.message ?: "Aegis operation failed", ErrorReason.INTERNAL_ERROR)
        } finally {
            wipePassword(oldPasswordChars)
            wipePassword(newPasswordChars)
            cekMaterial?.fill(0)
        }
    }

    // ============================================================
    // Argon2id KDF
    // ============================================================

    private fun deriveArgon2idKey(
        password: CharArray,
        salt: ByteArray,
        memoryKb: Int,
        iterations: Int
    ): ByteArray = deriveArgon2idKey(password, salt, memoryKb, iterations, ARGON2_PARALLELISM)

    private fun deriveArgon2idKey(
        password: CharArray,
        salt: ByteArray,
        memoryKb: Int,
        iterations: Int,
        parallelism: Int
    ): ByteArray {
        val passwordBytes = password.toUtf8Bytes()
        try {
            val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withMemoryAsKB(memoryKb)
                .withIterations(iterations)
                .withParallelism(parallelism)
                .build()

            val generator = Argon2BytesGenerator()
            generator.init(params)

            val result = ByteArray(KEY_SIZE_BYTES)
            generator.generateBytes(passwordBytes, result)
            return result
        } finally {
            passwordBytes.fill(0)
        }
    }

    private data class KdfParams(
        val memoryKb: Int,
        val iterations: Int,
        val parallelism: Int
    )

    private data class V2Header(
        val cipherType: CipherType,
        val salt: ByteArray,
        val commitSalt: ByteArray,
        val kdfParams: KdfParams,
        val headerNonce: ByteArray,
        val wrappedCek: ByteArray,
        val keyCommitment: ByteArray,
        val chunkSize: Int,
        val totalChunks: Long,
        val payloadSize: Long,
        val flags: Int,
        val metadata: ByteArray?
    )

    private class Aegis2Failure(
        override val message: String,
        val reason: ErrorReason,
        cause: Throwable? = null
    ) : Exception(message, cause)

    private interface CipherEngine {
        val nonceSize: Int
        val tagSize: Int
        fun encrypt(nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray
        fun decrypt(nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray
    }

    private class AES256GCMEngine(key: ByteArray) : CipherEngine {
        private val keySpec = SecretKeySpec(key.copyOf(), KEY_ALGORITHM)
        override val nonceSize: Int = IV_SIZE_BYTES
        override val tagSize: Int = GCM_TAG_LENGTH_BYTES

        override fun encrypt(nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
            val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce))
            if (aad.isNotEmpty()) cipher.updateAAD(aad)
            return cipher.doFinal(plaintext)
        }

        override fun decrypt(nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray {
            val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce))
            if (aad.isNotEmpty()) cipher.updateAAD(aad)
            return cipher.doFinal(ciphertext)
        }
    }

    private class XChaCha20Poly1305Engine(key: ByteArray) : CipherEngine {
        private val keyMaterial = key
        override val nonceSize: Int = XCHACHA_NONCE_SIZE_BYTES
        override val tagSize: Int = GCM_TAG_LENGTH_BYTES

        private companion object {
            val cipherPool: ThreadLocal<ChaCha20Poly1305> = ThreadLocal.withInitial { ChaCha20Poly1305() }
        }

        override fun encrypt(nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
            return process(true, nonce, plaintext, aad)
        }

        override fun decrypt(nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray {
            return process(false, nonce, ciphertext, aad)
        }

        private fun process(forEncryption: Boolean, nonce: ByteArray, input: ByteArray, aad: ByteArray): ByteArray {
            if (nonce.size != XCHACHA_NONCE_SIZE_BYTES) throw GeneralSecurityException("Invalid XChaCha nonce")
            val subKey = hChaCha20(keyMaterial, nonce.copyOfRange(0, 16))
            try {
                val ietfNonce = ByteArray(12)
                System.arraycopy(nonce, 16, ietfNonce, 4, 8)
                val cipher = cipherPool.get()!!
                cipher.reset()
                cipher.init(forEncryption, AEADParameters(KeyParameter(subKey), GCM_TAG_LENGTH_BITS, ietfNonce, aad))
                val output = ByteArray(cipher.getOutputSize(input.size))
                val written = cipher.processBytes(input, 0, input.size, output, 0)
                val finalWritten = cipher.doFinal(output, written)
                val total = written + finalWritten
                return if (total == output.size) output else output.copyOf(total)
            } catch (e: InvalidCipherTextException) {
                throw AEADBadTagException(e.message).apply { initCause(e) }
            } finally {
                subKey.fill(0)
            }
        }
    }

    private fun createCipherEngine(cipherType: CipherType, key: ByteArray): CipherEngine {
        return when (cipherType) {
            CipherType.XChaCha20Poly1305 -> XChaCha20Poly1305Engine(key)
            CipherType.AES256GCM -> AES256GCMEngine(key)
        }
    }

    // ============================================================
    // Device-Adaptive KDF Parameter Selection
    // ============================================================

    private fun selectKdfParams(): KdfParams {
        val runtime = Runtime.getRuntime()
        val usableMemoryMb = runtime.maxMemory()
            .coerceAtMost(640L * 1024L * 1024L) / (1024L * 1024L)
        val cores = Runtime.getRuntime().availableProcessors().coerceIn(1, 4)
        val params = when {
            usableMemoryMb >= 512L -> KdfParams(128_000, 4, cores)
            usableMemoryMb >= 256L -> KdfParams(64_000, 3, minOf(2, cores))
            usableMemoryMb >= 128L -> KdfParams(32_000, 3, 1)
            else -> KdfParams(16_000, 2, 1)
        }
        println("$KDF_LOG_TAG: Selected KDF: ${params.memoryKb}KB/${params.iterations}iter/${params.parallelism}way")
        return params
    }

    private fun validateKdfParams(params: KdfParams) {
        if (params.memoryKb !in MIN_V2_KDF_MEMORY_KB..MAX_V2_KDF_MEMORY_KB) {
            throw Aegis2Failure("Invalid KDF memory parameter", ErrorReason.UNSUPPORTED_FORMAT)
        }
        if (params.iterations !in 1..MAX_V2_KDF_ITERATIONS) {
            throw Aegis2Failure("Invalid KDF iterations parameter", ErrorReason.UNSUPPORTED_FORMAT)
        }
        if (params.parallelism !in 1..MAX_V2_KDF_PARALLELISM) {
            throw Aegis2Failure("Invalid KDF parallelism parameter", ErrorReason.UNSUPPORTED_FORMAT)
        }
    }

    // ============================================================
    // Encrypt Pipeline (JSON → GZIP → Chunked AEAD)
    // ============================================================

    private fun encryptJsonV2ToStreamBlocking(
        jsonData: String,
        passwordChars: CharArray,
        outputStream: OutputStream,
        cipherType: CipherType,
        progress: Aegis2Progress?,
        checkCancellation: () -> Unit
    ) {
        val payloadFile = createAegisTempFile("aegis2-json-", ".gz")
        try {
            progress?.onPhase(Phase.COMPRESS)
            FileOutputStream(payloadFile).use { fileOutput ->
                OutputStreamWriter(GZIPOutputStream(fileOutput, STREAM_BUFFER_SIZE), StandardCharsets.UTF_8).use { writer ->
                    var offset = 0
                    while (offset < jsonData.length) {
                        checkCancellation()
                        val end = minOf(offset + 8192, jsonData.length)
                        writer.write(jsonData, offset, end - offset)
                        offset = end
                    }
                }
            }
            encryptPayloadFileV2ToStreamBlocking(
                payloadFile = payloadFile,
                passwordChars = passwordChars,
                outputStream = outputStream,
                cipherType = cipherType,
                flags = FLAG_GZIP_PAYLOAD,
                metadata = """{"compression":"gzip","content":"json"}""".toByteArray(StandardCharsets.UTF_8),
                progress = progress,
                checkCancellation = checkCancellation
            )
        } finally {
            deleteTempFile(payloadFile)
        }
    }

    private fun encryptPayloadFileV2ToStreamBlocking(
        payloadFile: File,
        passwordChars: CharArray,
        outputStream: OutputStream,
        cipherType: CipherType,
        flags: Int,
        metadata: ByteArray?,
        progress: Aegis2Progress?,
        checkCancellation: () -> Unit
    ) {
        if (payloadFile.length() > MAX_V2_PAYLOAD_BYTES) {
            throw Aegis2Failure("Aegis payload is too large", ErrorReason.UNSUPPORTED_FORMAT)
        }
        var kekMaterial: ByteArray? = null
        var commitKey: ByteArray? = null
        var cekMaterial: ByteArray? = null
        try {
            val kdfParams = selectKdfParams()
            val payloadSize = payloadFile.length()
            val totalChunks = calculateTotalChunks(payloadSize, DEFAULT_CHUNK_SIZE)
            val salt = randomBytes(SALT_SIZE_BYTES)
            val commitSalt = randomBytes(SALT_SIZE_BYTES)
            val headerNonce = randomBytes(nonceSizeFor(cipherType))
            cekMaterial = randomBytes(KEY_SIZE_BYTES)

            progress?.onPhase(Phase.KDF)
            checkCancellation()
            kekMaterial = deriveArgon2idKey(passwordChars, salt, kdfParams.memoryKb, kdfParams.iterations, kdfParams.parallelism)
            checkCancellation()
            commitKey = deriveArgon2idKey(
                passwordChars, commitSalt,
                (kdfParams.memoryKb / 2).coerceAtLeast(MIN_V2_KDF_MEMORY_KB),
                kdfParams.iterations, kdfParams.parallelism
            )

            val wrapEngine = createCipherEngine(cipherType, kekMaterial)
            val wrappedCek = wrapEngine.encrypt(headerNonce, cekMaterial, ByteArray(0))
            val commitment = computeKeyCommitment(commitKey, V2_FORMAT_VERSION, headerNonce, wrappedCek)
            val header = V2Header(
                cipherType = cipherType,
                salt = salt,
                commitSalt = commitSalt,
                kdfParams = kdfParams,
                headerNonce = headerNonce,
                wrappedCek = wrappedCek,
                keyCommitment = commitment,
                chunkSize = DEFAULT_CHUNK_SIZE,
                totalChunks = totalChunks,
                payloadSize = payloadSize,
                flags = flags,
                metadata = metadata
            )

            val dos = DataOutputStream(BufferedOutputStream(outputStream, STREAM_BUFFER_SIZE))
            writeV2Header(dos, header)
            progress?.onPhase(Phase.ENCRYPT_CHUNKS)
            writeEncryptedV2Chunks(payloadFile, dos, cekMaterial, header, progress, checkCancellation)
            dos.flush()
        } finally {
            kekMaterial?.fill(0)
            commitKey?.fill(0)
            cekMaterial?.fill(0)
        }
    }

    // ============================================================
    // Decrypt Pipeline
    // ============================================================

    private fun decryptJsonV2FromStreamBlocking(
        inputStream: InputStream,
        passwordChars: CharArray,
        progress: Aegis2Progress? = null,
        checkCancellation: () -> Unit
    ): String {
        val payloadFile = createAegisTempFile("aegis2-payload-", ".bin")
        try {
            FileOutputStream(payloadFile).use { output ->
                val header = decryptPayloadV2ToStreamBlocking(inputStream, passwordChars, output, progress, checkCancellation)
                if (header.flags and FLAG_GZIP_PAYLOAD == 0) {
                    if (payloadFile.length() > MAX_DECRYPTED_JSON_BYTES) {
                        throw SecurityException("Decrypted Aegis payload is too large")
                    }
                    return payloadFile.readText(StandardCharsets.UTF_8)
                }
            }

            progress?.onPhase(Phase.DECOMPRESS)
            FileInputStream(payloadFile).use { compressedInput ->
                GZIPInputStream(compressedInput, STREAM_BUFFER_SIZE).use { gzip ->
                    val output = LimitedByteArrayOutputStream(DEFAULT_CHUNK_SIZE, MAX_DECRYPTED_JSON_BYTES)
                    gzip.copyTo(output, STREAM_BUFFER_SIZE)
                    checkCancellation()
                    return output.toString(StandardCharsets.UTF_8.name())
                }
            }
        } finally {
            deleteTempFile(payloadFile)
        }
    }

    private fun decryptPayloadV2ToStreamBlocking(
        inputStream: InputStream,
        passwordChars: CharArray,
        outputStream: OutputStream,
        progress: Aegis2Progress?,
        checkCancellation: () -> Unit
    ): V2Header {
        var cekMaterial: ByteArray? = null
        var dis: DataInputStream? = null
        try {
            val bufferedInput = if (inputStream is BufferedInputStream) {
                inputStream
            } else {
                BufferedInputStream(inputStream, STREAM_BUFFER_SIZE)
            }
            dis = DataInputStream(bufferedInput)
            val header = readV2Header(dis)
            cekMaterial = unwrapAndVerifyCek(header, passwordChars, checkCancellation)
            progress?.onPhase(Phase.DECRYPT_CHUNKS)
            readEncryptedV2Chunks(dis, outputStream, cekMaterial, header, progress, checkCancellation)
            outputStream.flush()
            return header
        } finally {
            cekMaterial?.fill(0)
            runCatching { dis?.close() }
        }
    }

    // ============================================================
    // Chunked AEAD with EOS MAC
    // ============================================================

    private fun writeEncryptedV2Chunks(
        payloadFile: File,
        dos: DataOutputStream,
        cekMaterial: ByteArray,
        header: V2Header,
        progress: Aegis2Progress?,
        checkCancellation: () -> Unit
    ) {
        val engine = createCipherEngine(header.cipherType, cekMaterial)
        val eosMac = newEosMac(cekMaterial)
        val buffer = ByteArray(header.chunkSize)
        var chunkIndex = 0L
        var processed = 0L
        FileInputStream(payloadFile).use { input ->
            while (chunkIndex < header.totalChunks) {
                checkCancellation()
                val expectedPlaintextSize = expectedChunkPlaintextSize(header, chunkIndex)
                input.readFullyOrThrow(buffer, expectedPlaintextSize)
                val aad = chunkAad(chunkIndex, header.totalChunks, expectedPlaintextSize)
                val nonce = randomBytes(engine.nonceSize)
                val plaintext = buffer.copyOf(expectedPlaintextSize)
                val encrypted = try {
                    engine.encrypt(nonce, plaintext, aad)
                } finally {
                    plaintext.fill(0)
                }
                if (encrypted.size != expectedPlaintextSize + engine.tagSize) {
                    throw Aegis2Failure("Invalid encrypted chunk size", ErrorReason.INTERNAL_ERROR)
                }
                dos.write(nonce)
                dos.write(encrypted)
                eosMac.update(encrypted, encrypted.size - engine.tagSize, engine.tagSize)
                encrypted.fill(0)
                buffer.fill(0, 0, expectedPlaintextSize)
                processed += expectedPlaintextSize.toLong()
                progress?.onProgress(processed, header.payloadSize)
                chunkIndex++
            }
            if (input.read() != -1) throw Aegis2Failure("Payload size changed during encryption", ErrorReason.IO_ERROR)
        }
        progress?.onPhase(Phase.MAC)
        dos.write(eosMac.doFinal())
    }

    private fun readEncryptedV2Chunks(
        dis: DataInputStream,
        outputStream: OutputStream,
        cekMaterial: ByteArray,
        header: V2Header,
        progress: Aegis2Progress?,
        checkCancellation: () -> Unit
    ) {
        val engine = createCipherEngine(header.cipherType, cekMaterial)
        val eosMac = newEosMac(cekMaterial)
        var processed = 0L
        for (chunkIndex in 0 until header.totalChunks) {
            checkCancellation()
            val plaintextSize = expectedChunkPlaintextSize(header, chunkIndex)
            val encryptedSize = plaintextSize + engine.tagSize
            val nonce = ByteArray(engine.nonceSize)
            val encrypted = ByteArray(encryptedSize)
            dis.readFully(nonce)
            dis.readFully(encrypted)
            eosMac.update(encrypted, encrypted.size - engine.tagSize, engine.tagSize)
            val plaintext = engine.decrypt(nonce, encrypted, chunkAad(chunkIndex, header.totalChunks, plaintextSize))
            if (plaintext.size != plaintextSize) {
                throw Aegis2Failure("Chunk plaintext size mismatch", ErrorReason.FILE_CORRUPTED)
            }
            outputStream.write(plaintext)
            processed += plaintext.size.toLong()
            progress?.onProgress(processed, header.payloadSize)
            nonce.fill(0)
            encrypted.fill(0)
            plaintext.fill(0)
        }
        progress?.onPhase(Phase.MAC)
        val expected = eosMac.doFinal()
        val actual = ByteArray(EOS_MAC_SIZE_BYTES)
        dis.readFully(actual)
        if (!MessageDigest.isEqual(expected, actual)) {
            throw Aegis2Failure("Aegis2 end-of-stream MAC mismatch", ErrorReason.FILE_CORRUPTED)
        }
        expected.fill(0)
        actual.fill(0)
        if (dis.read() != -1) {
            throw Aegis2Failure("Trailing data after Aegis2 payload", ErrorReason.FILE_CORRUPTED)
        }
    }

    // ============================================================
    // Key Unwrapping & Verification
    // ============================================================

    private fun unwrapAndVerifyCek(
        header: V2Header,
        passwordChars: CharArray,
        checkCancellation: () -> Unit
    ): ByteArray {
        validateKdfParams(header.kdfParams)
        var kekMaterial: ByteArray? = null
        var commitKey: ByteArray? = null
        try {
            checkCancellation()
            kekMaterial = deriveArgon2idKey(
                passwordChars, header.salt,
                header.kdfParams.memoryKb, header.kdfParams.iterations, header.kdfParams.parallelism
            )
            val cek = createCipherEngine(header.cipherType, kekMaterial)
                .decrypt(header.headerNonce, header.wrappedCek, ByteArray(0))
            if (cek.size != KEY_SIZE_BYTES) {
                cek.fill(0)
                throw Aegis2Failure("Invalid content key size", ErrorReason.FILE_CORRUPTED)
            }
            checkCancellation()
            commitKey = deriveArgon2idKey(
                passwordChars, header.commitSalt,
                (header.kdfParams.memoryKb / 2).coerceAtLeast(MIN_V2_KDF_MEMORY_KB),
                header.kdfParams.iterations, header.kdfParams.parallelism
            )
            val expectedCommitment = computeKeyCommitment(commitKey, V2_FORMAT_VERSION, header.headerNonce, header.wrappedCek)
            if (!MessageDigest.isEqual(expectedCommitment, header.keyCommitment)) {
                cek.fill(0)
                throw Aegis2Failure("Aegis2 key commitment mismatch", ErrorReason.FILE_TAMPERED)
            }
            expectedCommitment.fill(0)
            return cek
        } finally {
            kekMaterial?.fill(0)
            commitKey?.fill(0)
        }
    }

    private fun buildV2HeaderForExistingCek(
        oldHeader: V2Header,
        cekMaterial: ByteArray,
        newPasswordChars: CharArray,
        checkCancellation: () -> Unit
    ): V2Header {
        var newKek: ByteArray? = null
        var newCommitKey: ByteArray? = null
        try {
            val newParams = selectKdfParams()
            val newSalt = randomBytes(SALT_SIZE_BYTES)
            val newCommitSalt = randomBytes(SALT_SIZE_BYTES)
            val newHeaderNonce = randomBytes(nonceSizeFor(oldHeader.cipherType))
            checkCancellation()
            newKek = deriveArgon2idKey(newPasswordChars, newSalt, newParams.memoryKb, newParams.iterations, newParams.parallelism)
            newCommitKey = deriveArgon2idKey(
                newPasswordChars, newCommitSalt,
                (newParams.memoryKb / 2).coerceAtLeast(MIN_V2_KDF_MEMORY_KB),
                newParams.iterations, newParams.parallelism
            )
            val wrappedCek = createCipherEngine(oldHeader.cipherType, newKek).encrypt(newHeaderNonce, cekMaterial, ByteArray(0))
            val commitment = computeKeyCommitment(newCommitKey, V2_FORMAT_VERSION, newHeaderNonce, wrappedCek)
            return oldHeader.copy(
                salt = newSalt,
                commitSalt = newCommitSalt,
                kdfParams = newParams,
                headerNonce = newHeaderNonce,
                wrappedCek = wrappedCek,
                keyCommitment = commitment
            )
        } finally {
            newKek?.fill(0)
            newCommitKey?.fill(0)
        }
    }

    // ============================================================
    // TLV Header Read/Write
    // ============================================================

    private fun writeV2Header(dos: DataOutputStream, header: V2Header) {
        val headerBytes = ByteArrayOutputStream(512).use { raw ->
            DataOutputStream(raw).use { tlv ->
                tlv.writeTlv(TlvTag.CIPHER_ID, byteArrayOf(cipherIdFor(header.cipherType).toByte()))
                tlv.writeTlv(TlvTag.KDF_SALT, header.salt)
                tlv.writeTlv(TlvTag.KDF_COMMIT_SALT, header.commitSalt)
                tlv.writeTlv(TlvTag.KDF_MEMORY_KB, intBytes(header.kdfParams.memoryKb))
                tlv.writeTlv(TlvTag.KDF_ITERATIONS, intBytes(header.kdfParams.iterations))
                tlv.writeTlv(TlvTag.KDF_PARALLELISM, byteArrayOf(header.kdfParams.parallelism.toByte()))
                tlv.writeTlv(TlvTag.HEADER_NONCE, header.headerNonce)
                tlv.writeTlv(TlvTag.WRAPPED_CEK, header.wrappedCek)
                tlv.writeTlv(TlvTag.KEY_COMMITMENT, header.keyCommitment)
                tlv.writeTlv(TlvTag.CHUNK_SIZE, intBytes(header.chunkSize))
                tlv.writeTlv(TlvTag.TOTAL_CHUNKS, longBytes(header.totalChunks))
                header.metadata?.let { tlv.writeTlv(TlvTag.FILE_METADATA, it) }
                tlv.writeTlv(TlvTag.PAYLOAD_SIZE, longBytes(header.payloadSize))
                tlv.writeTlv(TlvTag.FLAGS, byteArrayOf(header.flags.toByte()))
                tlv.writeTlv(TlvTag.HEADER_END, ByteArray(0))
                tlv.flush()
            }
            raw.toByteArray()
        }
        if (headerBytes.size > MAX_V2_HEADER_BYTES) {
            throw Aegis2Failure("Aegis2 header is too large", ErrorReason.INTERNAL_ERROR)
        }
        dos.write(MAGIC_BYTES)
        dos.writeByte(V2_FORMAT_VERSION.toInt())
        dos.writeInt(headerBytes.size)
        dos.write(headerBytes)
    }

    private fun readV2Header(dis: DataInputStream): V2Header {
        val magic = ByteArray(MAGIC_BYTES.size)
        dis.readFully(magic)
        if (!magic.contentEquals(MAGIC_BYTES)) {
            throw Aegis2Failure("Not a valid .aegis file", ErrorReason.UNSUPPORTED_FORMAT)
        }
        val version = dis.readByte()
        if (version != V2_FORMAT_VERSION) {
            throw Aegis2Failure("Unsupported .aegis version", ErrorReason.UNSUPPORTED_FORMAT)
        }
        val headerLength = dis.readInt()
        if (headerLength <= 0 || headerLength > MAX_V2_HEADER_BYTES) {
            throw Aegis2Failure("Invalid Aegis2 header length", ErrorReason.UNSUPPORTED_FORMAT)
        }
        val headerBytes = ByteArray(headerLength)
        dis.readFully(headerBytes)
        val tlvs = LinkedHashMap<Int, ByteArray>()
        var offset = 0
        var sawEnd = false
        while (offset < headerBytes.size) {
            if (offset + 5 > headerBytes.size) {
                throw Aegis2Failure("Truncated Aegis2 TLV header", ErrorReason.FILE_CORRUPTED)
            }
            val tag = headerBytes[offset].toInt() and 0xff
            val length = ByteBuffer.wrap(headerBytes, offset + 1, Int.SIZE_BYTES).int
            offset += 5
            if (length < 0 || offset + length > headerBytes.size) {
                throw Aegis2Failure("Invalid Aegis2 TLV length", ErrorReason.FILE_CORRUPTED)
            }
            if (tag == 0xFD || tag == 0xFE) {
                throw Aegis2Failure("Unsupported vendor-specific Aegis2 header", ErrorReason.UNSUPPORTED_FORMAT)
            }
            val value = headerBytes.copyOfRange(offset, offset + length)
            offset += length
            if (tag == TlvTag.HEADER_END) {
                if (length != 0) throw Aegis2Failure("Invalid Aegis2 header end", ErrorReason.FILE_CORRUPTED)
                sawEnd = true
                break
            }
            if (tag !in 0xFD..0xFE) tlvs[tag] = value
        }
        if (!sawEnd) throw Aegis2Failure("Aegis2 header end not found", ErrorReason.FILE_CORRUPTED)
        if (offset != headerBytes.size) {
            throw Aegis2Failure("Unexpected data after Aegis2 header end", ErrorReason.FILE_CORRUPTED)
        }

        val cipher = cipherTypeFromId(requiredTlv(tlvs, TlvTag.CIPHER_ID).singleUnsigned())
            ?: throw Aegis2Failure("Unsupported Aegis2 cipher", ErrorReason.UNSUPPORTED_FORMAT)
        val kdfParams = KdfParams(
            memoryKb = requiredTlv(tlvs, TlvTag.KDF_MEMORY_KB).toInt32(),
            iterations = requiredTlv(tlvs, TlvTag.KDF_ITERATIONS).toInt32(),
            parallelism = requiredTlv(tlvs, TlvTag.KDF_PARALLELISM).singleUnsigned()
        )
        validateKdfParams(kdfParams)
        val headerNonce = requiredTlv(tlvs, TlvTag.HEADER_NONCE)
        if (headerNonce.size != nonceSizeFor(cipher)) {
            throw Aegis2Failure("Invalid Aegis2 header nonce", ErrorReason.FILE_CORRUPTED)
        }
        val chunkSize = requiredTlv(tlvs, TlvTag.CHUNK_SIZE).toInt32()
        if (chunkSize !in 1024..1_048_576) {
            throw Aegis2Failure("Invalid Aegis2 chunk size", ErrorReason.UNSUPPORTED_FORMAT)
        }
        val totalChunks = requiredTlv(tlvs, TlvTag.TOTAL_CHUNKS).toInt64()
        val payloadSize = requiredTlv(tlvs, TlvTag.PAYLOAD_SIZE).toInt64()
        if (totalChunks < 0 || payloadSize < 0 || payloadSize > MAX_V2_PAYLOAD_BYTES) {
            throw Aegis2Failure("Invalid Aegis2 payload size", ErrorReason.UNSUPPORTED_FORMAT)
        }
        if (calculateTotalChunks(payloadSize, chunkSize) != totalChunks) {
            throw Aegis2Failure("Aegis2 chunk count does not match payload size", ErrorReason.FILE_CORRUPTED)
        }

        val salt = requiredTlv(tlvs, TlvTag.KDF_SALT)
        val commitSalt = requiredTlv(tlvs, TlvTag.KDF_COMMIT_SALT)
        val commitment = requiredTlv(tlvs, TlvTag.KEY_COMMITMENT)
        if (salt.size != SALT_SIZE_BYTES || commitSalt.size != SALT_SIZE_BYTES || commitment.size != EOS_MAC_SIZE_BYTES) {
            throw Aegis2Failure("Invalid Aegis2 cryptographic header", ErrorReason.FILE_CORRUPTED)
        }
        val wrappedCek = requiredTlv(tlvs, TlvTag.WRAPPED_CEK)
        if (wrappedCek.size != KEY_SIZE_BYTES + GCM_TAG_LENGTH_BYTES) {
            throw Aegis2Failure("Invalid Aegis2 wrapped key", ErrorReason.FILE_CORRUPTED)
        }
        return V2Header(
            cipherType = cipher,
            salt = salt,
            commitSalt = commitSalt,
            kdfParams = kdfParams,
            headerNonce = headerNonce,
            wrappedCek = wrappedCek,
            keyCommitment = commitment,
            chunkSize = chunkSize,
            totalChunks = totalChunks,
            payloadSize = payloadSize,
            flags = tlvs[TlvTag.FLAGS]?.singleUnsigned() ?: 0,
            metadata = tlvs[TlvTag.FILE_METADATA]
        )
    }

    private fun requiredTlv(tlvs: Map<Int, ByteArray>, tag: Int): ByteArray {
        return tlvs[tag] ?: throw Aegis2Failure("Missing required Aegis2 TLV tag $tag", ErrorReason.FILE_CORRUPTED)
    }

    private fun DataOutputStream.writeTlv(tag: Int, value: ByteArray) {
        writeByte(tag)
        writeInt(value.size)
        write(value)
    }

    // ============================================================
    // Key Commitment & EOS MAC
    // ============================================================

    private fun computeKeyCommitment(
        commitKey: ByteArray,
        formatVersion: Byte,
        headerNonce: ByteArray,
        wrappedCek: ByteArray
    ): ByteArray {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(commitKey, HMAC_ALGORITHM))
        mac.update(KEY_COMMITMENT_LABEL)
        mac.update(formatVersion)
        mac.update(shortBytes(headerNonce.size))
        mac.update(headerNonce)
        mac.update(shortBytes(wrappedCek.size))
        mac.update(wrappedCek)
        return mac.doFinal()
    }

    private fun newEosMac(cekMaterial: ByteArray): Mac {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(cekMaterial, HMAC_ALGORITHM))
        mac.update(EOS_MAC_LABEL)
        return mac
    }

    private fun chunkAad(chunkIndex: Long, totalChunks: Long, plaintextSize: Int): ByteArray {
        return ByteBuffer.allocate(20)
            .putLong(chunkIndex)
            .putLong(totalChunks)
            .putInt(plaintextSize)
            .array()
    }

    private fun calculateTotalChunks(payloadSize: Long, chunkSize: Int): Long {
        if (payloadSize == 0L) return 0L
        return ((payloadSize - 1L) / chunkSize.toLong()) + 1L
    }

    private fun expectedChunkPlaintextSize(header: V2Header, chunkIndex: Long): Int {
        val processedBefore = chunkIndex * header.chunkSize.toLong()
        val remaining = header.payloadSize - processedBefore
        if (remaining <= 0L) throw Aegis2Failure("Invalid Aegis2 chunk index", ErrorReason.FILE_CORRUPTED)
        return minOf(header.chunkSize.toLong(), remaining).toInt()
    }

    // ============================================================
    // Cipher Helpers
    // ============================================================

    private fun nonceSizeFor(cipherType: CipherType): Int = when (cipherType) {
        CipherType.XChaCha20Poly1305 -> XCHACHA_NONCE_SIZE_BYTES
        CipherType.AES256GCM -> IV_SIZE_BYTES
    }

    private fun cipherIdFor(cipherType: CipherType): Int = when (cipherType) {
        CipherType.XChaCha20Poly1305 -> CIPHER_ID_XCHACHA20_POLY1305
        CipherType.AES256GCM -> CIPHER_ID_AES256_GCM
    }

    private fun cipherTypeFromId(cipherId: Int): CipherType? = when (cipherId) {
        CIPHER_ID_XCHACHA20_POLY1305 -> CipherType.XChaCha20Poly1305
        CIPHER_ID_AES256_GCM -> CipherType.AES256GCM
        else -> null
    }

    private fun intBytes(value: Int): ByteArray = ByteBuffer.allocate(Int.SIZE_BYTES).putInt(value).array()
    private fun longBytes(value: Long): ByteArray = ByteBuffer.allocate(Long.SIZE_BYTES).putLong(value).array()
    private fun shortBytes(value: Int): ByteArray = ByteBuffer.allocate(Short.SIZE_BYTES).putShort(value.toShort()).array()

    private fun ByteArray.toInt32(): Int {
        if (size != Int.SIZE_BYTES) throw Aegis2Failure("Invalid Aegis2 uint32", ErrorReason.FILE_CORRUPTED)
        return ByteBuffer.wrap(this).int
    }

    private fun ByteArray.toInt64(): Long {
        if (size != Long.SIZE_BYTES) throw Aegis2Failure("Invalid Aegis2 uint64", ErrorReason.FILE_CORRUPTED)
        return ByteBuffer.wrap(this).long
    }

    private fun ByteArray.singleUnsigned(): Int {
        if (size != 1) throw Aegis2Failure("Invalid Aegis2 uint8", ErrorReason.FILE_CORRUPTED)
        return this[0].toInt() and 0xff
    }

    private fun InputStream.readFullyOrThrow(buffer: ByteArray, length: Int) {
        var offset = 0
        while (offset < length) {
            val read = read(buffer, offset, length - offset)
            if (read == -1) throw Aegis2Failure("Unexpected end of Aegis2 payload", ErrorReason.FILE_CORRUPTED)
            offset += read
        }
    }

    private fun copyWithProgress(
        input: InputStream,
        output: OutputStream,
        totalBytes: Long,
        progress: Aegis2Progress?,
        checkCancellation: () -> Unit
    ) {
        val buffer = ByteArray(STREAM_BUFFER_SIZE)
        var processed = 0L
        while (true) {
            checkCancellation()
            val read = input.read(buffer)
            if (read == -1) break
            output.write(buffer, 0, read)
            processed += read.toLong()
            progress?.onProgress(processed, totalBytes)
        }
        buffer.fill(0)
    }

    // ============================================================
    // Legacy v1 Binary Decrypt (backward compat)
    // ============================================================

    private fun wrapKey(kek: SecretKeySpec, iv: ByteArray, cekPlaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.ENCRYPT_MODE, kek, gcmSpec)
        return cipher.doFinal(cekPlaintext)
    }

    private fun unwrapKey(kek: SecretKeySpec, iv: ByteArray, encryptedCek: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
        val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.DECRYPT_MODE, kek, gcmSpec)
        return cipher.doFinal(encryptedCek)
    }

    private fun incrementIv(iv: ByteArray): ByteArray {
        val newIv = iv.copyOf()
        for (i in newIv.size - 1 downTo 0) {
            newIv[i]++
            if (newIv[i] != 0.toByte()) break
        }
        return newIv
    }

    private fun readDecryptedCompressedPayload(
        dis: DataInputStream,
        cek: SecretKeySpec,
        payloadIv: ByteArray,
        chunkSize: Int,
        checkCancellation: () -> Unit
    ): String {
        val decryptedIn = ChunkDecryptingInputStream(dis, cek, payloadIv, chunkSize, checkCancellation)
        GZIPInputStream(decryptedIn, STREAM_BUFFER_SIZE).use { gzip ->
            val output = LimitedByteArrayOutputStream(DEFAULT_CHUNK_SIZE, MAX_DECRYPTED_JSON_BYTES)
            gzip.copyTo(output, STREAM_BUFFER_SIZE)
            checkCancellation()
            return output.toString(StandardCharsets.UTF_8.name())
        }
    }

    private class ChunkEncryptingOutputStream(
        private val dos: DataOutputStream,
        private val cek: SecretKeySpec,
        baseIv: ByteArray,
        private val chunkSize: Int,
        private val checkCancellation: () -> Unit
    ) : OutputStream() {
        private val buffer = ByteArray(chunkSize)
        private var bufferSize = 0
        private var currentIv = baseIv.copyOf()
        private var closed = false

        override fun write(b: Int) {
            buffer[bufferSize++] = b.toByte()
            if (bufferSize == buffer.size) flushChunk()
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            var offset = off
            var remaining = len
            while (remaining > 0) {
                val copied = minOf(remaining, buffer.size - bufferSize)
                System.arraycopy(b, offset, buffer, bufferSize, copied)
                bufferSize += copied
                offset += copied
                remaining -= copied
                if (bufferSize == buffer.size) flushChunk()
            }
        }

        override fun flush() { dos.flush() }

        override fun close() {
            if (closed) return
            try {
                flushChunk()
                dos.writeInt(0)
                dos.flush()
            } finally {
                buffer.fill(0)
                closed = true
            }
        }

        private fun flushChunk() {
            if (bufferSize == 0) return
            checkCancellation()
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, currentIv)
            val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
            cipher.init(Cipher.ENCRYPT_MODE, cek, gcmSpec)
            val encrypted = cipher.doFinal(buffer, 0, bufferSize)
            dos.writeInt(encrypted.size)
            dos.write(encrypted)
            encrypted.fill(0)
            currentIv = incrementIv(currentIv)
            buffer.fill(0, 0, bufferSize)
            bufferSize = 0
        }
    }

    private class ChunkDecryptingInputStream(
        private val dis: DataInputStream,
        private val cek: SecretKeySpec,
        baseIv: ByteArray,
        private val chunkSize: Int,
        private val checkCancellation: () -> Unit
    ) : FilterInputStream(dis) {
        private val maxEncryptedChunkSize = chunkSize + GCM_TAG_LENGTH_BYTES
        private var currentIv = baseIv.copyOf()
        private var currentChunk = ByteArray(0)
        private var currentOffset = 0
        private var endReached = false

        override fun read(): Int {
            if (!ensureChunk()) return -1
            return currentChunk[currentOffset++].toInt() and 0xff
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (!ensureChunk()) return -1
            val copied = minOf(len, currentChunk.size - currentOffset)
            System.arraycopy(currentChunk, currentOffset, b, off, copied)
            currentOffset += copied
            return copied
        }

        override fun close() { currentChunk.fill(0) }

        private fun ensureChunk(): Boolean {
            if (currentOffset < currentChunk.size) return true
            currentChunk.fill(0)
            if (endReached) return false

            checkCancellation()
            val encryptedSize = dis.readInt()
            if (encryptedSize == 0) {
                endReached = true
                return false
            }
            if (encryptedSize < GCM_TAG_LENGTH_BYTES || encryptedSize > maxEncryptedChunkSize) {
                throw SecurityException("Invalid chunk size: $encryptedSize")
            }

            val encryptedChunk = ByteArray(encryptedSize)
            dis.readFully(encryptedChunk)
            val gcmSpec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, currentIv)
            val cipher = Cipher.getInstance(CIPHER_ALGORITHM)
            cipher.init(Cipher.DECRYPT_MODE, cek, gcmSpec)
            currentChunk = cipher.doFinal(encryptedChunk)
            encryptedChunk.fill(0)
            currentOffset = 0
            currentIv = incrementIv(currentIv)
            return currentChunk.isNotEmpty() || ensureChunk()
        }
    }

    private class LimitedByteArrayOutputStream(
        initialSize: Int,
        private val maxSize: Int
    ) : ByteArrayOutputStream(initialSize) {
        override fun write(b: ByteArray, off: Int, len: Int) {
            require(count + len <= maxSize) { "Aegis payload is too large" }
            super.write(b, off, len)
        }
        override fun write(b: Int) {
            require(count + 1 <= maxSize) { "Aegis payload is too large" }
            super.write(b)
        }
    }

    // ============================================================
    // Utilities
    // ============================================================

    private fun randomBytes(size: Int): ByteArray {
        val bytes = ByteArray(size)
        secureRandom.get()!!.nextBytes(bytes)
        return bytes
    }

    private fun createAegisTempFile(prefix: String, suffix: String): File {
        cleanupStaleAegisTempFiles()
        return File.createTempFile(prefix, suffix)
    }

    private fun cleanupStaleAegisTempFiles() {
        val tempDir = File(System.getProperty("java.io.tmpdir") ?: return)
        val now = System.currentTimeMillis()
        val files = tempDir.listFiles { file ->
            file.isFile &&
                    (file.name.startsWith("aegis2-json-") || file.name.startsWith("aegis2-payload-")) &&
                    now - file.lastModified() > TEMP_FILE_MAX_AGE_MS
        } ?: return
        for (file in files) deleteTempFile(file)
    }

    private fun deleteTempFile(file: File) {
        if (file.exists() && !file.delete()) {
            println("$AEGIS2_LOG_TAG: Unable to delete temporary file: ${file.name}")
        }
    }

    private fun encodeBase64(data: ByteArray): String = Base64.getEncoder().encodeToString(data)
    private fun decodeBase64(data: String): ByteArray = Base64.getDecoder().decode(data)

    private fun wipePassword(passwordChars: CharArray) {
        Arrays.fill(passwordChars, '\u0000')
    }

    private suspend fun cancellationChecker(): () -> Unit {
        val context = currentCoroutineContext()
        return {
            context.ensureActive()
            if (Thread.currentThread().isInterrupted) {
                throw CancellationException("Aegis operation interrupted")
            }
        }
    }

    private fun CharArray.toUtf8Bytes(): ByteArray {
        var byteBuffer: ByteBuffer? = null
        return try {
            byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(this))
            val bytes = ByteArray(byteBuffer.remaining())
            byteBuffer.get(bytes)
            bytes
        } finally {
            if (byteBuffer != null && byteBuffer.hasArray()) {
                byteBuffer.array().fill(0)
            }
        }
    }

    private fun String.utf8ByteLimitSafeLength(): Int {
        if (length > MAX_DECRYPTED_JSON_BYTES) {
            return MAX_DECRYPTED_JSON_BYTES + 1
        }
        var bytes = 0
        var index = 0
        while (index < length) {
            val ch = this[index]
            bytes += when {
                ch.code <= 0x7f -> 1
                ch.code <= 0x7ff -> 2
                Character.isHighSurrogate(ch) && index + 1 < length && Character.isLowSurrogate(this[index + 1]) -> {
                    index++
                    4
                }
                Character.isLowSurrogate(ch) -> 0
                Character.isHighSurrogate(ch) -> 4
                else -> 3
            }
            if (bytes > MAX_DECRYPTED_JSON_BYTES) return bytes
            index++
        }
        return bytes
    }

    // ============================================================
    // HChaCha20 (subkey derivation for XChaCha20)
    // ============================================================

    private fun hChaCha20(key: ByteArray, nonce16: ByteArray): ByteArray {
        if (key.size != KEY_SIZE_BYTES || nonce16.size != 16) {
            throw GeneralSecurityException("Invalid HChaCha20 input")
        }
        fun littleEndianToInt(bytes: ByteArray, offset: Int): Int {
            return (bytes[offset].toInt() and 0xff) or
                    ((bytes[offset + 1].toInt() and 0xff) shl 8) or
                    ((bytes[offset + 2].toInt() and 0xff) shl 16) or
                    ((bytes[offset + 3].toInt() and 0xff) shl 24)
        }
        fun intToLittleEndian(value: Int, out: ByteArray, offset: Int) {
            out[offset] = value.toByte()
            out[offset + 1] = (value ushr 8).toByte()
            out[offset + 2] = (value ushr 16).toByte()
            out[offset + 3] = (value ushr 24).toByte()
        }
        fun quarterRound(state: IntArray, a: Int, b: Int, c: Int, d: Int) {
            state[a] += state[b]
            state[d] = Integer.rotateLeft(state[d] xor state[a], 16)
            state[c] += state[d]
            state[b] = Integer.rotateLeft(state[b] xor state[c], 12)
            state[a] += state[b]
            state[d] = Integer.rotateLeft(state[d] xor state[a], 8)
            state[c] += state[d]
            state[b] = Integer.rotateLeft(state[b] xor state[c], 7)
        }

        val state = IntArray(16)
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574
        for (i in 0 until 8) state[4 + i] = littleEndianToInt(key, i * 4)
        for (i in 0 until 4) state[12 + i] = littleEndianToInt(nonce16, i * 4)

        repeat(10) {
            quarterRound(state, 0, 4, 8, 12)
            quarterRound(state, 1, 5, 9, 13)
            quarterRound(state, 2, 6, 10, 14)
            quarterRound(state, 3, 7, 11, 15)
            quarterRound(state, 0, 5, 10, 15)
            quarterRound(state, 1, 6, 11, 12)
            quarterRound(state, 2, 7, 8, 13)
            quarterRound(state, 3, 4, 9, 14)
        }

        val out = ByteArray(KEY_SIZE_BYTES)
        intToLittleEndian(state[0], out, 0)
        intToLittleEndian(state[1], out, 4)
        intToLittleEndian(state[2], out, 8)
        intToLittleEndian(state[3], out, 12)
        intToLittleEndian(state[12], out, 16)
        intToLittleEndian(state[13], out, 20)
        intToLittleEndian(state[14], out, 24)
        intToLittleEndian(state[15], out, 28)
        state.fill(0)
        return out
    }

    // ============================================================
    // Legacy v1 Binary helpers
    // ============================================================

    private fun writeCompressedEncryptedPayload(
        jsonData: String,
        dos: DataOutputStream,
        cek: SecretKeySpec,
        payloadIv: ByteArray,
        chunkSize: Int,
        checkCancellation: () -> Unit
    ) {
        val encryptedOut = ChunkEncryptingOutputStream(dos, cek, payloadIv, chunkSize, checkCancellation)
        OutputStreamWriter(GZIPOutputStream(encryptedOut, STREAM_BUFFER_SIZE), StandardCharsets.UTF_8).use { writer ->
            var offset = 0
            while (offset < jsonData.length) {
                checkCancellation()
                val end = minOf(offset + 8192, jsonData.length)
                writer.write(jsonData, offset, end - offset)
                offset = end
            }
        }
    }
}
