package com.ipc.contract

/**
 * Derivación de claves del protocolo CBC.
 *
 * KDF propia sobre BLAKE3 con separación de dominio. NO es HKDF.
 *
 * Debe producir exactamente los mismos bytes que `KeyDerivation` en Rust y
 * `KeyDerivation` en C++; los vectores en `tests/vectors/crypto.json` lo fijan.
 */
public class KeyDerivation(secret: ByteArray) {

    private val secret: ByteArray = secret.copyOf()

    init {
        require(secret.size == 32) { "el secreto raíz debe tener 32 bytes" }
    }

    /** Clave dedicada a la derivación de nonces (P0.4). */
    public fun deriveNonceKey(contractHash: ByteArray, sessionId: Long): ByteArray =
        SecurityUtils.deriveSubkey(secret, "ipc-cbc2-nonce-key-v1", contractHash, sessionId)

    public fun deriveSessionKey(contractHash: ByteArray, sessionId: Long): ByteArray =
        SecurityUtils.deriveSubkey(secret, "ipc-cbc2-session-v1", contractHash, sessionId)

    public fun deriveAuthKey(sessionKey: ByteArray): ByteArray =
        SecurityUtils.deriveSubkey(secret, "ipc-cbc2-auth-v1", sessionKey, 0L)

    public fun deriveEncryptionKey(sessionKey: ByteArray): ByteArray =
        SecurityUtils.deriveSubkey(secret, "ipc-cbc2-encrypt-v1", sessionKey, 0L)

    /** Sobrescribir el secreto raíz. */
    public fun destroy() {
        SecurityUtils.wipe(secret)
    }
}

/**
 * Política de seguridad de un contrato.
 *
 * Los valores son los del encoding canónico CBC (11 bytes, little-endian):
 *
 * | offset | campo                     |
 * |--------|---------------------------|
 * | 0      | security_level            |
 * | 1      | aead_algorithm            |
 * | 2      | hash_algorithm            |
 * | 3      | authentication_required   |
 * | 4      | confidentiality_required  |
 * | 5      | anti_replay               |
 * | 6-9    | replay_window_size (u32)  |
 * | 10     | signature_policy          |
 */
public data class SecurityPolicy(
    val level: SecurityLevel = SecurityLevel.AUTHENTICATED,
    val aeadAlgorithm: AeadAlgorithm = AeadAlgorithm.CHACHA20_POLY1305,
    val hashAlgorithm: HashAlgorithm = HashAlgorithm.BLAKE3,
    val authenticationRequired: Boolean = true,
    val confidentialityRequired: Boolean = true,
    val antiReplay: Boolean = true,
    val replayWindowSize: Int = 1024,
    val signaturePolicy: SignaturePolicy = SignaturePolicy.REQUIRED
) {
    /** Serializar al encoding canónico. */
    public fun toByteArray(): ByteArray {
        val out = ByteArray(11)
        out[0] = level.value.toByte()
        out[1] = aeadAlgorithm.value.toByte()
        out[2] = hashAlgorithm.value.toByte()
        out[3] = if (authenticationRequired) 1 else 0
        out[4] = if (confidentialityRequired) 1 else 0
        out[5] = if (antiReplay) 1 else 0
        out[6] = (replayWindowSize ushr 24).toByte()
        out[7] = (replayWindowSize ushr 16).toByte()
        out[8] = (replayWindowSize ushr 8).toByte()
        out[9] = replayWindowSize.toByte()
        out[10] = signaturePolicy.value.toByte()
        return out
    }

    public companion object {
        /** Parsear desde el encoding canónico, fail-closed. */
        @JvmStatic
        public fun fromByteArray(data: ByteArray): SecurityPolicy {
            require(data.size >= 11) { "sección de seguridad truncada" }
            val window = ((data[6].toInt() and 0xFF) shl 24) or
                ((data[7].toInt() and 0xFF) shl 16) or
                ((data[8].toInt() and 0xFF) shl 8) or
                (data[9].toInt() and 0xFF)
            require(window != 0) { "replay_window_size no puede ser 0" }
            for (i in intArrayOf(3, 4, 5)) {
                require(data[i] <= 1) { "flag booleano inválido en la política de seguridad" }
            }
            return SecurityPolicy(
                level = SecurityLevel.fromValue(data[0].toInt() and 0xFF),
                aeadAlgorithm = AeadAlgorithm.fromValue(data[1].toInt() and 0xFF),
                hashAlgorithm = HashAlgorithm.fromValue(data[2].toInt() and 0xFF),
                authenticationRequired = data[3] == 1.toByte(),
                confidentialityRequired = data[4] == 1.toByte(),
                antiReplay = data[5] == 1.toByte(),
                replayWindowSize = window,
                signaturePolicy = SignaturePolicy.fromValue(data[10].toInt() and 0xFF)
            )
        }
    }
}

public enum class SecurityLevel(val value: Int) {
    INTEGRITY_ONLY(0x01),
    AUTHENTICATED(0x02),
    ENCRYPTED(0x03);

    public companion object {
        @JvmStatic
        public fun fromValue(v: Int): SecurityLevel = when (v) {
            0x01 -> INTEGRITY_ONLY
            0x02 -> AUTHENTICATED
            0x03 -> ENCRYPTED
            else -> throw IllegalArgumentException("nivel de seguridad desconocido: $v")
        }
    }
}

public enum class AeadAlgorithm(val value: Int) {
    CHACHA20_POLY1305(0x01),
    AES_256_GCM(0x02);

    public companion object {
        @JvmStatic
        public fun fromValue(v: Int): AeadAlgorithm = when (v) {
            0x01 -> CHACHA20_POLY1305
            0x02 -> AES_256_GCM
            else -> throw IllegalArgumentException("AEAD desconocido: $v")
        }
    }
}

public enum class HashAlgorithm(val value: Int) {
    /** Sólo compatibilidad legacy. No puede ser la identidad de un contrato. */
    SHA256(0x01),
    BLAKE3(0x02);

    public companion object {
        @JvmStatic
        public fun fromValue(v: Int): HashAlgorithm = when (v) {
            0x01 -> SHA256
            0x02 -> BLAKE3
            else -> throw IllegalArgumentException("hash desconocido: $v")
        }
    }
}

public enum class SignaturePolicy(val value: Int) {
    NONE(0x00),
    OPTIONAL(0x01),
    REQUIRED(0x02);

    public val requiresSignature: Boolean
        get() = this == REQUIRED

    public companion object {
        @JvmStatic
        public fun fromValue(v: Int): SignaturePolicy = when (v) {
            0x00 -> NONE
            0x01 -> OPTIONAL
            0x02 -> REQUIRED
            else -> throw IllegalArgumentException("política de firma desconocida: $v")
        }
    }
}
