package com.ipc.contract

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.EdECPoint
import java.security.spec.NamedParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Utilidades de seguridad del protocolo CBC.
 *
 * Correcciones aplicadas respecto a v2.1 (ver `docs/SECURITY.md`):
 *
 *  - **P0.1** El hash de identidad es BLAKE3-256 ([Blake3]), no SHA-256.
 *    `MessageDigest("SHA-256")` producía un `contract_hash` distinto al de
 *    Rust para el mismo contrato.
 *  - **P0.2** La firma es Ed25519 real vía JCA (`SunEC`, disponible desde
 *    JDK 15). La v2.1 hacía
 *    `MessageDigest("SHA-256").digest(data + privateKey)`, que no es una firma:
 *    es un hash al que se le pega la clave privada.
 *  - **P0.3** El anti-replay usa la misma máquina de estados que Rust y C++,
 *    indexada por (session_id, direction). La v2.1 mantenía un
 *    `ConcurrentHashMap<Long, AtomicLong>` sobre el nonce colapsado a 64 bits.
 *  - **P0.4** El nonce se deriva de material secreto con BLAKE3 keyed. La
 *    v2.1 lo generaba con `SecureRandom`, lo que rompe la conformidad entre
 *    bindings y elimina la garantía estructural de unicidad.
 *
 * Política zero-log: ninguna de estas funciones imprime ni registra nada.
 */
public object SecurityUtils {

    public const val AES_GCM_KEY_SIZE: Int = 32
    public const val AES_GCM_NONCE_SIZE: Int = 12
    public const val AES_GCM_TAG_SIZE: Int = 16

    public const val ED25519_KEY_SIZE: Int = 32
    public const val ED25519_SIGNATURE_SIZE: Int = 64

    private val secureRandom = java.security.SecureRandom()

    // -----------------------------------------------------------------------
    // GENERACIÓN
    // -----------------------------------------------------------------------

    /**
     * Bytes aleatorios criptográficos.
     *
     * NO usar para el nonce de un frame AEAD: la unicidad del nonce viene de
     * [deriveNonce], ligada a la clave de sesión. Reservar para desafíos de un
     * solo uso (handshake, identificadores de sesión).
     */
    @JvmStatic
    public fun generateNonce(size: Int = ProtocolConstants.NONCE_SIZE): ByteArray {
        val nonce = ByteArray(size)
        secureRandom.nextBytes(nonce)
        return nonce
    }

    @JvmStatic
    public fun generateKey(size: Int = AES_GCM_KEY_SIZE): ByteArray {
        val key = ByteArray(size)
        secureRandom.nextBytes(key)
        return key
    }

    // -----------------------------------------------------------------------
    // HASHING (P0.1)
    // -----------------------------------------------------------------------

    /**
     * BLAKE3-256. Único digest con el que se calcula `contract_hash`.
     *
     * SHA-256 sigue disponible como [sha256] para compatibilidad, pero no
     * puede ser la identidad de un contrato CBC.
     */
    @JvmStatic
    public fun blake3Hash(data: ByteArray): ByteArray = Blake3.hash(data)

    @JvmStatic
    public fun blake3KeyedHash(key: ByteArray, data: ByteArray): ByteArray =
        Blake3.keyedHash(key, data)

    /** SHA-256, sólo para interoperabilidad legacy. NO usar como identidad. */
    @JvmStatic
    public fun sha256(data: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(data)

    // -----------------------------------------------------------------------
    // HMAC
    // -----------------------------------------------------------------------

    @JvmStatic
    public fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /**
     * HMAC de múltiples partes, con separación de dominio explícita.
     *
     * Se concatena internamente con longitudes prefijadas para evitar que
     * `("AB","C")` y `("A","BC")` produzcan el mismo resultado.
     */
    @JvmStatic
    public fun hmacSha256Parts(key: ByteArray, parts: List<ByteArray>): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        for (part in parts) {
            val len = part.size
            mac.update(byteArrayOf(
                (len ushr 24).toByte(), (len ushr 16).toByte(),
                (len ushr 8).toByte(), len.toByte()
            ))
            mac.update(part)
        }
        return mac.doFinal()
    }

    // -----------------------------------------------------------------------
    // KEY DERIVATION (P0.4)
    // -----------------------------------------------------------------------

    /**
     * Subclave con separación de dominio.
     *
     * KDF propia sobre BLAKE3 (NO es HKDF):
     *
     *     subkey = BLAKE3_keyed(secret, domain || material || session_id_le)
     *
     * Debe producir los mismos bytes que `KeyDerivation` en Rust y C++.
     */
    @JvmStatic
    public fun deriveSubkey(
        secret: ByteArray,
        domain: String,
        material: ByteArray,
        sessionId: Long
    ): ByteArray {
        require(secret.size == 32) { "el secreto raíz debe tener 32 bytes" }
        val sb = ByteArray(domain.length + material.size + 8)
        val domainBytes = domain.toByteArray(Charsets.UTF_8)
        System.arraycopy(domainBytes, 0, sb, 0, domainBytes.size)
        System.arraycopy(material, 0, sb, domainBytes.size, material.size)
        var o = domainBytes.size + material.size
        for (i in 0 until 8) {
            sb[o + i] = ((sessionId ushr (8 * i)) and 0xFF).toByte()
        }
        return blake3KeyedHash(secret, sb)
    }

    // -----------------------------------------------------------------------
    // NONCE (P0.4)
    // -----------------------------------------------------------------------

    /**
     * Nonce AEAD de 96 bits derivado del secreto de sesión.
     *
     *     nonce = BLAKE3_keyed(
     *         key  = nonce_key,
     *         data = "ipc-cbc2-nonce-v1" || direction || session_id_le || sequence_le
     *     )[0..12]
     */
    @JvmStatic
    public fun deriveNonce(
        nonceKey: ByteArray,
        sessionId: Long,
        sequence: Long,
        direction: Direction
    ): ByteArray {
        require(nonceKey.size == 32) { "la clave de nonce debe tener 32 bytes" }

        val domain = "ipc-cbc2-nonce-v1".toByteArray(Charsets.UTF_8)
        val data = ByteArray(domain.size + 1 + 8 + 8)
        System.arraycopy(domain, 0, data, 0, domain.size)

        var o = domain.size
        data[o++] = direction.code.toByte()

        for (i in 0 until 8) data[o + i] = ((sessionId ushr (8 * i)) and 0xFF).toByte()
        o += 8
        for (i in 0 until 8) data[o + i] = ((sequence ushr (8 * i)) and 0xFF).toByte()

        return blake3KeyedHash(nonceKey, data).copyOf(12)
    }

    // -----------------------------------------------------------------------
    // AEAD
    // -----------------------------------------------------------------------

    @JvmStatic
    public fun encryptAesGcm(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray
    ): ByteArray {
        require(key.size == AES_GCM_KEY_SIZE) { "la clave debe tener 32 bytes" }
        require(nonce.size == AES_GCM_NONCE_SIZE) { "el nonce debe tener 12 bytes" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(AES_GCM_TAG_SIZE * 8, nonce)
        )
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    @JvmStatic
    public fun decryptAesGcm(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray
    ): ByteArray {
        require(key.size == AES_GCM_KEY_SIZE) { "la clave debe tener 32 bytes" }
        require(nonce.size == AES_GCM_NONCE_SIZE) { "el nonce debe tener 12 bytes" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(AES_GCM_TAG_SIZE * 8, nonce)
        )
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    /**
     * ChaCha20-Poly1305 vía JCA.
     *
     * La política por defecto del contrato CBC es ChaCha20-Poly1305, así que
     * es el algoritmo que debe estar disponible. La v2.1 delegaba en
     * `encryptChacha20` pero su implementación era en realidad
     * `encryptAesGcm`, con lo que los tres bindings no coincidían.
     */
    @JvmStatic
    public fun encryptChaCha20(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray
    ): ByteArray {
        require(key.size == 32) { "la clave ChaCha20 debe tener 32 bytes" }
        require(nonce.size == 12) { "el nonce debe tener 12 bytes" }
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "ChaCha20"),
            javax.crypto.spec.IvParameterSpec(nonce)
        )
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    @JvmStatic
    public fun decryptChaCha20(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray
    ): ByteArray {
        require(key.size == 32) { "la clave ChaCha20 debe tener 32 bytes" }
        require(nonce.size == 12) { "el nonce debe tener 12 bytes" }
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "ChaCha20"),
            javax.crypto.spec.IvParameterSpec(nonce)
        )
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    // -----------------------------------------------------------------------
    // FIRMA Ed25519 (P0.2)
    // -----------------------------------------------------------------------

    /** Generar par de claves Ed25519. */
    @JvmStatic
    public fun generateKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    /**
     * Firmar con Ed25519.
     *
     * @param privateKeySeed semilla de 32 bytes (la "expanded" de Ed25519)
     */
    @JvmStatic
    public fun sign(data: ByteArray, privateKeySeed: ByteArray): ByteArray {
        require(privateKeySeed.size == ED25519_KEY_SIZE) {
            "la semilla de clave privada Ed25519 debe tener 32 bytes"
        }
        val spec = EdECPrivateKeySpec(NamedParameterSpec.ED25519, privateKeySeed)
        val key = KeyFactory.getInstance("Ed25519").generatePrivate(spec)
        val sig = Signature.getInstance("Ed25519")
        sig.initSign(key as PrivateKey)
        sig.update(data)
        return sig.sign()
    }

    /**
     * Extraer la clave pública cruda (32 bytes) de un `PublicKey` de JCA.
     *
     * JCA expone las claves Ed25519 envueltas en X.509 (RFC 8410); los 32
     * bytes crudos son el último campo del BIT STRING. [verify] trabaja con
     * la clave en bruto, que es el formato que usan los vectores.
     *
     * No se deriva la clave pública desde la semilla porque `KeyFactory` de
     * JDK 17 no expone ese cálculo: hacerlo exigiría implementar la
     * multiplicación de escalares de la curva Edwards, muy por encima del
     * alcance de un binding.
     */
    @JvmStatic
    public fun extractRawPublicKey(publicKey: PublicKey): ByteArray {
        val encoded = publicKey.encoded
        require(encoded != null && encoded.size >= 32) { "clave pública Ed25519 mal formada" }
        return encoded.copyOfRange(encoded.size - 32, encoded.size)
    }

    /**
     * Extraer la semilla cruda (32 bytes) de una `PrivateKey` de JCA.
     *
     * El envoltorio PKCS#8 de Ed25519 contiene únicamente la semilla, que es
     * lo que [sign] espera.
     */
    @JvmStatic
    public fun extractRawPrivateSeed(privateKey: PrivateKey): ByteArray {
        val encoded = privateKey.encoded
        require(encoded != null && encoded.size >= 32) { "clave privada Ed25519 mal formada" }
        return encoded.copyOfRange(encoded.size - 32, encoded.size)
    }

    /**
     * Verificar una firma Ed25519.
     *
     * @param publicKeyRaw clave pública en bruto de 32 bytes
     */
    @JvmStatic
    public fun verify(
        data: ByteArray,
        signature: ByteArray,
        publicKeyRaw: ByteArray
    ): Boolean {
        if (signature.size != ED25519_SIGNATURE_SIZE) return false
        if (publicKeyRaw.size != ED25519_KEY_SIZE) return false
        return try {
            // Se reconstruye el envoltorio X.509 de SubjectPublicKeyInfo en
            // lugar de usar `EdECPoint`: el orden de sus parámetros cambió
            // entre JDK 15 y 17, mientras que el prefijo ASN.1 de Ed25519 es
            // fijo (RFC 8410).
            val key = KeyFactory.getInstance("Ed25519")
                .generatePublic(X509EncodedKeySpec(wrapX509(publicKeyRaw)))
            val sig = Signature.getInstance("Ed25519")
            sig.initVerify(key as PublicKey)
            sig.update(data)
            sig.verify(signature)
        } catch (e: Exception) {
            // Una clave malformada o una firma corrupta son un rechazo, no una
            // excepción que pueda tumbar al proceso que escucha el socket.
            false
        }
    }

    /**
     * Prefijo DER de SubjectPublicKeyInfo para una clave Ed25519 en bruto
     * (RFC 8410, sección 7).
     */
    private fun wrapX509(raw32: ByteArray): ByteArray =
        byteArrayOf(
            0x30, 0x2A,             // SEQUENCE, 42 bytes
            0x30, 0x05,             // SEQUENCE, 5 bytes
            0x06, 0x03, 0x2B.toByte(), 0x65, 0x70,   // OID 1.3.101.112 (Ed25519)
            0x03, 0x21, 0x00        // BIT STRING, 33 bytes
        ) + raw32

    // -----------------------------------------------------------------------
    // UTILIDADES
    // -----------------------------------------------------------------------

    /**
     * Comparación en tiempo constante.
     *
     * Usa `MessageDigest.isEqual`, que no sale del bucle en el primer byte
     * distinto. Devolver `false` en cuanto hay una diferencia filtraría
     * información sobre el valor esperado.
     */
    @JvmStatic
    public fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        return java.security.MessageDigest.isEqual(a, b)
    }

    @JvmStatic
    public fun wipe(bytes: ByteArray) {
        Arrays.fill(bytes, 0)
    }
}
