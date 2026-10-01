package com.ipc.contract

/**
 * BLAKE3-256 en Kotlin puro.
 *
 * P0.1: `contract_hash` debe ser BLAKE3-256 en Rust, Kotlin y C++ por igual.
 * La JDK no incluye BLAKE3 y `MessageDigest.getInstance("BLAKE3")` lanza
 * `NoSuchAlgorithmException`: la v2.1 usaba SHA-256, con lo que el hash del
 * mismo contrato era distinto en cada lenguaje.
 *
 * Implementación de un solo chunk (entrances <= 1024 bytes), que es lo que
 * necesita el formato CBC: un header de 256 bytes más sus secciones. Para
 * entradas mayores se lanza [IllegalArgumentException] en vez de devolver un
 * digest incorrecto, porque `contract_hash` es la identidad del contrato.
 *
 * Verificada byte a byte contra el crate `blake3` de Rust mediante
 * `KotlinConformanceTest`.
 */
public object Blake3 {

    private const val OUT_LEN = 32
    private const val KEY_LEN = 32
    private const val BLOCK_LEN = 64
    private const val MAX_SINGLE_CHUNK = 1024

    private const val CHUNK_START = 1
    private const val CHUNK_END = 1 shl 1
    private const val ROOT = 1 shl 3
    private const val KEYED_HASH = 1 shl 4

    private val IV = intArrayOf(
        0x6A09E667.toInt(), 0xBB67AE85.toInt(), 0x3C6EF372.toInt(), 0xA54FF53A.toInt(),
        0x510E527F.toInt(), 0x9B05688C.toInt(), 0x1F83D9AB.toInt(), 0x5BE0CD19.toInt()
    )

    private fun rotr(x: Int, n: Int): Int = (x ushr n) or (x shl (32 - n))

    private val MSG_PERM = intArrayOf(2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)

    private fun g(s: IntArray, a: Int, b: Int, c: Int, d: Int, mx: Int, my: Int) {
        s[a] += s[b] + mx
        s[d] = rotr(s[d] xor s[a], 16)
        s[c] += s[d]
        s[b] = rotr(s[b] xor s[c], 12)
        s[a] += s[b] + my
        s[d] = rotr(s[d] xor s[a], 8)
        s[c] += s[d]
        s[b] = rotr(s[b] xor s[c], 7)
    }

    private fun roundFn(s: IntArray, m: IntArray) {
        // Columnas
        g(s, 0, 4, 8, 12, m[0], m[1])
        g(s, 1, 5, 9, 13, m[2], m[3])
        g(s, 2, 6, 10, 14, m[4], m[5])
        g(s, 3, 7, 11, 15, m[6], m[7])
        // Diagonales
        g(s, 0, 5, 10, 15, m[8], m[9])
        g(s, 1, 6, 11, 12, m[10], m[11])
        g(s, 2, 7, 8, 13, m[12], m[13])
        g(s, 3, 4, 9, 14, m[14], m[15])
    }

    private fun permute(m: IntArray) {
        val p = IntArray(16)
        for (i in 0 until 16) p[i] = m[MSG_PERM[i]]
        System.arraycopy(p, 0, m, 0, 16)
    }

    private fun wordsFromBlock(block: ByteArray, offset: Int, m: IntArray) {
        for (i in 0 until 16) {
            val o = offset + i * 4
            m[i] = (block[o].toInt() and 0xFF) or
                ((block[o + 1].toInt() and 0xFF) shl 8) or
                ((block[o + 2].toInt() and 0xFF) shl 16) or
                ((block[o + 3].toInt() and 0xFF) shl 24)
        }
    }

    /** Compresión BLAKE3: 7 rondas. Devuelve el estado de 16 palabras. */
    private fun compress(cv: IntArray, msg: IntArray, counter: Long, blockLen: Int, flags: Int): IntArray {
        val out = IntArray(16)
        System.arraycopy(cv, 0, out, 0, 8)
        out[8] = IV[0]; out[9] = IV[1]; out[10] = IV[2]; out[11] = IV[3]
        out[12] = (counter and 0xFFFFFFFFL).toInt()
        out[13] = ((counter ushr 32) and 0xFFFFFFFFL).toInt()
        out[14] = blockLen
        out[15] = flags

        val m = msg.copyOf()
        for (r in 0 until 7) {
            roundFn(out, m)
            if (r < 6) permute(m)
        }
        return out
    }

    private fun hashImpl(key: IntArray, data: ByteArray, baseFlags: Int): ByteArray {
        require(data.size <= MAX_SINGLE_CHUNK) {
            "BLAKE3 (Kotlin) soporta hasta $MAX_SINGLE_CHUNK bytes por llamada; " +
                "para entradas mayores se requiere la implementación con árbol"
        }

        // Estado del chunk
        var cv = key.copyOf()
        var blocksCompressed = 0
        val buf = ByteArray(BLOCK_LEN)
        var bufLen = 0

        var input = 0
        while (input < data.size) {
            if (bufLen == BLOCK_LEN) {
                val msg = IntArray(16)
                wordsFromBlock(buf, 0, msg)
                val startFlag = if (blocksCompressed == 0) CHUNK_START else 0
                val st = compress(cv, msg, 0L, BLOCK_LEN, baseFlags or startFlag)
                cv = IntArray(8) { st[it] xor st[it + 8] }
                blocksCompressed++
                bufLen = 0
            }
            val take = minOf(BLOCK_LEN - bufLen, data.size - input)
            System.arraycopy(data, input, buf, bufLen, take)
            bufLen += take
            input += take
        }

        // Bloque final: relleno con ceros y flags de cierre
        val block = buf.copyOf()
        if (bufLen < BLOCK_LEN) {
            java.util.Arrays.fill(block, bufLen, BLOCK_LEN, 0)
        }
        val msg = IntArray(16)
        wordsFromBlock(block, 0, msg)
        val startFlag = if (blocksCompressed == 0) CHUNK_START else 0
        val st = compress(cv, msg, 0L, bufLen, baseFlags or startFlag or CHUNK_END or ROOT)

        // La salida es el chaining value del nodo raíz: las primeras 8
        // palabras plegadas, en little-endian.
        val out = ByteArray(OUT_LEN)
        for (i in 0 until 8) {
            val w = st[i] xor st[i + 8]
            out[i * 4] = (w and 0xFF).toByte()
            out[i * 4 + 1] = ((w ushr 8) and 0xFF).toByte()
            out[i * 4 + 2] = ((w ushr 16) and 0xFF).toByte()
            out[i * 4 + 3] = ((w ushr 24) and 0xFF).toByte()
        }
        return out
    }

    private fun bytesToWords(b: ByteArray): IntArray {
        require(b.size == KEY_LEN) { "BLAKE3: la clave debe tener $KEY_LEN bytes" }
        val w = IntArray(8)
        for (i in 0 until 8) {
            val o = i * 4
            w[i] = (b[o].toInt() and 0xFF) or
                ((b[o + 1].toInt() and 0xFF) shl 8) or
                ((b[o + 2].toInt() and 0xFF) shl 16) or
                ((b[o + 3].toInt() and 0xFF) shl 24)
        }
        return w
    }

    /** Hash BLAKE3-256 sin clave. */
    @JvmStatic
    public fun hash(data: ByteArray): ByteArray = hashImpl(IV, data, 0)

    /** Hash BLAKE3-256 en modo keyed (PRF). */
    @JvmStatic
    public fun keyedHash(key: ByteArray, data: ByteArray): ByteArray =
        hashImpl(bytesToWords(key), data, KEYED_HASH)
}
