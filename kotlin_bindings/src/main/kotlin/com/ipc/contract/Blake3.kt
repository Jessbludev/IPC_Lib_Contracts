@file:Suppress("MemberVisibilityCanBePrivate")

package com.ipc.contract

/**
 * BLAKE3-256 portable.
 *
 * P0.1: `contract_hash` de un contrato CBC es BLAKE3-256 en Rust, Kotlin y
 * C++. No se delega en ninguna biblioteca externa: la implementación es propia
 * y se verifica byte a byte contra la referencia de Rust.
 *
 * Implementa el árbol de sub-chunks completo de la especificación, sin límite
 * de tamaño. La estructura sigue a la implementación de referencia:
 *
 *  - `ChunkState` mantiene el chaining value y el bloque en curso de un chunk.
 *  - Al llenarse un chunk, su chaining value se apila y se empieza otro.
 *  - La pila mantiene sub-chunks con número de chunks completados
 *    estrictamente decreciente de abajo hacia arriba.
 *  - Al finalizar, los sub-chunks pendientes se combinan de derecha a
 *    izquierda con el último chunk, y el nodo resultante se comprime como raíz.
 */
public object Blake3 {

    public const val OUT_LEN: Int = 32
    public const val KEY_LEN: Int = 32

    private val IV = intArrayOf(
        0x6A09E667.toInt(), 0xBB67AE85.toInt(), 0x3C6EF372.toInt(), 0xA54FF53A.toInt(),
        0x510E527F.toInt(), 0x9B05688C.toInt(), 0x1F83D9AB.toInt(), 0x5BE0CD19.toInt()
    )

    private val MSG_PERM = intArrayOf(2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)

    private const val CHUNK_START = 1 shl 0
    private const val CHUNK_END = 1 shl 1
    private const val PARENT = 1 shl 2
    private const val ROOT = 1 shl 3
    private const val KEYED_HASH = 1 shl 4

    private const val BLOCK_LEN = 64
    private const val CHUNK_LEN = 1024

    private fun rotr(x: Int, n: Int): Int = (x ushr n) or (x shl (32 - n))

    private fun g(s: IntArray, a: Int, b: Int, c: Int, d: Int, mx: Int, my: Int) {
        s[a] = s[a] + s[b] + mx
        s[d] = rotr(s[d] xor s[a], 16)
        s[c] = s[c] + s[d]
        s[b] = rotr(s[b] xor s[c], 12)
        s[a] = s[a] + s[b] + my
        s[d] = rotr(s[d] xor s[a], 8)
        s[c] = s[c] + s[d]
        s[b] = rotr(s[b] xor s[c], 7)
    }

    private fun roundFn(s: IntArray, m: IntArray) {
        g(s, 0, 4, 8, 12, m[0], m[1])
        g(s, 1, 5, 9, 13, m[2], m[3])
        g(s, 2, 6, 10, 14, m[4], m[5])
        g(s, 3, 7, 11, 15, m[6], m[7])
        g(s, 0, 5, 10, 15, m[8], m[9])
        g(s, 1, 6, 11, 12, m[10], m[11])
        g(s, 2, 7, 8, 13, m[12], m[13])
        g(s, 3, 4, 9, 14, m[14], m[15])
    }

    private fun permute(m: IntArray) {
        val permuted = IntArray(16)
        for (i in 0 until 16) permuted[i] = m[MSG_PERM[i]]
        System.arraycopy(permuted, 0, m, 0, 16)
    }

    private fun wordsFromBlock(block: ByteArray, offset: Int, m: IntArray) {
        for (i in 0 until 16) {
            val b = offset + i * 4
            m[i] = (block[b].toInt() and 0xFF) or
                ((block[b + 1].toInt() and 0xFF) shl 8) or
                ((block[b + 2].toInt() and 0xFF) shl 16) or
                ((block[b + 3].toInt() and 0xFF) shl 24)
        }
    }

    /**
     * Compresión BLAKE3.
     *
     * Devuelve el estado completo de 16 palabras, **sin plegar**. El plegado a
     * chaining value (`s[i] xor s[i+8]`) y la lectura del digest raíz son
     * operaciones distintas según se trate de un chunk intermedio o del nodo
     * raíz, así que las hace quien llama.
     *
     * Las palabras 8..12 toman IV[0..4] y las últimas cuatro se ASIGNAN
     * (contador, longitud y flags), no se Xorean con el IV.
     */
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

    /** Nodo de salida de un chunk: lo necesario para comprimirlo como padre o como raíz. */
    private class Output(
        val inputCv: IntArray,
        val blockWords: IntArray,
        val counter: Long,
        val blockLen: Int,
        val flags: Int
    )

    private fun wordsToBytes(words: IntArray, out: ByteArray, outOffset: Int) {
        for (i in 0 until 8) {
            val w = words[i]
            out[outOffset + i * 4] = (w and 0xFF).toByte()
            out[outOffset + i * 4 + 1] = ((w ushr 8) and 0xFF).toByte()
            out[outOffset + i * 4 + 2] = ((w ushr 16) and 0xFF).toByte()
            out[outOffset + i * 4 + 3] = ((w ushr 24) and 0xFF).toByte()
        }
    }

    private fun fold(st: IntArray): IntArray = IntArray(8) { st[it] xor st[it + 8] }

    private fun outputRootBytes(o: Output): ByteArray {
        val st = compress(o.inputCv, o.blockWords, o.counter, o.blockLen, o.flags or ROOT)
        val out = ByteArray(OUT_LEN)
        wordsToBytes(fold(st), out, 0)
        return out
    }

    private fun parentCv(left: IntArray, right: IntArray, key: IntArray, keyFlags: Int): IntArray {
        val block = IntArray(16)
        System.arraycopy(left, 0, block, 0, 8)
        System.arraycopy(right, 0, block, 8, 8)
        val st = compress(key, block, 0L, BLOCK_LEN, PARENT or keyFlags)
        return fold(st)
    }

    private fun parentOutput(left: IntArray, right: IntArray, key: IntArray, keyFlags: Int): Output {
        val block = IntArray(16)
        System.arraycopy(left, 0, block, 0, 8)
        System.arraycopy(right, 0, block, 8, 8)
        return Output(key.copyOf(), block, 0L, BLOCK_LEN, PARENT or keyFlags)
    }

    /**
     * Estado de un chunk en curso.
     */
    private class ChunkState(counter: Long, key: IntArray, flags: Int) {
        var cv: IntArray = key.copyOf()
        var chunkCounter: Long = counter
        var blocksCompressed: Int = 0
        var flags: Int = flags
        val buf = ByteArray(BLOCK_LEN)
        var bufLen: Int = 0

        fun length(): Int = BLOCK_LEN * blocksCompressed + bufLen

        private fun startFlag(): Int = if (blocksCompressed == 0) CHUNK_START else 0

        fun update(input: ByteArray, offset: Int, len: Int) {
            var pos = offset
            var remaining = len
            while (remaining > 0) {
                if (bufLen == BLOCK_LEN) {
                    val msg = IntArray(16)
                    wordsFromBlock(buf, 0, msg)
                    val st = compress(cv, msg, chunkCounter, BLOCK_LEN, flags or startFlag())
                    cv = fold(st)
                    blocksCompressed++
                    bufLen = 0
                }
                val take = minOf(BLOCK_LEN - bufLen, remaining)
                System.arraycopy(input, pos, buf, bufLen, take)
                bufLen += take
                pos += take
                remaining -= take
            }
        }

        fun output(): Output {
            val block = buf.copyOf()
            if (bufLen < BLOCK_LEN) {
                java.util.Arrays.fill(block, bufLen, BLOCK_LEN, 0)
            }
            val blockWords = IntArray(16)
            wordsFromBlock(block, 0, blockWords)
            return Output(cv.copyOf(), blockWords, chunkCounter, bufLen, flags or startFlag() or CHUNK_END)
        }

        fun chainingValue(): IntArray = fold(compress(cv, output().blockWords, chunkCounter, bufLen, flags or startFlag() or CHUNK_END))
    }

    /**
     * Hasher incremental de BLAKE3.
     *
     * Equivale a [hash] por construcción, pero acepta la entrada troceada. El
     * resultado no depende de la partición, que es la propiedad que comprueban
     * los tests de conformidad.
     */
    public class Blake3Hasher(keyed: Boolean = false) {
        private var keyFlags: Int = if (keyed) KEYED_HASH else 0
        private var key: IntArray = IV.copyOf()
        private var chunk: ChunkState = ChunkState(0L, key, keyFlags)

        /**
         * Sub-chunks completados pendientes de combinar.
         *
         * El invariante es que el número de chunks que representa cada entrada
         * es estrictamente decreciente de abajo hacia arriba, lo que garantiza
         * que la forma final sea el árbol canónico de la especificación.
         */
        private val cvStack = ArrayList<IntArray>()

        /** Fijar la clave de 32 bytes del modo keyed. Debe llamarse antes de [update]. */
        public fun setKey(keyBytes: ByteArray) {
            require(keyBytes.size == KEY_LEN) { "BLAKE3 requiere una clave de $KEY_LEN bytes" }
            key = bytesToWords(keyBytes)
            keyFlags = KEYED_HASH
            chunk = ChunkState(0L, key, keyFlags)
            cvStack.clear()
        }

        /** Volver al estado inicial. */
        public fun reset() {
            chunk = ChunkState(0L, key, keyFlags)
            cvStack.clear()
        }

        private fun addChunkChainingValue(newCv: IntArray, totalChunksIn: Long) {
            var newCvVar = newCv
            var totalChunks = totalChunksIn
            while ((totalChunks and 1L) == 0L) {
                val left = cvStack.removeAt(cvStack.size - 1)
                newCvVar = parentCv(left, newCvVar, key, keyFlags)
                totalChunks = totalChunks shr 1
            }
            cvStack.add(newCvVar)
        }

        /** Absorber más entrada. El resultado no depende de cómo se trocee. */
        public fun update(data: ByteArray) = update(data, 0, data.size)

        public fun update(data: ByteArray, offset: Int, len: Int) {
            var pos = offset
            var remaining = len
            while (remaining > 0) {
                if (chunk.length() == CHUNK_LEN) {
                    val cv = chunk.chainingValue()
                    val total = chunk.chunkCounter + 1
                    addChunkChainingValue(cv, total)
                    chunk = ChunkState(total, key, keyFlags)
                }
                val want = CHUNK_LEN - chunk.length()
                val take = minOf(want, remaining)
                chunk.update(data, pos, take)
                pos += take
                remaining -= take
            }
        }

        /** Digest final de 32 bytes. No consume el hasher. */
        public fun finalize(): ByteArray {
            // Caso trivial: un solo chunk, sin combines pendientes.
            if (cvStack.isEmpty()) {
                val st = compress(
                    chunk.cv, chunk.output().blockWords, chunk.chunkCounter, chunk.bufLen,
                    chunk.flags or (if (chunk.blocksCompressed == 0) CHUNK_START else 0) or CHUNK_END or ROOT
                )
                val out = ByteArray(OUT_LEN)
                wordsToBytes(fold(st), out, 0)
                return out
            }

            var out = chunk.output()
            for (i in cvStack.indices.reversed()) {
                val st = compress(out.inputCv, out.blockWords, out.counter, out.blockLen, out.flags)
                val right = fold(st)
                out = parentOutput(cvStack[i], right, key, keyFlags)
            }
            return outputRootBytes(out)
        }

        public fun digest(): ByteArray = finalize()
    }

    private fun bytesToWords(b: ByteArray): IntArray {
        require(b.size == KEY_LEN) { "BLAKE3 requiere una clave de $KEY_LEN bytes" }
        val w = IntArray(8)
        for (i in 0 until 8) {
            w[i] = (b[i * 4].toInt() and 0xFF) or
                ((b[i * 4 + 1].toInt() and 0xFF) shl 8) or
                ((b[i * 4 + 2].toInt() and 0xFF) shl 16) or
                ((b[i * 4 + 3].toInt() and 0xFF) shl 24)
        }
        return w
    }

    private fun hashImpl(key: IntArray, data: ByteArray, keyed: Boolean): ByteArray {
        // Se apoya en el hasher incremental en lugar de duplicar el bucle del
        // árbol: garantiza por construcción que la API incremental y la
        // one-shot no pueden divergir.
        val h = Blake3Hasher(keyed)
        if (keyed) h.setKey(intsToBytes(key))
        h.update(data)
        return h.finalize()
    }

    private fun intsToBytes(w: IntArray): ByteArray {
        val out = ByteArray(32)
        wordsToBytes(w, out, 0)
        return out
    }

    /** Hash BLAKE3-256 sin clave, de cualquier tamaño. */
    @JvmStatic
    public fun hash(data: ByteArray): ByteArray = hashImpl(IV, data, false)

    /** Hash BLAKE3-256 en modo keyed (PRF), de cualquier tamaño. */
    @JvmStatic
    public fun keyedHash(key: ByteArray, data: ByteArray): ByteArray {
        require(key.size == KEY_LEN) { "BLAKE3 requiere una clave de $KEY_LEN bytes" }
        return hashImpl(bytesToWords(key), data, true)
    }
}
