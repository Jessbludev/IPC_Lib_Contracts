package com.ipc.contract

import java.util.concurrent.ConcurrentHashMap

/**
 * Dirección de un frame respecto a la sesión.
 *
 * TX y RX tienen ventanas independientes: un frame reflejado nunca puede ser
 * aceptado como nuevo en la dirección opuesta.
 */
public enum class Direction(public val code: Int) {
    TX(0x01),
    RX(0x02)
}

/** Resultado de la comprobación anti-replay. */
public enum class ReplayResult {
    ACCEPTED,
    REPLAY,
    OUT_OF_WINDOW
}

/**
 * Ventana deslizante de secuencias, idéntica a `ReplayWindow` en Rust y
 * `ReplayWindow` en C++ (P0.3).
 *
 * Índice 0 = secuencia más alta; índice `i` = `highest - i`.
 *
 * La v2.1 mantenía un `ConcurrentHashMap<Long, AtomicLong>` sobre el nonce
 * convertido con `ByteBuffer.wrap(nonce).order(BIG_ENDIAN).long`. Eso tenía
 * dos problemas: colapsa 96 bits a 64 (colisiones triviales) y el mapa
 * crecía sin límite.
 */
public class ReplayWindow @JvmOverloads constructor(windowSize: Int = 1024) {

    public companion object {
        public const val MIN_WINDOW: Int = 64
        public const val MAX_WINDOW: Int = 1 shl 20

        /** Normalizar el tamaño de ventana declarado al rango seguro. */
        @JvmStatic
        public fun normalizeWindow(windowSize: Int): Int =
            windowSize.coerceIn(MIN_WINDOW, MAX_WINDOW)
    }

    private val window: Int = normalizeWindow(windowSize)
    private val bitmap: LongArray = LongArray((window + 63) / 64)

    var highest: Long = 0
        private set

    var initialized: Boolean = false
        private set

    /** Desplaza el bitmap `shift` posiciones hacia secuencias más altas. */
    private fun shiftLeft(shift: Int) {
        val wordShift = shift / 64
        val bitShift = shift % 64

        if (wordShift >= bitmap.size) {
            bitmap.fill(0L)
            return
        }
        for (i in bitmap.indices.reversed()) {
            var v = bitmap[i - wordShift] shl bitShift
            if (bitShift > 0 && i > wordShift) {
                v = v or (bitmap[i - wordShift - 1] ushr (64 - bitShift))
            }
            bitmap[i] = v
        }
    }

    private fun isBitSet(offset: Int): Boolean {
        val word = offset / 64
        val bit = offset % 64
        return word < bitmap.size && (bitmap[word] and (1L shl bit)) != 0L
    }

    private fun setBit(offset: Int) {
        val word = offset / 64
        val bit = offset % 64
        if (word < bitmap.size) bitmap[word] = bitmap[word] or (1L shl bit)
    }

    /** Verificar y registrar una secuencia. */
    @Synchronized
    public fun checkAndMark(sequence: Long): ReplayResult {
        val effectiveWindow = bitmap.size * 64

        if (!initialized) {
            initialized = true
            highest = sequence
            bitmap.fill(0L)
            setBit(0)
            return ReplayResult.ACCEPTED
        }

        if (sequence > highest) {
            val gap = (sequence - highest).toInt()
            shiftLeft(gap)
            highest = sequence
            setBit(0)
            if (gap >= effectiveWindow) {
                // Salto mayor que la ventana: se resincroniza y se olvida el
                // estado anterior, que ya no es interpretable.
                bitmap.fill(0L)
                setBit(0)
            }
            return ReplayResult.ACCEPTED
        }

        val offset = (highest - sequence).toInt()
        if (offset >= effectiveWindow) return ReplayResult.OUT_OF_WINDOW
        if (isBitSet(offset)) return ReplayResult.REPLAY

        setBit(offset)
        return ReplayResult.ACCEPTED
    }

    /** Instantánea del estado, para los vectores de conformidad. */
    public fun snapshot(): Triple<Long, Boolean, List<Long>> =
        Triple(highest, initialized, bitmap.toList())

    /** Restaurar un estado serializado (para conformidad). */
    public fun restore(highest: Long, initialized: Boolean, words: List<Long>) {
        this.highest = highest
        this.initialized = initialized
        for (i in bitmap.indices) {
            bitmap[i] = words.getOrElse(i) { 0L }
        }
    }
}

/** Clave compuesta sesión + dirección. */
public data class SessionDirectionKey(val sessionId: Long, val direction: Direction)

/**
 * Anti-replay: una ventana por (session_id, direction).
 *
 * Debe comportarse exactamente igual que Rust y C++.
 */
public class AntiReplay @JvmOverloads constructor(windowSize: Int = 1024) {

    public val windowSize: Int = ReplayWindow.normalizeWindow(windowSize)

    private val windows = ConcurrentHashMap<SessionDirectionKey, ReplayWindow>()

    /** Verificar y registrar una secuencia para (sesión, dirección). */
    public fun check(sessionId: Long, direction: Direction, sequence: Long): ReplayResult {
        val key = SessionDirectionKey(sessionId, direction)
        val window = windows.computeIfAbsent(key) { ReplayWindow(windowSize) }
        return window.checkAndMark(sequence)
    }

    /** Instantánea del estado de una ventana (conConformidad). */
    public fun snapshot(sessionId: Long, direction: Direction): Triple<Long, Boolean, List<Long>>? =
        windows[SessionDirectionKey(sessionId, direction)]?.snapshot()

    /** Restaurar el estado de una ventana (conformidad). */
    public fun restore(sessionId: Long, direction: Direction, highest: Long, initialized: Boolean, bitmap: List<Long>) {
        val key = SessionDirectionKey(sessionId, direction)
        val w = windows.computeIfAbsent(key) { ReplayWindow(windowSize) }
        w.restore(highest, initialized, bitmap)
    }

    /** Eliminar el estado de una sesión (ambas direcciones). */
    public fun removeSession(sessionId: Long) {
        windows.remove(SessionDirectionKey(sessionId, Direction.TX))
        windows.remove(SessionDirectionKey(sessionId, Direction.RX))
    }

    /** Número de ventanas activas. */
    public fun activeSessions(): Int = windows.size
}
