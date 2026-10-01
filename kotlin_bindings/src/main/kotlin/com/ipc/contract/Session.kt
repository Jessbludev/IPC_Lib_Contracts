package com.ipc.contract

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Sesión de contrato
 * Gestiona el estado de comunicación entre endpoints
 */

// ============================================================================
// ESTADOS DE SESIÓN
// ============================================================================

/**
 * Estados posibles de una sesión
 */
public enum class SessionState {
    /** Sesión no inicializada */
    INIT,

    /** Handshake en progreso */
    HANDSHAKING,

    /** Handshake completado, autenticación pendiente */
    AUTHENTICATING,

    /** Sesión activa */
    ACTIVE,

    /** Sesión en pausa */
    PAUSED,

    /** Sesión cerrándose */
    CLOSING,

    /** Sesión cerrada */
    CLOSED,

    /** Error en la sesión */
    ERROR
}

// ============================================================================
// LISTENER DE SESIÓN
// ============================================================================

/**
 * Listener para eventos de sesión
 */
public interface SessionListener {
    public fun onStateChanged(oldState: SessionState, newState: SessionState)
    public fun onError(error: Throwable)
    public fun onFrameReceived(frame: Frame)
    public fun onFrameSent(frame: Frame)
    public fun onChannelOpened(channelId: Int)
    public fun onChannelClosed(channelId: Int)
}

/**
 * Adaptador por defecto para SessionListener
 */
public open class SessionListenerAdapter : SessionListener {
    override fun onStateChanged(oldState: SessionState, newState: SessionState) {}
    override fun onError(error: Throwable) {}
    override fun onFrameReceived(frame: Frame) {}
    override fun onFrameSent(frame: Frame) {}
    override fun onChannelOpened(channelId: Int) {}
    override fun onChannelClosed(channelId: Int) {}
}

// ============================================================================
// CANAL
// ============================================================================

/**
 * Canal de comunicación
 * Modelo abstracción de flujo de datos bidireccional
 */
public class Channel(
    public val id: Int,
    private val session: ContractSession,
    private val role: OperationRole
) {
    private val _frames = Channel<Frame>(kotlinx.coroutines.channels.Channel.UNLIMITED)
    public val frames: ReceiveChannel<Frame> = _frames

    private var _isOpen = true
    public val isOpen: Boolean get() = _isOpen

    private var _isPaused = false
    public val isPaused: Boolean get() = _isPaused

    /**
     * Enviar frame al canal
     */
    public suspend fun send(frame: Frame) {
        if (!_isOpen) throw ContractException("Channel $id is closed")
        _frames.send(frame)
    }

    /**
     * Enviar datos de forma conveniente
     */
    public suspend fun sendData(data: ByteArray, operationId: OperationId, lastFrame: Boolean = true) {
        val frame = Frame(
            sessionId = session.id,
            sequence = session.nextSequence(),
            channelId = id,
            operationId = operationId,
            packetType = PacketType.DATA,
            payload = data,
            flags = FrameFlags(lastFrame = lastFrame),
            role = session.contract.role
        )
        send(frame)
    }

    /**
     * Enviar string
     */
    public suspend fun sendString(data: String, operationId: OperationId, lastFrame: Boolean = true) {
        sendData(data.toByteArray(Charsets.UTF_8), operationId, lastFrame)
    }

    /**
     * Recibir frame del canal
     */
    public suspend fun receive(): Frame {
        return _frames.receive()
    }

    /**
     * Recibir datos como bytes
     */
    public suspend fun receiveData(): ByteArray {
        val frame = receive()
        return frame.payload
    }

    /**
     * Recibir datos como string
     */
    public suspend fun receiveString(): String {
        return String(receiveData(), Charsets.UTF_8)
    }

    /**
     * Pausar el canal
     */
    public fun pause() {
        _isPaused = true
    }

    /**
     * Reanudar el canal
     */
    public fun resume() {
        _isPaused = false
    }

    /**
     * Cerrar el canal
     */
    public fun close() {
        _isOpen = false
        _frames.close()
    }
}

// ============================================================================
// SESIÓN DE CONTRATO
// ============================================================================

/**
 * Sesión de comunicación basada en contrato
 *
 * Gestiona:
 * - Estados de sesión
 * - Canales lógicos
 * - Secuencia de frames
 * - Timeouts
 */
public class ContractSession(
    public val contract: Contract,
    public val role: ContractRole,
    public val id: Long = System.currentTimeMillis()
) {
    // Estado
    @Volatile
    private var _state = SessionState.INIT
    public val state: SessionState get() = _state

    // Secuencia
    private val _sequence = AtomicLong(0)

    // Timeout de operación
    public var operationTimeoutMs: Long = 30000

    // Listener
    private var listener: SessionListener = SessionListenerAdapter()

    // Canales
    private val channels = ConcurrentHashMap<Int, Channel>()
    private var nextChannelId = 1

    // Frames pendientes de respuesta
    private val pendingRequests = ConcurrentHashMap<Long, CompletableDeferred<Frame>>()

    // Coroutine scope
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Establecer listener
     */
    public fun setListener(listener: SessionListener) {
        this.listener = listener
    }

    /**
     * Obtener siguiente número de secuencia
     */
    public fun nextSequence(): Long = _sequence.incrementAndGet()

    /**
     * Establecer estado
     */
    public fun setState(newState: SessionState) {
        val oldState = _state
        _state = newState
        listener.onStateChanged(oldState, newState)
    }

    /**
     * Iniciar handshake
     */
    public suspend fun startHandshake(transport: Transport): Frame {
        setState(SessionState.HANDSHAKING)

        val handshakeFrame = FrameUtils.createHandshakeFrame(
            contractHash = contract.getContractHash(),
            protocolVersion = ProtocolConstants.PROTOCOL_VERSION
        )

        transport.send(handshakeFrame)
        listener.onFrameSent(handshakeFrame)

        // Esperar respuesta
        val response = transport.receive()

        if (!FrameUtils.isValidHandshake(response)) {
            throw ContractException("Invalid handshake response")
        }

        val (_, sessionId) = FrameUtils.parseHandshakeResponse(response)

        setState(SessionState.AUTHENTICATING)
        return response
    }

    /**
     * Crear canal
     */
    public fun createChannel(role: OperationRole = OperationRole.REQUEST_RESPONSE): Channel {
        val channelId = nextChannelId++
        val channel = Channel(channelId, this, role)
        channels[channelId] = channel
        listener.onChannelOpened(channelId)
        return channel
    }

    /**
     * Obtener canal por ID
     */
    public fun getChannel(channelId: Int): Channel? = channels[channelId]

    /**
     * Cerrar canal
     */
    public fun closeChannel(channelId: Int) {
        channels.remove(channelId)?.close()
        listener.onChannelClosed(channelId)
    }

    /**
     * Enviar request y esperar respuesta (Request-Response mode)
     */
    public suspend fun request(
        operationId: OperationId,
        payload: ByteArray,
        channelId: Int = 0,
        timeoutMs: Long? = null
    ): Frame {
        if (_state != SessionState.ACTIVE) {
            throw ContractException("Session not active: $_state")
        }

        val sequence = nextSequence()
        val deferred = CompletableDeferred<Frame>()

        pendingRequests[sequence] = deferred

        val frame = Frame(
            sessionId = id,
            sequence = sequence,
            channelId = channelId,
            operationId = operationId,
            packetType = PacketType.DATA,
            payload = payload,
            flags = FrameFlags(),
            role = contract.role
        )

        try {
            listener.onFrameSent(frame)
            return deferred.await()
        } finally {
            pendingRequests.remove(sequence)
        }
    }

    /**
     * Enviar request con datos serializados
     */
    public suspend inline fun <reified T> requestSerialized(
        operationId: OperationId,
        data: T,
        serializer: ContractSerializer,
        typeId: Short,
        channelId: Int = 0,
        timeoutMs: Long? = null
    ): ByteArray {
        val payload = serializer.serialize(data, typeId)
        val response = request(operationId, payload, channelId, timeoutMs)
        return response.payload
    }

    /**
     * Enviar y olvidar (Fire-and-forget mode)
     */
    public fun sendOneWay(
        operationId: OperationId,
        payload: ByteArray,
        channelId: Int = 0
    ) {
        if (_state != SessionState.ACTIVE) {
            throw ContractException("Session not active: $_state")
        }

        val frame = Frame(
            sessionId = id,
            sequence = nextSequence(),
            channelId = channelId,
            operationId = operationId,
            packetType = PacketType.DATA,
            payload = payload,
            flags = FrameFlags(lastFrame = true),
            role = contract.role
        )

        listener.onFrameSent(frame)
    }

    /**
     * Recibir frame
     */
    public fun receiveFrame(frame: Frame) {
        listener.onFrameReceived(frame)

        // Responder a request pendiente
        frame.sequence.takeIf { pendingRequests.containsKey(it) }?.let { seq ->
            pendingRequests[seq]?.complete(frame)
        }

        // Notificar a canal
        frame.channelId.takeIf { channels.containsKey(it) }?.let { chId ->
            scope.launch {
                channels[chId]?.send(frame)
            }
        }
    }

    /**
     * Cerrar sesión
     */
    public fun close() {
        setState(SessionState.CLOSING)
        channels.values.forEach { it.close() }
        channels.clear()
        pendingRequests.values.forEach { it.cancel() }
        pendingRequests.clear()
        scope.cancel()
        setState(SessionState.CLOSED)
    }
}

// ============================================================================
// TRANSPORT
// ============================================================================

/**
 * Transport abstracto
 * Implementado para Unix Domain Sockets, TCP, etc.
 */
public interface Transport {
    public suspend fun send(frame: Frame)
    public suspend fun receive(): Frame
    public fun close()
    public val isConnected: Boolean
}

/**
 * Transport que usa Unix Domain Sockets
 */
public class UnixSocketTransport(private val socketPath: String) : Transport {
    // En una implementación real, usaríamos JNI o una biblioteca como JNR
    // Por ahora, este es un placeholder
    private var connected = false

    override val isConnected: Boolean get() = connected

    override suspend fun send(frame: Frame) {
        // Implementación real usaría Unix Domain Socket
        throw NotImplementedError("UnixSocketTransport requires native implementation")
    }

    override suspend fun receive(): Frame {
        throw NotImplementedError("UnixSocketTransport requires native implementation")
    }

    override fun close() {
        connected = false
    }
}

/**
 * Transport in-memory para testing
 */
public class InMemoryTransport : Transport {
    private val frames = Channel<Frame>(kotlinx.coroutines.channels.Channel.UNLIMITED)
    private var connected = true

    override val isConnected: Boolean get() = connected

    override suspend fun send(frame: Frame) {
        frames.send(frame)
    }

    override suspend fun receive(): Frame {
        return frames.receive()
    }

    override fun close() {
        connected = false
        frames.close()
    }
}

// ============================================================================
// BUILDER DE SESIÓN
// ============================================================================

/**
 * Builder para crear sesiones de contrato
 */
public class SessionBuilder {
    private var contract: Contract? = null
    private var role: ContractRole = ContractRole.MUTUAL
    private var sessionId: Long = System.currentTimeMillis()
    private var timeoutMs: Long = 30000
    private var listener: SessionListener = SessionListenerAdapter()

    public fun contract(contract: Contract): SessionBuilder {
        this.contract = contract
        return this
    }

    public fun role(role: ContractRole): SessionBuilder {
        this.role = role
        return this
    }

    public fun sessionId(id: Long): SessionBuilder {
        this.sessionId = id
        return this
    }

    public fun timeout(timeoutMs: Long): SessionBuilder {
        this.timeoutMs = timeoutMs
        return this
    }

    public fun listener(listener: SessionListener): SessionBuilder {
        this.listener = listener
        return this
    }

    public fun build(): ContractSession {
        val c = contract ?: throw ContractException("Contract is required")
        return ContractSession(c, role, sessionId).also {
            it.operationTimeoutMs = timeoutMs
            it.setListener(listener)
        }
    }
}
