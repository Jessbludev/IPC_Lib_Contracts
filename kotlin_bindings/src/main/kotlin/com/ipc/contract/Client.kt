package com.ipc.contract

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.*
import java.util.concurrent.ConcurrentHashMap

/**
 * Cliente IPC para comunicación con procesos Rust/CPP/Zig
 *
 * Modos de ejecución:
 * - Message-Response: Solicitud espera acción, sesión activa
 * - Multiplexing: Varias comunicaciones del mismo estado
 * - Fire-and-Forget: Realiza acción y olvida, sesión temporal
 * - Real-time: Conexión constante para streaming
 */

// ============================================================================
// MODOS DE EJECUCIÓN
// ============================================================================

/**
 * Modos de ejecución de la comunicación
 */
public enum class ExecutionMode {
    /**
     * Message-Response: Solicitud espera acción, sesión activa
     * - Envía request, espera response
     * - Sesión persiste hasta explícitamente cerrada
     */
    MESSAGE_RESPONSE,

    /**
     * Multiplexing: Varias comunicaciones del mismo estado
     * - Múltiples operaciones concurrentes
     * - Cada operación tiene su propio sequence
     * - Orden de entrega definido
     */
    MULTIPLEXING,

    /**
     * Fire-and-Forget: Realiza acción y olvida
     * - No espera respuesta
     * - Sesión temporal
     * - Ideal para eventos, logs, métricas
     */
    FIRE_AND_FORGET,

    /**
     * Real-time: Conexión constante
     * - Streaming de datos en vivo
     * - Conexión persistente
     * - Control de flujo (pause/resume)
     */
    REAL_TIME
}

// ============================================================================
// CALLbacks
// ============================================================================

/**
 * Resultado de operación
 */
public sealed class OperationResult {
    public data class Success(val payload: ByteArray) : OperationResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            // `other` es nullable: un `data class` con un `ByteArray` debe
            // comparar el contenido, no la referencia del array.
            if (other !is Success) return false
            return payload.contentEquals(other.payload)
        }

        override fun hashCode(): Int = payload.contentHashCode()
    }

    public data class Error(val code: Int, val message: String) : OperationResult()
    public data object Timeout : OperationResult()
    public data class StreamFrame(val frame: Frame) : OperationResult()
}

// ============================================================================
// CALL OPCIONAL
// ============================================================================

/**
 * Llamada de operación con resultado
 */
public class OperationCall(
    val operationId: OperationId,
    val payload: ByteArray,
    val channelId: Int = 0
) {
    private val _result = CompletableDeferred<OperationResult>()
    public val result: Deferred<OperationResult> = _result

    public fun complete(result: OperationResult) {
        _result.complete(result)
    }

    public fun completeExceptionally(error: Throwable) {
        _result.completeExceptionally(error)
    }
}

// ============================================================================
// CLIENTE IPC
// ============================================================================

/**
 * Cliente IPC para comunicación con procesos Rust/CPP/Zig
 */
public class IpcClient(
    private val transport: Transport,
    private val contract: Contract,
    private val seed: ByteArray,
    private val mode: ExecutionMode = ExecutionMode.MESSAGE_RESPONSE
) {
    /**
     * Acceso al contrato para las funciones `inline` públicas.
     *
     * Una función `inline` pública no puede referenciar un campo privado desde
     * el cuerpo de la clase; el accessor resuelve el acceso sin exponer el
     * contrato como propiedad mutable.
     */
    public fun requireContract(): Contract = contract

    // Sesión activa
    private var session: ContractSession? = null
    private var isRunning = false

    // Coroutine scope
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Llamadas pendientes (para multiplexing)
    private val pendingCalls = ConcurrentHashMap<Long, OperationCall>()

    // Canales de streaming (para real-time mode)
    private val streamingChannels = ConcurrentHashMap<Int, Channel>()

    // Listener
    private var eventListener: IpcEventListener = IpcEventListenerAdapter()

    /**
     * Conectar al servidor
     */
    public suspend fun connect() {
        if (isRunning) return

        // Crear sesión
        session = SessionBuilder()
            .contract(contract)
            .role(contract.role)
            .listener(object : SessionListenerAdapter() {
                override fun onFrameReceived(frame: Frame) {
                    handleIncomingFrame(frame)
                }

                override fun onError(error: Throwable) {
                    eventListener.onError(error)
                }
            })
            .build()

        // Handshake
        session?.startHandshake(transport)

        // Aplicar seguridad
        if (contract.securityPolicy.authenticationRequired) {
            authenticate()
        }

        session?.setState(SessionState.ACTIVE)
        isRunning = true

        // Iniciar loop de recepción
        scope.launch { receiveLoop() }
    }

    /**
     * Autenticación con seed
     */
    private suspend fun authenticate() {
        // Token de autenticación = subclave `auth` derivada del secreto de
        // sesión (P0.4). Mismo dominio que Rust y C++, así que el token es
        // idéntico en los tres bindings para la misma entrada.
        val contractHash = contract.getContractHash()
        val kd = KeyDerivation(seed)
        val authToken = kd.deriveAuthKey(kd.deriveSessionKey(contractHash, session?.id ?: 0))
        val authFrame = FrameUtils.createAuthFrame(
            sessionId = session?.id ?: 0,
            token = authToken,
            contractHash = contractHash
        )
        transport.send(authFrame)
    }

    /**
     * Loop de recepción de frames
     */
    private suspend fun receiveLoop() {
        while (isRunning) {
            try {
                val frame = withTimeoutOrNull(5000) {
                    transport.receive()
                } ?: continue

                session?.receiveFrame(frame)
                handleIncomingFrame(frame)
            } catch (e: CancellationException) {
                break
            } catch (e: Exception) {
                eventListener.onError(e)
            }
        }
    }

    /**
     * Manejar frame entrante
     */
    private fun handleIncomingFrame(frame: Frame) {
        // Notificar listener
        eventListener.onFrameReceived(frame)

        // Responder a llamada pendiente
        val call = pendingCalls.remove(frame.sequence)
        if (call != null) {
            if (frame.packetType == PacketType.ERROR) {
                call.complete(OperationResult.Error(
                    FrameUtils.getErrorCode(frame),
                    FrameUtils.getErrorMessage(frame)
                ))
            } else {
                call.complete(OperationResult.Success(frame.payload))
            }
        }

        // Notificar streaming channels
        if (mode == ExecutionMode.REAL_TIME && frame.channelId > 0) {
            streamingChannels[frame.channelId]?.let { channel ->
                scope.launch {
                    channel.send(frame)
                }
            }
        }
    }

    // ============================================================================
    // OPERACIONES POR MODO
    // ============================================================================

    /**
     * Operación en modo Message-Response
     */
    public suspend fun request(operationId: OperationId, payload: ByteArray): OperationResult {
        return when (mode) {
            ExecutionMode.MESSAGE_RESPONSE -> {
                val call = OperationCall(operationId, payload)
                pendingCalls[session?.nextSequence() ?: 0] = call

                val frame = Frame(
                    sessionId = session?.id ?: 0,
                    sequence = session?.nextSequence() ?: 0,
                    channelId = 0,
                    operationId = operationId,
                    packetType = PacketType.DATA,
                    payload = payload,
                    flags = FrameFlags(),
                    role = contract.role
                )

                transport.send(frame)

                withTimeout(session?.operationTimeoutMs ?: 30000) {
                    call.result.await()
                } ?: OperationResult.Timeout
            }

            ExecutionMode.FIRE_AND_FORGET -> {
                sendOneWay(operationId, payload)
                OperationResult.Success(ByteArray(0))
            }

            else -> throw ContractException("Operation not supported in $mode mode")
        }
    }

    /**
     * Operación con nombre de operación
     */
    public suspend fun request(operationName: String, payload: ByteArray): OperationResult {
        val op = requireContract().getOperationByName(operationName)
            ?: throw ContractNotFoundException("Operation not found: $operationName")
        return request(OperationId(op.operationId), payload)
    }

    /**
     * Operación con datos serializados
     */
    public suspend inline fun <reified T> requestTyped(
        operationName: String,
        data: T,
        serializer: ContractSerializer
    ): OperationResult {
        val op = requireContract().getOperationByName(operationName)
            ?: throw ContractNotFoundException("Operation not found: $operationName")

        val inputTypeId = op.inputTypeId
            ?: throw ContractException("Operation $operationName has no input")

        val payload = serializer.serialize(data, inputTypeId)
        return request(OperationId(op.operationId), payload)
    }

    /**
     * Enviar y olvidar (modo fire-and-forget)
     */
    public fun sendOneWay(operationId: OperationId, payload: ByteArray) {
        val frame = Frame(
            sessionId = session?.id ?: 0,
            sequence = session?.nextSequence() ?: 0,
            channelId = 0,
            operationId = operationId,
            packetType = PacketType.DATA,
            payload = payload,
            flags = FrameFlags(lastFrame = true),
            role = contract.role
        )

        scope.launch {
            transport.send(frame)
        }
    }

    /**
     * Crear canal multiplexado (modo multiplexing)
     */
    public suspend fun createMultiplexedChannel(): Channel {
        val channel = session?.createChannel(OperationRole.REQUEST_RESPONSE)
            ?: throw ContractException("Session not active")

        return channel
    }

    /**
     * Iniciar streaming (modo real-time)
     */
    public suspend fun startStreaming(operationId: OperationId): Channel {
        if (mode != ExecutionMode.REAL_TIME) {
            throw ContractException("Streaming only available in REAL_TIME mode")
        }

        val channel = session?.createChannel(OperationRole.STREAM_START)
            ?: throw ContractException("Session not active")

        streamingChannels[channel.id] = channel

        // Enviar frame de inicio de stream
        val frame = Frame(
            sessionId = session?.id ?: 0,
            sequence = session?.nextSequence() ?: 0,
            channelId = channel.id,
            operationId = operationId,
            packetType = PacketType.DATA,
            payload = ByteArray(0),
            flags = FrameFlags(streaming = true),
            role = contract.role
        )

        transport.send(frame)

        return channel
    }

    /**
     * Enviar datos a stream
     */
    public suspend fun sendToStream(channelId: Int, data: ByteArray, lastFrame: Boolean = false) {
        val channel = streamingChannels[channelId]
            ?: throw ContractNotFoundException("Stream channel $channelId not found")

        val frame = Frame(
            sessionId = session?.id ?: 0,
            sequence = session?.nextSequence() ?: 0,
            channelId = channelId,
            operationId = OperationId(0),  // Continuation
            packetType = PacketType.DATA,
            payload = data,
            flags = FrameFlags(streaming = true, lastFrame = lastFrame),
            role = contract.role
        )

        transport.send(frame)
    }

    /**
     * Pausar stream
     */
    public fun pauseStream(channelId: Int) {
        streamingChannels[channelId]?.pause()
    }

    /**
     * Reanudar stream
     */
    public fun resumeStream(channelId: Int) {
        streamingChannels[channelId]?.resume()
    }

    /**
     * Terminar stream
     */
    public fun endStream(channelId: Int) {
        val channel = streamingChannels.remove(channelId)
        channel?.close()
    }

    // ============================================================================
    // GESTIÓN DE SESIÓN
    // ============================================================================

    /**
     * Verificar si está conectado
     */
    public fun isConnected(): Boolean = isRunning && transport.isConnected

    /**
     * Obtener sesión activa
     */
    public fun getSession(): ContractSession? = session

    /**
     * Establecer listener de eventos
     */
    public fun setEventListener(listener: IpcEventListener) {
        this.eventListener = listener
    }

    /**
     * Ping para mantener alive
     */
    public suspend fun ping(): Boolean {
        if (!isRunning) return false

        val frame = Frame(
            sessionId = session?.id ?: 0,
            sequence = session?.nextSequence() ?: 0,
            channelId = 0,
            operationId = OperationId.PING,
            packetType = PacketType.HEARTBEAT,
            payload = ByteArray(0),
            flags = FrameFlags(),
            role = contract.role
        )

        transport.send(frame)
        return true
    }

    /**
     * Cerrar conexión
     */
    public fun close() {
        isRunning = false
        streamingChannels.values.forEach { it.close() }
        streamingChannels.clear()
        session?.close()
        transport.close()
        scope.cancel()
    }
}

// ============================================================================
// LISTENER DE EVENTOS
// ============================================================================

/**
 * Listener para eventos del cliente IPC
 */
public interface IpcEventListener {
    public fun onFrameReceived(frame: Frame)
    public fun onError(error: Throwable)
    public fun onDisconnect()
    public fun onReconnect()
}

/**
 * Adaptador por defecto para IpcEventListener
 */
public open class IpcEventListenerAdapter : IpcEventListener {
    override fun onFrameReceived(frame: Frame) {}
    override fun onError(error: Throwable) {}
    override fun onDisconnect() {}
    override fun onReconnect() {}
}

// ============================================================================
// BUILDER DE CLIENTE
// ============================================================================

/**
 * Builder para crear cliente IPC
 */
public class IpcClientBuilder {
    private var contractPath: String? = null
    private var contract: Contract? = null
    private var socketPath: String? = null
    private var host: String? = null
    private var port: Int? = null
    private var seed: ByteArray = ByteArray(0)
    private var mode: ExecutionMode = ExecutionMode.MESSAGE_RESPONSE
    private var eventListener: IpcEventListener = IpcEventListenerAdapter()

    public fun contract(path: String): IpcClientBuilder {
        this.contractPath = path
        return this
    }

    public fun contract(contract: Contract): IpcClientBuilder {
        this.contract = contract
        return this
    }

    public fun unixSocket(path: String): IpcClientBuilder {
        this.socketPath = path
        return this
    }

    public fun tcp(host: String, port: Int): IpcClientBuilder {
        this.host = host
        this.port = port
        return this
    }

    public fun seed(seed: ByteArray): IpcClientBuilder {
        this.seed = seed
        return this
    }

    public fun seed(seed: String): IpcClientBuilder {
        this.seed = seed.toByteArray(Charsets.UTF_8)
        return this
    }

    public fun mode(mode: ExecutionMode): IpcClientBuilder {
        this.mode = mode
        return this
    }

    public fun eventListener(listener: IpcEventListener): IpcClientBuilder {
        this.eventListener = listener
        return this
    }

    public fun build(): IpcClient {
        val c = contract ?: contractPath?.let { Contract.load(it) }
            ?: throw ContractException("Contract is required")

        val transport = when {
            socketPath != null -> UnixSocketTransport(socketPath!!)
            host != null && port != null -> TcpTransport(host!!, port!!)
            else -> throw ContractException("Transport not configured")
        }

        return IpcClient(transport, c, seed, mode).also {
            it.setEventListener(eventListener)
        }
    }
}

// ============================================================================
// TCP TRANSPORT (Placeholder)
// ============================================================================

public class TcpTransport(private val host: String, private val port: Int) : Transport {
    private var connected = false

    override val isConnected: Boolean get() = connected

    override suspend fun send(frame: Frame) {
        throw NotImplementedError("TcpTransport requires native implementation")
    }

    override suspend fun receive(): Frame {
        throw NotImplementedError("TcpTransport requires native implementation")
    }

    override fun close() {
        connected = false
    }
}
