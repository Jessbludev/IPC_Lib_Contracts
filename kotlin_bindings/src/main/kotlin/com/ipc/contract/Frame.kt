package com.ipc.contract

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Frame del protocolo wire v2
 * Comunicación entre procesos via Unix Domain Sockets
 */

// ============================================================================
// ID DE OPERACIÓN
// ============================================================================

/**
 * ID numérico de operación (0x0001 - 0xFFFF)
 */
@kotlin.jvm.JvmInline
public value class OperationId(public val value: Short) {
    public companion object {
        public val HANDSHAKE: OperationId = OperationId(ProtocolConstants.OP_HANDSHAKE)
        public val AUTH: OperationId = OperationId(ProtocolConstants.OP_AUTH)
        public val PING: OperationId = OperationId(ProtocolConstants.OP_PING)
        public val SESSION_START: OperationId = OperationId(ProtocolConstants.OP_SESSION_START)
        public val SESSION_END: OperationId = OperationId(ProtocolConstants.OP_SESSION_END)

        public fun fromShort(value: Short): OperationId = OperationId(value)
    }

    public fun toShort(): Short = value
}

// ============================================================================
// FLAGS DE FRAME
// ============================================================================

/**
 * Flags del frame
 */
public data class FrameFlags(
    public var compressed: Boolean = false,
    public var encrypted: Boolean = false,
    public var authenticated: Boolean = false,
    public var streaming: Boolean = false,
    public var lastFrame: Boolean = false
) {
    public fun toByte(): Byte {
        var flags = 0
        if (compressed) flags = flags or 0x01
        if (encrypted) flags = flags or 0x02
        if (authenticated) flags = flags or 0x04
        if (streaming) flags = flags or 0x08
        if (lastFrame) flags = flags or 0x10
        return flags.toByte()
    }

    public companion object {
        public fun fromByte(value: Byte): FrameFlags {
            val flags = value.toInt()
            return FrameFlags(
                compressed = (flags and 0x01) != 0,
                encrypted = (flags and 0x02) != 0,
                authenticated = (flags and 0x04) != 0,
                streaming = (flags and 0x08) != 0,
                lastFrame = (flags and 0x10) != 0
            )
        }
    }
}

// ============================================================================
// FRAME
// ============================================================================

/**
 * Frame del protocolo wire (64 bytes de header)
 *
 * Estructura:
 * - Magic: 4 bytes ("CBC1")
 * - Version: 1 byte
 * - Flags: 1 byte
 * - Packet Type: 1 byte
 * - Role: 1 byte
 * - Session ID: 8 bytes
 * - Sequence: 8 bytes
 * - Channel ID: 4 bytes
 * - Operation ID: 2 bytes
 * - Payload Length: 4 bytes
 * - Schema ID: 2 bytes
 * - Contract Hash Prefix: 12 bytes
 * - Nonce: 12 bytes
 * - Reserved: 4 bytes
 */
public class Frame(
    public var sessionId: Long,
    public var sequence: Long,
    public var channelId: Int,
    public var operationId: OperationId,
    public var packetType: PacketType,
    public var payload: ByteArray,
    public var flags: FrameFlags = FrameFlags(),
    public var role: ContractRole = ContractRole.MUTUAL,
    public var schemaId: Short = 0,
    public var contractHashPrefix: ByteArray = ByteArray(12),
    public var nonce: ByteArray = ByteArray(ProtocolConstants.NONCE_SIZE)
) {
    public companion object {
        public const val HEADER_SIZE: Int = ProtocolConstants.FRAME_HEADER_SIZE

        /**
         * Crear frame desde bytes
         */
        public fun parse(data: ByteArray): Frame {
            require(data.size >= HEADER_SIZE) { "Frame too short: ${data.size} < $HEADER_SIZE" }

            val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)

            // Magic (4 bytes)
            val magic = ByteArray(4)
            buffer.get(magic)
            if (String(magic) != ProtocolConstants.MAGIC) {
                throw ContractParseException("Invalid frame magic: ${String(magic)}")
            }

            // Version (1 byte)
            val version = buffer.get()
            if (version != ProtocolConstants.PROTOCOL_VERSION) {
                throw ContractParseException("Unsupported protocol version: $version")
            }

            // Flags (1 byte)
            val flags = FrameFlags.fromByte(buffer.get())

            // Packet Type (1 byte)
            val packetType = PacketType.fromValue(buffer.get())

            // Role (1 byte)
            val role = ContractRole.fromValue(buffer.get())

            // Session ID (8 bytes)
            val sessionId = buffer.long

            // Sequence (8 bytes)
            val sequence = buffer.long

            // Channel ID (4 bytes)
            val channelId = buffer.int

            // Operation ID (2 bytes)
            val operationId = OperationId(buffer.short)

            // Payload Length (4 bytes)
            val payloadLength = buffer.int

            // Schema ID (2 bytes)
            val schemaId = buffer.short

            // Contract Hash Prefix (12 bytes)
            val hashPrefix = ByteArray(12)
            buffer.get(hashPrefix)

            // Nonce (12 bytes)
            val nonce = ByteArray(ProtocolConstants.NONCE_SIZE)
            buffer.get(nonce)

            // Reserved (4 bytes)
            buffer.int

            // Payload
            val payload = if (payloadLength > 0) {
                val payloadData = data.copyOfRange(HEADER_SIZE, HEADER_SIZE + payloadLength)
                payloadData
            } else ByteArray(0)

            return Frame(
                sessionId = sessionId,
                sequence = sequence,
                channelId = channelId,
                operationId = operationId,
                packetType = packetType,
                payload = payload,
                flags = flags,
                role = role,
                schemaId = schemaId,
                contractHashPrefix = hashPrefix,
                nonce = nonce
            )
        }
    }

    /**
     * Serializar frame a bytes
     */
    public fun toByteArray(): ByteArray {
        val totalSize = HEADER_SIZE + payload.size
        val buffer = ByteBuffer.allocate(totalSize).order(ByteOrder.BIG_ENDIAN)

        // Magic (4 bytes)
        buffer.put(ProtocolConstants.MAGIC.toByteArray(Charsets.US_ASCII))

        // Version (1 byte)
        buffer.put(ProtocolConstants.PROTOCOL_VERSION)

        // Flags (1 byte)
        buffer.put(flags.toByte())

        // Packet Type (1 byte)
        buffer.put(packetType.value)

        // Role (1 byte)
        buffer.put(role.value)

        // Session ID (8 bytes)
        buffer.putLong(sessionId)

        // Sequence (8 bytes)
        buffer.putLong(sequence)

        // Channel ID (4 bytes)
        buffer.putInt(channelId)

        // Operation ID (2 bytes)
        buffer.putShort(operationId.toShort())

        // Payload Length (4 bytes)
        buffer.putInt(payload.size)

        // Schema ID (2 bytes)
        buffer.putShort(schemaId)

        // Contract Hash Prefix (12 bytes)
        buffer.put(contractHashPrefix)

        // Nonce (12 bytes)
        buffer.put(nonce)

        // Reserved (4 bytes)
        buffer.putInt(0)

        // Payload
        if (payload.isNotEmpty()) {
            buffer.put(payload)
        }

        return buffer.array()
    }

    /**
     * Obtener payload como string UTF-8
     */
    public fun getPayloadAsString(): String {
        return String(payload, Charsets.UTF_8)
    }

    /**
     * Establecer payload desde string UTF-8
     */
    public fun setPayloadFromString(value: String) {
        this.payload = value.toByteArray(Charsets.UTF_8)
    }

    /**
     * Verificar si es el último frame de una secuencia
     */
    public fun isLastFrame(): Boolean = flags.lastFrame

    /**
     * Verificar si es frame de datos
     */
    public fun isDataFrame(): Boolean = packetType == PacketType.DATA

    /**
     * Verificar si es frame de control
     */
    public fun isControlFrame(): Boolean = packetType == PacketType.CONTROL

    /**
     * Marcar como último frame
     */
    public fun markAsLastFrame(): Frame {
        this.flags = this.flags.copy(lastFrame = true)
        return this
    }

    /**
     * Crear frame de error
     */
    public fun createErrorFrame(errorCode: Int, errorMessage: String): Frame {
        val errorPayload = ByteBuffer.allocate(8 + errorMessage.length)
            .order(ByteOrder.BIG_ENDIAN)
            .putInt(errorCode)
            .put(errorMessage.toByteArray(Charsets.UTF_8))

        return Frame(
            sessionId = sessionId,
            sequence = sequence + 1,
            channelId = channelId,
            operationId = operationId,
            packetType = PacketType.ERROR,
            payload = errorPayload.array(),
            flags = FrameFlags(),
            role = role
        )
    }

    /**
     * Crear frame de acknowledgment
     */
    public fun createAckFrame(): Frame {
        return Frame(
            sessionId = sessionId,
            sequence = sequence,
            channelId = channelId,
            operationId = operationId,
            packetType = PacketType.CONTROL,
            payload = byteArrayOf(0x01),  // ACK
            flags = FrameFlags(),
            role = role
        )
    }

    /**
     * Crear frame de heartbeat
     */
    public fun createHeartbeatFrame(): Frame {
        return Frame(
            sessionId = sessionId,
            sequence = sequence,
            channelId = 0,
            operationId = OperationId.PING,
            packetType = PacketType.HEARTBEAT,
            payload = ByteArray(0),
            flags = FrameFlags(),
            role = role
        )
    }

    /**
     * Crear frame de EOF
     */
    public fun createEofFrame(): Frame {
        return Frame(
            sessionId = sessionId,
            sequence = sequence,
            channelId = channelId,
            operationId = operationId,
            packetType = PacketType.EOF,
            payload = ByteArray(0),
            flags = flags.copy(lastFrame = true),
            role = role
        )
    }
}

// ============================================================================
// TIPOS DE ERROR
// ============================================================================

/**
 * Códigos de error del protocolo
 */
public enum class ProtocolError(val code: Int, val message: String) {
    // Errores de protocolo (0x01-0x1F)
    INVALID_MAGIC(0x01, "Invalid magic bytes"),
    INVALID_VERSION(0x02, "Unsupported protocol version"),
    INVALID_PACKET_TYPE(0x03, "Invalid packet type"),
    PAYLOAD_TOO_LARGE(0x04, "Payload exceeds maximum size"),
    INVALID_SEQUENCE(0x05, "Invalid sequence number"),

    // Errores de contrato (0x20-0x3F)
    CONTRACT_NOT_FOUND(0x20, "Contract not found"),
    CONTRACT_HASH_MISMATCH(0x21, "Contract hash mismatch"),
    CONTRACT_SIGNATURE_INVALID(0x22, "Invalid contract signature"),
    TYPE_NOT_FOUND(0x23, "Type not found in contract"),
    OPERATION_NOT_FOUND(0x24, "Operation not found in contract"),
    INVALID_PAYLOAD(0x25, "Invalid payload format"),

    // Errores de sesión (0x40-0x5F)
    SESSION_NOT_FOUND(0x40, "Session not found"),
    SESSION_EXPIRED(0x41, "Session has expired"),
    CHANNEL_NOT_FOUND(0x42, "Channel not found"),
    CHANNEL_CLOSED(0x43, "Channel is closed"),
    SEQUENCE_GAP(0x44, "Sequence number gap detected"),

    // Errores de seguridad (0x60-0x7F)
    AUTHENTICATION_REQUIRED(0x60, "Authentication is required"),
    AUTHENTICATION_FAILED(0x61, "Authentication failed"),
    ENCRYPTION_REQUIRED(0x62, "Encryption is required"),
    DECRYPTION_FAILED(0x63, "Decryption failed"),
    REPLAY_DETECTED(0x64, "Replay attack detected"),
    INVALID_NONCE(0x65, "Invalid nonce"),
    HMAC_INVALID(0x66, "HMAC verification failed"),

    // Errores de operación (0x80-0x9F)
    OPERATION_TIMEOUT(0x80, "Operation timed out"),
    OPERATION_NOT_SUPPORTED(0x81, "Operation not supported"),
    INVALID_STATE(0x82, "Invalid operation state"),
    BUFFER_OVERFLOW(0x83, "Buffer overflow detected"),

    // Errores internos (0xE0-0xFF)
    INTERNAL_ERROR(0xE0, "Internal error"),
    TRANSPORT_ERROR(0xE1, "Transport layer error"),
    OUT_OF_MEMORY(0xE2, "Out of memory");

    public companion object {
        public fun fromCode(code: Int): ProtocolError {
            return entries.find { it.code == code } ?: INTERNAL_ERROR
        }
    }
}

// ============================================================================
// UTILIDADES DE FRAME
// ============================================================================

/**
 * Utilidades para trabajar con frames
 */
public object FrameUtils {

    /**
     * Crear frame de handshake inicial
     */
    public fun createHandshakeFrame(
        contractHash: ByteArray,
        protocolVersion: Byte = ProtocolConstants.PROTOCOL_VERSION
    ): Frame {
        val payload = ByteBuffer.allocate(13)
            .order(ByteOrder.BIG_ENDIAN)
            .put(protocolVersion)
            .put(contractHash.copyOf(12))
            .array()

        return Frame(
            sessionId = 0,
            sequence = 0,
            channelId = 0,
            operationId = OperationId.HANDSHAKE,
            packetType = PacketType.CONTROL,
            payload = payload,
            flags = FrameFlags(),
            role = ContractRole.MUTUAL,
            contractHashPrefix = contractHash.copyOf(12)
        )
    }

    /**
     * Crear frame de autenticación
     */
    public fun createAuthFrame(
        sessionId: Long,
        token: ByteArray,
        contractHash: ByteArray
    ): Frame {
        val payload = ByteBuffer.allocate(token.size + 12)
            .order(ByteOrder.BIG_ENDIAN)
            .put(token)
            .put(contractHash.copyOf(12))
            .array()

        return Frame(
            sessionId = sessionId,
            sequence = 1,
            channelId = 0,
            operationId = OperationId.AUTH,
            packetType = PacketType.CONTROL,
            payload = payload,
            flags = FrameFlags(authenticated = true),
            role = ContractRole.MUTUAL,
            contractHashPrefix = contractHash.copyOf(12)
        )
    }

    /**
     * Crear frame de inicio de sesión
     */
    public fun createSessionStartFrame(
        contractHash: ByteArray,
        role: ContractRole
    ): Frame {
        val payload = ByteBuffer.allocate(13)
            .order(ByteOrder.BIG_ENDIAN)
            .put(role.value)
            .put(contractHash.copyOf(12))
            .array()

        return Frame(
            sessionId = 0,
            sequence = 0,
            channelId = 0,
            operationId = OperationId.SESSION_START,
            packetType = PacketType.CONTROL,
            payload = payload,
            flags = FrameFlags(),
            role = role,
            contractHashPrefix = contractHash.copyOf(12)
        )
    }

    /**
     * Parsear payload de handshake
     */
    public fun parseHandshakeResponse(frame: Frame): Pair<Byte, ByteArray> {
        val buffer = ByteBuffer.wrap(frame.payload).order(ByteOrder.BIG_ENDIAN)
        val acceptedVersion = buffer.get()
        val sessionId = buffer.long
        return Pair(acceptedVersion, byteArrayOf(sessionId.toByte()))
    }

    /**
     * Verificar que el frame es un handshake válido
     */
    public fun isValidHandshake(frame: Frame): Boolean {
        return frame.operationId == OperationId.HANDSHAKE &&
                frame.packetType == PacketType.CONTROL &&
                frame.payload.size >= 13
    }

    /**
     * Verificar que el frame es un error
     */
    public fun isErrorFrame(frame: Frame): Boolean {
        return frame.packetType == PacketType.ERROR
    }

    /**
     * Extraer código de error del frame
     */
    public fun getErrorCode(frame: Frame): Int {
        if (!isErrorFrame(frame) || frame.payload.size < 4) return -1
        val buffer = ByteBuffer.wrap(frame.payload).order(ByteOrder.BIG_ENDIAN)
        return buffer.int
    }

    /**
     * Extraer mensaje de error del frame
     */
    public fun getErrorMessage(frame: Frame): String {
        if (!isErrorFrame(frame)) return ""
        val buffer = ByteBuffer.wrap(frame.payload).order(ByteOrder.BIG_ENDIAN)
        buffer.int  // Skip error code
        val messageBytes = frame.payload.copyOfRange(4, frame.payload.size)
        return String(messageBytes, Charsets.UTF_8)
    }
}
