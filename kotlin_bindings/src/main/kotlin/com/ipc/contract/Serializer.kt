package com.ipc.contract

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Serializador de datos para el protocolo CBC
 * Convierte tipos Kotlin a bytes y viceversa
 */

// ============================================================================
// SERIALIZADOR
// ============================================================================

/**
 * Serializador para codificar/decodificar datos según el contrato
 */
public class ContractSerializer(private val contract: Contract) {

    /**
     * Serializar valor a bytes según tipo
     */
    public fun serialize(value: Any?, typeId: Short): ByteArray {
        return when (PrimitiveType.fromId(typeId)) {
            PrimitiveType.U8 -> byteArrayOf(value as Byte)
            PrimitiveType.U16 -> {
                val buffer = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN)
                buffer.putShort(value as Short)
                buffer.array()
            }
            PrimitiveType.U32 -> {
                val buffer = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
                buffer.putInt((value as Number).toInt())
                buffer.array()
            }
            PrimitiveType.U64 -> {
                val buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN)
                buffer.putLong((value as Number).toLong())
                buffer.array()
            }
            PrimitiveType.I8 -> byteArrayOf(value as Byte)
            PrimitiveType.I16 -> {
                val buffer = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN)
                buffer.putShort(value as Short)
                buffer.array()
            }
            PrimitiveType.I32 -> {
                val buffer = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
                buffer.putInt((value as Number).toInt())
                buffer.array()
            }
            PrimitiveType.I64 -> {
                val buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN)
                buffer.putLong((value as Number).toLong())
                buffer.array()
            }
            PrimitiveType.F32 -> {
                val buffer = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
                buffer.putFloat((value as Number).toFloat())
                buffer.array()
            }
            PrimitiveType.F64 -> {
                val buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN)
                buffer.putDouble((value as Number).toDouble())
                buffer.array()
            }
            PrimitiveType.BOOL -> byteArrayOf(if (value as Boolean) 1 else 0)
            PrimitiveType.STRING -> serializeString(value as String)
            PrimitiveType.BYTES -> serializeBytes(value as ByteArray)
        }
    }

    /**
     * Deserializar bytes a valor según tipo
     */
    public fun deserialize(data: ByteArray, typeId: Short): Any? {
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)

        return when (PrimitiveType.fromId(typeId)) {
            PrimitiveType.U8 -> buffer.get()
            PrimitiveType.U16 -> buffer.short.toUShort().toByte()
            PrimitiveType.U32 -> buffer.int.toUInt().toInt().toByte()
            PrimitiveType.U64 -> buffer.long.toULong().toLong().toByte()
            PrimitiveType.I8 -> buffer.get()
            PrimitiveType.I16 -> buffer.short
            PrimitiveType.I32 -> buffer.int
            PrimitiveType.I64 -> buffer.long
            PrimitiveType.F32 -> buffer.float
            PrimitiveType.F64 -> buffer.double
            PrimitiveType.BOOL -> buffer.get().toInt() != 0
            PrimitiveType.STRING -> deserializeString(data)
            PrimitiveType.BYTES -> deserializeBytes(data)
        }
    }

    /**
     * Serializar struct a bytes
     */
    public fun serializeStruct(values: Map<String, Any?>, typeId: Short): ByteArray {
        val type = contract.getType(typeId) ?: throw ContractNotFoundException("Type $typeId not found")

        val kind = type.kind as? TypeKind.Struct
            ?: throw ContractSerializationException("Type $typeId is not a struct")

        val buffer = ByteBuffer.allocate(guessStructSize(values, kind))
            .order(ByteOrder.BIG_ENDIAN)

        for (field in kind.fields) {
            val value = values[field.name]
            buffer.put(serialize(value, field.typeId))
        }

        return buffer.array()
    }

    /**
     * Deserializar struct desde bytes
     */
    public fun deserializeStruct(data: ByteArray, typeId: Short): Map<String, Any?> {
        val type = contract.getType(typeId) ?: throw ContractNotFoundException("Type $typeId not found")

        val kind = type.kind as? TypeKind.Struct
            ?: throw ContractDeserializationException("Type $typeId is not a struct")

        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        val result = mutableMapOf<String, Any?>()

        for (field in kind.fields) {
            val fieldSize = getPrimitiveSize(field.typeId)
            val fieldData = if (fieldSize > 0) {
                val arr = ByteArray(fieldSize)
                buffer.get(arr)
                arr
            } else {
                // Variable size - need length prefix
                val length = buffer.int
                val arr = ByteArray(length)
                buffer.get(arr)
                arr
            }
            result[field.name] = deserialize(fieldData, field.typeId)
        }

        return result
    }

    /**
     * Serializar enum a bytes
     */
    public fun serializeEnum(variantName: String, associatedValue: Any?, typeId: Short): ByteArray {
        val type = contract.getType(typeId) ?: throw ContractNotFoundException("Type $typeId not found")

        val kind = type.kind as? TypeKind.Enum
            ?: throw ContractSerializationException("Type $typeId is not an enum")

        val variantIndex = kind.variants.indexOfFirst { it.name == variantName }
        if (variantIndex < 0) throw ContractSerializationException("Unknown variant: $variantName")

        val variant = kind.variants[variantIndex]
        val buffer = ByteBuffer.allocate(1 + (if (variant.associatedTypeId != null) 64 else 0))
            .order(ByteOrder.BIG_ENDIAN)

        buffer.put(variantIndex.toByte())

        if (variant.associatedTypeId != null && associatedValue != null) {
            buffer.put(serialize(associatedValue, variant.associatedTypeId))
        }

        return buffer.array()
    }

    /**
     * Deserializar enum desde bytes
     */
    public fun deserializeEnum(data: ByteArray, typeId: Short): Pair<String, Any?> {
        val type = contract.getType(typeId) ?: throw ContractNotFoundException("Type $typeId not found")

        val kind = type.kind as? TypeKind.Enum
            ?: throw ContractDeserializationException("Type $typeId is not an enum")

        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        val variantIndex = buffer.get().toInt()

        if (variantIndex < 0 || variantIndex >= kind.variants.size) {
            throw ContractDeserializationException("Invalid variant index: $variantIndex")
        }

        val variant = kind.variants[variantIndex]
        val associatedValue = if (variant.associatedTypeId != null) {
            val remaining = data.copyOfRange(1, data.size)
            deserialize(remaining, variant.associatedTypeId)
        } else null

        return Pair(variant.name, associatedValue)
    }

    /**
     * Serializar array a bytes
     */
    public fun serializeArray(values: List<Any?>, elementTypeId: Short): ByteArray {
        val elementSize = getPrimitiveSize(elementTypeId)
        val count = values.size

        val totalSize = if (elementSize > 0) {
            4 + count * elementSize
        } else {
            // Variable size elements
            4 + values.sumOf { getSerializedSize(it, elementTypeId) }
        }

        val buffer = ByteBuffer.allocate(totalSize).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(count)

        for (value in values) {
            if (elementSize > 0) {
                buffer.put(serialize(value, elementTypeId))
            } else {
                val elementBytes = serialize(value, elementTypeId)
                buffer.putInt(elementBytes.size)
                buffer.put(elementBytes)
            }
        }

        return buffer.array()
    }

    /**
     * Deserializar array desde bytes
     */
    public fun deserializeArray(data: ByteArray, elementTypeId: Short): List<Any?> {
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        val count = buffer.int
        val elementSize = getPrimitiveSize(elementTypeId)

        val result = mutableListOf<Any?>()
        repeat(count) {
            if (elementSize > 0) {
                val elementData = ByteArray(elementSize)
                buffer.get(elementData)
                result.add(deserialize(elementData, elementTypeId))
            } else {
                val length = buffer.int
                val elementData = ByteArray(length)
                buffer.get(elementData)
                result.add(deserialize(elementData, elementTypeId))
            }
        }

        return result
    }

    // ============================================================================
    // HELPERS
    // ============================================================================

    private fun serializeString(value: String): ByteArray {
        val bytes = value.toByteArray(Charsets.UTF_8)
        val buffer = ByteBuffer.allocate(4 + bytes.size).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(bytes.size)
        buffer.put(bytes)
        return buffer.array()
    }

    private fun deserializeString(data: ByteArray): String {
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        val length = buffer.int
        val bytes = ByteArray(length)
        buffer.get(bytes)
        return String(bytes, Charsets.UTF_8)
    }

    private fun serializeBytes(value: ByteArray): ByteArray {
        val buffer = ByteBuffer.allocate(4 + value.size).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(value.size)
        buffer.put(value)
        return buffer.array()
    }

    private fun deserializeBytes(data: ByteArray): ByteArray {
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        val length = buffer.int
        val bytes = ByteArray(length)
        buffer.get(bytes)
        return bytes
    }

    private fun getPrimitiveSize(typeId: Short): Int {
        return try {
            PrimitiveType.fromId(typeId).size
        } catch (e: ContractParseException) {
            -1  // Not a primitive
        }
    }

    private fun getSerializedSize(value: Any?, typeId: Short): Int {
        return when (PrimitiveType.fromId(typeId)) {
            PrimitiveType.STRING -> 4 + (value as String).toByteArray().size
            PrimitiveType.BYTES -> 4 + (value as ByteArray).size
            else -> getPrimitiveSize(typeId)
        }
    }

    private fun guessStructSize(values: Map<String, Any?>, kind: TypeKind.Struct): Int {
        var size = 0
        for (field in kind.fields) {
            val value = values[field.name]
            if (value != null) {
                size += getSerializedSize(value, field.typeId)
            }
        }
        return maxOf(size, 64)  // Minimum size
    }
}

// ============================================================================
// BUILDER DE MENSAJES
// ============================================================================

/**
 * Builder para crear mensajes de operación
 */
public class MessageBuilder(private val contract: Contract) {
    private val serializer = ContractSerializer(contract)
    private var operationId: Short = 0
    private var channelId: Int = 0
    private var payload: ByteArray = ByteArray(0)
    private var packetType: PacketType = PacketType.DATA

    public fun operation(id: Short): MessageBuilder {
        this.operationId = id
        return this
    }

    public fun operation(name: String): MessageBuilder {
        val op = contract.getOperationByName(name)
            ?: throw ContractNotFoundException("Operation not found: $name")
        this.operationId = op.operationId
        return this
    }

    public fun channel(id: Int): MessageBuilder {
        this.channelId = id
        return this
    }

    public fun packetType(type: PacketType): MessageBuilder {
        this.packetType = type
        return this
    }

    public fun payload(data: ByteArray): MessageBuilder {
        this.payload = data
        return this
    }

    public fun payload(value: Any?, typeId: Short): MessageBuilder {
        this.payload = serializer.serialize(value, typeId)
        return this
    }

    public fun payloadStruct(values: Map<String, Any?>, typeId: Short): MessageBuilder {
        this.payload = serializer.serializeStruct(values, typeId)
        return this
    }

    public fun payloadArray(values: List<Any?>, elementTypeId: Short): MessageBuilder {
        this.payload = serializer.serializeArray(values, elementTypeId)
        return this
    }

    public fun build(sessionId: Long, sequence: Long): Frame {
        return Frame(
            sessionId = sessionId,
            sequence = sequence,
            channelId = channelId,
            operationId = OperationId(operationId),
            packetType = packetType,
            payload = payload
        )
    }
}

// ============================================================================
// UTILIDADES DE SERIALIZACIÓN
// ============================================================================

/**
 * Utilidades para serialización de tipos comunes
 */
public object SerializationUtils {

    /**
     * Codificar string UTF-8 con longitud prefix
     */
    public fun encodeString(value: String): ByteArray {
        val bytes = value.toByteArray(Charsets.UTF_8)
        val buffer = ByteBuffer.allocate(4 + bytes.size).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(bytes.size)
        buffer.put(bytes)
        return buffer.array()
    }

    /**
     * Decodificar string UTF-8 con longitud prefix
     */
    public fun decodeString(data: ByteArray): String {
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        val length = buffer.int
        val bytes = ByteArray(length)
        buffer.get(bytes)
        return String(bytes, Charsets.UTF_8)
    }

    /**
     * Codificar bytes con longitud prefix
     */
    public fun encodeBytes(value: ByteArray): ByteArray {
        val buffer = ByteBuffer.allocate(4 + value.size).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(value.size)
        buffer.put(value)
        return buffer.array()
    }

    /**
     * Decodificar bytes con longitud prefix
     */
    public fun decodeBytes(data: ByteArray): ByteArray {
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        val length = buffer.int
        val bytes = ByteArray(length)
        buffer.get(bytes)
        return bytes
    }

    /**
     * Codificar entero 64-bit big-endian
     */
    public fun encodeI64(value: Long): ByteArray {
        val buffer = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN)
        buffer.putLong(value)
        return buffer.array()
    }

    /**
     * Decodificar entero 64-bit big-endian
     */
    public fun decodeI64(data: ByteArray): Long {
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        return buffer.long
    }

    /**
     * Codificar entero 32-bit big-endian
     */
    public fun encodeI32(value: Int): ByteArray {
        val buffer = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(value)
        return buffer.array()
    }

    /**
     * Decodificar entero 32-bit big-endian
     */
    public fun decodeI32(data: ByteArray): Int {
        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        return buffer.int
    }

    /**
     * Calcular hash SHA-256
     */
    public fun sha256(data: ByteArray): ByteArray {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }

    /**
     * Calcular HMAC-SHA256
     */
    public fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        val secretKey = javax.crypto.spec.SecretKeySpec(key, "HmacSHA256")
        mac.init(secretKey)
        return mac.doFinal(data)
    }
}
