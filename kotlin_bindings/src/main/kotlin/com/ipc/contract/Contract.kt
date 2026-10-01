package com.ipc.contract

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.experimental.xor

/**
 * Canonical Binary Contract - Kotlin Bindings
 *
 * Comunicación inter-proceso sin FFI entre Kotlin y Rust/CPP/Zig
 * via contratos binarios canónicos y sockets Unix.
 */

// ============================================================================
// CONSTANTES DEL PROTOCOLO
// ============================================================================

public object ProtocolConstants {
    public const val MAGIC: String = "CBC1"
    public const val FORMAT_VERSION: Byte = 1
    public const val PROTOCOL_VERSION: Byte = 2

    public const val HEADER_SIZE: Int = 256
    public const val FRAME_HEADER_SIZE: Int = 64
    public const val HASH_SIZE: Int = 32
    public const val SIGNATURE_SIZE: Int = 64
    public const val NONCE_SIZE: Int = 12

    // Tipos primitivos
    public const val TYPE_U8: Short = 0x0001
    public const val TYPE_U16: Short = 0x0002
    public const val TYPE_U32: Short = 0x0003
    public const val TYPE_U64: Short = 0x0004
    public const val TYPE_I8: Short = 0x0005
    public const val TYPE_I16: Short = 0x0006
    public const val TYPE_I32: Short = 0x0007
    public const val TYPE_I64: Short = 0x0008
    public const val TYPE_F32: Short = 0x0009
    public const val TYPE_F64: Short = 0x000A
    public const val TYPE_BOOL: Short = 0x000B
    public const val TYPE_STRING: Short = 0x000C
    public const val TYPE_BYTES: Short = 0x000D

    // Operaciones reservadas
    public const val OP_HANDSHAKE: Short = 0x0000
    public const val OP_AUTH: Short = 0x0001
    public const val OP_PING: Short = 0x0002
    public const val OP_SESSION_START: Short = 0x0003
    public const val OP_SESSION_END: Short = 0x0004

    // Roles de contrato
    public const val ROLE_CHILD: Byte = 0x01
    public const val ROLE_MUTUAL: Byte = 0x02
    public const val ROLE_PEER: Byte = 0x03
    public const val ROLE_MUX: Byte = 0x04
    public const val ROLE_STREAM: Byte = 0x05
    public const val ROLE_ONEWAY: Byte = 0x06

    // Tipos de paquete
    public const val PKT_DATA: Byte = 0x01
    public const val PKT_CONTROL: Byte = 0x02
    public const val PKT_ERROR: Byte = 0x03
    public const val PKT_EOF: Byte = 0x04
    public const val PKT_HEARTBEAT: Byte = 0x05
}

// ============================================================================
// EXCEPCIONES
// ============================================================================

public open class ContractException(message: String, cause: Throwable? = null) : Exception(message, cause)
public class ContractParseException(message: String) : ContractException(message)
public class ContractVerificationException(message: String) : ContractException(message)
public class ContractSecurityException(message: String) : ContractException(message)
public class ContractSerializationException(message: String) : ContractException(message)
public class ContractDeserializationException(message: String) : ContractException(message)
public class ContractNotFoundException(message: String) : ContractException(message)
public class ContractTimeoutException(message: String) : ContractException(message)

// ============================================================================
// FLAGS
// ============================================================================

/**
 * Flags del contrato
 */
@kotlin.annotation.Target(AnnotationTarget.CLASS, AnnotationTarget.PROPERTY)
@kotlin.annotation.Retention(AnnotationRetention.SOURCE)
public annotation class ContractFlag(val value: Int)

public object ContractFlags {
    public const val SIGNED: Int = 0x01
    public const val ENCRYPTED: Int = 0x02
    public const val AUTHENTICATED: Int = 0x04
    public const val REPLAY_PROTECTED: Int = 0x08
    public const val COMPRESSED: Int = 0x10
}

/**
 * Flags de operación
 */
@kotlin.annotation.Target(AnnotationTarget.CLASS, AnnotationTarget.PROPERTY)
@kotlin.annotation.Retention(AnnotationRetention.SOURCE)
public annotation class OperationFlag(val value: Int)

public object OperationFlags {
    public const val IDEMPOTENT: Int = 0x01
    public const val STREAMABLE: Int = 0x02
    public const val BATCHABLE: Int = 0x04
}

// ============================================================================
// VERSIÓN
// ============================================================================

/**
 * Versión semántica del contrato
 */
public data class ContractVersion(
    public val major: UShort,
    public val minor: UShort,
    public val patch: UShort
) {
    public fun toInt(): Int = (major.toInt() shl 16) or (minor.toInt() shl 8) or patch.toInt()

    override fun toString(): String = "$major.$minor.$patch"

    public fun compareTo(other: ContractVersion): Int {
        val thisInt = this.toInt()
        val otherInt = other.toInt()
        return when {
            thisInt < otherInt -> -1
            thisInt > otherInt -> 1
            else -> 0
        }
    }

    public fun isCompatible(other: ContractVersion): Boolean {
        return major == other.major
    }

    public fun isBackwardCompatible(other: ContractVersion): Boolean {
        return major == other.major && minor <= other.minor
    }

    public companion object {
        public fun fromInt(value: Int): ContractVersion {
            return ContractVersion(
                major = ((value shr 16) and 0xFFFF).toUShort(),
                minor = ((value shr 8) and 0xFF).toUShort(),
                patch = (value and 0xFF).toUShort()
            )
        }

        public fun parse(version: String): ContractVersion {
            val parts = version.split(".")
            require(parts.size == 3) { "Version must be major.minor.patch" }
            return ContractVersion(
                major = parts[0].toUShort(),
                minor = parts[1].toUShort(),
                patch = parts[2].toUShort()
            )
        }
    }
}

// ============================================================================
// ROLES DE CONTRATO
// ============================================================================

/**
 * Rol del contrato - define el patrón de comunicación
 */
public enum class ContractRole(val value: Byte) {
    /** Proceso subordinado/controlado por otro */
    CHILD(ProtocolConstants.ROLE_CHILD),

    /** Ambos extremos pueden iniciar operaciones */
    MUTUAL(ProtocolConstants.ROLE_MUTUAL),

    /** Comunicación simétrica entre pares */
    PEER(ProtocolConstants.ROLE_PEER),

    /** Múltiples canales lógicos */
    MUX(ProtocolConstants.ROLE_MUX),

    /** Flujo persistente (streaming) */
    STREAM(ProtocolConstants.ROLE_STREAM),

    /** Comunicación unidireccional */
    ONEWAY(ProtocolConstants.ROLE_ONEWAY);

    public companion object {
        public fun fromValue(value: Byte): ContractRole {
            return entries.find { it.value == value }
                ?: throw ContractParseException("Unknown role: $value")
        }
    }
}

// ============================================================================
// TIPOS DE PAQUETE
// ============================================================================

/**
 * Tipo de paquete en el protocolo wire
 */
public enum class PacketType(val value: Byte) {
    DATA(ProtocolConstants.PKT_DATA),
    CONTROL(ProtocolConstants.PKT_CONTROL),
    ERROR(ProtocolConstants.PKT_ERROR),
    EOF(ProtocolConstants.PKT_EOF),
    HEARTBEAT(ProtocolConstants.PKT_HEARTBEAT);

    public companion object {
        public fun fromValue(value: Byte): PacketType {
            return entries.find { it.value == value }
                ?: throw ContractParseException("Unknown packet type: $value")
        }
    }
}

// ============================================================================
// TIPOS DE DATOS
// ============================================================================

/**
 * Tipo primitivo
 */
public enum class PrimitiveType(val id: Short, val size: Int) {
    U8(ProtocolConstants.TYPE_U8, 1),
    U16(ProtocolConstants.TYPE_U16, 2),
    U32(ProtocolConstants.TYPE_U32, 4),
    U64(ProtocolConstants.TYPE_U64, 8),
    I8(ProtocolConstants.TYPE_I8, 1),
    I16(ProtocolConstants.TYPE_I16, 2),
    I32(ProtocolConstants.TYPE_I32, 4),
    I64(ProtocolConstants.TYPE_I64, 8),
    F32(ProtocolConstants.TYPE_F32, 4),
    F64(ProtocolConstants.TYPE_F64, 8),
    BOOL(ProtocolConstants.TYPE_BOOL, 1),
    STRING(ProtocolConstants.TYPE_STRING, -1),  // Variable
    BYTES(ProtocolConstants.TYPE_BYTES, -1);      // Variable

    public companion object {
        public fun fromId(id: Short): PrimitiveType {
            return entries.find { it.id == id }
                ?: throw ContractParseException("Unknown type id: $id")
        }
    }
}

/**
 * Definición de campo
 */
public data class FieldDefinition(
    public val name: String,
    public val typeId: Short,
    public val isOptional: Boolean = false,
    public val constraints: List<FieldConstraint> = emptyList()
)

/**
 * Restricción de campo
 */
public sealed class FieldConstraint {
    public data class Min(val value: Long) : FieldConstraint()
    public data class Max(val value: Long) : FieldConstraint()
    public data class MinLength(val value: Int) : FieldConstraint()
    public data class MaxLength(val value: Int) : FieldConstraint()
    public data class Pattern(val regex: String) : FieldConstraint()
}

/**
 * Definición de tipo
 */
public data class TypeDefinition(
    public val typeId: Short,
    public val name: String,
    public val kind: TypeKind
)

/**
 * Tipo de dato
 */
public sealed class TypeKind {
    public data class Primitive(val type: PrimitiveType) : TypeKind()
    public data class Array(val elementTypeId: Short, val length: Int) : TypeKind()
    public data class Struct(val fields: List<FieldDefinition>) : TypeKind()
    public data class Enum(val variants: List<EnumVariant>) : TypeKind()
    public data class Map(val keyTypeId: Short, val valueTypeId: Short) : TypeKind()
}

/**
 * Variante de enum
 */
public data class EnumVariant(
    public val name: String,
    public val associatedTypeId: Short? = null
)

// ============================================================================
// OPERACIONES
// ============================================================================

/**
 * Rol de operación
 */
public enum class OperationRole(val value: Byte) {
    REQUEST_RESPONSE(0x01),
    ONE_WAY(0x02),
    STREAM_START(0x03),
    STREAM_DATA(0x04),
    STREAM_END(0x05);

    public companion object {
        public fun fromValue(value: Byte): OperationRole {
            return entries.find { it.value == value }
                ?: throw ContractParseException("Unknown operation role: $value")
        }
    }
}

/**
 * Definición de operación
 */
public data class OperationDefinition(
    public val operationId: Short,
    public val name: String,
    public val inputTypeId: Short?,
    public val outputTypeId: Short?,
    public val timeoutMs: UInt,
    public val role: OperationRole,
    public val flags: Set<OperationFlag> = emptySet()
)

// ============================================================================
// HEADER DEL CONTRATO
// ============================================================================

/**
 * Header del contrato binario (256 bytes)
 */
public class ContractHeader {
    // Identificación (16 bytes)
    public var magic: ByteArray = ByteArray(4)  // "CBC1"
    public var formatVersion: Byte = 0
    public var flags: Int = 0
    public var headerSize: Short = 0

    // Identificador único (16 bytes)
    public var contractId: Long = 0
    public var version: ContractVersion = ContractVersion(0u, 0u, 0u)

    // Hash del contrato (32 bytes)
    public var contractHash: ByteArray = ByteArray(32)

    // Offsets y tamaños (24 bytes)
    public var typesOffset: Int = 0
    public var typesSize: Int = 0
    public var operationsOffset: Int = 0
    public var operationsSize: Int = 0
    public var securityPolicyOffset: Int = 0
    public var securityPolicySize: Short = 0

    // Metadatos (variable)
    public var name: String = ""
    public var namespace: String = ""

    // Reserved
    private val reserved: ByteArray = ByteArray(128)

    public companion object {
        public const val SIZE: Int = 256

        /**
         * Parsear header desde bytes
         */
        public fun parse(data: ByteArray): ContractHeader {
            require(data.size >= SIZE) { "Header too short: ${data.size} < $SIZE" }

            val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
            val header = ContractHeader()

            // Identificación
            buffer.get(header.magic, 0, 4)
            header.formatVersion = buffer.get()
            header.flags = buffer.int
            header.headerSize = buffer.short

            // Verificar magic
            if (String(header.magic) != ProtocolConstants.MAGIC) {
                throw ContractParseException("Invalid magic: ${String(header.magic)}")
            }

            // Identificador único
            header.contractId = buffer.long
            header.version = ContractVersion(
                buffer.short.toUShort(),
                buffer.short.toUShort(),
                buffer.short.toUShort()
            )

            // Hash
            buffer.get(header.contractHash, 0, 32)

            // Offsets y tamaños
            header.typesOffset = buffer.int
            header.typesSize = buffer.int
            header.operationsOffset = buffer.int
            header.operationsSize = buffer.int
            header.securityPolicyOffset = buffer.int
            header.securityPolicySize = buffer.short

            // Metadatos
            val nameLength = buffer.get().toInt()
            val namespaceLength = buffer.get().toInt()

            val nameBytes = ByteArray(nameLength)
            buffer.get(nameBytes)
            header.name = String(nameBytes, Charsets.UTF_8)

            val namespaceBytes = ByteArray(namespaceLength)
            buffer.get(namespaceBytes)
            header.namespace = String(namespaceBytes, Charsets.UTF_8)

            return header
        }
    }

    /**
     * Serializar header a bytes
     */
    public fun toByteArray(): ByteArray {
        val buffer = ByteBuffer.allocate(SIZE).order(ByteOrder.BIG_ENDIAN)

        // Identificación
        buffer.put(magic)
        buffer.put(formatVersion)
        buffer.putInt(flags)
        buffer.putShort(headerSize)

        // Identificador único
        buffer.putLong(contractId)
        buffer.putShort(version.major.toShort())
        buffer.putShort(version.minor.toShort())
        buffer.putShort(version.patch.toShort())

        // Hash
        buffer.put(contractHash)

        // Offsets y tamaños
        buffer.putInt(typesOffset)
        buffer.putInt(typesSize)
        buffer.putInt(operationsOffset)
        buffer.putInt(operationsSize)
        buffer.putInt(securityPolicyOffset)
        buffer.putShort(securityPolicySize)

        // Metadatos
        buffer.put(name.length.toByte())
        buffer.put(namespace.length.toByte())
        buffer.put(name.toByteArray(Charsets.UTF_8))
        buffer.put(namespace.toByteArray(Charsets.UTF_8))

        // Reserved
        buffer.put(reserved)

        return buffer.array()
    }

    /**
     * Obtener prefijo del hash para identificación
     */
    public fun getHashPrefix(): ByteArray {
        return contractHash.copyOf(12)
    }
}

// ============================================================================
// POLÍTICA DE SEGURIDAD
// ============================================================================
//
// La definición canónica de `SecurityPolicy` (11 bytes, con BLAKE3 como hash
// de identidad y política de firma) vive en `KeyDerivation.kt`.
//
// La versión anterior de este archivo definía una política de 3 bytes con
// niveles NONE/OPTIONAL/REQUIRED por eje, incompatible byte a byte con el
// encoding de Rust y C++: el mismo contrato producía políticas distintas en
// cada binding. Se elimina aquí para que haya una sola definición.

// ============================================================================
// CONTRATO
// ============================================================================

/**
 * Contrato binario canónico
 */
public class Contract {
    public val header: ContractHeader
    public val types: Map<Short, TypeDefinition>
    public val operations: Map<Short, OperationDefinition>
    public val securityPolicy: SecurityPolicy
    public val role: ContractRole
    public val signature: ByteArray?

    internal constructor(
        header: ContractHeader,
        types: Map<Short, TypeDefinition>,
        operations: Map<Short, OperationDefinition>,
        securityPolicy: SecurityPolicy,
        role: ContractRole,
        signature: ByteArray?
    ) {
        this.header = header
        this.types = types
        this.operations = operations
        this.securityPolicy = securityPolicy
        this.role = role
        this.signature = signature
    }

    /**
     * Cargar contrato desde archivo
     */
    public companion object {
        public fun load(path: String): Contract {
            return load(java.io.File(path).readBytes())
        }

        public fun load(data: ByteArray): Contract {
            val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)

            // Parsear header
            val header = ContractHeader.parse(data.copyOfRange(0, ContractHeader.SIZE))

            // Verificar magic
            if (String(header.magic) != ProtocolConstants.MAGIC) {
                throw ContractParseException("Invalid magic bytes")
            }

            // Extraer tipo y operaciones (simplificado - en implementación real sería más complejo)
            val types = parseTypes(data, header)
            val operations = parseOperations(data, header)
            val securityPolicy = parseSecurityPolicy(data, header)
            val role = ContractRole.fromValue(data[header.securityPolicyOffset - 1])

            // Verificar hash
            val calculatedHash = calculateContractHash(data)
            if (!header.contractHash.contentEquals(calculatedHash)) {
                throw ContractVerificationException("Contract hash mismatch")
            }

            // Extraer firma si existe
            val signature = if ((header.flags and ContractFlags.SIGNED) != 0) {
                data.copyOfRange(data.size - ProtocolConstants.SIGNATURE_SIZE, data.size)
            } else null

            return Contract(header, types, operations, securityPolicy, role, signature)
        }

        private fun parseTypes(data: ByteArray, header: ContractHeader): Map<Short, TypeDefinition> {
            val types = mutableMapOf<Short, TypeDefinition>()
            if (header.typesSize.toLong() == 0L) return types

            val typesStart = header.typesOffset
            val typesEnd = typesStart + header.typesSize
            val buffer = ByteBuffer.wrap(data, typesStart, typesEnd - typesStart)

            while (buffer.hasRemaining() && buffer.position() < typesEnd - typesStart) {
                val typeId = buffer.short
                val nameLength = buffer.get().toInt()
                val nameBytes = ByteArray(nameLength)
                buffer.get(nameBytes)
                val name = String(nameBytes, Charsets.UTF_8)
                val kindByte = buffer.get()

                val kind = when (kindByte.toInt()) {
                    0x01 -> TypeKind.Primitive(PrimitiveType.fromId(buffer.short))
                    0x02 -> TypeKind.Array(buffer.short, buffer.int)
                    0x03 -> {
                        val fieldCount = buffer.get().toInt()
                        val fields = (0 until fieldCount).map {
                            val fNameLen = buffer.get().toInt()
                            val fNameBytes = ByteArray(fNameLen)
                            buffer.get(fNameBytes)
                            FieldDefinition(String(fNameBytes), buffer.short)
                        }
                        TypeKind.Struct(fields)
                    }
                    else -> throw ContractParseException("Unknown type kind: $kindByte")
                }

                types[typeId] = TypeDefinition(typeId, name, kind)
            }

            return types
        }

        private fun parseOperations(data: ByteArray, header: ContractHeader): Map<Short, OperationDefinition> {
            val operations = mutableMapOf<Short, OperationDefinition>()
            if (header.operationsSize.toLong() == 0L) return operations

            val opsStart = header.operationsOffset
            val opsEnd = opsStart + header.operationsSize
            val buffer = ByteBuffer.wrap(data, opsStart, opsEnd - opsStart)

            while (buffer.hasRemaining() && buffer.position() < opsEnd - opsStart) {
                val opId = buffer.short
                val nameLength = buffer.get().toInt()
                val nameBytes = ByteArray(nameLength)
                buffer.get(nameBytes)
                val name = String(nameBytes, Charsets.UTF_8)

                val inputTypeId = if (buffer.get().toInt() == 1) buffer.short else null
                val outputTypeId = if (buffer.get().toInt() == 1) buffer.short else null
                val timeoutMs = buffer.int.toUInt()
                val role = OperationRole.fromValue(buffer.get())

                operations[opId] = OperationDefinition(opId, name, inputTypeId, outputTypeId, timeoutMs, role)
            }

            return operations
        }

        private fun parseSecurityPolicy(data: ByteArray, header: ContractHeader): SecurityPolicy {
            if (header.securityPolicySize.toInt() == 0) {
                return SecurityPolicy()
            }
            val policyStart = header.securityPolicyOffset
            val policyData = data.copyOfRange(policyStart, policyStart + header.securityPolicySize.toInt())
            return SecurityPolicy.fromByteArray(policyData)
        }

        /**
         * Calcular el hash de identidad del contrato (BLAKE3-256).
         *
         * P0.1: la v2.1 calculaba aquí un SHA-256, de modo que el mismo
         * contratoCBC1 producía un `contract_hash` distinto en Kotlin que en
         * Rust. Ese es exactamente el motivo por el que los bindings no eran
         * interoperables: la identidad es lo que se compara en el handshake.
         *
         * Se hashea la representación canónica completa (header con el hash a
         * cero y los offsets a cero, más las secciones de tipos, operaciones y
         * seguridad), nunca "todo menos los últimos N bytes": la firma no es
         * necesariamente el último contenido si el formato cambia.
         */
        public fun calculateContractHash(data: ByteArray): ByteArray =
            SecurityUtils.blake3Hash(canonicalPayload(data))

        /**
         * Preimagen canónico que se hashea y se firma.
         *
         * Header (256 B) con `contract_hash` a cero y todos los offsets a
         * cero, seguido de las secciones de tipos, operaciones y seguridad.
         */
        public fun canonicalPayload(data: ByteArray): ByteArray {
            require(data.size >= ProtocolConstants.HEADER_SIZE) {
                "el contrato es menor que el header"
            }
            val header = data.copyOfRange(0, ProtocolConstants.HEADER_SIZE)

            // contract_hash (offset 24..56) a cero
            for (i in 24 until 56) header[i] = 0
            // Offsets y tamaños de sección (56..96) a cero
            for (i in 56 until 96) header[i] = 0

            val typesOff = readInt(data, 64)
            val typesSize = readInt(data, 68)
            val opsOff = readInt(data, 72)
            val opsSize = readInt(data, 76)
            val secOff = readInt(data, 80)
            val secSize = readInt(data, 84)

            val out = java.io.ByteArrayOutputStream()
            out.write(header)
            out.write(section(data, typesOff, typesSize, "types"))
            out.write(section(data, opsOff, opsSize, "operations"))
            out.write(section(data, secOff, secSize, "security"))
            return out.toByteArray()
        }

        private fun readInt(d: ByteArray, o: Int): Int =
            (d[o].toInt() and 0xFF) or
                ((d[o + 1].toInt() and 0xFF) shl 8) or
                ((d[o + 2].toInt() and 0xFF) shl 16) or
                ((d[o + 3].toInt() and 0xFF) shl 24)

        private fun section(d: ByteArray, offset: Int, size: Int, name: String): ByteArray {
            if (size == 0) return ByteArray(0)
            val end = offset.toLong() + size.toLong()
            require(end <= d.size && offset >= ProtocolConstants.HEADER_SIZE) {
                "sección $name fuera de rango (offset=$offset size=$size archivo=${d.size})"
            }
            return d.copyOfRange(offset, end.toInt())
        }
    }

    /**
     * Obtener tipo por ID
     */
    public fun getType(typeId: Short): TypeDefinition? = types[typeId]

    /**
     * Obtener operación por ID
     */
    public fun getOperation(opId: Short): OperationDefinition? = operations[opId]

    /**
     * Obtener operación por nombre
     */
    public fun getOperationByName(name: String): OperationDefinition? {
        return operations.values.find { it.name == name }
    }

    /**
     * Verificar contrato
     */
    public fun verify(): Boolean {
        return try {
            val calculatedHash = calculateContractHash(
                header.toByteArray() + getTypesBytes() + getOperationsBytes() + getSecurityBytes()
            )
            header.contractHash.contentEquals(calculatedHash)
        } catch (e: Exception) {
            false
        }
    }

    internal fun getTypesBytes(): ByteArray {
        // Serialización de tipos
        val baos = java.io.ByteArrayOutputStream()
        types.forEach { (_, type) ->
            baos.write(type.typeId.toInt())
            baos.write(type.name.length)
            baos.write(type.name.toByteArray(Charsets.UTF_8))
        }
        return baos.toByteArray()
    }

    internal fun getOperationsBytes(): ByteArray {
        // Serialización de operaciones
        val baos = java.io.ByteArrayOutputStream()
        operations.forEach { (_, op) ->
            baos.write(op.operationId.toInt())
            baos.write(op.name.length)
            baos.write(op.name.toByteArray(Charsets.UTF_8))
        }
        return baos.toByteArray()
    }

    internal fun getSecurityBytes(): ByteArray {
        return securityPolicy.toByteArray()
    }

    /**
     * Obtener identificador único del contrato
     */
    public fun getContractId(): Long = header.contractId

    /**
     * Obtener hash del contrato
     */
    public fun getContractHash(): ByteArray = header.contractHash.copyOf()

    /**
     * Obtener versión del contrato
     */
    public fun getVersion(): ContractVersion = header.version
}
