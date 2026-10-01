#pragma once

/**
 * Canonical Binary Contract - C++ Bindings
 *
 * Comunicación inter-proceso sin FFI entre C++ y Rust/Go/Kotlin
 * via contratos binarios canónicos y sockets Unix.
 *
 * Requiere: C++17 o superior
 */

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <variant>
#include <memory>
#include <array>
#include <stdexcept>
#include <functional>

namespace ipc {

// ============================================================================
// CONSTANTES DEL PROTOCOLO
// ============================================================================

namespace protocol {
    static constexpr const char* MAGIC = "CBC1";
    static constexpr uint8_t FORMAT_VERSION = 1;
    static constexpr uint8_t PROTOCOL_VERSION = 2;

    static constexpr size_t HEADER_SIZE = 256;
    static constexpr size_t FRAME_HEADER_SIZE = 64;
    static constexpr size_t HASH_SIZE = 32;
    static constexpr size_t SIGNATURE_SIZE = 64;
    static constexpr size_t NONCE_SIZE = 12;

    // Tipos primitivos
    static constexpr uint16_t TYPE_U8 = 0x0001;
    static constexpr uint16_t TYPE_U16 = 0x0002;
    static constexpr uint16_t TYPE_U32 = 0x0003;
    static constexpr uint16_t TYPE_U64 = 0x0004;
    static constexpr uint16_t TYPE_I8 = 0x0005;
    static constexpr uint16_t TYPE_I16 = 0x0006;
    static constexpr uint16_t TYPE_I32 = 0x0007;
    static constexpr uint16_t TYPE_I64 = 0x0008;
    static constexpr uint16_t TYPE_F32 = 0x0009;
    static constexpr uint16_t TYPE_F64 = 0x000A;
    static constexpr uint16_t TYPE_BOOL = 0x000B;
    static constexpr uint16_t TYPE_STRING = 0x000C;
    static constexpr uint16_t TYPE_BYTES = 0x000D;

    // Operaciones reservadas
    static constexpr uint16_t OP_HANDSHAKE = 0x0000;
    static constexpr uint16_t OP_AUTH = 0x0001;
    static constexpr uint16_t OP_PING = 0x0002;
    static constexpr uint16_t OP_SESSION_START = 0x0003;
    static constexpr uint16_t OP_SESSION_END = 0x0004;

    // Roles de contrato
    static constexpr uint8_t ROLE_CHILD = 0x01;
    static constexpr uint8_t ROLE_MUTUAL = 0x02;
    static constexpr uint8_t ROLE_PEER = 0x03;
    static constexpr uint8_t ROLE_MUX = 0x04;
    static constexpr uint8_t ROLE_STREAM = 0x05;
    static constexpr uint8_t ROLE_ONEWAY = 0x06;

    // Tipos de paquete
    static constexpr uint8_t PKT_DATA = 0x01;
    static constexpr uint8_t PKT_CONTROL = 0x02;
    static constexpr uint8_t PKT_ERROR = 0x03;
    static constexpr uint8_t PKT_EOF = 0x04;
    static constexpr uint8_t PKT_HEARTBEAT = 0x05;
}

// ============================================================================
// EXCEPCIONES
// ============================================================================

class ContractException : public std::runtime_error {
public:
    explicit ContractException(const std::string& msg) : std::runtime_error(msg) {}
};

class ContractParseException : public ContractException {
public:
    using ContractException::ContractException;
};

class ContractVerificationException : public ContractException {
public:
    using ContractException::ContractException;
};

class ContractSecurityException : public ContractException {
public:
    using ContractException::ContractException;
};

class ContractNotFoundException : public ContractException {
public:
    using ContractException::ContractException;
};

class ContractTimeoutException : public ContractException {
public:
    using ContractException::ContractException;
};

// ============================================================================
// VERSIÓN
// ============================================================================

/**
 * Versión semántica del contrato
 */
struct Version {
    uint16_t major;
    uint16_t minor;
    uint16_t patch;

    Version(uint16_t major = 0, uint16_t minor = 0, uint16_t patch = 0)
        : major(major), minor(minor), patch(patch) {}

    [[nodiscard]] std::string to_string() const {
        return std::to_string(major) + "." + std::to_string(minor) + "." + std::to_string(patch);
    }

    [[nodiscard]] int to_int() const {
        return (major << 16) | (minor << 8) | patch;
    }

    [[nodiscard]] bool is_compatible(const Version& other) const {
        return major == other.major;
    }

    [[nodiscard]] bool is_backward_compatible(const Version& other) const {
        return major == other.major && minor <= other.minor;
    }

    static Version from_int(int value);
    static Version parse(const std::string& version);
};

// ============================================================================
// ROLES
// ============================================================================

enum class ContractRole : uint8_t {
    CHILD = protocol::ROLE_CHILD,
    MUTUAL = protocol::ROLE_MUTUAL,
    PEER = protocol::ROLE_PEER,
    MUX = protocol::ROLE_MUX,
    STREAM = protocol::ROLE_STREAM,
    ONEWAY = protocol::ROLE_ONEWAY
};

enum class PacketType : uint8_t {
    DATA = protocol::PKT_DATA,
    CONTROL = protocol::PKT_CONTROL,
    ERROR = protocol::PKT_ERROR,
    EOF_ = protocol::PKT_EOF,
    HEARTBEAT = protocol::PKT_HEARTBEAT
};

enum class OperationRole : uint8_t {
    REQUEST_RESPONSE = 0x01,
    ONE_WAY = 0x02,
    STREAM_START = 0x03,
    STREAM_DATA = 0x04,
    STREAM_END = 0x05
};

// ============================================================================
// FLAGS
// ============================================================================

struct ContractFlags {
    bool signed_ = false;
    bool encrypted = false;
    bool authenticated = false;
    bool replay_protected = false;
    bool compressed = false;

    [[nodiscard]] uint32_t to_int() const;
    static ContractFlags from_int(uint32_t flags);
};

struct FrameFlags {
    bool compressed = false;
    bool encrypted = false;
    bool authenticated = false;
    bool streaming = false;
    bool last_frame = false;

    [[nodiscard]] uint8_t to_byte() const;
    static FrameFlags from_byte(uint8_t flags);
};

struct OperationFlags {
    bool idempotent = false;
    bool streamable = false;
    bool batchable = false;

    [[nodiscard]] uint32_t to_int() const;
    static OperationFlags from_int(uint32_t flags);
};

// ============================================================================
// TIPOS DE DATOS
// ============================================================================

enum class PrimitiveType : uint16_t {
    U8 = protocol::TYPE_U8,
    U16 = protocol::TYPE_U16,
    U32 = protocol::TYPE_U32,
    U64 = protocol::TYPE_U64,
    I8 = protocol::TYPE_I8,
    I16 = protocol::TYPE_I16,
    I32 = protocol::TYPE_I32,
    I64 = protocol::TYPE_I64,
    F32 = protocol::TYPE_F32,
    F64 = protocol::TYPE_F64,
    BOOL = protocol::TYPE_BOOL,
    STRING = protocol::TYPE_STRING,
    BYTES = protocol::TYPE_BYTES
};

struct FieldConstraint {
    enum class Type { MIN, MAX, MIN_LENGTH, MAX_LENGTH, PATTERN };
    Type type;
    std::variant<int64_t, int, std::string> value;
};

struct FieldDefinition {
    std::string name;
    uint16_t type_id;
    bool is_optional = false;
    std::vector<FieldConstraint> constraints;
};

struct EnumVariant {
    std::string name;
    std::optional<uint16_t> associated_type_id;
};

struct TypeKind {
    enum class Kind { PRIMITIVE, ARRAY, STRUCT, ENUM, MAP };
    Kind kind;

    std::variant<
        PrimitiveType,
        std::pair<uint16_t, uint32_t>,  // Array: (element_type_id, length)
        std::vector<FieldDefinition>,    // Struct
        std::vector<EnumVariant>,       // Enum
        std::pair<uint16_t, uint16_t>   // Map: (key_type_id, value_type_id)
    > data;
};

struct TypeDefinition {
    uint16_t type_id;
    std::string name;
    TypeKind kind;
};

// ============================================================================
// OPERACIONES
// ============================================================================

struct OperationDefinition {
    uint16_t operation_id;
    std::string name;
    std::optional<uint16_t> input_type_id;
    std::optional<uint16_t> output_type_id;
    uint32_t timeout_ms;
    OperationRole role;
    OperationFlags flags;
};

// ============================================================================
// POLÍTICA DE SEGURIDAD
// ============================================================================

enum class SecurityLevel : uint8_t {
    NONE = 0,
    OPTIONAL = 1,
    REQUIRED = 2
};

struct SecurityPolicy {
    SecurityLevel authentication = SecurityLevel::OPTIONAL;
    SecurityLevel encryption = SecurityLevel::OPTIONAL;
    SecurityLevel replay_protection = SecurityLevel::OPTIONAL;

    [[nodiscard]] bool is_authentication_required() const {
        return authentication == SecurityLevel::REQUIRED;
    }
    [[nodiscard]] bool is_encryption_required() const {
        return encryption == SecurityLevel::REQUIRED;
    }
    [[nodiscard]] bool is_replay_protection_required() const {
        return replay_protection == SecurityLevel::REQUIRED;
    }

    [[nodiscard]] std::vector<uint8_t> to_bytes() const;
    static SecurityPolicy from_bytes(const std::vector<uint8_t>& data);
};

// ============================================================================
// HEADER DEL CONTRATO
// ============================================================================

struct ContractHeader {
    std::array<uint8_t, 4> magic;           // "CBC1"
    uint8_t format_version = 0;
    uint32_t flags = 0;
    uint16_t header_size = 0;

    uint64_t contract_id = 0;
    Version version;

    std::array<uint8_t, protocol::HASH_SIZE> contract_hash;

    uint32_t types_offset = 0;
    uint32_t types_size = 0;
    uint32_t operations_offset = 0;
    uint32_t operations_size = 0;
    uint32_t security_policy_offset = 0;
    uint16_t security_policy_size = 0;

    std::string name;
    std::string namespace_;

    static constexpr size_t SIZE = protocol::HEADER_SIZE;

    [[nodiscard]] std::array<uint8_t, 12> get_hash_prefix() const;
    [[nodiscard]] std::vector<uint8_t> to_bytes() const;
    static ContractHeader parse(const std::vector<uint8_t>& data);
};

// ============================================================================
// CONTRATO
// ============================================================================

class Contract {
public:
    Contract() = default;
    explicit Contract(const std::string& path);
    explicit Contract(const std::vector<uint8_t>& data);

    // No copying
    Contract(const Contract&) = delete;
    Contract& operator=(const Contract&) = delete;

    // Moving
    Contract(Contract&&) noexcept;
    Contract& operator=(Contract&&) noexcept;

    ~Contract();

    // Acceso a datos
    [[nodiscard]] const ContractHeader& header() const { return header_; }
    [[nodiscard]] const std::map<uint16_t, TypeDefinition>& types() const { return types_; }
    [[nodiscard]] const std::map<uint16_t, OperationDefinition>& operations() const { return operations_; }
    [[nodiscard]] const SecurityPolicy& security_policy() const { return security_policy_; }
    [[nodiscard]] ContractRole role() const { return role_; }
    [[nodiscard]] const std::vector<uint8_t>& signature() const { return signature_; }

    // Utilidades
    [[nodiscard]] std::optional<TypeDefinition> get_type(uint16_t type_id) const;
    [[nodiscard]] std::optional<OperationDefinition> get_operation(uint16_t op_id) const;
    [[nodiscard]] std::optional<OperationDefinition> get_operation_by_name(const std::string& name) const;
    [[nodiscard]] uint64_t contract_id() const { return header_.contract_id; }
    [[nodiscard]] std::vector<uint8_t> get_contract_hash() const;
    [[nodiscard]] Version version() const { return header_.version; }
    [[nodiscard]] bool verify() const;

    // Serialización
    [[nodiscard]] std::vector<uint8_t> to_bytes() const;

    // Crear desde archivo
    static std::shared_ptr<Contract> load(const std::string& path);

    /**
     * Hash de identidad del contrato: BLAKE3-256 sobre el preimagen canónico
     * (P0.1).
     *
     * Es público para que los tests de conformidad puedan comprobar que C++
     * reproduce exactamente el mismo `contract_hash` que Rust.
     */
    static std::vector<uint8_t> calculate_hash(const std::vector<uint8_t>& data);

private:
    ContractHeader header_;
    std::map<uint16_t, TypeDefinition> types_;
    std::map<uint16_t, OperationDefinition> operations_;
    SecurityPolicy security_policy_;
    ContractRole role_ = ContractRole::MUTUAL;
    std::vector<uint8_t> signature_;
    std::vector<uint8_t> raw_data_;

    void parse();
};

// ============================================================================
// ID DE OPERACIÓN
// ============================================================================

struct OperationId {
    uint16_t value;

    OperationId() : value(0) {}
    explicit OperationId(uint16_t v) : value(v) {}

    static OperationId handshake() { return OperationId(protocol::OP_HANDSHAKE); }
    static OperationId auth() { return OperationId(protocol::OP_AUTH); }
    static OperationId ping() { return OperationId(protocol::OP_PING); }
    static OperationId session_start() { return OperationId(protocol::OP_SESSION_START); }
    static OperationId session_end() { return OperationId(protocol::OP_SESSION_END); }

    [[nodiscard]] bool operator==(const OperationId& other) const { return value == other.value; }
    [[nodiscard]] bool operator!=(const OperationId& other) const { return value != other.value; }
};

// ============================================================================
// FRAME
// ============================================================================

class Frame {
public:
    Frame() = default;

    Frame(uint64_t session_id, uint64_t sequence, uint32_t channel_id,
          OperationId operation_id, PacketType packet_type,
          std::vector<uint8_t> payload);

    // Serialización
    [[nodiscard]] std::vector<uint8_t> to_bytes() const;
    static Frame parse(const std::vector<uint8_t>& data);

    // Getters
    [[nodiscard]] uint64_t session_id() const { return session_id_; }
    [[nodiscard]] uint64_t sequence() const { return sequence_; }
    [[nodiscard]] uint32_t channel_id() const { return channel_id_; }
    [[nodiscard]] OperationId operation_id() const { return operation_id_; }
    [[nodiscard]] PacketType packet_type() const { return packet_type_; }
    [[nodiscard]] const std::vector<uint8_t>& payload() const { return payload_; }
    [[nodiscard]] FrameFlags flags() const { return flags_; }
    [[nodiscard]] ContractRole role() const { return role_; }
    [[nodiscard]] uint16_t schema_id() const { return schema_id_; }
    [[nodiscard]] std::array<uint8_t, protocol::NONCE_SIZE> nonce() const { return nonce_; }

    // Setters
    void set_session_id(uint64_t id) { session_id_ = id; }
    void set_sequence(uint64_t seq) { sequence_ = seq; }
    void set_channel_id(uint32_t id) { channel_id_ = id; }
    void set_operation_id(OperationId op) { operation_id_ = op; }
    void set_packet_type(PacketType type) { packet_type_ = type; }
    void set_payload(std::vector<uint8_t> data) { payload_ = std::move(data); }
    void set_flags(FrameFlags flags) { flags_ = flags; }
    void set_role(ContractRole role) { role_ = role; }
    void set_schema_id(uint16_t id) { schema_id_ = id; }
    void set_nonce(std::array<uint8_t, protocol::NONCE_SIZE> n) { nonce_ = n; }

    // Utilidades
    [[nodiscard]] std::string payload_as_string() const;
    void set_payload_from_string(const std::string& str);

    [[nodiscard]] bool is_last_frame() const { return flags_.last_frame; }
    [[nodiscard]] bool is_data_frame() const { return packet_type_ == PacketType::DATA; }
    [[nodiscard]] bool is_control_frame() const { return packet_type_ == PacketType::CONTROL; }

    void mark_as_last_frame() { flags_.last_frame = true; }

    [[nodiscard]] Frame create_error_frame(int error_code, const std::string& message) const;
    [[nodiscard]] Frame create_ack_frame() const;
    [[nodiscard]] Frame create_heartbeat_frame() const;
    [[nodiscard]] Frame create_eof_frame() const;

    static constexpr size_t HEADER_SIZE = protocol::FRAME_HEADER_SIZE;

private:
    uint64_t session_id_ = 0;
    uint64_t sequence_ = 0;
    uint32_t channel_id_ = 0;
    OperationId operation_id_;
    PacketType packet_type_ = PacketType::DATA;
    std::vector<uint8_t> payload_;
    FrameFlags flags_;
    ContractRole role_ = ContractRole::MUTUAL;
    uint16_t schema_id_ = 0;
    std::array<uint8_t, protocol::NONCE_SIZE> nonce_ = {};
    std::array<uint8_t, 12> contract_hash_prefix_ = {};
};

// ============================================================================
// UTILIDADES
// ============================================================================

namespace FrameUtils {
    [[nodiscard]] Frame create_handshake_frame(const std::vector<uint8_t>& contract_hash,
                                               uint8_t protocol_version = protocol::PROTOCOL_VERSION);
    [[nodiscard]] Frame create_auth_frame(uint64_t session_id, const std::vector<uint8_t>& token,
                                           const std::vector<uint8_t>& contract_hash);
    [[nodiscard]] Frame create_session_start_frame(const std::vector<uint8_t>& contract_hash,
                                                     ContractRole role);

    [[nodiscard]] std::pair<uint8_t, uint64_t> parse_handshake_response(const Frame& frame);
    [[nodiscard]] bool is_valid_handshake(const Frame& frame);
    [[nodiscard]] bool is_error_frame(const Frame& frame);
    [[nodiscard]] int get_error_code(const Frame& frame);
    [[nodiscard]] std::string get_error_message(const Frame& frame);
}

}  // namespace ipc
