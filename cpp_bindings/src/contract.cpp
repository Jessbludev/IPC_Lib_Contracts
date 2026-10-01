/**
 * Canonical Binary Contract - C++ Bindings Implementation
 */

#include "ipc/contract.hpp"
#include "ipc/blake3.hpp"
#include "ipc/security.hpp"
#include <fstream>
#include <cstring>
#include <algorithm>

namespace ipc {

// ============================================================================
// VERSIÓN
// ============================================================================

Version Version::from_int(int value) {
    return Version(
        static_cast<uint16_t>((value >> 16) & 0xFFFF),
        static_cast<uint16_t>((value >> 8) & 0xFF),
        static_cast<uint16_t>(value & 0xFF)
    );
}

Version Version::parse(const std::string& version) {
    uint16_t major = 0, minor = 0, patch = 0;
    std::sscanf(version.c_str(), "%hu.%hu.%hu", &major, &minor, &patch);
    return Version(major, minor, patch);
}

// ============================================================================
// FLAGS
// ============================================================================

uint32_t ContractFlags::to_int() const {
    uint32_t result = 0;
    if (signed_) result |= 0x01;
    if (encrypted) result |= 0x02;
    if (authenticated) result |= 0x04;
    if (replay_protected) result |= 0x08;
    if (compressed) result |= 0x10;
    return result;
}

ContractFlags ContractFlags::from_int(uint32_t flags) {
    ContractFlags result;
    result.signed_ = (flags & 0x01) != 0;
    result.encrypted = (flags & 0x02) != 0;
    result.authenticated = (flags & 0x04) != 0;
    result.replay_protected = (flags & 0x08) != 0;
    result.compressed = (flags & 0x10) != 0;
    return result;
}

uint8_t FrameFlags::to_byte() const {
    uint8_t result = 0;
    if (compressed) result |= 0x01;
    if (encrypted) result |= 0x02;
    if (authenticated) result |= 0x04;
    if (streaming) result |= 0x08;
    if (last_frame) result |= 0x10;
    return result;
}

FrameFlags FrameFlags::from_byte(uint8_t flags) {
    FrameFlags result;
    result.compressed = (flags & 0x01) != 0;
    result.encrypted = (flags & 0x02) != 0;
    result.authenticated = (flags & 0x04) != 0;
    result.streaming = (flags & 0x08) != 0;
    result.last_frame = (flags & 0x10) != 0;
    return result;
}

uint32_t OperationFlags::to_int() const {
    uint32_t result = 0;
    if (idempotent) result |= 0x01;
    if (streamable) result |= 0x02;
    if (batchable) result |= 0x04;
    return result;
}

OperationFlags OperationFlags::from_int(uint32_t flags) {
    OperationFlags result;
    result.idempotent = (flags & 0x01) != 0;
    result.streamable = (flags & 0x02) != 0;
    result.batchable = (flags & 0x04) != 0;
    return result;
}

// ============================================================================
// POLÍTICA DE SEGURIDAD
// ============================================================================

std::vector<uint8_t> SecurityPolicy::to_bytes() const {
    return std::vector<uint8_t>{
        static_cast<uint8_t>(authentication),
        static_cast<uint8_t>(encryption),
        static_cast<uint8_t>(replay_protection)
    };
}

SecurityPolicy SecurityPolicy::from_bytes(const std::vector<uint8_t>& data) {
    SecurityPolicy policy;
    if (data.size() >= 3) {
        policy.authentication = static_cast<SecurityLevel>(data[0]);
        policy.encryption = static_cast<SecurityLevel>(data[1]);
        policy.replay_protection = static_cast<SecurityLevel>(data[2]);
    }
    return policy;
}

// ============================================================================
// HEADER DEL CONTRATO
// ============================================================================

std::array<uint8_t, 12> ContractHeader::get_hash_prefix() const {
    std::array<uint8_t, 12> prefix;
    std::copy_n(contract_hash.begin(), 12, prefix.begin());
    return prefix;
}

std::vector<uint8_t> ContractHeader::to_bytes() const {
    std::vector<uint8_t> buffer(SIZE, 0);
    size_t offset = 0;

    // Magic
    std::memcpy(buffer.data() + offset, magic.data(), 4);
    offset += 4;

    // Version y flags
    buffer[offset++] = format_version;
    *reinterpret_cast<uint32_t*>(buffer.data() + offset) = flags;
    offset += 4;
    *reinterpret_cast<uint16_t*>(buffer.data() + offset) = header_size;
    offset += 2;

    // Contract ID y version
    *reinterpret_cast<uint64_t*>(buffer.data() + offset) = contract_id;
    offset += 8;
    *reinterpret_cast<uint16_t*>(buffer.data() + offset) = version.major;
    offset += 2;
    *reinterpret_cast<uint16_t*>(buffer.data() + offset) = version.minor;
    offset += 2;
    *reinterpret_cast<uint16_t*>(buffer.data() + offset) = version.patch;
    offset += 2;

    // Hash
    std::memcpy(buffer.data() + offset, contract_hash.data(), protocol::HASH_SIZE);
    offset += protocol::HASH_SIZE;

    // Offsets y tamaños
    *reinterpret_cast<uint32_t*>(buffer.data() + offset) = types_offset;
    offset += 4;
    *reinterpret_cast<uint32_t*>(buffer.data() + offset) = types_size;
    offset += 4;
    *reinterpret_cast<uint32_t*>(buffer.data() + offset) = operations_offset;
    offset += 4;
    *reinterpret_cast<uint32_t*>(buffer.data() + offset) = operations_size;
    offset += 4;
    *reinterpret_cast<uint32_t*>(buffer.data() + offset) = security_policy_offset;
    offset += 4;
    *reinterpret_cast<uint16_t*>(buffer.data() + offset) = security_policy_size;
    offset += 2;

    // Metadatos
    buffer[offset++] = static_cast<uint8_t>(name.length());
    buffer[offset++] = static_cast<uint8_t>(namespace_.length());
    std::memcpy(buffer.data() + offset, name.data(), name.length());
    offset += name.length();
    std::memcpy(buffer.data() + offset, namespace_.data(), namespace_.length());

    return buffer;
}

ContractHeader ContractHeader::parse(const std::vector<uint8_t>& data) {
    if (data.size() < SIZE) {
        throw ContractParseException("Header too short");
    }

    ContractHeader header;
    size_t offset = 0;

    // Magic
    std::memcpy(header.magic.data(), data.data() + offset, 4);
    offset += 4;

    // Verificar magic
    if (std::memcmp(header.magic.data(), protocol::MAGIC, 4) != 0) {
        throw ContractParseException("Invalid magic bytes");
    }

    header.format_version = data[offset++];
    header.flags = *reinterpret_cast<const uint32_t*>(data.data() + offset);
    offset += 4;
    header.header_size = *reinterpret_cast<const uint16_t*>(data.data() + offset);
    offset += 2;

    header.contract_id = *reinterpret_cast<const uint64_t*>(data.data() + offset);
    offset += 8;
    header.version.major = *reinterpret_cast<const uint16_t*>(data.data() + offset);
    offset += 2;
    header.version.minor = *reinterpret_cast<const uint16_t*>(data.data() + offset);
    offset += 2;
    header.version.patch = *reinterpret_cast<const uint16_t*>(data.data() + offset);
    offset += 2;

    std::memcpy(header.contract_hash.data(), data.data() + offset, protocol::HASH_SIZE);
    offset += protocol::HASH_SIZE;

    header.types_offset = *reinterpret_cast<const uint32_t*>(data.data() + offset);
    offset += 4;
    header.types_size = *reinterpret_cast<const uint32_t*>(data.data() + offset);
    offset += 4;
    header.operations_offset = *reinterpret_cast<const uint32_t*>(data.data() + offset);
    offset += 4;
    header.operations_size = *reinterpret_cast<const uint32_t*>(data.data() + offset);
    offset += 4;
    header.security_policy_offset = *reinterpret_cast<const uint32_t*>(data.data() + offset);
    offset += 4;
    header.security_policy_size = *reinterpret_cast<const uint16_t*>(data.data() + offset);
    offset += 2;

    // Metadatos
    uint8_t name_len = data[offset++];
    uint8_t ns_len = data[offset++];
    header.name = std::string(reinterpret_cast<const char*>(data.data() + offset), name_len);
    offset += name_len;
    header.namespace_ = std::string(reinterpret_cast<const char*>(data.data() + offset), ns_len);

    return header;
}

// ============================================================================
// CONTRATO
// ============================================================================

Contract::Contract(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw ContractException("Cannot open contract file: " + path);
    }

    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    raw_data_.resize(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(raw_data_.data()), size);
    file.close();

    parse();
}

Contract::Contract(const std::vector<uint8_t>& data) : raw_data_(data) {
    parse();
}

Contract::Contract(Contract&& other) noexcept
    : header_(other.header_)
    , types_(std::move(other.types_))
    , operations_(std::move(other.operations_))
    , security_policy_(other.security_policy_)
    , role_(other.role_)
    , signature_(std::move(other.signature_))
    , raw_data_(std::move(other.raw_data_)) {}

Contract& Contract::operator=(Contract&& other) noexcept {
    if (this != &other) {
        header_ = other.header_;
        types_ = std::move(other.types_);
        operations_ = std::move(other.operations_);
        security_policy_ = other.security_policy_;
        role_ = other.role_;
        signature_ = std::move(other.signature_);
        raw_data_ = std::move(other.raw_data_);
    }
    return *this;
}

Contract::~Contract() = default;

void Contract::parse() {
    if (raw_data_.size() < ContractHeader::SIZE) {
        throw ContractParseException("Data too short for header");
    }

    header_ = ContractHeader::parse(raw_data_);

    // Verificar magic
    if (std::memcmp(header_.magic.data(), protocol::MAGIC, 4) != 0) {
        throw ContractParseException("Invalid magic bytes");
    }

    // Parsear tipos
    if (header_.types_size > 0 && header_.types_offset > 0) {
        size_t start = header_.types_offset;
        size_t end = start + header_.types_size;

        while (start < end && start < raw_data_.size()) {
            uint16_t type_id = *reinterpret_cast<const uint16_t*>(raw_data_.data() + start);
            start += 2;

            uint8_t name_len = raw_data_[start++];
            std::string name(reinterpret_cast<const char*>(raw_data_.data() + start), name_len);
            start += name_len;

            uint8_t kind_byte = raw_data_[start++];

            TypeKind kind;
            kind.kind = static_cast<TypeKind::Kind>(kind_byte);

            switch (kind.kind) {
                case TypeKind::Kind::PRIMITIVE: {
                    uint16_t primitive_id = *reinterpret_cast<const uint16_t*>(raw_data_.data() + start);
                    kind.data = static_cast<PrimitiveType>(primitive_id);
                    start += 2;
                    break;
                }
                case TypeKind::Kind::ARRAY: {
                    uint16_t elem_type = *reinterpret_cast<const uint16_t*>(raw_data_.data() + start);
                    start += 2;
                    uint32_t length = *reinterpret_cast<const uint32_t*>(raw_data_.data() + start);
                    start += 4;
                    kind.data = std::make_pair(elem_type, length);
                    break;
                }
                case TypeKind::Kind::STRUCT: {
                    uint8_t field_count = raw_data_[start++];
                    std::vector<FieldDefinition> fields;
                    for (uint8_t i = 0; i < field_count; ++i) {
                        uint8_t fname_len = raw_data_[start++];
                        std::string fname(reinterpret_cast<const char*>(raw_data_.data() + start), fname_len);
                        start += fname_len;
                        uint16_t ftype_id = *reinterpret_cast<const uint16_t*>(raw_data_.data() + start);
                        start += 2;
                        fields.push_back({fname, ftype_id});
                    }
                    kind.data = fields;
                    break;
                }
                default:
                    break;
            }

            types_[type_id] = {type_id, name, kind};
        }
    }

    // Parsear operaciones
    if (header_.operations_size > 0 && header_.operations_offset > 0) {
        size_t start = header_.operations_offset;
        size_t end = start + header_.operations_size;

        while (start < end && start < raw_data_.size()) {
            uint16_t op_id = *reinterpret_cast<const uint16_t*>(raw_data_.data() + start);
            start += 2;

            uint8_t name_len = raw_data_[start++];
            std::string name(reinterpret_cast<const char*>(raw_data_.data() + start), name_len);
            start += name_len;

            std::optional<uint16_t> input_id, output_id;
            if (raw_data_[start++]) {
                input_id = *reinterpret_cast<const uint16_t*>(raw_data_.data() + start);
                start += 2;
            }
            if (raw_data_[start++]) {
                output_id = *reinterpret_cast<const uint16_t*>(raw_data_.data() + start);
                start += 2;
            }

            uint32_t timeout = *reinterpret_cast<const uint32_t*>(raw_data_.data() + start);
            start += 4;
            OperationRole role = static_cast<OperationRole>(raw_data_[start++]);

            operations_[op_id] = {op_id, name, input_id, output_id, timeout, role, {}};
        }
    }

    // Parsear política de seguridad
    if (header_.security_policy_size > 0 && header_.security_policy_offset > 0) {
        auto policy_data = std::vector<uint8_t>(
            raw_data_.begin() + header_.security_policy_offset,
            raw_data_.begin() + header_.security_policy_offset + header_.security_policy_size
        );
        security_policy_ = SecurityPolicy::from_bytes(policy_data);
    }

    // Extraer rol del payload (simplificado)
    if (header_.security_policy_offset > 0) {
        role_ = static_cast<ContractRole>(raw_data_[header_.security_policy_offset - 1]);
    }
}

/**
 * Hash de identidad del contrato (P0.1).
 *
 * BLAKE3-256 sobre el preimagen canónico: el header con `contract_hash` a
 * cero y todos los offsets a cero, seguido de las secciones de tipos,
 * operaciones y seguridad.
 *
 * La v2.1 devolvía 32 bytes cero. Como `Contract::verify()` compara ese
 * resultado con el hash declarado, `verify()` era `false` para todos los
 * contratos: la comprobación de integridad no verificaba nada y fallaba en
 * silencio, que es peor que no tenerla.
 */
std::vector<uint8_t> Contract::calculate_hash(const std::vector<uint8_t>& data) {
    constexpr size_t HEADER_SIZE = 256;
    if (data.size() < HEADER_SIZE) {
        throw ContractException("el contrato es menor que el header CBC");
    }

    std::vector<uint8_t> header(data.begin(), data.begin() + HEADER_SIZE);

    // contract_hash (24..56) a cero
    std::fill(header.begin() + 24, header.begin() + 56, 0);
    // Offsets y tamaños de sección (56..96) a cero
    std::fill(header.begin() + 56, header.begin() + 96, 0);

    auto read_u32 = [&data](size_t o) -> uint32_t {
        return static_cast<uint32_t>(data[o]) |
               (static_cast<uint32_t>(data[o + 1]) << 8) |
               (static_cast<uint32_t>(data[o + 2]) << 16) |
               (static_cast<uint32_t>(data[o + 3]) << 24);
    };

    // Extraer una sección ya validada por el lector. Se comprueba el rango
    // antes de indexar: un offset manipulado no debe producir un slice fuera
    // de rango ni un hash silenciosamente distinto.
    auto section = [&data](uint32_t offset, uint32_t size, const char* name) {
        std::vector<uint8_t> out;
        if (size == 0) return out;
        const size_t start = static_cast<size_t>(offset);
        const size_t end = start + static_cast<size_t>(size);
        if (end < start || end > data.size()) {
            throw ContractException(std::string("seccion ") + name + " fuera de rango");
        }
        out.assign(data.begin() + static_cast<long>(start),
                   data.begin() + static_cast<long>(end));
        return out;
    };

    std::vector<uint8_t> payload;
    payload.reserve(header.size() + 256);
    payload.insert(payload.end(), header.begin(), header.end());

    auto types = section(read_u32(64), read_u32(68), "types");
    auto ops = section(read_u32(72), read_u32(76), "operations");
    auto sec = section(read_u32(80), read_u32(84), "security");

    payload.insert(payload.end(), types.begin(), types.end());
    payload.insert(payload.end(), ops.begin(), ops.end());
    payload.insert(payload.end(), sec.begin(), sec.end());

    const auto digest = ipc::blake3::hash(payload);
    return std::vector<uint8_t>(digest.begin(), digest.end());
}

std::optional<TypeDefinition> Contract::get_type(uint16_t type_id) const {
    auto it = types_.find(type_id);
    if (it != types_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<OperationDefinition> Contract::get_operation(uint16_t op_id) const {
    auto it = operations_.find(op_id);
    if (it != operations_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<OperationDefinition> Contract::get_operation_by_name(const std::string& name) const {
    for (const auto& [id, op] : operations_) {
        if (op.name == name) {
            return op;
        }
    }
    return std::nullopt;
}

std::vector<uint8_t> Contract::get_contract_hash() const {
    std::vector<uint8_t> hash(protocol::HASH_SIZE);
    std::copy_n(header_.contract_hash.begin(), protocol::HASH_SIZE, hash.begin());
    return hash;
}

bool Contract::verify() const {
    try {
        const auto calculated = calculate_hash(raw_data_);
        const std::vector<uint8_t> declared(header_.contract_hash.begin(),
                                            header_.contract_hash.end());
        return security::constant_time_equals(declared, calculated);
    } catch (const std::exception&) {
        // Un contrato malformado no verifica. Se devuelve `false` en lugar de
        // propagar la excepción porque `verify()` es una consulta de estado.
        return false;
    }
}

std::vector<uint8_t> Contract::to_bytes() const {
    return raw_data_;
}

std::shared_ptr<Contract> Contract::load(const std::string& path) {
    return std::make_shared<Contract>(path);
}

// ============================================================================
// FRAME
// ============================================================================

Frame::Frame(uint64_t session_id, uint64_t sequence, uint32_t channel_id,
             OperationId operation_id, PacketType packet_type,
             std::vector<uint8_t> payload)
    : session_id_(session_id)
    , sequence_(sequence)
    , channel_id_(channel_id)
    , operation_id_(operation_id)
    , packet_type_(packet_type)
    , payload_(std::move(payload)) {}

std::vector<uint8_t> Frame::to_bytes() const {
    size_t total_size = HEADER_SIZE + payload_.size();
    std::vector<uint8_t> buffer(total_size, 0);
    size_t offset = 0;

    // Magic
    std::memcpy(buffer.data() + offset, protocol::MAGIC, 4);
    offset += 4;

    // Version
    buffer[offset++] = protocol::PROTOCOL_VERSION;

    // Flags
    buffer[offset++] = flags_.to_byte();

    // Packet Type
    buffer[offset++] = static_cast<uint8_t>(packet_type_);

    // Role
    buffer[offset++] = static_cast<uint8_t>(role_);

    // Session ID
    *reinterpret_cast<uint64_t*>(buffer.data() + offset) = session_id_;
    offset += 8;

    // Sequence
    *reinterpret_cast<uint64_t*>(buffer.data() + offset) = sequence_;
    offset += 8;

    // Channel ID
    *reinterpret_cast<uint32_t*>(buffer.data() + offset) = channel_id_;
    offset += 4;

    // Operation ID
    *reinterpret_cast<uint16_t*>(buffer.data() + offset) = operation_id_.value;
    offset += 2;

    // Payload Length
    *reinterpret_cast<uint32_t*>(buffer.data() + offset) = static_cast<uint32_t>(payload_.size());
    offset += 4;

    // Schema ID
    *reinterpret_cast<uint16_t*>(buffer.data() + offset) = schema_id_;
    offset += 2;

    // Contract Hash Prefix
    std::memcpy(buffer.data() + offset, contract_hash_prefix_.data(), 12);
    offset += 12;

    // Nonce
    std::memcpy(buffer.data() + offset, nonce_.data(), protocol::NONCE_SIZE);
    offset += protocol::NONCE_SIZE;

    // Reserved
    *reinterpret_cast<uint32_t*>(buffer.data() + offset) = 0;
    offset += 4;

    // Payload
    if (!payload_.empty()) {
        std::memcpy(buffer.data() + offset, payload_.data(), payload_.size());
    }

    return buffer;
}

Frame Frame::parse(const std::vector<uint8_t>& data) {
    if (data.size() < HEADER_SIZE) {
        throw ContractParseException("Frame too short");
    }

    Frame frame;
    size_t offset = 0;

    // Magic
    if (std::memcmp(data.data() + offset, protocol::MAGIC, 4) != 0) {
        throw ContractParseException("Invalid frame magic");
    }
    offset += 4;

    // Version
    uint8_t version = data[offset++];
    if (version != protocol::PROTOCOL_VERSION) {
        throw ContractParseException("Unsupported protocol version");
    }

    frame.flags_ = FrameFlags::from_byte(data[offset++]);
    frame.packet_type_ = static_cast<PacketType>(data[offset++]);
    frame.role_ = static_cast<ContractRole>(data[offset++]);

    frame.session_id_ = *reinterpret_cast<const uint64_t*>(data.data() + offset);
    offset += 8;

    frame.sequence_ = *reinterpret_cast<const uint64_t*>(data.data() + offset);
    offset += 8;

    frame.channel_id_ = *reinterpret_cast<const uint32_t*>(data.data() + offset);
    offset += 4;

    frame.operation_id_ = OperationId(*reinterpret_cast<const uint16_t*>(data.data() + offset));
    offset += 2;

    uint32_t payload_len = *reinterpret_cast<const uint32_t*>(data.data() + offset);
    offset += 4;

    frame.schema_id_ = *reinterpret_cast<const uint16_t*>(data.data() + offset);
    offset += 2;

    std::memcpy(frame.contract_hash_prefix_.data(), data.data() + offset, 12);
    offset += 12;

    std::memcpy(frame.nonce_.data(), data.data() + offset, protocol::NONCE_SIZE);
    offset += protocol::NONCE_SIZE;

    // Skip reserved
    offset += 4;

    // Payload
    if (payload_len > 0) {
        frame.payload_ = std::vector<uint8_t>(data.begin() + offset, data.begin() + offset + payload_len);
    }

    return frame;
}

std::string Frame::payload_as_string() const {
    return std::string(payload_.begin(), payload_.end());
}

void Frame::set_payload_from_string(const std::string& str) {
    payload_ = std::vector<uint8_t>(str.begin(), str.end());
}

Frame Frame::create_error_frame(int error_code, const std::string& message) const {
    // El código se serializa byte a byte en little-endian. La versión
    // anterior hacía `*reinterpret_cast<int*>(ptr) = code`, que:
    //  - viola el aliasing y la alineación (comportamiento indefinido), y
    //  - escribe 4 bytes con ordenación nativa, de modo que el mismo error se
    //    decodificaba de forma distinta en big-endian.
    // El wire format es explícito y por tanto portable.
    const uint32_t code = static_cast<uint32_t>(error_code);

    std::vector<uint8_t> error_payload;
    error_payload.reserve(4 + message.size());
    for (int i = 0; i < 4; ++i) {
        error_payload.push_back(static_cast<uint8_t>((code >> (8 * i)) & 0xFF));
    }
    error_payload.insert(error_payload.end(), message.begin(), message.end());

    return Frame(session_id_, sequence_ + 1, channel_id_,
                 operation_id_, PacketType::ERROR, error_payload);
}

Frame Frame::create_ack_frame() const {
    return Frame(session_id_, sequence_, channel_id_,
                 operation_id_, PacketType::CONTROL, std::vector<uint8_t>{0x01});
}

Frame Frame::create_heartbeat_frame() const {
    return Frame(session_id_, sequence_, 0,
                 OperationId::ping(), PacketType::HEARTBEAT, {});
}

Frame Frame::create_eof_frame() const {
    Frame f(session_id_, sequence_, channel_id_,
            operation_id_, PacketType::EOF_, {});
    f.flags_.last_frame = true;
    return f;
}

// ============================================================================
// UTILIDADES DE FRAME
// ============================================================================

namespace FrameUtils {

Frame create_handshake_frame(const std::vector<uint8_t>& contract_hash,
                             uint8_t protocol_version) {
    std::vector<uint8_t> payload;
    payload.reserve(13);
    payload.push_back(protocol_version);

    std::array<uint8_t, 12> prefix;
    std::copy_n(contract_hash.begin(), 12, prefix.begin());
    payload.insert(payload.end(), prefix.begin(), prefix.end());

    Frame frame(0, 0, 0, OperationId::handshake(), PacketType::CONTROL, payload);
    frame.set_nonce(prefix);
    return frame;
}

Frame create_auth_frame(uint64_t session_id, const std::vector<uint8_t>& token,
                        const std::vector<uint8_t>& contract_hash) {
    std::vector<uint8_t> payload = token;
    std::array<uint8_t, 12> prefix;
    std::copy_n(contract_hash.begin(), 12, prefix.begin());
    payload.insert(payload.end(), prefix.begin(), prefix.end());

    Frame frame(session_id, 1, 0, OperationId::auth(), PacketType::CONTROL, payload);
    frame.set_flags(FrameFlags{});
    frame.set_nonce(prefix);
    return frame;
}

Frame create_session_start_frame(const std::vector<uint8_t>& contract_hash,
                                 ContractRole role) {
    std::vector<uint8_t> payload;
    payload.reserve(13);
    payload.push_back(static_cast<uint8_t>(role));

    std::array<uint8_t, 12> prefix;
    std::copy_n(contract_hash.begin(), 12, prefix.begin());
    payload.insert(payload.end(), prefix.begin(), prefix.end());

    Frame frame(0, 0, 0, OperationId::session_start(), PacketType::CONTROL, payload);
    frame.set_role(role);
    frame.set_nonce(prefix);
    return frame;
}

std::pair<uint8_t, uint64_t> parse_handshake_response(const Frame& frame) {
    if (frame.payload().size() < 9) {
        throw ContractParseException("Invalid handshake response");
    }
    uint8_t version = frame.payload()[0];
    uint64_t session_id = *reinterpret_cast<const uint64_t*>(frame.payload().data() + 1);
    return {version, session_id};
}

bool is_valid_handshake(const Frame& frame) {
    return frame.operation_id() == OperationId::handshake() &&
           frame.packet_type() == PacketType::CONTROL &&
           frame.payload().size() >= 9;
}

bool is_error_frame(const Frame& frame) {
    return frame.packet_type() == PacketType::ERROR;
}

int get_error_code(const Frame& frame) {
    if (!is_error_frame(frame) || frame.payload().size() < 4) {
        return -1;
    }
    return *reinterpret_cast<const int*>(frame.payload().data());
}

std::string get_error_message(const Frame& frame) {
    if (!is_error_frame(frame)) {
        return "";
    }
    if (frame.payload().size() <= 4) {
        return "";
    }
    return std::string(frame.payload().begin() + 4, frame.payload().end());
}

}  // namespace FrameUtils

}  // namespace ipc
