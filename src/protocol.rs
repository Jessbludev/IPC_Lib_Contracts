// =============================================================================
// Wire Protocol v2 - Protocolo de Comunicación Seguro
// =============================================================================
//
// Estructura del frame:
//
// +-----------------------------------------------------------------+
// |                         FRAME HEADER                              |
// +-----------------------------------------------------------------+
// | 0-3   | Magic (4)        | CBC1                                 |
// | 4     | Version (1)       | 0x02                                 |
// | 5     | Flags (1)        | Compressed(1) | Encrypted(2)         |
// | 6     | Packet Type (1)   | HELLO, REQUEST, RESPONSE, etc.       |
// | 7     | Role/Mode (1)    | CHILD, MUTUAL, PEER, MUX, STREAM    |
// +-----------------------------------------------------------------+
// | 8-15  | Session ID (8)   | u64                                  |
// | 16-23 | Sequence (8)     | u64 (para anti-replay y ordering)   |
// | 24-27 | Channel ID (4)   | u32 (para multiplexación)           |
// | 28-31 | Operation ID (4)| u16 (2 bytes usados, 2 reserved)   |
// +-----------------------------------------------------------------+
// | 32-35 | Payload Length (4)| u32                                  |
// | 36-39 | Schema ID (4)    | u16 type + u16 reserved             |
// | 40-51 | Contract Hash    | Primeros 12 bytes del hash BLAKE3-256 |
// +-----------------------------------------------------------------+
// | 52-63 | Nonce (12)       | Para AEAD                           |
// +-----------------------------------------------------------------+
//
// Payload (si está cifrado):
// +-----------------------------------------------------------------+
// |                         AUTHENTICATED DATA                        |
// +-----------------------------------------------------------------+
// | AAD (16 bytes)    | protocol_version + flags + operation_id    |
// +-----------------------------------------------------------------+
// | Encrypted Payload | ciphertext + auth_tag (16 bytes)            |
// +-----------------------------------------------------------------+
//
// =============================================================================

use serde::{Deserialize, Serialize};
use crate::types::TypeId;
use crate::operations::OperationId;

/// Tipos de roles de contrato
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContractRole {
    /// Proceso subordinado/controlado por otro
    Child = 0x01,

    /// Ambos extremos pueden iniciar operaciones
    Mutual = 0x02,

    /// Comunicación simétrica entre pares
    Peer = 0x03,

    /// Múltiples canales lógicos
    Mux = 0x04,

    /// Flujo persistente (streaming)
    Stream = 0x05,

    /// Comunicación unidireccional
    OneWay = 0x06,
}

/// Tipos de paquetes en el protocolo
///
/// Estructura de rangos:
/// - 0x00-0x0F: Control del protocolo
/// - 0x10-0x1F: Autenticación
/// - 0x20-0x2F: Operaciones request/response
/// - 0x30-0x3F: Streaming
/// - 0xE0-0xEF: Errores
/// - 0xF0-0xFF: Sistema (heartbeat, ping/pong)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketType {
    // -------------------------------------------------------------------------
    // Control del protocolo (0x00-0x0F)
    // -------------------------------------------------------------------------
    /// Cierre de conexión
    Close = 0x00,

    /// Inicio de handshake
    Hello = 0x01,
    /// Acknowledgment de handshake
    HelloAck = 0x02,
    /// Negación de handshake
    HelloNack = 0x03,

    // -------------------------------------------------------------------------
    // Autenticación (0x10-0x1F)
    // -------------------------------------------------------------------------
    /// Solicitud de autenticación
    Auth = 0x10,
    /// Autenticación exitosa
    AuthOk = 0x11,
    /// Autenticación fallida
    AuthNok = 0x12,

    // -------------------------------------------------------------------------
    // Operaciones (0x20-0x2F)
    // -------------------------------------------------------------------------
    /// Solicitud de operación
    Request = 0x20,
    /// Respuesta exitosa
    Response = 0x21,
    /// Respuesta de error
    ResponseError = 0x22,

    // -------------------------------------------------------------------------
    // Streaming (0x30-0x3F)
    // -------------------------------------------------------------------------
    /// Inicio de stream
    StreamStart = 0x30,
    /// Datos del stream
    StreamData = 0x31,
    /// Fin del stream
    StreamEnd = 0x32,
    /// Pausar stream
    StreamPause = 0x33,
    /// Reanudar stream
    StreamResume = 0x34,

    // -------------------------------------------------------------------------
    // Errores (0xE0-0xEF)
    // -------------------------------------------------------------------------
    /// Error genérico
    Error = 0xE0,
    /// Error de protocolo
    ProtocolError = 0xE1,
    /// Error de seguridad
    SecurityError = 0xE2,
    /// Error de timeout
    TimeoutError = 0xE3,

    // -------------------------------------------------------------------------
    // Sistema (0xF0-0xFF)
    // -------------------------------------------------------------------------
    /// Heartbeat
    Heartbeat = 0xF0,
    /// Acknowledgment de heartbeat
    HeartbeatAck = 0xF1,
    /// Ping (solicitud de pong)
    Ping = 0xFE,
    /// Pong (respuesta a ping)
    Pong = 0xFF,
}

/// Flags de frame
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameFlags(u8);

impl FrameFlags {
    pub const COMPRESSED: u8 = 0b00000001;
    pub const ENCRYPTED: u8 = 0b00000010;
    pub const PRIORITY: u8 = 0b00000100;
    pub const NO_ACK: u8 = 0b00001000;

    /// Bits definidos. Cualquier otro bit se rechaza al parsear.
    pub const KNOWN: u8 = Self::COMPRESSED | Self::ENCRYPTED | Self::PRIORITY | Self::NO_ACK;

    pub fn bits(&self) -> u8 {
        self.0
    }

    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    pub fn is_compressed(&self) -> bool {
        (self.0 & Self::COMPRESSED) != 0
    }

    pub fn is_encrypted(&self) -> bool {
        (self.0 & Self::ENCRYPTED) != 0
    }

    pub fn is_priority(&self) -> bool {
        (self.0 & Self::PRIORITY) != 0
    }

    pub fn no_ack(&self) -> bool {
        (self.0 & Self::NO_ACK) != 0
    }

    pub fn with_compressed(mut self, v: bool) -> Self {
        if v {
            self.0 |= Self::COMPRESSED;
        } else {
            self.0 &= !Self::COMPRESSED;
        }
        self
    }

    pub fn with_encrypted(mut self, v: bool) -> Self {
        if v {
            self.0 |= Self::ENCRYPTED;
        } else {
            self.0 &= !Self::ENCRYPTED;
        }
        self
    }
}

/// Frame del protocolo
#[derive(Debug, Clone)]
pub struct Frame {
    /// Magic (4 bytes)
    pub magic: [u8; 4],

    /// Versión del protocolo (1 byte)
    pub version: u8,

    /// Flags (1 byte)
    pub flags: FrameFlags,

    /// Tipo de paquete (1 byte)
    pub packet_type: PacketType,

    /// Rol del contrato (1 byte)
    pub role: ContractRole,

    /// ID de sesión (8 bytes)
    pub session_id: u64,

    /// Número de secuencia (8 bytes)
    pub sequence: u64,

    /// ID de canal (4 bytes)
    pub channel_id: u32,

    /// ID de operación (2 bytes)
    pub operation_id: OperationId,

    /// Longitud del payload (4 bytes)
    pub payload_length: u32,

    /// Schema del payload (2 bytes type + 2 bytes reserved)
    pub schema_id: TypeId,

    /// Prefijo del hash del contrato (12 bytes)
    pub contract_hash_prefix: [u8; 12],

    /// Nonce para AEAD (12 bytes)
    pub nonce: [u8; 12],

    /// Payload
    pub payload: Vec<u8>,
}

impl Frame {
    /// Tamaño del header
    pub const HEADER_SIZE: usize = 64;

    /// Tamaño del nonce dentro del header
    pub const NONCE_SIZE: usize = 12;

    /// Longitud del prefijo de `contract_hash` presente en cada frame
    pub const CONTRACT_HASH_PREFIX_SIZE: usize = 12;

    /// Crear nuevo frame
    pub fn new(
        packet_type: PacketType,
        role: ContractRole,
        session_id: u64,
        sequence: u64,
        channel_id: u32,
        operation_id: OperationId,
        schema_id: TypeId,
        contract_hash_prefix: &[u8; 12],
        payload: Vec<u8>,
    ) -> Self {
        Self {
            magic: *b"CBC1",
            version: crate::PROTOCOL_VERSION,
            flags: FrameFlags::default(),
            packet_type,
            role,
            session_id,
            sequence,
            channel_id,
            operation_id,
            payload_length: payload.len() as u32,
            schema_id,
            contract_hash_prefix: *contract_hash_prefix,
            nonce: [0u8; 12],
            payload,
        }
    }

    /// Serializar a bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.payload.len());

        // Magic
        buf.extend_from_slice(&self.magic);

        // Version
        buf.push(self.version);

        // Flags
        buf.push(self.flags.bits());

        // Packet type
        buf.push(self.packet_type as u8);

        // Role
        buf.push(self.role as u8);

        // Session ID
        buf.extend_from_slice(&self.session_id.to_le_bytes());

        // Sequence
        buf.extend_from_slice(&self.sequence.to_le_bytes());

        // Channel ID
        buf.extend_from_slice(&self.channel_id.to_le_bytes());

        // Operation ID
        buf.extend_from_slice(&(self.operation_id.0 as u16).to_le_bytes());
        buf.extend_from_slice(&[0u8, 0u8]); // Reserved

        // Payload length
        buf.extend_from_slice(&self.payload_length.to_le_bytes());

        // Schema ID
        buf.extend_from_slice(&(self.schema_id.0 as u16).to_le_bytes());
        buf.extend_from_slice(&[0u8, 0u8]); // Reserved

        // Contract hash prefix
        buf.extend_from_slice(&self.contract_hash_prefix);

        // Nonce
        buf.extend_from_slice(&self.nonce);

        // Payload
        buf.extend_from_slice(&self.payload);

        buf
    }

    /// Deserializar de bytes
    ///
    /// # Seguridad
    ///
    /// - Nunca usa unwrap() en datos de entrada
    /// - Valida MAX_PAYLOAD_SIZE
    /// - Verifica consistencia de tamaño de frame
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < Self::HEADER_SIZE {
            return Err(ProtocolError::FrameTooShort);
        }

        let mut offset: usize = 0;

        // Helper para leer slices con bounds checking
        macro_rules! read_slice {
            ($name:ident, $size:expr) => {
                let end = offset.checked_add($size)
                    .ok_or_else(|| ProtocolError::ParseError(concat!("overflow reading ", stringify!($name))))?;
                if end > data.len() {
                    return Err(ProtocolError::ParseError(concat!("out of bounds reading ", stringify!($name))));
                }
                let $name = &data[offset..end];
                offset = end;
            };
        }

        // Magic (4 bytes)
        read_slice!(magic_slice, 4);
        let magic: [u8; 4] = magic_slice.try_into()
            .map_err(|_| ProtocolError::ParseError("invalid magic size"))?;

        if &magic != b"CBC1" {
            return Err(ProtocolError::InvalidMagic);
        }

        // Version (1 byte)
        let version = data[offset];
        offset += 1;

        if version != crate::PROTOCOL_VERSION {
            return Err(ProtocolError::IncompatibleVersion(version));
        }

        // Flags (1 byte)
        let flags_bits = data[offset];
        // Rechazo por defecto de bits desconocidos (fail-closed).
        let unknown_flags = flags_bits & !FrameFlags::KNOWN;
        if unknown_flags != 0 {
            return Err(ProtocolError::UnknownFlags(unknown_flags));
        }
        let flags = FrameFlags::from_bits(flags_bits);
        offset += 1;

        // Packet type (1 byte)
        let packet_type = PacketType::try_from(data[offset])
            .map_err(|_: ProtocolError| ProtocolError::InvalidPacketType(data[offset]))?;
        offset += 1;

        // Role (1 byte)
        let role = ContractRole::try_from(data[offset])
            .map_err(|_: ProtocolError| ProtocolError::InvalidRole(data[offset]))?;
        offset += 1;

        // Session ID (8 bytes)
        read_slice!(session_bytes, 8);
        let session_id = u64::from_le_bytes(
            session_bytes.try_into()
                .map_err(|_| ProtocolError::ParseError("invalid session_id size"))?
        );

        // Sequence (8 bytes)
        read_slice!(sequence_bytes, 8);
        let sequence = u64::from_le_bytes(
            sequence_bytes.try_into()
                .map_err(|_| ProtocolError::ParseError("invalid sequence size"))?
        );

        // Channel ID (4 bytes)
        read_slice!(channel_bytes, 4);
        let channel_id = u32::from_le_bytes(
            channel_bytes.try_into()
                .map_err(|_| ProtocolError::ParseError("invalid channel_id size"))?
        );

        // Operation ID (2 bytes + 2 reserved)
        read_slice!(operation_bytes, 4);
        if operation_bytes[2] != 0 || operation_bytes[3] != 0 {
            return Err(ProtocolError::NonZeroReserved("operation_id"));
        }
        let operation_id = OperationId(
            u16::from_le_bytes(
                operation_bytes[..2].try_into()
                    .map_err(|_| ProtocolError::ParseError("invalid operation_id size"))?
            )
        );

        // Payload length (4 bytes)
        read_slice!(payload_len_bytes, 4);
        let payload_length = u32::from_le_bytes(
            payload_len_bytes.try_into()
                .map_err(|_| ProtocolError::ParseError("invalid payload_length size"))?
        );

        // Validar tamaño máximo de payload
        if payload_length > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                declared: payload_length,
                maximum: MAX_PAYLOAD_SIZE,
            });
        }

        // Schema ID (2 bytes + 2 reserved)
        read_slice!(schema_bytes, 4);
        if schema_bytes[2] != 0 || schema_bytes[3] != 0 {
            return Err(ProtocolError::NonZeroReserved("schema_id"));
        }
        let schema_id = TypeId(
            u16::from_le_bytes(
                schema_bytes[..2].try_into()
                    .map_err(|_| ProtocolError::ParseError("invalid schema_id size"))?
            )
        );

        // Contract hash prefix (12 bytes)
        read_slice!(hash_prefix_bytes, Self::CONTRACT_HASH_PREFIX_SIZE);
        let contract_hash_prefix: [u8; 12] = hash_prefix_bytes
            .try_into()
            .map_err(|_| ProtocolError::ParseError("invalid contract_hash_prefix size"))?;

        // Nonce (12 bytes)
        read_slice!(nonce_bytes, Self::NONCE_SIZE);
        let nonce: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| ProtocolError::ParseError("invalid nonce size"))?;

        // Payload. El offset debe coincidir exactamente con el final del
        // header: cualquier hueco implicaría un layout distinto alcanzable con
        // un header manipulado.
        if offset != Self::HEADER_SIZE {
            return Err(ProtocolError::ParseError("header layout mismatch"));
        }

        let payload_end = offset
            .checked_add(payload_length as usize)
            .ok_or(ProtocolError::ParseError("payload length overflow"))?;

        // Verificar que el frame tiene exactamente el tamaño esperado
        if data.len() != payload_end {
            return Err(ProtocolError::FrameSizeMismatch {
                expected: payload_end,
                actual: data.len(),
            });
        }

        let payload = data[offset..payload_end].to_vec();

        Ok(Self {
            magic,
            version,
            flags,
            packet_type,
            role,
            session_id,
            sequence,
            channel_id,
            operation_id,
            payload_length,
            schema_id,
            contract_hash_prefix,
            nonce,
            payload,
        })
    }

    /// Generar AAD (Additional Authenticated Data)
    ///
    /// El AAD cubre los 48 primeros bytes del header, es decir, todo lo que
    /// excepto el nonce (que es el IV) y el payload (que es el mensaje). Regla
    /// del protocolo: *todo campo del header que afecte la interpretación del
    /// payload debe estar autenticado*.
    pub fn get_aad(&self) -> Vec<u8> {
        self.header_aad()
    }

    /// AAD canónico = byte 0..48 del header serializado
    ///
    /// Se toma del propio header serializado en lugar de reensamblarlo campo a
    /// campo: garantiza que lo que se autentica es exactamente lo que viaja por
    /// el cable, sin riesgo de divergencia entre las dos representaciones.
    pub fn header_aad(&self) -> Vec<u8> {
        let bytes = self.to_bytes();
        // `to_bytes` siempre emite HEADER_SIZE (64) bytes de header como
        // mínimo, así que el slice es seguro.
        bytes[..Self::HEADER_SIZE - Self::NONCE_SIZE].to_vec()
    }

    /// Derivar el nonce de este frame
    ///
    /// P0.4: requiere la clave de nonce de sesión. La versión anterior de
    /// v2.1 derivaba el nonce sin ningún secreto:
    ///
    /// ```text
    /// BLAKE3("CBC2-NONCE" || session_id || sequence || direction)[0..12]
    /// ```
    ///
    /// lo que hacía los nonces calculables por cualquier observador. Ahora se
    /// usa BLAKE3 en modo keyed con la clave de sesión.
    pub fn derive_nonce(
        &self,
        nonce_key: &[u8; 32],
        direction: crate::security::Direction,
    ) -> [u8; 12] {
        crate::security::derive_nonce(nonce_key, self.session_id, self.sequence, direction)
    }
}

impl TryFrom<u8> for PacketType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0x00 => std::result::Result::Ok(PacketType::Close),
            0x01 => std::result::Result::Ok(PacketType::Hello),
            0x02 => std::result::Result::Ok(PacketType::HelloAck),
            0x03 => std::result::Result::Ok(PacketType::HelloNack),
            0x10 => std::result::Result::Ok(PacketType::Auth),
            0x11 => std::result::Result::Ok(PacketType::AuthOk),
            0x12 => std::result::Result::Ok(PacketType::AuthNok),
            0x20 => std::result::Result::Ok(PacketType::Request),
            0x21 => std::result::Result::Ok(PacketType::Response),
            0x22 => std::result::Result::Ok(PacketType::ResponseError),
            0x30 => std::result::Result::Ok(PacketType::StreamStart),
            0x31 => std::result::Result::Ok(PacketType::StreamData),
            0x32 => std::result::Result::Ok(PacketType::StreamEnd),
            0x33 => std::result::Result::Ok(PacketType::StreamPause),
            0x34 => std::result::Result::Ok(PacketType::StreamResume),
            0xE0 => std::result::Result::Ok(PacketType::Error),
            0xE1 => std::result::Result::Ok(PacketType::ProtocolError),
            0xE2 => std::result::Result::Ok(PacketType::SecurityError),
            0xE3 => std::result::Result::Ok(PacketType::TimeoutError),
            0xF0 => std::result::Result::Ok(PacketType::Heartbeat),
            0xF1 => std::result::Result::Ok(PacketType::HeartbeatAck),
            0xFE => std::result::Result::Ok(PacketType::Ping),
            0xFF => std::result::Result::Ok(PacketType::Pong),
            _ => std::result::Result::Err(ProtocolError::InvalidPacketType(value)),
        }
    }
}

impl TryFrom<u8> for ContractRole {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0x01 => std::result::Result::Ok(ContractRole::Child),
            0x02 => std::result::Result::Ok(ContractRole::Mutual),
            0x03 => std::result::Result::Ok(ContractRole::Peer),
            0x04 => std::result::Result::Ok(ContractRole::Mux),
            0x05 => std::result::Result::Ok(ContractRole::Stream),
            0x06 => std::result::Result::Ok(ContractRole::OneWay),
            _ => std::result::Result::Err(ProtocolError::InvalidRole(value)),
        }
    }
}

/// Errores del protocolo
///
/// Todos los errores son no-fatales y pueden ser manejados por el llamador.
/// Nunca se debe usar panic en respuesta a datos de entrada remotos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// Frame más corto que el header mínimo
    FrameTooShort,

    /// Magic bytes inválidos (no es "CBC1")
    InvalidMagic,

    /// Versión de protocolo incompatible
    IncompatibleVersion(u8),

    /// Tipo de paquete desconocido
    InvalidPacketType(u8),

    /// Rol de contrato desconocido
    InvalidRole(u8),

    /// Payload demasiado corto para lo declarado
    PayloadTooShort,

    /// Payload excede el tamaño máximo permitido
    PayloadTooLarge {
        declared: u32,
        maximum: u32,
    },

    /// Tamaño de frame inconsistente
    FrameSizeMismatch {
        expected: usize,
        actual: usize,
    },

    /// Fallo en descifrado
    DecryptionFailed,

    /// Fallo en autenticación (HMAC/AEAD)
    AuthenticationFailed,

    /// Ataque de replay detectado
    AntiReplayDetected,

    /// Fallo en parsing de datos
    ParseError(&'static str),

    /// Bits de flag no reconocidos (fail-closed)
    UnknownFlags(u8),

    /// Bytes reservados con valor distinto de cero
    NonZeroReserved(&'static str),

    /// Nonce inválido o reutilizado
    InvalidNonce,
}

/// Máximo tamaño de payload permitido
pub const MAX_PAYLOAD_SIZE: u32 = 16 * 1024 * 1024; // 16 MB

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolError::FrameTooShort => write!(f, "frame too short"),
            ProtocolError::InvalidMagic => write!(f, "invalid magic bytes"),
            ProtocolError::IncompatibleVersion(v) => write!(f, "incompatible version: {}", v),
            ProtocolError::InvalidPacketType(v) => write!(f, "invalid packet type: {:#04x}", v),
            ProtocolError::InvalidRole(v) => write!(f, "invalid role: {:#04x}", v),
            ProtocolError::PayloadTooShort => write!(f, "payload too short"),
            ProtocolError::PayloadTooLarge { declared, maximum } => {
                write!(f, "payload too large: {} > {} bytes", declared, maximum)
            }
            ProtocolError::FrameSizeMismatch { expected, actual } => {
                write!(f, "frame size mismatch: expected {} but got {}", expected, actual)
            }
            ProtocolError::DecryptionFailed => write!(f, "decryption failed"),
            ProtocolError::AuthenticationFailed => write!(f, "authentication failed"),
            ProtocolError::AntiReplayDetected => write!(f, "anti-replay: replay detected"),
            ProtocolError::ParseError(msg) => write!(f, "parse error: {}", msg),
            ProtocolError::UnknownFlags(bits) => {
                write!(f, "unknown frame flags: {:#04x}", bits)
            }
            ProtocolError::NonZeroReserved(field) => {
                write!(f, "reserved bytes of {} must be zero", field)
            }
            ProtocolError::InvalidNonce => write!(f, "invalid or reused nonce"),
        }
    }
}

impl std::error::Error for ProtocolError {}

// =============================================================================
// HANDSHAKE
// =============================================================================
//
// P0.6: la identidad completa del contrato (32 bytes) viaja en el HELLO.
//
// El frame normal sólo lleva `contract_hash_prefix[12]`, suficiente como
// discriminador rápido pero NO como identidad criptográfica: 12 bytes permiten
// que un atacante construya un prefijo idéntico con una identidad distinta. La
// identidad autoritativa se negocia una vez, en el HELLO, y ambos extremos
// deben compararla completa antes de establecer claves de sesión.
//
// LAYOUT DEL PAYLOAD HELLO (72 bytes, orden canónico):
//
// | 0-1   | protocol_version (u16) |
// | 2-3   | hello_flags (u16)      |
// | 4-35  | contract_hash[32]      |  <- identidad autoritativa
// | 36-39 | security_level (u32)   |
// | 40-43 | aead_algorithm (u32)   |
// | 44-47 | hash_algorithm (u32)   |
// | 48-51 | signature_policy (u32) |
// | 52-55 | replay_window (u32)    |
// | 56-59 | reserved (u32)         |
// | 60-63 | client_challenge (u32) |
// | 64-71 | reserved (8)           |
//
// -----------------------------------------------------------------------------

use crate::security::{Direction, SecurityLevel, AeadAlgorithm, HashAlgorithm, SignaturePolicy};

/// Tamaño del payload HELLO serializado
pub const HELLO_PAYLOAD_SIZE: usize = 72;

/// Bytes de contrato que viajan en el HELLO
pub const HELLO_CONTRACT_HASH_SIZE: usize = 32;

/// Handshake HELLO: negociación inicial de identidad y política
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeHello {
    /// Versión del protocolo
    pub protocol_version: u16,
    /// Identidad criptográfica completa del contrato
    pub contract_hash: [u8; 32],
    /// Nivel de seguridad requerido por el emisor
    pub security_level: SecurityLevel,
    /// AEAD deseado
    pub aead_algorithm: AeadAlgorithm,
    /// Hash de identidad
    pub hash_algorithm: HashAlgorithm,
    /// Política de firma exigida
    pub signature_policy: SignaturePolicy,
    /// Tamaño de ventana anti-replay solicitado
    pub replay_window: u32,
    /// Nonce de desafío del cliente (evita reflexión en el HELLO)
    pub client_challenge: u32,
}

impl HandshakeHello {
    /// Construir un HELLO a partir de la identidad del contrato local
    pub fn from_contract(
        contract_hash: &[u8; 32],
        policy: &crate::security::SecurityPolicy,
    ) -> Self {
        Self {
            protocol_version: crate::PROTOCOL_VERSION as u16,
            contract_hash: *contract_hash,
            security_level: policy.level,
            aead_algorithm: policy.aead_algorithm,
            hash_algorithm: policy.hash_algorithm,
            signature_policy: policy.signature_policy,
            replay_window: policy.replay_window_size as u32,
            client_challenge: 0, // lo rellena el emisor con entropía
        }
    }

    /// Serializar a bytes canónicos
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HELLO_PAYLOAD_SIZE);
        buf.extend_from_slice(&self.protocol_version.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // hello_flags reservado
        buf.extend_from_slice(&self.contract_hash);
        buf.extend_from_slice(&(self.security_level as u32).to_le_bytes());
        buf.extend_from_slice(&(self.aead_algorithm as u32).to_le_bytes());
        buf.extend_from_slice(&(self.hash_algorithm as u32).to_le_bytes());
        buf.extend_from_slice(&(self.signature_policy as u32).to_le_bytes());
        buf.extend_from_slice(&self.replay_window.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // reservado
        buf.extend_from_slice(&self.client_challenge.to_le_bytes());
        buf.extend_from_slice(&[0u8; 8]); // reservado
        buf
    }

    /// Parsear desde bytes, sin panic
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProtocolError> {
        if data.len() < HELLO_PAYLOAD_SIZE {
            return Err(ProtocolError::FrameTooShort);
        }

        let u16_at = |o: usize| -> u16 { u16::from_le_bytes([data[o], data[o + 1]]) };
        let u32_at =
            |o: usize| -> u32 { u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]) };

        let protocol_version = u16_at(0);
        if protocol_version as u8 != crate::PROTOCOL_VERSION {
            return Err(ProtocolError::IncompatibleVersion(protocol_version as u8));
        }

        let mut contract_hash = [0u8; 32];
        contract_hash.copy_from_slice(&data[4..36]);

        let security_level = match u32_at(36) {
            0x01 => SecurityLevel::IntegrityOnly,
            0x02 => SecurityLevel::Authenticated,
            0x03 => SecurityLevel::Encrypted,
            _ => return Err(ProtocolError::ParseError("unknown security level")),
        };
        let aead_algorithm = match u32_at(40) {
            0x01 => AeadAlgorithm::ChaCha20Poly1305,
            0x02 => AeadAlgorithm::Aes256Gcm,
            _ => return Err(ProtocolError::ParseError("unknown aead")),
        };
        let hash_algorithm = match u32_at(44) {
            0x01 => HashAlgorithm::Sha256,
            0x02 => HashAlgorithm::Blake3,
            _ => return Err(ProtocolError::ParseError("unknown hash")),
        };
        let signature_policy = match u32_at(48) {
            0x00 => SignaturePolicy::None,
            0x01 => SignaturePolicy::Optional,
            0x02 => SignaturePolicy::Required,
            _ => return Err(ProtocolError::ParseError("unknown signature policy")),
        };

        let replay_window = u32_at(52);
        if replay_window == 0 || replay_window as usize > crate::security::ReplayWindow::MAX_WINDOW {
            return Err(ProtocolError::ParseError("invalid replay window"));
        }

        Ok(Self {
            protocol_version,
            contract_hash,
            security_level,
            aead_algorithm,
            hash_algorithm,
            signature_policy,
            replay_window,
            client_challenge: u32_at(60),
        })
    }

    /// Comparar la identidad completa del contrato (P0.6)
    ///
    /// Devuelve `false` en cuanto un byte difiere. Ambos operandos son
    /// públicos (identidades de contrato, no secretos), así que no hace falta
    /// una comparación en tiempo constante.
    pub fn matches_contract(&self, local_hash: &[u8; 32]) -> bool {
        self.contract_hash == *local_hash
    }
}

/// Estado de un protocolo de sesión sobre un frame
///
/// Envuelve el frame con verificación de integridad, descifrado y anti-replay
/// en el orden correcto.
pub struct WireProtocol;

impl WireProtocol {
    /// Verificar y decifrar un frame recibido.
    ///
    /// # Orden de operaciones (obligatorio)
    /// 1. Validar el frame estructuralmente
    /// 2. Comprobar el prefijo de `contract_hash` (discriptor rápido)
    /// 3. Verificar AEAD sobre el AAD del header (autenticidad)
    /// 4. Sólo entonces registrar la secuencia en la ventana anti-replay
    ///
    /// El paso 4 va después del 3 a propósito: un atacante sin la clave no debe
    /// poder avanzar la ventana de un emisor legítimo.
    pub fn receive(
        frame: &Frame,
        contract_hash_prefix: &[u8; 12],
        decryption_key: &[u8; 32],
        cipher: &crate::security::AeadCipher,
        anti_replay: &crate::security::AntiReplay,
    ) -> Result<Vec<u8>, ProtocolError> {
        // 2. Discriminador rápido
        if &frame.contract_hash_prefix != contract_hash_prefix {
            return Err(ProtocolError::ParseError("contract hash prefix mismatch"));
        }

        // 3. AEAD. `header_aad()` reconstruye exactamente los 48 bytes
        //    autenticados a partir del frame tal como llegó.
        let aad = frame.header_aad();
        let plaintext = cipher
            .decrypt_chacha20(decryption_key, &frame.nonce, &aad, &frame.payload)
            .map_err(|_| ProtocolError::DecryptionFailed)?;

        // 4. Anti-replay, sólo tras autenticar
        anti_replay
            .check(frame.session_id, Direction::Rx, frame.sequence)
            .map_err(|_| ProtocolError::AntiReplayDetected)?;

        Ok(plaintext)
    }

    /// Cifrar y preparar un frame para envío
    pub fn send(
        frame: &mut Frame,
        nonce_key: &[u8; 32],
        encryption_key: &[u8; 32],
        direction: Direction,
        cipher: &crate::security::AeadCipher,
    ) -> Result<(), ProtocolError> {
        let nonce =
            crate::security::derive_nonce(nonce_key, frame.session_id, frame.sequence, direction);
        frame.nonce = nonce;

        let aad = frame.header_aad();
        let ciphertext = cipher
            .encrypt_chacha20(encryption_key, &nonce, &aad, &frame.payload)
            .map_err(|_| ProtocolError::DecryptionFailed)?;

        frame.payload = ciphertext;
        frame.payload_length = frame.payload.len() as u32;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_serialization() {
        let frame = Frame::new(
            PacketType::Request,
            ContractRole::Mutual,
            12345,
            1,
            0,
            OperationId(0x0101),
            TypeId(0x0003),
            &[0u8; 12],
            b"test payload".to_vec(),
        );

        let bytes = frame.to_bytes();
        let parsed = Frame::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.session_id, 12345);
        assert_eq!(parsed.sequence, 1);
        assert_eq!(parsed.payload, b"test payload");
    }

    #[test]
    fn test_frame_size() {
        let frame = Frame::new(
            PacketType::Hello,
            ContractRole::Child,
            1,
            0,
            0,
            OperationId::HANDSHAKE,
            TypeId(0),
            &[0u8; 12],
            vec![],
        );

        assert_eq!(frame.to_bytes().len(), Frame::HEADER_SIZE);
    }
}
