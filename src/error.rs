// =============================================================================
// Tipos de Error
// =============================================================================

use thiserror::Error;

/// Resultado de operaciones de contrato
pub type Result<T> = std::result::Result<T, ContractError>;

/// Errores del sistema de contratos
#[derive(Error, Debug)]
pub enum ContractError {
    // -------------------------------------------------------------------------
    // Errores de formato
    // -------------------------------------------------------------------------
    #[error("Magic inválido")]
    InvalidMagic,

    #[error("Versión de formato incompatible: {0}")]
    IncompatibleFormat(u8),

    #[error("Header inválido: {0}")]
    InvalidHeader(String),

    #[error("Sección inválida: {0}")]
    InvalidSection(String),

    #[error("Versión de contrato inválida")]
    InvalidVersion,

    #[error("Hash no coincide - contrato modificado")]
    HashMismatch,

    // -------------------------------------------------------------------------
    // Errores de seguridad
    // -------------------------------------------------------------------------
    #[error("Error de cifrado: {0}")]
    EncryptionError(String),

    #[error("Error de descifrado: {0}")]
    DecryptionError(String),

    #[error("Autenticación fallida")]
    AuthenticationFailed,

    #[error("Protección anti-replay activada")]
    AntiReplayDetected,

    #[error("Firma inválida")]
    InvalidSignature,

    // -------------------------------------------------------------------------
    // Errores de handshake
    // -------------------------------------------------------------------------
    #[error("Handshake fallido: {0}")]
    HandshakeFailed(String),

    #[error("Contract mismatch: hashes no coinciden")]
    ContractMismatch,

    #[error("Autenticación requerida pero no proporcionada")]
    AuthenticationRequired,

    // -------------------------------------------------------------------------
    // Errores de sesión
    // -------------------------------------------------------------------------
    #[error("Sesión no encontrada: {0}")]
    SessionNotFound(u64),

    #[error("Sesión expirada")]
    SessionExpired,

    #[error("Sesión cerrada")]
    SessionClosed,

    // -------------------------------------------------------------------------
    // Errores de operación
    // -------------------------------------------------------------------------
    #[error("Operación no encontrada: {0}")]
    OperationNotFound(u16),

    #[error("Timeout de operación")]
    OperationTimeout,

    #[error("Operación no soportada en este rol")]
    OperationNotSupported,

    // -------------------------------------------------------------------------
    // Errores de transporte
    // -------------------------------------------------------------------------
    #[error("Error de I/O: {0}")]
    IoError(String),

    #[error("Conexión cerrada")]
    ConnectionClosed,

    #[error("Timeout de conexión")]
    ConnectionTimeout,

    #[error("Socket no disponible: {0}")]
    SocketNotAvailable(String),

    // -------------------------------------------------------------------------
    // Errores genéricos
    // -------------------------------------------------------------------------
    #[error("Error interno: {0}")]
    Internal(String),
}

impl From<crate::security::AeadError> for ContractError {
    fn from(e: crate::security::AeadError) -> Self {
        use crate::security::AeadError;
        match e {
            AeadError::DecryptionFailed => ContractError::DecryptionError("AEAD".into()),
            AeadError::AuthenticationFailed => ContractError::AuthenticationFailed,
            AeadError::InvalidNonce => ContractError::EncryptionError("nonce inválido".into()),
            _ => ContractError::EncryptionError("fallo de cifrado".into()),
        }
    }
}

impl From<crate::protocol::ProtocolError> for ContractError {
    fn from(e: crate::protocol::ProtocolError) -> Self {
        use crate::protocol::ProtocolError;
        match e {
            ProtocolError::DecryptionFailed => ContractError::DecryptionError("AEAD".into()),
            ProtocolError::AuthenticationFailed => ContractError::AuthenticationFailed,
            ProtocolError::AntiReplayDetected => ContractError::AntiReplayDetected,
            ProtocolError::InvalidNonce => ContractError::EncryptionError("nonce inválido".into()),
            other => ContractError::Internal(other.to_string()),
        }
    }
}
