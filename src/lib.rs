// =============================================================================
// IPC Contract System v2 - Core Library
// =============================================================================
//
// Implementación del sistema de contratos binarios canónicos con seguridad
// criptográfica real.
//
// Arquitectura:
// ┌─────────────────────────────────────────────────────────────────────┐
// │                    Contract Definition (DSL/YAML)                   │
// │                         Formato humano-legible                       │
// └─────────────────────────────────┬───────────────────────────────────┘
//                                   │ contractc compile
//                                   ▼
// ┌─────────────────────────────────────────────────────────────────────┐
// │              Canonical Binary Contract (CBC)                        │
// │  ┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────┐   │
// │  │ MAGIC   │ HEADER  │ TYPES   │ OPS     │ SECURITY│ SIG     │   │
// │  │ CBC1    │         │ IDs     │ IDs     │ POLICY  │         │   │
// │  └─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘   │
// │                               │                                     │
// │                    BLAKE3-256 Hash (excluye firma)                │
// └─────────────────────────────────┬───────────────────────────────────┘
//                                   │
//              ┌────────────────────┼────────────────────┐
//              ▼                    ▼                    ▼
//         Rust Bindings       Kotlin Bindings      TS Bindings
//              │                    │                    │
//              └────────────────────┼────────────────────┘
//                                   ▼
//                         IPC Runtime v2
//
// @version 2.0.0
// =============================================================================

#![allow(unused_variables)]
#![allow(dead_code)]

pub mod binary_contract;
pub mod types;
pub mod operations;
pub mod security;
pub mod protocol;
pub mod generators;
pub mod error;

pub use binary_contract::{
    Contract, ContractHeader, ContractReader, ContractSigner, ContractWriter, ContractVersion,
};
pub use types::{TypeId, TypeRegistry, PrimitiveType};
pub use operations::{OperationId, OperationRegistry, Operation};
pub use security::{
    derive_nonce, production_policy, AeadCipher, AeadError, AntiReplay, AeadAlgorithm,
    Direction, KeyDerivation, ReplayWindow, SecurityLevel, SecurityPolicy, SessionKey,
    SignaturePolicy,
};
pub use protocol::{
    ContractRole, Frame, FrameFlags, HandshakeHello, PacketType, ProtocolError, WireProtocol,
    HELLO_CONTRACT_HASH_SIZE, HELLO_PAYLOAD_SIZE,
};
pub use error::{ContractError, Result};

// =============================================================================
// CONSTANTS
// =============================================================================

/// Magic bytes para CBC (Canonical Binary Contract)
/// CBC1 = Contract Binary Format version 1
pub const CBC_MAGIC: &[u8; 4] = b"CBC1";

/// Versión del formato binario
pub const FORMAT_VERSION: u8 = 1;

/// Versión del protocolo wire
pub const PROTOCOL_VERSION: u8 = 2;

/// Tamaño del hash del contrato (BLAKE3-256)
pub const CONTRACT_HASH_SIZE: usize = 32;

/// Tamaño del signature (Ed25519)
pub const SIGNATURE_SIZE: usize = 64;

/// Tamaño del nonce (12 bytes para ChaCha20/AES-GCM)
pub const NONCE_SIZE: usize = 12;

/// Tamaño mínimo del header
pub const MIN_HEADER_SIZE: usize = 64;

/// Tamaño máximo de payload (16MB)
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

/// Timeout de handshake (10 segundos)
pub const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

/// Timeout de keepalive (30 segundos)
pub const KEEPALIVE_TIMEOUT_MS: u64 = 30_000;

// =============================================================================
// VERSION INFO
// =============================================================================

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const VERSION_MAJOR: u8 = 2;
pub const VERSION_MINOR: u8 = 1;
pub const VERSION_PATCH: u8 = 0;

pub fn version_info() -> &'static str {
    concat!(
        "ipc-contract-system v",
        env!("CARGO_PKG_VERSION"),
        " (format v",
        stringify!(FORMAT_VERSION),
        ", protocol v",
        stringify!(PROTOCOL_VERSION),
        ")"
    )
}
