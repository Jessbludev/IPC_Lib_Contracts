//! Fuzzing de los parsers de datos externos.
//!
//! Objetivo P0.5: ningun byte remoto puede provocar un panic, una asignacion
//! desbordada ni un bucle infinito. Un fallo es siempre `Err`.
//!
//! Estos tests usan generacion aleatoria de proptest, mas rapido que AFL para
//! esta clase de entradas y suficiente para cazar los casos comunes:
//! truncamiento, longitudes absurdas, bytes no UTF-8, flags y enums fuera de
//! rango.
//!
//! Nota de sintaxis: dentro del macro proptest no puede haber comentarios de
//! ninguna clase. Un `//` o un `///` en medio del bloque hace que el macro
//! descarte silenciosamente todo su contenido, y el fichero compila sin
//! errores pero sin registrar ningun test. Por eso los tests de este modulo
//! no llevan comentarios inline.

use ipc_contract_system::binary_contract::{Contract, ContractHeader, ContractReader, ContractSigner};
use ipc_contract_system::operations::OperationId;
use ipc_contract_system::protocol::{Frame, PacketType, ProtocolError};
use ipc_contract_system::types::{TypeId, TypeKind};
use ipc_contract_system::{ContractRole, ContractVersion};
use ed25519_dalek::SigningKey;
use proptest::prelude::*;

/// Frame de request valido, base para las mutaciones.
fn sample_frame(payload: &[u8]) -> Frame {
    Frame::new(
        PacketType::Request,
        ContractRole::Mutual,
        42,
        1,
        0,
        OperationId(0x0101),
        TypeId(0x0003),
        &[7u8; 12],
        payload.to_vec(),
    )
}

proptest! {
    #[test]
    fn frame_parser_never_panics(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = Frame::from_bytes(&data);
    }

    #[test]
    fn frame_parser_rejects_truncation(len in 0usize..64) {
        let bytes = sample_frame(b"payload").to_bytes();
        let r = Frame::from_bytes(&bytes[..len.min(bytes.len())]);
        prop_assert!(r.is_err());
    }

    #[test]
    fn frame_rejects_bad_magic(pos in 0usize..4) {
        let mut bytes = sample_frame(b"x").to_bytes();
        bytes[pos] = b'Z';
        prop_assert!(
            matches!(Frame::from_bytes(&bytes), Err(ProtocolError::InvalidMagic)),
            "el magic alterado debe rechazarse"
        );
    }

    #[test]
    fn frame_rejects_unknown_flags(bit in 0u8..8) {
        let mut bytes = sample_frame(b"x").to_bytes();
        bytes[5] = 1u8 << bit;
        match Frame::from_bytes(&bytes) {
            Ok(_) => prop_assert!(bit < 4, "un flag desconocido no debe aceptarse"),
            Err(ProtocolError::UnknownFlags(_)) => prop_assert!(bit >= 4),
            Err(other) => prop_assert!(false, "error inesperado: {}", other),
        }
    }


    #[test]
    fn frame_rejects_trailing_bytes(extra in prop::collection::vec(any::<u8>(), 1..64)) {
        let mut bytes = sample_frame(b"payload").to_bytes();
        bytes.extend_from_slice(&extra);
        prop_assert!(
            matches!(
                Frame::from_bytes(&bytes),
                Err(ProtocolError::FrameSizeMismatch { .. })
            ),
            "bytes sobrantes tras el payload deben rechazarse"
        );
    }
}

proptest! {
    #[test]
    fn header_parser_never_panics(data in prop::collection::vec(any::<u8>(), 0..256)) {
        let _ = ContractHeader::from_bytes(&data);
    }

    #[test]
    fn contract_reader_never_panics(data in prop::collection::vec(any::<u8>(), 0..8192)) {
        let _ = ContractReader::from_bytes(&data);
    }

    #[test]
    fn contract_reader_survives_random_offsets(offset in any::<u32>(), size in any::<u32>()) {
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(b"CBC1");
        data[4] = 1;
        data[6..8].copy_from_slice(&256u16.to_le_bytes());
        data[64..68].copy_from_slice(&offset.to_le_bytes());
        data[68..72].copy_from_slice(&size.to_le_bytes());
        let _ = ContractReader::from_bytes(&data);
    }
}

proptest! {
    #[test]
    fn contract_roundtrip_is_stable(
        name in "[a-zA-Z0-9_]{1,63}",
        n_types in 0usize..8,
        n_ops in 0usize..8,
    ) {
        let mut c = Contract::new(&name, "ns", ContractVersion::new(1, 0, 0));
        c.header.contract_id = 42;

        for i in 0..n_types {
            c.types.register(
                &format!("T{i}"),
                TypeKind::Array {
                    element_type: TypeId(0x0003),
                    max_length: (i as u32) + 1,
                },
            );
        }
        for i in 0..n_ops {
            c.operations
                .register_auto(&format!("op{i}"), "d", TypeId(0x0003), TypeId(0x0001));
        }

        c.finalize().unwrap();

        let sk = SigningKey::from_bytes(&[9u8; 32]);
        ContractSigner::sign(&mut c, &sk).unwrap();

        let binary = c.to_binary().unwrap();
        let parsed = ContractReader::from_bytes(&binary).unwrap();

        prop_assert_eq!(&parsed.header.name, &c.header.name);
        prop_assert_eq!(parsed.header.contract_hash, c.header.contract_hash);
        prop_assert_eq!(parsed.types.compounds().count(), n_types);
        prop_assert_eq!(parsed.operations.iter().count(), n_ops);
    }

    #[test]
    fn tampering_is_detected(pos in 0usize..4096) {
        let mut c = Contract::new("c", "n", ContractVersion::new(1, 0, 0));
        c.header.contract_id = 1;
        c.types.register(
            "T",
            TypeKind::Array { element_type: TypeId(0x0003), max_length: 4 },
        );
        c.operations.register_auto("op", "d", TypeId(1), TypeId(2));
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        ContractSigner::sign(&mut c, &sk).unwrap();

        let mut binary = c.to_binary().unwrap();
        let p = pos % binary.len();
        binary[p] ^= 0xFF;

        if let Ok(parsed) = ContractReader::from_bytes(&binary) {
            let vk = sk.verifying_key();
            prop_assert!(
                ContractSigner::verify(&parsed, &vk).is_err(),
                "un contrato alterado no debe pasar la verificacion de firma"
            );
        }
    }
}

/// `payload_length` mayor que MAX_PAYLOAD_SIZE se rechaza antes de reservar.
///
/// Test determinista: `proptest!` exige al menos un parámetro generador, así
/// que un caso sin parámetros debe vivir fuera del macro.
#[test]
fn frame_rejects_huge_payload_length() {
    let mut bytes = sample_frame(b"x").to_bytes();
    bytes[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        Frame::from_bytes(&bytes),
        Err(ProtocolError::PayloadTooLarge { .. })
    ));
}
