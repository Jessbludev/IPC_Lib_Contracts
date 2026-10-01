//! Conformidad cross-language: fija los valores dorados de
//! `tests/vectors/crypto.json`.
//!
//! Estos valores son la referencia que Kotlin y C++ deben reproducir byte a
//! byte. Si este test falla, la identidad del contrato o la derivación de
//! claves cambiaron y los demás bindings quedan obsoletos: hay que regenerar
//! los vectores y volver a validar los tres lenguajes.
//!
//! Regenerar: `cargo run --example conformance_vectors > tests/vectors/crypto.json`

use ipc_contract_system::binary_contract::ContractSigner;
use ipc_contract_system::security::{
    derive_nonce, AeadAlgorithm, AeadCipher, AntiReplay, AntiReplayError, Direction, KeyDerivation,
};
use ipc_contract_system::types::{TypeId, TypeKind};
use ipc_contract_system::{Contract, ContractVersion};
use serde_json::Value;
use std::path::Path;

fn vectors() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/crypto.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("no se pudo leer {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("los vectores deben ser JSON válido")
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex válido"))
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn arr32(hex: &str) -> [u8; 32] {
    hex_to_bytes(hex).try_into().expect("32 bytes")
}

// ---------------------------------------------------------------------------
// P0.1: BLAKE3-256 único
// ---------------------------------------------------------------------------

#[test]
fn blake3_matches_golden_vectors() {
    let v = vectors();

    let cases: Vec<(Vec<u8>, &str)> = vec![
        (vec![], "empty"),
        (b"abc".to_vec(), "abc"),
        (vec![0u8; 256], "contract_header_256"),
        ((1u8..=64).collect(), "seq_1_to_64"),
        (b"contrato-espanol-nihon".to_vec(), "utf8_accents"),
        (vec![0u8; 1024], "zeros_1024"),
    ];

    for (data, key) in cases {
        let got = bytes_to_hex(&ipc_contract_system::security::blake3_hash(&data));
        let want = v["blake3"][key].as_str().unwrap_or_else(|| panic!("falta el vector {key}"));
        assert_eq!(got, want, "BLAKE3 diverge en el vector '{key}'");
    }
}

// ---------------------------------------------------------------------------
// P0.4: derivación de claves y nonce
// ---------------------------------------------------------------------------

#[test]
fn key_derivation_matches_golden_vectors() {
    let v = vectors();
    let k = &v["kdf"];

    let secret = arr32(k["secret_hex"].as_str().unwrap());
    let contract_hash = arr32(k["contract_hash_hex"].as_str().unwrap());
    let session_id = k["session_id"].as_u64().unwrap();

    let kd = KeyDerivation::new(&secret);
    let session_key = kd.derive_session_key(&contract_hash, session_id);

    assert_eq!(bytes_to_hex(&session_key.0), k["session_key"].as_str().unwrap());
    assert_eq!(
        bytes_to_hex(&kd.derive_nonce_key(&contract_hash, session_id).0),
        k["nonce_key"].as_str().unwrap()
    );
    assert_eq!(
        bytes_to_hex(&kd.derive_encryption_key(&session_key.0).0),
        k["encryption_key"].as_str().unwrap()
    );
    assert_eq!(
        bytes_to_hex(&kd.derive_auth_key(&session_key.0).0),
        k["auth_key"].as_str().unwrap()
    );
}

#[test]
fn nonce_derivation_matches_golden_vectors() {
    let v = vectors();
    let n = &v["nonce"];
    let nonce_key = arr32(n["nonce_key_hex"].as_str().unwrap());

    let cases = [
        ("tx_s42_q7", 42u64, 7u64, Direction::Tx),
        ("rx_s42_q7", 42, 7, Direction::Rx),
        ("tx_s42_q8", 42, 8, Direction::Tx),
        ("tx_s43_q7", 43, 7, Direction::Tx),
        ("tx_s42_q0", 42, 0, Direction::Tx),
    ];

    for (key, session, seq, dir) in cases {
        let got = bytes_to_hex(&derive_nonce(&nonce_key, session, seq, dir));
        assert_eq!(got, n[key].as_str().unwrap(), "nonce diverge en '{key}'");
    }
}

// ---------------------------------------------------------------------------
// P0.2: Ed25519 real
// ---------------------------------------------------------------------------

#[test]
fn ed25519_matches_golden_vectors() {
    use ed25519_dalek::{Signer, Verifier};
    let v = vectors();
    let e = &v["ed25519"];

    let sk = arr32(e["private_key_hex"].as_str().unwrap());
    let msg = hex_to_bytes(e["message_hex"].as_str().unwrap());
    let expected_pub = arr32(e["public_key_hex"].as_str().unwrap());
    let expected_sig = hex_to_bytes(e["signature_hex"].as_str().unwrap());

    let signing = ed25519_dalek::SigningKey::from_bytes(&sk);
    let verifying = signing.verifying_key();

    // La clave pública debe derivarse de la privada por la curva, no ser un
    // hash de ella (que es lo que hacía la versión anterior).
    assert_eq!(
        bytes_to_hex(verifying.as_bytes()),
        bytes_to_hex(&expected_pub),
        "la clave pública no coincide: no es una clave Ed25519 derivada"
    );

    let sig = signing.sign(&msg);
    assert_eq!(bytes_to_hex(&sig.to_bytes()), bytes_to_hex(&expected_sig));
    assert!(verifying.verify(&msg, &sig).is_ok());

    // Firma manipulada debe rechazarse
    let mut forged = expected_sig.clone();
    forged[0] ^= 0x01;
    let forged_sig = ed25519_dalek::Signature::from_bytes(
        forged.as_slice().try_into().unwrap(),
    );
    assert!(
        verifying.verify(&msg, &forged_sig).is_err(),
        "una firma manipulada no debe verificar"
    );

    // Mensaje manipulado debe rechazarse
    let mut other_msg = msg.clone();
    other_msg[0] ^= 0xFF;
    assert!(verifying.verify(&other_msg, &sig).is_err());
}

// ---------------------------------------------------------------------------
// P0.3: máquina de estados anti-replay
// ---------------------------------------------------------------------------

#[test]
fn anti_replay_matches_golden_transcript() {
    let v = vectors();
    let r = &v["replay"];
    let window = r["window_size"].as_u64().unwrap() as usize;

    let ar = AntiReplay::new(window);
    let transcript = r["transcript"].as_array().expect("transcript");

    for entry in transcript {
        let seq = entry["seq"].as_u64().unwrap();
        let expected = entry["expected"].as_str().unwrap();

        let got = match ar.check(7, Direction::Rx, seq) {
            Ok(()) => "accept",
            Err(AntiReplayError::Replay { .. }) => "replay",
            Err(AntiReplayError::SequenceOutOfWindow { .. }) => "out_of_window",
        };

        assert_eq!(
            got, expected,
            "la ventana anti-replay cambió de comportamiento en seq={seq}"
        );
    }

    // Estado final esperado
    let (highest, initialized, bitmap) = ar.snapshot(7, Direction::Rx).expect("ventana");
    assert_eq!(highest, r["final_highest"].as_u64().unwrap());
    assert_eq!(initialized, r["final_initialized"].as_bool().unwrap());

    let want_bitmap: Vec<u64> = r["final_bitmap_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| u64::from_str_radix(s.as_str().unwrap(), 16).unwrap())
        .collect();
    assert_eq!(bitmap, want_bitmap, "el bitmap final difiere");
}

// ---------------------------------------------------------------------------
// AEAD determinista
// ---------------------------------------------------------------------------

#[test]
fn aead_matches_golden_vector() {
    let v = vectors();
    let a = &v["aead"];

    let key = arr32(a["key_hex"].as_str().unwrap());
    let nonce: [u8; 12] = hex_to_bytes(a["nonce_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let aad = hex_to_bytes(a["aad_hex"].as_str().unwrap());
    let plaintext = hex_to_bytes(a["plaintext_hex"].as_str().unwrap());
    let expected_ct = hex_to_bytes(a["ciphertext_hex"].as_str().unwrap());

    let cipher = AeadCipher::new(AeadAlgorithm::ChaCha20Poly1305);
    let ct = cipher
        .encrypt_chacha20(&key, &nonce, &aad, &plaintext)
        .expect("cifrado");

    assert_eq!(
        bytes_to_hex(&ct),
        bytes_to_hex(&expected_ct),
        "el ciphertext AEAD diverge: el AAD o el nonce cambiaron"
    );

    // El AAD está autenticado: alterarlo debe romper el descifrado
    let mut bad_aad = aad.clone();
    bad_aad[0] ^= 0xFF;
    assert!(
        cipher
            .decrypt_chacha20(&key, &nonce, &bad_aad, &ct)
            .is_err(),
        "un AAD modificado debe fallar la autenticación"
    );
}

// ---------------------------------------------------------------------------
// P0.1 + P0.2 extremo a extremo: identidad y firma del contrato
// ---------------------------------------------------------------------------

fn build_demo_contract() -> Contract {
    let mut contract = Contract::new(
        "image_processor",
        "demo.contracts",
        ContractVersion::new(1, 0, 0),
    );
    contract.header.contract_id = 0x0123456789ABCDEF;
    contract.types.register(
        "PixelBuffer",
        TypeKind::Array {
            element_type: TypeId(0x0022), // F64
            max_length: 4096,
        },
    );
    contract
        .operations
        .register_auto("resize", "Redimensiona la imagen", TypeId(0x0003), TypeId(0x0001));
    contract.finalize().expect("finalize");
    contract
}

#[test]
fn contract_hash_matches_golden_vector() {
    let v = vectors();
    let c = &v["contract"];

    let contract = build_demo_contract();

    assert_eq!(contract.header.name, c["name"].as_str().unwrap());
    assert_eq!(contract.header.namespace, c["namespace"].as_str().unwrap());
    assert_eq!(
        contract.header.version.to_string(),
        c["version"].as_str().unwrap()
    );

    let hash_hex = bytes_to_hex(&contract.header.contract_hash);
    assert_eq!(
        hash_hex,
        c["contract_hash_hex"].as_str().unwrap(),
        "contract_hash diverge: la identidad canónica cambió"
    );

    // El prefijo de 12 bytes es exactamente el prefijo del hash completo
    assert_eq!(
        bytes_to_hex(&contract.header.contract_hash[..12]),
        c["contract_hash_prefix_hex"].as_str().unwrap()
    );
}

#[test]
fn signed_contract_matches_golden_vector() {
    use ed25519_dalek::SigningKey;
    let v = vectors();
    let c = &v["contract"];
    let e = &v["ed25519"];

    let mut contract = build_demo_contract();
    let signing = SigningKey::from_bytes(&arr32(e["private_key_hex"].as_str().unwrap()));
    ContractSigner::sign(&mut contract, &signing).expect("firma");

    assert_eq!(
        bytes_to_hex(&contract.header.contract_hash),
        c["signed_contract_hash_hex"].as_str().unwrap()
    );
    assert_eq!(
        bytes_to_hex(contract.signature.as_ref().unwrap()),
        c["signature_hex"].as_str().unwrap(),
        "la firma Ed25519 diverge"
    );

    // La firma debe verificar contra la clave pública del vector
    let verifying =
        ed25519_dalek::VerifyingKey::from_bytes(&arr32(e["public_key_hex"].as_str().unwrap()))
            .unwrap();
    ContractSigner::verify(&contract, &verifying).expect("la firma debe verificar");
}
