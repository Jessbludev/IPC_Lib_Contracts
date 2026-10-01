//! Genera los vectores de conformidad canónicos (golden vectors).
//!
//! Uso:
//!     cargo run --example conformance_vectors > tests/vectors/crypto.json
//!
//! Los valores que produce son la referencia contra la que Kotlin y C++ deben
//! coincidir byte a byte. Si un binding diverge, la conformidad cross-language
//! está rota: P0.1 (BLAKE3 único), P0.2 (Ed25519 real), P0.3 (anti-replay
//! idéntico) y P0.4 (nonce con material secreto) no se cumplen.

use ipc_contract_system::binary_contract::ContractSigner;
use ipc_contract_system::security::{
    derive_nonce, AeadAlgorithm, AeadCipher, AntiReplay, AntiReplayError, Direction, KeyDerivation,
};
use ipc_contract_system::types::{TypeId, TypeKind};
use ipc_contract_system::{Contract, ContractVersion};
use std::fmt::Write as _;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Objeto JSON con entradas `clave: valor`, sin coma final.
struct Obj {
    lines: Vec<String>,
    indent: String,
}

impl Obj {
    fn new(indent: &str) -> Self {
        Self {
            lines: Vec::new(),
            indent: indent.to_string(),
        }
    }
    fn add(&mut self, key: &str, value: &str) {
        self.lines.push(format!("\"{key}\": {value}"));
    }
    /// Renderiza el objeto con indentación y sin coma final.
    fn finish(&self) -> String {
        let mut s = format!("{{\n");
        for (i, line) in self.lines.iter().enumerate() {
            s.push_str(&self.indent);
            s.push_str(line);
            if i + 1 < self.lines.len() {
                s.push(',');
            }
            s.push('\n');
        }
        s.push_str("  }");
        s
    }
}

fn main() {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"version\": \"2.1.1\",\n");
    out.push_str("  \"note\": \"Vectores dorados de conformidad cross-language. Regenerar con: cargo run --example conformance_vectors\",\n");

    // --- BLAKE3: identidad de contrato (P0.1) ---
    let inputs: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("abc", b"abc".to_vec()),
        ("contract_header_256", vec![0u8; 256]),
        ("seq_1_to_64", (1u8..=64).collect()),
        ("utf8_accents", "contrato-espanol-nihon".as_bytes().to_vec()),
        ("zeros_1024", vec![0u8; 1024]),
    ];
    let mut obj = Obj::new("    ");
    for (name, data) in &inputs {
        obj.add(
            name,
            &format!("\"{}\"", hex(&ipc_contract_system::security::blake3_hash(data))),
        );
    }
    out.push_str("  \"blake3\": ");
    out.push_str(&obj.finish());
    out.push_str(",\n");

    // --- KDF (P0.4) ---
    let secret: [u8; 32] = core::array::from_fn(|i| i as u8);
    let contract_hash: [u8; 32] = core::array::from_fn(|i| (0x20 + i) as u8);
    let kd = KeyDerivation::new(&secret);

    let session_key = kd.derive_session_key(&contract_hash, 42);
    let nonce_key = kd.derive_nonce_key(&contract_hash, 42);
    let enc_key = kd.derive_encryption_key(&session_key.0);
    let auth_key = kd.derive_auth_key(&session_key.0);

    let mut obj = Obj::new("    ");
    obj.add("secret_hex", &format!("\"{}\"", hex(&secret)));
    obj.add("contract_hash_hex", &format!("\"{}\"", hex(&contract_hash)));
    obj.add("session_id", "42");
    obj.add("session_key", &format!("\"{}\"", hex(&session_key.0)));
    obj.add("nonce_key", &format!("\"{}\"", hex(&nonce_key.0)));
    obj.add("encryption_key", &format!("\"{}\"", hex(&enc_key.0)));
    obj.add("auth_key", &format!("\"{}\"", hex(&auth_key.0)));
    out.push_str("  \"kdf\": ");
    out.push_str(&obj.finish());
    out.push_str(",\n");

    // --- Nonce (P0.4) ---
    let cases: [(&str, u64, u64, Direction); 5] = [
        ("tx_s42_q7", 42, 7, Direction::Tx),
        ("rx_s42_q7", 42, 7, Direction::Rx),
        ("tx_s42_q8", 42, 8, Direction::Tx),
        ("tx_s43_q7", 43, 7, Direction::Tx),
        ("tx_s42_q0", 42, 0, Direction::Tx),
    ];
    let mut obj = Obj::new("    ");
    obj.add("nonce_key_hex", &format!("\"{}\"", hex(&nonce_key.0)));
    for (label, session, seq, dir) in cases {
        let n = derive_nonce(&nonce_key.0, session, seq, dir);
        obj.add(label, &format!("\"{}\"", hex(&n)));
    }
    out.push_str("  \"nonce\": ");
    out.push_str(&obj.finish());
    out.push_str(",\n");

    // --- Ed25519 (P0.2) ---
    use ed25519_dalek::{Signer, Verifier};
    let sk_bytes: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
    let signing = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
    let verifying = signing.verifying_key();
    let msg = b"ipc-contract-cbc1-canonical-payload";

    let sig = signing.sign(msg);
    let mut forged = sig.to_bytes();
    forged[0] ^= 0x01;

    let mut obj = Obj::new("    ");
    obj.add("private_key_hex", &format!("\"{}\"", hex(&sk_bytes)));
    obj.add("public_key_hex", &format!("\"{}\"", hex(verifying.as_bytes())));
    obj.add("message_hex", &format!("\"{}\"", hex(msg)));
    obj.add("signature_hex", &format!("\"{}\"", hex(&sig.to_bytes())));
    obj.add("tampered_signature_hex", &format!("\"{}\"", hex(&forged)));
    obj.add("signature_verifies", &verifying.verify(msg, &sig).is_ok().to_string());
    obj.add(
        "tampered_verifies",
        &verifying
            .verify(msg, &ed25519_dalek::Signature::from_bytes(&forged))
            .is_ok()
            .to_string(),
    );
    out.push_str("  \"ed25519\": ");
    out.push_str(&obj.finish());
    out.push_str(",\n");

    // --- Anti-replay (P0.3) ---
    let transcript: [(&str, u64); 10] = [
        ("accept", 10),
        ("accept", 11),
        ("accept", 12),
        ("replay", 11),
        ("accept", 13),
        ("accept", 40),
        // offset 39 < 64 y bit no marcado: nunca se vio, se acepta.
        // (La ventana recuerda lo recibido, no lo no recibido.)
        ("accept", 1),
        // offset 28 < 64 y bit marcado: replay
        ("replay", 12),
        // Aceptar 200 avanza highest a 200; entonces la secuencia 1 queda a
        // offset 199 >= 64 y debe rechazarse por antigüedad, no como replay.
        ("accept", 200),
        ("out_of_window", 1),
    ];
    let ar = AntiReplay::new(64);

    let mut lines = String::new();
    for (i, (expected, seq)) in transcript.iter().enumerate() {
        let got = match ar.check(7, Direction::Rx, *seq) {
            Ok(()) => "accept",
            Err(AntiReplayError::Replay { .. }) => "replay",
            Err(AntiReplayError::SequenceOutOfWindow { .. }) => "out_of_window",
        };
        let comma = if i + 1 < transcript.len() { "," } else { "" };
        let _ = writeln!(
            lines,
            "      {{ \"seq\": {seq}, \"expected\": \"{expected}\", \"got\": \"{got}\" }}{comma}"
        );
        assert_eq!(*expected, got, "el replay vector {seq} cambio de comportamiento");
    }

    let (highest, initialized, bitmap) = ar.snapshot(7, Direction::Rx).expect("ventana");
    let bitmap_hex: Vec<String> = bitmap.iter().map(|w| format!("\"{w:016x}\"")).collect();

    out.push_str("  \"replay\": {\n");
    out.push_str("    \"window_size\": 64,\n");
    out.push_str(&format!("    \"transcript\": [\n{}    ],\n", lines));
    out.push_str(&format!("    \"final_highest\": {highest},\n"));
    out.push_str(&format!("    \"final_initialized\": {initialized},\n"));
    out.push_str(&format!("    \"final_bitmap_hex\": [{}]\n", bitmap_hex.join(", ")));
    out.push_str("  },\n");

    // --- AEAD ---
    let cipher = AeadCipher::new(AeadAlgorithm::ChaCha20Poly1305);
    let aead_key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x11));
    let aead_nonce = derive_nonce(&nonce_key.0, 42, 7, Direction::Tx);
    let aad = b"header-aad-48-bytes!!";
    let plaintext = b"payloado-secreto";

    let ct = cipher
        .encrypt_chacha20(&aead_key, &aead_nonce, aad, plaintext)
        .expect("cifrado");

    let mut obj = Obj::new("    ");
    obj.add("algorithm", "\"chacha20-poly1305\"");
    obj.add("key_hex", &format!("\"{}\"", hex(&aead_key)));
    obj.add("nonce_hex", &format!("\"{}\"", hex(&aead_nonce)));
    obj.add("aad_hex", &format!("\"{}\"", hex(aad)));
    obj.add("plaintext_hex", &format!("\"{}\"", hex(plaintext)));
    obj.add("ciphertext_hex", &format!("\"{}\"", hex(&ct)));
    out.push_str("  \"aead\": ");
    out.push_str(&obj.finish());
    out.push_str(",\n");

    // --- Contrato completo (P0.1 extremo a extremo + P0.2 firma) ---
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

    let mut signed = contract.clone();
    ContractSigner::sign(&mut signed, &signing).expect("sign");

    let mut obj = Obj::new("    ");
    obj.add("name", "\"image_processor\"");
    obj.add("namespace", "\"demo.contracts\"");
    obj.add("version", "\"1.0.0\"");
    obj.add("contract_id", "\"0123456789abcdef\"");
    obj.add(
        "contract_hash_hex",
        &format!("\"{}\"", hex(&contract.header.contract_hash)),
    );
    obj.add(
        "contract_hash_prefix_hex",
        &format!("\"{}\"", hex(&contract.header.contract_hash[..12])),
    );
    obj.add(
        "signed_contract_hash_hex",
        &format!("\"{}\"", hex(&signed.header.contract_hash)),
    );
    obj.add(
        "signature_hex",
        &format!("\"{}\"", hex(signed.signature.as_ref().unwrap())),
    );
    out.push_str("  \"contract\": ");
    out.push_str(&obj.finish());
    out.push_str("\n}\n");

    print!("{out}");
}
