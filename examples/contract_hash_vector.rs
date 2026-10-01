//! Genera el valor esperado para el test de conformidad de `contract_hash`
//! en C++, construyendo exactamente el mismo buffer que construye ese test.
//!
//! Uso:
//!     cargo run --example contract_hash_vector

use ipc_contract_system::binary_contract::ContractSigner;
use ipc_contract_system::types::TypeId;
use ipc_contract_system::{Contract, ContractVersion};

fn main() {
    let mut c = Contract::new("c", "n", ContractVersion::new(1, 0, 0));
    c.header.contract_id = 0x0201;
    c.types.register(
        "T",
        ipc_contract_system::types::TypeKind::Array {
            element_type: TypeId(0x0003),
            max_length: 4,
        },
    );
    c.operations.register_auto("op", "d", TypeId(1), TypeId(2));
    c.finalize().expect("finalize");

    let binary = c.to_binary().expect("to_binary");

    println!("contract_hash      = {}", hex(&c.header.contract_hash));
    println!("binary_len         = {}", binary.len());
    println!("security_policy    = {}", hex(&c.security_to_binary().expect("sec")));
    println!("types_section      = {}", hex(&c.types.to_binary()));
    println!("ops_section        = {}", hex(&c.operations.to_binary()));
    println!("full_binary        = {}", hex(&binary));

    // Firma sobre el mismo contenido, para que el test pueda verificar.
    use ed25519_dalek::SigningKey;
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let mut signed = c.clone();
    ContractSigner::sign(&mut signed, &sk).expect("sign");
    println!("signed_binary      = {}", hex(&signed.to_binary().expect("to_binary")));

    // `calculate_hash` sobre el binario firmado debe reproducir el hash
    // declarado: es la comprobación que C++ no hacía (devolvía 32 ceros).
    let signed_bytes = signed.to_binary().expect("to_binary");
    let unverified = ipc_contract_system::binary_contract::ContractReader::from_bytes(&signed_bytes)
        .expect("reader");
    let reparsed = unverified.inspect();
    println!("reparsed_hash      = {}", hex(&reparsed.header.contract_hash));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
